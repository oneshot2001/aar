"""Clean-room AAR v0.2 verifier and deterministic W-12 verdict producer.

The implementation follows the numbered order in ``spec/CONFORMANCE.md``.
It deliberately exposes evaluation time and prior state as inputs; it never
consults a clock or network service.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import hashes, relying_party, verdict
from .cbor import CBORError, dumps, loads
from .crypto import N, is_der_ecdsa_signature, parse_p256_spki, verify_es256


MAX_U53 = 9_007_199_254_740_991
ZERO16 = bytes(16)
ZERO32 = bytes(32)

LIMITS = {
    "exact_encoded_bundle_bytes": 16_777_216,
    "cbor_container_nesting": 32,
    "receipt_nodes": 10_000,
    "directed_graph_edges": 50_000,
    "parents_per_receipt": 64,
    "dag_depth": 128,
    "dag_width": 4_096,
    "encoded_proof_bytes": 65_536,
    "aggregate_proof_bytes": 4_194_304,
    "epoch_manifest_entries": 10_000,
    "merkle_batch_leaves": 1_048_576,
    "credential_path_length": 8,
}

PROFILES = ("AAR-1", "AAR-2", "AAR-2A", "AAR-3")
NODE_KINDS = (
    "observation",
    "inference",
    "authorization",
    "action_attempt",
    "dispatch",
    "outcome_observation",
)

STEP_NAMES = (
    "Bundle byte limit",
    "Bundle CBOR",
    "Bundle schema",
    "Static resource counts",
    "Trust-policy input",
    "Envelope mechanics",
    "Content commitments and IDs",
    "Credential lifecycle",
    "Emission identity",
    "Receipt schema semantics",
    "Replay and freshness",
    "Referential closure and graph",
    "Authorization dominance",
    "Epoch state machine",
    "Manifest index",
    "Merkle batches",
    "Anchors",
    "Bundle ranges and coverage",
    "Evidence-class qualification",
    "Verdict",
)
PRINCIPAL_TYPES = ("human", "service", "workload_instance", "model_endpoint")
PRINCIPAL_ROLES = (
    "agent",
    "enforcement_point",
    "authority_source",
    "approver",
    "outcome_observer",
    "anchor_service",
    "verifier",
)
KEY_USAGES = (
    "agent_signing",
    "ep_signing",
    "authority_signing",
    "approver_signing",
    "outcome_signing",
    "anchor_signing",
    "verifier_signing",
    "credential_issuing",
    "status_signing",
)

CONTENT_TYPES = {
    "credentials": "application/aar-credential+cbor;v=0.2",
    "rotations": "application/aar-rotation+cbor;v=0.2",
    "status_snapshots": "application/aar-status+cbor;v=0.2",
    "requests": "application/aar-request+cbor;v=0.2",
    "delegations": "application/aar-delegation+cbor;v=0.2",
    "epoch_events": "application/aar-epoch-event+cbor;v=0.2",
    "epoch_manifests": "application/aar-epoch-manifest+cbor;v=0.2",
    "anchors": "application/aar-anchor-record+cbor;v=0.2",
    "merkle_batches": "application/aar-merkle-batch+cbor;v=0.2",
    "mediator_countersignatures": "application/aar-mediator-countersignature+cbor;v=0.2",
    "receipts": "application/aar-receipt+cbor;v=0.2",
    "presentations": "application/aar-presentation+cbor;v=0.2",
}

ARTIFACT_ORDER = (
    "credentials",
    "rotations",
    "status_snapshots",
    "requests",
    "delegations",
    "epoch_events",
    "epoch_manifests",
    "anchors",
    "merkle_batches",
    "mediator_countersignatures",
    "receipts",
)

# Fixed-size payload identifiers, checked at step 6 before any consumer indexes,
# sorts, or hashes them (harness `payloadFixedFields` parity): wrong type is
# schema/bad-type, wrong size is schema/digest-size. subject_kid is included for
# credentials because it is used as a map key and compared to sha256(public_key).
PAYLOAD_FIXED_FIELDS: dict[str, tuple[tuple[str, int], ...]] = {
    CONTENT_TYPES["credentials"]: (("credential_id", 32), ("subject_kid", 32)),
    CONTENT_TYPES["rotations"]: (("rotation_id", 32),),
    CONTENT_TYPES["status_snapshots"]: (("snapshot_id", 32),),
    CONTENT_TYPES["requests"]: (("request_id", 16),),
    CONTENT_TYPES["delegations"]: (("delegation_id", 32),),
    CONTENT_TYPES["epoch_events"]: (("event_id", 32),),
    CONTENT_TYPES["epoch_manifests"]: (("manifest_id", 32),),
    CONTENT_TYPES["anchors"]: (("anchor_id", 32),),
    CONTENT_TYPES["merkle_batches"]: (("batch_id", 32),),
    CONTENT_TYPES["mediator_countersignatures"]: (("countersignature_id", 32), ("action_attempt_receipt_digest", 32), ("command_digest", 32)),
    CONTENT_TYPES["receipts"]: (("receipt_id", 32),),
    CONTENT_TYPES["presentations"]: (("presentation_id", 32),),
}


class ValidationError(Exception):
    def __init__(self, code: str, step: int, *, indeterminate: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.step = step
        self.indeterminate = indeterminate


def _fail(code: str, step: int, *, indeterminate: bool = False) -> None:
    raise ValidationError(code, step, indeterminate=indeterminate)


def _uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_U53


def _bstr(value: Any, size: int | None = None) -> bool:
    return isinstance(value, bytes) and (size is None or len(value) == size)


def _strictly_sorted(values: list[Any]) -> bool:
    encoded = [dumps(value) for value in values]
    return all(encoded[index - 1] < encoded[index] for index in range(1, len(encoded)))


def _closed_map(value: Any, required: Iterable[Any], optional: Iterable[Any] = (), *,
                indeterminate: bool = False) -> dict[Any, Any]:
    if not _type_ok(value, "map"):
        _fail("schema/bad-type", 3)
    required_set = set(required)
    allowed = required_set | set(optional)
    if any(key not in allowed for key in value):
        _fail("schema/unknown-field", 3)
    if any(key not in value for key in required_set):
        # A missing trust input is missing external policy (section 5): indeterminate.
        _fail("schema/missing-field", 3, indeterminate=indeterminate)
    return value


def _compare_encoded(left: Any, right: Any) -> int:
    """Deterministic-CBOR encoded-byte order, length first (harness compareEncoded)."""
    a, b = dumps(left), dumps(right)
    if len(a) != len(b):
        return len(a) - len(b)
    return (a > b) - (a < b)


def _sorted_unique(values: list[Any]) -> None:
    for index in range(1, len(values)):
        order = _compare_encoded(values[index - 1], values[index])
        if order == 0:
            _fail("schema/duplicate-entry", 3)
        if order > 0:
            _fail("schema/unsorted-set", 3)


# Bundle artifact arrays in harness ARTIFACT_FIELDS order; the value is the
# primary-ID field (merkle proofs sort by (batch_id, leaf_index)).
ARTIFACT_SORT_FIELDS = {
    "receipts": "receipt_id", "requests": "request_id", "delegations": "delegation_id",
    "credentials": "credential_id", "status_snapshots": "snapshot_id", "rotations": "rotation_id",
    "epoch_events": "event_id", "epoch_manifests": "manifest_id", "anchors": "anchor_id",
    "merkle_batches": "batch_id", "merkle_proofs": None, "manifest_payloads": "digest",
    "mediator_countersignatures": "countersignature_id",
}
_NO_KEY = object()


def _artifact_sort_key(field: str, entry: Any) -> Any:
    """Primary-ID sort key when the payload is decodable; _NO_KEY leaves the array to step 6."""
    if field == "merkle_proofs":
        return [entry["batch_id"], entry["leaf_index"]] if _type_ok(entry, "map") \
            and _bstr(entry.get("batch_id"), 32) and _uint(entry.get("leaf_index")) else _NO_KEY
    if field == "manifest_payloads":
        return entry["digest"] if _type_ok(entry, "map") and _bstr(entry.get("digest"), 32) else _NO_KEY
    if not (isinstance(entry, list) and entry and isinstance(entry[0], bytes)):
        return _NO_KEY
    try:
        payload = loads(entry[0])
    except CBORError:
        return _NO_KEY
    return payload.get(ARTIFACT_SORT_FIELDS[field], _NO_KEY) if _type_ok(payload, "map") else _NO_KEY


def _check_fixed(value: Any, size: int) -> None:
    if not isinstance(value, bytes):
        _fail("schema/bad-type", 3)
    if len(value) != size:
        _fail("schema/digest-size", 3)


def _check_text(value: Any, maximum: int = 128) -> None:
    if not isinstance(value, str):
        _fail("schema/bad-type", 3)
    if not (1 <= len(value.encode("utf-8")) <= maximum):
        _fail("schema/string-size", 3)


@dataclass
class Envelope:
    category: str
    index: int
    raw_value: list[Any]
    envelope_bytes: bytes
    payload_bytes: bytes
    payload: dict[str, Any]
    cose_bytes: bytes
    cose: list[Any]
    protected_bytes: bytes
    protected: dict[Any, Any]


@dataclass
class Evaluation:
    result: str
    reason: str | None
    step: int
    verdict: dict[str, Any]
    verdict_bytes: bytes
    report: dict[str, Any]


@dataclass
class State:
    raw: bytes
    evaluated_at: int
    prior_state: dict[str, Any] | None
    replay_state: dict[str, Any] | None
    configured_trust_policy: dict[str, Any] | None = None
    configuration: relying_party.Configuration | None = None
    bundle: dict[str, Any] | None = None
    envelopes: dict[str, list[Envelope]] = field(default_factory=lambda: defaultdict(list))
    credentials_by_kid: dict[bytes, Envelope] = field(default_factory=dict)
    credentials_by_id: dict[bytes, Envelope] = field(default_factory=dict)
    receipts_by_id: dict[bytes, Envelope] = field(default_factory=dict)
    embedded_delegations: dict[bytes, Envelope] = field(default_factory=dict)
    payloads_by_digest: dict[bytes, dict[str, Any]] = field(default_factory=dict)
    observations: list[str] = field(default_factory=list)
    selector_matching_receipts: int | None = None
    classes: dict[str, str] = field(default_factory=lambda: {
        "time": "not_evaluated",
        "provenance": "not_evaluated",
        "outcome": "not_evaluated",
    })
    stateful_checks: str = "not_evaluated"
    input_origin_ancestry: str = "not_evaluated"
    input_origin_attempts: list[dict[str, Any]] = field(default_factory=list)


def _schema_bundle(bundle: Any) -> dict[str, Any]:
    required = {
        "v", "created_at", "bundle_nonce", "claimed_profile", "selector",
        "selector_commitment", "coverage", "trust_inputs", "ranges", "artifacts",
    }
    bundle = _closed_map(bundle, required)
    # Field order and codes mirror harness validateBundleSchema (round 6, D1).
    if not _uint(bundle["v"]):
        _fail("schema/bad-type", 3)
    if bundle["v"] != 2:
        _fail("schema/version-wrong", 3)
    if not _uint(bundle["created_at"]):
        _fail("schema/bad-type", 3)
    _check_fixed(bundle["bundle_nonce"], 16)
    if not isinstance(bundle["claimed_profile"], str):
        _fail("schema/bad-type", 3)
    if bundle["claimed_profile"] not in PROFILES:
        _fail("schema/enum-unknown", 3)
    if not isinstance(bundle["coverage"], str):
        _fail("schema/bad-type", 3)
    if bundle["coverage"] not in ("valid_subset", "complete"):
        _fail("schema/enum-unknown", 3)
    _check_fixed(bundle["selector_commitment"], 32)
    if not isinstance(bundle["ranges"], list):
        _fail("schema/bad-type", 3)
    if len(bundle["ranges"]) > 256:
        _fail("schema/out-of-range", 3)
    # Amendments (n) and (ab): every member of a range proof, its entries and
    # boundaries, is checked for presence then type here (step 6 never sees them).
    for range_proof in bundle["ranges"]:
        if not _type_ok(range_proof, "map"):
            _fail("schema/bad-type", 3)
        _apply_rules(range_proof, RANGE_PROOF_RULES, 3)

    selector = _closed_map(
        bundle["selector"],
        {"tenant_id", "site_id", "committed_from", "committed_until", "receipt_kinds"},
        {"subject_ids", "correlation_ids", "issuer_kids"},
    )
    _check_fixed(selector["tenant_id"], 16)
    _check_fixed(selector["site_id"], 16)
    if not _uint(selector["committed_from"]) or not _uint(selector["committed_until"]):
        _fail("schema/bad-type", 3)
    for name, limit in (("receipt_kinds", 6), ("subject_ids", 256), ("correlation_ids", 256), ("issuer_kids", 64)):
        if name not in selector:
            continue
        values = selector[name]
        if not isinstance(values, list):
            _fail("schema/bad-type", 3)
        if not (1 <= len(values) <= limit):
            _fail("schema/out-of-range", 3)
        if name == "receipt_kinds":
            for value in values:
                if not isinstance(value, str):
                    _fail("schema/bad-type", 3)
                if value not in NODE_KINDS:
                    _fail("schema/enum-unknown", 3)
        else:
            for value in values:
                _check_fixed(value, 32 if name == "issuer_kids" else 16)
        _sorted_unique(values)  # amendment (i): the same pairwise comparison as artifact arrays

    # D-82 part 3: the shape of trust_inputs (snapshot, root records, expected
    # heads) is step-3 bundle schema; step 5 validates its content. Field order
    # mirrors harness validateBundleSchema.
    trust = _closed_map(
        bundle["trust_inputs"],
        {"evaluation_time", "trust_store", "expected_anchor_heads", "verifier_policy_digest"},
        {"life_safety_action_names"}, indeterminate=True,
    )
    if not _uint(trust["evaluation_time"]):
        _fail("schema/bad-type", 3)
    _check_fixed(trust["verifier_policy_digest"], 32)
    heads = trust["expected_anchor_heads"]
    if not isinstance(heads, list):
        _fail("schema/bad-type", 3)
    if not 1 <= len(heads) <= 32:
        _fail("schema/out-of-range", 3)
    if "life_safety_action_names" in trust:
        names = trust["life_safety_action_names"]
        if not isinstance(names, list):
            _fail("schema/bad-type", 3)
        if len(names) > 64:
            _fail("schema/out-of-range", 3)
        for name in names:
            _check_text(name)
    store = _closed_map(trust["trust_store"], {"digest", "snapshot_id", "created_at", "roots"}, indeterminate=True)
    _check_fixed(store["digest"], 32)
    _check_fixed(store["snapshot_id"], 32)
    if not _uint(store["created_at"]) or not isinstance(store["roots"], list):
        _fail("schema/bad-type", 3)
    if not 1 <= len(store["roots"]) <= 64:
        _fail("schema/out-of-range", 3)
    for root in store["roots"]:
        _closed_map(root, {"root_id", "root_kid", "tenant_id", "allowed_sites", "allowed_key_usages"}, indeterminate=True)
        for name, size in (("root_id", 32), ("root_kid", 32), ("tenant_id", 16)):
            _check_fixed(root[name], size)
        if not isinstance(root["allowed_sites"], list) or not isinstance(root["allowed_key_usages"], list):
            _fail("schema/bad-type", 3)
        if not 1 <= len(root["allowed_sites"]) <= 256 or not 1 <= len(root["allowed_key_usages"]) <= 8:
            _fail("schema/out-of-range", 3)
        for site in root["allowed_sites"]:
            _check_fixed(site, 16)
        for usage in root["allowed_key_usages"]:
            if not isinstance(usage, str):
                _fail("schema/bad-type", 3)
            if usage not in KEY_USAGES:
                _fail("schema/enum-unknown", 3)
        _sorted_unique(root["allowed_sites"])
        _sorted_unique(root["allowed_key_usages"])
    for head in heads:
        _closed_map(head, {"target_id", "observed_at", "tree_size", "root"}, indeterminate=True)
        _check_fixed(head["target_id"], 16)
        _check_fixed(head["root"], 32)
        if not _uint(head["observed_at"]) or not _uint(head["tree_size"]):
            _fail("schema/bad-type", 3)
        if not 1 <= head["tree_size"] <= 4_294_967_295:
            _fail("schema/out-of-range", 3)
    if len({head["target_id"] for head in heads}) != len(heads):  # amendment (ap): the D-77 root_kid pattern
        _fail("schema/duplicate-entry", 3)

    artifacts = _closed_map(
        bundle["artifacts"],
        {"receipts", "requests", "delegations", "credentials", "status_snapshots",
         "rotations", "epoch_events", "epoch_manifests", "anchors", "merkle_batches",
         "merkle_proofs", "manifest_payloads"},
        {"mediator_countersignatures"},
    )
    ceilings = {
        "receipts": 10_000, "requests": 10_000, "delegations": 1_000,
        "credentials": 1_000, "status_snapshots": 4_000, "rotations": 1_000,
        "epoch_events": 2_000, "epoch_manifests": 256, "anchors": 2_048,
        "merkle_batches": 1_000, "merkle_proofs": 10_000, "manifest_payloads": 4_096,
        "mediator_countersignatures": 10_000,
    }
    for name in ceilings:
        if not isinstance(artifacts.get(name, []), list):
            _fail("schema/bad-type", 3)
    # Section 2 explicitly defers section-1 resource ceilings to step 4.
    for name, ceiling in ceilings.items():
        if name not in {"receipts", "merkle_proofs", "mediator_countersignatures"} and len(artifacts.get(name, [])) > ceiling:
            _fail("schema/out-of-range", 3)
    for payload in artifacts["manifest_payloads"]:
        payload = _closed_map(payload, {"digest", "media_type", "canonical_bytes"})
        _check_fixed(payload["digest"], 32)
        _check_text(payload["media_type"])
        if not isinstance(payload["canonical_bytes"], bytes):
            _fail("schema/bad-type", 3)
        if not (1 <= len(payload["canonical_bytes"]) <= 1_048_576):
            _fail("schema/out-of-range", 3)

    # Amendments (b) and (ab): every member of a Merkle membership proof is
    # checked for presence then type here (step 6 never sees it).
    for proof in artifacts["merkle_proofs"]:
        if not _type_ok(proof, "map"):
            _fail("schema/bad-type", 3)
        _apply_rules(proof, MERKLE_PROOF_RULES, 3)
        if len(proof["siblings"]) > 20:  # amendment (ak): the CDDL bound
            _fail("schema/out-of-range", 3)

    # D-82 part 3: sort order and uniqueness of every artifact array are judged
    # here, before step 6 touches any envelope. An array with an undecodable
    # member is left to step 6 (harness artifactSortKey parity).
    for name in ARTIFACT_SORT_FIELDS:
        keys = [_artifact_sort_key(name, entry) for entry in artifacts.get(name, [])]
        if len(keys) > 1 and all(key is not _NO_KEY for key in keys):
            _sorted_unique(keys)

    if hashes.selector_commitment(selector) != bundle["selector_commitment"]:
        _fail("bundle/selector-commitment", 3)
    return bundle


def _loose_payload(value: Any) -> dict[str, Any] | None:
    """Any artifact entry whose element 0 is a bstr decoding to a map (amendment f)."""
    if not (isinstance(value, list) and value and isinstance(value[0], bytes)):
        return None
    try:
        payload = loads(value[0])
    except CBORError:
        return None
    return payload if _type_ok(payload, "map") else None


def _resource_checks(bundle: dict[str, Any]) -> None:
    artifacts = bundle["artifacts"]
    receipts = artifacts["receipts"]
    if len(receipts) > LIMITS["receipt_nodes"]:
        _fail("resource/node-count", 4)
    if len(artifacts.get("mediator_countersignatures", [])) > LIMITS["receipt_nodes"]:
        _fail("resource/node-count", 4)
    edge_count = 0
    for value in receipts:
        payload = _loose_payload(value)
        parents = payload.get("parents", []) if payload else []
        if isinstance(parents, list):
            if len(parents) > LIMITS["parents_per_receipt"]:
                _fail("resource/parent-count", 4)
            edge_count += len(parents)
    if edge_count > LIMITS["directed_graph_edges"]:
        _fail("resource/edge-count", 4)

    # Amendment (ah): a proof object is one inclusion, consistency, or membership
    # proof; each is counted once and the container carrying it is not counted.
    proof_objects: list[Any] = []
    for range_proof in bundle["ranges"]:
        if not _type_ok(range_proof, "map"):
            continue
        entries = range_proof.get("entries")
        wrappers = (entries if isinstance(entries, list) else []) + [range_proof[name] for name in ("left_boundary", "right_boundary") if name in range_proof]
        proof_objects.extend(wrapper["inclusion"] for wrapper in wrappers if _type_ok(wrapper, "map") and "inclusion" in wrapper)
    proof_objects.extend(artifacts["merkle_proofs"])
    for value in artifacts["anchors"]:
        payload = _loose_payload(value)
        if payload is not None:
            proof_objects.extend(payload[name] for name in ("inclusion", "consistency") if name in payload)
    total = 0
    for proof in proof_objects:
        size = len(dumps(proof))
        if size > LIMITS["encoded_proof_bytes"]:
            _fail("resource/proof-too-large", 4)
        total += size
    if total > LIMITS["aggregate_proof_bytes"]:
        _fail("resource/proofs-too-large", 4)


def _trust_policy_checks(state: State) -> None:
    """Step 5 content checks; the shape of trust_inputs is step-3 schema (D-82)."""
    assert state.bundle is not None
    trust = state.bundle["trust_inputs"]
    store = trust["trust_store"]
    if store["snapshot_id"] == bytes(32):  # amendment (ah): the verdict's not-evaluated sentinel
        _fail("schema/out-of-range", 5)
    if hashes.trust_store_digest(store) != store["digest"]:
        _fail("hash/mismatch", 5)
    if len({root["root_kid"] for root in store["roots"]}) != len(store["roots"]):
        _fail("schema/duplicate-entry", 5)
    selector = state.bundle["selector"]
    for root in store["roots"]:
        if root["tenant_id"] != selector["tenant_id"] or selector["site_id"] not in root["allowed_sites"]:
            _fail("credential/root-not-accepted", 5)
    # D-83 part 4: separation; a producer root that is a verifier kid.
    if state.configuration is not None and any(root["root_kid"] in state.configuration.verifier_kids for root in store["roots"]):
        _fail("credential/root-not-accepted", 5)
    if trust["evaluation_time"] != state.evaluated_at:
        _fail("schema/out-of-range", 5)
    if state.evaluated_at < store["created_at"]:
        _fail("schema/out-of-range", 5)


def _parse_embedded(data: bytes, *, cose: bool = False) -> Any:
    if cose and data and data[0] >> 5 == 6:
        _fail("cose/tagged", 6)
    try:
        return loads(data)
    except CBORError as exc:  # amendment (aq): a nested tag is cbor/tag-forbidden; cose/tagged is the wrapping tag only
        _fail(exc.code, 6)


def _preparse_payloads(state: State) -> None:
    """Decode payload bstrs for key indexing; this does not accept/reject COSE."""
    assert state.bundle is not None
    for category in ARTIFACT_ORDER:
        for index, value in enumerate(state.bundle["artifacts"].get(category, [])):
            payload = _loose_payload(value)
            if payload is None:
                continue
            placeholder = Envelope(category, index, value, dumps(value), value[0], payload, b"", [], b"", {})
            if category == "credentials":
                kid = payload.get("subject_kid")
                credential_id = payload.get("credential_id")
                if isinstance(kid, bytes):
                    state.credentials_by_kid.setdefault(kid, placeholder)
                if isinstance(credential_id, bytes):
                    state.credentials_by_id[credential_id] = placeholder


def _raw_mediator_kids(state: State) -> set[bytes]:
    """Classify a carried credential as countersign-related without accepting it."""
    assert state.bundle is not None
    kids: set[bytes] = set()
    for value in state.bundle["artifacts"].get("mediator_countersignatures", []):
        try:
            if not isinstance(value, list) or len(value) < 2 or not isinstance(value[1], bytes):
                continue
            cose = loads(value[1])
            if not isinstance(cose, list) or len(cose) != 4 or not isinstance(cose[0], bytes):
                continue
            protected = loads(cose[0])
            kid = protected.get(4) if isinstance(protected, dict) else None
            if _bstr(kid, 32):
                kids.add(kid)
        except CBORError:
            continue
    return kids


INPUT_ORIGINS = {"principal", "operator_system", "device_sensed", "third_party", "unknown"}
STATUS_INSTANTS = {"revoked": "revoked_at", "compromised": "compromise_at"}
TIME_CLASSES = ("asserted", "boot_bound", "externally_anchored")
PROVENANCE_CLASSES = ("self_asserted", "proxy_captured", "provider_attested")
OUTCOME_LEVELS = ("accepted", "dispatched", "device_acknowledged", "independently_sensed", "contradicted", "unknown")
TRANSFORMATION_OPERATIONS = ("decode", "crop", "embed", "ocr", "truncate", "retrieve", "normalize", "render", "redact")
# D-82 part 8: the bounded step-6 schema table. Rules are (path, kind, optional)
# in CDDL field order within each production; kind is a scalar type or a closed
# enum tuple. A container's rule precedes its members' rules (D-81 UINT_FIELDS
# generalised; the credential and presentation blocks are inline because their
# pinned precedences interleave D-73 checks).
# A rule whose kind is a list is applied to every member of the array at its
# path; each member must be a text-keyed map (amendment b: array members).
INDEX_ENTRY_RULES = (
    (("leaf_index",), "uint", False), (("receipt_id",), "bstr32", False), (("receipt_kind",), "text", False), (("issuer_kid",), "bstr32", False),
    (("issuer_seq",), "uint", False), (("epoch_seq",), "uint", False), (("committed_at",), "uint", False),
    (("subject_ids",), "bstr16[]", False), (("correlation_ids",), "bstr16[]", False),
)
INDEPENDENCE_GROUP_RULES = ((("independence_group",), "bstr16", False), (("operator_id",), "bstr16", False), (("failure_domain_id",), "bstr16", False))
INCLUSION_RULES = ((("tree_size",), "uint", False), (("leaf_index",), "uint", False), (("siblings",), "bstr32[]", False))
# Amendment (ab): the bare proof-bearing productions, typed at step 3.
MERKLE_PROOF_RULES = (
    (("batch_id",), "bstr32", False), (("tree_size",), "uint", False), (("leaf_index",), "uint", False),
    (("leaf",), "map", False), (("leaf", "tree_size"), "uint", False), (("leaf", "leaf_index"), "uint", False),
    (("leaf", "tenant_id"), "bstr16", False), (("leaf", "site_id"), "bstr16", False), (("leaf", "epoch_id"), "uint", False),
    (("leaf", "item_digest"), "bstr32", False), (("siblings",), "bstr32[]", False),
)
RANGE_ITEM_RULES = ((("entry",), "map", False), (("entry",), INDEX_ENTRY_RULES, False), (("inclusion",), "map", False), (("inclusion",), INCLUSION_RULES, False))
RANGE_PROOF_RULES = (
    (("manifest_id",), "bstr32", False), (("selector_commitment",), "bstr32", False), (("tree_size",), "uint", False),
    (("first_leaf_index",), "uint", True), (("entries",), "array", False), (("entries",), RANGE_ITEM_RULES, False),
    (("left_boundary",), "map", True), (("left_boundary",), RANGE_ITEM_RULES, False),
    (("right_boundary",), "map", True), (("right_boundary",), RANGE_ITEM_RULES, False),
)
FIELD_RULES: dict[str, tuple[tuple[tuple[str, ...], Any, bool], ...]] = {
    CONTENT_TYPES["rotations"]: ((("effective_at",), "uint", False), (("continuity_sequence",), "uint", False)),
    CONTENT_TYPES["delegations"]: ((("not_before",), "uint", False), (("not_after",), "uint", False), (("use",), ("one_time", "reusable"), False)),
    CONTENT_TYPES["epoch_events"]: (
        (("epoch_id",), "uint", False), (("event_seq",), "uint", False), (("occurred_at",), "uint", False),
        (("event",), ("open", "close", "anchor_submitted", "fork_declared"), False), (("body",), "map", False),
    ),
    CONTENT_TYPES["epoch_manifests"]: (
        (("epoch_id",), "uint", False), (("opened_at",), "uint", False), (("closed_at",), "uint", False),
        (("sequence_span",), "map", False), (("sequence_span", "first"), "uint|nil", False), (("sequence_span", "last"), "uint|nil", False),
        (("close_reason",), ("duration", "size", "administrative", "padding"), False),
        (("late_arrival_policy",), ("next_epoch_only",), False), (("anchor_deadline",), "uint", False),
        (("fork_policy",), ("reject_and_surface",), False),
        (("receipt_index",), "map", False), (("receipt_index", "leaf_count"), "uint", False), (("receipt_index", "root"), "bstr32", False),
        (("receipt_index", "entries"), "array", False), (("receipt_index", "entries"), INDEX_ENTRY_RULES, False),
    ),
    CONTENT_TYPES["anchors"]: (
        (("epoch_id",), "uint", False), (("manifest_digest",), "bstr32", False), (("submitted_at",), "uint", False), (("accepted_at",), "uint", False),
        (("anchor_tree_size",), "uint", False), (("anchor_leaf_index",), "uint", False), (("anchor_root",), "bstr32", False),
        (("inclusion",), "map", False), (("inclusion", "tree_size"), "uint", False), (("inclusion", "leaf_index"), "uint", False),
        (("inclusion", "leaf_digest"), "bstr32", False), (("inclusion", "siblings"), "bstr32[]", False),
        (("consistency",), "map", True), (("consistency", "old_tree_size"), "uint", False), (("consistency", "new_tree_size"), "uint", False),
        (("consistency", "old_root"), "bstr32", False), (("consistency", "new_root"), "bstr32", False), (("consistency", "path"), "bstr32[]", False),
        (("head",), "map", False), (("head", "observed_at"), "uint", False), (("head", "tree_size"), "uint", False),
        (("head", "root"), "bstr32", False), (("head", "max_age_s"), "uint", False),
    ),
    CONTENT_TYPES["merkle_batches"]: (
        (("tenant_id",), "bstr16", False), (("site_id",), "bstr16", False), (("epoch_owner_kid",), "bstr32", False), (("epoch_id",), "uint", False),
        (("signer_kid",), "bstr32", False), (("tree_size",), "uint", False), (("root",), "bstr32", False), (("created_at",), "uint", False), (("claim",), "text", False),
    ),
    CONTENT_TYPES["mediator_countersignatures"]: ((("mediator_observed_at",), "uint", False),),
    CONTENT_TYPES["receipts"]: (
        (("binding",), "map", False), (("binding", "tenant_id"), "bytes", False), (("binding", "site_id"), "bytes", False),
        (("binding", "epoch_owner_kid"), "bytes", False), (("binding", "epoch_id"), "uint", False), (("binding", "epoch_seq"), "uint", False),
        (("binding", "late_for_epoch_id"), "uint", True),
        (("emission",), "map", False), (("emission", "issuer_seq"), "uint", False), (("emission", "committed_at"), "uint", False),
        (("freshness",), "map", False), (("freshness", "issued_at"), "uint", False), (("freshness", "expires_at"), "uint", False),
        (("freshness", "nonce"), "bytes", False), (("freshness", "replay_domain"), "bytes", False), (("freshness", "invocation_id"), "bytes", False),
        (("freshness", "use"), "text", False), (("freshness", "intended_parents"), "array", False),
        (("evidence",), "map", False), (("evidence", "time"), "map", False), (("evidence", "time", "class"), TIME_CLASSES, False),
        (("evidence", "time", "wall_time"), "uint", False),
        (("evidence", "provenance"), "map", True), (("evidence", "provenance", "class"), PROVENANCE_CLASSES, False),
        (("evidence", "outcome"), "map", True), (("evidence", "outcome", "level"), OUTCOME_LEVELS, False),
        (("parents",), "array", False), (("parents",), ((("parent_epoch_id",), "uint", False),), False),
        (("correlation",), "map", True), (("correlation", "phase"), ("request", "ingress_ack", "accounted"), False),
        (("body",), "map", False),
    ),
}


def _type_ok(value: Any, kind: Any) -> bool:
    if kind == "uint":
        return _uint(value)
    if kind in ("bstr32", "bstr16"):
        return isinstance(value, bytes)  # size is judged after type (schema/digest-size)
    if kind in ("bstr32[]", "bstr16[]"):
        return isinstance(value, list)
    if kind == "uint|nil":  # sequence-span members
        return value is None or _uint(value)
    if kind == "bytes":
        return isinstance(value, bytes)
    if kind == "map":  # a text-keyed map (harness object() parity)
        return isinstance(value, dict) and all(isinstance(key, str) for key in value)
    if kind == "array":
        return isinstance(value, list)
    return isinstance(value, str)  # "text" and enums


def _check_field(container: Any, name: str, kind: Any, optional: bool = False, step: int = 6) -> None:
    """Presence (schema/missing-field), then type (schema/bad-type), then size (schema/digest-size) or enum (schema/enum-unknown)."""
    if name not in container:
        if optional:
            return
        _fail("schema/missing-field", step)
    value = container[name]
    if not _type_ok(value, kind):
        _fail("schema/bad-type", step)
    if kind in ("bstr32", "bstr16") and len(value) != (32 if kind == "bstr32" else 16):
        _fail("schema/digest-size", step)
    if kind in ("bstr32[]", "bstr16[]"):
        size = 32 if kind == "bstr32[]" else 16
        for member in value:
            if not isinstance(member, bytes):
                _fail("schema/bad-type", step)
            if len(member) != size:
                _fail("schema/digest-size", step)
    if isinstance(kind, tuple) and value not in kind:
        _fail("schema/enum-unknown", step)


def _apply_rules(payload: dict[str, Any], rules: tuple[tuple[tuple[str, ...], Any, bool], ...], step: int = 6) -> None:
    for path, kind, optional in rules:
        container: Any = payload
        for key in (path if isinstance(kind, tuple) and kind and isinstance(kind[0], tuple) else path[:-1]):
            if key not in container:  # an absent optional ancestor; its own rule allowed that
                container = None
                break
            container = container[key]
        if container is None:
            continue
        if isinstance(kind, tuple) and kind and isinstance(kind[0], tuple):
            for member in (container if isinstance(container, list) else [container]):  # a boundary wrapper is one map
                if not _type_ok(member, "map"):
                    _fail("schema/bad-type", step)
                _apply_rules(member, kind, step)
        else:
            _check_field(container, path[-1], kind, optional, step)


def _check_transformations(transforms: Any) -> None:
    """Each text-keyed transformation map validates its closed operation enum."""
    for transform in transforms:
        if isinstance(transform, dict) and all(isinstance(key, str) for key in transform):
            _check_field(transform, "operation", TRANSFORMATION_OPERATIONS)
# D-81 (6.7.7): the time an object claims for its own signed act. Credentials,
# delegations, and rotations carry none and take the evaluation time.
SIGNING_TIME_FIELDS = {
    "epoch_manifests": "closed_at", "epoch_events": "occurred_at", "anchors": "accepted_at",
    "merkle_batches": "created_at", "presentations": "delivered_at", "status_snapshots": "produced_at",
    "mediator_countersignatures": "mediator_observed_at",
}


def _signing_time(category: str, payload: dict[str, Any], evaluated_at: int) -> Any:
    if category == "receipts":
        return payload["emission"].get("committed_at")
    if category == "requests":
        freshness = payload.get("freshness")
        return freshness.get("issued_at") if _type_ok(freshness, "map") else None
    field = SIGNING_TIME_FIELDS.get(category)
    return payload.get(field) if field else evaluated_at


def _schema_payload(content_type: str, payload: Any) -> dict[str, Any]:
    if not _type_ok(payload, "map"):
        _fail("schema/bad-type", 6)
    schemas: dict[str, tuple[set[str], set[str]]] = {
        CONTENT_TYPES["credentials"]: ({"v", "credential_id", "subject_kid", "public_key", "issuer_kid", "principal_type", "principal_role", "tenant_id", "site_id", "valid_from", "valid_until", "cose_alg", "curve", "key_usage", "trust_anchor_id", "path", "profile_limits"}, set()),
        CONTENT_TYPES["rotations"]: ({"v", "rotation_id", "predecessor_credential_id", "successor_credential_id", "predecessor_kid", "successor_kid", "effective_at", "tenant_id", "site_id", "continuity_sequence"}, set()),
        CONTENT_TYPES["status_snapshots"]: ({"v", "snapshot_id", "credential_id", "issuer_kid", "produced_at", "next_update", "lease_not_before", "lease_not_after", "profile", "status", "sequence", "tenant_id", "site_id"}, {"revoked_at", "compromise_at"}),
        CONTENT_TYPES["requests"]: ({"v", "request_id", "action_intent_digest", "target_ep_kid", "tenant_id", "site_id", "correlation", "freshness", "legal"}, set()),
        CONTENT_TYPES["delegations"]: ({"v", "delegation_id", "issuer_credential_id", "subject_credential_id", "tenant_id", "site_id", "scope", "not_before", "not_after", "use", "replay_domain", "parent_delegations"}, {"invocation_id"}),
        CONTENT_TYPES["epoch_events"]: ({"v", "event_id", "tenant_id", "site_id", "epoch_owner_kid", "epoch_id", "event_seq", "occurred_at", "event", "body"}, {"previous_event_digest"}),
        CONTENT_TYPES["epoch_manifests"]: ({"manifest_id", "v", "tenant_id", "site_id", "epoch_owner_kid", "epoch_id", "opened_at", "closed_at", "sequence_span", "item_count", "close_reason", "max_duration_s", "late_arrival_policy", "anchor_deadline", "fork_policy", "receipt_index", "anchor_plan"}, {"predecessor_manifest_digest"}),
        CONTENT_TYPES["anchors"]: ({"v", "anchor_id", "target", "tenant_id", "site_id", "epoch_id", "manifest_id", "manifest_digest", "submitted_at", "accepted_at", "anchor_tree_size", "anchor_leaf_index", "anchor_root", "inclusion", "head", "claim"}, {"consistency"}),
        CONTENT_TYPES["merkle_batches"]: ({"v", "batch_id", "tenant_id", "site_id", "epoch_owner_kid", "epoch_id", "signer_kid", "tree_size", "root", "created_at", "claim"}, set()),
        CONTENT_TYPES["mediator_countersignatures"]: ({"v", "countersignature_id", "action_attempt_receipt_digest", "command_digest", "mediator_observed_at"}, set()),
        CONTENT_TYPES["receipts"]: ({"receipt_id", "v", "kind", "issuer_principal_type", "issuer_role", "binding", "emission", "freshness", "legal", "evidence", "parents", "body"}, {"root", "correlation"}),
        CONTENT_TYPES["presentations"]: ({"presentation_id", "presenter_credential_id", "signer_mode", "artifacts", "transforms", "ui_implementation", "ui_version", "delivered_at", "session_id", "approval_scope_digest", "state"}, set()),
    }
    required, optional = schemas[content_type]
    unknown = set(payload) - required - optional
    if unknown:
        _fail("schema/unknown-field", 6)
    if required - set(payload):
        _fail("schema/missing-field", 6)
    if "v" in payload:
        if not isinstance(payload["v"], int) or isinstance(payload["v"], bool):
            _fail("schema/bad-type", 6)
        if payload["v"] != 2:
            _fail("schema/version-wrong", 6)
    if content_type == CONTENT_TYPES["credentials"]:
        # CDDL order; the fixed-size ids stay last (pinned: principal_type before ids).
        _check_field(payload, "principal_type", PRINCIPAL_TYPES)
        _check_field(payload, "principal_role", PRINCIPAL_ROLES)
        _check_field(payload, "valid_from", "uint")
        _check_field(payload, "valid_until", "uint")
        # D-73: closed algorithm enum, checked in harness order (type, then value).
        if not isinstance(payload.get("cose_alg"), int) or isinstance(payload.get("cose_alg"), bool) \
                or not isinstance(payload.get("curve"), str):
            _fail("schema/bad-type", 6)
        if payload["cose_alg"] != -7 or payload["curve"] != "P-256":
            _fail("schema/enum-unknown", 6)
        _check_field(payload, "key_usage", KEY_USAGES)
        if not isinstance(payload["path"], list):
            _fail("schema/bad-type", 6)
        if len(payload["path"]) > LIMITS["credential_path_length"]:  # amendment (ah)
            _fail("schema/out-of-range", 6)
    if content_type == CONTENT_TYPES["presentations"]:
        # CDDL order; presentation_id stays last (pinned: state before ids).
        _check_field(payload, "signer_mode", ("approver_originated", "ep_authenticated_session"))
        _check_field(payload, "transforms", "array")
        for transform in payload["transforms"]:
            if not _type_ok(transform, "map"):
                _fail("schema/bad-type", 6)
        _check_transformations(payload["transforms"])
        _check_field(payload, "delivered_at", "uint")
        _check_field(payload, "state", ("assembled", "delivered", "rendered", "human_approved"))
    if content_type == CONTENT_TYPES["status_snapshots"]:
        # D-81, in CDDL field order: the four times, then the closed status
        # enum (type first), the instant the status requires, then sequence.
        if any(not _uint(payload[field]) for field in ("produced_at", "next_update", "lease_not_before", "lease_not_after")):
            _fail("schema/bad-type", 6)
        if not isinstance(payload["profile"], str):
            _fail("schema/bad-type", 6)
        if payload["profile"] not in ("AAR-1", "AAR-2", "AAR-2A", "AAR-3"):
            _fail("schema/enum-unknown", 6)
        if not isinstance(payload["status"], str):
            _fail("schema/bad-type", 6)
        if payload["status"] not in ("good", "revoked", "compromised", "unknown"):
            _fail("schema/enum-unknown", 6)
        instant = STATUS_INSTANTS.get(payload["status"])
        if instant is not None and instant not in payload:
            _fail("schema/missing-field", 6)
        if any(field in payload and not _uint(payload[field]) for field in STATUS_INSTANTS.values()):
            _fail("schema/bad-type", 6)
        if not _uint(payload["sequence"]):
            _fail("schema/bad-type", 6)
    if content_type == CONTENT_TYPES["requests"]:
        freshness = payload["freshness"]
        if not _type_ok(freshness, "map"):
            _fail("schema/bad-type", 6)
        for field in ("issued_at", "expires_at"):
            if field not in freshness:
                _fail("schema/missing-field", 6)
            if not _uint(freshness[field]):
                _fail("schema/bad-type", 6)
    # D-82 part 8: the bounded table, in CDDL order; receipts run it after the
    # kind enum below, every other production before its fixed-size ids.
    if content_type != CONTENT_TYPES["receipts"]:
        _apply_rules(payload, FIELD_RULES.get(content_type, ()))
    if content_type == CONTENT_TYPES["merkle_batches"] and not 1 <= payload["tree_size"] <= LIMITS["merkle_batch_leaves"]:
        _fail("schema/out-of-range", 6)  # amendment (ak): the CDDL bound
    for field, size in PAYLOAD_FIXED_FIELDS[content_type]:
        value = payload.get(field)
        if not isinstance(value, bytes):
            _fail("schema/bad-type", 6)
        if len(value) != size:
            _fail("schema/digest-size", 6)
    if content_type == CONTENT_TYPES["receipts"]:
        # Container types are pinned here so every later step may index them
        # without a guard; malformed input must yield a signed schema verdict,
        # never an unhandled exception (harness verifier.ts parity).
        if payload.get("kind") not in NODE_KINDS:
            _fail("schema/enum-unknown", 6)
        _apply_rules(payload, FIELD_RULES[content_type])
    if content_type == CONTENT_TYPES["receipts"]:
        body = payload["body"]
        if payload["kind"] == "observation":
            consumption = body.get("consumption")
            if not _type_ok(consumption, "map"):
                _fail("schema/bad-type", 6)
            if "items" not in consumption:
                _fail("schema/missing-field", 6)
            items = consumption["items"]
            if not isinstance(items, list):
                _fail("schema/bad-type", 6)
            if not 1 <= len(items) <= 4096:
                _fail("schema/out-of-range", 6)
            for item in items:
                if not isinstance(item, dict) or any(not isinstance(key, str) for key in item):
                    continue  # Step 10 owns item shape.
                if isinstance(item.get("transformations"), list):  # a non-list is left to step 10
                    _check_transformations(item["transformations"])
                if "disposition" not in item:
                    _fail("schema/missing-field", 6)
                for name, allowed in (("disposition", {"used", "discarded"}), ("origin", INPUT_ORIGINS)):
                    if name == "origin" and name not in item:
                        continue
                    if not isinstance(item.get(name), str):
                        _fail("schema/bad-type", 6)
                    if item[name] not in allowed:
                        _fail("schema/enum-unknown", 6)
            _check_field(body, "observed_at", "uint")
            if "native_attestations" in body:
                if not isinstance(body["native_attestations"], list):
                    _fail("schema/bad-type", 6)
                for attestation in body["native_attestations"]:
                    if not _type_ok(attestation, "map"):
                        _fail("schema/bad-type", 6)
                    _check_field(attestation, "format", ("axis_signed_video", "c2pa", "other"))
        if payload["kind"] == "inference" and "origins" in body:
            origins = body["origins"]
            if not isinstance(origins, list):
                _fail("schema/bad-type", 6)
            if not 1 <= len(origins) <= 5:
                _fail("schema/out-of-range", 6)
            for origin in origins:
                if not isinstance(origin, str):
                    _fail("schema/bad-type", 6)
                if origin not in INPUT_ORIGINS:
                    _fail("schema/enum-unknown", 6)
            if len(set(origins)) != len(origins):
                _fail("schema/duplicate-entry", 6)
            encoded = [dumps(origin) for origin in origins]
            if encoded != sorted(encoded):
                _fail("schema/unsorted-set", 6)
        if payload["kind"] == "action_attempt":
            action = body.get("action")
            if not _type_ok(action, "map"):
                _fail("schema/bad-type", 6)
            _check_field(action, "informational_reversibility", ("reversible", "irreversible"))
            _check_field(action, "operational_reversibility", ("reversible", "lossy", "irreversible"))
            command = body.get("command")
            if not _type_ok(command, "map"):
                _fail("schema/bad-type", 6)
            if "excluded_fields" not in command:
                _fail("schema/missing-field", 6)
            excluded = command["excluded_fields"]
            if not isinstance(excluded, list):
                _fail("schema/bad-type", 6)
            if len(excluded) > 32:
                _fail("schema/out-of-range", 6)
            for field in excluded:
                if not _type_ok(field, "map"):
                    _fail("schema/bad-type", 6)
                required = {"name", "reason", "value_commitment"}
                if set(field) - required:
                    _fail("schema/unknown-field", 6)
                if required - set(field):
                    _fail("schema/missing-field", 6)
                if not isinstance(field["name"], str):
                    _fail("schema/bad-type", 6)
                if not 1 <= len(field["name"].encode("utf-8")) <= 128:
                    _fail("schema/string-size", 6)
                if not isinstance(field["reason"], str):
                    _fail("schema/bad-type", 6)
                if not isinstance(field["value_commitment"], bytes):
                    _fail("schema/bad-type", 6)
                if len(field["value_commitment"]) != 32:
                    _fail("schema/digest-size", 6)
                if field["reason"] not in ("secret", "volatile_header", "transport_generated"):
                    _fail("schema/enum-unknown", 6)
        if payload["kind"] == "dispatch":
            _check_field(body, "dispatched_at", "uint")
        if payload["kind"] == "outcome_observation":
            _check_field(body, "observed_at", "uint")
            _check_field(body, "state", ("consistent", "contradicted", "unknown"))
    if content_type == CONTENT_TYPES["epoch_manifests"]:
        plan = payload.get("anchor_plan")
        if not _type_ok(plan, "map") or not _type_ok(plan.get("independence"), "map"):
            _fail("schema/bad-type", 6)
        independence = plan["independence"]
        if "basis" not in independence:
            _fail("schema/missing-field", 6)
        if not isinstance(independence["basis"], str):
            _fail("schema/bad-type", 6)
        if independence["basis"] not in ("distinct_operator_and_failure_domain", "same_operator"):
            _fail("schema/enum-unknown", 6)
        if "groups" not in independence:  # round 8: the groups and their members join the table
            _fail("schema/missing-field", 6)
        if not isinstance(independence["groups"], list):
            _fail("schema/bad-type", 6)
        for group in independence["groups"]:
            if not _type_ok(group, "map"):
                _fail("schema/bad-type", 6)
            _apply_rules(group, INDEPENDENCE_GROUP_RULES)
        # Amendment (ap): a repeated target_id among the well-formed plan targets (no
        # step-6 targets shape exists; malformed targets stay unplanned at step 17).
        targets = plan.get("targets")
        ids = [target["target_id"] for target in targets if _type_ok(target, "map") and _bstr(target.get("target_id"), 16)] if isinstance(targets, list) else []
        if len(set(ids)) != len(ids):
            _fail("schema/duplicate-entry", 6)
    if content_type == CONTENT_TYPES["epoch_events"]:
        for name in {"open": ("first_epoch_seq",), "close": ("last_epoch_seq", "anchor_deadline"), "anchor_submitted": ("submitted_at",)}.get(payload["event"], ()):
            _check_field(payload["body"], name, "uint")
    if content_type == CONTENT_TYPES["mediator_countersignatures"] and not _uint(payload.get("mediator_observed_at")):
        _fail("countersign/invalid", 6)
    return payload


def _required_usage(category: str, payload: dict[str, Any]) -> str:
    if category in {"credentials", "rotations"}:
        return "credential_issuing"
    if category == "status_snapshots":
        return "status_signing"
    if category == "requests":
        return "agent_signing"
    if category == "delegations":
        return "authority_signing"
    if category in {"epoch_events", "epoch_manifests", "merkle_batches"}:
        return "ep_signing"
    if category == "anchors":
        return "anchor_signing"
    if category == "mediator_countersignatures":
        return "outcome_signing"
    if category == "presentations":
        return "approver_signing" if payload.get("signer_mode") == "approver_originated" else "ep_signing"
    roles = {
        "agent": "agent_signing",
        "enforcement_point": "ep_signing",
        "outcome_observer": "outcome_signing",
    }
    role = payload.get("issuer_role")
    return roles.get(role, "") if isinstance(role, str) else ""  # amendment (q): a non-text role matches no role


def _validate_envelope(state: State, category: str, index: int, value: Any,
                       enclosing_kid: bytes | None = None) -> Envelope:
    expected_type = CONTENT_TYPES[category]
    if not (isinstance(value, list) and len(value) == 2 and isinstance(value[0], bytes) and isinstance(value[1], bytes)):
        _fail("schema/bad-type", 6)
    payload_bytes, cose_bytes = value
    cose = _parse_embedded(cose_bytes, cose=True)
    if not (isinstance(cose, list) and len(cose) == 4 and isinstance(cose[0], bytes)
            and isinstance(cose[1], dict) and isinstance(cose[3], bytes)):
        _fail("cose/bad-structure", 6)
    protected_bytes = cose[0]
    try:
        protected = loads(protected_bytes)
    except CBORError:
        _fail("cose/protected-not-map", 6)
    if not isinstance(protected, dict):
        _fail("cose/protected-not-map", 6)
    allowed_labels = {1, 3, 4}
    if category == "receipts":
        allowed_labels |= set(range(-70006, -69999))
    if any(label not in allowed_labels for label in protected):
        _fail("cose/protected-label", 6)
    if 1 not in protected:
        _fail("cose/alg-missing", 6)
    if protected[1] != -7:
        _fail("cose/alg-wrong", 6)
    if 3 not in protected:
        _fail("cose/content-type-missing", 6)
    if protected[3] != expected_type:
        _fail("cose/content-type-wrong", 6)
    if 4 not in protected:
        _fail("cose/kid-missing", 6)
    if not _bstr(protected[4], 32):
        _fail("schema/digest-size", 6)
    if category == "receipts" and any(label not in protected for label in range(-70006, -69999)):
        _fail("cose/receipt-coordinate-missing", 6)
    if 1 in cose[1]:
        _fail("cose/alg-in-unprotected", 6)
    if cose[1]:
        _fail("cose/unprotected-not-empty", 6)
    if cose[2] is not None:
        _fail("cose/payload-not-detached", 6)
    signature = cose[3]
    if len(signature) != 64:
        _fail("sig/der-encoding" if is_der_ecdsa_signature(signature) else "sig/bad-length", 6)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r == 0 or s == 0:
        _fail("sig/zero-rs", 6)
    if s > N // 2:
        _fail("sig/high-s", 6)

    payload = _schema_payload(expected_type, _parse_embedded(payload_bytes))
    envelope = Envelope(category, index, value, dumps(value), payload_bytes, payload,
                        cose_bytes, cose, protected_bytes, protected)
    credential = state.credentials_by_kid.get(protected[4])
    if credential is None:
        _fail("key/not-found", 6, indeterminate=True)
    claims = credential.payload
    public_key = claims.get("public_key")
    if not isinstance(public_key, bytes):
        _fail("countersign/credential-invalid" if category == "mediator_countersignatures" else "schema/bad-type", 6)
    if hashes.sha256(public_key) != claims.get("subject_kid"):
        _fail("credential/kid-key-mismatch", 6)
    try:
        parse_p256_spki(public_key)
    except ValueError:
        _fail("key/not-p256", 6)
    usage = _required_usage(category, payload)
    if claims.get("key_usage") != usage or (category == "mediator_countersignatures" and claims.get("principal_role") != "outcome_observer"):
        if category == "receipts":
            _fail("receipt/signer-role-mismatch", 6)
        _fail("credential/usage-mismatch", 6)
    if category == "credentials":
        if protected[4] != payload.get("issuer_kid") or (not payload.get("path") and protected[4] != payload.get("subject_kid")):
            _fail("credential/usage-mismatch", 6)
    elif category == "status_snapshots":
        if protected[4] != payload.get("issuer_kid"):
            _fail("credential/usage-mismatch", 6)
    elif category == "anchors":
        target = payload.get("target")
        if protected[4] != (target.get("anchor_kid") if _type_ok(target, "map") else None):
            _fail("credential/usage-mismatch", 6)
    elif category == "delegations" or (category == "presentations" and payload.get("signer_mode") == "approver_originated"):
        field = "issuer_credential_id" if category == "delegations" else "presenter_credential_id"
        credential_id = payload.get(field)
        declared = state.credentials_by_id.get(credential_id) if isinstance(credential_id, bytes) else None
        if declared is None or protected[4] != declared.payload.get("subject_kid"):
            _fail("credential/usage-mismatch", 6)
    elif category == "presentations" and payload.get("signer_mode") == "ep_authenticated_session":
        if protected[4] != enclosing_kid:
            _fail("credential/usage-mismatch", 6)
    elif category in {"epoch_events", "epoch_manifests", "merkle_batches"}:
        if protected[4] != payload.get("epoch_owner_kid"):
            _fail("credential/usage-mismatch", 6)
        if category == "merkle_batches" and payload.get("signer_kid") != payload.get("epoch_owner_kid"):
            _fail("credential/usage-mismatch", 6)
    if state.bundle is not None:
        selector = state.bundle["selector"]
        if claims.get("tenant_id") != selector["tenant_id"] or claims.get("site_id") != selector["site_id"]:
            _fail("credential/usage-mismatch", 6)
    signing_time = _signing_time(category, payload, state.evaluated_at)
    if not _uint(signing_time):
        _fail("schema/bad-type", 6)
    if not _uint(claims.get("valid_from")) or not _uint(claims.get("valid_until")):
        _fail("countersign/credential-invalid" if category == "mediator_countersignatures" else "schema/bad-type", 6)
    if signing_time < claims["valid_from"]:
        _fail("credential/not-yet-valid", 6)
    if signing_time >= claims["valid_until"]:
        _fail("credential/expired", 6)
    if category == "receipts":
        binding = payload.get("binding", {})
        emission = payload.get("emission", {})
        coordinates = {
            -70000: payload.get("issuer_principal_type"),
            -70001: binding.get("tenant_id"), -70002: binding.get("site_id"),
            -70003: binding.get("epoch_id"), -70004: binding.get("epoch_seq"),
            -70005: emission.get("issuer_seq"), -70006: payload.get("issuer_role"),
        }
        if any(protected[label] != coordinate for label, coordinate in coordinates.items()):
            _fail("cose/receipt-coordinate-mismatch", 6)

    sig_structure = dumps(["Signature1", protected_bytes, b"", payload_bytes])
    if not verify_es256(public_key, sig_structure, signature):
        _fail("sig/verify-failed", 6)
    return envelope


def _envelope_checks(state: State) -> None:
    assert state.bundle is not None
    _preparse_payloads(state)
    mediator_kids = _raw_mediator_kids(state)
    for category in ARTIFACT_ORDER:
        for index, value in enumerate(state.bundle["artifacts"].get(category, [])):
            try:
                envelope = _validate_envelope(state, category, index, value)
            except ValidationError as exc:
                if category == "mediator_countersignatures":
                    credential_error = exc.code.startswith("credential/") or exc.code.startswith("key/") or exc.code == "countersign/credential-invalid"
                    _fail("countersign/credential-invalid" if credential_error else "countersign/invalid", 6)
                if category == "credentials":
                    payload = _loose_payload(value)
                    subject_kid = payload.get("subject_kid") if _type_ok(payload, "map") else None
                    if isinstance(subject_kid, bytes) and subject_kid in mediator_kids:
                        _fail("countersign/credential-invalid", 6)
                raise
            state.envelopes[category].append(envelope)
            if category == "credentials":
                state.credentials_by_id[envelope.payload["credential_id"]] = envelope
            elif category == "receipts":
                state.receipts_by_id[envelope.payload["receipt_id"]] = envelope
                # Amendment (g): nested validation is decided by presence, so a
                # present null reaches the envelope checks (harness parity).
                body = envelope.payload["body"]
                if envelope.payload["kind"] == "authorization" and "delegation" in body:
                    nested = _validate_envelope(state, "delegations", index, body["delegation"])
                    state.embedded_delegations[envelope.payload["receipt_id"]] = nested
                if "presentation" in body:
                    nested = _validate_envelope(state, "presentations", index, body["presentation"], envelope.protected[4])
                    state.envelopes["presentations"].append(nested)
    for payload in state.bundle["artifacts"]["manifest_payloads"]:
        state.payloads_by_digest[payload["digest"]] = payload


def _receipt_commitments(receipt: dict[str, Any]) -> None:
    """Amendment (ac): the commitments at their CDDL positions only, in harness receiptHashes order.
    A non-bstr hash preimage is schema/bad-type (hashing never throws); a non-bstr compared digest is a mismatch."""
    body, kind = receipt["body"], receipt["kind"]
    if kind == "observation":
        consumption = body.get("consumption")
        if _type_ok(consumption, "map") and "manifest_digest" in consumption and "items" in consumption:
            if hashes.consumption_manifest_digest(consumption) != consumption["manifest_digest"]:
                _fail("hash/mismatch", 7)
    if kind == "inference":
        conclusion = body.get("conclusion")
        if _type_ok(conclusion, "map") and {"canonical_cbor", "digest", "schema_id"} <= set(conclusion):
            if not isinstance(conclusion["canonical_cbor"], bytes):
                _fail("schema/bad-type", 7)
            if hashes.sha256(conclusion["canonical_cbor"]) != conclusion["digest"]:
                _fail("hash/mismatch", 7)
    if kind == "authorization":
        decision = body.get("decision")
        if _type_ok(decision, "map") and {"decision_commitment", "policy_set_root", "evaluated_inputs"} <= set(decision):
            if hashes.decision_commitment(decision) != decision["decision_commitment"]:
                _fail("hash/mismatch", 7)
    if kind == "action_attempt":
        action = body.get("action")
        if _type_ok(action, "map") and {"parameters_cbor", "parameters_digest"} <= set(action):
            if not isinstance(action["parameters_cbor"], bytes):
                _fail("schema/bad-type", 7)
            if hashes.sha256(action["parameters_cbor"]) != action["parameters_digest"]:
                _fail("hash/mismatch", 7)
        command = body.get("command")
        if _type_ok(command, "map") and {"command_id", "canonical_command", "command_digest"} <= set(command):
            if not isinstance(command["canonical_command"], bytes):
                _fail("schema/bad-type", 7)
            if hashes.sha256(command["canonical_command"]) != command["command_digest"]:
                _fail("hash/mismatch", 7)
            if hashes.command_id(command) != command["command_id"]:
                _fail("hash/mismatch", 7)


def _content_commitments(state: State) -> None:
    assert state.bundle is not None
    artifact_fields = {
        "credentials": "credential_id", "rotations": "rotation_id",
        "status_snapshots": "snapshot_id", "delegations": "delegation_id",
        "epoch_events": "event_id", "epoch_manifests": "manifest_id",
        "anchors": "anchor_id", "merkle_batches": "batch_id",
        "mediator_countersignatures": "countersignature_id",
        "presentations": "presentation_id",
    }
    # Amendment (am): artifacts are visited in the step-6 order; a receipt's
    # commitments, then its embedded delegation's and presentation's ids, before the next artifact.
    for category in ARTIFACT_ORDER:
        for envelope in state.envelopes[category]:
            payload = envelope.payload
            if category == "receipts":
                if hashes.receipt_id(payload, envelope.protected_bytes) != payload["receipt_id"]:
                    _fail("identity/receipt-id-mismatch", 7)
                _receipt_commitments(payload)
                nested = [state.embedded_delegations[payload["receipt_id"]]] if payload["receipt_id"] in state.embedded_delegations else []
                nested += [item for item in state.envelopes["presentations"] if item.index == envelope.index]
                for item in nested:
                    field = artifact_fields[item.category]
                    if hashes.artifact_id(item.payload, field) != item.payload[field]:
                        _fail("identity/artifact-id-mismatch", 7)
            elif category in artifact_fields:
                field = artifact_fields[category]
                if hashes.artifact_id(payload, field) != payload[field]:
                    _fail("countersign/digest-mismatch" if category == "mediator_countersignatures" else "identity/artifact-id-mismatch", 7)

    for payload in state.bundle["artifacts"]["manifest_payloads"]:
        if hashes.sha256(payload["canonical_bytes"]) != payload["digest"]:
            _fail("hash/mismatch", 7)
    # Amendment (ac): the canonical manifest references at their CDDL positions
    # (an inference body's three manifests) are digest/media-type/length commitments.
    for envelope in state.envelopes["receipts"]:
        if envelope.payload["kind"] != "inference":
            continue
        for name in ("prompt_manifest", "retrieval_manifest", "tool_transcript_manifest"):
            reference = envelope.payload["body"].get(name)
            if not _type_ok(reference, "map") or not _bstr(reference.get("digest"), 32):
                continue
            supplied = state.payloads_by_digest.get(reference["digest"])
            if supplied is None:
                _fail("manifest/payload-missing", 7)
            if supplied["media_type"] != reference.get("media_type"):
                _fail("manifest/media-type-mismatch", 7)
            if not _uint(reference.get("byte_length")) or len(supplied["canonical_bytes"]) != reference["byte_length"]:
                _fail("hash/mismatch", 7)

    requests = {envelope.payload["request_id"]: envelope for envelope in state.envelopes["requests"]}
    for envelope in state.envelopes["receipts"]:
        root = envelope.payload.get("root")
        if not _type_ok(root, "map") or root.get("kind") != "agent_request":
            continue
        request = requests.get(root.get("request_id")) if _bstr(root.get("request_id"), 16) else None
        if request is None:
            _fail("bundle/dependency-missing", 7)
        if hashes.sha256(request.payload_bytes) != root.get("request_commitment"):
            _fail("request/commitment-mismatch", 7)
        # D-60. A correct commitment proves these are the bytes the agent signed; it
        # does not prove the agent signed them for this tenant, this site, or this
        # enforcement point. The request duplicates coordinates the receipt binding
        # also carries, so require agreement -- the same rule every other duplicated
        # coordinate pair already gets. Both sides are type-guarded: a missing or
        # non-conforming coordinate is treated as disagreement (normative,
        # CONFORMANCE step 7); untrusted input must yield a signed verdict, never
        # an unhandled exception.
        binding = envelope.payload.get("binding")
        claims = request.payload

        def _coordinate(container: object, key: str, size: int) -> bytes | None:
            value = container.get(key) if _type_ok(container, "map") else None
            return value if isinstance(value, bytes) and len(value) == size else None

        pairs = (
            (_coordinate(claims, "tenant_id", 16), _coordinate(binding, "tenant_id", 16)),
            (_coordinate(claims, "site_id", 16), _coordinate(binding, "site_id", 16)),
            (_coordinate(claims, "target_ep_kid", 32), _coordinate(binding, "epoch_owner_kid", 32)),
            (_coordinate(claims.get("correlation"), "target_ep_kid", 32), _coordinate(claims, "target_ep_kid", 32)),
        )
        for left, right in pairs:
            if left is None or right is None or left != right:
                _fail("request/coordinate-mismatch", 7)


def _credential_lifecycle(state: State) -> None:
    assert state.bundle is not None
    credentials = state.envelopes["credentials"]
    store = state.bundle["trust_inputs"]["trust_store"]
    roots = {root["root_kid"]: root for root in store["roots"]}
    by_id = {envelope.payload["credential_id"]: envelope for envelope in credentials}
    uses, used_kids = relying_party.signer_uses(state)
    mediator_kids = {envelope.protected[4] for envelope in state.envelopes["mediator_countersignatures"]}

    role_kids: dict[str, set[bytes]] = defaultdict(set)
    for envelope in credentials:
        role = envelope.payload["principal_role"]
        if role in {"agent", "enforcement_point", "authority_source"}:
            role_kids[role].add(envelope.payload["subject_kid"])
    roles = tuple(role_kids)
    for index, left in enumerate(roles):
        for right in roles[index + 1:]:
            if role_kids[left] & role_kids[right]:
                _fail("credential/role-key-reuse", 8)

    terminals: dict[bytes, dict[str, Any]] = {}
    for envelope in credentials:
        credential = envelope.payload
        mediator_credential = credential["subject_kid"] in mediator_kids
        path = credential["path"]
        if path and credential["subject_kid"] in roots:
            _fail("countersign/credential-invalid" if mediator_credential else "credential/path-invalid", 8)
        seen = {credential["credential_id"]}
        expected_issuer = credential["issuer_kid"]
        for credential_id in path:
            parent = by_id.get(credential_id) if _bstr(credential_id, 32) else None  # amendment (q)
            if parent is None or credential_id in seen:
                _fail("countersign/credential-invalid" if mediator_credential else "credential/path-invalid", 8)
            seen.add(credential_id)
            if parent.payload["subject_kid"] != expected_issuer:
                _fail("countersign/credential-invalid" if mediator_credential else "credential/path-invalid", 8)
            expected_issuer = parent.payload["issuer_kid"]
        terminals[credential["credential_id"]] = by_id[path[-1]].payload if path else credential

    relying_party.accept_roots(state.configuration, credentials, terminals, roots, used_kids, mediator_kids)

    # D-80: bind every record (ids/kids, predecessor's issuer signs, tenant and
    # site) in array order before any ordering check.
    rotations = [envelope.payload for envelope in state.envelopes["rotations"]]
    for envelope in state.envelopes["rotations"]:
        rotation = envelope.payload
        predecessor = by_id.get(rotation["predecessor_credential_id"]) if _bstr(rotation["predecessor_credential_id"], 32) else None
        successor = by_id.get(rotation["successor_credential_id"]) if _bstr(rotation["successor_credential_id"], 32) else None
        if predecessor is None or successor is None \
                or predecessor.payload["subject_kid"] != rotation["predecessor_kid"] \
                or successor.payload["subject_kid"] != rotation["successor_kid"] \
                or envelope.protected[4] != predecessor.payload["issuer_kid"] \
                or any(credential.payload["tenant_id"] != rotation["tenant_id"]
                       or credential.payload["site_id"] != rotation["site_id"]
                       for credential in (predecessor, successor)):
            _fail("credential/rotation-invalid", 8)
    by_pair: dict[tuple[bytes, bytes], list[dict[str, Any]]] = defaultdict(list)
    for rotation in rotations:
        by_pair[(rotation["tenant_id"], rotation["site_id"])].append(rotation)
    for items in by_pair.values():
        ordered = sorted(items, key=lambda item: (item["effective_at"], item["continuity_sequence"]))
        for previous, current in zip(ordered, ordered[1:]):
            if current["continuity_sequence"] <= previous["continuity_sequence"] \
                    or current["effective_at"] <= previous["effective_at"]:
                _fail("credential/rotation-rollback", 8)

    snapshot_envelopes = state.envelopes["status_snapshots"]
    for envelope in snapshot_envelopes:
        snapshot = envelope.payload
        profile = snapshot["profile"]
        max_age = 300 if profile in {"AAR-2A", "AAR-3"} else 86_400
        max_lease = 3_600 if profile in {"AAR-2A", "AAR-3"} else 86_400
        if snapshot["lease_not_after"] - snapshot["lease_not_before"] > max_lease:
            _fail("credential/lease-too-long", 8)
        if state.evaluated_at - snapshot["produced_at"] > max_age \
                or state.evaluated_at >= snapshot["next_update"]:
            _fail("credential/status-stale", 8)
        # D-81: judged at use time; an unresolved subject fails closed as if
        # used at the evaluation time.
        instant = STATUS_INSTANTS.get(snapshot["status"])
        if instant is not None:
            credential = by_id.get(snapshot["credential_id"]) if _bstr(snapshot["credential_id"], 32) else None
            used = [state.evaluated_at] if credential is None else uses.get(credential.payload["subject_kid"], [])
            if any(use >= snapshot[instant] for use in used):
                _fail(f"credential/{snapshot['status']}", 8)
        if snapshot["status"] == "unknown":
            _fail("credential/status-unknown", 8)
        if state.evaluated_at < snapshot["lease_not_before"]:
            _fail("credential/not-yet-valid", 8)
        if state.evaluated_at >= snapshot["lease_not_after"]:
            _fail("credential/lease-expired", 8)

    snapshots = {envelope.payload["snapshot_id"]: envelope.payload for envelope in snapshot_envelopes}
    for snapshot in snapshots.values():
        if not _bstr(snapshot["credential_id"], 32) or snapshot["credential_id"] not in by_id:
            _fail("credential/status-missing", 8)
    for receipt in state.envelopes["receipts"]:
        decision = receipt.payload.get("body", {}).get("decision")
        if not _type_ok(decision, "map") or not isinstance(decision.get("status_snapshot_ids"), list):
            continue  # a non-array is skipped (harness parity)
        for snapshot_id in decision["status_snapshot_ids"]:
            if not _bstr(snapshot_id, 32) or snapshot_id not in snapshots:
                _fail("credential/status-missing", 8)


def _emission_identity(state: State) -> None:
    observations: list[dict[str, Any]] = []
    for envelope in state.envelopes["receipts"]:
        receipt = envelope.payload
        # Identity coordinates are indexed as map keys below; pin their types
        # first so malformed input yields a signed verdict, never an unhashable
        # TypeError (harness validateReceiptIdentity parity).
        if not _uint(receipt["emission"].get("issuer_seq")):
            _fail("schema/bad-type", 9)
        if not (_bstr(receipt["binding"].get("epoch_owner_kid"), 32)
                and _uint(receipt["binding"].get("epoch_id"))
                and _uint(receipt["binding"].get("epoch_seq"))):
            _fail("schema/bad-type", 9)
        observations.append({
            "issuer_kid": envelope.protected[4],
            "issuer_seq": receipt["emission"]["issuer_seq"],
            "epoch_owner_kid": receipt["binding"]["epoch_owner_kid"],
            "epoch_id": receipt["binding"]["epoch_id"],
            "epoch_seq": receipt["binding"]["epoch_seq"],
            "receipt_id": receipt["receipt_id"],
            "envelope_digest": hashes.sha256(envelope.envelope_bytes),
        })

    by_receipt: dict[bytes, bytes] = {}
    by_issuer_coordinate: dict[tuple[bytes, int], bytes] = {}
    by_epoch_coordinate: dict[tuple[bytes, int, int], bytes] = {}
    for item in observations:
        receipt_id = item["receipt_id"]
        if receipt_id in by_receipt and by_receipt[receipt_id] != item["envelope_digest"]:
            _fail("identity/reuse", 9)
        by_receipt[receipt_id] = item["envelope_digest"]
        issuer_coordinate = item["issuer_kid"], item["issuer_seq"]
        epoch_coordinate = item["epoch_owner_kid"], item["epoch_id"], item["epoch_seq"]
        if issuer_coordinate in by_issuer_coordinate and by_issuer_coordinate[issuer_coordinate] != receipt_id:
            _fail("identity/coordinate-equivocation", 9)
        if epoch_coordinate in by_epoch_coordinate and by_epoch_coordinate[epoch_coordinate] != receipt_id:
            _fail("identity/coordinate-equivocation", 9)  # amendment (ah)
        by_issuer_coordinate[issuer_coordinate] = receipt_id
        by_epoch_coordinate[epoch_coordinate] = receipt_id

    if state.prior_state is None:
        state.stateful_checks = "not_evaluated"
        return
    state.stateful_checks = "evaluated"
    for prior in state.prior_state.get("prior_emissions", []):
        prior_id = bytes.fromhex(prior["receipt_id"])
        prior_digest = bytes.fromhex(prior["envelope_digest"])
        for item in observations:
            if item["receipt_id"] == prior_id and item["envelope_digest"] != prior_digest:
                _fail("identity/reuse", 9)
            if item["issuer_kid"] == bytes.fromhex(prior["issuer_kid"]) \
                    and item["issuer_seq"] < prior["issuer_seq"]:
                _fail("identity/issuer-sequence-rollback", 9)
            if item["epoch_owner_kid"] == bytes.fromhex(prior["epoch_owner_kid"]) \
                    and item["epoch_id"] == prior["epoch_id"] \
                    and item["epoch_seq"] <= prior["epoch_seq"]:
                _fail("identity/epoch-sequence-rollback", 9)


def _body_kind(body: Any) -> str | None:
    if not _type_ok(body, "map"):
        return None
    # Marker sets mirror the harness bodyKind conjunctions exactly, so a body
    # missing one of the fields the per-kind checks index is a kind/body
    # mismatch at step 10 in both implementations, never a KeyError.
    markers = (
        (("source_device", "consumption"), "observation"),
        (("model", "conclusion"), "inference"),
        (("decision", "delegation"), "authorization"),
        (("action", "command", "disposition"), "action_attempt"),
        (("attempt_id", "dispatched_at"), "dispatch"),
        (("observer", "observation_commitment"), "outcome_observation"),
    )
    found = [kind for keys, kind in markers if all(key in body for key in keys)]
    return found[0] if len(found) == 1 else None


def _receipt_semantics(state: State) -> None:
    payload_digests = set(state.payloads_by_digest)
    for envelope in state.envelopes["receipts"]:
        receipt = envelope.payload
        kind = receipt["kind"]
        body = receipt["body"]
        if _body_kind(body) != kind:
            _fail("receipt/kind-body-mismatch", 10)
        role_matrix = {
            "observation": {"agent", "enforcement_point", "outcome_observer"},
            "inference": {"agent"},
            "authorization": {"enforcement_point"},
            "action_attempt": {"enforcement_point"},
            "dispatch": {"enforcement_point"},
            "outcome_observation": {"outcome_observer"},
        }
        if receipt["issuer_role"] not in role_matrix[kind]:
            _fail("receipt/signer-role-mismatch", 10)

        evidence = receipt["evidence"]
        provenance_present = _type_ok(evidence.get("provenance"), "map")
        outcome_present = _type_ok(evidence.get("outcome"), "map")
        if provenance_present != (kind == "inference"):
            _fail("evidence/provenance-class-unsatisfied", 10)
        if outcome_present != (kind in {"action_attempt", "dispatch", "outcome_observation"}):
            _fail("evidence/outcome-class-unsatisfied", 10)
        if outcome_present:
            allowed = {
                "action_attempt": {"accepted"}, "dispatch": {"dispatched"},
                "outcome_observation": {"device_acknowledged", "independently_sensed", "contradicted", "unknown"},
            }
            if evidence["outcome"].get("level") not in allowed[kind]:
                _fail("evidence/outcome-class-unsatisfied", 10)

        # Ordinals and direct manifest cross-references are checked after hashes.
        if kind == "observation":
            # Nested containers are pinned before indexing (harness parity):
            # malformed interiors yield a signed verdict, never a TypeError.
            consumption = body["consumption"]
            if not _type_ok(consumption, "map") or not isinstance(consumption.get("items"), list):
                _fail("schema/bad-type", 10)
            items = consumption["items"]
            ordinals = [item.get("ordinal") if _type_ok(item, "map") and _uint(item.get("ordinal")) else None for item in items]
            if ordinals != list(range(len(items))):
                _fail("receipt/manifest-inconsistent", 10)
            for item in items:
                transforms = item.get("transformations", [])
                if not isinstance(transforms, list):
                    continue
                if [transform.get("ordinal") if _type_ok(transform, "map") and _uint(transform.get("ordinal")) else None
                        for transform in transforms] != list(range(len(transforms))):
                    _fail("receipt/manifest-inconsistent", 10)

        if kind == "inference":
            reference = body.get("consumption_manifest_id")
            resolved = isinstance(reference, bytes) and reference in payload_digests
            for parent in receipt["parents"]:
                if not _type_ok(parent, "map") or parent.get("edge_type") != "derived_from":
                    continue
                parent_id = parent.get("parent_id")
                parent_envelope = state.receipts_by_id.get(parent_id) if isinstance(parent_id, bytes) else None
                if parent_envelope and parent_envelope.payload["kind"] == "observation":
                    parent_consumption = parent_envelope.payload["body"].get("consumption")
                    if _type_ok(parent_consumption, "map"):
                        resolved |= parent_consumption.get("manifest_digest") == reference
            if not resolved:
                _fail("receipt/consumption-ref-unresolved", 10)

        if kind == "authorization":
            decision = body["decision"]
            if not _type_ok(decision, "map"):
                _fail("schema/bad-type", 10)
            presentation = body.get("presentation")
            if (decision.get("decision") == "permit_with_approval") != (presentation is not None):
                _fail("receipt/decision-presentation", 10)
            if decision.get("decision") == "permit_with_approval" and "approver_credential_id" not in decision:
                _fail("receipt/decision-presentation", 10)
            if decision.get("decision") != "permit_with_approval" and "approver_credential_id" in decision:
                _fail("receipt/decision-presentation", 10)
            if presentation is not None:
                nested = next((item for item in state.envelopes["presentations"]
                               if item.index == envelope.index), None)
                if nested is None or nested.payload["presenter_credential_id"] != decision.get("approver_credential_id"):
                    _fail("receipt/decision-presentation", 10)
                artifacts = nested.payload["artifacts"]
                if not isinstance(artifacts, list) or [item.get("ordinal") if _type_ok(item, "map") and _uint(item.get("ordinal")) else None
                                                       for item in artifacts] != list(range(len(artifacts))):
                    _fail("receipt/manifest-inconsistent", 10)

        if kind == "action_attempt":
            disposition = body["disposition"]
            if (disposition == "not_dispatched") != ("refusal_reason" in body):
                _fail("receipt/attempt-disposition", 10)
            action, command = body["action"], body["command"]
            if not _type_ok(action, "map") or not _type_ok(command, "map"):
                _fail("schema/bad-type", 10)
            hazard_class = action.get("hazard_class")
            if "hazard_class" in action and hazard_class != "life_safety":  # amendment (u)
                _fail("schema/enum-unknown", 10)
            life_safety_action_names = state.bundle["trust_inputs"].get(
                "life_safety_action_names", []
            )
            if hazard_class == "life_safety" \
                    and action.get("action_name") not in life_safety_action_names:
                _fail("receipt/hazard-class-unbound", 10)
            degraded = body.get("degraded")
            if "degraded" in body and (  # amendment (u)
                not _type_ok(degraded, "map")
                or set(degraded) != {"reason"}
                or degraded.get("reason") != "journal/unavailable"
                or hazard_class != "life_safety"
                or disposition != "eligible_for_dispatch"
            ):
                _fail("receipt/attempt-disposition", 10)
            # A missing field on either side is disagreement (harness `same`
            # returns false when a side is absent), never a KeyError.
            for field in ("action_name", "target_id"):
                if action.get(field) is None or action.get(field) != command.get(field):
                    _fail("receipt/action-command-mismatch", 10)
            # D-73: canonical_command decodes to canonical-command-payload and
            # its operation/target/parameters_digest agree with the normalized
            # action; an undecodable command is disagreement (harness parity).
            # When the optional parameters map is present, its deterministic
            # encoding must hash to parameters_digest.
            try:
                decoded = loads(command["canonical_command"]) \
                    if isinstance(command.get("canonical_command"), bytes) else None
            except CBORError:
                decoded = None
            # harness `object()` excludes maps with any non-text key; mirror it.
            if not isinstance(decoded, dict) or not all(isinstance(k, str) for k in decoded):
                _fail("receipt/action-command-mismatch", 10)
            for left, right in (("operation", "action_name"), ("target", "target_id"),
                                ("parameters_digest", "parameters_digest")):
                if decoded.get(left) is None or action.get(right) is None \
                        or dumps(decoded[left]) != dumps(action[right]):
                    _fail("receipt/action-command-mismatch", 10)
            if "parameters" in decoded:
                if not isinstance(decoded["parameters"], dict) \
                        or not all(isinstance(k, str) for k in decoded["parameters"]) \
                        or not isinstance(action.get("parameters_digest"), bytes) \
                        or hashes.sha256(dumps(decoded["parameters"])) != action["parameters_digest"]:
                    _fail("receipt/action-command-mismatch", 10)

        if kind == "dispatch":
            # Mirror the harness find() semantics exactly: take the FIRST
            # attempted_as edge, tolerating non-map parents (the step-11 parents
            # guard catches those), and require agreement only when the attempt
            # resolves. A malformed attempt command is disagreement (command
            # non-map resolves the compared command_id to undefined).
            edge = next((parent for parent in receipt["parents"]
                         if _type_ok(parent, "map") and parent.get("edge_type") == "attempted_as"), None)
            attempt_ref = edge.get("parent_id") if edge is not None else None
            attempt = state.receipts_by_id.get(attempt_ref) if isinstance(attempt_ref, bytes) else None
            if attempt is not None:
                attempt_command = attempt.payload["body"].get("command")
                command_id = attempt_command.get("command_id") if _type_ok(attempt_command, "map") else None
                if body["attempt_id"] != attempt.payload["receipt_id"] \
                        or command_id is None or body.get("command_id") != command_id:
                    _fail("receipt/dispatch-attempt-mismatch", 10)

        if kind == "outcome_observation":
            outcome_parents = [parent for parent in receipt["parents"]
                               if _type_ok(parent, "map") and parent.get("edge_type") == "observed_outcome"]
            if len(outcome_parents) != 1 or body.get("subject_id") is None \
                    or body.get("subject_id") != outcome_parents[0].get("parent_id"):
                _fail("receipt/outcome-subject-mismatch", 10)


def _mediator_countersignature_checks(state: State) -> None:
    countersignatures = state.envelopes["mediator_countersignatures"]
    if not countersignatures:
        return
    attempts = [envelope for envelope in state.envelopes["receipts"]
                if envelope.payload["kind"] == "action_attempt"]
    for countersignature in countersignatures:
        claims = countersignature.payload
        matches = [attempt for attempt in attempts
                   if hashes.sha256(attempt.envelope_bytes) == claims["action_attempt_receipt_digest"]]
        if len(matches) != 1:
            _fail("countersign/digest-mismatch", 10)
        command = matches[0].payload.get("body", {}).get("command")
        if not _type_ok(command, "map") or command.get("command_digest") != claims["command_digest"]:
            _fail("countersign/digest-mismatch", 10)
    if "mediator_countersigned" not in state.observations:
        state.observations.append("mediator_countersigned")


def _replay_freshness(state: State) -> None:
    replay_seen: dict[tuple[bytes, bytes], bytes] = {}
    flows: dict[bytes, tuple[bytes, bytes]] = {}
    for envelope in state.envelopes["receipts"]:
        receipt = envelope.payload
        freshness = receipt["freshness"]
        # Pin the types this step compares and indexes (harness parity): a
        # malformed freshness or parent edge yields a signed verdict, never a
        # TypeError/KeyError.
        if not (_uint(freshness.get("issued_at")) and _uint(freshness.get("expires_at"))
                and _uint(receipt["emission"].get("committed_at"))):
            _fail("schema/bad-type", 11)
        if not (_bstr(freshness.get("replay_domain")) and _bstr(freshness.get("invocation_id"))):
            _fail("schema/bad-type", 11)
        # Each parent edge is pinned to exactly what the CDDL requires
        # (spec/aar-core.cddl parent-edge): later steps subscript these fields
        # bare, so malformed edges must yield a signed verdict here, never a
        # KeyError at steps 12-13. Enum membership stays a step-12 judgment.
        if any(not _type_ok(parent, "map")
               or not isinstance(parent.get("edge_type"), str)
               or not _bstr(parent.get("parent_id"), 32)
               or not isinstance(parent.get("parent_kind"), str)
               or not _bstr(parent.get("parent_tenant_id"), 16)
               or not _bstr(parent.get("parent_site_id"), 16)
               or not _uint(parent.get("parent_epoch_id"))
               for parent in receipt["parents"]):
            _fail("schema/bad-type", 11)
        committed_at = receipt["emission"]["committed_at"]
        if freshness["issued_at"] > committed_at:
            _fail("replay/not-yet-valid", 11)
        if committed_at >= freshness["expires_at"]:  # amendment (v): the window bounds emission, not evaluation
            _fail("replay/expired", 11)
        parent_ids = [parent["parent_id"] for parent in receipt["parents"]]
        if freshness.get("intended_parents") != parent_ids:
            _fail("replay/parent-binding", 11)
        # Amendment (z): the receipts sharing one correlation_id form the flow; the
        # first seen (artifact order) sets its coordinate, and a receipt with no
        # correlation binding is in no flow for this check.
        correlation = receipt.get("correlation")
        correlation_id = correlation.get("correlation_id") if _type_ok(correlation, "map") else None
        if _bstr(correlation_id, 16):
            coordinate = freshness["replay_domain"], freshness["invocation_id"]
            if flows.setdefault(correlation_id, coordinate) != coordinate:
                _fail("replay/invocation-mismatch", 11)
        if freshness.get("use") == "one_time":
            coordinate = freshness["replay_domain"], freshness["invocation_id"]
            content = hashes.sha256(envelope.envelope_bytes)  # the replay state's content_digest
            if coordinate in replay_seen and replay_seen[coordinate] != content:
                _fail("replay/one-time-reused", 11)
            replay_seen[coordinate] = content

    if state.replay_state is None:
        # The caller did not supply external replay state. Stateful replay is not
        # claimed as passed; the KAT report exposes this as not_evaluated.
        return
    for entry in state.replay_state.get("entries", []):
        coordinate = entry["replay_domain"], entry["invocation_id"]
        if coordinate in replay_seen and replay_seen[coordinate] != entry["content_digest"]:
            _fail("replay/one-time-reused", 11)


EDGE_MATRIX = {
    "derived_from": ({"observation", "inference"}, {"observation", "inference"}),
    "requested_by": ({"observation", "inference"}, {"inference", "authorization", "action_attempt"}),
    "authorized_by": ({"authorization"}, {"action_attempt"}),
    "triggered_by": ({"observation", "inference"}, {"authorization", "action_attempt"}),
    "attempted_as": ({"action_attempt"}, {"dispatch"}),
    "observed_outcome": ({"action_attempt", "dispatch"}, {"outcome_observation"}),
    "supports": ({"observation", "inference", "outcome_observation"}, {"inference", "authorization", "outcome_observation"}),
}


def _graph_checks(state: State) -> dict[bytes, list[bytes]]:
    graph: dict[bytes, list[bytes]] = defaultdict(list)
    ranks: dict[bytes, int] = {}
    manifests = {env.payload["manifest_id"]: env.payload for env in state.envelopes["epoch_manifests"]}
    anchors = {env.payload["anchor_id"]: env.payload for env in state.envelopes["anchors"]}
    # Amendment (c): each listed check runs over every receipt, in artifact
    # order, before the next check begins (harness validateGraph model).
    ordered = state.envelopes["receipts"]  # artifact order (amendment c, round 3)
    edges = [(envelope.payload, parent_edge) for envelope in ordered for parent_edge in envelope.payload["parents"]]
    for _, parent_edge in edges:
        if state.receipts_by_id.get(parent_edge["parent_id"]) is None:
            _fail("graph/dangling-parent", 12)
    for _, parent_edge in edges:
        parent_receipt = state.receipts_by_id[parent_edge["parent_id"]].payload
        if parent_edge["parent_kind"] != parent_receipt["kind"] \
                or parent_edge["parent_tenant_id"] != parent_receipt["binding"]["tenant_id"] \
                or parent_edge["parent_site_id"] != parent_receipt["binding"]["site_id"] \
                or parent_edge["parent_epoch_id"] != parent_receipt["binding"]["epoch_id"]:
            _fail("graph/parent-metadata-mismatch", 12)
    for receipt, parent_edge in edges:
        parent_receipt = state.receipts_by_id[parent_edge["parent_id"]].payload
        matrix = EDGE_MATRIX.get(parent_edge["edge_type"])
        if matrix is None or parent_receipt["kind"] not in matrix[0] or receipt["kind"] not in matrix[1]:
            _fail("graph/edge-illegal", 12)
    allowed_roots = {
        "agent_request": {"observation", "inference"},
        "human_request": {"observation", "inference", "authorization"},
        "standing_condition_trigger": {"observation", "authorization"},
    }
    for envelope in ordered:
        receipt = envelope.payload
        root = receipt.get("root")
        if not receipt["parents"]:
            # Amendment (p): a root that is not a text-keyed map is root-missing;
            # a map whose kind is absent or unlisted is root-forbidden.
            if not _type_ok(root, "map"):
                _fail("graph/root-missing", 12)
            kind = root.get("kind")  # amendment (p): a non-text kind is unlisted
            if receipt["kind"] not in (allowed_roots.get(kind, set()) if isinstance(kind, str) else set()):
                _fail("graph/root-forbidden", 12)
        elif "root" in receipt:  # amendment (u): a present null root is present
            _fail("graph/root-forbidden", 12)
    for receipt, parent_edge in edges:
        parent_binding = state.receipts_by_id[parent_edge["parent_id"]].payload["binding"]
        if parent_binding["tenant_id"] != receipt["binding"]["tenant_id"] or parent_binding["site_id"] != receipt["binding"]["site_id"]:
            _fail("graph/tenant-site-splice", 12)
        same_epoch = parent_binding["epoch_id"] == receipt["binding"]["epoch_id"]
        cross = parent_edge.get("cross_epoch")
        if same_epoch and "cross_epoch" in parent_edge:  # amendment (u)
            _fail("graph/cross-epoch-forbidden", 12)
        if not same_epoch:
            reason = cross.get("reason") if _type_ok(cross, "map") else None
            allowed = isinstance(reason, str) and (
                (parent_edge["edge_type"] in {"derived_from", "supports"} and reason == "historical_evidence")
                or (parent_edge["edge_type"] == "observed_outcome" and reason in {"long_running_action", "late_outcome"})
            )
            if not allowed:
                _fail("graph/cross-epoch-forbidden", 12)
            # D-82 part 7 (section 2.1): the named manifest belongs to the parent's
            # owner, epoch, tenant, and site, and the named anchor binds it.
            manifest = manifests.get(cross.get("source_manifest_id")) if _bstr(cross.get("source_manifest_id"), 32) else None
            anchor = anchors.get(cross.get("source_anchor_id")) if _bstr(cross.get("source_anchor_id"), 32) else None
            if parent_binding["epoch_id"] >= receipt["binding"]["epoch_id"] or manifest is None or anchor is None \
                    or manifest["epoch_id"] != parent_binding["epoch_id"] \
                    or manifest["epoch_owner_kid"] != parent_binding["epoch_owner_kid"] \
                    or manifest["tenant_id"] != parent_binding["tenant_id"] \
                    or manifest["site_id"] != parent_binding["site_id"] \
                    or anchor["manifest_id"] != manifest["manifest_id"]:
                _fail("graph/cross-epoch-unanchored", 12)
    # Depth and width: longest path from a root, computed in topological order
    # (indegree queue, harness model) so the receipts' array order is irrelevant.
    indegree: dict[bytes, int] = {}
    for envelope in ordered:
        receipt = envelope.payload
        indegree[receipt["receipt_id"]] = len(receipt["parents"])
        for parent_edge in receipt["parents"]:
            graph[parent_edge["parent_id"]].append(receipt["receipt_id"])
    queue = deque(receipt_id for receipt_id, count in indegree.items() if count == 0)
    for receipt_id in queue:
        ranks[receipt_id] = 0
    while queue:
        receipt_id = queue.popleft()
        for child_id in graph.get(receipt_id, []):
            ranks[child_id] = max(ranks.get(child_id, 0), ranks[receipt_id] + 1)
            indegree[child_id] -= 1
            if indegree[child_id] == 0:
                queue.append(child_id)

    if ranks and max(ranks.values()) + 1 > LIMITS["dag_depth"]:
        _fail("resource/dag-depth", 12)
    widths: dict[int, int] = defaultdict(int)
    for rank in ranks.values():
        widths[rank] += 1
    if widths and max(widths.values()) > LIMITS["dag_width"]:
        _fail("resource/dag-width", 12)
    return graph


def _input_origin_ancestry(state: State, graph: dict[bytes, list[bytes]]) -> None:
    # Keep edge types from the receipts; step 12's graph stores successors only.
    incoming: dict[bytes, set[bytes]] = defaultdict(set)
    for parent_id, children in graph.items():
        for child_id in children:
            if any(edge["parent_id"] == parent_id and edge["edge_type"] not in {"attempted_as", "observed_outcome"}
                   for edge in state.receipts_by_id[child_id].payload["parents"]):
                incoming[child_id].add(parent_id)
    reachable: dict[bytes, set[bytes]] = {}

    def ancestors(node: bytes) -> set[bytes]:
        if node not in reachable:
            nodes = {node}
            for parent in incoming[node]:
                nodes.update(ancestors(parent))
            reachable[node] = nodes
        return reachable[node]

    def slots(nodes: set[bytes]) -> tuple[set[str], int, int]:
        origins: set[str] = set()
        declared = undeclared = 0
        for node in nodes:
            receipt = state.receipts_by_id[node].payload
            body = receipt["body"]
            if receipt["kind"] == "inference":
                if "origins" in body:
                    declared += 1
                    origins.update(body["origins"])
                else:
                    undeclared += 1
            elif receipt["kind"] == "observation":
                for item in body["consumption"]["items"]:
                    if item["disposition"] == "used":
                        if "origin" in item:
                            declared += 1
                            origins.add(item["origin"])
                        else:
                            undeclared += 1
        return origins, declared, undeclared

    dispatched = list(dict.fromkeys(
        edge["parent_id"] for env in state.envelopes["receipts"] if env.payload["kind"] == "dispatch"
        for edge in env.payload["parents"] if edge["edge_type"] == "attempted_as"
    ))
    undispatched = sorted(
        node for node, env in state.receipts_by_id.items()
        if env.payload["kind"] == "action_attempt" and env.payload["body"]["disposition"] == "eligible_for_dispatch"
        and node not in dispatched
    )
    union: set[bytes] = set()
    for node in dispatched + undispatched:
        nodes = ancestors(node)
        origins, _, undeclared = slots(nodes)
        is_dispatched = node in dispatched
        state.input_origin_attempts.append({
            "attempt_id": node.hex(), "dispatched": is_dispatched,
            "declared_origins": sorted(origins, key=dumps), "undeclared_slots": undeclared,
        })
        if is_dispatched:
            union.update(nodes)
    origins, declared, undeclared = slots(union)
    state.input_origin_ancestry = (
        "not_evaluated" if declared + undeclared == 0 else
        "not_declared" if declared == 0 else
        "declared_only" if undeclared == 0 else "partially_declared"
    )
    if origins & {"third_party", "device_sensed", "unknown"}:
        state.observations.append("untrusted_origin_declared_in_action_ancestry")


def _subset(child: Any, parent: Any) -> bool:
    if not isinstance(child, list) or not isinstance(parent, list):
        return False
    encoded = {dumps(item) for item in parent}
    return all(dumps(item) in encoded for item in child)


def _link_valid(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    """One chain link: window, four scope subsets, tenant/site, use and invocation not widened."""
    if parent["not_before"] > child["not_before"] or parent["not_after"] < child["not_after"]:
        return False
    parent_scope, child_scope = parent["scope"], child["scope"]
    if not _type_ok(parent_scope, "map") or not _type_ok(child_scope, "map"):
        return False
    if any(not _subset(child_scope.get(name), parent_scope.get(name))
           for name in ("actions", "targets", "purpose_ids", "allowed_profiles")):
        return False
    if parent["tenant_id"] != child["tenant_id"] or parent["site_id"] != child["site_id"]:
        return False
    if parent["use"] == "one_time" and child["use"] != "one_time":
        return False
    # Amendment (u): a present (null included) parent invocation_id must equal a present child one.
    return "invocation_id" not in parent or ("invocation_id" in child and parent["invocation_id"] == child["invocation_id"])


def _chain_valid(known: dict[bytes, dict[str, Any]], child: dict[str, Any], memo: dict[bytes, bool | None]) -> bool:
    """D-82 part 9 (amendment e): parent_delegations, transitively, array order,
    depth first, iterative. Each carried delegation's chain is evaluated at most
    once per verification (memo: True = valid, None = in progress); a delegation
    re-entered while in progress is a cycle. Every failure is one code.
    """
    stack: list[tuple[dict[str, Any], int]] = [(child, 0)]
    memo[child["delegation_id"]] = None
    while stack:
        node, index = stack[-1]
        parents = node["parent_delegations"]
        if not isinstance(parents, list):
            return False
        if index >= len(parents):
            memo[node["delegation_id"]] = True
            stack.pop()
            continue
        stack[-1] = (node, index + 1)
        parent_id = parents[index]
        parent = known.get(parent_id) if isinstance(parent_id, bytes) else None
        if parent is None or not _link_valid(parent, node):
            return False
        if parent_id in memo:
            if memo[parent_id] is None:
                return False  # cycle
            continue  # already evaluated: a validated chain is path-independent
        memo[parent_id] = None
        stack.append((parent, 0))
    return True


def _authorization_dominance(state: State, graph: dict[bytes, list[bytes]]) -> None:
    dispatched_attempt_ids: set[bytes] = set()
    known_delegations: dict[bytes, dict[str, Any]] = {}
    chain_memo: dict[bytes, bool | None] = {}
    for env in state.envelopes["delegations"]:
        known_delegations.setdefault(env.payload["delegation_id"], env.payload)
    for dispatch in (env for env in state.envelopes["receipts"] if env.payload["kind"] == "dispatch"):
        dispatch_receipt = dispatch.payload
        attempted = [parent for parent in dispatch_receipt["parents"] if parent["edge_type"] == "attempted_as"]
        if len(attempted) != 1:
            _fail("graph/dominator-missing", 13)
        attempt = state.receipts_by_id.get(attempted[0]["parent_id"])
        if attempt is None:
            _fail("graph/dominator-missing", 13)
        dispatched_attempt_ids.add(attempt.payload["receipt_id"])
        authorizations = [parent for parent in attempt.payload["parents"] if parent["edge_type"] == "authorized_by"]
        if not authorizations:
            _fail("graph/dominator-missing", 13)
        if len(authorizations) > 1:
            _fail("graph/dominator-ambiguous", 13)
        authorization = state.receipts_by_id.get(authorizations[0]["parent_id"])
        # A missing authorization_id is disagreement (harness same() parity),
        # never a KeyError.
        if authorization is None or authorization.payload["kind"] != "authorization" \
                or attempt.payload["body"].get("authorization_id") != authorization.payload["receipt_id"]:
            _fail("graph/dominator-missing", 13)
        auth_body = authorization.payload["body"]
        delegation = state.embedded_delegations.get(authorization.payload["receipt_id"])
        if delegation is None:
            _fail("graph/dominator-missing", 13)
        delegation_payload = delegation.payload
        if auth_body["decision"].get("delegation_id") != delegation_payload["delegation_id"]:
            _fail("graph/dominator-missing", 13)
        # D-79: the delegation names the enforcement point that signed the attempt.
        subject_id = delegation_payload["subject_credential_id"]
        subject = state.credentials_by_id.get(subject_id) if isinstance(subject_id, bytes) else None
        if subject is None or subject.payload["subject_kid"] != attempt.protected[4]:
            _fail("delegation/scope", 13)
        attempt_body = attempt.payload["body"]
        action = attempt_body["action"]
        scope = delegation_payload["scope"]
        # Amendment (l): a used delegation whose scope is not a map, or whose
        # lists are not arrays, is delegation/scope (harness parity).
        if not _type_ok(scope, "map") or any(not isinstance(scope.get(name), list)
                                              for name in ("actions", "targets", "purpose_ids", "allowed_profiles")):
            _fail("delegation/scope", 13)
        # Amendment (o): an absent or wrongly typed value is simply not contained.
        legal = attempt.payload["legal"]
        purpose = legal.get("purpose_id") if _type_ok(legal, "map") else None
        decision_profile = auth_body["decision"].get("profile")
        # Amendment (ag): both MUST be text and contained; a non-text value is never contained.
        if not isinstance(purpose, str) or not isinstance(decision_profile, str):
            _fail("delegation/scope", 13)
        invocation = attempt.payload["freshness"]["invocation_id"]
        if action["action_name"] not in scope["actions"] \
                or action["target_id"] not in scope["targets"] \
                or purpose not in scope["purpose_ids"] \
                or decision_profile not in scope["allowed_profiles"] \
                or delegation_payload["tenant_id"] != attempt.payload["binding"]["tenant_id"] \
                or delegation_payload["site_id"] != attempt.payload["binding"]["site_id"] \
                or ("invocation_id" in delegation_payload and delegation_payload["invocation_id"] != invocation) \
                or (delegation_payload["use"] == "one_time" and "invocation_id" not in delegation_payload):
            _fail("delegation/scope", 13)
        committed = attempt.payload["emission"]["committed_at"]
        if committed < delegation_payload["not_before"]:
            _fail("delegation/not-yet-valid", 13)
        if committed >= delegation_payload["not_after"]:
            _fail("delegation/expired", 13)
        if not _chain_valid(known_delegations, delegation_payload, chain_memo):
            _fail("delegation/chain-invalid", 13)

        assert state.bundle is not None
        if state.bundle["claimed_profile"] == "AAR-3":
            attempt_binding = attempt.payload["binding"]
            dispatch_binding = dispatch_receipt["binding"]
            attempt_committed_at = attempt.payload["emission"]["committed_at"]
            committed_before_dispatch = (
                attempt_binding["epoch_owner_kid"] == dispatch_binding["epoch_owner_kid"]
                and attempt_binding["epoch_id"] == dispatch_binding["epoch_id"]
                and attempt_binding["epoch_seq"] < dispatch_binding["epoch_seq"]
                and attempt_committed_at <= dispatch_receipt["body"]["dispatched_at"]
            )
            degraded = attempt_body.get("degraded")
            life_safety_exception = (
                action.get("hazard_class") == "life_safety"
                and _type_ok(degraded, "map")
                and degraded.get("reason") == "journal/unavailable"
            )
            if not committed_before_dispatch and not life_safety_exception:
                _fail("journal/uncommitted-dispatch", 13)
            if not committed_before_dispatch and "degraded_dispatch" not in state.observations:
                state.observations.append("degraded_dispatch")

    assert state.bundle is not None
    if state.bundle["claimed_profile"] == "AAR-3":
        for attempt in (
            env for env in state.envelopes["receipts"]
            if env.payload["kind"] == "action_attempt"
        ):
            body = attempt.payload["body"]
            if (
                body.get("disposition") == "not_dispatched"
                and body.get("refusal_reason") == "journal/unavailable"
                and attempt.payload["receipt_id"] not in dispatched_attempt_ids
                and "refused_pre_dispatch" not in state.observations
            ):
                state.observations.append("refused_pre_dispatch")


def _epoch_state_machine(state: State) -> None:
    groups: dict[tuple[bytes, int], list[Envelope]] = defaultdict(list)
    for envelope in state.envelopes["epoch_events"]:
        event = envelope.payload
        groups[(event["epoch_owner_kid"], event["epoch_id"])].append(envelope)
    manifests_by_group: dict[tuple[bytes, int], list[Envelope]] = defaultdict(list)
    for envelope in state.envelopes["epoch_manifests"]:
        manifest = envelope.payload
        manifests_by_group[(manifest["epoch_owner_kid"], manifest["epoch_id"])].append(envelope)
    ordered_events: dict[tuple[bytes, int], list[Envelope]] = {}
    for key, events in groups.items():
        ordered = sorted(events, key=lambda env: env.payload["event_seq"])
        ordered_events[key] = ordered
        for index, envelope in enumerate(ordered):
            event = envelope.payload
            if event["event_seq"] != index:
                _fail("epoch/event-chain", 14)
            if index == 0:
                if "previous_event_digest" in event:  # amendment (u): a present null is present
                    _fail("epoch/event-chain", 14)
            elif event.get("previous_event_digest") != hashes.sha256(ordered[index - 1].payload_bytes):
                _fail("epoch/event-chain", 14)

    primary_manifests: dict[tuple[bytes, int], Envelope] = {}
    for key, manifests in manifests_by_group.items():
        close_ids = {
            event.payload["body"]["manifest_id"]
            for event in ordered_events.get(key, [])
            if event.payload["event"] == "close" and _bstr(event.payload["body"].get("manifest_id"), 32)
        }
        primary_manifests[key] = next(
            (manifest for manifest in manifests if manifest.payload["manifest_id"] in close_ids),
            manifests[0],
        )

    owners: dict[bytes, list[Envelope]] = defaultdict(list)
    for (owner, _), envelope in primary_manifests.items():
        owners[owner].append(envelope)

    ordered_manifests: dict[bytes, list[Envelope]] = {}
    for items in owners.values():
        ordered = sorted(items, key=lambda env: env.payload["opened_at"])
        ordered_manifests[ordered[0].payload["epoch_owner_kid"]] = ordered
        for previous, current in zip(ordered, ordered[1:]):
            if current.payload["epoch_id"] <= previous.payload["epoch_id"]:
                _fail("epoch/id-nonmonotonic", 14)

    for ordered in ordered_manifests.values():
        # Amendments (u) and (w): a present predecessor that is not a 32-byte bstr
        # is a mismatch; the first carried manifest may name an uncarried one.
        first = ordered[0].payload
        if "predecessor_manifest_digest" in first and not _bstr(first["predecessor_manifest_digest"], 32):
            _fail("epoch/predecessor-mismatch", 14)
        for previous, current in zip(ordered, ordered[1:]):
            if current.payload.get("predecessor_manifest_digest") != hashes.sha256(previous.payload_bytes):
                _fail("epoch/predecessor-mismatch", 14)

    open_close: dict[tuple[bytes, int], tuple[dict[str, Any], dict[str, Any]]] = {}
    for key, ordered in ordered_events.items():
        opens = [env for env in ordered if env.payload["event"] == "open"]
        closes = [env for env in ordered if env.payload["event"] == "close"]
        if len(opens) != 1 or len(closes) != 1 \
                or opens[0].payload["event_seq"] >= closes[0].payload["event_seq"] \
                or opens[0].payload["occurred_at"] >= closes[0].payload["occurred_at"]:
            _fail("epoch/open-close", 14)
        # D-73: an event group without its manifest is not a closed epoch.
        if key not in primary_manifests:
            _fail("epoch/open-close", 14)
        open_close[key] = opens[0].payload, closes[0].payload
    # D-73: a carried manifest whose owner/epoch has no open+close events is
    # not a closed epoch either (harness parity; demo bundles used to omit
    # events and pyref accepted them).
    for key in manifests_by_group:
        if key not in ordered_events:
            _fail("epoch/open-close", 14)

    # Amendment (d): duration is judged on the manifest pair and on the event pair.
    for key, (opened, closed) in open_close.items():
        manifest = primary_manifests[key].payload
        if manifest["closed_at"] - manifest["opened_at"] > 86_400:
            _fail("epoch/duration-exceeded", 14)
        if closed["occurred_at"] - opened["occurred_at"] > 86_400:
            _fail("epoch/duration-exceeded", 14)

    for key, (opened, closed) in open_close.items():
        manifest_env = primary_manifests.get(key)
        if manifest_env is None:
            continue
        manifest = manifest_env.payload
        if closed["body"].get("manifest_id") != manifest["manifest_id"]:
            _fail("epoch/span-count-mismatch", 14)
        if not _uint(closed["body"].get("item_count")) or not _uint(manifest["item_count"]) or not _uint(manifest["receipt_index"]["leaf_count"]) \
                or closed["body"]["item_count"] != manifest["item_count"] \
                or closed["body"]["last_epoch_seq"] != manifest["sequence_span"]["last"] \
                or opened["body"]["first_epoch_seq"] != manifest["sequence_span"]["first"] \
                or manifest["item_count"] != len(manifest["receipt_index"]["entries"]) \
                or manifest["receipt_index"]["leaf_count"] != manifest["item_count"]:  # amendments (ad), (ah): a bool count is never a uint
            _fail("epoch/span-count-mismatch", 14)

    for envelope in state.envelopes["receipts"]:
        receipt = envelope.payload
        matching = primary_manifests.get((receipt["binding"]["epoch_owner_kid"], receipt["binding"]["epoch_id"]))
        if matching and receipt["emission"]["committed_at"] > matching.payload["closed_at"]:
            _fail("epoch/late-insertion", 14)
        late_for = receipt["binding"].get("late_for_epoch_id")
        if late_for is not None and late_for >= receipt["binding"]["epoch_id"]:
            _fail("epoch/late-insertion", 14)

    for key, (_, closed) in open_close.items():
        manifest = primary_manifests[key].payload  # paired above (D-73)
        expected_deadline = manifest["closed_at"] + 86_400
        deadline_valid = (
            manifest["anchor_deadline"] == expected_deadline
            and closed["body"]["anchor_deadline"] == expected_deadline
        )
        if not deadline_valid:
            _fail("epoch/anchor-deadline", 14)
        submitted = [env.payload for env in ordered_events[key] if env.payload["event"] == "anchor_submitted"]
        if any(event["body"]["submitted_at"] > closed["body"]["anchor_deadline"] for event in submitted):
            _fail("epoch/anchor-deadline", 14)

    if any(len(items) > 1 for items in manifests_by_group.values()):
        _fail("epoch/fork", 14)
    # D-82 part 2: the wire's handling is reject_and_surface; the report surfaces it.
    if any(env.payload["event"] == "fork_declared" for env in state.envelopes["epoch_events"]):
        _fail("epoch/fork", 14)


def _manifest_index_checks(state: State) -> None:
    for envelope in state.envelopes["epoch_manifests"]:
        manifest = envelope.payload
        index = manifest["receipt_index"]
        entries = index["entries"]
        ordering = [(item["committed_at"], item["epoch_seq"], item["receipt_id"]) for item in entries]
        if ordering != sorted(ordering) or len(set(ordering)) != len(ordering):
            _fail("manifest/index-order", 15)
        leaf_indices = [item["leaf_index"] for item in entries]
        if leaf_indices != list(range(len(entries))):
            _fail("manifest/index-gap", 15)
        receipt_ids = [item["receipt_id"] for item in entries]
        epoch_sequences = [item["epoch_seq"] for item in entries]
        if len(set(receipt_ids)) != len(receipt_ids) or len(set(epoch_sequences)) != len(epoch_sequences):
            _fail("manifest/index-duplicate", 15)
        for entry in entries:
            receipt = state.receipts_by_id.get(entry["receipt_id"])
            if receipt is None:
                continue
            payload = receipt.payload
            if entry["receipt_kind"] != payload["kind"] \
                    or entry["issuer_kid"] != receipt.protected[4] \
                    or entry["issuer_seq"] != payload["emission"]["issuer_seq"] \
                    or entry["epoch_seq"] != payload["binding"]["epoch_seq"] \
                    or entry["committed_at"] != payload["emission"]["committed_at"]:
                _fail("manifest/index-receipt-mismatch", 15)
        span = manifest["sequence_span"]
        if entries:
            if span != {"first": min(epoch_sequences), "last": max(epoch_sequences)}:
                _fail("epoch/span-count-mismatch", 15)
        elif span != {"first": None, "last": None} or manifest["close_reason"] != "padding":
            _fail("epoch/span-count-mismatch", 15)
        if entries:
            computed = hashes.promoted_root(
                (hashes.manifest_index_leaf(entry) for entry in entries), hashes.manifest_index_node
            )
            if computed != index["root"]:
                _fail("manifest/index-root-mismatch", 15)


def _audit_path_length(index: int, size: int) -> int:
    length = 0
    while size > 1:
        if index & 1 or index + 1 < size:
            length += 1
        index //= 2
        size = (size + 1) // 2
    return length


def _merkle_checks(state: State) -> None:
    batches = {env.payload["batch_id"]: env.payload for env in state.envelopes["merkle_batches"]}
    successful: dict[bytes, list[dict[str, Any]]] = defaultdict(list)
    assert state.bundle is not None
    for proof in state.bundle["artifacts"]["merkle_proofs"]:
        batch = batches.get(proof["batch_id"]) if _bstr(proof.get("batch_id"), 32) else None
        leaf = proof["leaf"]
        if batch is None or proof["tree_size"] != batch["tree_size"] \
                or proof["leaf_index"] != leaf["leaf_index"] \
                or leaf["tree_size"] != batch["tree_size"] \
                or leaf["tenant_id"] != batch["tenant_id"] \
                or leaf["site_id"] != batch["site_id"] \
                or leaf["epoch_id"] != batch["epoch_id"]:
            _fail("merkle/batch-binding", 16)
        if len(proof["siblings"]) != _audit_path_length(proof["leaf_index"], proof["tree_size"]):
            _fail("merkle/path-length", 16)
        root = hashes.inclusion_root(
            hashes.merkle_leaf(leaf), proof["leaf_index"], proof["tree_size"],
            proof["siblings"], hashes.merkle_node,
        )
        if root != batch["root"]:
            _fail("merkle/root-mismatch", 16)
        successful[proof["batch_id"]].append(leaf)
        if "membership_only" not in state.observations:
            state.observations.append("membership_only")
    for leaves in successful.values():
        seen: dict[tuple[Any, ...], int] = {}
        for leaf in leaves:
            content = leaf["tenant_id"], leaf["site_id"], leaf["epoch_id"], leaf["item_digest"]
            if content in seen and seen[content] != leaf["leaf_index"]:
                _fail("merkle/duplicate-leaf", 16)
            seen[content] = leaf["leaf_index"]


def _rfc6962_consistent(proof: dict[str, Any]) -> bool:
    old_size, new_size = proof["old_tree_size"], proof["new_tree_size"]
    old_root, new_root, path = proof["old_root"], proof["new_root"], proof["path"]
    if old_size > new_size or old_size < 1:
        return False
    if old_size == new_size:
        return not path and old_root == new_root
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    offset = 0
    if fn == 0:
        first, second = old_root, old_root
    else:
        if not path:
            return False
        first = second = path[0]
        offset = 1
    while fn:
        if offset >= len(path):
            return False
        if fn & 1:
            first = hashes.rfc6962_node(path[offset], first)
            second = hashes.rfc6962_node(path[offset], second)
            offset += 1
        elif fn < sn:
            second = hashes.rfc6962_node(second, path[offset])
            offset += 1
        fn >>= 1
        sn >>= 1
    while sn:
        if offset >= len(path):
            return False
        second = hashes.rfc6962_node(second, path[offset])
        offset += 1
        sn >>= 1
    return offset == len(path) and first == old_root and second == new_root


def _anchor_checks(state: State) -> None:
    manifests = {env.payload["manifest_id"]: env for env in state.envelopes["epoch_manifests"]}
    assert state.bundle is not None
    expected_heads = {head["target_id"]: head for head in state.bundle["trust_inputs"]["expected_anchor_heads"]}
    for envelope in state.envelopes["anchors"]:
        anchor = envelope.payload
        manifest_env = manifests.get(anchor["manifest_id"]) if _bstr(anchor["manifest_id"], 32) else None
        # Amendment (q), harness order: an unresolved manifest has no plan, so its
        # target is unplanned; a non-array plan target list plans nothing.
        planned = manifest_env.payload["anchor_plan"].get("targets") if manifest_env is not None else None
        targets = {target["target_id"]: target for target in planned
                   if _type_ok(target, "map") and _bstr(target.get("target_id"), 16)} if isinstance(planned, list) else {}
        target = targets.get(anchor["target"].get("target_id")) if _type_ok(anchor["target"], "map") and _bstr(anchor["target"].get("target_id"), 16) else None
        if target is None:
            _fail("anchor/target-unplanned", 17)
        manifest = manifest_env.payload
        if target != anchor["target"]:
            _fail("anchor/target-unplanned", 17)
        inclusion = anchor["inclusion"]
        leaf_digest = hashes.rfc6962_leaf(hashes.anchor_leaf_input(anchor))
        if inclusion["leaf_digest"] != leaf_digest:
            _fail("anchor/inclusion-invalid", 17)
        root = hashes.inclusion_root(
            leaf_digest, inclusion["leaf_index"], inclusion["tree_size"],
            inclusion["siblings"], hashes.rfc6962_node,
        )
        if root != anchor["anchor_root"] or not _uint(anchor["anchor_tree_size"]) or not _uint(anchor["anchor_leaf_index"]) \
                or inclusion["tree_size"] != anchor["anchor_tree_size"] or inclusion["leaf_index"] != anchor["anchor_leaf_index"]:
            _fail("anchor/inclusion-invalid", 17)
        if "consistency" in anchor:
            consistency = anchor["consistency"]  # amendment (x): the proof's new head is the record's head
            if consistency["new_tree_size"] != anchor["anchor_tree_size"] or consistency["new_root"] != anchor["anchor_root"] \
                    or not _rfc6962_consistent(consistency):
                _fail("anchor/consistency-invalid", 17)
        if anchor["tenant_id"] != manifest["tenant_id"] \
                or anchor["site_id"] != manifest["site_id"] \
                or anchor["epoch_id"] != manifest["epoch_id"] \
                or anchor["manifest_digest"] != hashes.sha256(manifest_env.payload_bytes):
            _fail("anchor/manifest-binding", 17)
        if anchor["submitted_at"] > manifest["closed_at"] + 86_400:
            _fail("anchor/submission-late", 17)
        expected = expected_heads.get(anchor["target"]["target_id"])
        if expected is None:
            _fail("anchor/head-missing", 17, indeterminate=True)
        head = anchor["head"]  # amendment (y): equal sizes with differing roots, or differing sizes with equal roots
        if (expected["tree_size"] == head["tree_size"]) != (expected["root"] == head["root"]):
            _fail("anchor/head-mismatch", 17)
        if state.evaluated_at - expected["observed_at"] > 86_400:
            _fail("anchor/head-stale", 17)
        groups = {group["independence_group"]: group
                  for group in manifest["anchor_plan"]["independence"]["groups"]}
        group = groups.get(target["independence_group"])
        if group is None or group["operator_id"] != target["operator_id"]:
            _fail("anchor/independence-invalid", 17)
        independence = manifest["anchor_plan"]["independence"]
        if independence["basis"] == "distinct_operator_and_failure_domain":
            declared = independence["groups"]
            for index, entry in enumerate(declared):
                for other in declared[index + 1:]:
                    if entry["operator_id"] == other["operator_id"] or entry["failure_domain_id"] == other["failure_domain_id"]:
                        _fail("anchor/independence-invalid", 17)
        state.observations.append("anchor_existence_order_only")


def _selector_matches(selector: dict[str, Any], entry: dict[str, Any]) -> bool:
    if not (selector["committed_from"] <= entry["committed_at"] < selector["committed_until"]):
        return False
    if entry["receipt_kind"] not in selector["receipt_kinds"]:
        return False
    tests = (("subject_ids", "subject_ids"), ("correlation_ids", "correlation_ids"))
    for selector_name, entry_name in tests:
        if selector_name in selector and not set(selector[selector_name]) & set(entry[entry_name]):
            return False
    if "issuer_kids" in selector and entry["issuer_kid"] not in selector["issuer_kids"]:
        return False
    return True


def _verify_index_proof(entry: dict[str, Any], proof: dict[str, Any], root: bytes) -> bool:
    if proof["leaf_index"] != entry["leaf_index"] or proof["tree_size"] < 1:
        return False
    if len(proof["siblings"]) != _audit_path_length(proof["leaf_index"], proof["tree_size"]):
        return False
    computed = hashes.inclusion_root(
        hashes.manifest_index_leaf(entry), proof["leaf_index"], proof["tree_size"],
        proof["siblings"], hashes.manifest_index_node,
    )
    return computed == root


def _bundle_ranges(state: State) -> None:
    assert state.bundle is not None
    bundle = state.bundle
    selector = bundle["selector"]
    if selector["committed_from"] >= selector["committed_until"]:
        _fail("bundle/selector-interval", 18)
    manifests = {env.payload["manifest_id"]: env.payload for env in state.envelopes["epoch_manifests"]}
    state.selector_matching_receipts = len({
        entry["receipt_id"]
        for manifest in manifests.values()
        if manifest["tenant_id"] == selector["tenant_id"]
        and manifest["site_id"] == selector["site_id"]
        for entry in manifest["receipt_index"]["entries"]
        if _bstr(entry.get("receipt_id"), 32) and entry["receipt_id"] in state.receipts_by_id and _selector_matches(selector, entry)
    })
    selected_ids: set[bytes] = set()
    previous_last: dict[bytes, int] = {}
    for range_proof in bundle["ranges"]:
        manifest = manifests.get(range_proof["manifest_id"]) if _bstr(range_proof.get("manifest_id"), 32) else None
        if manifest is None:
            _fail("bundle/range-manifest-missing", 18)
        if range_proof.get("selector_commitment") != bundle["selector_commitment"]:
            _fail("bundle/range-selector-mismatch", 18)
        entries = range_proof["entries"]
        indices = [item["entry"]["leaf_index"] for item in entries]
        if indices and (indices != list(range(indices[0], indices[0] + len(indices)))
                        or range_proof.get("first_leaf_index") != indices[0]
                        or indices[0] <= previous_last.get(range_proof["manifest_id"], -1)):  # amendment (al)
            _fail("bundle/range-noncontiguous", 18)
        if not indices and "first_leaf_index" in range_proof:
            _fail("bundle/range-noncontiguous", 18)
        if indices:
            previous_last[range_proof["manifest_id"]] = indices[-1]
        for item in entries:
            if not _verify_index_proof(item["entry"], item["inclusion"], manifest["receipt_index"]["root"]):
                _fail("bundle/range-proof-invalid", 18)
        for boundary_name in ("left_boundary", "right_boundary"):
            boundary = range_proof.get(boundary_name)
            if boundary and not _verify_index_proof(boundary["entry"], boundary["inclusion"], manifest["receipt_index"]["root"]):
                _fail("bundle/range-proof-invalid", 18)
        objective = [entry for entry in manifest["receipt_index"]["entries"]
                     if selector["committed_from"] <= entry["committed_at"] < selector["committed_until"]]
        if [item["entry"] for item in entries] != objective:
            _fail("bundle/range-boundary", 18)
        for item in entries:
            if _selector_matches(selector, item["entry"]):
                selected_ids.add(item["entry"]["receipt_id"])

    if bundle["coverage"] == "complete":
        if not bundle["ranges"]:
            _fail("bundle/coverage-overclaim", 18)
        missing = selected_ids - set(state.receipts_by_id)
        if missing:
            _fail("bundle/selected-receipt-missing", 18)
        reachable = set(selected_ids)
        queue = deque(selected_ids)
        while queue:
            receipt = state.receipts_by_id.get(queue.popleft())
            if receipt:
                for parent in receipt.payload["parents"]:
                    if parent["parent_id"] not in reachable:
                        reachable.add(parent["parent_id"])
                        queue.append(parent["parent_id"])
        # Amendment (aj): a carried receipt not reachable from a selected one is
        # judged by its objective index entry; none at all is out of scope too.
        index_entries: dict[bytes, dict[str, Any]] = {}
        for manifest in manifests.values():
            for entry in manifest["receipt_index"]["entries"]:
                index_entries.setdefault(entry["receipt_id"], entry)
        for receipt_id in state.receipts_by_id:
            entry = index_entries.get(receipt_id)
            if receipt_id not in reachable and (entry is None or not _selector_matches(selector, entry)):
                _fail("bundle/artifact-out-of-scope", 18)
        state.observations.append("producer_declared_complete")
    state.observations.append("ingress_completeness_not_established")


def _evidence_classes(state: State) -> None:
    time_order = {"asserted": 0, "boot_bound": 1, "externally_anchored": 2}
    provenance_order = {"self_asserted": 0, "proxy_captured": 1, "provider_attested": 2}
    outcome_order = {"accepted": 0, "dispatched": 1, "device_acknowledged": 2, "independently_sensed": 3}
    # D-82 part 6: every maximum class starts at not_evaluated (harness parity).
    maximum_time = maximum_provenance = maximum_outcome = "not_evaluated"
    anchors = {env.payload["anchor_id"]: env.payload for env in state.envelopes["anchors"]}
    manifests_by_id = {env.payload["manifest_id"]: env.payload for env in state.envelopes["epoch_manifests"]}

    def ancestor_domains(receipt: dict[str, Any]) -> list[Any]:
        """Amendment (s): the source_device.failure_domain_id of every ancestor
        (every edge type, each receipt once) whose source_device is a text-keyed map."""
        queue = deque(parent["parent_id"] for parent in receipt["parents"])
        seen: set[bytes] = set()
        domains: list[Any] = []
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            ancestor = state.receipts_by_id.get(node)
            if ancestor is None:
                continue
            device = ancestor.payload["body"].get("source_device")
            if _type_ok(device, "map") and "failure_domain_id" in device:
                domains.append(device["failure_domain_id"])
            queue.extend(parent["parent_id"] for parent in ancestor.payload["parents"])
        return domains
    for envelope in state.envelopes["receipts"]:
        receipt = envelope.payload
        evidence = receipt["evidence"]
        time = evidence["time"]
        declared = time["class"]
        if declared in {"boot_bound", "externally_anchored"}:
            artifact_id = time.get("boot_attestation_id")
            if not _bstr(artifact_id, 32):  # amendment (q): a non-32-byte id resolves to nothing
                _fail("evidence/time-class-unsatisfied", 19)
            if artifact_id not in state.payloads_by_digest:
                _fail("manifest/payload-missing", 19)
        if declared == "externally_anchored":
            anchor = anchors.get(time.get("anchor_id")) if _bstr(time.get("anchor_id"), 32) else None
            anchor_manifest = manifests_by_id.get(anchor["manifest_id"]) if anchor is not None else None  # amendment (aa)
            binding = receipt["binding"]
            if anchor is None or anchor_manifest is None or anchor["epoch_id"] >= binding["epoch_id"] \
                    or anchor["tenant_id"] != binding["tenant_id"] \
                    or anchor["site_id"] != binding["site_id"] \
                    or anchor_manifest["epoch_owner_kid"] != binding["epoch_owner_kid"] \
                    or anchor["accepted_at"] > receipt["emission"]["committed_at"]:
                _fail("evidence/time-class-unsatisfied", 19)
        if maximum_time == "not_evaluated" or time_order[declared] > time_order[maximum_time]:
            maximum_time = declared

        provenance = evidence.get("provenance")
        if provenance:
            declared = provenance["class"]
            if declared in {"proxy_captured", "provider_attested"}:
                capture = provenance.get("capture_attestation_id")
                if not _bstr(capture, 32):
                    _fail("evidence/provenance-class-unsatisfied", 19)
                if capture not in state.payloads_by_digest:
                    _fail("manifest/payload-missing", 19)
            if declared == "provider_attested":
                provider = provenance.get("provider_attestation_id")
                if not _bstr(provider, 32):
                    _fail("evidence/provenance-class-unsatisfied", 19)
                if provider not in state.payloads_by_digest:
                    _fail("manifest/payload-missing", 19)
            if maximum_provenance == "not_evaluated" or provenance_order[declared] > provenance_order[maximum_provenance]:
                maximum_provenance = declared

        outcome = evidence.get("outcome")
        if outcome:
            level = outcome["level"]
            if level == "independently_sensed":
                predicate = outcome.get("qualifying_predicate_id")
                if not _bstr(predicate, 32):
                    _fail("evidence/outcome-class-unsatisfied", 19)
                if predicate not in state.payloads_by_digest:
                    _fail("manifest/payload-missing", 19)
                observer = receipt["body"].get("observer")
                # Amendment (u): an absent observer has no domain and is not contained; a null domain is a value.
                if _type_ok(observer, "map") and "failure_domain_id" in observer \
                        and any(dumps(domain) == dumps(observer["failure_domain_id"]) for domain in ancestor_domains(receipt)):
                    _fail("evidence/observer-not-independent", 19)
            if level == "contradicted":
                maximum_outcome = level
            elif level == "unknown" and maximum_outcome != "contradicted":
                maximum_outcome = level
            elif level in outcome_order and maximum_outcome not in {"contradicted", "unknown"} \
                    and (maximum_outcome == "not_evaluated"
                         or outcome_order[level] > outcome_order[maximum_outcome]):
                maximum_outcome = level
    state.classes = {"time": maximum_time, "provenance": maximum_provenance, "outcome": maximum_outcome}


def _prior_emissions_map(value: dict[str, Any]) -> dict[str, Any]:
    entries = [{
        "issuer_kid": bytes.fromhex(entry["issuer_kid"]),
        "issuer_seq": entry["issuer_seq"],
        "epoch_owner_kid": bytes.fromhex(entry["epoch_owner_kid"]),
        "epoch_id": entry["epoch_id"],
        "epoch_seq": entry["epoch_seq"],
        "receipt_id": bytes.fromhex(entry["receipt_id"]),
        "envelope_digest": bytes.fromhex(entry["envelope_digest"]),
    } for entry in value.get("prior_emissions", [])]
    emission_order = [
        dumps([entry["issuer_kid"], entry["issuer_seq"], entry["epoch_owner_kid"],
               entry["epoch_id"], entry["epoch_seq"], entry["receipt_id"], entry["envelope_digest"]])
        for entry in entries
    ]
    if any(previous >= current for previous, current in zip(emission_order, emission_order[1:])):
        raise ValueError("prior-state.prior_emissions must be strictly sorted and unique")
    return {"entries": entries}


def _contains_value(container: Any, target_bytes: bytes) -> bool:
    if dumps(container) == target_bytes:
        return True
    if isinstance(container, dict):
        return any(_contains_value(value, target_bytes) for value in container.values())
    if isinstance(container, list):
        return any(_contains_value(value, target_bytes) for value in container)
    return False


def evaluate(
    raw: bytes,
    *,
    evaluated_at: int,
    prior_state: dict[str, Any] | None = None,
    replay_state: dict[str, Any] | None = None,
    context_bundle_raw: bytes | None = None,
    configured_trust_policy: dict[str, Any] | None = None,
    configuration: relying_party.Configuration | None = None,
) -> Evaluation:
    """Evaluate exact input bytes and return one deterministic signed verdict.

    ``context_bundle_raw`` is used only for standalone KAT wire objects. The
    standalone object must occur byte-identically in that bundle; all trust,
    closure, and scope values then come from the supplied bundle context while
    ``bundle_digest`` continues to bind the exact standalone fixture bytes.
    """
    if not _uint(evaluated_at):
        raise ValueError("evaluated_at must be an explicit uint <= 2^53-1")
    if prior_state is not None:
        _prior_emissions_map(prior_state)
    state = State(
        raw=raw,
        evaluated_at=evaluated_at,
        prior_state=prior_state,
        replay_state=replay_state,
        configured_trust_policy=configured_trust_policy,
        configuration=configuration,
    )
    result = "conformant"
    reason: str | None = None
    step = 20
    try:
        if len(raw) > LIMITS["exact_encoded_bundle_bytes"]:
            _fail("resource/bundle-too-large", 1)
        try:
            decoded = loads(raw, max_depth=LIMITS["cbor_container_nesting"])
        except CBORError as exc:
            _fail(exc.code, 2)
        # Amendment (j): a map is a bundle unless a standalone context was supplied
        # for a map-shaped wire object (a Merkle proof); the closed-map check
        # then reports a missing top-level member.
        if isinstance(decoded, dict) and (context_bundle_raw is None or set(decoded) >= {"selector", "artifacts", "trust_inputs"}):
            state.bundle = _schema_bundle(decoded)
        elif context_bundle_raw is not None:
            context = loads(context_bundle_raw)
            if not _contains_value(context, raw):
                _fail("bundle/dependency-missing", 3)
            state.bundle = _schema_bundle(context)
        else:
            _fail("schema/bad-type", 3)
        _resource_checks(state.bundle)
        _trust_policy_checks(state)
        _envelope_checks(state)
        _content_commitments(state)
        _credential_lifecycle(state)
        _emission_identity(state)
        _receipt_semantics(state)
        _mediator_countersignature_checks(state)
        _replay_freshness(state)
        graph = _graph_checks(state)
        _authorization_dominance(state, graph)
        _input_origin_ancestry(state, graph)
        _epoch_state_machine(state)
        _manifest_index_checks(state)
        _merkle_checks(state)
        _anchor_checks(state)
        _bundle_ranges(state)
        _evidence_classes(state)
        relying_party.verifier_identity(state)
    except ValidationError as exc:
        result = "indeterminate" if exc.indeterminate else "nonconformant"
        reason = exc.code
        step = exc.step
    fields = verdict._verdict_fields(state, result, reason, step)
    signed, verdict_bytes = verdict._sign_verdict(fields, state.configuration)
    report_observations = list(signed["observations"])
    if result == "conformant" and state.selector_matching_receipts == 0:
        report_observations.append("empty_scope")
    if prior_state is None:
        report_observations.append("stateful_not_evaluated")

    steps = []
    for number, name in enumerate(STEP_NAMES, 1):
        if result == "conformant" or number < step or number == 20:
            status = "pass"
        elif number == step:
            status = "fail"
        else:
            status = "not_evaluated"
        steps.append({"step": number, "name": name, "status": status})
    report = {
        "first_failure_step": None if result == "conformant" else step,
        "first_failure_reason": reason,
        "steps": steps,
        "observations": list(dict.fromkeys(report_observations)),
        "report_layer_observations": [
            observation for observation in report_observations
            if observation in {"empty_scope", "stateful_not_evaluated"}
        ],
        "selector_matching_receipts": state.selector_matching_receipts,
        "input_origin_ancestry": {
            "bundle_digest": signed["bundle_digest"].hex(),
            "verdict_id": signed["verdict_id"].hex(),
            "attempts": state.input_origin_attempts if result == "conformant" else [],
        },
        "stateful_properties": state.stateful_checks,
        "replay_state": "not_evaluated" if replay_state is None else "evaluated",
    }
    return Evaluation(result, reason, step, signed, verdict_bytes, report)
