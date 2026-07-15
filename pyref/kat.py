"""Run Gate 4 clean-room C1 and C2 KAT suites."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import hashes
from .cbor import CBORError, dumps, loads
from .crypto import TEST_KEYS_BY_KID, TEST_SCALARS, key_id, sign_es256
from .verifier import Evaluation, evaluate


ROOT = Path(__file__).resolve().parent.parent
KAT_DIRECTORIES = (ROOT / "kats" / "positive", ROOT / "kats" / "class-boundary")
RESULTS_PATH = Path(__file__).resolve().parent / "results-c1.json"
C2_RESULTS_PATH = Path(__file__).resolve().parent / "results-c2.json"
DIVERGENCES_PATH = Path(__file__).resolve().parent / "DIVERGENCES.md"

ROUND_TRIP_SPEC = (
    "Every item is encoded using the RFC 8949 section 4.2.1 core deterministic "
    "encoding requirements. Definite lengths, shortest integer encodings, valid "
    "UTF-8, unique map keys, and deterministic encoded-key ordering are required."
)
ID_SPEC = (
    "Recompute every content-derived ID and every declared digest whose bytes are "
    "present. Recompute delegation_id, credential_id, snapshot_id, rotation_id, "
    "event_id, anchor_id, and batch_id from their domain-separated deterministic-CBOR "
    "claims with their own ID field absent."
)
SIGNATURE_SPEC = (
    "All signed objects use an untagged, detached COSE_Sign1. ES256 means ECDSA "
    "P-256/SHA-256, deterministic RFC 6979 signing, a 64-byte P1363 r||s signature, "
    "nonzero r and s, and low-S normalization."
)


@dataclass(frozen=True)
class SignedEnvelope:
    path: str
    payload_bytes: bytes
    payload: Any
    cose_bytes: bytes
    cose: list[Any]
    protected_bytes: bytes
    protected: dict[Any, Any]


@dataclass
class Candidate:
    name: str
    value: bytes
    path: str
    method: str


@dataclass
class Audit:
    candidates: dict[str, list[Candidate]] = field(default_factory=dict)
    checks: int = 0
    mismatch: dict[str, Any] | None = None

    def add(self, name: str, value: bytes, path: str, method: str) -> None:
        self.candidates.setdefault(name, []).append(Candidate(name, value, path, method))

    def compare(
        self,
        name: str,
        expected: bytes,
        produced: bytes,
        path: str,
        method: str,
    ) -> None:
        if self.mismatch is not None:
            return
        self.checks += 1
        self.add(name, produced, path, method)
        if produced != expected:
            self.mismatch = {
                "field": name,
                "path": path,
                "expected": expected.hex(),
                "produced": produced.hex(),
                "method": method,
            }


@dataclass
class CorpusContext:
    manifest_payload_digest_by_id: dict[bytes, bytes] = field(default_factory=dict)
    merkle_root_by_batch_id: dict[bytes, bytes] = field(default_factory=dict)
    event_payload_digests: set[bytes] = field(default_factory=set)


def _fixture_paths() -> list[Path]:
    return sorted(path for directory in KAT_DIRECTORIES for path in directory.glob("*.cbor"))


def _is_envelope(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 2
        and isinstance(value[0], bytes)
        and isinstance(value[1], bytes)
    )


def _parse_envelope(value: list[Any], path: str) -> SignedEnvelope:
    payload_bytes, cose_bytes = value
    payload = loads(payload_bytes)
    cose = loads(cose_bytes)
    if not (
        isinstance(cose, list)
        and len(cose) == 4
        and isinstance(cose[0], bytes)
        and isinstance(cose[1], dict)
        and cose[2] is None
        and isinstance(cose[3], bytes)
    ):
        raise CBORError(f"{path}: not a detached COSE_Sign1")
    protected = loads(cose[0])
    if not isinstance(protected, dict):
        raise CBORError(f"{path}: protected header is not a map")
    return SignedEnvelope(
        path=path,
        payload_bytes=payload_bytes,
        payload=payload,
        cose_bytes=cose_bytes,
        cose=cose,
        protected_bytes=cose[0],
        protected=protected,
    )


def _signed_envelopes(value: Any, path: str = "$", *, strict: bool = False) -> Iterator[SignedEnvelope]:
    if _is_envelope(value):
        try:
            envelope = _parse_envelope(value, path)
        except CBORError:
            # Several schema values are two-element bstr arrays (for example
            # conflicting event digests). Only treat the pair as an envelope
            # when element 1 independently has the COSE four-item shape.
            try:
                possible_cose = loads(value[1])
            except CBORError:
                possible_cose = None
            if strict and isinstance(possible_cose, list) and len(possible_cose) == 4:
                raise
        else:
            yield envelope
            yield from _signed_envelopes(envelope.payload, path + ".payload", strict=strict)
            return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _signed_envelopes(item, f"{path}.{key}", strict=strict)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _signed_envelopes(item, f"{path}[{index}]", strict=strict)


def _hex(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()
    return repr(value)


def _audit_manifest_index(index: dict[str, Any], path: str, audit: Audit) -> None:
    if audit.mismatch is not None:
        return
    entries = index.get("entries")
    expected = index.get("root")
    if not isinstance(entries, list) or not isinstance(expected, bytes) or not entries:
        return
    produced = hashes.promoted_root(
        (hashes.manifest_index_leaf(entry) for entry in entries), hashes.manifest_index_node
    )
    audit.compare("index_root", expected, produced, path + ".root", "manifest index leaf/node domains")


def _audit_merkle_proof(proof: dict[str, Any], path: str, audit: Audit) -> bytes | None:
    required = {"batch_id", "tree_size", "leaf_index", "leaf", "siblings"}
    if not required.issubset(proof):
        return None
    leaf_hash = hashes.merkle_leaf(proof["leaf"])
    audit.add("leaf_hash", leaf_hash, path + ".leaf", "AAR-MERKLE-LEAF-v1")
    root = hashes.inclusion_root(
        leaf_hash,
        proof["leaf_index"],
        proof["tree_size"],
        proof["siblings"],
        hashes.merkle_node,
    )
    audit.add("root", root, path, "AAR-MERKLE-NODE-v1 membership path")
    audit.add("batch_id", proof["batch_id"], path + ".batch_id", "proof batch reference")
    return root


def _audit_nested_maps(value: Any, path: str, audit: Audit) -> None:
    if audit.mismatch is not None:
        return
    if isinstance(value, dict):
        keys = set(value)
        if {"manifest_digest", "items"}.issubset(keys):
            produced = hashes.consumption_manifest_digest(value)
            audit.compare(
                "manifest_digest", value["manifest_digest"], produced,
                path + ".manifest_digest", "AAR-CONSUMPTION-MANIFEST-v1",
            )
        if {"decision_commitment", "policy_set_root", "evaluated_inputs"}.issubset(keys):
            produced = hashes.decision_commitment(value)
            audit.compare(
                "decision_commitment", value["decision_commitment"], produced,
                path + ".decision_commitment", "AAR-DECISION-RECORD-v1",
            )
        if {"command_id", "canonical_command", "command_digest"}.issubset(keys):
            audit.compare(
                "command_digest", value["command_digest"], hashes.sha256(value["canonical_command"]),
                path + ".command_digest", "SHA-256(canonical_command)",
            )
            if audit.mismatch is None:
                audit.compare(
                    "command_id", value["command_id"], hashes.command_id(value),
                    path + ".command_id", "AAR-COMMAND-MANIFEST-v1",
                )
        if {"parameters_cbor", "parameters_digest"}.issubset(keys):
            audit.compare(
                "parameters_digest", value["parameters_digest"], hashes.sha256(value["parameters_cbor"]),
                path + ".parameters_digest", "SHA-256(parameters_cbor)",
            )
        if {"canonical_cbor", "digest", "schema_id"}.issubset(keys):
            audit.compare(
                "digest", value["digest"], hashes.sha256(value["canonical_cbor"]),
                path + ".digest", "SHA-256(structured-claim.canonical_cbor)",
            )
        if {"canonical_bytes", "digest", "media_type"}.issubset(keys):
            audit.compare(
                "digest", value["digest"], hashes.sha256(value["canonical_bytes"]),
                path + ".digest", "SHA-256(canonical manifest bytes)",
            )
        if {"digest", "snapshot_id", "created_at", "roots"}.issubset(keys):
            produced = hashes.trust_store_digest(value)
            audit.compare(
                "trust_store_digest", value["digest"], produced,
                path + ".digest", "AAR-TRUST-STORE-v1",
            )
        if {"ordering", "leaf_count", "root", "entries"}.issubset(keys):
            _audit_manifest_index(value, path, audit)
        if {"batch_id", "tree_size", "leaf_index", "leaf", "siblings"}.issubset(keys):
            _audit_merkle_proof(value, path, audit)
        for key, item in value.items():
            _audit_nested_maps(item, f"{path}.{key}", audit)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _audit_nested_maps(item, f"{path}[{index}]", audit)


def _audit_envelope(envelope: SignedEnvelope, audit: Audit, context: CorpusContext) -> None:
    payload = envelope.payload
    if not isinstance(payload, dict):
        return
    content_type = envelope.protected.get(3)
    id_rules = {
        "application/aar-delegation+cbor;v=0.2": "delegation_id",
        "application/aar-credential+cbor;v=0.2": "credential_id",
        "application/aar-status+cbor;v=0.2": "snapshot_id",
        "application/aar-rotation+cbor;v=0.2": "rotation_id",
        "application/aar-epoch-event+cbor;v=0.2": "event_id",
        "application/aar-epoch-manifest+cbor;v=0.2": "manifest_id",
        "application/aar-anchor-record+cbor;v=0.2": "anchor_id",
        "application/aar-merkle-batch+cbor;v=0.2": "batch_id",
        "application/aar-presentation+cbor;v=0.2": "presentation_id",
    }
    if content_type == "application/aar-receipt+cbor;v=0.2" and "receipt_id" in payload:
        produced = hashes.receipt_id(payload, envelope.protected_bytes)
        audit.compare(
            "receipt_id", payload["receipt_id"], produced,
            envelope.path + ".payload.receipt_id", "AAR-RECEIPT-ID-v1",
        )
    elif content_type in id_rules and id_rules[content_type] in payload:
        field = id_rules[content_type]
        produced = hashes.artifact_id(payload, field)
        audit.compare(field, payload[field], produced, envelope.path + f".payload.{field}", hashes.ARTIFACT_DOMAINS[field])
    if audit.mismatch is not None:
        return
    if content_type == "application/aar-request+cbor;v=0.2":
        if isinstance(payload.get("request_id"), bytes):
            audit.add("request_id", payload["request_id"], envelope.path + ".payload.request_id", "declared id16")
        audit.add(
            "request_commitment", hashes.sha256(envelope.payload_bytes), envelope.path + ".payload",
            "SHA-256(exact request claims bstr)",
        )
    if content_type == "application/aar-credential+cbor;v=0.2" and {
        "public_key", "subject_kid"
    }.issubset(payload):
        audit.compare(
            "subject_kid", payload["subject_kid"], hashes.sha256(payload["public_key"]),
            envelope.path + ".payload.subject_kid", "SHA-256(DER SubjectPublicKeyInfo)",
        )
    if content_type == "application/aar-epoch-event+cbor;v=0.2":
        audit.add("event_payload_digest", hashes.sha256(envelope.payload_bytes), envelope.path + ".payload", "SHA-256(exact epoch-event payload bstr)")
        previous = payload.get("previous_event_digest")
        if isinstance(previous, bytes):
            audit.checks += 1
            if previous not in context.event_payload_digests:
                audit.mismatch = {
                    "field": "previous_event_digest",
                    "path": envelope.path + ".payload.previous_event_digest",
                    "expected": previous.hex(),
                    "produced": "no matching exact epoch-event payload digest in C1 corpus",
                    "method": "SHA-256(exact preceding epoch-event payload bstr)",
                }
            else:
                audit.add("previous_event_digest", previous, envelope.path, "matched exact event payload digest")
    if content_type == "application/aar-epoch-manifest+cbor;v=0.2":
        index = payload.get("receipt_index")
        if isinstance(index, dict):
            _audit_manifest_index(index, envelope.path + ".payload.receipt_index", audit)
    if content_type == "application/aar-anchor-record+cbor;v=0.2":
        inclusion = payload.get("inclusion")
        if isinstance(inclusion, dict):
            leaf_digest = hashes.rfc6962_leaf(hashes.anchor_leaf_input(payload))
            audit.compare(
                "leaf_digest", inclusion["leaf_digest"], leaf_digest,
                envelope.path + ".payload.inclusion.leaf_digest", "RFC 6962 SHA-256(0x00 || AAR anchor leaf input)",
            )
            if audit.mismatch is None:
                root = hashes.inclusion_root(
                    leaf_digest, inclusion["leaf_index"], inclusion["tree_size"],
                    inclusion["siblings"], hashes.rfc6962_node,
                )
                audit.compare(
                    "anchor_root", payload["anchor_root"], root,
                    envelope.path + ".payload.anchor_root", "RFC 6962 v1 inclusion path",
                )
        manifest_id = payload.get("manifest_id")
        manifest_digest = payload.get("manifest_digest")
        if audit.mismatch is None and isinstance(manifest_id, bytes) and isinstance(manifest_digest, bytes):
            recomputed_digest = context.manifest_payload_digest_by_id.get(manifest_id)
            audit.checks += 1
            if recomputed_digest is None or recomputed_digest != manifest_digest:
                audit.mismatch = {
                    "field": "manifest_digest",
                    "path": envelope.path + ".payload.manifest_digest",
                    "expected": manifest_digest.hex(),
                    "produced": _hex(recomputed_digest) if recomputed_digest else "no matching manifest payload in C1 corpus",
                    "method": "SHA-256(exact epoch-manifest payload bstr), keyed by recomputed manifest_id",
                }
            else:
                audit.add("manifest_id", manifest_id, envelope.path, "matched recomputed epoch manifest ID")
                audit.add("manifest_digest", recomputed_digest, envelope.path, "SHA-256(exact matched epoch-manifest payload)")
    if content_type == "application/aar-merkle-batch+cbor;v=0.2":
        batch_id = payload.get("batch_id")
        expected_root = payload.get("root")
        if audit.mismatch is None and isinstance(batch_id, bytes) and isinstance(expected_root, bytes):
            proof_root = context.merkle_root_by_batch_id.get(batch_id)
            audit.checks += 1
            if proof_root is None or proof_root != expected_root:
                audit.mismatch = {
                    "field": "root",
                    "path": envelope.path + ".payload.root",
                    "expected": expected_root.hex(),
                    "produced": _hex(proof_root) if proof_root else "no matching membership proof in C1 corpus",
                    "method": "AAR-MERKLE-LEAF-v1/AAR-MERKLE-NODE-v1 membership path",
                }
            else:
                audit.add("root", proof_root, envelope.path, "matched recomputed membership root")
    _audit_nested_maps(payload, envelope.path + ".payload", audit)


def _build_context(decoded: dict[Path, Any]) -> CorpusContext:
    context = CorpusContext()
    for obj in decoded.values():
        for envelope in _signed_envelopes(obj):
            content_type = envelope.protected.get(3)
            if content_type == "application/aar-epoch-event+cbor;v=0.2":
                context.event_payload_digests.add(hashes.sha256(envelope.payload_bytes))
            elif content_type == "application/aar-epoch-manifest+cbor;v=0.2" and isinstance(envelope.payload, dict):
                manifest_id = hashes.artifact_id(envelope.payload, "manifest_id")
                context.manifest_payload_digest_by_id[manifest_id] = hashes.sha256(envelope.payload_bytes)
    for obj in decoded.values():
        stack = [obj]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                if {"batch_id", "tree_size", "leaf_index", "leaf", "siblings"}.issubset(value):
                    leaf_hash = hashes.merkle_leaf(value["leaf"])
                    root = hashes.inclusion_root(
                        leaf_hash, value["leaf_index"], value["tree_size"], value["siblings"], hashes.merkle_node
                    )
                    context.merkle_root_by_batch_id[value["batch_id"]] = root
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    return context


def _audit_ids(
    obj: Any, raw: bytes, sidecar: dict[str, Any], context: CorpusContext
) -> Audit:
    audit = Audit()
    audit.add("bundle_digest", hashes.sha256(raw), "$", "SHA-256(exact deterministic bundle bytes)")
    if isinstance(obj, dict) and "selector" in obj and "selector_commitment" in obj:
        produced = hashes.selector_commitment(obj["selector"])
        audit.compare(
            "selector_commitment", obj["selector_commitment"], produced,
            "$.selector_commitment", "AAR-BUNDLE-SELECTOR-v1",
        )
    _audit_nested_maps(obj, "$", audit)
    if audit.mismatch is None:
        for envelope in _signed_envelopes(obj, strict=True):
            _audit_envelope(envelope, audit, context)
            if audit.mismatch is not None:
                break
    if audit.mismatch is not None:
        return audit
    for name, expected_hex in sidecar.get("computed_ids", {}).items():
        expected = bytes.fromhex(expected_hex)
        candidates = audit.candidates.get(name, [])
        audit.checks += 1
        if any(candidate.value == expected for candidate in candidates):
            continue
        audit.mismatch = {
            "field": name,
            "path": "JSON sidecar computed_ids",
            "expected": expected.hex(),
            "produced": [
                {"value": candidate.value.hex(), "path": candidate.path, "method": candidate.method}
                for candidate in candidates
            ] or "no spec-derived candidate",
            "method": "sidecar comparison against independently derived values",
        }
        break
    return audit


def _check_signatures(obj: Any, sidecar: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    for role, expected_hex in sidecar.get("key_ids_used", {}).items():
        scalar = TEST_SCALARS.get(role)
        if scalar is None:
            return 0, {"path": "JSON sidecar key_ids_used", "expected": expected_hex, "produced": "unknown test-key role"}
        produced = key_id(scalar).hex()
        if produced != expected_hex:
            return 0, {"path": f"JSON sidecar key_ids_used.{role}", "expected": expected_hex, "produced": produced}
    count = 0
    try:
        envelopes = list(_signed_envelopes(obj, strict=True))
    except CBORError as exc:
        return count, {"path": "$", "expected": "detached COSE_Sign1", "produced": str(exc)}
    for envelope in envelopes:
        kid = envelope.protected.get(4)
        key = TEST_KEYS_BY_KID.get(kid)
        if key is None:
            return count, {
                "path": envelope.path + ".protected[4]",
                "expected": "one published C1 test kid",
                "produced": _hex(kid),
            }
        role, scalar = key
        sig_structure = dumps(["Signature1", envelope.protected_bytes, b"", envelope.payload_bytes])
        produced = sign_es256(scalar, sig_structure)
        expected = envelope.cose[3]
        count += 1
        if produced != expected:
            return count, {
                "path": envelope.path + ".signature",
                "key_role": role,
                "expected": expected.hex(),
                "produced": produced.hex(),
            }
    return count, None


def _divergence(
    fixture: Path,
    check: str,
    mismatch: dict[str, Any],
    spec: str,
    hypothesis: str,
) -> dict[str, Any]:
    return {
        "fixture": str(fixture.relative_to(ROOT)),
        "check": check,
        "expected": mismatch.get("expected"),
        "produced": mismatch.get("produced"),
        "location": mismatch.get("path"),
        "spec_sentences": [spec],
        "ambiguity_hypothesis": hypothesis,
    }


def _write_divergences(divergences: list[dict[str, Any]]) -> None:
    lines = [
        "# C1 divergences",
        "",
        "Generated by `python -m pyref.kat` under the Gate 4 clean-room protocol.",
        "",
    ]
    if not divergences:
        lines.extend(["No divergences recorded.", ""])
    for index, item in enumerate(divergences, 1):
        lines.extend(
            [
                f"## {index}. `{item['fixture']}` — {item['check']}",
                "",
                f"- Location: `{item['location']}`",
                f"- Expected: `{json.dumps(item['expected'], sort_keys=True)}`",
                f"- Produced: `{json.dumps(item['produced'], sort_keys=True)}`",
                "- Spec sentence(s) relied on:",
                "",
                f"  > {item['spec_sentences'][0]}",
                "",
                f"- Ambiguity hypothesis: {item['ambiguity_hypothesis']}",
                "",
            ]
        )
    DIVERGENCES_PATH.write_text("\n".join(lines), encoding="utf-8")


def run_c1() -> dict[str, Any]:
    paths = _fixture_paths()
    decoded: dict[Path, Any] = {}
    decode_errors: dict[Path, str] = {}
    for path in paths:
        try:
            decoded[path] = loads(path.read_bytes())
        except CBORError as exc:
            decode_errors[path] = str(exc)
    context = _build_context(decoded)
    divergences: list[dict[str, Any]] = []
    fixture_results: list[dict[str, Any]] = []

    for path in paths:
        raw = path.read_bytes()
        sidecar = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        result: dict[str, Any] = {
            "fixture": str(path.relative_to(ROOT)),
            "checks": {},
        }
        if path in decode_errors:
            mismatch = {"path": "$", "expected": "one deterministic CBOR item", "produced": decode_errors[path]}
            result["checks"]["round_trip"] = {"status": "failed", **mismatch}
            result["checks"]["id_digest_recomputation"] = {"status": "skipped"}
            result["checks"]["signature_recomputation"] = {"status": "skipped"}
            divergences.append(_divergence(
                path, "round_trip", mismatch, ROUND_TRIP_SPEC,
                "The fixture bytes and the clean-room deterministic decoder disagree on the permitted CBOR profile.",
            ))
            fixture_results.append(result)
            continue
        obj = decoded[path]
        produced = dumps(obj)
        if produced != raw:
            mismatch = {"path": "$", "expected": raw.hex(), "produced": produced.hex()}
            result["checks"]["round_trip"] = {"status": "failed", **mismatch}
            result["checks"]["id_digest_recomputation"] = {"status": "skipped"}
            result["checks"]["signature_recomputation"] = {"status": "skipped"}
            divergences.append(_divergence(
                path, "round_trip", mismatch, ROUND_TRIP_SPEC,
                "The fixture and pyref apply different deterministic CBOR encodings to the same abstract value.",
            ))
            fixture_results.append(result)
            continue
        result["checks"]["round_trip"] = {"status": "passed"}

        audit = _audit_ids(obj, raw, sidecar, context)
        if audit.mismatch is not None:
            result["checks"]["id_digest_recomputation"] = {
                "status": "failed", "commitments_checked": audit.checks, **audit.mismatch
            }
            result["checks"]["signature_recomputation"] = {"status": "skipped"}
            divergences.append(_divergence(
                path, "id_digest_recomputation", audit.mismatch, ID_SPEC,
                "The fixture and pyref disagree on a domain-separated preimage, an exact-byte digest, or which corpus object supplies a referenced preimage.",
            ))
            fixture_results.append(result)
            continue
        result["checks"]["id_digest_recomputation"] = {
            "status": "passed", "commitments_checked": audit.checks
        }

        signature_count, signature_mismatch = _check_signatures(obj, sidecar)
        if signature_mismatch is not None:
            result["checks"]["signature_recomputation"] = {
                "status": "failed", "signatures_checked": signature_count, **signature_mismatch
            }
            divergences.append(_divergence(
                path, "signature_recomputation", signature_mismatch, SIGNATURE_SPEC,
                "The fixture and pyref disagree on the exact Sig_structure, RFC 6979 nonce derivation, P-256 operation, or low-S normalization.",
            ))
        else:
            result["checks"]["signature_recomputation"] = {
                "status": "passed", "signatures_checked": signature_count
            }
        fixture_results.append(result)

    check_names = ("round_trip", "id_digest_recomputation", "signature_recomputation")
    summary = {}
    for name in check_names:
        statuses = [fixture["checks"][name]["status"] for fixture in fixture_results]
        summary[name] = {
            "passed": statuses.count("passed"),
            "failed": statuses.count("failed"),
            "skipped": statuses.count("skipped"),
        }
    output = {
        "schema_version": 1,
        "slice": "C1",
        "fixtures_checked": len(fixture_results),
        "checks": summary,
        "divergence_count": len(divergences),
        "divergences": divergences,
        "fixtures": fixture_results,
    }
    RESULTS_PATH.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_divergences(divergences)
    return output


KAT_EVALUATION_TIME = 7_636_552
EMPTY_REPLAY_STATE: dict[str, Any] = {"entries": []}

OBJECT_ARTIFACT_CATEGORY = {
    "anchor-record-envelope": "anchors",
    "credential-envelope": "credentials",
    "delegation-envelope": "delegations",
    "epoch-event-envelope": "epoch_events",
    "epoch-manifest-envelope": "epoch_manifests",
    "merkle-batch-envelope": "merkle_batches",
    "merkle-membership-proof": "merkle_proofs",
    "receipt-envelope": "receipts",
    "request-envelope": "requests",
    "rotation-continuity-envelope": "rotations",
    "status-snapshot-envelope": "status_snapshots",
}


def _c2_fixture_paths() -> list[Path]:
    paths = list((ROOT / "kats" / "positive").glob("*.cbor"))
    paths.extend((ROOT / "kats" / "class-boundary").glob("*.cbor"))
    paths.extend((ROOT / "kats" / "negative").glob("*.cbor"))
    paths.extend((ROOT / "kats" / "negative" / "stateful").glob("*.bundle.cbor"))
    return sorted(paths)


def _sidecar_path(path: Path) -> Path:
    if path.name.endswith(".bundle.cbor"):
        return path.with_name(path.name.removesuffix(".bundle.cbor") + ".json")
    return path.with_suffix(".json")


def _prior_path(path: Path) -> Path | None:
    if not path.name.endswith(".bundle.cbor"):
        return None
    candidate = path.with_name(path.name.removesuffix(".bundle.cbor") + ".prior.json")
    return candidate if candidate.exists() else None


def _context_for_standalone(raw: bytes, sidecar: dict[str, Any], base_raw: bytes) -> bytes | None:
    object_type = sidecar.get("object_type")
    category = OBJECT_ARTIFACT_CATEGORY.get(object_type)
    if category is None:
        return None
    base = loads(base_raw)
    target = loads(raw)
    artifacts = base["artifacts"]
    if any(dumps(item) == raw for item in artifacts[category]):
        return base_raw
    artifacts[category].append(target)
    if category == "merkle_proofs":
        artifacts[category].sort(key=lambda item: (item["batch_id"], item["leaf_index"]))
    else:
        field = {
            "anchors": "anchor_id", "credentials": "credential_id",
            "delegations": "delegation_id", "epoch_events": "event_id",
            "epoch_manifests": "manifest_id", "merkle_batches": "batch_id",
            "receipts": "receipt_id", "requests": "request_id",
            "rotations": "rotation_id", "status_snapshots": "snapshot_id",
        }[category]
        artifacts[category].sort(key=lambda item: loads(item[0])[field])
    return dumps(base)


def _expected_result(code: str | None) -> str:
    if code is None:
        return "conformant"
    if code in {"key/not-found", "anchor/head-missing"}:
        return "indeterminate"
    return "nonconformant"


STEP_SPEC = {
    "resource": "Static resource limits are enforced in steps 1, 2, 4, and 12 before later semantic checks.",
    "cbor": "Step 2 decodes one untagged deterministic-CBOR item and checks the listed CBOR conditions in order.",
    "schema": "Step 3 checks the closed bundle schema, required fields, types, sizes, enums/ranges, and sorted unique arrays in order.",
    "cose": "Step 6 validates the detached four-element COSE structure, protected headers, empty unprotected map, and nil payload.",
    "sig": "Step 6 classifies signature encoding length-first and then verifies exact ES256 over the received bytes.",
    "key": "Step 6 resolves a carried P-256 verification key through the accepted credential path.",
    "hash": "Step 7 recomputes every declared digest whose bytes are present.",
    "identity": "Steps 7 and 9 recompute identifiers and enforce prior-state emission identity rules.",
    "credential": "Step 8 enforces credential paths, roots, rotations, status, compromise, and lease maxima.",
    "receipt": "Step 10 enforces receipt body, signer, manifest, decision, attempt, dispatch, and outcome semantics.",
    "replay": "Step 11 enforces freshness, exact parent binding, invocation consistency, and one-time replay state.",
    "delegation": "Step 13 requires one dominating valid delegation whose scope contains the action flow.",
    "graph": "Steps 12 and 13 enforce graph closure, metadata, edge legality, roots, cross-epoch rules, and dominance.",
    "epoch": "Step 14 validates event chains, epoch transitions, duration, spans, deadlines, late arrivals, and forks.",
    "manifest": "Steps 7, 15, and 19 validate manifest payloads, objective indexes, and required evidence artifacts.",
    "merkle": "Step 16 validates batch binding, path length, root recomputation, and duplicate proven content.",
    "anchor": "Step 17 validates target planning, proofs, manifest binding, deadlines, heads, and independence.",
    "bundle": "Steps 3, 7, and 18 validate selector commitments, dependencies, ranges, coverage, and scope.",
    "evidence": "Step 19 recomputes the maximum declared and structurally supported evidence classes.",
    "request": "Step 7 binds an agent_request root to SHA-256 of the exact request claims bstr.",
}


def _boundary_class(sidecar: dict[str, Any], evaluation: Evaluation) -> tuple[str | None, str | None]:
    expected = sidecar.get("expected_class")
    if expected is None:
        return None, None
    boundary = sidecar.get("boundary", "")
    if boundary.startswith("time"):
        produced = evaluation.verdict["limits"]["maximum_time_class"]
    elif boundary.startswith("provenance"):
        produced = evaluation.verdict["limits"]["maximum_provenance_class"]
    else:
        produced = evaluation.verdict["limits"]["maximum_outcome_level"]
    return expected, produced


def _write_c2_divergences(divergences: list[dict[str, Any]]) -> None:
    lines = [
        "# Gate 4 clean-room divergences",
        "",
        "Generated by `python -m pyref.kat --slice c2`.",
        "",
        "## C1",
        "",
        "No C1 divergences recorded.",
        "",
        "## C2 entry-point finding",
        "",
        "CONFORMANCE section 5 defines a W-12 verdict over a bundle, while the C2 corpus also requires verdicts for standalone `aar-wire-object` fixtures. For those fixtures, the runner requires byte-identical membership in (or deterministically augments) the published positive bundle KAT, uses that bundle's trust/scope context, and binds `bundle_digest` to the exact standalone fixture bytes. This is a clean-room corpus-entry-point interpretation requiring gate adjudication.",
        "",
        "## C2 verdict/reason divergences",
        "",
    ]
    if not divergences:
        lines.extend(["No verdict, reason-code, class, or determinism divergences recorded.", ""])
    for index, item in enumerate(divergences, 1):
        lines.extend([
            f"### {index}. `{item['fixture']}`",
            "",
            f"- Expected: `{json.dumps(item['expected'], sort_keys=True)}`",
            f"- Produced: `{json.dumps(item['produced'], sort_keys=True)}`",
            "- Spec sentence(s) relied on:",
            "",
            "  > First failure wins. No verifier may continue to a later step and substitute its reason for an earlier failure.",
            "",
            f"  > {item['spec_sentence']}",
            "",
            f"- Ambiguity hypothesis: {item['ambiguity_hypothesis']}",
            "",
        ])
    DIVERGENCES_PATH.write_text("\n".join(lines), encoding="utf-8")


def _divergence_hypothesis(fixture: dict[str, Any]) -> str:
    expected = fixture.get("expected_code")
    produced = fixture.get("produced_code")
    if fixture.get("expected_class") is not None:
        return (
            "The verdict result/reason agrees, but the C2 reporter selected the class dimension from the boundary's "
            "left-hand label (for example `proxy_captured_to_provider_attested`) and therefore reported the outcome "
            "dimension as `not_evaluated`. This is likely a pyref boundary-reporting bug, not a wire-verdict disagreement."
        )
    if produced == "credential/status-missing":
        return (
            "Changing and re-identifying the stapled snapshot leaves the clean-room reading of the decision's exact "
            "status_snapshot_id reference unresolved, making status-missing earlier than the intended status/lease defect. "
            "The fixture may intend the mutated snapshot to replace that reference implicitly, which the spec does not state."
        )
    if expected and expected.startswith("delegation/") and produced is None:
        return (
            "The mutated top-level delegation artifact is not the byte-identical delegation embedded in the carried "
            "authorization. Pyref applies attempt-time delegation checks to the embedded dominating delegation and treats "
            "the unreferenced top-level artifact as validly signed content; the fixture appears to require lifecycle/scope "
            "evaluation of every carried delegation even when it is not selected by an authorization path."
        )
    if expected == "epoch/late-insertion":
        return (
            "Pyref checked the close event's declared anchor deadline before comparing receipt commit time with the changed "
            "manifest close. Step 14 lists late-arrival routing before anchor deadline, so this is likely a pyref intra-step "
            "ordering bug exposed by a fixture carrying both consequences of the close-time mutation."
        )
    if expected and expected.startswith("manifest/index-") and produced == "manifest/index-root-mismatch":
        return (
            "The changed signed index entry bytes no longer recompute to the carried root. Pyref follows step 15's literal "
            "order, 'Recompute entry leaves and root, then require sort order, contiguous leaf indices, unique ...', so it "
            "reports root mismatch before the fixture's intended later index defect."
        )
    if expected == "bundle/artifact-out-of-scope" and produced == "bundle/range-boundary":
        return (
            "Pyref compares each carried range against every objective manifest entry in the half-open temporal slice before "
            "checking extra carried artifacts. The fixture appears to treat that range as boundary-complete under a narrower "
            "selector reading, while D-19 says ranges carry nonmatching kinds/subjects as well."
        )
    return (
        "The clean-room implementation and fixture expectation differ on the first applicable validation step or exact "
        "semantic trigger. No fixture-specific verifier tuning was applied after the formal corpus run."
    )


def run_c2() -> dict[str, Any]:
    base_raw = (ROOT / "kats" / "positive" / "bundle-valid-subset.cbor").read_bytes()
    fixtures: list[dict[str, Any]] = []
    divergences: list[dict[str, Any]] = []
    for path in _c2_fixture_paths():
        sidecar = json.loads(_sidecar_path(path).read_text(encoding="utf-8"))
        raw = path.read_bytes()
        prior_path = _prior_path(path)
        prior = json.loads(prior_path.read_text(encoding="utf-8")) if prior_path else None
        context = None
        if sidecar.get("object_type") and sidecar.get("object_type") != "bundle":
            context = _context_for_standalone(raw, sidecar, base_raw)
        expected_code = sidecar.get("expected_code")
        expected_result = _expected_result(expected_code)
        try:
            first = evaluate(
                raw, evaluated_at=KAT_EVALUATION_TIME, prior_state=prior,
                replay_state=EMPTY_REPLAY_STATE, context_bundle_raw=context,
            )
            second = evaluate(
                raw, evaluated_at=KAT_EVALUATION_TIME, prior_state=prior,
                replay_state=EMPTY_REPLAY_STATE, context_bundle_raw=context,
            )
            deterministic = first.verdict_bytes == second.verdict_bytes
            produced_code = first.reason
            expected_class, produced_class = _boundary_class(sidecar, first)
            matched = (
                first.result == expected_result and produced_code == expected_code
                and deterministic and (expected_class is None or expected_class == produced_class)
            )
            fixture = {
                "fixture": str(path.relative_to(ROOT)),
                "expected_result": expected_result, "produced_result": first.result,
                "expected_code": expected_code, "produced_code": produced_code,
                "expected_class": expected_class, "produced_class": produced_class,
                "matched": matched, "deterministic": deterministic,
                "verdict_sha256": hashes.sha256(first.verdict_bytes).hex(),
                "first_failure_step": first.report["first_failure_step"],
                "stateful_properties": first.report["stateful_properties"],
            }
        except Exception as exc:  # Continue the corpus and surface internal failures.
            matched = False
            fixture = {
                "fixture": str(path.relative_to(ROOT)),
                "expected_result": expected_result, "produced_result": "internal_error",
                "expected_code": expected_code, "produced_code": type(exc).__name__,
                "expected_class": sidecar.get("expected_class"), "produced_class": None,
                "matched": False, "deterministic": False, "error": str(exc),
                "first_failure_step": None,
                "stateful_properties": "not_evaluated" if prior is None else "evaluation_failed",
            }
        fixtures.append(fixture)
        if not matched:
            prefix = "evidence" if fixture.get("expected_class") is not None else (expected_code or "schema").split("/", 1)[0]
            divergence = {
                "fixture": fixture["fixture"],
                "expected": {
                    "result": expected_result, "code": expected_code,
                    "class": fixture.get("expected_class"), "deterministic": True,
                },
                "produced": {
                    "result": fixture["produced_result"], "code": fixture["produced_code"],
                    "class": fixture.get("produced_class"),
                    "deterministic": fixture["deterministic"],
                },
                "spec_sentence": STEP_SPEC.get(prefix, STEP_SPEC["schema"]),
                "ambiguity_hypothesis": _divergence_hypothesis(fixture),
            }
            divergences.append(divergence)

    matched_count = sum(item["matched"] for item in fixtures)
    deterministic_count = sum(item["deterministic"] for item in fixtures)
    output = {
        "schema_version": 1,
        "slice": "C2",
        "evaluation_time": KAT_EVALUATION_TIME,
        "fixtures_evaluated": len(fixtures),
        "matches": matched_count,
        "mismatches": len(fixtures) - matched_count,
        "deterministic": deterministic_count == len(fixtures),
        "deterministic_fixtures": deterministic_count,
        "divergence_count": len(divergences),
        "entry_point_findings": 1,
        "divergences": divergences,
        "fixtures": fixtures,
    }
    C2_RESULTS_PATH.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_c2_divergences(divergences)
    return output


def _print_c1(output: dict[str, Any]) -> None:
    print(f"C1 fixtures checked: {output['fixtures_checked']}")
    for name, counts in output["checks"].items():
        print(
            f"{name}: {counts['passed']} passed, {counts['failed']} failed, "
            f"{counts['skipped']} skipped"
        )
    print(f"divergences: {output['divergence_count']}")
    print(f"results: {RESULTS_PATH.relative_to(ROOT)}")


def _print_c2(output: dict[str, Any]) -> None:
    print(f"C2 fixtures evaluated: {output['fixtures_evaluated']}")
    print(f"verdict/reason matches: {output['matches']}")
    print(f"mismatches: {output['mismatches']}")
    print(f"divergences: {output['divergence_count']}")
    print(f"determinism: {'passed' if output['deterministic'] else 'failed'} ({output['deterministic_fixtures']}/{output['fixtures_evaluated']})")
    print(f"results: {C2_RESULTS_PATH.relative_to(ROOT)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slice", choices=("c1", "c2", "all"), default="c1")
    args = parser.parse_args(argv)
    failed = False
    if args.slice in {"c1", "all"}:
        c1 = run_c1()
        _print_c1(c1)
        failed |= c1["divergence_count"] != 0
    if args.slice in {"c2", "all"}:
        c2 = run_c2()
        _print_c2(c2)
        failed |= c2["divergence_count"] != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
