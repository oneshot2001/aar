"""Verdict construction and signing for the clean-room AAR verifier.

``_verdict_fields`` populates the W-12 verdict from evaluation state (the
section 5 table on failure); ``_sign_verdict`` binds it under the verifier
signing key. Preimages are unchanged from their former home in ``verifier``.
"""

from __future__ import annotations

from typing import Any

from . import hashes, relying_party, verifier
from .cbor import dumps
from .crypto import sign_es256


def _limits_digest() -> bytes:
    return hashes.domain_hash("AAR-VERDICT-LIMITS-v1", verifier.LIMITS)


BUILD_DIGEST = hashes.sha256(b"pyref-aar-v0.3.1-d86-emission-identity-build-v1")
CONFIG_DIGEST = hashes.sha256(b"pyref-aar-v0.2-gate4-c2-fixed-conformance-config-v1")


def _normal_replay_state(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    entries = value.get("entries", [])
    normalized = []
    for entry in entries:
        normalized.append({
            "replay_domain": entry["replay_domain"],
            "invocation_id": entry["invocation_id"],
            "content_digest": entry["content_digest"],
        })
    normalized.sort(key=lambda item: dumps([item["replay_domain"], item["invocation_id"], item["content_digest"]]))
    return {"entries": normalized}


def _prior_emissions_digest(value: dict[str, Any] | None) -> bytes:
    return verifier.ZERO32 if value is None else hashes.domain_hash(
        "AAR-VERDICT-PRIOR-v1", verifier._prior_emissions_map(value)
    )


def _verdict_fields(state: verifier.State, result: str, reason: str | None, step: int) -> dict[str, Any]:
    # D-82 part 1: a failure verdict is populated by the section 5 table and
    # nothing else. state.bundle is set only once step 3 succeeded as a whole;
    # the four trust values are validated once step 5 has.
    bundle = state.bundle
    conformant = result == "conformant"
    trust_valid = bundle is not None and (conformant or step > 5)
    if bundle is not None:
        selector = bundle["selector"]
        scope = {
            "tenant_id": selector["tenant_id"], "site_id": selector["site_id"],
            "committed_from": selector["committed_from"], "committed_until": selector["committed_until"],
            "receipt_kinds": selector["receipt_kinds"], "coverage": bundle["coverage"],
            "ingress_completeness": "not_established",
        }
        selector_commitment = bundle["selector_commitment"]
        requested_profile = bundle["claimed_profile"]
    else:
        scope = {
            "tenant_id": verifier.ZERO16, "site_id": verifier.ZERO16, "committed_from": 0,
            "committed_until": 0, "receipt_kinds": ["observation"],
            "coverage": "valid_subset", "ingress_completeness": "not_established",
        }
        selector_commitment = verifier.ZERO32
        requested_profile = "AAR-1"
    # An explicitly configured trust value replaces only its sentinel.
    trust = bundle["trust_inputs"] if trust_valid else state.configured_trust_policy
    replay = _normal_replay_state(state.replay_state)
    trust_policy = {
        "trust_store_snapshot_id": trust["trust_store"]["snapshot_id"] if trust else verifier.ZERO32,
        "trust_store_digest": trust["trust_store"]["digest"] if trust else verifier.ZERO32,
        "verifier_policy_digest": trust["verifier_policy_digest"] if trust else verifier.ZERO32,
        "evaluation_time": state.evaluated_at,
        "anchor_heads_digest": hashes.domain_hash("AAR-VERDICT-HEADS-v1", trust["expected_anchor_heads"]) if trust else verifier.ZERO32,
        "replay_state_digest": verifier.ZERO32 if replay is None else hashes.domain_hash("AAR-VERDICT-REPLAY-v1", replay),
        "prior_emissions_digest": _prior_emissions_digest(state.prior_state),
        # D-83 part 7: the policy digest at every step, zero only without a policy.
        "relying_party_policy_digest": verifier.ZERO32 if state.configuration is None else state.configuration.policy_digest,
    }

    if conformant:
        # GATE3 F1: success never carries an early-failure sentinel.
        if bundle is None or scope["tenant_id"] == verifier.ZERO16 or trust_policy["trust_store_snapshot_id"] == verifier.ZERO32:
            raise RuntimeError("conformant verdict would carry an early-failure sentinel")
    limits = {
        "requested_profile": requested_profile,
        "evaluated_profile": requested_profile if conformant else "below_AAR-1",
        "maximum_time_class": state.classes["time"] if conformant else "not_evaluated",
        "maximum_provenance_class": state.classes["provenance"] if conformant else "not_evaluated",
        "maximum_outcome_level": state.classes["outcome"] if conformant else "not_evaluated",
        "technical_integrity": "satisfied" if conformant else ("not_evaluated" if step <= 5 else "not_satisfied"),
        "source_authenticity": "not_established",
        "custody_continuity": "not_established",
        "discovery_completeness": "producer_declared_only" if conformant and bundle["coverage"] == "complete" else "not_established",
        "legal_admissibility": "not_established",
        "input_origin_ancestry": state.input_origin_ancestry if conformant else "not_evaluated",
        "control_path_completeness": "not_established",  # D-84: on every result
    }
    fields: dict[str, Any] = {
        "v": 5,
        "evaluated_at": state.evaluated_at,
        "result": result,
        "bundle_digest": hashes.sha256(state.raw),
        "selector_commitment": selector_commitment,
        "verifier": {
            "product": "pyref", "version": "v0.3.1",
            "build_digest": BUILD_DIGEST, "config_digest": CONFIG_DIGEST,
            "limits_digest": _limits_digest(),
        },
        "trust_policy": trust_policy,
        "scope": scope,
        "limits": limits,
        # Failure verdicts carry no observations (harness parity, D-72).
        "observations": [] if reason is not None else list(dict.fromkeys(state.observations)),
    }
    if reason is not None:
        fields["reason"] = reason
    return fields


def _sign_verdict(fields: dict[str, Any], configuration: relying_party.Configuration | None) -> tuple[dict[str, Any], bytes]:
    scalar, verifier_kid = relying_party.signer(configuration)
    protected_bytes = dumps({1: -7, 3: "application/aar-verdict+cbor;v=0.3", 4: verifier_kid})
    verdict_id = hashes.domain_hash("AAR-VERDICT-ID-v1", protected_bytes, fields)
    verdict = {"verdict_id": verdict_id, **fields}
    payload_bytes = dumps(verdict)
    sig_structure = dumps(["Signature1", protected_bytes, b"", payload_bytes])
    signature = sign_es256(scalar, sig_structure)
    cose_bytes = dumps([protected_bytes, {}, None, signature])
    return verdict, dumps([payload_bytes, cose_bytes])
