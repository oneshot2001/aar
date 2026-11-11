"""CONFORMANCE step 13, authorization dominance.

Per dispatch: the single attempt and its permitting authorization (D-90),
the embedded delegation (D-53, D-79, the D-82 part 9 chain), one-time
consumption (D-90), then D-66; then every undispatched eligible attempt
(D-90). Moved out of ``verifier``. ``harness/dominance.ts`` mirrors this module.
Rejections go through ``verifier._fail`` by attribute so the premise
recorder sees them.
"""

from __future__ import annotations

from typing import Any

from . import hashes, verifier
from .cbor import dumps


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
    if not verifier._type_ok(parent_scope, "map") or not verifier._type_ok(child_scope, "map"):
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


def _permitting_authorization(state: verifier.State, attempt: verifier.Envelope) -> verifier.Envelope:
    """D-90: the attempt's single authorization, bound by id and by the recomputed
    decision commitment (a 32-byte digest on both sides); the attempt is eligible
    and the decision permits. Every failure but ambiguity is graph/dominator-missing."""
    authorizations = [parent for parent in attempt.payload["parents"] if parent["edge_type"] == "authorized_by"]
    if not authorizations:
        verifier._fail("graph/dominator-missing", 13)
    if len(authorizations) > 1:
        verifier._fail("graph/dominator-ambiguous", 13)
    authorization = state.receipts_by_id.get(authorizations[0]["parent_id"])
    body = attempt.payload["body"]
    # A missing authorization_id is disagreement (harness same() parity),
    # never a KeyError.
    if authorization is None or authorization.payload["kind"] != "authorization" \
            or body.get("authorization_id") != authorization.payload["receipt_id"]:
        verifier._fail("graph/dominator-missing", 13)
    decision = authorization.payload["body"]["decision"]
    commitment = body.get("decision_commitment")
    if not isinstance(commitment, bytes) or len(commitment) != 32 \
            or commitment != decision.get("decision_commitment") \
            or commitment != hashes.decision_commitment(decision) \
            or body.get("disposition") != "eligible_for_dispatch" \
            or decision.get("decision") not in ("permit", "permit_with_approval"):
        verifier._fail("graph/dominator-missing", 13)
    return authorization


def _chain_of(known: dict[bytes, dict[str, Any]], leaf: dict[str, Any]) -> list[dict[str, Any]]:
    """D-90: the embedded delegation and every carried delegation on its validated chain, once each."""
    seen: dict[bytes, dict[str, Any]] = {}
    stack = [leaf]
    while stack:
        node = stack.pop()
        if node["delegation_id"] in seen:
            continue
        seen[node["delegation_id"]] = node
        stack.extend(known[parent] for parent in node["parent_delegations"])
    return list(seen.values())


def authorization_dominance(state: verifier.State, graph: dict[bytes, list[bytes]]) -> None:
    dispatched_attempt_ids: set[bytes] = set()
    one_time_uses: set[bytes] = set()
    known_delegations: dict[bytes, dict[str, Any]] = {}
    chain_memo: dict[bytes, bool | None] = {}
    for env in state.envelopes["delegations"]:
        known_delegations.setdefault(env.payload["delegation_id"], env.payload)
    for dispatch in (env for env in state.envelopes["receipts"] if env.payload["kind"] == "dispatch"):
        dispatch_receipt = dispatch.payload
        attempted = [parent for parent in dispatch_receipt["parents"] if parent["edge_type"] == "attempted_as"]
        if len(attempted) != 1:
            verifier._fail("graph/dominator-missing", 13)
        attempt = state.receipts_by_id.get(attempted[0]["parent_id"])
        if attempt is None:
            verifier._fail("graph/dominator-missing", 13)
        dispatched_attempt_ids.add(attempt.payload["receipt_id"])
        authorization = _permitting_authorization(state, attempt)
        auth_body = authorization.payload["body"]
        delegation = state.embedded_delegations.get(authorization.payload["receipt_id"])
        if delegation is None:
            verifier._fail("graph/dominator-missing", 13)
        delegation_payload = delegation.payload
        if auth_body["decision"].get("delegation_id") != delegation_payload["delegation_id"]:
            verifier._fail("graph/dominator-missing", 13)
        # D-79: the delegation names the enforcement point that signed the attempt.
        subject_id = delegation_payload["subject_credential_id"]
        subject = state.credentials_by_id.get(subject_id) if isinstance(subject_id, bytes) else None
        if subject is None or subject.payload["subject_kid"] != attempt.protected[4]:
            verifier._fail("delegation/scope", 13)
        attempt_body = attempt.payload["body"]
        action = attempt_body["action"]
        scope = delegation_payload["scope"]
        # Amendment (l): a used delegation whose scope is not a map, or whose
        # lists are not arrays, is delegation/scope (harness parity).
        if not verifier._type_ok(scope, "map") or any(not isinstance(scope.get(name), list)
                                              for name in ("actions", "targets", "purpose_ids", "allowed_profiles")):
            verifier._fail("delegation/scope", 13)
        # Amendment (o): an absent or wrongly typed value is simply not contained.
        legal = attempt.payload["legal"]
        purpose = legal.get("purpose_id") if verifier._type_ok(legal, "map") else None
        decision_profile = auth_body["decision"].get("profile")
        # Amendment (ag): both MUST be text and contained; a non-text value is never contained.
        if not isinstance(purpose, str) or not isinstance(decision_profile, str):
            verifier._fail("delegation/scope", 13)
        invocation = attempt.payload["freshness"]["invocation_id"]
        if action["action_name"] not in scope["actions"] \
                or action["target_id"] not in scope["targets"] \
                or purpose not in scope["purpose_ids"] \
                or decision_profile not in scope["allowed_profiles"] \
                or delegation_payload["tenant_id"] != attempt.payload["binding"]["tenant_id"] \
                or delegation_payload["site_id"] != attempt.payload["binding"]["site_id"] \
                or ("invocation_id" in delegation_payload and delegation_payload["invocation_id"] != invocation) \
                or (delegation_payload["use"] == "one_time" and "invocation_id" not in delegation_payload):
            verifier._fail("delegation/scope", 13)
        committed = attempt.payload["emission"]["committed_at"]
        if committed < delegation_payload["not_before"]:
            verifier._fail("delegation/not-yet-valid", 13)
        if committed >= delegation_payload["not_after"]:
            verifier._fail("delegation/expired", 13)
        if not _chain_valid(known_delegations, delegation_payload, chain_memo):
            verifier._fail("delegation/chain-invalid", 13)
        # D-90: a dispatch consumes every one_time delegation on its chain; a second dispatch may not.
        one_time = [link["delegation_id"] for link in _chain_of(known_delegations, delegation_payload) if link["use"] == "one_time"]
        if any(key in one_time_uses for key in one_time):
            verifier._fail("delegation/scope", 13)
        one_time_uses.update(one_time)

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
                and verifier._type_ok(degraded, "map")
                and degraded.get("reason") == "journal/unavailable"
            )
            if not committed_before_dispatch and not life_safety_exception:
                verifier._fail("journal/uncommitted-dispatch", 13)
            if not committed_before_dispatch and "degraded_dispatch" not in state.observations:
                state.observations.append("degraded_dispatch")

    # D-90: an eligible attempt no dispatch names still needs its permitting authorization.
    for attempt in state.envelopes["receipts"]:
        if attempt.payload["kind"] == "action_attempt" \
                and attempt.payload["body"].get("disposition") == "eligible_for_dispatch" \
                and attempt.payload["receipt_id"] not in dispatched_attempt_ids:
            _permitting_authorization(state, attempt)

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
