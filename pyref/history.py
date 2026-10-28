"""CONFORMANCE step 20 history phase (D-87).

Every comparison against relying-party-supplied state, after every intrinsic
check, one class per full pass with D-86's witness order (carried artifact
order, then supplied order): (a) reuse and (b) equivocation against
prior_emissions, (c) the supplied replay state, (d) retained-epoch fork,
(e) retained-epoch membership; then the duplicate_exact and
sequence_below_observed_history observations. ``harness/history.ts`` mirrors
this module. Rejections go through ``verifier._fail`` by attribute so the
premise recorder sees them.
"""

from __future__ import annotations

from typing import Any

from . import emission_identity, hashes, manifest_index, verifier


def _key(value: dict[str, Any]) -> tuple[bytes, int]:
    return value["epoch_owner_kid"], value["epoch_id"]


def history(state: verifier.State) -> None:
    state.history_phase = True
    if state.prior_state is not None:
        state.stateful_checks = "evaluated"
    carried = [emission_identity.emission_of(envelope) for envelope in state.envelopes["receipts"]]
    entries = [] if state.prior_state is None else verifier._prior_emissions_map(state.prior_state)["entries"]
    # (a), (b): after (a) and step 9 rule 0(b), an equal receipt_id is an exact duplicate.
    if any(item["receipt_id"] == entry["receipt_id"] and item["envelope_digest"] != entry["envelope_digest"]
           for item in carried for entry in entries):
        verifier._fail("identity/reuse", 20)
    if any(item["receipt_id"] != entry["receipt_id"]
           and (emission_identity._issuer(item) == emission_identity._issuer(entry)
                or emission_identity._epoch(item) == emission_identity._epoch(entry))
           for item in carried for entry in entries):
        verifier._fail("identity/coordinate-equivocation", 20)
    # (c): a carried one-time receipt against the supplied replay state; an equal digest is a duplicate.
    replay = [] if state.replay_state is None else state.replay_state.get("entries", [])
    for envelope in state.envelopes["receipts"]:
        freshness = envelope.payload["freshness"]
        if freshness.get("use") != "one_time":
            continue
        content = hashes.sha256(envelope.envelope_bytes)
        if any((entry["replay_domain"], entry["invocation_id"]) == (freshness["replay_domain"], freshness["invocation_id"])
               and entry["content_digest"] != content for entry in replay):
            verifier._fail("replay/one-time-reused", 20)
    retained = state.retained or {}
    # (d): carried manifests, then carried events; positions the retained chain lacks extend it.
    for envelope in state.envelopes["epoch_manifests"]:
        epoch = retained.get(_key(envelope.payload))
        if epoch is not None and epoch["manifest_id"] != envelope.payload["manifest_id"]:
            verifier._fail("epoch/fork", 20)
    for envelope in state.envelopes["epoch_events"]:
        events = retained.get(_key(envelope.payload), {"events": []})["events"]
        if envelope.payload["event_seq"] < len(events) and events[envelope.payload["event_seq"]] != envelope.payload["event_id"]:
            verifier._fail("epoch/fork", 20)
    # (e): membership, then the step-15 fields; a retained index decides membership in its own epoch only.
    for envelope in state.envelopes["receipts"]:
        epoch = retained.get(_key(envelope.payload["binding"]))
        if epoch is not None and envelope.payload["receipt_id"] not in epoch["index"]:
            verifier._fail("manifest/receipt-unindexed", 20)
    for envelope in state.envelopes["receipts"]:
        entry = retained.get(_key(envelope.payload["binding"]), {"index": {}})["index"].get(envelope.payload["receipt_id"])
        if entry is not None and not manifest_index.entry_matches(entry, envelope):
            verifier._fail("manifest/index-receipt-mismatch", 20)
    # D-87 rule 2: supplied history is what the relying party observed; a lower sequence is relayed, never a rollback.
    known = {entry["receipt_id"] for entry in entries}
    if any(item["receipt_id"] in known for item in carried):
        state.observations.append("duplicate_exact")
    if any(item["receipt_id"] not in known
           and ((item["issuer_kid"] == entry["issuer_kid"] and item["issuer_seq"] < entry["issuer_seq"])
                or (_key(item) == _key(entry) and item["epoch_seq"] < entry["epoch_seq"]))
           for item in carried for entry in entries):
        state.observations.append("sequence_below_observed_history")


def membership(state: verifier.State) -> str:
    """D-87 rule 5, on a conformant verdict only: every carried receipt (at least one) listed by a retained epoch."""
    receipts = state.envelopes["receipts"]
    retained = state.retained
    return "all_receipts_listed" if retained is not None and receipts and all(
        envelope.payload["receipt_id"] in retained.get(_key(envelope.payload["binding"]), {"index": {}})["index"]
        for envelope in receipts) else "not_established"
