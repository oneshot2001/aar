"""CONFORMANCE step 9, emission identity (D-86).

History consistency, then phase A over the carried receipts alone, then phase
B against supplied prior state, one reason class per full pass.
``harness/emission-identity.ts`` mirrors this module. Rejections go through
``verifier._fail`` by attribute so the premise recorder sees them; history that
contradicts itself or a carried receipt is a usage error (no verdict), like
the D-76 duplicate/unsorted rule.
"""

from __future__ import annotations

from typing import Any

from . import hashes, relying_party, verifier

HISTORY_CONTRADICTS_ITSELF = (
    "prior-state.prior_emissions entries with one receipt_id and envelope_digest must have the same coordinates"
)
HISTORY_CONTRADICTS_RECEIPT = (
    "prior-state.prior_emissions entry matches a carried receipt's receipt_id and envelope_digest but not its coordinates"
)


def _issuer(item: dict[str, Any]) -> tuple[bytes, int]:
    return item["issuer_kid"], item["issuer_seq"]


def _epoch(item: dict[str, Any]) -> tuple[bytes, int, int]:
    return item["epoch_owner_kid"], item["epoch_id"], item["epoch_seq"]


def check_history(entries: list[dict[str, Any]]) -> None:
    """D-86 rule 0(a): checked with the duplicate/unsorted rule, before any bundle byte is read."""
    seen: dict[tuple[bytes, bytes], tuple[Any, ...]] = {}
    for entry in entries:
        coordinates = _issuer(entry) + _epoch(entry)
        if seen.setdefault((entry["receipt_id"], entry["envelope_digest"]), coordinates) != coordinates:
            raise ValueError(HISTORY_CONTRADICTS_ITSELF)


def emission_identity(state: verifier.State) -> None:
    carried: list[dict[str, Any]] = []
    for envelope in state.envelopes["receipts"]:
        receipt = envelope.payload
        # Identity coordinates are indexed as map keys below; pin their types
        # first so malformed input yields a signed verdict, never an unhashable
        # TypeError (harness emission-identity parity).
        if not verifier._uint(receipt["emission"].get("issuer_seq")):
            verifier._fail("schema/bad-type", 9)
        if not (verifier._bstr(receipt["binding"].get("epoch_owner_kid"), 32)
                and verifier._uint(receipt["binding"].get("epoch_id"))
                and verifier._uint(receipt["binding"].get("epoch_seq"))):
            verifier._fail("schema/bad-type", 9)
        carried.append({
            "issuer_kid": envelope.protected[4],
            "issuer_seq": receipt["emission"]["issuer_seq"],
            "epoch_owner_kid": receipt["binding"]["epoch_owner_kid"],
            "epoch_id": receipt["binding"]["epoch_id"],
            "epoch_seq": receipt["binding"]["epoch_seq"],
            "receipt_id": receipt["receipt_id"],
            "envelope_digest": hashes.sha256(envelope.envelope_bytes),
        })
    history = [] if state.prior_state is None else verifier._prior_emissions_map(state.prior_state)["entries"]
    # Rule 0(b), before phase A: history that contradicts a carried receipt is a usage error.
    if any(entry["receipt_id"] == item["receipt_id"] and entry["envelope_digest"] == item["envelope_digest"]
           and _issuer(entry) + _epoch(entry) != _issuer(item) + _epoch(item)
           for item in carried for entry in history):
        raise relying_party.UsageError(HISTORY_CONTRADICTS_RECEIPT)

    # Phase A: reuse over the whole bundle, then equivocation (issuer before epoch per receipt).
    by_receipt: dict[bytes, bytes] = {}
    for item in carried:
        if item["receipt_id"] in by_receipt:
            if by_receipt[item["receipt_id"]] != item["envelope_digest"]:
                verifier._fail("identity/reuse", 9)
            state.observations.append("duplicate_exact")
        by_receipt[item["receipt_id"]] = item["envelope_digest"]
    by_issuer_coordinate: dict[tuple[bytes, int], bytes] = {}
    by_epoch_coordinate: dict[tuple[bytes, int, int], bytes] = {}
    for item in carried:
        if by_issuer_coordinate.setdefault(_issuer(item), item["receipt_id"]) != item["receipt_id"]:
            verifier._fail("identity/coordinate-equivocation", 9)
        if by_epoch_coordinate.setdefault(_epoch(item), item["receipt_id"]) != item["receipt_id"]:
            verifier._fail("identity/coordinate-equivocation", 9)  # amendment (ah)

    if state.prior_state is None:
        state.stateful_checks = "not_evaluated"
        return
    state.stateful_checks = "evaluated"
    # Phase B: every carried receipt against every entry, one class per pass. After
    # (i) and rule 0(b), an equal ID is an exact duplicate: exempt from rollback only.
    if any(item["receipt_id"] == entry["receipt_id"] and item["envelope_digest"] != entry["envelope_digest"]
           for item in carried for entry in history):
        verifier._fail("identity/reuse", 9)
    for item in carried:
        for entry in history:
            if item["receipt_id"] == entry["receipt_id"]:
                state.observations.append("duplicate_exact")
            elif _issuer(item) == _issuer(entry) or _epoch(item) == _epoch(entry):
                verifier._fail("identity/coordinate-equivocation", 9)
    known = {entry["receipt_id"] for entry in history}
    remaining = [item for item in carried if item["receipt_id"] not in known]
    if any(item["issuer_kid"] == entry["issuer_kid"] and item["issuer_seq"] < entry["issuer_seq"]
           for item in remaining for entry in history):
        verifier._fail("identity/issuer-sequence-rollback", 9)
    if any(item["epoch_owner_kid"] == entry["epoch_owner_kid"] and item["epoch_id"] == entry["epoch_id"]
           and item["epoch_seq"] < entry["epoch_seq"] for item in remaining for entry in history):
        verifier._fail("identity/epoch-sequence-rollback", 9)
