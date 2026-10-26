"""CONFORMANCE step 9, emission identity (D-86).

Supplied prior state is checked first (entry shape, D-76 order, rule 0(a)),
then phase A over the carried receipts alone, then phase B against the prior
state, one reason class per full pass. ``harness/emission-identity.ts``
mirrors this module. Rejections go through ``verifier._fail`` by attribute so
the premise recorder sees them; malformed or contradictory history is a usage
error (no verdict), like the D-76 duplicate/unsorted rule.
"""

from __future__ import annotations

import re
from typing import Any

from . import hashes, relying_party, verifier
from .cbor import dumps

HISTORY_CONTRADICTS_ITSELF = (
    "prior-state.prior_emissions entries with one receipt_id and envelope_digest must have the same coordinates"
)
HISTORY_CONTRADICTS_RECEIPT = (
    "prior-state.prior_emissions entry matches a carried receipt's receipt_id and envelope_digest but not its coordinates"
)
ENTRY_KEYS = ("issuer_kid", "issuer_seq", "epoch_owner_kid", "epoch_id", "epoch_seq", "receipt_id", "envelope_digest")
UINT_KEYS = ("issuer_seq", "epoch_id", "epoch_seq")
HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")


def _issuer(item: dict[str, Any]) -> tuple[bytes, int]:
    return item["issuer_kid"], item["issuer_seq"]


def _epoch(item: dict[str, Any]) -> tuple[bytes, int, int]:
    return item["epoch_owner_kid"], item["epoch_id"], item["epoch_seq"]


def _field(value: Any, key: str, label: str) -> Any:
    if key in UINT_KEYS:
        # Compared by numeric value, as JSON.parse in the harness compares it: an
        # integral float in range (JSON 1.0, 1e0, -0.0) is that integer (E-11).
        if isinstance(value, float) and value.is_integer() and 0 <= value <= verifier.MAX_U53:
            value = int(value)
        if not verifier._uint(value):
            raise ValueError(f"{label} must be an unsigned integer <= 9007199254740991")
        return value
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a 32-byte lowercase or uppercase hex string")
    if not HEX.fullmatch(value):
        raise ValueError(f"{label} is not valid hex")
    if len(value) != 64:
        raise ValueError(f"{label} must decode to exactly 32 bytes")
    return bytes.fromhex(value)


def prior_entries(value: dict[str, Any]) -> list[dict[str, Any]]:
    """Supplied prior state, for evaluate() and the CLI alike: each entry is the
    closed seven-key map (uints, 32-byte hex), then the D-76 strict order, then
    D-86 rule 0(a). Any failure raises ValueError before evaluation begins."""
    if not isinstance(value, dict):
        raise ValueError("prior-state must be a JSON object")
    unknown_keys = sorted(set(value) - {"prior_emissions", "entries"})
    if unknown_keys:
        raise ValueError(f"prior-state: unknown {', '.join(unknown_keys)}")
    source = value.get("prior_emissions", [])
    if not isinstance(source, list):
        raise ValueError("prior-state.prior_emissions must be an array")
    entries = []
    for index, item in enumerate(source):
        label = f"prior-state.prior_emissions[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be a JSON object")
        missing, unknown = sorted(set(ENTRY_KEYS) - set(item)), sorted(set(item) - set(ENTRY_KEYS))
        if missing or unknown:
            details = ([f"missing {', '.join(missing)}"] if missing else []) + ([f"unknown {', '.join(unknown)}"] if unknown else [])
            raise ValueError(f"{label}: {'; '.join(details)}")
        entries.append({key: _field(item[key], key, f"{label}.{key}") for key in ENTRY_KEYS})
    order = [dumps([entry[key] for key in ENTRY_KEYS]) for entry in entries]
    if any(previous >= current for previous, current in zip(order, order[1:])):
        raise ValueError("prior-state.prior_emissions must be strictly sorted and unique")
    seen: dict[tuple[bytes, bytes], tuple[Any, ...]] = {}
    for entry in entries:
        coordinates = _issuer(entry) + _epoch(entry)
        if seen.setdefault((entry["receipt_id"], entry["envelope_digest"]), coordinates) != coordinates:
            raise ValueError(HISTORY_CONTRADICTS_ITSELF)
    return entries


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

    # Phase A: one equivocation pass, issuer before epoch per receipt. Step 3 already
    # rejects a repeated receipt_id in artifacts.receipts, so there is no in-bundle reuse.
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
