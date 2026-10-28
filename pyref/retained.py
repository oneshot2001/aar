"""D-87 rule 3: relying-party-retained bundles (prior-state ``retained_epochs``).

Checked before evaluation begins in CONFORMANCE section 5 order; every
failure is a ``UsageError`` (no verdict). ``harness/retained.ts`` mirrors
this module.
"""

from __future__ import annotations

import re
from typing import Any

from . import emission_identity, hashes, relying_party, verifier
from .cbor import loads

RETAINED_BUNDLES = 16
RETAINED_BYTES = 16_777_216
RETAINED_RECEIPT_CONTRADICTION = (
    "prior-state.prior_emissions entry matches a retained receipt's receipt_id and envelope_digest but not its coordinates"
)
RETAINED_UNLISTED = "prior-state.prior_emissions entry names a retained epoch whose index does not list its receipt_id"
RETAINED_COORDINATES = "prior-state.prior_emissions entry names a retained epoch whose index lists it with other coordinates"
LABEL = "prior-state.retained_epochs"
HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")


def bundles(prior_state: dict[str, Any]) -> list[bytes]:
    """The JSON form: at most 16 hex strings totalling at most 16 MiB, both checked
    before any is decoded, then the strict SHA-256 order."""
    value = prior_state["retained_epochs"]
    if not isinstance(value, list):
        raise relying_party.UsageError(f"{LABEL} must be an array")
    if len(value) > RETAINED_BUNDLES:
        raise relying_party.UsageError(f"{LABEL} must hold at most {RETAINED_BUNDLES} bundles")
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise relying_party.UsageError(f"{LABEL}[{index}] must be a hex string")
        if not HEX.fullmatch(item):
            raise relying_party.UsageError(f"{LABEL}[{index}] is not valid hex")
    if sum(len(item) // 2 for item in value) > RETAINED_BYTES:
        raise relying_party.UsageError(f"{LABEL} must total at most {RETAINED_BYTES} bytes")
    decoded = [bytes.fromhex(item) for item in value]
    digests = [hashes.sha256(item) for item in decoded]
    if any(previous >= current for previous, current in zip(digests, digests[1:])):
        raise relying_party.UsageError(f"{LABEL} must be strictly sorted and unique by SHA-256")
    return decoded


def digest(prior_state: dict[str, Any] | None) -> bytes:
    """retained_epochs_digest: zero without prior state, the empty-list digest without retained_epochs."""
    if prior_state is None:
        return verifier.ZERO32
    supplied = bundles(prior_state) if "retained_epochs" in prior_state else []
    return hashes.domain_hash("AAR-VERDICT-RETAINED-v1", {"bundles": [hashes.sha256(item) for item in supplied]})


def _own_time(blob: bytes, fallback: int) -> int:
    """A bundle that cannot be read this far fails steps 1 to 3 at any time."""
    try:
        time = loads(blob, max_depth=verifier.LIMITS["cbor_container_nesting"])["trust_inputs"]["evaluation_time"]
    except Exception:
        return fallback
    return time if verifier._uint(time) else fallback


def load(raw: bytes, prior_state: dict[str, Any] | None, evaluated_at: int,
         configuration: relying_party.Configuration | None) -> dict[tuple[bytes, int], dict[str, Any]] | None:
    if prior_state is None or "retained_epochs" not in prior_state:
        return None
    supplied = bundles(prior_state)
    for index, blob in enumerate(supplied):
        if blob == raw:
            raise relying_party.UsageError(f"{LABEL}[{index}] is byte-identical to the bundle being evaluated")
    retained: dict[tuple[bytes, int], dict[str, Any]] = {}
    receipts: list[dict[str, Any]] = []
    for index, blob in enumerate(supplied):
        at = _own_time(blob, evaluated_at)
        state = verifier.State(raw=blob, evaluated_at=at, prior_state=None, replay_state=None,
                               configuration=configuration, verifier_use=False)
        try:
            verifier._steps(state)
        except verifier.ValidationError as exc:
            raise relying_party.UsageError(f"{LABEL}[{index}] fails step {exc.step} ({exc.code})") from exc
        if at > evaluated_at:
            raise relying_party.UsageError(f"{LABEL}[{index}] evaluation time is later than the current evaluation time")
        receipts.extend(emission_identity.emission_of(envelope) for envelope in state.envelopes["receipts"])
        # Step 14 passed: every carried manifest is a closed epoch, one per key, its events a chain from 0.
        for envelope in state.envelopes["epoch_manifests"]:
            manifest = envelope.payload
            key = manifest["epoch_owner_kid"], manifest["epoch_id"]
            events = [event.payload["event_id"] for event in sorted(
                (event for event in state.envelopes["epoch_events"]
                 if (event.payload["epoch_owner_kid"], event.payload["epoch_id"]) == key),
                key=lambda event: event.payload["event_seq"])]
            epoch = {"manifest_id": manifest["manifest_id"], "events": events,
                     "index": {entry["receipt_id"]: entry for entry in manifest["receipt_index"]["entries"]}}
            known = retained.get(key)
            if known is not None and known["manifest_id"] != epoch["manifest_id"]:
                raise relying_party.UsageError(f"{LABEL}[{index}] carries a manifest that conflicts with a retained manifest for the same owner and epoch")
            if known is not None and any(position < len(events) and events[position] != event_id
                                         for position, event_id in enumerate(known["events"])):
                raise relying_party.UsageError(f"{LABEL}[{index}] carries an epoch event chain that conflicts with a retained chain")
            if known is None or len(events) > len(known["events"]):
                retained[key] = epoch
    entries = verifier._prior_emissions_map(prior_state)["entries"]
    if any(item["receipt_id"] == entry["receipt_id"] and item["envelope_digest"] == entry["envelope_digest"]
           and emission_identity.coordinates(item) != emission_identity.coordinates(entry)
           for entry in entries for item in receipts):
        raise relying_party.UsageError(RETAINED_RECEIPT_CONTRADICTION)
    for entry in entries:
        epoch = retained.get((entry["epoch_owner_kid"], entry["epoch_id"]))
        if epoch is None:
            continue
        indexed = epoch["index"].get(entry["receipt_id"])
        if indexed is None:
            raise relying_party.UsageError(RETAINED_UNLISTED)
        if (indexed["issuer_kid"], indexed["issuer_seq"], indexed["epoch_seq"]) != (entry["issuer_kid"], entry["issuer_seq"], entry["epoch_seq"]):
            raise relying_party.UsageError(RETAINED_COORDINATES)
    return retained
