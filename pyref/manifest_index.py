"""CONFORMANCE step 15, manifest index (D-54 order), then D-87 rule 0.

The per-manifest checks moved out of ``verifier`` unchanged; in-bundle
membership (rule 0) is the last rule of the step. ``harness/manifest-index.ts``
mirrors this module. Rejections go through ``verifier._fail`` by attribute so
the premise recorder sees them.
"""

from __future__ import annotations

from typing import Any

from . import hashes, verifier


def entry_matches(entry: dict[str, Any], envelope: verifier.Envelope) -> bool:
    """The step-15 fields of an index entry against a carried receipt (D-87 also judges a retained entry by them)."""
    payload = envelope.payload
    return entry["receipt_kind"] == payload["kind"] \
        and entry["issuer_kid"] == envelope.protected[4] \
        and entry["issuer_seq"] == payload["emission"]["issuer_seq"] \
        and entry["epoch_seq"] == payload["binding"]["epoch_seq"] \
        and entry["committed_at"] == payload["emission"]["committed_at"]


def manifest_index(state: verifier.State) -> None:
    for envelope in state.envelopes["epoch_manifests"]:
        manifest = envelope.payload
        index = manifest["receipt_index"]
        entries = index["entries"]
        ordering = [(item["committed_at"], item["epoch_seq"], item["receipt_id"]) for item in entries]
        if ordering != sorted(ordering) or len(set(ordering)) != len(ordering):
            verifier._fail("manifest/index-order", 15)
        leaf_indices = [item["leaf_index"] for item in entries]
        if leaf_indices != list(range(len(entries))):
            verifier._fail("manifest/index-gap", 15)
        receipt_ids = [item["receipt_id"] for item in entries]
        epoch_sequences = [item["epoch_seq"] for item in entries]
        if len(set(receipt_ids)) != len(receipt_ids) or len(set(epoch_sequences)) != len(epoch_sequences):
            verifier._fail("manifest/index-duplicate", 15)
        for entry in entries:
            receipt = state.receipts_by_id.get(entry["receipt_id"])
            if receipt is not None and not entry_matches(entry, receipt):
                verifier._fail("manifest/index-receipt-mismatch", 15)
        span = manifest["sequence_span"]
        if entries:
            if span != {"first": min(epoch_sequences), "last": max(epoch_sequences)}:
                verifier._fail("epoch/span-count-mismatch", 15)
        elif span != {"first": None, "last": None} or manifest["close_reason"] != "padding":
            verifier._fail("epoch/span-count-mismatch", 15)
        if entries:
            computed = hashes.promoted_root(
                (hashes.manifest_index_leaf(entry) for entry in entries), hashes.manifest_index_node
            )
            if computed != index["root"]:
                verifier._fail("manifest/index-root-mismatch", 15)
    # D-87 rule 0: a carried receipt whose binding names a carried manifest's owner and
    # epoch (one per key once step 14 passed) must be in that manifest's full index.
    listed = {
        (envelope.payload["epoch_owner_kid"], envelope.payload["epoch_id"]):
            {entry["receipt_id"] for entry in envelope.payload["receipt_index"]["entries"]}
        for envelope in state.envelopes["epoch_manifests"]
    }
    for envelope in state.envelopes["receipts"]:
        binding = envelope.payload["binding"]
        ids = listed.get((binding["epoch_owner_kid"], binding["epoch_id"]))
        if ids is not None and envelope.payload["receipt_id"] not in ids:
            verifier._fail("manifest/receipt-unindexed", 15)
