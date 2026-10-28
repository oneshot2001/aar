// CONFORMANCE step 15, manifest index: the per-manifest checks in D-54 order, then
// D-87 rule 0 (in-bundle membership) last. Moved out of verifier.ts unchanged
// except for rule 0. pyref/manifest_index.py mirrors this module.
import { equalBytes, toHex } from "./cbor";
import { domainHash } from "./crypto";
import { promotedRoot } from "./merkle";
import { B1Failure, compareEncoded, failure, Obj, Parsed, ParsedEnvelope, receiptsById, same } from "./verifier";

function compareIndexEntries(left: Obj, right: Obj): number {
  const time = (left.committed_at as number) - (right.committed_at as number);
  const sequence = (left.epoch_seq as number) - (right.epoch_seq as number);
  return time || sequence || compareEncoded(left.receipt_id!, right.receipt_id!);
}

// The step-15 fields of an index entry against a carried receipt (D-87 also judges a retained entry by them).
export function entryMatches(entry: Obj, receipt: ParsedEnvelope): boolean {
  const binding = receipt.payload.binding as Obj; const emission = receipt.payload.emission as Obj;
  return entry.receipt_kind === receipt.payload.kind && same(entry.issuer_kid, receipt.kid) && entry.issuer_seq === emission.issuer_seq && entry.epoch_seq === binding.epoch_seq && entry.committed_at === emission.committed_at;
}

export const epochKey = (owner: Uint8Array, epochId: number): string => `${toHex(owner)}:${epochId}`;

export function validateManifestIndexes(parsed: Parsed): B1Failure | undefined {
  const receipts = receiptsById(parsed);
  for (const manifest of parsed.epoch_manifest) {
    const index = manifest.payload.receipt_index as Obj;
    const entries = index.entries as Obj[];
    for (let position = 1; position < entries.length; position += 1) if (compareIndexEntries(entries[position - 1]!, entries[position]!) >= 0) return failure(15, "manifest/index-order", "epoch_manifest.receipt_index.entries");
    for (let position = 0; position < entries.length; position += 1) if (entries[position]!.leaf_index !== position) return failure(15, "manifest/index-gap", "epoch_manifest.receipt_index.entries.leaf_index");
    const ids = new Set<string>(); const sequences = new Set<number>();
    for (const entry of entries) {
      const id = toHex(entry.receipt_id as Uint8Array); const sequence = entry.epoch_seq as number;
      if (ids.has(id) || sequences.has(sequence)) return failure(15, "manifest/index-duplicate", "epoch_manifest.receipt_index.entries");
      ids.add(id); sequences.add(sequence);
    }
    for (const entry of entries) {
      const receipt = receipts.get(toHex(entry.receipt_id as Uint8Array));
      if (receipt !== undefined && !entryMatches(entry, receipt)) return failure(15, "manifest/index-receipt-mismatch", "epoch_manifest.receipt_index.entries");
    }
    // Amendment (ad): the span is the minimum and maximum epoch_seq over the
    // entries; a nil span pairs only with an empty padding index (counts are step 14).
    const span = manifest.payload.sequence_span as Obj;
    const epochSequences = entries.map((entry) => entry.epoch_seq as number);
    if (entries.length > 0 ? (span.first !== Math.min(...epochSequences) || span.last !== Math.max(...epochSequences)) : (span.first !== null || span.last !== null || manifest.payload.close_reason !== "padding")) return failure(15, "epoch/span-count-mismatch", "epoch_manifest.receipt_index");
    if (entries.length > 0 && !equalBytes(index.root as Uint8Array, promotedRoot(entries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry)), "AAR-MANIFEST-INDEX-NODE-v1"))) return failure(15, "manifest/index-root-mismatch", "epoch_manifest.receipt_index.root");
  }
  // D-87 rule 0: a carried receipt whose binding names a carried manifest's owner and
  // epoch (one per key once step 14 passed) must be in that manifest's full index.
  const listed = new Map(parsed.epoch_manifest.map((manifest) => [epochKey(manifest.payload.epoch_owner_kid as Uint8Array, manifest.payload.epoch_id as number),
    new Set(((manifest.payload.receipt_index as Obj).entries as Obj[]).map((entry) => toHex(entry.receipt_id as Uint8Array)))]));
  for (const receipt of parsed.receipt) {
    const binding = receipt.payload.binding as Obj;
    const ids = listed.get(epochKey(binding.epoch_owner_kid as Uint8Array, binding.epoch_id as number));
    if (ids !== undefined && !ids.has(toHex(receipt.payload.receipt_id as Uint8Array))) return failure(15, "manifest/receipt-unindexed", "receipt.binding");
  }
  return undefined;
}
