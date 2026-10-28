// CONFORMANCE step 20 history phase (D-87): every comparison against
// relying-party-supplied state, after every intrinsic check, one class per full
// pass with D-86's witness order (carried artifact order, then supplied order):
// (a) reuse and (b) equivocation against prior_emissions, (c) the supplied replay
// state, (d) retained-epoch fork, (e) retained-epoch membership; then the
// duplicate_exact and sequence_below_observed_history observations.
// pyref/history.py mirrors this module.
import { equalBytes, toHex } from "./cbor";
import { hash } from "./crypto";
import { emissionOf, fromPrior } from "./emission-identity";
import { entryMatches, epochKey } from "./manifest-index";
import { Retained } from "./retained";
import { B1Failure, failure, observe, Obj, Parsed, ParsedEnvelope, VerifyB1Options } from "./verifier";

const keyOf = (entry: ParsedEnvelope, field = "binding"): string => {
  const holder = (field === "binding" ? entry.payload.binding : entry.payload) as Obj;
  return epochKey(holder.epoch_owner_kid as Uint8Array, holder.epoch_id as number);
};

export function validateHistory(parsed: Parsed, options: VerifyB1Options, retained: Retained | undefined, observations: string[]): B1Failure | undefined {
  const carried = parsed.receipt.map(emissionOf);
  const history = (options.priorEmissions ?? []).map(fromPrior);
  // (a), (b): after (a) and step 9 rule 0(b), an equal receipt_id is an exact duplicate.
  for (const receipt of carried) for (const entry of history) if (entry.id === receipt.id && entry.digest !== receipt.digest) return failure(20, "identity/reuse", "receipts");
  for (const receipt of carried) {
    for (const entry of history) {
      if (entry.id === receipt.id) continue;
      if (entry.issuer === receipt.issuer) return failure(20, "identity/coordinate-equivocation", "receipt.emission.issuer_seq");
      if (entry.epoch === receipt.epoch) return failure(20, "identity/coordinate-equivocation", "receipt.binding.epoch_seq");
    }
  }
  // (c): a carried one-time receipt against the supplied replay state; an equal digest is a duplicate.
  for (const receipt of parsed.receipt) {
    const freshness = receipt.payload.freshness as Obj;
    if (freshness.use !== "one_time") continue;
    const digest = hash(receipt.envelopeBytes);
    for (const use of options.replayState ?? []) {
      if (equalBytes(use.replayDomain, freshness.replay_domain as Uint8Array) && equalBytes(use.invocationId, freshness.invocation_id as Uint8Array) && !equalBytes(use.contentDigest, digest)) return failure(20, "replay/one-time-reused", "receipt.freshness");
    }
  }
  const epochs = retained ?? new Map();
  // (d): carried manifests, then carried events; positions the retained chain lacks extend it.
  for (const manifest of parsed.epoch_manifest) {
    const epoch = epochs.get(keyOf(manifest, "payload"));
    if (epoch !== undefined && epoch.manifestId !== toHex(manifest.payload.manifest_id as Uint8Array)) return failure(20, "epoch/fork", "epoch_manifest.manifest_id");
  }
  for (const event of parsed.epoch_event) {
    const retainedId = epochs.get(keyOf(event, "payload"))?.events[event.payload.event_seq as number];
    if (retainedId !== undefined && retainedId !== toHex(event.payload.event_id as Uint8Array)) return failure(20, "epoch/fork", "epoch_event.event_id");
  }
  // (e): membership, then the step-15 fields; a retained index decides membership in its own epoch only.
  for (const receipt of parsed.receipt) if (epochs.get(keyOf(receipt))?.index.has(toHex(receipt.payload.receipt_id as Uint8Array)) === false) return failure(20, "manifest/receipt-unindexed", "receipt.binding");
  for (const receipt of parsed.receipt) {
    const entry = epochs.get(keyOf(receipt))?.index.get(toHex(receipt.payload.receipt_id as Uint8Array));
    if (entry !== undefined && !entryMatches(entry, receipt)) return failure(20, "manifest/index-receipt-mismatch", "receipt.binding");
  }
  // D-87 rule 2: supplied history is what the relying party observed; a lower sequence is relayed, never a rollback.
  const known = new Set(history.map((entry) => entry.id));
  if (carried.some((receipt) => known.has(receipt.id))) observe(observations, "duplicate_exact");
  if (carried.some((receipt) => !known.has(receipt.id) && history.some((entry) => (entry.kid === receipt.kid && receipt.seq < entry.seq) || (entry.owner === receipt.owner && entry.epochId === receipt.epochId && receipt.epochSeq < entry.epochSeq)))) observe(observations, "sequence_below_observed_history");
  return undefined;
}

// D-87 rule 5, on a conformant verdict only: every carried receipt (at least one) listed by a retained epoch.
export function retainedMembership(parsed: Parsed, retained: Retained | undefined): string {
  return retained !== undefined && parsed.receipt.length > 0 && parsed.receipt.every((receipt) => retained.get(keyOf(receipt))?.index.has(toHex(receipt.payload.receipt_id as Uint8Array)))
    ? "all_receipts_listed" : "not_established";
}
