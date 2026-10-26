// CONFORMANCE step 9, emission identity (D-86): history consistency, then phase A
// over the carried receipts alone, then phase B against supplied prior state, one
// reason class per full pass. pyref/emission_identity.py mirrors this module.
// Contradictory history is a usage error (a throw, no verdict), like the D-76
// duplicate/unsorted rule in verifyBundle.
import { toHex } from "./cbor";
import { hash } from "./crypto";
import { B1Failure, bytes, failure, observe, Obj, Parsed, PriorEmission, uint } from "./verifier";

export const HISTORY_CONTRADICTS_ITSELF = "prior-state.prior_emissions entries with one receipt_id and envelope_digest must have the same coordinates";
export const HISTORY_CONTRADICTS_RECEIPT = "prior-state.prior_emissions entry matches a carried receipt's receipt_id and envelope_digest but not its coordinates";

interface Emission { id: string; digest: string; kid: string; seq: number; owner: string; epochId: number; epochSeq: number; issuer: string; epoch: string }

function emission(id: Uint8Array, digest: Uint8Array, kid: Uint8Array, seq: number, owner: Uint8Array, epochId: number, epochSeq: number): Emission {
  return { id: toHex(id), digest: toHex(digest), kid: toHex(kid), seq, owner: toHex(owner), epochId, epochSeq, issuer: `${toHex(kid)}:${seq}`, epoch: `${toHex(owner)}:${epochId}:${epochSeq}` };
}

const fromPrior = (entry: PriorEmission): Emission => emission(entry.receiptId, entry.envelopeDigest, entry.issuerKid, entry.issuerSeq, entry.epochOwnerKid, entry.epochId, entry.epochSeq);
const sameCoordinates = (left: Emission, right: Emission): boolean => left.issuer === right.issuer && left.epoch === right.epoch;

// D-86 rule 0(a): checked with the duplicate/unsorted rule, before any bundle byte is read.
export function checkPriorHistory(prior: readonly PriorEmission[]): void {
  const seen = new Map<string, Emission>();
  for (const entry of prior.map(fromPrior)) {
    const key = `${entry.id}:${entry.digest}`;
    if (!sameCoordinates(seen.get(key) ?? entry, entry)) throw new Error(HISTORY_CONTRADICTS_ITSELF);
    seen.set(key, entry);
  }
}

export function validateEmission(parsed: Parsed, prior: readonly PriorEmission[] | undefined, observations: string[]): B1Failure | undefined {
  const carried: Emission[] = [];
  for (const receipt of parsed.receipt) {
    const binding = receipt.payload.binding as Obj;
    const emissionMap = receipt.payload.emission as Obj;
    // Identity coordinates are used as map keys below; pin their types first so
    // malformed input yields a signed verdict instead of a silent array-typed
    // coordinate collision (pyref emission_identity parity).
    if (!uint(emissionMap.issuer_seq)) return failure(9, "schema/bad-type", "receipt.emission.issuer_seq");
    if (!bytes(binding.epoch_owner_kid, 32) || !uint(binding.epoch_id) || !uint(binding.epoch_seq)) return failure(9, "schema/bad-type", "receipt.binding");
    carried.push(emission(receipt.payload.receipt_id as Uint8Array, hash(receipt.envelopeBytes), receipt.kid, emissionMap.issuer_seq, binding.epoch_owner_kid, binding.epoch_id, binding.epoch_seq));
  }
  const history = (prior ?? []).map(fromPrior);
  // Rule 0(b), before phase A: history that contradicts a carried receipt is a usage error.
  if (carried.some((receipt) => history.some((entry) => entry.id === receipt.id && entry.digest === receipt.digest && !sameCoordinates(entry, receipt)))) {
    throw new Error(HISTORY_CONTRADICTS_RECEIPT);
  }

  // Phase A: reuse over the whole bundle, then equivocation (issuer before epoch per receipt).
  const byId = new Map<string, string>();
  for (const receipt of carried) {
    const digest = byId.get(receipt.id);
    if (digest !== undefined && digest !== receipt.digest) return failure(9, "identity/reuse", "receipts");
    if (digest !== undefined) observe(observations, "duplicate_exact");
    byId.set(receipt.id, receipt.digest);
  }
  const issuers = new Map<string, string>();
  const epochs = new Map<string, string>();
  for (const receipt of carried) {
    if ((issuers.get(receipt.issuer) ?? receipt.id) !== receipt.id) return failure(9, "identity/coordinate-equivocation", "receipt.emission.issuer_seq");
    if ((epochs.get(receipt.epoch) ?? receipt.id) !== receipt.id) return failure(9, "identity/coordinate-equivocation", "receipt.binding.epoch_seq");
    issuers.set(receipt.issuer, receipt.id); epochs.set(receipt.epoch, receipt.id);
  }

  // Phase B: every carried receipt against every entry, one class per pass. After
  // (i) and rule 0(b), an equal ID is an exact duplicate: exempt from rollback only.
  for (const receipt of carried) for (const entry of history) if (entry.id === receipt.id && entry.digest !== receipt.digest) return failure(9, "identity/reuse", "receipts");
  for (const receipt of carried) {
    for (const entry of history) {
      if (entry.id === receipt.id) observe(observations, "duplicate_exact");
      else if (entry.issuer === receipt.issuer) return failure(9, "identity/coordinate-equivocation", "receipt.emission.issuer_seq");
      else if (entry.epoch === receipt.epoch) return failure(9, "identity/coordinate-equivocation", "receipt.binding.epoch_seq");
    }
  }
  const remaining = carried.filter((receipt) => !history.some((entry) => entry.id === receipt.id));
  for (const receipt of remaining) for (const entry of history) if (entry.kid === receipt.kid && receipt.seq < entry.seq) return failure(9, "identity/issuer-sequence-rollback", "receipt.emission.issuer_seq");
  for (const receipt of remaining) for (const entry of history) if (entry.owner === receipt.owner && entry.epochId === receipt.epochId && receipt.epochSeq < entry.epochSeq) return failure(9, "identity/epoch-sequence-rollback", "receipt.binding.epoch_seq");
  return undefined;
}
