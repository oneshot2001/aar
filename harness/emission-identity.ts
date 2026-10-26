// CONFORMANCE step 9, emission identity (D-86): supplied prior state is checked
// first (entry shape, D-76 order, rule 0(a)), then phase A over the carried
// receipts alone, then phase B against the prior state, one reason class per full
// pass. pyref/emission_identity.py mirrors this module. Malformed or contradictory
// history is a usage error (a throw, no verdict).
import { CborValue, encodeCbor, fromHex, toHex } from "./cbor";
import { hash } from "./crypto";
import { B1Failure, bytes, failure, observe, Obj, Parsed, PriorEmission, uint } from "./verifier";

export const HISTORY_CONTRADICTS_ITSELF = "prior-state.prior_emissions entries with one receipt_id and envelope_digest must have the same coordinates";
export const HISTORY_CONTRADICTS_RECEIPT = "prior-state.prior_emissions entry matches a carried receipt's receipt_id and envelope_digest but not its coordinates";
// Wire key, PriorEmission field, in the D-76 sort-tuple order.
const PRIOR_KEYS = [["issuer_kid", "issuerKid"], ["issuer_seq", "issuerSeq"], ["epoch_owner_kid", "epochOwnerKid"], ["epoch_id", "epochId"], ["epoch_seq", "epochSeq"], ["receipt_id", "receiptId"], ["envelope_digest", "envelopeDigest"]] as const;
const plain = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

// One entry field, with pyref's messages: a uint, or 32 bytes as hex (JSON) or as bytes (a typed caller).
function priorField(value: unknown, key: string, label: string): number | Uint8Array {
  if (key === "issuer_seq" || key === "epoch_id" || key === "epoch_seq") {
    if (!uint(value as CborValue)) throw new Error(`${label} must be an unsigned integer <= 9007199254740991`);
    return value as number;
  }
  if (value instanceof Uint8Array && value.length === 32) return value;
  if (value instanceof Uint8Array) throw new Error(`${label} must decode to exactly 32 bytes`);
  if (typeof value !== "string") throw new Error(`${label} must be a 32-byte lowercase or uppercase hex string`);
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) throw new Error(`${label} is not valid hex`);
  if (value.length !== 64) throw new Error(`${label} must decode to exactly 32 bytes`);
  return fromHex(value);
}

// The JSON prior state (pyref emission_identity.prior_entries): closed seven-key entries.
export function parsePriorState(value: unknown): PriorEmission[] {
  if (!plain(value)) throw new Error("prior-state must be a JSON object");
  const source = Object.hasOwn(value, "prior_emissions") ? value.prior_emissions : [];
  if (!Array.isArray(source)) throw new Error("prior-state.prior_emissions must be an array");
  const names: readonly string[] = PRIOR_KEYS.map(([key]) => key);
  return source.map((item: unknown, index) => {
    const label = `prior-state.prior_emissions[${index}]`;
    if (!plain(item)) throw new Error(`${label} must be a JSON object`);
    const missing = names.filter((key) => !Object.hasOwn(item, key)).sort();
    const unknown = Object.keys(item).filter((key) => !names.includes(key)).sort();
    if (missing.length > 0 || unknown.length > 0) {
      throw new Error(`${label}: ${[...(missing.length > 0 ? [`missing ${missing.join(", ")}`] : []), ...(unknown.length > 0 ? [`unknown ${unknown.join(", ")}`] : [])].join("; ")}`);
    }
    return Object.fromEntries(PRIOR_KEYS.map(([key, field]) => [field, priorField(item[key], key, `${label}.${key}`)])) as unknown as PriorEmission;
  });
}

interface Emission { id: string; digest: string; kid: string; seq: number; owner: string; epochId: number; epochSeq: number; issuer: string; epoch: string }

function emission(id: Uint8Array, digest: Uint8Array, kid: Uint8Array, seq: number, owner: Uint8Array, epochId: number, epochSeq: number): Emission {
  return { id: toHex(id), digest: toHex(digest), kid: toHex(kid), seq, owner: toHex(owner), epochId, epochSeq, issuer: `${toHex(kid)}:${seq}`, epoch: `${toHex(owner)}:${epochId}:${epochSeq}` };
}

const fromPrior = (entry: PriorEmission): Emission => emission(entry.receiptId, entry.envelopeDigest, entry.issuerKid, entry.issuerSeq, entry.epochOwnerKid, entry.epochId, entry.epochSeq);
const sameCoordinates = (left: Emission, right: Emission): boolean => left.issuer === right.issuer && left.epoch === right.epoch;

// verifyBundle's prior-state boundary, before evaluation begins: entry shape, the
// D-76 strict order, then D-86 rule 0(a) (pyref emission_identity.prior_entries).
export function checkPriorEmissions(prior: readonly PriorEmission[]): void {
  prior.forEach((entry, index) => { for (const [key, field] of PRIOR_KEYS) priorField(entry[field], key, `prior-state.prior_emissions[${index}].${key}`); });
  const keys = prior.map((entry) => toHex(encodeCbor(PRIOR_KEYS.map(([, field]) => entry[field]))));
  if (keys.some((key, index) => index > 0 && keys[index - 1]! >= key)) throw new Error("prior-state.prior_emissions must be strictly sorted and unique");
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

  // Phase A: one equivocation pass, issuer before epoch per receipt. Step 3 already
  // rejects a repeated receipt_id in artifacts.receipts, so there is no in-bundle reuse.
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
