// CONFORMANCE step 9, emission identity (D-86, D-87): supplied prior state is
// checked first (entry shape, D-76 order, rule 0(a)), then rule 0(b), then phase A
// over the carried receipts alone. Every other history comparison is the step-20
// history phase (history.ts). pyref/emission_identity.py mirrors this module.
// Malformed or contradictory history is a usage error (a throw, no verdict).
import { CborValue, encodeCbor, fromHex, toHex } from "./cbor";
import { hash } from "./crypto";
import { B1Failure, bytes, failure, Obj, Parsed, ParsedEnvelope, PriorEmission, uint } from "./verifier";

export const HISTORY_CONTRADICTS_ITSELF = "prior-state.prior_emissions entries with one receipt_id and envelope_digest must have the same coordinates";
export const HISTORY_CONTRADICTS_RECEIPT = "prior-state.prior_emissions entry matches a carried receipt's receipt_id and envelope_digest but not its coordinates";
// Wire key, PriorEmission field, in the D-76 sort-tuple order.
const PRIOR_KEYS = [["issuer_kid", "issuerKid"], ["issuer_seq", "issuerSeq"], ["epoch_owner_kid", "epochOwnerKid"], ["epoch_id", "epochId"], ["epoch_seq", "epochSeq"], ["receipt_id", "receiptId"], ["envelope_digest", "envelopeDigest"]] as const;
const plain = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

const UINT_KEYS: readonly string[] = ["issuer_seq", "epoch_id", "epoch_seq"];

function uintField(value: unknown, label: string): number {
  if (!uint(value as CborValue)) throw new Error(`${label} must be an unsigned integer <= 9007199254740991`);
  return value as number;
}

// A closed entry: every field present, nothing else, named by its wire key when
// missing (pyref's message). The JSON form uses wire keys, the typed form field names.
function closedEntry(item: unknown, label: string, typed: boolean): Record<string, unknown> {
  if (!plain(item)) throw new Error(`${label} must be a JSON object`);
  const names: readonly string[] = PRIOR_KEYS.map(([key, field]) => typed ? field : key);
  const missing = PRIOR_KEYS.filter(([key, field]) => !Object.hasOwn(item, typed ? field : key)).map(([key]) => key).sort();
  const unknown = Object.keys(item).filter((key) => !names.includes(key)).sort();
  if (missing.length > 0 || unknown.length > 0) {
    throw new Error(`${label}: ${[...(missing.length > 0 ? [`missing ${missing.join(", ")}`] : []), ...(unknown.length > 0 ? [`unknown ${unknown.join(", ")}`] : [])].join("; ")}`);
  }
  return item;
}

// The JSON prior state (pyref emission_identity.prior_entries): a closed top level and
// closed seven-key entries; hex strings are decoded here and nowhere else.
export function parsePriorState(value: unknown): PriorEmission[] {
  if (!plain(value)) throw new Error("prior-state must be a JSON object");
  const unknown = Object.keys(value).filter((key) => !["prior_emissions", "retained_epochs", "entries"].includes(key)).sort();
  if (unknown.length > 0) throw new Error(`prior-state: unknown ${unknown.join(", ")}`);
  const source = Object.hasOwn(value, "prior_emissions") ? value.prior_emissions : [];
  if (!Array.isArray(source)) throw new Error("prior-state.prior_emissions must be an array");
  return source.map((item: unknown, index) => {
    const label = `prior-state.prior_emissions[${index}]`;
    const entry = closedEntry(item, label, false);
    return Object.fromEntries(PRIOR_KEYS.map(([key, field]) => {
      const raw = entry[key];
      if (UINT_KEYS.includes(key)) return [field, uintField(raw, `${label}.${key}`)];
      if (typeof raw !== "string") throw new Error(`${label}.${key} must be a 32-byte lowercase or uppercase hex string`);
      if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(raw)) throw new Error(`${label}.${key} is not valid hex`);
      if (raw.length !== 64) throw new Error(`${label}.${key} must decode to exactly 32 bytes`);
      return [field, fromHex(raw)];
    })) as unknown as PriorEmission;
  });
}

export interface Emission { id: string; digest: string; kid: string; seq: number; owner: string; epochId: number; epochSeq: number; issuer: string; epoch: string }

function emission(id: Uint8Array, digest: Uint8Array, kid: Uint8Array, seq: number, owner: Uint8Array, epochId: number, epochSeq: number): Emission {
  return { id: toHex(id), digest: toHex(digest), kid: toHex(kid), seq, owner: toHex(owner), epochId, epochSeq, issuer: `${toHex(kid)}:${seq}`, epoch: `${toHex(owner)}:${epochId}:${epochSeq}` };
}

export const fromPrior = (entry: PriorEmission): Emission => emission(entry.receiptId, entry.envelopeDigest, entry.issuerKid, entry.issuerSeq, entry.epochOwnerKid, entry.epochId, entry.epochSeq);
export const sameCoordinates = (left: Emission, right: Emission): boolean => left.issuer === right.issuer && left.epoch === right.epoch;
// A carried receipt's emission; its coordinate types are pinned at step 9 before any use.
export function emissionOf(receipt: ParsedEnvelope): Emission {
  const binding = receipt.payload.binding as Obj;
  return emission(receipt.payload.receipt_id as Uint8Array, hash(receipt.envelopeBytes), receipt.kid, (receipt.payload.emission as Obj).issuer_seq as number, binding.epoch_owner_kid as Uint8Array, binding.epoch_id as number, binding.epoch_seq as number);
}

// The typed prior-state boundary, run by verifyBundle before evaluation begins and by
// the verdict digest before hashing (pyref emission_identity.prior_entries): an array
// of closed entries holding 32-byte Uint8Arrays (a string is refused, never decoded)
// and uints, then the D-76 strict order, then D-86 rule 0(a).
export function checkPriorEmissions(prior: readonly PriorEmission[]): void {
  if (!Array.isArray(prior)) throw new Error("prior-state.prior_emissions must be an array");
  prior.forEach((item, index) => {
    const label = `prior-state.prior_emissions[${index}]`;
    const entry = closedEntry(item, label, true);
    for (const [key, field] of PRIOR_KEYS) {
      const value = entry[field];
      if (UINT_KEYS.includes(key)) uintField(value, `${label}.${key}`);
      else if (!(value instanceof Uint8Array)) throw new Error(`${label}.${key} must be a 32-byte Uint8Array`);
      else if (value.length !== 32) throw new Error(`${label}.${key} must decode to exactly 32 bytes`);
    }
  });
  const keys = prior.map((entry) => toHex(encodeCbor(PRIOR_KEYS.map(([, field]) => entry[field]))));
  if (keys.some((key, index) => index > 0 && keys[index - 1]! >= key)) throw new Error("prior-state.prior_emissions must be strictly sorted and unique");
  const seen = new Map<string, Emission>();
  for (const entry of prior.map(fromPrior)) {
    const key = `${entry.id}:${entry.digest}`;
    if (!sameCoordinates(seen.get(key) ?? entry, entry)) throw new Error(HISTORY_CONTRADICTS_ITSELF);
    seen.set(key, entry);
  }
}

export function validateEmission(parsed: Parsed, prior: readonly PriorEmission[] | undefined): B1Failure | undefined {
  const carried: Emission[] = [];
  for (const receipt of parsed.receipt) {
    const binding = receipt.payload.binding as Obj;
    // Identity coordinates are used as map keys below; pin their types first so
    // malformed input yields a signed verdict instead of a silent array-typed
    // coordinate collision (pyref emission_identity parity).
    if (!uint((receipt.payload.emission as Obj).issuer_seq)) return failure(9, "schema/bad-type", "receipt.emission.issuer_seq");
    if (!bytes(binding.epoch_owner_kid, 32) || !uint(binding.epoch_id) || !uint(binding.epoch_seq)) return failure(9, "schema/bad-type", "receipt.binding");
    carried.push(emissionOf(receipt));
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
  return undefined;
}
