// D-87 rule 3: relying-party-retained bundles (prior-state retained_epochs), checked
// before evaluation begins in CONFORMANCE section 5 order. Every failure is a usage
// error (a throw, no verdict). pyref/retained.py mirrors this module.
import { CborValue, decodeCbor, fromHex, toHex } from "./cbor";
import { domainHash, hash } from "./crypto";
import { Emission, emissionOf, fromPrior, sameCoordinates } from "./emission-identity";
import { epochKey } from "./manifest-index";
import { evaluateSteps, Obj, uint, VerifyB1Options } from "./verifier";

export const RETAINED_BUNDLES = 16;
export const RETAINED_BYTES = 16_777_216;
export const RETAINED_RECEIPT_CONTRADICTION = "prior-state.prior_emissions entry matches a retained receipt's receipt_id and envelope_digest but not its coordinates";
export const RETAINED_UNLISTED = "prior-state.prior_emissions entry names a retained epoch whose index does not list its receipt_id";
export const RETAINED_COORDINATES = "prior-state.prior_emissions entry names a retained epoch whose index lists it with other coordinates";

// One retained epoch, keyed by epochKey(owner, epoch_id): its manifest, full index by receipt_id, event chain by event_seq.
export interface RetainedEpoch { manifestId: string; index: Map<string, Obj>; events: string[] }
export type Retained = Map<string, RetainedEpoch>;

const LABEL = "prior-state.retained_epochs";

function checkCount(value: unknown): asserts value is unknown[] {
  if (!Array.isArray(value)) throw new Error(`${LABEL} must be an array`);
  if (value.length > RETAINED_BUNDLES) throw new Error(`${LABEL} must hold at most ${RETAINED_BUNDLES} bundles`);
}

function checkTotal(lengths: number[]): void {
  if (lengths.reduce((sum, length) => sum + length, 0) > RETAINED_BYTES) throw new Error(`${LABEL} must total at most ${RETAINED_BYTES} bytes`);
}

// The JSON form (pyref retained.load's first checks): at most 16 hex strings totalling at
// most 16 MiB, both checked before any is decoded; hex strings are decoded here and nowhere else.
export function parseRetainedJson(value: unknown): Uint8Array[] {
  checkCount(value);
  value.forEach((item, index) => {
    if (typeof item !== "string") throw new Error(`${LABEL}[${index}] must be a hex string`);
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(item)) throw new Error(`${LABEL}[${index}] is not valid hex`);
  });
  checkTotal((value as string[]).map((item) => item.length / 2));
  return (value as string[]).map(fromHex);
}

// The typed form: count, byte arrays, total, then the strict SHA-256 order. Returns the digests.
function checkRetained(bundles: unknown): string[] {
  checkCount(bundles);
  bundles.forEach((item, index) => { if (!(item instanceof Uint8Array)) throw new Error(`${LABEL}[${index}] must be a Uint8Array`); });
  checkTotal((bundles as Uint8Array[]).map((item) => item.length));
  const digests = (bundles as Uint8Array[]).map((item) => toHex(hash(item)));
  if (digests.some((digest, index) => index > 0 && digests[index - 1]! >= digest)) throw new Error(`${LABEL} must be strictly sorted and unique by SHA-256`);
  return digests;
}

// retained_epochs_digest: zero without prior state, the empty-list digest without retained_epochs.
export function retainedEpochsDigest(options: VerifyB1Options): Uint8Array {
  if (options.priorEmissions === undefined && options.retainedEpochs === undefined) return new Uint8Array(32);
  return domainHash("AAR-VERDICT-RETAINED-v1", { bundles: checkRetained(options.retainedEpochs ?? []).map(fromHex) });
}

// A bundle that cannot be read this far fails steps 1 to 3 at any time.
function ownTime(bundle: Uint8Array, fallback: number): number {
  try {
    const value = decodeCbor(bundle) as Obj;
    const time = (value.trust_inputs as Obj).evaluation_time as CborValue;
    return uint(time) ? time : fallback;
  } catch { return fallback; }
}

export function loadRetained(input: Uint8Array, options: VerifyB1Options): Retained | undefined {
  if (options.retainedEpochs === undefined) return undefined;
  if (options.priorEmissions === undefined) throw new Error(`${LABEL} requires priorEmissions (the prior state it belongs to)`);
  const bundles = options.retainedEpochs;
  checkRetained(bundles);
  const current = toHex(hash(input));
  bundles.forEach((bundle, index) => { if (toHex(hash(bundle)) === current) throw new Error(`${LABEL}[${index}] is byte-identical to the bundle being evaluated`); });
  const retained: Retained = new Map();
  const receipts: Emission[] = [];
  bundles.forEach((bundle, index) => {
    const at = ownTime(bundle, options.evaluationTime);
    const steps = evaluateSteps(bundle, { evaluationTime: at, configuration: options.configuration }, false);
    if ("issue" in steps) throw new Error(`${LABEL}[${index}] fails step ${steps.issue.step} (${steps.issue.reason})`);
    if (at > options.evaluationTime) throw new Error(`${LABEL}[${index}] evaluation time is later than the current evaluation time`);
    receipts.push(...steps.parsed.receipt.map(emissionOf));
    // Step 14 passed: every carried manifest is a closed epoch, one per key, its events a chain from 0.
    for (const manifest of steps.parsed.epoch_manifest) {
      const key = epochKey(manifest.payload.epoch_owner_kid as Uint8Array, manifest.payload.epoch_id as number);
      const events = steps.parsed.epoch_event.filter((event) => epochKey(event.payload.epoch_owner_kid as Uint8Array, event.payload.epoch_id as number) === key)
        .sort((left, right) => (left.payload.event_seq as number) - (right.payload.event_seq as number)).map((event) => toHex(event.payload.event_id as Uint8Array));
      const epoch: RetainedEpoch = { manifestId: toHex(manifest.payload.manifest_id as Uint8Array), events,
        index: new Map(((manifest.payload.receipt_index as Obj).entries as Obj[]).map((entry) => [toHex(entry.receipt_id as Uint8Array), entry])) };
      const known = retained.get(key);
      if (known !== undefined && known.manifestId !== epoch.manifestId) throw new Error(`${LABEL}[${index}] carries a manifest that conflicts with a retained manifest for the same owner and epoch`);
      if (known !== undefined && known.events.some((id, position) => position < events.length && events[position] !== id)) throw new Error(`${LABEL}[${index}] carries an epoch event chain that conflicts with a retained chain`);
      if (known === undefined || events.length > known.events.length) retained.set(key, epoch);
    }
  });
  const prior = options.priorEmissions.map(fromPrior);
  if (prior.some((entry) => receipts.some((receipt) => receipt.id === entry.id && receipt.digest === entry.digest && !sameCoordinates(receipt, entry)))) throw new Error(RETAINED_RECEIPT_CONTRADICTION);
  for (const entry of prior) {
    const listed = retained.get(`${entry.owner}:${entry.epochId}`)?.index;
    if (listed === undefined) continue;
    const indexed = listed.get(entry.id);
    if (indexed === undefined) throw new Error(RETAINED_UNLISTED);
    if (toHex(indexed.issuer_kid as Uint8Array) !== entry.kid || indexed.issuer_seq !== entry.seq || indexed.epoch_seq !== entry.epochSeq) throw new Error(RETAINED_COORDINATES);
  }
  return retained;
}
