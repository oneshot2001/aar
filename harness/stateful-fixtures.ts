import { CborValue, decodeCbor, encodeCbor, toHex } from "./cbor";
import { deterministicId, hash } from "./crypto";
import { parsePriorState } from "./emission-identity";
import { buildFixtures } from "./fixtures";
import { mutateReceiptWhere, payload, protectedMap, receiptList, same } from "./mutate";
import { PriorEmission } from "./verifier";

type Obj = Record<string, CborValue>;

export interface StatefulPriorJson {
  prior_emissions?: Array<{
    issuer_kid: string;
    issuer_seq: number;
    epoch_owner_kid: string;
    epoch_id: number;
    epoch_seq: number;
    receipt_id: string;
    envelope_digest: string;
  }>;
}

// A fixture without `prior` is evaluated without prior state; one whose
// expected_code is null is conformant and is written under kats/positive/stateful/.
export interface StatefulFixture {
  name: string;
  bundle: Uint8Array;
  prior?: StatefulPriorJson;
  descriptor: { name: string; expected_result?: "conformant"; expected_code: string | null; expected_observations?: string[]; absent_observations?: string[]; mutation_description: string };
}

function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

// The prior-state entry that exactly re-presents one carried receipt envelope.
function entryOf(envelope: CborValue): PriorEmission {
  const receipt = payload(envelope);
  const kid = protectedMap(envelope).get(4);
  if (!(kid instanceof Uint8Array) || !object(receipt.binding) || !object(receipt.emission)) throw new Error("receipt malformed");
  return {
    issuerKid: kid, issuerSeq: receipt.emission.issuer_seq as number,
    epochOwnerKid: receipt.binding.epoch_owner_kid as Uint8Array, epochId: receipt.binding.epoch_id as number, epochSeq: receipt.binding.epoch_seq as number,
    receiptId: receipt.receipt_id as Uint8Array, envelopeDigest: hash(encodeCbor(envelope)),
  };
}

// The exact prior-state entry of every carried receipt, in artifact order.
export function exactEntries(bytes: Uint8Array): PriorEmission[] {
  const bundle = decodeCbor(bytes, { strict: true });
  if (!object(bundle) || !object(bundle.artifacts) || !Array.isArray(bundle.artifacts.receipts)) throw new Error("bundle malformed");
  return bundle.artifacts.receipts.map(entryOf);
}

function base(): { bytes: Uint8Array; entries: PriorEmission[] } {
  const kat = buildFixtures().kats.find((entry) => entry.filename === "bundle-valid-subset");
  if (kat === undefined) throw new Error("positive bundle missing");
  return { bytes: kat.bytes, entries: exactEntries(kat.bytes) };
}

// Committed order: strictly sorted by deterministic CBOR of the entry tuple (CONFORMANCE section 5).
export function priorJson(...values: PriorEmission[]): StatefulPriorJson {
  const key = (value: PriorEmission): string => toHex(encodeCbor([value.issuerKid, value.issuerSeq, value.epochOwnerKid, value.epochId, value.epochSeq, value.receiptId, value.envelopeDigest]));
  return { prior_emissions: [...values].sort((left, right) => key(left) < key(right) ? -1 : 1).map((value) => ({
    issuer_kid: toHex(value.issuerKid), issuer_seq: value.issuerSeq,
    epoch_owner_kid: toHex(value.epochOwnerKid), epoch_id: value.epochId, epoch_seq: value.epochSeq,
    receipt_id: toHex(value.receiptId), envelope_digest: toHex(value.envelopeDigest),
  })) };
}

// The JSON prior state, validated as pyref's library and CLI validate it (E-06).
export function parseStatefulPrior(value: StatefulPriorJson): PriorEmission[] {
  return parsePriorState(value);
}

// One carried receipt mutated through the harness/mutate.ts path (re-id + re-sign + sort).
export function mutated(bytes: Uint8Array, index: number, mutation: (value: Obj) => void): Uint8Array {
  const bundle = decodeCbor(bytes, { strict: true }) as Obj;
  const target = payload(receiptList(bundle)[index]!);
  mutateReceiptWhere(bundle, (value) => same(value, target), mutation);
  return encodeCbor(bundle);
}

// The six differential-fuzz splits D-86 rules on: run, id, seed, receipts[index].emission.issuer_seq = seq.
export const FUZZ_SPLITS = [
  ["2026-10-22", "m-01770", "issuer", 5, 104], ["2026-10-22", "m-01931", "issuer", 0, 102], ["2026-10-22", "m-01969", "issuer", 2, 100],
  ["2026-10-22", "m-01986", "epoch", 3, 103], ["2026-10-24", "m-01906", "issuer", 0, 102], ["2026-10-24", "m-01946", "issuer", 0, 107],
] as const;

export function buildStatefulFixtures(): StatefulFixture[] {
  const source = base();
  const common = source.entries[0]!;
  const other = { receiptId: deterministicId("prior:other-receipt"), envelopeDigest: deterministicId("prior:other-envelope") };
  const issuerRollback = priorJson({ ...common, issuerSeq: 9_999_999, epochOwnerKid: deterministicId("prior:other-epoch-owner"), receiptId: deterministicId("prior:other-receipt") });
  const epochRollback = priorJson({ ...common, issuerKid: deterministicId("prior:other-issuer"), epochSeq: 9_999_999, receiptId: deterministicId("prior:other-receipt") });
  const lowestIssuer = source.entries.filter((entry) => same(entry.issuerKid, common.issuerKid)).reduce((low, entry) => entry.issuerSeq < low.issuerSeq ? entry : low);
  const lowestEpoch = source.entries.reduce((low, entry) => entry.epochSeq < low.epochSeq ? entry : low);
  const highestEpoch = source.entries.reduce((high, entry) => entry.epochSeq > high.epochSeq ? entry : high);
  const ids = (label: string): Pick<PriorEmission, "receiptId" | "envelopeDigest"> => ({ receiptId: deterministicId(`prior:${label}-receipt`), envelopeDigest: deterministicId(`prior:${label}-envelope`) });
  // An epoch rollback for receipts[0] and nothing else; its zero issuer kid sorts it first in committed order.
  const epochAbove = { ...common, ...other, issuerKid: new Uint8Array(32), issuerSeq: 0, epochSeq: 9_999_999 };
  // One issuer and one epoch coordinate no carried receipt uses.
  const unrelated = { issuerKid: deterministicId("prior:history-only-issuer"), issuerSeq: 0, epochOwnerKid: deterministicId("prior:history-only-owner"), epochId: 1, epochSeq: 0 };
  const negative = (name: string, bundle: Uint8Array, prior: StatefulPriorJson | undefined, expected_code: string, mutation_description: string): StatefulFixture =>
    ({ name, bundle, ...(prior ? { prior } : {}), descriptor: { name, expected_code, mutation_description } });
  const positive = (name: string, prior: StatefulPriorJson, mutation_description: string, duplicate = true): StatefulFixture =>
    ({ name, bundle: source.bytes, prior, descriptor: { name, expected_result: "conformant", expected_code: null, expected_observations: duplicate ? ["duplicate_exact"] : [], ...(duplicate ? {} : { absent_observations: ["duplicate_exact"] }), mutation_description } });
  const phaseOrder = mutated(source.bytes, 1, (value) => { (value.binding as Obj).epoch_seq = common.epochSeq; });
  return [
    negative("identity-reuse", source.bytes, priorJson({ ...common, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "identity/reuse", "Prior evaluated state binds the carried receipt ID to different envelope bytes."),
    negative("identity-issuer-sequence-rollback", source.bytes, issuerRollback, "identity/issuer-sequence-rollback", "Prior evaluated state has a greater sequence for the carried issuer kid."),
    negative("identity-epoch-sequence-rollback", source.bytes, epochRollback, "identity/epoch-sequence-rollback", "Prior evaluated state has a greater sequence for the carried epoch owner and epoch."),
    ...FUZZ_SPLITS.map(([run, id, seed, index, seq]) => negative(`d86-fuzz-${id}`, mutated(source.bytes, index, (value) => { (value.emission as Obj).issuer_seq = seq; }), seed === "issuer" ? issuerRollback : epochRollback, "identity/coordinate-equivocation",
      `Fuzz split docs/fuzz-runs/${run}/${id} rebuilt: receipts[${index}].emission.issuer_seq = ${seq} repeats a sibling's issuer coordinate on the ${seed}-sequence-rollback seed and prior; the in-bundle collision (phase A) outranks the history rollback (D-86).`)),
    negative("d86-history-issuer-coordinate", source.bytes, priorJson({ ...lowestIssuer, ...other, epochOwnerKid: deterministicId("prior:other-epoch-owner") }), "identity/coordinate-equivocation",
      "Q1: a prior entry names a carried receipt's issuer coordinate (its issuer's lowest issuer_seq) under a different receipt ID, in an unrelated epoch."),
    negative("d86-history-epoch-coordinate", source.bytes, priorJson({ ...lowestEpoch, ...other, issuerKid: deterministicId("prior:other-issuer"), issuerSeq: 0 }), "identity/coordinate-equivocation",
      "Q2: a prior entry names a carried receipt's epoch coordinate under a different receipt ID; an equal epoch_seq is equivocation, not rollback."),
    negative("d86-history-reuse-outranks-rollback", source.bytes, priorJson(epochAbove, { ...common, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "identity/reuse",
      "Phase B class order: receipts[0] is an epoch rollback against the first committed entry and an ID reuse against a later one; the reuse pass runs first."),
    negative("d86-phase-order-with-prior", phaseOrder, issuerRollback, "identity/coordinate-equivocation",
      "Phase order: receipts[1].binding.epoch_seq repeats receipts[0]'s epoch coordinate, and the prior is an issuer rollback; the in-bundle collision (phase A) outranks it."),
    negative("d86-phase-order-without-prior", phaseOrder, undefined, "identity/coordinate-equivocation",
      "Phase order: the d86-phase-order-with-prior bundle evaluated without prior state reports the same code."),
    positive("d86-history-exact-represent", priorJson(lowestEpoch),
      "Q3: the prior entry exactly re-presents one carried receipt; it is a duplicate observation, exempt from rollback against its own sequence."),
    positive("d86-history-full-reobservation", priorJson(...source.entries),
      "Every carried receipt exactly re-presented in prior state; the receipt-wide duplicate exemption keeps a lower sequence from reading as rollback against a later copy."),
    // D-86 review (E-06 C): the phase-B class order, the limits of the duplicate exemption, history-only conflicts, partial history.
    negative("d86-phase-b-issuer-outranks-epoch-rollback", source.bytes, priorJson(epochAbove, { ...common, ...ids("issuer-above"), issuerSeq: 9_999_999, epochOwnerKid: deterministicId("prior:other-epoch-owner") }), "identity/issuer-sequence-rollback",
      "Phase B class order: receipts[0] is an epoch rollback against the first committed entry and an issuer rollback against the second; the issuer-rollback pass runs before the epoch-rollback pass (a per-pair interleave reports the epoch rollback)."),
    negative("d86-phase-b-equivocation-outranks-rollback", source.bytes, priorJson(epochAbove, { ...source.entries.at(-1)!, ...ids("issuer-coordinate"), epochOwnerKid: deterministicId("prior:other-epoch-owner") }), "identity/coordinate-equivocation",
      "Phase B class order: receipts[0] is an epoch rollback against the first committed entry, and the second names the last carried receipt's issuer coordinate under another receipt ID; the equivocation pass runs before both rollback passes."),
    negative("d86-duplicate-not-exempt-from-equivocation", source.bytes, priorJson(lowestEpoch, { ...lowestEpoch, ...other, issuerKid: new Uint8Array(32), issuerSeq: 0 }), "identity/coordinate-equivocation",
      "An exact copy of one carried receipt plus an entry naming that receipt's epoch coordinate under another receipt ID: the duplicate is exempt from rollback only, so the equivocation pass still fails it."),
    negative("d86-duplicate-not-exempt-from-reuse", source.bytes, priorJson(lowestEpoch, { ...lowestEpoch, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "identity/reuse",
      "An exact copy of one carried receipt plus an entry giving that receipt ID other envelope bytes: the duplicate is exempt from rollback only, so the reuse pass still fails it."),
    positive("d86-history-only-conflict", priorJson({ ...unrelated, ...ids("history-only-a") }, { ...unrelated, ...ids("history-only-b") }),
      "Two prior entries share one issuer coordinate and one epoch coordinate under different receipt IDs, and neither touches a carried receipt: entries that conflict only with each other do not fail the bundle.", false),
    negative("d86-partial-history-epoch-rollback", source.bytes, priorJson(highestEpoch), "identity/epoch-sequence-rollback",
      "Partial history: an exact copy of only the highest-epoch_seq carried receipt. That receipt is a duplicate observation; the bundle's other receipts in its epoch have lower epoch_seq and are epoch rollback against it (unchanged from v0.3.0; whether prior state is a complete record or a high-water mark is a BACKLOG design question)."),
  ];
}
