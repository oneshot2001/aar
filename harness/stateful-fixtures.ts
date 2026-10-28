import { CborValue, decodeCbor, encodeCbor, toHex } from "./cbor";
import { deterministicId, hash, id16 } from "./crypto";
import { checkPriorEmissions, parsePriorState } from "./emission-identity";
import { buildFixtures } from "./fixtures";
import { artifacts, clone, keepReceipts, mutateLastEvent, mutateReceiptWhere, payload, protectedMap, rebuildManifest, receiptList, resign, same, sortArtifacts } from "./mutate";
import { receiptBy, replaceReceipt } from "./mutate-graph";
import { buildD82PositiveFixtures } from "./negative-fixtures";
import { parseRetainedJson } from "./retained";
import { PriorEmission, VerifyB1Options } from "./verifier";

type Obj = Record<string, CborValue>;

export interface StatefulPriorJson {
  retained_epochs?: string[];
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
  descriptor: { name: string; expected_result?: "conformant"; expected_code: string | null; expected_step?: number; expected_observations?: string[]; absent_observations?: string[]; expected_limits?: Record<string, string>; mutation_description: string };
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

// The whole JSON prior state as verifyBundle options, checked in pyref's order:
// prior_emissions (shape, D-76 order, rule 0(a)), then the retained_epochs shape (D-87).
export function statefulOptions(value: StatefulPriorJson): Pick<VerifyB1Options, "priorEmissions" | "retainedEpochs"> {
  const priorEmissions = parsePriorState(value);
  checkPriorEmissions(priorEmissions);
  return Object.hasOwn(value, "retained_epochs") ? { priorEmissions, retainedEpochs: parseRetainedJson(value.retained_epochs) } : { priorEmissions };
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
  // An epoch rollback for every carried receipt in receipts[0]'s epoch (here every carried receipt) and no other
  // check; its zero issuer kid sorts it first in committed order.
  const epochAbove = { ...common, ...other, issuerKid: new Uint8Array(32), issuerSeq: 0, epochSeq: 9_999_999 };
  // One issuer and one epoch coordinate no carried receipt uses.
  const unrelated = { issuerKid: deterministicId("prior:history-only-issuer"), issuerSeq: 0, epochOwnerKid: deterministicId("prior:history-only-owner"), epochId: 1, epochSeq: 0 };
  // D-87: phase A stays at step 9; every comparison with supplied state is the step-20 history phase.
  const negative = (name: string, bundle: Uint8Array, prior: StatefulPriorJson | undefined, expected_code: string, mutation_description: string, expected_step = 20): StatefulFixture =>
    ({ name, bundle, ...(prior ? { prior } : {}), descriptor: { name, expected_code, expected_step, mutation_description } });
  const positive = (name: string, prior: StatefulPriorJson, mutation_description: string, observations = ["duplicate_exact"], bundle = source.bytes, limits?: Record<string, string>): StatefulFixture =>
    ({ name, bundle, prior, descriptor: { name, expected_result: "conformant", expected_code: null, expected_observations: observations, ...(observations.length > 0 ? {} : { absent_observations: ["duplicate_exact"] }), ...(limits ? { expected_limits: limits } : {}), mutation_description } });
  const below = ["sequence_below_observed_history"];
  const phaseOrder = mutated(source.bytes, 1, (value) => { (value.binding as Obj).epoch_seq = common.epochSeq; });
  return [
    negative("identity-reuse", source.bytes, priorJson({ ...common, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "identity/reuse", "Prior evaluated state binds the carried receipt ID to different envelope bytes."),
    positive("identity-issuer-sequence-rollback", issuerRollback, "Prior evaluated state has a greater sequence for the carried issuer kid: what the relying party observed, not a complete record, so the lower sequence is the observation sequence_below_observed_history (D-87; was identity/issuer-sequence-rollback).", below),
    positive("identity-epoch-sequence-rollback", epochRollback, "Prior evaluated state has a greater sequence for the carried epoch owner and epoch: the observation sequence_below_observed_history (D-87; was identity/epoch-sequence-rollback).", below),
    ...FUZZ_SPLITS.map(([run, id, seed, index, seq]) => negative(`d86-fuzz-${id}`, mutated(source.bytes, index, (value) => { (value.emission as Obj).issuer_seq = seq; }), seed === "issuer" ? issuerRollback : epochRollback, "identity/coordinate-equivocation",
      `Fuzz split docs/fuzz-runs/${run}/${id} rebuilt: receipts[${index}].emission.issuer_seq = ${seq} repeats a sibling's issuer coordinate on the ${seed}-sequence-rollback seed and prior; the in-bundle collision (phase A) outranks the history rollback (D-86).`, 9)),
    negative("d86-history-issuer-coordinate", source.bytes, priorJson({ ...lowestIssuer, ...other, epochOwnerKid: deterministicId("prior:other-epoch-owner") }), "identity/coordinate-equivocation",
      "Q1: a prior entry names a carried receipt's issuer coordinate (its issuer's lowest issuer_seq) under a different receipt ID, in an unrelated epoch."),
    negative("d86-history-epoch-coordinate", source.bytes, priorJson({ ...lowestEpoch, ...other, issuerKid: deterministicId("prior:other-issuer"), issuerSeq: 0 }), "identity/coordinate-equivocation",
      "Q2: a prior entry names a carried receipt's epoch coordinate under a different receipt ID; an equal epoch_seq is equivocation, not rollback."),
    negative("d86-history-reuse-outranks-rollback", source.bytes, priorJson(epochAbove, { ...common, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "identity/reuse",
      "Phase B class order: receipts[0] is an epoch rollback against the first committed entry and an ID reuse against a later one; the reuse pass runs first."),
    negative("d86-phase-order-with-prior", phaseOrder, issuerRollback, "identity/coordinate-equivocation",
      "Phase order: receipts[1].binding.epoch_seq repeats receipts[0]'s epoch coordinate, and the prior is an issuer rollback; the in-bundle collision (phase A) outranks it.", 9),
    negative("d86-phase-order-without-prior", phaseOrder, undefined, "identity/coordinate-equivocation",
      "Phase order: the d86-phase-order-with-prior bundle evaluated without prior state reports the same code.", 9),
    positive("d86-history-exact-represent", priorJson(lowestEpoch),
      "Q3: the prior entry exactly re-presents one carried receipt; it is a duplicate observation, exempt from rollback against its own sequence."),
    positive("d86-history-full-reobservation", priorJson(...source.entries),
      "Every carried receipt exactly re-presented in prior state; the receipt-wide duplicate exemption keeps a lower sequence from reading as rollback against a later copy."),
    // D-86 review (E-06 C): the phase-B class order, the limits of the duplicate exemption, history-only conflicts, partial history.
    positive("d86-phase-b-issuer-outranks-epoch-rollback", priorJson(epochAbove, { ...common, ...ids("issuer-above"), issuerSeq: 9_999_999, epochOwnerKid: deterministicId("prior:other-epoch-owner") }),
      "receipts[0] is below the first committed entry's epoch_seq and the second's issuer_seq; both are the one observation sequence_below_observed_history, not a rollback class (D-87; was identity/issuer-sequence-rollback).", below),
    negative("d86-phase-b-equivocation-outranks-rollback", source.bytes, priorJson(epochAbove, { ...source.entries.at(-1)!, ...ids("issuer-coordinate"), epochOwnerKid: deterministicId("prior:other-epoch-owner") }), "identity/coordinate-equivocation",
      "Phase B class order: receipts[0] is an epoch rollback against the first committed entry, and the second names the last carried receipt's issuer coordinate under another receipt ID; the equivocation pass runs before both rollback passes."),
    negative("d86-duplicate-not-exempt-from-equivocation", source.bytes, priorJson(lowestEpoch, { ...lowestEpoch, ...other, issuerKid: new Uint8Array(32), issuerSeq: 0 }), "identity/coordinate-equivocation",
      "An exact copy of one carried receipt plus an entry naming that receipt's epoch coordinate under another receipt ID: the duplicate is exempt from rollback only, so the equivocation pass still fails it."),
    negative("d86-duplicate-not-exempt-from-reuse", source.bytes, priorJson(lowestEpoch, { ...lowestEpoch, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "identity/reuse",
      "An exact copy of one carried receipt plus an entry giving that receipt ID other envelope bytes: the duplicate is exempt from rollback only, so the reuse pass still fails it."),
    positive("d86-history-only-conflict", priorJson({ ...unrelated, ...ids("history-only-a") }, { ...unrelated, ...ids("history-only-b") }),
      "Two prior entries share one issuer coordinate and one epoch coordinate under different receipt IDs, and neither touches a carried receipt: entries that conflict only with each other do not fail the bundle.", []),
    positive("d86-partial-history-epoch-rollback", priorJson(highestEpoch),
      "Partial history: an exact copy of only the highest-epoch_seq carried receipt. That receipt is a duplicate observation; the bundle's other receipts in its epoch have lower epoch_seq, which is the observation sequence_below_observed_history (D-87: prior state is what the relying party observed; was identity/epoch-sequence-rollback).", ["duplicate_exact", ...below]),
    ...d87(source.bytes, negative, positive),
  ];
}

// D-87 rows. The retained bundle is a zero-receipt carrier of bundle-valid-subset's
// closed epoch 42 (manifest, events, anchor): its index lists every receipt the base carries.
function d87(base: Uint8Array, negative: (...args: [string, Uint8Array, StatefulPriorJson | undefined, string, string, number?]) => StatefulFixture,
  positive: (name: string, prior: StatefulPriorJson, description: string, observations?: string[], bundle?: Uint8Array, limits?: Record<string, string>) => StatefulFixture): StatefulFixture[] {
  const edit = (mutation: (bundle: Obj) => void): Uint8Array => { const bundle = decodeCbor(base, { strict: true }) as Obj; mutation(bundle); return encodeCbor(bundle); };
  const clearJournal = (bundle: Obj): void => { for (const field of ["epoch_events", "epoch_manifests", "anchors", "merkle_batches", "merkle_proofs"]) artifacts(bundle)[field] = []; bundle.ranges = []; };
  // A second root observation (human_request root, fresh nonce) at epoch_seq 777, issuer_seq 7777, in the given epoch.
  const extra = (bundle: Obj, epochId: number): void => {
    const envelope = receiptBy(bundle, (p) => p.kind === "observation" && object(p.root)); const next = clone(payload(envelope));
    next.root = { kind: "human_request", request_id: id16("d87:extra"), request_commitment: deterministicId("d87:extra") };
    Object.assign(next.binding as Obj, { epoch_id: epochId, epoch_seq: 777 }); (next.emission as Obj).issuer_seq = 7777; (next.freshness as Obj).nonce = id16("d87:extra");
    receiptList(bundle).push(resign(envelope, next, true)); sortArtifacts(bundle, "receipts");
  };
  const retained = { retained_epochs: [toHex(edit((bundle) => keepReceipts(bundle, () => false)))] };
  const listed = { retained_manifest_membership: "all_receipts_listed" }; const unlisted = { retained_manifest_membership: "not_established" };
  // graph-dangling-parent exactly as negative-fixtures builds it (graphFixture over bundle-valid-subset).
  const dangling = edit((bundle) => {
    clearJournal(bundle); keepReceipts(bundle, (value) => value.kind === "observation" && (object(value.root) || (value.parents as CborValue[]).length > 0));
    const childEnvelope = receiptBy(bundle, (value) => value.kind === "observation" && !object(value.root)); const child = clone(payload(childEnvelope));
    ((child.parents as Obj[])[0]!).parent_id = deterministicId("dangling-parent"); (child.freshness as Obj).intended_parents = [((child.parents as Obj[])[0]!).parent_id!]; replaceReceipt(bundle, childEnvelope, child);
  });
  return [
    negative("d87-receipt-unindexed-in-bundle", buildD82PositiveFixtures(false).find((fixture) => fixture.filename === "d82-chain-two-levels")!.bytes, undefined, "manifest/receipt-unindexed",
      "Rule 0: the pre-D-87 bytes of kats/positive/d82-chain-two-levels (the embedded delegation re-signed, so the authorization and its descendants carry new receipt IDs) while the carried epoch-42 manifest still indexes the old ones.", 15),
    positive("d87-retained-superset", retained, "The retained bundle carries epoch 42 with no receipts; the bundle carries every receipt that index lists, so each carried receipt is listed by a retained epoch.", [], base, listed),
    negative("d87-retained-forged-insertion", edit((bundle) => { clearJournal(bundle); extra(bundle, 42); }), retained, "manifest/receipt-unindexed",
      "The bundle drops its journal (so rule 0 has no carried manifest) and adds a root observation bound to epoch 42 that the retained index does not list: class (e) membership."),
    negative("d87-retained-competing-manifest", edit((bundle) => rebuildManifest(bundle, (m) => { m.predecessor_manifest_digest = deterministicId("d87:competing-predecessor"); }, true)), retained, "epoch/fork",
      "The bundle carries an internally valid epoch-42 manifest with another manifest_id (an uncarried predecessor named): class (d), manifest pass."),
    negative("d87-retained-conflicting-event", edit((bundle) => mutateLastEvent(bundle, (p) => { p.occurred_at = (p.occurred_at as number) - 1; })), retained, "epoch/fork",
      "Same manifest as the retained one, but the final anchor_submitted event differs (occurred_at one second earlier, event_id re-derived): class (d), event pass."),
    positive("d87-retained-unretained-epoch", retained, "Beside the epoch-42 receipts (all listed), a root observation bound to epoch 43, which no retained bundle carries: conformant, and the limit stays not_established.", [], edit((bundle) => extra(bundle, 43)), unlisted),
    positive("d87-retained-zero-receipts", retained, "A bundle with no receipts and no journal, with retained epochs supplied: the limit needs at least one carried receipt, so it stays not_established.", [], edit((bundle) => { clearJournal(bundle); keepReceipts(bundle, () => false); }), unlisted),
    negative("d87-history-independence-dangling-parent", dangling, priorJson({ ...exactEntries(dangling)[0]!, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "graph/dangling-parent",
      "Pin: the graph-dangling-parent bytes with a prior entry reusing a carried receipt ID (identity/reuse in history). The intrinsic defect is reported as without history (v0.3.1 reported identity/reuse at step 9).", 12),
  ];
}
