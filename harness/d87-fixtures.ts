// The D-87 stateful rows, written with the D-86 rows by generate-negative.ts. The
// retained bundle is a zero-receipt carrier of bundle-valid-subset's closed epoch 42
// (manifest, events, anchor): its index lists every receipt the base carries. Kept out
// of stateful-fixtures.ts so the fuzz build (difffuzz-seeds) does not reach negative-fixtures.ts.
import { CborValue, decodeCbor, encodeCbor, toHex } from "./cbor";
import { deterministicId, domainHash, id16 } from "./crypto";
import { promotedRoot } from "./merkle";
import { artifacts, clone, keepReceipts, mutateLastEvent, payload, rebuildManifest, receiptList, resign, sortArtifacts } from "./mutate";
import { receiptBy, replaceReceipt } from "./mutate-graph";
import { buildD82PositiveFixtures } from "./negative-fixtures";
import { base as stateful, exactEntries, priorJson, StatefulFixture, StatefulPriorJson } from "./stateful-fixtures";

type Obj = Record<string, CborValue>;
const object = (value: CborValue | undefined): value is Obj => typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
// Descriptors in stateful-fixtures.ts key order.
const negative = (name: string, bundle: Uint8Array, prior: StatefulPriorJson | undefined, expected_code: string, mutation_description: string, expected_step = 20): StatefulFixture =>
  ({ name, bundle, ...(prior ? { prior } : {}), descriptor: { name, expected_code, expected_step, mutation_description } });
const positive = (name: string, prior: StatefulPriorJson | undefined, mutation_description: string, bundle: Uint8Array, limits: Record<string, string>): StatefulFixture =>
  ({ name, bundle, ...(prior ? { prior } : {}), descriptor: { name, expected_result: "conformant", expected_code: null, expected_observations: [], absent_observations: ["duplicate_exact"], expected_limits: limits, mutation_description } });

export function buildD87Fixtures(): StatefulFixture[] {
  const base = stateful().bytes;
  const edit = (mutation: (bundle: Obj) => void): Uint8Array => { const bundle = decodeCbor(base, { strict: true }) as Obj; mutation(bundle); return encodeCbor(bundle); };
  const clearJournal = (bundle: Obj): void => { for (const field of ["epoch_events", "epoch_manifests", "anchors", "merkle_batches", "merkle_proofs"]) artifacts(bundle)[field] = []; bundle.ranges = []; };
  // A second observation at epoch_seq 777, issuer_seq 7777, in the given epoch: a copy of the root observation
  // (human_request root, fresh nonce), or with root = false of the derived one, then change().
  const extra = (bundle: Obj, epochId: number, change: (next: Obj) => void = () => {}, root = true): void => {
    const envelope = receiptBy(bundle, (p) => p.kind === "observation" && object(p.root) === root); const next = clone(payload(envelope));
    if (root) next.root = { kind: "human_request", request_id: id16("d87:extra"), request_commitment: deterministicId("d87:extra") };
    Object.assign(next.binding as Obj, { epoch_id: epochId, epoch_seq: 777 }); (next.emission as Obj).issuer_seq = 7777; (next.freshness as Obj).nonce = id16("d87:extra");
    change(next); receiptList(bundle).push(resign(envelope, next, true)); sortArtifacts(bundle, "receipts");
  };
  // An extra derived observation whose parent nobody carries: graph/dangling-parent at step 12 on any base.
  const dangle = (bundle: Obj): void => extra(bundle, 42, (next) => { const edge = (next.parents as Obj[])[0]!; edge.parent_id = deterministicId("d87:dangling-parent"); (next.freshness as Obj).intended_parents = [edge.parent_id]; }, false);
  const competing = (bundle: Obj): void => rebuildManifest(bundle, (m) => { m.predecessor_manifest_digest = deterministicId("d87:competing-predecessor"); }, true);
  const retained = { retained_epochs: [toHex(edit((bundle) => keepReceipts(bundle, () => false)))] };
  const listed = { retained_manifest_membership: "all_receipts_listed" }; const unlisted = { retained_manifest_membership: "not_established" };
  // The retained carrier with its first index entry's issuer_seq raised, every commitment rebuilt.
  const misindexed = { retained_epochs: [toHex(edit((bundle) => { keepReceipts(bundle, () => false); rebuildManifest(bundle, (m) => {
    const index = m.receipt_index as Obj; const entries = (index.entries as Obj[]).map((entry, position) => position === 0 ? { ...entry, issuer_seq: (entry.issuer_seq as number) + 1 } : entry);
    m.receipt_index = { ...index, entries, root: promotedRoot(entries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry)), "AAR-MANIFEST-INDEX-NODE-v1") };
  }, true); }))] };
  // repair-d82-verifier-key-not-found exactly as negative-fixtures builds it.
  const keyless = edit((bundle) => { artifacts(bundle).credentials = (artifacts(bundle).credentials as CborValue[]).filter((entry) => payload(entry).key_usage !== "verifier_signing"); });
  // graph-dangling-parent exactly as negative-fixtures builds it (graphFixture over bundle-valid-subset).
  const dangling = edit((bundle) => {
    clearJournal(bundle); keepReceipts(bundle, (value) => value.kind === "observation" && (object(value.root) || (value.parents as CborValue[]).length > 0));
    const childEnvelope = receiptBy(bundle, (value) => value.kind === "observation" && !object(value.root)); const child = clone(payload(childEnvelope));
    ((child.parents as Obj[])[0]!).parent_id = deterministicId("dangling-parent"); (child.freshness as Obj).intended_parents = [((child.parents as Obj[])[0]!).parent_id!]; replaceReceipt(bundle, childEnvelope, child);
  });
  // A carried receipt's issuer coordinate under another ID, outside every retained epoch (no load-time index check).
  const equivocating = { ...exactEntries(dangling)[0]!, receiptId: deterministicId("d87:other-receipt"), envelopeDigest: deterministicId("d87:other-envelope"), epochOwnerKid: deterministicId("d87:other-owner") };
  return [
    negative("d87-receipt-unindexed-in-bundle", buildD82PositiveFixtures(false).find((fixture) => fixture.filename === "d82-chain-two-levels")!.bytes, undefined, "manifest/receipt-unindexed",
      "Rule 0: the pre-D-87 bytes of kats/positive/d82-chain-two-levels (the embedded delegation re-signed, so the authorization and its descendants carry new receipt IDs) while the carried epoch-42 manifest still indexes the old ones.", 15),
    positive("d87-retained-superset", retained, "The retained bundle carries epoch 42 with no receipts; the bundle carries every receipt that index lists, so each carried receipt is listed by a retained epoch.", base, listed),
    negative("d87-retained-forged-insertion", edit((bundle) => { clearJournal(bundle); extra(bundle, 42); }), retained, "manifest/receipt-unindexed",
      "The bundle drops its journal (so rule 0 has no carried manifest) and adds a root observation bound to epoch 42 that the retained index does not list: class (e) membership."),
    negative("d87-retained-competing-manifest", edit(competing), retained, "epoch/fork",
      "The bundle carries an internally valid epoch-42 manifest with another manifest_id (an uncarried predecessor named), so its close and anchor_submitted events (which carry manifest_id) differ from the retained ones too: class (d), first failing in the manifest pass; the two passes give one code, so their order is not observable."),
    negative("d87-retained-conflicting-event", edit((bundle) => mutateLastEvent(bundle, (p) => { p.occurred_at = (p.occurred_at as number) - 1; })), retained, "epoch/fork",
      "Same manifest as the retained one, but the final anchor_submitted event differs (occurred_at one second earlier, event_id re-derived): class (d), event pass."),
    positive("d87-retained-unretained-epoch", retained, "Beside the epoch-42 receipts (all listed), a root observation bound to epoch 43, which no retained bundle carries: conformant, and the limit stays not_established.", edit((bundle) => extra(bundle, 43)), unlisted),
    positive("d87-retained-zero-receipts", retained, "A bundle with no receipts and no journal, with retained epochs supplied: the limit needs at least one carried receipt, so it stays not_established.", edit((bundle) => { clearJournal(bundle); keepReceipts(bundle, () => false); }), unlisted),
    negative("d87-history-independence-dangling-parent", dangling, priorJson({ ...exactEntries(dangling)[0]!, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "graph/dangling-parent",
      "Pin: the graph-dangling-parent bytes with a prior entry reusing a carried receipt ID (identity/reuse in history). The intrinsic defect is reported as without history (v0.3.1 reported identity/reuse at step 9).", 12),
    // Fix round 1 pins (F-06 item 4).
    negative("d87-retained-index-mismatch", edit(clearJournal), misindexed, "manifest/index-receipt-mismatch",
      "The retained epoch-42 index lists every carried receipt, but its first entry's issuer_seq is one higher than the receipt's (index root, manifest, events and anchor rebuilt); the bundle carries no journal, so no fork: class (e), step-15 fields pass."),
    negative("d87-history-independence-equivocation-membership", dangling, { ...priorJson(equivocating), ...retained }, "graph/dangling-parent",
      "Pin: the graph-dangling-parent bytes with history that trips class (b) (an entry naming a carried receipt's issuer coordinate under another ID, outside any retained epoch) and class (e) (the re-identified child is not in the retained index): the intrinsic defect is reported as without history.", 12),
    negative("d87-history-independence-fork", edit((bundle) => { competing(bundle); dangle(bundle); }), retained, "graph/dangling-parent",
      "Pin: the d87-retained-competing-manifest bundle plus a derived observation whose parent nobody carries; the retained epoch would make it epoch/fork (class d) at step 20, the intrinsic defect is reported first.", 12),
    negative("d87-history-after-key-not-found", keyless, priorJson({ ...exactEntries(keyless)[0]!, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "key/not-found",
      "The repair-d82-verifier-key-not-found bytes (no verifier_signing credential) with a prior entry reusing a carried receipt ID: the step-20 key resolution runs before the history phase, so the result is indeterminate key/not-found as without history (v0.3.1: identity/reuse at step 9).", 20),
    positive("d87-late-for-epoch-not-selecting", undefined, "Rule 0: beside the epoch-42 receipts, a root observation bound to epoch 43 with late_for_epoch_id 42; no epoch-43 manifest is carried, and late_for_epoch_id never selects the epoch-42 manifest, so the receipt is not judged against its index: conformant.", edit((bundle) => extra(bundle, 43, (next) => { (next.binding as Obj).late_for_epoch_id = 42; })), unlisted),
  ];
}
