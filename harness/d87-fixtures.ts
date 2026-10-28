// The D-87 stateful rows, written with the D-86 rows by generate-negative.ts. The
// retained bundle is a zero-receipt carrier of bundle-valid-subset's closed epoch 42
// (manifest, events, anchor): its index lists every receipt the base carries. Kept out
// of stateful-fixtures.ts so the fuzz build (difffuzz-seeds) does not reach negative-fixtures.ts.
import { CborValue, decodeCbor, encodeCbor, toHex } from "./cbor";
import { deterministicId, id16 } from "./crypto";
import { artifacts, clone, keepReceipts, mutateLastEvent, payload, rebuildManifest, receiptList, resign, sortArtifacts } from "./mutate";
import { receiptBy, replaceReceipt } from "./mutate-graph";
import { buildD82PositiveFixtures } from "./negative-fixtures";
import { base as stateful, exactEntries, priorJson, StatefulFixture, StatefulPriorJson } from "./stateful-fixtures";

type Obj = Record<string, CborValue>;
const object = (value: CborValue | undefined): value is Obj => typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
// Descriptors in stateful-fixtures.ts key order.
const negative = (name: string, bundle: Uint8Array, prior: StatefulPriorJson | undefined, expected_code: string, mutation_description: string, expected_step = 20): StatefulFixture =>
  ({ name, bundle, ...(prior ? { prior } : {}), descriptor: { name, expected_code, expected_step, mutation_description } });
const positive = (name: string, prior: StatefulPriorJson, mutation_description: string, bundle: Uint8Array, limits: Record<string, string>): StatefulFixture =>
  ({ name, bundle, prior, descriptor: { name, expected_result: "conformant", expected_code: null, expected_observations: [], absent_observations: ["duplicate_exact"], expected_limits: limits, mutation_description } });

export function buildD87Fixtures(): StatefulFixture[] {
  const base = stateful().bytes;
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
    positive("d87-retained-superset", retained, "The retained bundle carries epoch 42 with no receipts; the bundle carries every receipt that index lists, so each carried receipt is listed by a retained epoch.", base, listed),
    negative("d87-retained-forged-insertion", edit((bundle) => { clearJournal(bundle); extra(bundle, 42); }), retained, "manifest/receipt-unindexed",
      "The bundle drops its journal (so rule 0 has no carried manifest) and adds a root observation bound to epoch 42 that the retained index does not list: class (e) membership."),
    negative("d87-retained-competing-manifest", edit((bundle) => rebuildManifest(bundle, (m) => { m.predecessor_manifest_digest = deterministicId("d87:competing-predecessor"); }, true)), retained, "epoch/fork",
      "The bundle carries an internally valid epoch-42 manifest with another manifest_id (an uncarried predecessor named): class (d), manifest pass."),
    negative("d87-retained-conflicting-event", edit((bundle) => mutateLastEvent(bundle, (p) => { p.occurred_at = (p.occurred_at as number) - 1; })), retained, "epoch/fork",
      "Same manifest as the retained one, but the final anchor_submitted event differs (occurred_at one second earlier, event_id re-derived): class (d), event pass."),
    positive("d87-retained-unretained-epoch", retained, "Beside the epoch-42 receipts (all listed), a root observation bound to epoch 43, which no retained bundle carries: conformant, and the limit stays not_established.", edit((bundle) => extra(bundle, 43)), unlisted),
    positive("d87-retained-zero-receipts", retained, "A bundle with no receipts and no journal, with retained epochs supplied: the limit needs at least one carried receipt, so it stays not_established.", edit((bundle) => { clearJournal(bundle); keepReceipts(bundle, () => false); }), unlisted),
    negative("d87-history-independence-dangling-parent", dangling, priorJson({ ...exactEntries(dangling)[0]!, envelopeDigest: deterministicId("prior:nonidentical-envelope") }), "graph/dangling-parent",
      "Pin: the graph-dangling-parent bytes with a prior entry reusing a carried receipt ID (identity/reuse in history). The intrinsic defect is reported as without history (v0.3.1 reported identity/reuse at step 9).", 12),
  ];
}
