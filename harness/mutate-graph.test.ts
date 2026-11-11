// D-90 review: the cascades carry a recomputed decision_commitment only into attempts that
// cite the changed authorization and still carry its old value. A planted mismatch, and an
// attempt citing another authorization with the same old value, stay as they were.
import { expect, test } from "bun:test";
import { decodeCbor, toHex } from "./cbor";
import { deterministicId, domainHash } from "./crypto";
import { buildFixtures } from "./fixtures";
import { Obj, payload, receiptList, withoutField } from "./mutate";
import { mutateEmbeddedDelegation, rewriteD78Receipts } from "./mutate-graph";

const base = (): Obj => decodeCbor(buildFixtures().kats.find((item) => item.filename === "bundle-valid-subset")!.bytes, { strict: true }) as Obj;
const receipts = (bundle: Obj): Obj[] => receiptList(bundle).map(payload);
const decision = (receipt: Obj): Obj => (receipt.body as Obj).decision as Obj;
const permit = (bundle: Obj): Obj => receipts(bundle).find((r) => r.kind === "authorization" && decision(r).decision === "permit")!;
const attempt = (bundle: Obj, disposition: string): Obj => receipts(bundle).find((r) => r.kind === "action_attempt" && (r.body as Obj).disposition === disposition)!;
const commitment = (receipt: Obj): string => toHex((receipt.body as Obj).decision_commitment as Uint8Array);

test("commitment relink: consistent attempts follow, a planted mismatch stays", () => {
  const bundle = base();
  const planted = deterministicId("planted-commitment");
  rewriteD78Receipts(bundle, (r) => {
    if (r.kind === "authorization" && decision(r).decision === "permit") { decision(r).profile = "AAR-2A"; decision(r).evaluated_inputs = [...(decision(r).evaluated_inputs as Obj[])].reverse(); decision(r).decision_commitment = domainHash("AAR-DECISION-RECORD-v1", withoutField(decision(r), "decision_commitment")); }
    if (r.kind === "action_attempt" && (r.body as Obj).disposition === "eligible_for_dispatch") (r.body as Obj).decision_commitment = planted;
  });
  const fresh = toHex(decision(permit(bundle)).decision_commitment as Uint8Array);
  expect(commitment(attempt(bundle, "eligible_for_dispatch"))).toBe(toHex(planted));
  expect(commitment(attempt(bundle, "not_dispatched"))).toBe(fresh);
});

test("commitment relink: an attempt citing another authorization keeps its value", () => {
  const bundle = base();
  const old = toHex(decision(permit(bundle)).decision_commitment as Uint8Array);
  const approval = receipts(bundle).find((r) => r.kind === "authorization" && decision(r).decision === "permit_with_approval")!;
  rewriteD78Receipts(bundle, (r) => {
    if (r.kind !== "action_attempt" || (r.body as Obj).disposition !== "not_dispatched") return;
    (r.parents as Obj[]).find((edge) => edge.edge_type === "authorized_by")!.parent_id = approval.receipt_id!;
    (r.body as Obj).authorization_id = approval.receipt_id!; // still carries the permit's commitment
  });
  mutateEmbeddedDelegation(bundle, (d) => { d.not_after = (d.not_after as number) - 1; });
  expect(commitment(attempt(bundle, "not_dispatched"))).toBe(old);
  expect(commitment(attempt(bundle, "eligible_for_dispatch"))).toBe(toHex(decision(permit(bundle)).decision_commitment as Uint8Array));
  expect(commitment(attempt(bundle, "eligible_for_dispatch"))).not.toBe(old);
});
