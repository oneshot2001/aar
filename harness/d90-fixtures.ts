// The D-90 rows (a dispatch must descend from a permit through an eligible attempt
// that carries the decision's recomputed commitment; one_time delegations are consumed
// once per bundle, across the whole chain), written by generate-negative.ts. Kept out
// of negative-fixtures.ts, which the size ratchet pins. Rows start from
// bundle-valid-subset; receipt edits cascade through rewriteD78Receipts, which carries
// a recomputed decision_commitment into the attempts that cite it.
import { CborValue, decodeCbor, encodeCbor, toHex } from "./cbor";
import { deterministicId, domainHash, signDetached } from "./crypto";
import { buildFixtures } from "./fixtures";
import { artifacts, clone, compare, keepReceipts, Obj, payload, receiptList, resign, sortArtifacts, withoutField } from "./mutate";
import { mutateEmbeddedDelegation, receiptBy, reindexCarried, rewriteD78Receipts } from "./mutate-graph";
import { clearJournal, NegativeFixture, updateAttemptFlow } from "./negative-fixtures";

const base = (): Obj => decodeCbor(buildFixtures().kats.find((item) => item.filename === "bundle-valid-subset")!.bytes, { strict: true }) as Obj;
const body = (receipt: Obj): Obj => receipt.body as Obj;
const decisionOf = (receipt: Obj): Obj => body(receipt).decision as Obj;
const isPermit = (receipt: Obj): boolean => receipt.kind === "authorization" && decisionOf(receipt).decision === "permit";
const isEligible = (receipt: Obj): boolean => receipt.kind === "action_attempt" && body(receipt).disposition === "eligible_for_dispatch";
const isRefused = (receipt: Obj): boolean => receipt.kind === "action_attempt" && body(receipt).disposition === "not_dispatched";
const recommit = (decision: Obj): void => { decision.decision_commitment = domainHash("AAR-DECISION-RECORD-v1", withoutField(decision, "decision_commitment")); };

function edit(bundle: Obj, predicate: (receipt: Obj) => boolean, mutation: (receipt: Obj, originals: Obj[]) => void): void {
  rewriteD78Receipts(bundle, (receipt, originals) => { if (predicate(receipt)) mutation(receipt, originals); });
}
const deny = (bundle: Obj): void => edit(bundle, isPermit, (r) => { decisionOf(r).decision = "deny"; recommit(decisionOf(r)); });
const refuse = (receipt: Obj): void => { body(receipt).disposition = "not_dispatched"; body(receipt).refusal_reason = "held for a person"; };
const allow = (receipt: Obj): void => { body(receipt).disposition = "eligible_for_dispatch"; delete body(receipt).refusal_reason; };
const unsent = (bundle: Obj): ((receipt: Obj) => boolean) => {
  const sent = new Set(receiptList(bundle).map(payload).filter((r) => r.kind === "dispatch").map((r) => toHex(body(r).attempt_id as Uint8Array)));
  return (receipt) => receipt.kind === "action_attempt" && !sent.has(toHex(receipt.receipt_id as Uint8Array));
};

// A second dispatch of `attempt`, ordered after the first in artifact order. The
// journal is cleared: its index binds only the original receipts.
function addDispatch(bundle: Obj, attempt: (receipt: Obj) => boolean): void {
  const target = payload(receiptBy(bundle, attempt));
  const firstEnvelope = receiptBy(bundle, (r) => r.kind === "dispatch");
  const first = payload(firstEnvelope);
  for (let nonce = 0; nonce < 1024; nonce += 1) {
    const next = clone(first);
    (next.binding as Obj).epoch_seq = 10; (next.emission as Obj).issuer_seq = 110;
    (next.parents as Obj[]).find((edge) => edge.edge_type === "attempted_as")!.parent_id = target.receipt_id!;
    (next.freshness as Obj).intended_parents = (next.parents as Obj[]).map((edge) => edge.parent_id!);
    body(next).attempt_id = target.receipt_id!;
    body(next).command_id = (body(target).command as Obj).command_id!;
    body(next).adapter_invocation_id = deterministicId(`d90-dispatch:${nonce}`).subarray(0, 16);
    const candidate = resign(firstEnvelope, next, true);
    if (compare(payload(candidate).receipt_id as Uint8Array, first.receipt_id as Uint8Array) > 0) {
      receiptList(bundle).push(candidate); sortArtifacts(bundle, "receipts"); clearJournal(bundle); return;
    }
  }
  throw new Error("could not order the D-90 dispatch");
}

// The permit authorization's embedded delegation made one_time (invocation bound to the flow's).
function oneTime(bundle: Obj, extra: (delegation: Obj) => void = () => {}): void {
  const invocation = (payload(receiptBy(bundle, isEligible)).freshness as Obj).invocation_id!;
  mutateEmbeddedDelegation(bundle, (d) => { d.use = "one_time"; d.invocation_id = invocation; extra(d); });
}

// A carried one_time parent delegation P (from the permit's embedded delegation). The permit
// authorization embeds a one_time child of P; the approval authorization embeds `second(P, child)`;
// the refused attempt becomes eligible under the approval authorization and is dispatched.
function twoLeavesUnderOneParent(bundle: Obj, second: (parent: Obj, child: Obj) => Obj): void {
  const invocation = (payload(receiptBy(bundle, isEligible)).freshness as Obj).invocation_id!;
  const parent = clone(payload(body(payload(receiptBy(bundle, isPermit))).delegation!));
  Object.assign(parent, { use: "one_time", invocation_id: invocation, replay_domain: deterministicId("d90-one-time-parent"), parent_delegations: [] });
  parent.delegation_id = domainHash("AAR-DELEGATION-ID-v1", withoutField(parent, "delegation_id"));
  (artifacts(bundle).delegations as CborValue[]).push(signDetached(parent, "application/aar-delegation+cbor;v=0.2", "authority_signing").envelope);
  sortArtifacts(bundle, "delegations");
  let child: Obj = {};
  mutateEmbeddedDelegation(bundle, (d) => { Object.assign(d, { use: "one_time", invocation_id: invocation, parent_delegations: [parent.delegation_id!] }); child = clone(d); });
  const approval = (r: Obj): boolean => r.kind === "authorization" && decisionOf(r).decision === "permit_with_approval";
  mutateEmbeddedDelegation(bundle, (d) => { for (const key of Object.keys(d)) delete d[key]; Object.assign(d, second(parent, child)); }, approval);
  const approvalReceipt = payload(receiptBy(bundle, approval));
  edit(bundle, isRefused, (r) => {
    allow(r);
    (r.parents as Obj[]).find((edge) => edge.edge_type === "authorized_by")!.parent_id = approvalReceipt.receipt_id!;
    body(r).authorization_id = approvalReceipt.receipt_id!;
    body(r).decision_commitment = decisionOf(approvalReceipt).decision_commitment!;
  });
  addDispatch(bundle, unsent(bundle));
}

function aar3(bundle: Obj): void { bundle.claimed_profile = "AAR-3"; }
function journalUncommitted(bundle: Obj, lifeSafety: boolean): void {
  if (lifeSafety) (bundle.trust_inputs as Obj).life_safety_action_names = ["camera.stream.view"];
  updateAttemptFlow(bundle, (attempt, receipts) => {
    if (lifeSafety) { (body(attempt).action as Obj).hazard_class = "life_safety"; body(attempt).degraded = { reason: "journal/unavailable" }; }
    const dispatchedAt = body(receipts.find((r) => r.kind === "dispatch")!).dispatched_at as number;
    (attempt.binding as Obj).epoch_seq = ((receipts.find((r) => r.kind === "dispatch")!.binding as Obj).epoch_seq as number) + 1;
    (attempt.emission as Obj).committed_at = dispatchedAt + 1;
    ((attempt.evidence as Obj).time as Obj).wall_time = dispatchedAt + 1;
  });
  clearJournal(bundle);
}

export function buildD90Fixtures(): NegativeFixture[] {
  const row = (name: string, code: string, step: number, description: string, mutation: (bundle: Obj) => void): NegativeFixture => {
    const bundle = base(); mutation(bundle); reindexCarried(bundle); // the D-90 defect is the row's only one
    return { filename: name, bytes: encodeCbor(bundle), descriptor: { name, expected_code: code, mutation_description: description, expected_result: "nonconformant", expected_step: step } };
  };
  const missing = (name: string, description: string, mutation: (bundle: Obj) => void) => row(name, "graph/dominator-missing", 13, description, mutation);
  const commitment = (label: string, value: CborValue | undefined) => missing(`d90-attempt-commitment-${label}`,
    `The dispatched attempt's decision_commitment is ${label} (re-signed, cascaded); it must be the authorization's recomputed 32-byte commitment.`,
    (b) => edit(b, isEligible, (r) => { if (value === undefined) delete body(r).decision_commitment; else body(r).decision_commitment = value; }));
  const schema = (name: string, code: string, description: string, mutation: (bundle: Obj) => void) => row(name, code, 6, description, mutation);
  const decisionValue = (label: string, code: string, value: CborValue | undefined) => schema(`d90-decision-${label}`, code,
    `The permit authorization's decision.decision is ${label} (commitment recomputed); the decision enum is closed at step 6.`,
    (b) => edit(b, isPermit, (r) => { if (value === undefined) delete decisionOf(r).decision; else decisionOf(r).decision = value; recommit(decisionOf(r)); }));
  const dispositionValue = (label: string, code: string, value: CborValue | undefined) => schema(`d90-disposition-${label}`, code,
    `The dispatched attempt's disposition is ${label}; the disposition enum is closed at step 6.`,
    (b) => edit(b, isEligible, (r) => { if (value === undefined) delete body(r).disposition; else body(r).disposition = value; }));
  return [
    missing("d90-dispatch-refused-attempt", "The dispatched attempt is not_dispatched with a refusal_reason; a dispatch needs an eligible attempt.", (b) => edit(b, isEligible, refuse)),
    missing("d90-dispatch-under-deny", "The authorization the dispatched attempt cites says deny (commitment recomputed and carried into the attempts); a dispatch needs a permit.", deny),
    commitment("other", deterministicId("d90-other-commitment")),
    commitment("missing", undefined),
    commitment("null", null),
    commitment("int", 5),
    missing("d90-commitment-not-recomputed", "The permit decision lacks policy_set_root, so step 7 does not recompute its commitment; attempt and authorization still carry the same stale value.",
      (b) => edit(b, isPermit, (r) => { delete decisionOf(r).policy_set_root; })),
    missing("d90-undispatched-eligible-under-deny", "No dispatch or outcome is carried; the permit becomes deny and the attempt stays eligible_for_dispatch; an eligible attempt needs a permitting authorization even when nothing was sent.",
      (b) => { keepReceipts(b, (r) => r.kind !== "dispatch" && r.kind !== "outcome_observation"); clearJournal(b); deny(b); }),
    missing("d90-order-deny-before-scope", "The permit becomes deny and its delegation's targets no longer contain the action's target; the decision check precedes the delegation checks (was delegation/scope).",
      (b) => { mutateEmbeddedDelegation(b, (d) => { (d.scope as Obj).targets = [deterministicId("d90-other-target").subarray(0, 16)]; }); deny(b); }),
    missing("d90-life-safety-degraded-under-deny", "AAR-3 life-safety degraded dispatch (journal/unavailable) under a deny; the life-safety exception waives journal commitment, never permission.",
      (b) => { aar3(b); journalUncommitted(b, true); keepReceipts(b, (r) => !isRefused(r)); deny(b); }),
    row("d90-order-journal-before-later-refused-dispatch", "journal/uncommitted-dispatch", 13, "AAR-3: the first dispatch's attempt is committed after it; a later dispatch cites the refused attempt. Dispatches are judged one at a time in array order.",
      (b) => { aar3(b); journalUncommitted(b, false); addDispatch(b, isRefused); }),
    decisionValue("hold", "schema/enum-unknown", "hold"),
    decisionValue("missing", "schema/missing-field", undefined),
    decisionValue("null", "schema/bad-type", null),
    decisionValue("int", "schema/bad-type", 1),
    dispositionValue("held", "schema/enum-unknown", "held"),
    dispositionValue("missing", "schema/missing-field", undefined),
    dispositionValue("null", "schema/bad-type", null),
    schema("d90-order-action-name-before-disposition", "schema/enum-unknown", "The dispatched attempt's action_name is camera.export_clip and its disposition is absent; action names come before disposition in CDDL order.",
      (b) => edit(b, isEligible, (r) => { (body(r).action as Obj).action_name = "camera.export_clip"; delete body(r).disposition; })),
    row("d90-one-time-two-attempts", "delegation/scope", 13, "The embedded delegation is one_time; the refused attempt becomes eligible and a second dispatch sends it. A one_time delegation authorizes one dispatch.",
      (b) => { oneTime(b); edit(b, isRefused, allow); addDispatch(b, unsent(b)); }),
    row("d90-one-time-one-attempt-two-dispatches", "delegation/scope", 13, "The embedded delegation is one_time and the one eligible attempt is dispatched twice (distinct adapter invocations).",
      (b) => { oneTime(b); addDispatch(b, isEligible); }),
    row("d90-one-time-parent-two-children", "delegation/scope", 13, "A carried one_time parent has two one_time children embedded in two authorizations; each child authorizes one dispatch. Consumption covers the whole chain.",
      (b) => twoLeavesUnderOneParent(b, (_parent, child) => ({ ...clone(child), replay_domain: deterministicId("d90-second-child") }))),
    row("d90-one-time-parent-then-child", "delegation/scope", 13, "One authorization embeds a one_time child of a carried one_time parent; the other embeds the parent itself. The parent is consumed twice.",
      (b) => twoLeavesUnderOneParent(b, (parent) => clone(parent))),
  ];
}

export function buildD90PositiveFixtures() {
  const bundle = base();
  keepReceipts(bundle, (r) => r.kind !== "dispatch" && r.kind !== "outcome_observation");
  clearJournal(bundle);
  deny(bundle);
  edit(bundle, isEligible, refuse);
  reindexCarried(bundle);
  const filename = "d90-deny-refusal-no-dispatch";
  return [{ filename, bytes: encodeCbor(bundle), descriptor: { name: filename, object_type: "bundle" as const, expectation: "conformant" as const, expected_result: "conformant" as const, expected_code: null,
    mutation_description: "A deny authorization, both attempts not_dispatched with a refusal_reason, no dispatch: a recorded refusal under a deny stays conformant." } }];
}
