// Graph-level mutation primitives shared by the negative-fixture kit and the
// differential fuzz tool: the embedded-delegation mutator with its descendant
// receipt cascade. Extracted unchanged in behaviour (Packet D, Stage C).
import { CborValue, toHex } from "./cbor";
import { domainHash } from "./crypto";
import { Obj, clone, payload, receiptList, resign, sortArtifacts } from "./mutate";

export function receiptBy(bundle: Obj, predicate: (value: Obj) => boolean): CborValue {
  const entry = receiptList(bundle).find((candidate) => predicate(payload(candidate)));
  if (entry === undefined) throw new Error("receipt target missing");
  return entry;
}

export function replaceReceipt(bundle: Obj, original: CborValue, next: Obj): CborValue {
  const list = receiptList(bundle);
  const index = list.indexOf(original);
  if (index < 0) throw new Error("receipt replacement target missing");
  const replacement = resign(original, next, true);
  list[index] = replacement;
  sortArtifacts(bundle, "receipts");
  return replacement;
}

// `authorization` selects the enclosing receipt; the kit's default is the first permit authorization.
export function mutateEmbeddedDelegation(bundle: Obj, mutation: (value: Obj) => void, authorization: (value: Obj) => boolean = (value) => value.kind === "authorization" && ((value.body as Obj).decision as Obj).decision === "permit"): void {
  const authorizationEnvelope = receiptBy(bundle, authorization);
  const oldAuthorization = payload(authorizationEnvelope);
  const nextAuthorization = clone(oldAuthorization);
  const body = nextAuthorization.body as Obj;
  const delegationEnvelope = body.delegation!;
  const delegation = clone(payload(delegationEnvelope));
  mutation(delegation);
  delegation.delegation_id = domainHash("AAR-DELEGATION-ID-v1", Object.fromEntries(Object.entries(delegation).filter(([key]) => key !== "delegation_id")));
  body.delegation = resign(delegationEnvelope, delegation);
  const decision = body.decision as Obj;
  decision.delegation_id = delegation.delegation_id!;
  decision.decision_commitment = domainHash("AAR-DECISION-RECORD-v1", Object.fromEntries(Object.entries(decision).filter(([key]) => key !== "decision_commitment")));
  const replacement = replaceReceipt(bundle, authorizationEnvelope, nextAuthorization);

  const replacements = new Map([[toHex(oldAuthorization.receipt_id as Uint8Array), payload(replacement).receipt_id as Uint8Array]]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const envelope of [...receiptList(bundle)]) {
      const current = payload(envelope);
      const next = clone(current);
      let replace = false;
      for (const edge of next.parents as Obj[]) {
        const parentId = replacements.get(toHex(edge.parent_id as Uint8Array));
        if (parentId !== undefined) { edge.parent_id = parentId; replace = true; }
      }
      const nextBody = next.body as Obj;
      for (const field of ["authorization_id", "attempt_id", "subject_id"] as const) {
        if (!(nextBody[field] instanceof Uint8Array)) continue;
        const id = replacements.get(toHex(nextBody[field]));
        if (id !== undefined) { nextBody[field] = id; replace = true; }
      }
      if (!replace) continue;
      (next.freshness as Obj).intended_parents = (next.parents as Obj[]).map((edge) => edge.parent_id!);
      const nextEnvelope = replaceReceipt(bundle, envelope, next);
      replacements.set(toHex(current.receipt_id as Uint8Array), payload(nextEnvelope).receipt_id as Uint8Array);
      changed = true;
    }
  }
}
