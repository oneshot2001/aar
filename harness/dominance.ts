// CONFORMANCE step 13, authorization dominance: per dispatch, the single
// attempt and its permitting authorization (D-90), the embedded delegation
// (D-53, D-79, D-82 part 9 chain), one-time consumption (D-90), then D-66;
// then every undispatched eligible attempt (D-90). Moved out of verifier.ts.
// pyref/dominance.py mirrors this module.
import { equalBytes, toHex } from "./cbor";
import { domainHash } from "./crypto";
import { B1Failure, bytes, failure, Obj, object, observe, Parsed, ParsedEnvelope, receiptsById, same } from "./verifier";
import type { CborValue } from "./cbor";

function subset(child: CborValue | undefined, parent: CborValue | undefined): boolean {
  return Array.isArray(child) && Array.isArray(parent) && child.every((value) => parent.some((candidate) => same(candidate, value)));
}

// D-82 part 9: parent_delegations, transitively, array order, depth first.
// Every link resolves to a carried top-level delegation, contains the child's
// window and its four scope lists, shares tenant and site, does not widen use
// or invocation_id, and is not already on the path (a cycle is a traversal
// bound: content IDs make one cryptographically unreachable).
// One chain link: window, four scope subsets, tenant/site, use and invocation not widened.
function linkValid(parent: Obj, child: Obj): boolean {
  if ((parent.not_before as number) > (child.not_before as number) || (parent.not_after as number) < (child.not_after as number)) return false;
  const parentScope = parent.scope; const childScope = child.scope;
  if (!object(parentScope) || !object(childScope)) return false;
  if (["actions", "targets", "purpose_ids", "allowed_profiles"].some((name) => !subset(childScope[name], parentScope[name]))) return false;
  if (!same(parent.tenant_id, child.tenant_id) || !same(parent.site_id, child.site_id)) return false;
  if (parent.use === "one_time" && child.use !== "one_time") return false;
  return parent.invocation_id === undefined || same(parent.invocation_id, child.invocation_id);
}

// D-82 part 9 (amendment e): parent_delegations, transitively, array order,
// depth first, iterative. Each carried delegation's chain is evaluated at most
// once per verification (memo: true = valid, null = in progress); a delegation
// re-entered while in progress is a cycle. Every failure is one code.
function chainValid(known: Map<string, ParsedEnvelope>, child: Obj, memo: Map<string, boolean | null>): boolean {
  const stack: { node: Obj; index: number }[] = [{ node: child, index: 0 }];
  memo.set(toHex(child.delegation_id as Uint8Array), null);
  while (stack.length > 0) {
    const frame = stack[stack.length - 1]!;
    const parents = frame.node.parent_delegations;
    if (!Array.isArray(parents)) return false;
    if (frame.index >= parents.length) { memo.set(toHex(frame.node.delegation_id as Uint8Array), true); stack.pop(); continue; }
    const parentId = parents[frame.index]!;
    frame.index += 1;
    const parent = bytes(parentId, 32) ? known.get(toHex(parentId))?.payload : undefined;
    if (parent === undefined || !linkValid(parent, frame.node)) return false;
    const key = toHex(parentId as Uint8Array);
    if (memo.has(key)) {
      if (memo.get(key) === null) return false; // cycle
      continue; // already evaluated: a validated chain is path-independent
    }
    memo.set(key, null);
    stack.push({ node: parent, index: 0 });
  }
  return true;
}

// D-90: the attempt's single authorization, bound by id and by the recomputed
// decision commitment (a 32-byte digest on both sides); the attempt is eligible
// and the decision permits. Every failure but ambiguity is graph/dominator-missing.
function permittingAuthorization(attempt: ParsedEnvelope, byId: Map<string, ParsedEnvelope>): ParsedEnvelope | B1Failure {
  const edges = (attempt.payload.parents as Obj[]).filter((edge) => edge.edge_type === "authorized_by");
  if (edges.length === 0) return failure(13, "graph/dominator-missing", "attempt.parents");
  if (edges.length > 1) return failure(13, "graph/dominator-ambiguous", "attempt.parents");
  const authorization = byId.get(toHex(edges[0]!.parent_id as Uint8Array));
  const body = attempt.payload.body as Obj;
  if (authorization?.payload.kind !== "authorization" || !same(body.authorization_id, authorization.payload.receipt_id)) return failure(13, "graph/dominator-missing", "attempt.body.authorization_id");
  const decision = (authorization.payload.body as Obj).decision as Obj;
  const commitment = body.decision_commitment;
  const record = Object.fromEntries(Object.entries(decision).filter(([key]) => key !== "decision_commitment"));
  if (!bytes(commitment, 32) || !same(commitment, decision.decision_commitment) || !equalBytes(commitment, domainHash("AAR-DECISION-RECORD-v1", record))
    || body.disposition !== "eligible_for_dispatch" || (decision.decision !== "permit" && decision.decision !== "permit_with_approval")) return failure(13, "graph/dominator-missing", "attempt.body.decision_commitment");
  return authorization;
}

// D-90: the embedded delegation and every carried delegation on its validated chain, once each.
function chainOf(known: Map<string, ParsedEnvelope>, leaf: Obj): Obj[] {
  const seen = new Map<string, Obj>();
  const stack = [leaf];
  while (stack.length > 0) {
    const node = stack.pop()!;
    const key = toHex(node.delegation_id as Uint8Array);
    if (seen.has(key)) continue;
    seen.set(key, node);
    for (const id of node.parent_delegations as Uint8Array[]) stack.push(known.get(toHex(id))!.payload);
  }
  return [...seen.values()];
}

export function validateDominance(bundle: Obj, parsed: Parsed, observations: string[]): B1Failure | undefined {
  const byId = receiptsById(parsed);
  const parentDelegations = new Map<string, ParsedEnvelope>();
  for (const entry of parsed.delegation) { const id = toHex(entry.payload.delegation_id as Uint8Array); if (!parentDelegations.has(id)) parentDelegations.set(id, entry); }
  const chainMemo = new Map<string, boolean | null>();
  const embeddedDelegations = new Map(parsed.embeddedDelegations.map((entry) => [toHex(entry.authorization.payload.receipt_id as Uint8Array), entry.delegation]));
  const dispatchedAttemptIds = new Set<string>();
  const oneTimeUses = new Set<string>();
  for (const dispatch of parsed.receipt.filter((entry) => entry.payload.kind === "dispatch")) {
    const attemptEdges = (dispatch.payload.parents as Obj[]).filter((edge) => edge.edge_type === "attempted_as");
    const attempt = attemptEdges.length === 1 ? byId.get(toHex(attemptEdges[0]!.parent_id as Uint8Array)) : undefined;
    if (attempt === undefined || attempt.payload.kind !== "action_attempt") return failure(13, "graph/dominator-missing", "dispatch.parents");
    dispatchedAttemptIds.add(toHex(attempt.payload.receipt_id as Uint8Array));
    const resolved = permittingAuthorization(attempt, byId);
    if ("ok" in resolved) return resolved;
    const authorization = resolved;
    const attemptBody = attempt.payload.body as Obj;
    const decision = (authorization.payload.body as Obj).decision as Obj;
    const delegation = embeddedDelegations.get(toHex(authorization.payload.receipt_id as Uint8Array));
    if (delegation === undefined || !same(decision.delegation_id, delegation.payload.delegation_id)) return failure(13, "graph/dominator-missing", "authorization.body.decision.delegation_id");
    // D-79: the delegation names the enforcement point that signed the attempt.
    const subject = parsed.credential.find((credential) => same(credential.payload.credential_id, delegation.payload.subject_credential_id));
    if (subject === undefined || !same(subject.payload.subject_kid, attempt.kid)) return failure(13, "delegation/scope", "authorization.body.delegation.subject_credential_id");
    const scope: Obj = object(delegation.payload.scope) ? delegation.payload.scope : {}; // amendment (l): a non-map scope contains nothing
    const action = attemptBody.action as Obj;
    const legal = attempt.payload.legal; // amendment (o): an absent or wrongly typed value is simply not contained
    const purpose = object(legal) && typeof legal.purpose_id === "string" ? legal.purpose_id : undefined; // amendment (ag): text and contained
    const profile = typeof decision.profile === "string" ? decision.profile : undefined;
    if (!Array.isArray(scope.actions) || !scope.actions.some((value) => same(value, action.action_name)) || !Array.isArray(scope.targets) || !scope.targets.some((value) => same(value, action.target_id)) || !Array.isArray(scope.purpose_ids) || !scope.purpose_ids.some((value) => same(value, purpose)) || !Array.isArray(scope.allowed_profiles) || !scope.allowed_profiles.some((value) => same(value, profile)) || !same(delegation.payload.tenant_id, (attempt.payload.binding as Obj).tenant_id) || !same(delegation.payload.site_id, (attempt.payload.binding as Obj).site_id) || (delegation.payload.invocation_id !== undefined && !same(delegation.payload.invocation_id, (attempt.payload.freshness as Obj).invocation_id)) || (delegation.payload.use === "one_time" && delegation.payload.invocation_id === undefined)) return failure(13, "delegation/scope", "authorization.body.delegation.scope");
    const committed = (attempt.payload.emission as Obj).committed_at as number;
    if (committed < (delegation.payload.not_before as number)) return failure(13, "delegation/not-yet-valid", "authorization.body.delegation.not_before");
    if (committed >= (delegation.payload.not_after as number)) return failure(13, "delegation/expired", "authorization.body.delegation.not_after");
    if (!chainValid(parentDelegations, delegation.payload, chainMemo)) return failure(13, "delegation/chain-invalid", "authorization.body.delegation.parent_delegations");
    // D-90: a dispatch consumes every one_time delegation on its chain; a second dispatch may not.
    const oneTime = chainOf(parentDelegations, delegation.payload).filter((link) => link.use === "one_time").map((link) => toHex(link.delegation_id as Uint8Array));
    if (oneTime.some((key) => oneTimeUses.has(key))) return failure(13, "delegation/scope", "authorization.body.delegation.use");
    for (const key of oneTime) oneTimeUses.add(key);
    if (bundle.claimed_profile === "AAR-3") {
      const attemptBinding = attempt.payload.binding as Obj;
      const dispatchBinding = dispatch.payload.binding as Obj;
      const attemptEmission = attempt.payload.emission as Obj;
      const dispatchBody = dispatch.payload.body as Obj;
      const committedBeforeDispatch = same(attemptBinding.epoch_owner_kid, dispatchBinding.epoch_owner_kid)
        && attemptBinding.epoch_id === dispatchBinding.epoch_id
        && (attemptBinding.epoch_seq as number) < (dispatchBinding.epoch_seq as number)
        && (attemptEmission.committed_at as number) <= (dispatchBody.dispatched_at as number);
      const degraded = attemptBody.degraded;
      const action = attemptBody.action as Obj;
      const lifeSafetyException = action.hazard_class === "life_safety"
        && object(degraded) && degraded.reason === "journal/unavailable";
      if (!committedBeforeDispatch && !lifeSafetyException) {
        return failure(13, "journal/uncommitted-dispatch", "dispatch.parents.attempted_as");
      }
      if (!committedBeforeDispatch) observe(observations, "degraded_dispatch");
    }
  }
  // D-90: an eligible attempt no dispatch names still needs its permitting authorization.
  for (const attempt of parsed.receipt) {
    if (attempt.payload.kind !== "action_attempt" || (attempt.payload.body as Obj).disposition !== "eligible_for_dispatch" || dispatchedAttemptIds.has(toHex(attempt.payload.receipt_id as Uint8Array))) continue;
    const resolved = permittingAuthorization(attempt, byId);
    if ("ok" in resolved) return resolved;
  }
  if (bundle.claimed_profile === "AAR-3") for (const attempt of parsed.receipt.filter((entry) => entry.payload.kind === "action_attempt")) {
    const body = attempt.payload.body as Obj;
    if (body.disposition === "not_dispatched" && body.refusal_reason === "journal/unavailable"
      && !dispatchedAttemptIds.has(toHex(attempt.payload.receipt_id as Uint8Array))) {
      observe(observations, "refused_pre_dispatch");
    }
  }
  return undefined;
}
