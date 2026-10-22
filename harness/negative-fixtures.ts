import { CborScalar, CborValue, decodeCbor, encodeCbor, equalBytes, toHex } from "./cbor";
import { deterministicId, domainHash, hash, id16, P256_HALF_ORDER, P256_ORDER, signDetached } from "./crypto";
import { buildFixtures } from "./fixtures";
import { buildCountersignFixtures } from "./countersign-fixtures";
import { promotedProofWithDomain, promotedRoot, rfc6962Leaf } from "./merkle";
import { TEST_KEYS, TestKeyName } from "./testkeys";
import { object, clone, same, artifacts, payload, cose, protectedMap, signerFor, contentType, resign, mutateArtifact, mutateReceipt, mutateReceiptWhere, sortArtifacts, compare, recalcSelector, recalcTrust, modifyCose, receiptList, keepReceipts, withoutField, rebuildEventChain, rfcRootFromProof, rebuildManifest, addSecondEpoch, flipSignature, relinkEventChain, mutateLastEvent, mutateMerkleBatch, addManifestWithAnchor, crossEpochChild, addTopLevelDelegation } from "./mutate";

type Obj = Record<string, CborValue>;

export interface NegativeDescriptor {
  name: string;
  expected_code: string;
  expected_result?: "nonconformant" | "indeterminate";
  expected_step?: number;
  mutation_description: string;
}

export interface NegativeFixture {
  filename: string;
  bytes: Uint8Array;
  descriptor: NegativeDescriptor;
}

export interface ClassBoundaryFixture {
  filename: string;
  bytes: Uint8Array;
  descriptor: {
    name: string;
    boundary: string;
    expectation: "reject" | "conformant";
    expected_code?: string;
    expected_class?: string;
  };
}

export interface TerminalOutcomeFixture {
  filename: string;
  bytes: Uint8Array;
  descriptor: {
    name: string;
    object_type: "bundle";
    terminal_order: string;
    expectation: "conformant";
    expected_class: "contradicted" | "unknown";
  };
}

export interface EvidenceCommitFixture {
  filename: string;
  bytes: Uint8Array;
  descriptor: {
    name: string;
    object_type: "bundle";
    expectation: "conformant" | "nonconformant";
    expected_code?: "journal/uncommitted-dispatch" | "receipt/hazard-class-unbound";
    expected_observations: string[];
  };
}

function baseBundle(): Obj {
  const kat = buildFixtures().kats.find((item) => item.filename === "bundle-valid-subset");
  if (kat === undefined) throw new Error("positive bundle fixture missing");
  const value = decodeCbor(kat.bytes, { strict: true });
  if (!object(value)) throw new Error("positive bundle is not a map");
  return value;
}

/**
 * Re-sign the agent request with mutated claims, then repair every agent_request root
 * commitment that names it so `request/commitment-mismatch` cannot mask the result.
 * Re-identifying those receipts orphans their children, but step 7 fires before the
 * step-12 graph checks, so the coordinate rejection is what a verifier reports.
 */
function divergeRequest(bundle: Obj, mutation: (claims: Obj) => void): void {
  const requests = artifacts(bundle).requests as CborValue[];
  if (requests.length === 0) throw new Error("no request envelope to diverge");
  const original = payload(requests[0]!);
  const requestId = original.request_id as Uint8Array;
  const next = clone(original);
  mutation(next);
  requests[0] = resign(requests[0]!, next);
  sortArtifacts(bundle, "requests");
  const commitment = hash((requests[0] as CborValue[])[0] as Uint8Array);
  const receipts = artifacts(bundle).receipts as CborValue[];
  for (let index = 0; index < receipts.length; index += 1) {
    const value = payload(receipts[index]!);
    if (!object(value.root) || value.root.kind !== "agent_request") continue;
    if (!equalBytes(value.root.request_id as Uint8Array, requestId)) continue;
    const nextReceipt = clone(value);
    (nextReceipt.root as Obj).request_commitment = commitment;
    receipts[index] = resign(receipts[index]!, nextReceipt, true);
  }
  sortArtifacts(bundle, "receipts");
}

/**
 * Every request coordinate that duplicates a receipt-binding value, one bundle per
 * field (D-60). The corpus carries only the target_ep_kid case because filenames derive
 * from the reason code and it holds one fixture per code; these give per-field coverage.
 */
export function buildRequestCoordinateVariants(): { label: string; bytes: Uint8Array }[] {
  const variants: { label: string; mutate: (claims: Obj) => void }[] = [
    { label: "tenant_id", mutate: (claims) => { claims.tenant_id = id16("other-tenant"); } },
    { label: "site_id", mutate: (claims) => { claims.site_id = id16("other-site"); } },
    { label: "target_ep_kid", mutate: (claims) => { claims.target_ep_kid = TEST_KEYS.verifier_signing.kid; (claims.correlation as Obj).target_ep_kid = TEST_KEYS.verifier_signing.kid; } },
    { label: "correlation.target_ep_kid", mutate: (claims) => { (claims.correlation as Obj).target_ep_kid = TEST_KEYS.verifier_signing.kid; } },
    // Malformed coordinates: treated as disagreement, never a crash — the
    // adversarial-review classes (pyref TypeError/KeyError) that corpus parity
    // could not see because no fixture carried them.
    { label: "correlation non-map", mutate: (claims) => { claims.correlation = 5; } },
    { label: "correlation missing target_ep_kid", mutate: (claims) => { delete (claims.correlation as Obj).target_ep_kid; } },
    { label: "tenant_id wrong length", mutate: (claims) => { claims.tenant_id = new Uint8Array(15); } },
  ];
  return variants.map(({ label, mutate }) => {
    const bundle = clone(baseBundle());
    divergeRequest(bundle, mutate);
    return { label, bytes: encodeCbor(bundle) };
  });
}

/**
 * Malformed-type variants for the crash-hardening pass: input classes the
 * corpus does not carry (non-map containers, array-typed identifiers, non-bstr
 * hash preimages) that previously crashed one implementation or the other.
 * Each must yield a SIGNED verdict with the same reason code at the same step
 * in both implementations — never an unhandled exception. Step-6 schema
 * variants swap the payload bytes without re-signing (schema is checked before
 * signature verification); post-signature variants re-sign.
 */
export function buildMalformedTypeVariants(): { label: string; bytes: Uint8Array; code: string; step: number }[] {
  const swapPayload = (bundle: Obj, category: string, mutate: (value: Obj) => void): void => {
    const list = artifacts(bundle)[category] as CborValue[];
    const next = clone(payload(list[0]!));
    mutate(next);
    (list[0] as CborValue[])[0] = encodeCbor(next);
  };
  const variants: { label: string; code: string; step: number; build: (bundle: Obj) => void }[] = [
    // The proven P1: pyref crashed with AttributeError before signature
    // verification on a non-map receipt binding.
    { label: "receipt binding non-map", code: "schema/bad-type", step: 6, build: (bundle) => swapPayload(bundle, "receipts", (value) => { value.binding = 5; }) },
    { label: "request_id array", code: "schema/bad-type", step: 6, build: (bundle) => swapPayload(bundle, "requests", (value) => { value.request_id = [...(value.request_id as Uint8Array)]; }) },
    { label: "receipt committed_at non-uint", code: "schema/bad-type", step: 6, build: (bundle) => swapPayload(bundle, "receipts", (value) => { (value.emission as Obj).committed_at = "soon"; }) },
    // D-82 part 8: the receipt sub-map members are presence-then-type at step 6.
    { label: "receipt committed_at missing", code: "schema/missing-field", step: 6, build: (bundle) => swapPayload(bundle, "receipts", (value) => { delete (value.emission as Obj).committed_at; }) },
    { label: "credential subject_kid array", code: "schema/bad-type", step: 6, build: (bundle) => swapPayload(bundle, "credentials", (value) => { value.subject_kid = [...(value.subject_kid as Uint8Array)]; }) },
    // Post-signature classes: re-signed so the guarded step is actually reached.
    { label: "canonical_command non-bstr", code: "schema/bad-type", step: 7, build: (bundle) => mutateReceipt(bundle, "action_attempt", (value) => { ((value.body as Obj).command as Obj).canonical_command = "not-bytes"; }) },
    { label: "binding epoch_owner_kid array", code: "schema/bad-type", step: 6, build: (bundle) => mutateReceiptWhere(bundle, (value) => !object(value.root), (value) => { const binding = value.binding as Obj; binding.epoch_owner_kid = [...(binding.epoch_owner_kid as Uint8Array)]; }) },
    { label: "freshness issued_at non-uint", code: "schema/bad-type", step: 6, build: (bundle) => mutateReceiptWhere(bundle, (value) => !object(value.root), (value) => { (value.freshness as Obj).issued_at = "soon"; }) },
    // Both impls must skip a non-map parent edge at the step-10 dispatch clause
    // and converge on the step-11 parents guard (gate-proven divergence class).
    { label: "dispatch parent edge non-map", code: "schema/bad-type", step: 6, build: (bundle) => mutateReceipt(bundle, "dispatch", (value) => { const parents = value.parents as CborValue[]; const index = parents.findIndex((parent) => object(parent) && parent.edge_type === "attempted_as"); if (index < 0) throw new Error("attempted_as edge missing"); parents[index] = 5; }) },
    // A parent edge omitting a CDDL-required field converges on the same
    // step-11 guard (round-2 gate class: pyref died KeyError at step 12).
    { label: "parent edge missing edge_type", code: "schema/bad-type", step: 11, build: (bundle) => mutateReceipt(bundle, "dispatch", (value) => { const parents = value.parents as CborValue[]; const index = parents.findIndex((parent) => object(parent) && parent.edge_type === "attempted_as"); if (index < 0) throw new Error("attempted_as edge missing"); delete (parents[index] as Obj).edge_type; }) },
  ];
  return variants.map(({ label, code, step, build }) => {
    const bundle = clone(baseBundle());
    build(bundle);
    return { label, code, step, bytes: encodeCbor(bundle) };
  });
}

function fixture(code: string, description: string, value: Uint8Array | Obj): NegativeFixture {
  const filename = code.replaceAll("/", "-");
  return { filename, bytes: value instanceof Uint8Array ? value : encodeCbor(value), descriptor: { name: filename, expected_code: code, mutation_description: description } };
}

function bundleFixture(code: string, description: string, mutation: (bundle: Obj) => void): NegativeFixture {
  const bundle = clone(baseBundle());
  mutation(bundle);
  return fixture(code, description, bundle);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function bigint32(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let cursor = value;
  for (let i = 31; i >= 0; i -= 1) { out[i] = Number(cursor & 0xffn); cursor >>= 8n; }
  return out;
}

function clearJournal(bundle: Obj): void {
  const value = artifacts(bundle);
  value.epoch_events = [];
  value.epoch_manifests = [];
  value.anchors = [];
  value.merkle_batches = [];
  value.merkle_proofs = [];
  bundle.ranges = [];
}

function addOpaquePayload(bundle: Obj, label: string): Uint8Array {
  const canonicalBytes = encodeCbor({ artifact: label, format_version: 1 });
  const digest = hash(canonicalBytes);
  (artifacts(bundle).manifest_payloads as Obj[]).push({
    digest,
    media_type: "application/aar-evidence-artifact+cbor",
    canonical_bytes: canonicalBytes,
  });
  sortArtifacts(bundle, "manifest_payloads");
  return digest;
}

function receiptBy(bundle: Obj, predicate: (value: Obj) => boolean): CborValue {
  const entry = receiptList(bundle).find((candidate) => predicate(payload(candidate)));
  if (entry === undefined) throw new Error("receipt target missing");
  return entry;
}

function replaceReceipt(bundle: Obj, original: CborValue, next: Obj): CborValue {
  const list = receiptList(bundle);
  const index = list.indexOf(original);
  if (index < 0) throw new Error("receipt replacement target missing");
  const replacement = resign(original, next, true);
  list[index] = replacement;
  sortArtifacts(bundle, "receipts");
  return replacement;
}

function updateAttemptFlow(bundle: Obj, mutation: (attempt: Obj, receipts: Obj[]) => void): void {
  const attemptEnvelope = receiptBy(bundle, (value) => value.kind === "action_attempt" && (value.body as Obj).disposition === "eligible_for_dispatch");
  const oldAttempt = payload(attemptEnvelope);
  const nextAttempt = clone(oldAttempt);
  mutation(nextAttempt, receiptList(bundle).map(payload));
  (nextAttempt.freshness as Obj).intended_parents = (nextAttempt.parents as Obj[]).map((edge) => edge.parent_id!);
  const newAttemptEnvelope = replaceReceipt(bundle, attemptEnvelope, nextAttempt);
  const newAttempt = payload(newAttemptEnvelope);

  const dispatchEnvelope = receiptBy(bundle, (value) => value.kind === "dispatch");
  const nextDispatch = clone(payload(dispatchEnvelope));
  const attemptedAs = (nextDispatch.parents as Obj[]).find((edge) => edge.edge_type === "attempted_as")!;
  attemptedAs.parent_id = newAttempt.receipt_id!;
  (nextDispatch.body as Obj).attempt_id = newAttempt.receipt_id!;
  (nextDispatch.freshness as Obj).intended_parents = (nextDispatch.parents as Obj[]).map((edge) => edge.parent_id!);
  replaceReceipt(bundle, dispatchEnvelope, nextDispatch);
  keepReceipts(bundle, (value) => value.kind !== "outcome_observation");
}

function addLaterDominatorDefect(bundle: Obj): void {
  const refusedEnvelope = receiptBy(bundle, (value) => value.kind === "action_attempt"
    && (value.body as Obj).disposition === "not_dispatched");
  const nextAttempt = clone(payload(refusedEnvelope));
  const body = nextAttempt.body as Obj;
  const action = body.action as Obj;
  const command = body.command as Obj;
  action.action_name = "camera.ptz.preset";
  command.action_name = "camera.ptz.preset";
  command.canonical_command = encodeCbor({
    operation: action.action_name!, target: action.target_id!, parameters_digest: action.parameters_digest!,
  });
  command.command_digest = hash(command.canonical_command as Uint8Array);
  command.command_id = domainHash("AAR-COMMAND-MANIFEST-v1", withoutField(command, "command_id"));
  body.disposition = "eligible_for_dispatch";
  delete body.refusal_reason;
  const replacement = replaceReceipt(bundle, refusedEnvelope, nextAttempt);
  const attempt = payload(replacement);

  const firstDispatchEnvelope = receiptBy(bundle, (value) => value.kind === "dispatch");
  const firstDispatch = payload(firstDispatchEnvelope);
  const firstDispatchId = firstDispatch.receipt_id as Uint8Array;
  let secondDispatchEnvelope: CborValue[] | undefined;
  for (let nonce = 0; nonce < 1024; nonce += 1) {
    const secondDispatch = clone(firstDispatch);
    (secondDispatch.binding as Obj).epoch_seq = 10;
    (secondDispatch.emission as Obj).issuer_seq = 110;
    const edge = (secondDispatch.parents as Obj[]).find((parent) => parent.edge_type === "attempted_as")!;
    edge.parent_id = attempt.receipt_id!;
    (secondDispatch.freshness as Obj).intended_parents = (secondDispatch.parents as Obj[]).map((parent) => parent.parent_id!);
    const secondBody = secondDispatch.body as Obj;
    secondBody.attempt_id = attempt.receipt_id!;
    secondBody.command_id = command.command_id!;
    secondBody.target_response_body_digest = deterministicId(`d66-array-order:${nonce}`);
    const candidate = resign(firstDispatchEnvelope, secondDispatch, true);
    if (compare((payload(candidate).receipt_id as Uint8Array), firstDispatchId) > 0) {
      secondDispatchEnvelope = candidate;
      break;
    }
  }
  if (secondDispatchEnvelope === undefined) throw new Error("could not order D-66 dispatch fixtures");
  receiptList(bundle).push(secondDispatchEnvelope);
  sortArtifacts(bundle, "receipts");
}

// n arrays nested one in the next, innermost empty (the reviewer's round-3 shape).
function nest(n: number): CborValue { let value: CborValue = []; for (let i = 1; i < n; i += 1) value = [value]; return value; }

function mutateEmbeddedDelegation(bundle: Obj, mutation: (value: Obj) => void): void {
  const authorizationEnvelope = receiptBy(bundle, (value) => value.kind === "authorization" && ((value.body as Obj).decision as Obj).decision === "permit");
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

// Probe-test entry point (verifier.test.ts): the embedded-delegation mutator with cascade.
export function mutateEmbeddedDelegationForProbe(bundle: Obj, mutation: (value: Obj) => void): void {
  mutateEmbeddedDelegation(bundle, mutation);
}

function indexProofs(manifest: Obj): Obj[] {
  const index = manifest.receipt_index as Obj;
  const entries = index.entries as Obj[];
  const leaves = entries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry));
  return entries.map((entry, leafIndex) => ({
    entry: clone(entry),
    inclusion: { tree_size: entries.length, leaf_index: leafIndex, siblings: promotedProofWithDomain(leaves, leafIndex, "AAR-MANIFEST-INDEX-NODE-v1") },
  }));
}

function makeCompleteRange(bundle: Obj): void {
  const manifest = payload((artifacts(bundle).epoch_manifests as CborValue[])[0]!);
  const selector = bundle.selector as Obj;
  const proofs = indexProofs(manifest).filter((wrapped) => {
    const entry = wrapped.entry as Obj;
    return (entry.committed_at as number) >= (selector.committed_from as number) && (entry.committed_at as number) < (selector.committed_until as number);
  });
  bundle.coverage = "complete";
  bundle.ranges = [{ manifest_id: manifest.manifest_id!, selector_commitment: bundle.selector_commitment!, tree_size: (manifest.receipt_index as Obj).leaf_count!, ...(proofs.length === 0 ? {} : { first_leaf_index: (proofs[0]!.entry as Obj).leaf_index! }), entries: proofs }];
}

// D-77 fixtures use genuine signatures and valid content IDs unless step 6
// deliberately fires before content validation.
function d77Credential(bundle: Obj, key: TestKeyName, usage: string, issuer: TestKeyName, path: CborValue[], signer: TestKeyName, extra: Obj = {}): Obj {
  const template = (artifacts(bundle).credentials as CborValue[]).map(payload).find((p) => p.key_usage === usage)!;
  const claims: Obj = { ...clone(template), subject_kid: TEST_KEYS[key].kid, public_key: TEST_KEYS[key].spki,
    issuer_kid: TEST_KEYS[issuer].kid, path, ...extra };
  claims.credential_id = domainHash("AAR-CREDENTIAL-ID-v1", withoutField(claims, "credential_id"));
  (artifacts(bundle).credentials as CborValue[]).push(signDetached(claims, "application/aar-credential+cbor;v=0.2", signer).envelope);
  sortArtifacts(bundle, "credentials");
  return claims;
}

function d77Root(bundle: Obj): Obj {
  return (artifacts(bundle).credentials as CborValue[]).map(payload).find((p) => (p.path as CborValue[]).length === 0)!;
}

function d77Authorization(bundle: Obj, mutation: (body: Obj) => void): void {
  // A parentless authorization is a valid subset on its own; no action needs a journal.
  keepReceipts(bundle, (p) => p.kind === "authorization" && (p.parents as CborValue[]).length === 0);
  clearJournal(bundle);
  mutateReceipt(bundle, "authorization", (p) => {
    const body = p.body as Obj;
    mutation(body);
    const decision = body.decision as Obj;
    decision.decision_commitment = domainHash("AAR-DECISION-RECORD-v1", withoutField(decision, "decision_commitment"));
  });
}

function d77OmitUsage(bundle: Obj, usage: string): void {
  const root = (((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[])[0]!;
  root.allowed_key_usages = (root.allowed_key_usages as CborValue[]).filter((value) => value !== usage);
  recalcTrust(bundle);
}

function credentialId(bundle: Obj, key: TestKeyName): Uint8Array {
  return (artifacts(bundle).credentials as CborValue[]).map(payload).find((p) => same(p.subject_kid, TEST_KEYS[key].kid))!.credential_id as Uint8Array;
}

// D-81 (6.7.7): the time each object claims for its own signed act; lifecycle
// envelopes take the evaluation time. Every use of `kid` across the bundle.
const SIGNING_TIME_FIELD: Record<string, string> = {
  "application/aar-epoch-manifest+cbor;v=0.2": "closed_at", "application/aar-epoch-event+cbor;v=0.2": "occurred_at",
  "application/aar-anchor-record+cbor;v=0.2": "accepted_at", "application/aar-merkle-batch+cbor;v=0.2": "created_at",
  "application/aar-presentation+cbor;v=0.2": "delivered_at", "application/aar-status+cbor;v=0.2": "produced_at",
  "application/aar-mediator-countersignature+cbor;v=0.2": "mediator_observed_at",
};
function useTimes(bundle: Obj, kid: Uint8Array): number[] {
  const evaluation = (bundle.trust_inputs as Obj).evaluation_time as number;
  const times: number[] = [];
  const visit = (envelope: CborValue): void => {
    if (!same(protectedMap(envelope).get(4), kid)) return;
    const type = contentType(envelope); const p = payload(envelope);
    times.push(type === "application/aar-receipt+cbor;v=0.2" ? (p.emission as Obj).committed_at as number
      : type === "application/aar-request+cbor;v=0.2" ? (p.freshness as Obj).issued_at as number
      : SIGNING_TIME_FIELD[type] === undefined ? evaluation : p[SIGNING_TIME_FIELD[type]!] as number);
  };
  for (const field of ["credentials", "rotations", "status_snapshots", "requests", "delegations", "epoch_events", "epoch_manifests", "anchors", "merkle_batches", "mediator_countersignatures", "receipts"]) {
    for (const envelope of (artifacts(bundle)[field] ?? []) as CborValue[]) {
      visit(envelope);
      if (field === "receipts") for (const nested of ["delegation", "presentation"]) { const value = (payload(envelope).body as Obj)[nested]; if (value !== undefined) visit(value); }
    }
  }
  return times;
}

// D-81: the instant precedes the earliest use of the named EP key, so every use is at or after it.
function revokedBeforeUse(status: Obj, bundle: Obj): void { status.status = "revoked"; status.revoked_at = Math.min(...useTimes(bundle, TEST_KEYS.ep_signing.kid)); }
function compromisedBeforeUse(status: Obj, bundle: Obj): void { status.status = "compromised"; status.compromise_at = Math.min(...useTimes(bundle, TEST_KEYS.ep_signing.kid)); }

// A second (refreshed) snapshot cloned from the stapled one, so decision references stay intact.
function addStatusSnapshot(bundle: Obj, mutation: (status: Obj, evaluation: number) => void): void {
  const list = artifacts(bundle).status_snapshots as CborValue[];
  const next = clone(payload(list[0]!));
  next.sequence = (next.sequence as number) + 1;
  mutation(next, (bundle.trust_inputs as Obj).evaluation_time as number);
  next.snapshot_id = domainHash("AAR-STATUS-ID-v1", withoutField(next, "snapshot_id"));
  list.push(resign(list[0]!, next));
  sortArtifacts(bundle, "status_snapshots");
}

function addRotation(bundle: Obj, mutation: (rotation: Obj) => void): void {
  const list = artifacts(bundle).rotations as CborValue[];
  const next = clone(payload(list[0]!));
  mutation(next);
  next.rotation_id = domainHash("AAR-ROTATION-ID-v1", withoutField(next, "rotation_id"));
  list.push(resign(list[0]!, next));
  sortArtifacts(bundle, "rotations");
}

// D-80: the root rotates to a self-signed successor root; the record is signed by the predecessor root.
function d80RootRotation(bundle: Obj, successorInStore: boolean): void {
  const root = d77Root(bundle);
  const successor = d77Credential(bundle, "d77_outsider", "credential_issuing", "d77_outsider", [], "d77_outsider");
  if (successorInStore) {
    const roots = ((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[];
    roots.push({ ...clone(roots[0]!), root_id: deterministicId("trust-root:d80-successor"), root_kid: TEST_KEYS.d77_outsider.kid });
    recalcTrust(bundle);
  }
  addRotation(bundle, (r) => {
    Object.assign(r, { predecessor_credential_id: root.credential_id!, successor_credential_id: successor.credential_id!, predecessor_kid: root.subject_kid!, successor_kid: successor.subject_kid!,
      effective_at: (r.effective_at as number) + 100, continuity_sequence: 2 });
  });
}

export function buildPresentationEnumVariants() {
  const cases: [string, Obj, string][] = [];
  for (const field of ["signer_mode", "state"]) {
    for (const [index, value] of [0, false, null, [], {}, new Uint8Array()].entries()) {
      cases.push([`${field}-nontext-${index}`, { [field]: value }, "schema/bad-type"]);
    }
  }
  cases.push(["mode-before-state", { signer_mode: "bogus_mode", state: 0 }, "schema/enum-unknown"]);
  cases.push(["state-before-id", { state: "bogus_state", presentation_id: new Uint8Array(31) }, "schema/enum-unknown"]);
  return cases.map(([name, fields, code]) => {
    const bundle = baseBundle();
    d77Authorization(bundle, (body) => {
      const presentation = body.presentation as CborValue[];
      // Leave the nested signature/ID stale: schema validation must precede both.
      presentation[0] = encodeCbor({ ...payload(presentation), ...fields });
    });
    return { name, bytes: encodeCbor(bundle), code, step: 6 };
  });
}

// Rewrite dependencies before children so every changed receipt and consumption
// commitment is re-signed, including paths that do not follow epoch_seq order.
function rewriteD78Receipts(bundle: Obj, mutation: (receipt: Obj, originals: Obj[]) => void): void {
  const originals = receiptList(bundle).map(payload);
  const sources = new Map(receiptList(bundle).map((envelope) => [toHex(payload(envelope).receipt_id as Uint8Array), envelope]));
  const rewritten = new Map<string, Obj>();
  const manifests = new Map<string, Uint8Array>();
  function visit(id: string): Obj {
    if (rewritten.has(id)) return rewritten.get(id)!;
    const envelope = sources.get(id)!;
    const next = clone(payload(envelope));
    mutation(next, originals);
    const body = next.body as Obj;
    for (const edge of next.parents as Obj[]) {
      const parent = visit(toHex(edge.parent_id as Uint8Array));
      edge.parent_id = parent.receipt_id!;
      edge.parent_kind = parent.kind!;
      edge.parent_epoch_id = (parent.binding as Obj).epoch_id!;
    }
    for (const field of ["authorization_id", "attempt_id", "subject_id"]) {
      if (body[field] instanceof Uint8Array && sources.has(toHex(body[field]))) body[field] = visit(toHex(body[field])).receipt_id!;
    }
    if (next.kind === "observation") {
      const consumption = body.consumption as Obj;
      const oldDigest = consumption.manifest_digest as Uint8Array;
      consumption.manifest_digest = domainHash("AAR-CONSUMPTION-MANIFEST-v1", { items: consumption.items! });
      manifests.set(toHex(oldDigest), consumption.manifest_digest as Uint8Array);
    }
    if (next.kind === "inference") body.consumption_manifest_id = manifests.get(toHex(body.consumption_manifest_id as Uint8Array)) ?? body.consumption_manifest_id!;
    (next.freshness as Obj).intended_parents = (next.parents as Obj[]).map((edge) => edge.parent_id!);
    const replacement = replaceReceipt(bundle, envelope, next);
    const value = payload(replacement);
    rewritten.set(id, value);
    return value;
  }
  for (const id of sources.keys()) visit(id);
}

export function buildD78Fixtures() {
  type Descriptor = {
    name: string; object_type: "bundle"; expected_result: "conformant" | "nonconformant";
    expected_code: string | null; expected_step?: number; expected_class?: string;
    expected_observations: string[]; absent_observations: string[];
  };
  const result: { filename: string; directory: "positive" | "class-boundary" | "negative"; bytes: Uint8Array; descriptor: Descriptor }[] = [];
  const observation = "untrusted_origin_declared_in_action_ancestry";
  const positive = (filename: string, expectedClass: string, origins: string[] | undefined, itemOrigin?: string, discarded = false, noInput = false): void => {
    const bundle = baseBundle();
    // These valid subsets omit journal artifacts whose indexes bind the old receipts.
    clearJournal(bundle);
    const ids = new Map<string, Uint8Array>();
    const manifests = new Map<string, Uint8Array>();
    const receipts = [...receiptList(bundle)].sort((a, b) => ((payload(a).binding as Obj).epoch_seq as number) - ((payload(b).binding as Obj).epoch_seq as number));
    for (const envelope of receipts) {
      const next = clone(payload(envelope)); const body = next.body as Obj;
      if (next.kind === "observation") {
        const consumption = body.consumption as Obj;
        const oldDigest = consumption.manifest_digest as Uint8Array;
        for (const item of consumption.items as Obj[]) {
          if (itemOrigin !== undefined) item.origin = itemOrigin;
          if (discarded) item.disposition = "discarded";
        }
        consumption.manifest_digest = domainHash("AAR-CONSUMPTION-MANIFEST-v1", { items: consumption.items! });
        manifests.set(toHex(oldDigest), consumption.manifest_digest as Uint8Array);
      }
      if (next.kind === "inference") {
        // Only inferences with parents receive origins: the root inference lies outside every attempt's ancestry.
        if (origins !== undefined && (next.parents as Obj[]).length > 0) body.origins = origins;
        body.consumption_manifest_id = manifests.get(toHex(body.consumption_manifest_id as Uint8Array)) ?? body.consumption_manifest_id!;
      }
      for (const edge of next.parents as Obj[]) edge.parent_id = ids.get(toHex(edge.parent_id as Uint8Array)) ?? edge.parent_id!;
      for (const field of ["authorization_id", "attempt_id", "subject_id"]) {
        if (body[field] instanceof Uint8Array) body[field] = ids.get(toHex(body[field])) ?? body[field];
      }
      (next.freshness as Obj).intended_parents = (next.parents as Obj[]).map((edge) => edge.parent_id!);
      const replacement = replaceReceipt(bundle, envelope, next);
      ids.set(toHex(payload(envelope).receipt_id as Uint8Array), payload(replacement).receipt_id as Uint8Array);
    }
    if (noInput) updateAttemptFlow(bundle, (attempt, receipts) => {
      const authorization = receipts.find((receipt) => receipt.kind === "authorization" && object(receipt.root))!;
      const edge = (attempt.parents as Obj[]).find((parent) => parent.edge_type === "authorized_by")!;
      edge.parent_id = authorization.receipt_id!;
      attempt.parents = [edge];
      (attempt.body as Obj).authorization_id = authorization.receipt_id!;
    });
    const untrusted = !noInput && ((origins ?? []).some((origin) => ["third_party", "device_sensed", "unknown"].includes(origin))
      || (!discarded && itemOrigin !== undefined && ["third_party", "device_sensed", "unknown"].includes(itemOrigin)));
    result.push({ filename, directory: filename.startsWith("d78-") ? "positive" : "class-boundary", bytes: encodeCbor(bundle), descriptor: {
      name: filename, object_type: "bundle", expected_result: "conformant", expected_code: null, expected_class: expectedClass,
      expected_observations: untrusted ? [observation] : [], absent_observations: untrusted ? [] : [observation],
    } });
  };
  positive("d78-origin-third-party-retrieval", "partially_declared", ["principal", "third_party"]);
  positive("origin-declared-only-device-sensed", "declared_only", ["device_sensed"], "device_sensed");
  positive("origin-declared-only-trusted", "declared_only", ["principal", "operator_system"], "principal");
  positive("origin-no-input-ancestor", "not_evaluated", undefined, undefined, false, true);
  positive("origin-unknown-only", "partially_declared", ["unknown"]);
  positive("origin-all-discarded", "not_declared", undefined, "third_party", true);
  const negatives: [string, string, string, CborValue][] = [
    ["item-disposition-missing", "schema/missing-field", "disposition", null],
    ["origins-not-array", "schema/bad-type", "origins", "principal"],
    ["origins-empty", "schema/out-of-range", "origins", []],
    ["origins-six", "schema/out-of-range", "origins", ["unknown", "principal", "third_party", "device_sensed", "operator_system", "unknown"]],
    ["origins-nontext", "schema/bad-type", "origins", [1]],
    ["origins-enum-unknown", "schema/enum-unknown", "origins", ["web"]],
    ["origins-duplicate-nonadjacent", "schema/duplicate-entry", "origins", ["unknown", "principal", "unknown"]],
    ["origins-unsorted", "schema/unsorted-set", "origins", ["principal", "unknown"]],
    ["item-origin-enum-unknown", "schema/enum-unknown", "origin", "web"],
    ["item-origin-nontext", "schema/bad-type", "origin", 1],
    ["item-disposition-enum-unknown", "schema/enum-unknown", "disposition", "ignored"],
    ["item-disposition-nontext", "schema/bad-type", "disposition", 1],
  ];
  for (const [suffix, code, field, value] of negatives) {
    const bundle = baseBundle();
    mutateReceipt(bundle, field === "origins" ? "inference" : "observation", (receipt) => {
      const body = receipt.body as Obj;
      if (field === "origins") body.origins = value;
      else {
        const item = ((body.consumption as Obj).items as Obj[])[0]!;
        if (suffix === "item-disposition-missing") { delete item.disposition; item.origin = "web"; }
        else item[field] = value;
      }
    });
    const filename = `repair-d78-${suffix}`;
    result.push({ filename, directory: "negative", bytes: encodeCbor(bundle), descriptor: {
      name: filename, object_type: "bundle", expected_result: "nonconformant", expected_code: code, expected_step: 6,
      expected_observations: [], absent_observations: [observation],
    } });
  }
  const add = (filename: string, bundle: Obj, expectedClass = "declared_only", expectedObservations = [observation], code: string | null = null, step?: number): void => {
    result.push({ filename, directory: code ? "negative" : "class-boundary", bytes: encodeCbor(bundle), descriptor: {
      name: filename, object_type: "bundle", expected_result: code ? "nonconformant" : "conformant",
      expected_code: code, ...(step === undefined ? {} : { expected_step: step }), expected_class: expectedClass,
      expected_observations: expectedObservations, absent_observations: code ? [observation] : [],
    } });
  };
  const declared = () => decodeCbor(result.find((fixture) => fixture.filename === "origin-declared-only-trusted")!.bytes, { strict: true }) as Obj;

  // Only the historical root observation declares third_party. Its sole outgoing
  // edge crosses from epoch 42 into epoch 43 using the D-10 historical exception.
  const cross = baseBundle();
  const oldRoot = payload(receiptBy(cross, (r) => r.kind === "observation" && object(r.root)));
  rewriteD78Receipts(cross, (r) => {
    if (same(r.receipt_id, oldRoot.receipt_id)) {
      for (const item of ((r.body as Obj).consumption as Obj).items as Obj[]) item.origin = "third_party";
    } else (r.binding as Obj).epoch_id = 43;
  });
  const newRoot = payload(receiptBy(cross, (r) => r.kind === "observation" && object(r.root)));
  rebuildManifest(cross, (manifest) => {
    const index = manifest.receipt_index as Obj;
    const entry = clone((index.entries as Obj[]).find((e) => same(e.receipt_id, oldRoot.receipt_id))!);
    entry.receipt_id = newRoot.receipt_id!; entry.leaf_index = 0;
    index.entries = [entry]; index.leaf_count = 1;
    index.root = promotedRoot([domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry)], "AAR-MANIFEST-INDEX-NODE-v1");
    manifest.item_count = 1; manifest.sequence_span = { first: 0, last: 0 };
  }, true);
  const sourceManifest = payload((artifacts(cross).epoch_manifests as CborValue[])[0]!);
  const sourceAnchor = payload((artifacts(cross).anchors as CborValue[])[0]!);
  rewriteD78Receipts(cross, (r) => {
    for (const edge of r.parents as Obj[]) if (same(edge.parent_id, newRoot.receipt_id)) edge.cross_epoch = {
      source_manifest_id: sourceManifest.manifest_id!, source_anchor_id: sourceAnchor.anchor_id!, reason: "historical_evidence",
    };
  });
  artifacts(cross).merkle_batches = []; artifacts(cross).merkle_proofs = [];
  add("origin-cross-epoch-ancestry", cross, "partially_declared");

  const supports = baseBundle(); clearJournal(supports);
  rewriteD78Receipts(supports, (r, originals) => {
    const body = r.body as Obj;
    const observationRoot = originals.find((v) => v.kind === "observation" && object(v.root))!;
    const outcome = originals.find((v) => v.kind === "outcome_observation")!;
    if (r.kind === "observation" && object(r.root)) for (const item of (body.consumption as Obj).items as Obj[]) item.origin = "third_party";
    if (r.kind === "outcome_observation") {
      const template = clone((originals.find((v) => v.kind === "observation" && !object(v.root))!.parents as Obj[])[0]!);
      template.edge_type = "supports"; template.parent_id = observationRoot.receipt_id!;
      const refused = originals.find((v) => v.kind === "action_attempt" && (v.body as Obj).disposition === "not_dispatched")!;
      const subject = clone((r.parents as Obj[])[0]!);
      subject.parent_id = refused.receipt_id!;
      r.parents = [subject, template]; body.subject_id = refused.receipt_id!;
    }
    if (r.kind === "action_attempt" && body.disposition === "not_dispatched") {
      const authorization = originals.find((v) => v.kind === "authorization" && object(v.root))!;
      const edge = clone((r.parents as Obj[]).find((e) => e.edge_type === "authorized_by")!);
      edge.parent_id = authorization.receipt_id!; r.parents = [edge];
      body.authorization_id = authorization.receipt_id!;
      body.decision_commitment = ((authorization.body as Obj).decision as Obj).decision_commitment!;
    }
    if (r.kind === "inference" && (r.parents as Obj[]).length) {
      const edge = clone((r.parents as Obj[])[0]!);
      edge.edge_type = "supports"; edge.parent_id = outcome.receipt_id!;
      r.parents = [edge]; body.consumption_manifest_id = (body.prompt_manifest as Obj).digest!;
    }
  });
  add("origin-outcome-supports-ancestry", supports, "partially_declared");

  const two = declared();
  rewriteD78Receipts(two, (r) => { if (r.kind === "inference" && (r.parents as Obj[]).length) (r.body as Obj).origins = ["principal"]; });
  const other = declared();
  rewriteD78Receipts(other, (r) => {
    (r.binding as Obj).epoch_seq = ((r.binding as Obj).epoch_seq as number) + 20;
    (r.emission as Obj).issuer_seq = ((r.emission as Obj).issuer_seq as number) + 20;
    if (r.kind === "inference" && (r.parents as Obj[]).length) (r.body as Obj).origins = ["third_party"];
    if (r.kind === "observation") for (const item of ((r.body as Obj).consumption as Obj).items as Obj[]) item.origin = "third_party";
  });
  receiptList(two).push(...receiptList(other)); sortArtifacts(two, "receipts");
  add("origin-two-attempts-distinct-sets", two);

  const late = decodeCbor(result.find((fixture) => fixture.filename === "d78-origin-third-party-retrieval")!.bytes, { strict: true }) as Obj;
  // Match the existing manifest-without-events defect: a closed manifest has
  // no open/close events, so both implementations fail at step 14.
  artifacts(late).epoch_manifests = artifacts(baseBundle()).epoch_manifests!;
  add("repair-d78-untrusted-then-late-failure", late, "not_evaluated", [], "epoch/open-close", 14);

  const aar3 = declared(); aar3.claimed_profile = "AAR-3";
  rewriteD78Receipts(aar3, (r) => {
    if (r.kind === "inference" && (r.parents as Obj[]).length) (r.body as Obj).origins = ["third_party"];
    if (r.kind === "action_attempt" && (r.body as Obj).disposition === "not_dispatched") (r.body as Obj).refusal_reason = "journal/unavailable";
  });
  // Membership proofs are independent of receipt ancestry and may cover other
  // journal items; retain the fresh base corpus's signed batch and proofs.
  const journal = artifacts(baseBundle());
  artifacts(aar3).merkle_batches = journal.merkle_batches!; artifacts(aar3).merkle_proofs = journal.merkle_proofs!;
  add("origin-aar3-refused-and-untrusted", aar3, "declared_only", ["refused_pre_dispatch", observation, "membership_only", "ingress_completeness_not_established"]);
  return result;
}

export function buildD78ItemVariants() {
  const bundle = baseBundle(); clearJournal(bundle);
  rewriteD78Receipts(bundle, (receipt) => {
    if (receipt.kind !== "observation") return;
    const consumption = (receipt.body as Obj).consumption as Obj;
    consumption.items = (consumption.items as Obj[]).map((item) => new Map<CborScalar, CborValue>([...Object.entries(item), [123, true], ["origin", "web"]]));
  });
  const variants = [{ name: "d78-item-123-origin-web", bytes: encodeCbor(bundle), code: "receipt/manifest-inconsistent", step: 10 }];
  for (const [name, disposition, origin, code] of [
    ["d78-item-disposition-type-before-origin-enum", 1, "web", "schema/bad-type"],
    ["d78-item-disposition-enum-before-origin-type", "ignored", 1, "schema/enum-unknown"],
  ] as const) {
    const ordered = baseBundle();
    mutateReceipt(ordered, "observation", (receipt) => {
      const item = (((receipt.body as Obj).consumption as Obj).items as Obj[])[0]!;
      item.disposition = disposition; item.origin = origin;
    });
    variants.push({ name, bytes: encodeCbor(ordered), code, step: 6 });
  }
  return variants;
}

export function buildD78ReportVariants() {
  const source = buildD78Fixtures().find((fixture) => fixture.filename === "d78-origin-third-party-retrieval")!;
  const undispatched = decodeCbor(source.bytes, { strict: true }) as Obj;
  keepReceipts(undispatched, (receipt) => !["dispatch", "outcome_observation"].includes(receipt.kind as string));
  const mixed = decodeCbor(source.bytes, { strict: true }) as Obj;
  mutateReceiptWhere(mixed, (receipt) => receipt.kind === "action_attempt" && (receipt.body as Obj).disposition === "not_dispatched", (receipt) => {
    (receipt.body as Obj).disposition = "eligible_for_dispatch";
    delete (receipt.body as Obj).refusal_reason;
  });
  const repeated = decodeCbor(source.bytes, { strict: true }) as Obj;
  const dispatchEnvelope = receiptBy(repeated, (receipt) => receipt.kind === "dispatch");
  const dispatch = clone(payload(dispatchEnvelope));
  (dispatch.binding as Obj).epoch_seq = 10;
  (dispatch.emission as Obj).issuer_seq = 110;
  receiptList(repeated).push(resign(dispatchEnvelope, dispatch, true));
  sortArtifacts(repeated, "receipts");
  return [
    { name: "d78-report-eligible-undispatched", bytes: encodeCbor(undispatched), dispatched: [false], limit: "not_evaluated" },
    { name: "d78-report-mixed-attempts-diamond", bytes: encodeCbor(mixed), dispatched: [true, false], limit: "partially_declared" },
    { name: "d78-report-repeated-dispatch", bytes: encodeCbor(repeated), dispatched: [true], limit: "partially_declared" },
  ];
}

export function buildD77PositiveFixtures() {
  const bundle = baseBundle();
  // outcome_signing signs only its outcome receipt and has no ID references.
  mutateArtifact(bundle, "credentials", (p) => same(p.subject_kid, TEST_KEYS.outcome_signing.kid),
    (p) => { p.valid_until = ((bundle.trust_inputs as Obj).evaluation_time as number) - 1; });
  const filename = "repair-d77-receipt-signed-before-expiry";
  const epSession = baseBundle();
  const inference = receiptBy(epSession, (p) => p.kind === "inference" && (p.parents as CborValue[]).length === 0);
  d77Authorization(epSession, (body) => {
    const p = payload(body.presentation!);
    p.signer_mode = "ep_authenticated_session";
    p.presentation_id = domainHash("AAR-PRESENTATION-MANIFEST-v1", withoutField(p, "presentation_id"));
    body.presentation = signDetached(p, contentType(body.presentation!), "ep_signing").envelope;
  });
  receiptList(epSession).push(inference);
  sortArtifacts(epSession, "receipts");
  const epSessionName = "repair-d77-presentation-ep-session-positive";
  return [{ filename, bytes: encodeCbor(bundle), descriptor: { name: filename, object_type: "bundle",
    expectation: "conformant", expected_result: "conformant", expected_code: null,
    mutation_description: "Expire the receipt-only outcome signing credential after committed_at but before evaluation time; recompute its ID and signature." } },
  { filename: epSessionName, bytes: encodeCbor(epSession), descriptor: { name: epSessionName, object_type: "bundle",
    expectation: "conformant", expected_result: "conformant", expected_code: null,
    mutation_description: "An EP-session presentation is signed by the enclosing authorization receipt's EP key; presenter and decision name the same approver." } }];
}

// D-80 / D-81 positives: conformant bundles that pin the use-time and namespace rules.
export function buildD80D81PositiveFixtures() {
  const make = (filename: string, description: string, mutate: (bundle: Obj) => void) => {
    const bundle = baseBundle(); mutate(bundle);
    return { filename, bytes: encodeCbor(bundle), descriptor: { name: filename, object_type: "bundle" as const,
      expectation: "conformant" as const, expected_result: "conformant" as const, expected_code: null, mutation_description: description } };
  };
  const afterLastUse = (field: "revoked_at" | "compromise_at") => (bundle: Obj): void => addStatusSnapshot(bundle, (s, evaluation) => {
    s.status = field === "revoked_at" ? "revoked" : "compromised";
    s[field] = Math.max(...useTimes(bundle, TEST_KEYS.ep_signing.kid)) + 1;
    if ((s[field] as number) >= evaluation) throw new Error("EP key use reaches the evaluation time");
  });
  return [
    make("d80-rotation-two-sites-same-seq", "A second allowed site rotates its own agent credentials under the same root with the same continuity_sequence; groups are never compared.", (bundle) => {
      const site = id16("site:d80-second-site");
      const root = (((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[])[0]!;
      root.allowed_sites = [...(root.allowed_sites as CborValue[]), site].sort(compare); recalcTrust(bundle);
      const rootId = d77Root(bundle).credential_id!;
      const predecessor = d77Credential(bundle, "d77_outsider", "agent_signing", "credential_issuing", [rootId], "credential_issuing", { site_id: site });
      const successor = d77Credential(bundle, "d77_leaf", "agent_signing", "credential_issuing", [rootId], "credential_issuing", { site_id: site });
      addRotation(bundle, (r) => { Object.assign(r, { predecessor_credential_id: predecessor.credential_id!, successor_credential_id: successor.credential_id!, predecessor_kid: predecessor.subject_kid!, successor_kid: successor.subject_kid!, site_id: site }); });
    }),
    make("d80-root-rotation", "The root rotates to a self-signed successor root carried in the trust store; the record is signed by the predecessor root.", (bundle) => d80RootRotation(bundle, true)),
    make("d81-status-revoked-after-last-use", "A refreshed snapshot revokes the EP credential one second after its last use and before evaluation.", afterLastUse("revoked_at")),
    make("d81-status-compromised-after-last-use", "A refreshed snapshot marks the EP credential compromised one second after its last use and before evaluation.", afterLastUse("compromise_at")),
    make("d81-status-revoked-key-unused", "A refreshed snapshot revokes the agent_signing_successor credential, whose key signs nothing in the bundle.", (bundle) => addStatusSnapshot(bundle, (s) => { s.status = "revoked"; s.revoked_at = s.produced_at!; s.credential_id = credentialId(bundle, "agent_signing_successor"); })),
    make("d81-anchor-credential-expired-after-use", "The anchor_signing credential expires one second after its anchor record's accepted_at and before evaluation.", (bundle) => {
      const anchor = payload((artifacts(bundle).anchors as CborValue[])[0]!);
      mutateArtifact(bundle, "credentials", (p) => same(p.subject_kid, TEST_KEYS.anchor_signing.kid), (p) => { p.valid_until = (anchor.accepted_at as number) + 1; });
    }),
  ];
}

// D-82 helpers.
// Single-fault kit (Codex P2, round 2): every schema fixture carries exactly
// its fault, with content ids recomputed over the mutated claims and every
// touched envelope re-signed by its key.
// Mutate the nested presentation of the approval authorization: presentation
// re-identified and re-signed by the approver, the enclosing receipt re-signed.
function mutatePresentation(bundle: Obj, mutate: (value: Obj) => void): void {
  mutateReceiptWhere(bundle, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => {
    const presentation = (p.body as Obj).presentation!;
    const next = clone(payload(presentation));
    mutate(next);
    next.presentation_id = domainHash("AAR-PRESENTATION-MANIFEST-v1", withoutField(next, "presentation_id"));
    (p.body as Obj).presentation = signDetached(next, contentType(presentation), signerFor(presentation)).envelope;
  });
}

// Mutate receipts matching the predicate and re-derive every dependent receipt
// id (parent edges, body references, intended parents) through rewriteD78Receipts.
function mutateReceiptsCascade(bundle: Obj, predicate: (value: Obj) => boolean, mutate: (value: Obj) => void): void {
  rewriteD78Receipts(bundle, (r) => { if (predicate(r)) mutate(r); });
}

// A ladder of top-level delegations: `levels` deep, `width` wide, every
// delegation naming every delegation of the next level (shared ancestors).
// Returns the ids of the first level for the embedded delegation to name.
export function addDelegationLadder(bundle: Obj, levels: number, width: number): Uint8Array[] {
  const list = artifacts(bundle).delegations as CborValue[];
  const template = clone(payload(list[0]!));
  list.length = 0; // the unreferenced base delegation leaves room under the 1,000 ceiling
  let next: Uint8Array[] = [];
  for (let level = levels - 1; level >= 0; level -= 1) {
    const ids: Uint8Array[] = [];
    for (let column = 0; column < width; column += 1) {
      const claims = clone(template);
      claims.replay_domain = deterministicId(`d82-ladder:${level}:${column}`);
      claims.parent_delegations = next;
      claims.delegation_id = domainHash("AAR-DELEGATION-ID-v1", withoutField(claims, "delegation_id"));
      list.push(signDetached(claims, "application/aar-delegation+cbor;v=0.2", "authority_signing").envelope);
      ids.push(claims.delegation_id as Uint8Array);
    }
    next = ids;
  }
  sortArtifacts(bundle, "delegations");
  return next;
}

const TRANSFORM: Obj = {
  ordinal: 0, operation: "crop", input_digest: deterministicId("transform:in"), output_digest: deterministicId("transform:out"),
  parameters_digest: deterministicId("transform:parameters"), implementation_id: "aar-kat-transform", implementation_version: "1.0.0",
};

// D-82 part 6: conformant subsets whose maximum classes start at not_evaluated.
export function buildD82PositiveFixtures() {
  const make = (filename: string, description: string, mutate: (bundle: Obj) => void) => {
    const bundle = baseBundle(); mutate(bundle);
    return { filename, bytes: encodeCbor(bundle), descriptor: { name: filename, object_type: "bundle" as const,
      expectation: "conformant" as const, expected_result: "conformant" as const, expected_code: null, mutation_description: description } };
  };
  return [
    make("d82-observer-independent-of-unrelated-observation", "The outcome declares independently_sensed with a qualifying predicate and an observer whose failure domain matches a new parentless observation that is not in the outcome's ancestry (amendment s); the round-4 pyref judged every carried observation.", (bundle) => {
      clearJournal(bundle);
      const domain = id16("failure-domain:unrelated-observer");
      const rootEnvelope = receiptBy(bundle, (p) => p.kind === "observation" && object(p.root));
      const unrelated = clone(payload(rootEnvelope));
      unrelated.root = { kind: "human_request", request_id: id16("request:human:unrelated"), request_commitment: deterministicId("human-request:unrelated") };
      (unrelated.binding as Obj).epoch_seq = 10; (unrelated.emission as Obj).issuer_seq = 110; (unrelated.emission as Obj).committed_at = 1_735_689_710;
      (unrelated.freshness as Obj).nonce = id16("nonce:unrelated-observation");
      ((unrelated.body as Obj).source_device as Obj).failure_domain_id = domain;
      receiptList(bundle).push(resign(rootEnvelope, unrelated, true)); sortArtifacts(bundle, "receipts");
      const predicateId = addOpaquePayload(bundle, "qualification:independent");
      mutateReceiptWhere(bundle, (p) => p.kind === "outcome_observation", (p) => {
        const outcome = (p.evidence as Obj).outcome as Obj; outcome.level = "independently_sensed"; outcome.qualifying_predicate_id = predicateId;
        ((p.body as Obj).observer as Obj).failure_domain_id = domain;
      });
    }),
    make("d82-chain-shared-ancestors", "The embedded delegation names two carried parents that each name their own parent, both naming one shared grandparent: five delegations, each chain evaluated once.", (bundle) => {
      mutateEmbeddedDelegation(bundle, (d) => { d.parent_delegations = addDelegationLadder(bundle, 3, 2).slice(0, 2); });
    }),
    make("d82-chain-two-levels", "The embedded delegation names a carried parent that names a carried grandparent; every link contains the child's window and scope lists and widens nothing.", (bundle) => {
      const grandparent = addTopLevelDelegation(bundle, (d) => { const scope = d.scope as Obj; scope.actions = ["camera.ptz.preset", "camera.stream.view"]; scope.allowed_profiles = ["AAR-1", "AAR-2", "AAR-2A", "AAR-3"]; d.not_before = (d.not_before as number) - 100; d.not_after = (d.not_after as number) + 100; });
      const parent = addTopLevelDelegation(bundle, (d) => { d.parent_delegations = [grandparent.delegation_id!]; d.not_before = (d.not_before as number) - 50; d.not_after = (d.not_after as number) + 50; });
      mutateEmbeddedDelegation(bundle, (d) => { d.parent_delegations = [parent.delegation_id!]; });
    }),
    make("d82-observation-only-subset", "Only the two observation receipts, no journal: no inference, so maximum_provenance_class is not_evaluated in both verifiers.", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, (p) => p.kind === "observation");
    }),
    make("d82-no-receipts-subset", "An empty selected set with no journal: every maximum class is not_evaluated.", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, () => false);
    }),
    make("d82-receipt-verified-after-window", "The root observation's freshness window closes one second after it was committed; the window bounds emission, not evaluation (amendment v).", (bundle) => {
      clearJournal(bundle); mutateReceiptsCascade(bundle, (p) => p.kind === "observation" && object(p.root), (p) => { (p.freshness as Obj).expires_at = ((p.emission as Obj).committed_at as number) + 1; });
    }),
    make("d82-invocation-differs-across-derived-from", "The derived observation carries another invocation_id and no correlation binding: it is in no action flow (amendment z).", (bundle) => {
      clearJournal(bundle); mutateReceiptsCascade(bundle, (p) => p.kind === "observation" && !object(p.root), (p) => { (p.freshness as Obj).invocation_id = id16("other-invocation"); delete p.correlation; });
    }),
    make("d82-manifest-predecessor-uncarried", "The only manifest names an uncarried predecessor (amendment w).", (bundle) => rebuildManifest(bundle, (m) => { m.predecessor_manifest_digest = deterministicId("uncarried-predecessor"); }, true)),
    make("d82-anchor-head-newer-than-expected", "The anchor record's head is three leaves past the expected head with a different root: no conflict (amendment y).", (bundle) => mutateArtifact(bundle, "anchors", () => true, (p) => { const head = p.head as Obj; head.tree_size = (head.tree_size as number) + 3; head.root = deterministicId("newer-head"); })),
    make("d82-parent-delegation-invocation-absent", "A carried parent delegation without invocation_id and an embedded child without one (the control for amendment u at the chain link).", (bundle) => {
      const parent = addTopLevelDelegation(bundle, (d) => { delete d.invocation_id; (d.scope as Obj).actions = ["camera.ptz.preset", "camera.stream.view"]; (d.scope as Obj).allowed_profiles = ["AAR-1", "AAR-2", "AAR-2A", "AAR-3"]; d.not_before = (d.not_before as number) - 100; d.not_after = (d.not_after as number) + 100; d.replay_domain = deterministicId("u:parent"); });
      mutateEmbeddedDelegation(bundle, (d) => { d.parent_delegations = [parent.delegation_id!]; delete d.invocation_id; });
    }),
    make("d82-index-order-not-seq-order", "The manifest index holds two uncarried entries whose committed_at order is not their epoch_seq order; the span is the minimum and maximum epoch_seq (amendment ad).", (bundle) => {
      keepReceipts(bundle, () => false);
      rebuildManifest(bundle, (m) => {
        const template = ((m.receipt_index as Obj).entries as Obj[])[0]!;
        const entries = [{ ...clone(template), leaf_index: 0, receipt_id: deterministicId("uncarried-a"), epoch_seq: 5, committed_at: template.committed_at }, { ...clone(template), leaf_index: 1, receipt_id: deterministicId("uncarried-b"), epoch_seq: 3, committed_at: (template.committed_at as number) + 1 }];
        m.receipt_index = { ...(m.receipt_index as Obj), entries, leaf_count: 2, root: promotedRoot(entries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry)), "AAR-MANIFEST-INDEX-NODE-v1") };
        m.item_count = 2; m.sequence_span = { first: 3, last: 5 };
      }, true);
      mutateArtifact(bundle, "epoch_events", (p) => p.event === "open", (p) => { (p.body as Obj).first_epoch_seq = 3; }); relinkEventChain(bundle);
    }),
  ];
}

export function buildNegativeFixtures(): NegativeFixture[] {
  const result: NegativeFixture[] = [];
  const add = (value: NegativeFixture): void => { result.push(value); };
  const validBytes = encodeCbor(baseBundle());
  // D-68..D-70 and D-73 release repairs. Schema negatives deliberately leave later
  // commitments unrepaired: tests assert the exact step so a later hash
  // rejection cannot masquerade as schema enforcement.
  const releaseRepairs: [string, string, string, (bundle: Obj) => void][] = [
    ["repair-d68-principal-role-as-type", "schema/enum-unknown", "Set the root credential principal_type to the role text authority_source, keeping its credential_id.", (bundle) => {
      mutateArtifact(bundle, "credentials", (p) => p.key_usage === "credential_issuing", (p) => { p.principal_type = "authority_source"; }, false);
    }],
    ["repair-d68-principal-type-not-text", "schema/bad-type", "Set the root credential principal_type to the integer 7, keeping its credential_id.", (bundle) => {
      mutateArtifact(bundle, "credentials", (p) => p.key_usage === "credential_issuing", (p) => { p.principal_type = 7; }, false);
    }],
    ["repair-d68-principal-type-and-short-id", "schema/enum-unknown", "Set the root credential principal_type to authority_source and truncate its credential_id to 31 bytes; the enum check precedes fixed-size checks.", (bundle) => {
      mutateArtifact(bundle, "credentials", (p) => p.key_usage === "credential_issuing", (p) => { p.principal_type = "authority_source"; p.credential_id = (p.credential_id as Uint8Array).slice(0, 31); }, false);
    }],
    ["repair-d69-consumption-empty", "schema/out-of-range", "Empty the root observation consumption items array.", (bundle) => {
      mutateReceipt(bundle, "observation", (p) => { ((p.body as Obj).consumption as Obj).items = []; });
    }],
    ["repair-d69-consumption-overflow", "schema/out-of-range", "Repeat the root observation consumption item 4,097 times.", (bundle) => {
      mutateReceipt(bundle, "observation", (p) => { const c = (p.body as Obj).consumption as Obj; c.items = Array.from({ length: 4097 }, () => clone((c.items as CborValue[])[0]!)); });
    }],
    ["repair-d69-exclusion-reason", "schema/enum-unknown", "Give the action-attempt excluded field an unknown reason while its value commitment is present.", (bundle) => {
      mutateReceipt(bundle, "action_attempt", (p) => { (((p.body as Obj).command as Obj).excluded_fields as Obj[])[0]!.reason = "injected_only_at_transport"; });
    }],
    ["repair-d69-exclusion-commitment", "schema/missing-field", "Remove the action-attempt excluded field value commitment while its reason stays valid.", (bundle) => {
      mutateReceipt(bundle, "action_attempt", (p) => { delete (((p.body as Obj).command as Obj).excluded_fields as Obj[])[0]!.value_commitment; });
    }],
    // The three command fixtures recompute command_digest/command_id so step 7 (content commitments) stays clean; the
    // mediator countersignature is NOT re-bound, which is fine only because step 10's action/command check fires first.
    ["repair-d73-command-parameters-digest-mismatch", "receipt/action-command-mismatch", "Rebuild the attempt canonical command with a foreign parameters_digest, recomputing command_digest and command_id so step 7 stays clean.", (bundle) => {
      mutateReceipt(bundle, "action_attempt", (p) => { const b = p.body as Obj; const a = b.action as Obj; const c = b.command as Obj;
        c.canonical_command = encodeCbor({ operation: a.action_name!, target: a.target_id!, parameters_digest: deterministicId("foreign-parameters") });
        c.command_digest = hash(c.canonical_command as Uint8Array); c.command_id = domainHash("AAR-COMMAND-MANIFEST-v1", withoutField(c, "command_id")); });
    }],
    ["repair-d73-command-parameters-present-mismatch", "receipt/action-command-mismatch", "Carry a parameters map in the canonical command whose deterministic encoding does not hash to the correct parameters_digest.", (bundle) => {
      mutateReceipt(bundle, "action_attempt", (p) => { const b = p.body as Obj; const a = b.action as Obj; const c = b.command as Obj;
        c.canonical_command = encodeCbor({ operation: a.action_name!, target: a.target_id!, parameters_digest: a.parameters_digest!, parameters: { stream_profile: "not-the-committed-profile" } });
        c.command_digest = hash(c.canonical_command as Uint8Array); c.command_id = domainHash("AAR-COMMAND-MANIFEST-v1", withoutField(c, "command_id")); });
    }],
    ["repair-d73-command-parameters-nontext-key", "receipt/action-command-mismatch", "Carry a parameters map with an integer key whose deterministic encoding DOES hash to a matching parameters_digest; non-text keys are outside canonical-command-payload.", (bundle) => {
      mutateReceipt(bundle, "action_attempt", (p) => { const b = p.body as Obj; const a = b.action as Obj; const c = b.command as Obj;
        const parameters = new Map<CborScalar, CborValue>([[1, "x"]]); const digest = hash(encodeCbor(parameters));
        a.parameters_cbor = encodeCbor(parameters); a.parameters_digest = digest;
        c.canonical_command = encodeCbor(new Map<CborScalar, CborValue>([["operation", a.action_name!], ["target", a.target_id!], ["parameters_digest", digest], ["parameters", parameters]]));
        c.command_digest = hash(c.canonical_command as Uint8Array); c.command_id = domainHash("AAR-COMMAND-MANIFEST-v1", withoutField(c, "command_id")); });
    }],
    ["repair-d73-credential-alg-unknown", "schema/enum-unknown", "Set the root credential cose_alg to -8, keeping its credential_id.", (bundle) => {
      mutateArtifact(bundle, "credentials", (p) => p.key_usage === "credential_issuing", (p) => { p.cose_alg = -8; }, false);
    }],
    ["repair-d73-credential-alg-not-int", "schema/bad-type", "Set the root credential cose_alg to the text ES256, keeping its credential_id.", (bundle) => {
      mutateArtifact(bundle, "credentials", (p) => p.key_usage === "credential_issuing", (p) => { p.cose_alg = "ES256"; }, false);
    }],
    ["repair-d73-manifest-without-events", "epoch/open-close", "Remove every epoch event while keeping the closed manifest; a manifest with no open/close is not a closed epoch.", (bundle) => {
      artifacts(bundle).epoch_events = [];
    }],
    ["repair-d69-anchor-basis-no-anchor", "schema/enum-unknown", "Declare an unknown anchor-plan independence basis in a manifest carried without any anchor record.", (bundle) => {
      rebuildManifest(bundle, (p) => { ((p.anchor_plan as Obj).independence as Obj).basis = "same_operator_demo_only"; });
    }],
    ["repair-d69-independence-duplicate-operator", "anchor/independence-invalid", "Add a second independence group that repeats the first group's operator_id under a distinct_operator_and_failure_domain plan with its anchor rebuilt.", (bundle) => {
      rebuildManifest(bundle, (p) => {
        const groups = ((p.anchor_plan as Obj).independence as Obj).groups as Obj[];
        groups.push({ independence_group: id16("independence-group:log-2"), operator_id: groups[0]!.operator_id!, failure_domain_id: id16("failure-domain:log-2") });
      }, true);
    }],
    ["repair-d70-evaluation-time", "schema/out-of-range", "Advance the bundle trust_inputs.evaluation_time one second past the caller's evaluation time.", (bundle) => { (bundle.trust_inputs as Obj).evaluation_time = 1_735_689_801; }],
    ["repair-d70-trust-created-after-evaluation", "schema/out-of-range", "Set the trust-store snapshot created_at one second after the evaluation time and repair the store digest.", (bundle) => {
      ((bundle.trust_inputs as Obj).trust_store as Obj).created_at = 1_735_689_801; recalcTrust(bundle);
    }],
  ];
  for (const [name, code, description, mutate] of releaseRepairs) {
    const item = bundleFixture(code, description, mutate);
    add({ ...item, filename: name, descriptor: { ...item.descriptor, name } });
  }

  const d77Repairs: [string, string, number, string, (bundle: Obj) => void][] = [
    ["credential-issuer-forged", "credential/usage-mismatch", 6, "Outsider O self-signs a credential_issuing credential claiming the accepted root as issuer, then issues an agent leaf under O and that root.", (bundle) => {
      const root = d77Root(bundle);
      const outsider = d77Credential(bundle, "d77_outsider", "credential_issuing", "credential_issuing", [root.credential_id!], "d77_outsider");
      d77Credential(bundle, "d77_leaf", "agent_signing", "d77_outsider", [outsider.credential_id!, root.credential_id!], "d77_outsider");
    }],
    ["root-not-self-signed", "credential/usage-mismatch", 6, "Carry an empty-path credential naming itself as issuer and subject but signed by the accepted credential_issuing key.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "credential_issuing", "d77_outsider", [], "credential_issuing");
    }],
    ["status-issuer-mismatch", "credential/usage-mismatch", 6, "Keep the status payload byte-identical and sign it with a second valid status_signing key.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "status_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      const list = artifacts(bundle).status_snapshots as CborValue[];
      list[0] = signDetached(payload(list[0]!), contentType(list[0]!), "d77_outsider").envelope;
    }],
    ["anchor-signer-mismatch", "credential/usage-mismatch", 6, "Keep the anchor payload and planned target byte-identical and sign the record with a second valid anchor_signing key.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "anchor_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      const list = artifacts(bundle).anchors as CborValue[];
      list[0] = signDetached(payload(list[0]!), contentType(list[0]!), "d77_outsider").envelope;
    }],
    ["root-subject-clause", "credential/usage-mismatch", 6, "The real root signs an empty-path credential whose issuer is that root but whose subject is a different key.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "credential_issuing", "credential_issuing", [], "credential_issuing");
    }],
    ["delegation-issuer-forged", "credential/usage-mismatch", 6, "Authority B signs the unchanged top-level delegation naming authority A as issuer.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "authority_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      const list = artifacts(bundle).delegations as CborValue[];
      list[0] = signDetached(payload(list[0]!), contentType(list[0]!), "d77_outsider").envelope;
    }],
    ["embedded-delegation-issuer-forged", "credential/usage-mismatch", 6, "Authority B signs only the embedded delegation naming authority A, in a valid authorization-only subset.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "authority_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      artifacts(bundle).delegations = [];
      d77Authorization(bundle, (body) => {
        body.delegation = signDetached(payload(body.delegation!), contentType(body.delegation!), "d77_outsider").envelope;
      });
    }],
    ["presentation-signer-forged", "credential/usage-mismatch", 6, "Approver B signs a presentation naming approver A; decision and enclosing commitments remain consistent in an authorization-only subset.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "approver_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      d77Authorization(bundle, (body) => {
        body.presentation = signDetached(payload(body.presentation!), contentType(body.presentation!), "d77_outsider").envelope;
      });
    }],
    ["presentation-ep-session-signer-mismatch", "credential/usage-mismatch", 6, "An EP-session presentation is signed by a second valid ep_signing key, while the enclosing authorization retains the original EP signer.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "ep_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      d77Authorization(bundle, (body) => {
        const p = payload(body.presentation!);
        p.signer_mode = "ep_authenticated_session";
        p.presentation_id = domainHash("AAR-PRESENTATION-MANIFEST-v1", withoutField(p, "presentation_id"));
        body.presentation = signDetached(p, contentType(body.presentation!), "d77_outsider").envelope;
      });
    }],
    ["presentation-signer-mode-unknown", "schema/enum-unknown", 6, "A presentation with signer_mode bogus_mode is signed by a second valid ep_signing key; presenter and decision name approver A, with all commitments repaired.", (bundle) => {
      d77Credential(bundle, "d77_outsider", "ep_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      d77Authorization(bundle, (body) => {
        const p = payload(body.presentation!);
        p.signer_mode = "bogus_mode";
        p.presentation_id = domainHash("AAR-PRESENTATION-MANIFEST-v1", withoutField(p, "presentation_id"));
        body.presentation = signDetached(p, contentType(body.presentation!), "d77_outsider").envelope;
      });
    }],
    ["presentation-state-unknown", "schema/enum-unknown", 6, "An otherwise valid approver-originated presentation has state bogus_state, with its content ID and enclosing commitments repaired.", (bundle) => {
      d77Authorization(bundle, (body) => {
        const p = payload(body.presentation!);
        p.state = "bogus_state";
        p.presentation_id = domainHash("AAR-PRESENTATION-MANIFEST-v1", withoutField(p, "presentation_id"));
        body.presentation = signDetached(p, contentType(body.presentation!), "approver_signing").envelope;
      });
    }],
    ["presenter-approver-mismatch", "receipt/decision-presentation", 10, "Presenter A validly signs its presentation, but the decision names approver B; repair commitments in an authorization-only subset.", (bundle) => {
      const approver = d77Credential(bundle, "d77_outsider", "approver_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      d77Authorization(bundle, (body) => { (body.decision as Obj).approver_credential_id = approver.credential_id!; });
    }],
    ["duplicate-subject-find-first", "credential/expired", 6, "Carry an expired self-signed root credential sorted before the valid credential for the same root key.", (bundle) => {
      const root = d77Root(bundle);
      const expired = clone(root);
      expired.valid_until = ((bundle.trust_inputs as Obj).evaluation_time as number) - 1;
      do {
        expired.valid_until = (expired.valid_until as number) - 1;
        expired.credential_id = domainHash("AAR-CREDENTIAL-ID-v1", withoutField(expired, "credential_id"));
      } while (compare(expired.credential_id, root.credential_id!) >= 0);
      (artifacts(bundle).credentials as CborValue[]).push(signDetached(expired, "application/aar-credential+cbor;v=0.2", "credential_issuing").envelope);
      sortArtifacts(bundle, "credentials");
    }],
    ["root-key-reissued", "credential/path-invalid", 8, "A valid intermediate credential_issuing key issues a second credential for the accepted root key with a non-empty path.", (bundle) => {
      const root = d77Root(bundle);
      const intermediate = d77Credential(bundle, "d77_outsider", "credential_issuing", "credential_issuing", [root.credential_id!], "credential_issuing");
      d77Credential(bundle, "credential_issuing", "credential_issuing", "d77_outsider", [intermediate.credential_id!, root.credential_id!], "d77_outsider");
    }],
    ["credential-path-null", "schema/bad-type", 6, "Set the self-signed root credential path to null, retaining its ID so schema validation must precede content-ID validation.", (bundle) => {
      mutateArtifact(bundle, "credentials", (p) => (p.path as CborValue[]).length === 0, (p) => { p.path = null; }, false);
    }],
    ["countersigned-subject-issuer-forged", "countersign/credential-invalid", 6, "Sign the mediator subject credential with a valid outsider issuing key while it still claims issuance by the accepted root.", (bundle) => {
      const countersigned = decodeCbor(buildCountersignFixtures()[0]!.bytes, { strict: true }) as Obj;
      Object.assign(bundle, countersigned);
      d77Credential(bundle, "d77_outsider", "credential_issuing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      const credentials = artifacts(bundle).credentials as CborValue[];
      const index = credentials.findIndex((entry) => same(payload(entry).subject_kid, TEST_KEYS.mediator_outcome_signing.kid));
      credentials[index] = signDetached(payload(credentials[index]!), "application/aar-credential+cbor;v=0.2", "d77_outsider").envelope;
    }],
    ["root-usage-not-allowed", "credential/root-not-accepted", 8, "Remove ep_signing from the accepted root's usages and recompute the trust digest.", (bundle) => { d77OmitUsage(bundle, "ep_signing"); }],
    ["embedded-delegation-usage", "credential/root-not-accepted", 8, "Remove the top-level delegation so authority_signing is used only by embedded delegations, and remove its root permission.", (bundle) => {
      artifacts(bundle).delegations = []; d77OmitUsage(bundle, "authority_signing");
    }],
    ["duplicate-root-kid", "schema/duplicate-entry", 5, "Repeat a root_kid in a second root record and recompute the trust digest.", (bundle) => {
      const roots = (((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[]);
      roots.push({ ...clone(roots[0]!), root_id: deterministicId("d77-duplicate-root-record") }); recalcTrust(bundle);
    }],
    ["receipt-signer-valid-until-boundary", "credential/expired", 6, "Set the receipt-only outcome signing credential valid_until to its receipt committed_at.", (bundle) => {
      const receipt = (artifacts(bundle).receipts as CborValue[]).map(payload).find((p) => p.kind === "outcome_observation")!;
      mutateArtifact(bundle, "credentials", (p) => same(p.subject_kid, TEST_KEYS.outcome_signing.kid), (p) => { p.valid_until = (receipt.emission as Obj).committed_at!; });
    }],
    ["nonreceipt-signer-valid-until-boundary", "credential/expired", 6, "Set the anchor_signing credential valid_until to its anchor record's accepted_at; a non-receipt signs at the time it claims (D-81).", (bundle) => {
      const anchor = payload((artifacts(bundle).anchors as CborValue[])[0]!);
      mutateArtifact(bundle, "credentials", (p) => same(p.subject_kid, TEST_KEYS.anchor_signing.kid), (p) => { p.valid_until = anchor.accepted_at!; });
    }],
    ["order-tenant-before-validity", "credential/usage-mismatch", 6, "Give the status signer both a foreign site and expired validity; scope must fail first.", (bundle) => {
      mutateArtifact(bundle, "credentials", (p) => p.key_usage === "status_signing", (p) => { p.site_id = id16("d77-foreign-site"); p.valid_until = ((bundle.trust_inputs as Obj).evaluation_time as number) - 1; });
    }],
    ["order-key-before-coordinates", "key/not-found", 6, "Give a receipt an unknown protected kid and a mismatching protected site; key resolution must fail first.", (bundle) => {
      modifyCose(bundle, "receipts", 0, (value) => {
        const protectedValue = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>;
        protectedValue.set(4, TEST_KEYS.d77_outsider.kid); protectedValue.set(-70002, id16("d77-foreign-site")); value[0] = encodeCbor(protectedValue);
      });
    }],
  ];
  for (const [suffix, code, step, description, mutate] of d77Repairs) {
    const item = bundleFixture(code, description, mutate);
    const name = `repair-d77-${suffix}`;
    add({ ...item, filename: name, descriptor: { ...item.descriptor, name,
      expected_result: code === "key/not-found" ? "indeterminate" : "nonconformant", expected_step: step } });
  }

  // D-79 / D-80 / D-81 repairs: genuine signatures and valid content IDs unless step 6 fires on the mutation itself.
  const delegationRepair = (mutation: (delegation: Obj, bundle: Obj) => void) => (bundle: Obj): void => mutateEmbeddedDelegation(bundle, (d) => mutation(d, bundle));
  const statusRepair = (mutation: (status: Obj, evaluation: number, bundle: Obj) => void) => (bundle: Obj): void => addStatusSnapshot(bundle, (s, evaluation) => mutation(s, evaluation, bundle));
  const d79to81Repairs: [string, string, number, string, (bundle: Obj) => void][] = [
    ["repair-d79-delegation-subject-mismatch", "delegation/scope", 13, "Point the embedded delegation subject_credential_id at the agent_signing credential; the attempt is EP-signed.", delegationRepair((d, b) => { d.subject_credential_id = credentialId(b, "agent_signing"); })],
    ["repair-d79-delegation-subject-unresolved", "delegation/scope", 13, "Point the embedded delegation subject_credential_id at an id no carried credential has.", delegationRepair((d) => { d.subject_credential_id = deterministicId("d79-missing-subject-credential"); })],
    ["repair-d79-delegation-subject-before-expiry", "delegation/scope", 13, "Wrong subject AND not_after before the attempt's committed_at; the subject check precedes the window.", delegationRepair((d, b) => { d.subject_credential_id = credentialId(b, "agent_signing"); d.not_after = 1; })],
    ["repair-d79-delegation-scope-before-window", "delegation/scope", 13, "Action out of scope AND not_after before the attempt's committed_at; scope precedes the window.", delegationRepair((d) => { (d.scope as Obj).actions = ["camera.ptz.preset"]; d.not_after = 1; })],
    ["repair-d79-delegation-one-time-no-invocation", "delegation/scope", 13, "A one_time delegation without invocation_id fails the invocation check.", delegationRepair((d) => { d.use = "one_time"; delete d.invocation_id; })],
    ["repair-d79-delegation-invocation-mismatch-reusable", "delegation/scope", 13, "A reusable delegation carrying a different invocation_id; the check applies whenever the field is present.", delegationRepair((d) => { d.invocation_id = id16("d79-other-invocation"); })],
    ["repair-d80-rotation-signer-not-predecessor-issuer", "credential/rotation-invalid", 8, "A carried intermediate credential_issuing credential (d77_leaf under the root) re-signs the unchanged rotation; it did not issue the predecessor.", (bundle) => {
      d77Credential(bundle, "d77_leaf", "credential_issuing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      const list = artifacts(bundle).rotations as CborValue[];
      list[0] = signDetached(payload(list[0]!), contentType(list[0]!), "d77_leaf").envelope;
    }],
    ["repair-d80-rotation-site-mismatch", "credential/rotation-invalid", 8, "Move the rotation record to a foreign site_id, recompute its ID, and re-sign it with the issuing root; both credentials stay on the original site.", (bundle) => {
      mutateArtifact(bundle, "rotations", () => true, (r) => { r.site_id = id16("d80-foreign-site"); });
    }],
    ["repair-d80-rotation-binding-before-rollback", "credential/rotation-invalid", 8, "Three rotations: records 0 and 2 reuse continuity_sequence 1 with increasing effective_at (a rollback); record 1 names a wrong predecessor_kid. Every record binds before ordering.", (bundle) => {
      const list = artifacts(bundle).rotations as CborValue[]; const original = list[0]!; const base = payload(original);
      const bad = clone(base); bad.predecessor_kid = deterministicId("d80-wrong-predecessor-kid"); bad.rotation_id = domainHash("AAR-ROTATION-ID-v1", withoutField(bad, "rotation_id"));
      for (let offset = 1; offset < 1024; offset += 1) {
        const late = clone(base); late.effective_at = (base.effective_at as number) + offset; late.rotation_id = domainHash("AAR-ROTATION-ID-v1", withoutField(late, "rotation_id"));
        const ids = [base.rotation_id!, bad.rotation_id!, late.rotation_id!].sort(compare);
        if (!same(ids[1], bad.rotation_id)) continue;
        list.push(resign(original, bad), resign(original, late)); sortArtifacts(bundle, "rotations"); return;
      }
      throw new Error("could not order D-80 rotation fixtures");
    }],
    ["repair-d80-root-rotation-successor-not-in-store", "credential/root-not-accepted", 8, "The root rotates to a self-signed successor root that the trust store does not carry; a rotation never makes its successor accepted.", (bundle) => d80RootRotation(bundle, false)],
    ["repair-d81-status-revoked-missing-revoked-at", "schema/missing-field", 6, "A refreshed snapshot says revoked without revoked_at.", statusRepair((s) => { s.status = "revoked"; })],
    ["repair-d81-status-compromised-missing-compromise-at", "schema/missing-field", 6, "A refreshed snapshot says compromised without compromise_at.", statusRepair((s) => { s.status = "compromised"; })],
    ["repair-d81-status-revoked-at-bad-type", "schema/bad-type", 6, "A refreshed revoked snapshot carries a text revoked_at.", statusRepair((s) => { s.status = "revoked"; s.revoked_at = "soon"; })],
    ["repair-d81-status-enum-unknown", "schema/enum-unknown", 6, "A refreshed snapshot carries status good2.", statusRepair((s) => { s.status = "good2"; })],
    ["repair-d81-status-revoked-unresolved-credential", "credential/revoked", 8, "A revoked snapshot naming no carried credential fails closed as if used at the evaluation time.", statusRepair((s) => { s.status = "revoked"; s.revoked_at = s.produced_at!; s.credential_id = deterministicId("d81-missing-credential"); })],
    ["repair-d81-status-good-unresolved-credential", "credential/status-missing", 8, "A good snapshot naming no carried credential; content passes, then the reference fails.", statusRepair((s) => { s.credential_id = deterministicId("d81-missing-credential"); })],
    ["repair-d81-status-verifier-revoked", "credential/revoked", 8, "A revoked snapshot names the verifier_signing credential, effective at evaluation time: signing the verdict is a use.", statusRepair((s, evaluation, b) => { s.status = "revoked"; s.revoked_at = evaluation; s.credential_id = credentialId(b, "verifier_signing"); })],
    ["repair-d81-status-profile-enum-unknown", "schema/enum-unknown", 6, "A refreshed snapshot carries profile AAR-9 with a 5000 s lease; the closed profile enum fails before any lease arithmetic.", statusRepair((s) => { s.profile = "AAR-9"; s.lease_not_after = (s.lease_not_before as number) + 5000; })],
    ["repair-d81-status-stale-next-update-boundary", "credential/status-stale", 8, "A refreshed snapshot whose next_update equals the evaluation time (half-open).", statusRepair((s, evaluation) => { s.next_update = evaluation; })],
    ["repair-d81-status-stale-before-revoked", "credential/status-stale", 8, "Stale AND revoked before the EP key's earliest use; freshness fires first.", statusRepair((s, evaluation, b) => { s.next_update = evaluation; s.status = "revoked"; s.revoked_at = Math.min(...useTimes(b, TEST_KEYS.ep_signing.kid)); })],
    // Round 2: malformed time/sequence fields fail at step 6 before any arithmetic; the two lifecycle twins put the re-mutated originals under the byte gate.
    ["repair-d81-status-next-update-bad-type", "schema/bad-type", 6, "A refreshed snapshot carries a text next_update.", statusRepair((s) => { s.next_update = "future"; })],
    ["repair-d81-status-bad-type", "schema/bad-type", 6, "A refreshed snapshot carries status false; the type gate precedes the enum.", statusRepair((s) => { s.status = false; })],
    ["repair-d80-rotation-effective-at-bad-type", "schema/bad-type", 6, "A second rotation carries a text effective_at.", (bundle) => addRotation(bundle, (r) => { r.effective_at = "later"; })],
    ["repair-d81-anchor-accepted-at-missing", "schema/missing-field", 6, "Remove accepted_at from the anchor record and re-sign it.", (bundle) => mutateArtifact(bundle, "anchors", () => true, (a) => { delete a.accepted_at; })],
    ["repair-d81-request-issued-at-missing", "schema/missing-field", 6, "Remove freshness.issued_at from the agent request, re-sign it, and repair the root commitment.", (bundle) => divergeRequest(bundle, (claims) => { delete (claims.freshness as Obj).issued_at; })],
    ["repair-d81-status-revoked-before-use", "credential/revoked", 8, "Twin of credential-revoked: the stapled snapshot is revoked effective at the EP key's earliest signing time.", (bundle) => mutateArtifact(bundle, "status_snapshots", () => true, (s) => revokedBeforeUse(s, bundle))],
    ["repair-d81-status-compromised-before-use", "credential/compromised", 8, "Twin of credential-compromised: the stapled snapshot is compromised effective at the EP key's earliest signing time.", (bundle) => mutateArtifact(bundle, "status_snapshots", () => true, (s) => compromisedBeforeUse(s, bundle))],
    ["repair-d81-anchor-credential-not-yet-valid-at-use", "credential/not-yet-valid", 6, "The anchor_signing credential becomes valid one second after its anchor record's accepted_at, still before evaluation.", (bundle) => {
      const anchor = payload((artifacts(bundle).anchors as CborValue[])[0]!);
      mutateArtifact(bundle, "credentials", (p) => same(p.subject_kid, TEST_KEYS.anchor_signing.kid), (p) => { p.valid_from = (anchor.accepted_at as number) + 1; });
    }],
  ];
  for (const [name, code, step, description, mutate] of d79to81Repairs) {
    const item = bundleFixture(code, description, mutate);
    add({ ...item, filename: name, descriptor: { ...item.descriptor, name, expected_result: "nonconformant", expected_step: step } });
  }

  // D-82 repairs: ordering at step 3, per-envelope traversal at step 6.
  const d82Repairs: [string, string, number, string, (bundle: Obj) => void][] = [
    ["repair-d82-order-before-signature", "schema/unsorted-set", 3, "Reverse the receipt array and corrupt the first credential's signature; artifact order is judged at step 3 before any envelope is verified.", (bundle) => {
      (artifacts(bundle).receipts as CborValue[]).reverse();
      modifyCose(bundle, "credentials", 0, (value) => { const signature = new Uint8Array(value[3] as Uint8Array); signature[0] = signature[0]! ^ 1; value[3] = signature; });
    }],
    ["repair-d82-sig-before-later-origins", "sig/verify-failed", 6, "Corrupt credentials[0]'s signature and give a later inference a non-array origins; each envelope completes sub-steps 1 to 9 before the next is decoded.", (bundle) => {
      modifyCose(bundle, "credentials", 0, (value) => { const signature = new Uint8Array(value[3] as Uint8Array); signature[0] = signature[0]! ^ 1; value[3] = signature; });
      mutateReceiptsCascade(bundle, (p) => p.kind === "inference", (p) => { (p.body as Obj).origins = "principal"; });
    }],
    ["repair-d82-embedded-delegation-before-later-receipt", "schema/enum-unknown", 6, "The approval authorization's embedded delegation carries use twice (re-identified, re-signed, decision repaired; replay_domain salted so the authorization sorts before another receipt) and the next receipt in array order carries a corrupted signature; a traversal that visited every receipt before its embedded delegation would report sig/verify-failed.", (bundle) => {
      for (let salt = 0; salt < 1024; salt += 1) {
        const candidate = clone(bundle);
        mutateReceiptWhere(candidate, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => {
          const body = p.body as Obj; const d = clone(payload(body.delegation!)); d.use = "twice"; d.replay_domain = deterministicId(`d82-pin:${salt}`);
          d.delegation_id = domainHash("AAR-DELEGATION-ID-v1", withoutField(d, "delegation_id"));
          body.delegation = resign(body.delegation!, d);
          const decision = body.decision as Obj; decision.delegation_id = d.delegation_id!;
          decision.decision_commitment = domainHash("AAR-DECISION-RECORD-v1", withoutField(decision, "decision_commitment"));
        });
        const list = receiptList(candidate);
        const index = list.findIndex((entry) => { const d = payload(entry); return d.kind === "authorization" && (d.body as Obj).presentation !== undefined; });
        if (index + 1 < list.length) { list[index + 1] = flipSignature(list[index + 1]!); Object.assign(bundle, candidate); return; }
      }
      throw new Error("no salt places the authorization before another receipt");
    }],
  ];
  // D-82 stage 2: outcome subject edge (part 5), cross-epoch binding and late
  // insertion (part 7), transitive chains (part 9), the step-20 verdict (part 10).
  const chainRepair = (mutateParent: (parent: Obj) => void) => (bundle: Obj): void => {
    const parent = addTopLevelDelegation(bundle, mutateParent);
    mutateEmbeddedDelegation(bundle, (d) => { d.parent_delegations = [parent.delegation_id!]; });
  };
  d82Repairs.push(
    ["receipt-outcome-no-subject-edge", "receipt/outcome-subject-mismatch", 10, "The outcome observation carries only a supports parent (the derived observation) and no observed_outcome edge.", (bundle) => {
      const observation = payload(receiptBy(bundle, (p) => p.kind === "observation" && !object(p.root)));
      mutateReceipt(bundle, "outcome_observation", (p) => {
        const edge = clone((p.parents as Obj[])[0]!); edge.edge_type = "supports"; edge.parent_id = observation.receipt_id!; edge.parent_kind = "observation";
        p.parents = [edge]; (p.freshness as Obj).intended_parents = [edge.parent_id!];
      });
    }],
    ["receipt-outcome-two-subject-edges", "receipt/outcome-subject-mismatch", 10, "The outcome observation carries observed_outcome edges to both the dispatch and its attempt; the subject still names the dispatch.", (bundle) => {
      const attempt = payload(receiptBy(bundle, (p) => p.kind === "action_attempt" && (p.body as Obj).disposition === "eligible_for_dispatch"));
      mutateReceipt(bundle, "outcome_observation", (p) => {
        const edge = clone((p.parents as Obj[])[0]!); edge.parent_id = attempt.receipt_id!; edge.parent_kind = "action_attempt";
        (p.parents as Obj[]).push(edge); (p.freshness as Obj).intended_parents = (p.parents as Obj[]).map((e) => e.parent_id!);
      });
    }],
    ["graph-cross-epoch-wrong-epoch-manifest", "graph/cross-epoch-unanchored", 12, "A historical edge from epoch 42 into 43 names a carried, anchored manifest of epoch 41 under the same owner.", (bundle) => {
      const { manifest, anchor } = addManifestWithAnchor(bundle, 41, "ep_signing");
      crossEpochChild(bundle, manifest.manifest_id as Uint8Array, anchor.anchor_id as Uint8Array);
    }],
    ["graph-cross-epoch-same-number-other-owner", "graph/cross-epoch-unanchored", 12, "A historical edge from epoch 42 into 43 names a carried, anchored epoch-42 manifest of a different owner (an outsider EP).", (bundle) => {
      d77Credential(bundle, "d77_outsider", "ep_signing", "credential_issuing", [d77Root(bundle).credential_id!], "credential_issuing");
      const { manifest, anchor } = addManifestWithAnchor(bundle, 42, "d77_outsider");
      crossEpochChild(bundle, manifest.manifest_id as Uint8Array, anchor.anchor_id as Uint8Array);
    }],
    ["repair-d82-late-for-epoch-equal", "epoch/late-insertion", 14, "The outcome observation declares late_for_epoch_id equal to its own epoch_id; no manifest is carried.", (bundle) => {
      clearJournal(bundle);
      mutateReceipt(bundle, "outcome_observation", (p) => { (p.binding as Obj).late_for_epoch_id = (p.binding as Obj).epoch_id!; });
    }],
    ["repair-d82-branching-chain", "epoch/event-chain", 14, "A second close event reuses event_seq 1 with a different previous_event_digest: conflicting chains fail at chain linkage, before any fork rule.", (bundle) => {
      const list = artifacts(bundle).epoch_events as CborValue[];
      const close = list.find((entry) => payload(entry).event === "close")!;
      const next = clone(payload(close)); next.previous_event_digest = deterministicId("d82-branch");
      next.event_id = domainHash("AAR-EPOCH-EVENT-ID-v1", withoutField(next, "event_id"));
      list.push(resign(close, next)); sortArtifacts(bundle, "epoch_events");
    }],
    ["repair-d82-chain-scope-widened", "delegation/chain-invalid", 13, "The embedded delegation names a carried parent whose actions omit the child's camera.stream.view.", chainRepair((d) => { (d.scope as Obj).actions = ["camera.ptz.preset"]; })],
    ["repair-d82-chain-grandparent-missing", "delegation/chain-invalid", 13, "The embedded delegation names a carried parent that names an uncarried grandparent.", chainRepair((d) => { d.parent_delegations = [deterministicId("d82-missing-grandparent")]; })],
    ["repair-d82-chain-use-widened", "delegation/chain-invalid", 13, "The embedded reusable delegation names a carried one_time parent.", chainRepair((d) => { d.use = "one_time"; })],
    ["graph-cross-epoch-reason-not-text", "graph/cross-epoch-forbidden", 12, "A cross-epoch link whose reason is an empty list; formerly an uncaught TypeError in pyref.", (bundle) => {
      const manifest = payload((artifacts(bundle).epoch_manifests as CborValue[])[0]!); const anchor = payload((artifacts(bundle).anchors as CborValue[])[0]!);
      crossEpochChild(bundle, manifest.manifest_id as Uint8Array, anchor.anchor_id as Uint8Array);
      mutateReceiptWhere(bundle, (p) => p.kind === "observation" && !object(p.root), (p) => { (((p.parents as Obj[])[0]!).cross_epoch as Obj).reason = []; });
    }],
    ["repair-d82-delegation-scope-not-map", "delegation/scope", 13, "The embedded delegation's scope is the integer 5; formerly an uncaught TypeError in pyref.", (bundle) => mutateEmbeddedDelegation(bundle, (d) => { d.scope = 5; })],
    ["repair-d82-delegation-scope-actions-not-array", "delegation/scope", 13, "The embedded delegation's scope.actions is the integer 5.", (bundle) => mutateEmbeddedDelegation(bundle, (d) => { (d.scope as Obj).actions = 5; })],
    ["epoch-manifest-duration-exceeded", "epoch/duration-exceeded", 14, "The manifest's opened_at precedes its closed_at by more than 86,400 s while the open/close events stay within; the manifest pair is judged first.", (bundle) => {
      rebuildManifest(bundle, (m) => { m.opened_at = (m.opened_at as number) - 200_000; }, true);
    }],
    // Stage B (round 2): parity on malformed inputs.
    ["repair-d82-presentation-null", "schema/bad-type", 6, "The approval authorization carries presentation: null; a present null nested envelope is a step-6 type failure (amendment g).", (bundle) => mutateReceiptWhere(bundle, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => { (p.body as Obj).presentation = null; })],
    ["repair-d82-delegation-null", "schema/bad-type", 6, "The approval authorization carries delegation: null.", (bundle) => mutateReceiptWhere(bundle, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => { (p.body as Obj).delegation = null; })],
    ["repair-d82-credential-envelope-three-elements", "schema/bad-type", 6, "The root credential envelope carries a third element; both loose indexes still resolve it for the earlier credential, and it fails at its own position (amendment f).", (bundle) => {
      const list = artifacts(bundle).credentials as CborValue[];
      const index = list.findIndex((entry) => (payload(entry).path as CborValue[]).length === 0);
      list[index] = [...(list[index] as CborValue[]), 0];
    }],
    ["repair-d82-cose-protected-empty-map", "cose/alg-missing", 6, "The first credential's protected bstr holds an empty map (amendment h).", (bundle) => modifyCose(bundle, "credentials", 0, (value) => { value[0] = encodeCbor(new Map<CborScalar, CborValue>()); })],
    ["repair-d82-cose-protected-undecodable", "cose/protected-not-map", 6, "The first credential's protected bstr does not decode (amendment h).", (bundle) => modifyCose(bundle, "credentials", 0, (value) => { value[0] = Uint8Array.of(0xff); })],
    ["repair-d82-sig-r-at-order", "sig/verify-failed", 6, "The first credential's signature carries r equal to the group order with its original low s; sub-step 5 passes, verification fails (amendment h).", (bundle) => modifyCose(bundle, "credentials", 0, (value) => { value[3] = concat(bigint32(P256_ORDER), (value[3] as Uint8Array).slice(32)); })],
    ["repair-d82-selector-kinds-duplicate-unsorted", "schema/unsorted-set", 3, "receipt_kinds [inference, observation, inference]: the first disordered pair is reported before the later duplicate (amendment i).", (bundle) => { (bundle.selector as Obj).receipt_kinds = ["inference", "observation", "inference"]; recalcSelector(bundle); }],
    ["repair-d82-trust-inputs-missing", "schema/missing-field", 3, "The bundle has no trust_inputs member (amendment j).", (bundle) => { delete bundle.trust_inputs; }],
    ["repair-d82-graph-dangling-before-root-missing", "graph/dangling-parent", 12, "The epoch-seq-0 observation lacks its root descriptor and the later derived observation names a parent nobody carries; parents are resolved over every receipt before root rules (amendment c).", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, (p) => p.kind === "observation");
      mutateReceiptWhere(bundle, (p) => object(p.root), (p) => { delete p.root; });
      mutateReceiptWhere(bundle, (p) => (p.parents as CborValue[]).length > 0, (p) => { ((p.parents as Obj[])[0]!).parent_id = deterministicId("d82-dangling"); (p.freshness as Obj).intended_parents = [deterministicId("d82-dangling")]; });
    }],
    // Round 3 (B-11): step-12 artifact order and root guard, step-13 guarded scope reads.
    ["repair-d82-graph-root-order-artifact", "graph/root-forbidden", 12, "Two parentless receipts: the inference root (smaller receipt_id, epoch_seq 1) carries a standing_condition_trigger root, forbidden for an inference; the observation root (larger receipt_id, epoch_seq 0) lacks its descriptor. Artifact order reports root-forbidden; epoch_seq order would report root-missing. The observation's nonce is salted until the ids order that way.", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, (p) => (p.parents as CborValue[]).length === 0 && p.kind !== "authorization");
      mutateReceiptWhere(bundle, (p) => p.kind === "inference", (p) => { (p.root as Obj).kind = "standing_condition_trigger"; });
      const inferenceId = payload(receiptBy(bundle, (p) => p.kind === "inference")).receipt_id!;
      for (let salt = 0; salt < 1024; salt += 1) {
        const candidate = clone(bundle);
        mutateReceiptWhere(candidate, (p) => p.kind === "observation", (p) => { delete p.root; (p.freshness as Obj).nonce = id16(`d82-root-order:${salt}`); });
        if (compare(inferenceId, payload(receiptBy(candidate, (p) => p.kind === "observation")).receipt_id!) < 0) { Object.assign(bundle, candidate); return; }
      }
      throw new Error("no salt orders the observation after the inference");
    }],
    ["repair-d82-root-not-map", "graph/root-missing", 12, "The parentless observation's root is the integer 5; formerly an AttributeError at step 7 in pyref.", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, (p) => (p.parents as CborValue[]).length === 0);
      mutateReceiptWhere(bundle, (p) => p.kind === "observation", (p) => { p.root = 5; });
    }],
    ["repair-d82-root-kind-missing", "graph/root-forbidden", 12, "The parentless observation's root lacks kind; formerly a KeyError at step 12 in pyref.", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, (p) => (p.parents as CborValue[]).length === 0);
      mutateReceiptWhere(bundle, (p) => p.kind === "observation", (p) => { delete (p.root as Obj).kind; });
    }],
    ["repair-d82-attempt-legal-not-map", "delegation/scope", 13, "The dispatched attempt's legal is the integer 5; its purpose is not contained (amendment o).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "action_attempt" && (p.body as Obj).disposition === "eligible_for_dispatch", (p) => { p.legal = 5; })],
    ["repair-d82-decision-profile-missing", "delegation/scope", 13, "The permit authorization's decision lacks profile (commitment recomputed); the profile is not contained (amendment o).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "authorization" && ((p.body as Obj).decision as Obj).decision === "permit", (p) => {
      const decision = (p.body as Obj).decision as Obj; delete decision.profile;
      decision.decision_commitment = domainHash("AAR-DECISION-RECORD-v1", withoutField(decision, "decision_commitment"));
    })],
    // Round 4 (B-14): reference lookups through guards (amendment q), presentation ordinals (amendment r).
    ["repair-d82-issuer-role-list", "receipt/signer-role-mismatch", 6, "The outcome observation's issuer_role is a list, mirrored in protected -70006; a non-text role matches no role (amendment q).", (bundle) => mutateReceipt(bundle, "outcome_observation", (p) => { p.issuer_role = ["outcome_observer"]; })],
    ["repair-d82-credential-path-member-not-bytes", "credential/path-invalid", 8, "The verifier credential's path is [5].", (bundle) => mutateArtifact(bundle, "credentials", (p) => p.key_usage === "verifier_signing", (p) => { p.path = [5]; })],
    ["repair-d82-rotation-successor-id-not-bytes", "credential/rotation-invalid", 8, "The rotation's successor_credential_id is the integer 5.", (bundle) => mutateArtifact(bundle, "rotations", () => true, (p) => { p.successor_credential_id = 5; })],
    ["repair-d82-status-credential-id-not-bytes", "credential/status-missing", 8, "A refreshed good snapshot names credential_id 5.", (bundle) => addStatusSnapshot(bundle, (s) => { s.credential_id = 5; })],
    ["repair-d82-status-snapshot-id-member-not-bytes", "credential/status-missing", 8, "The permit authorization's decision.status_snapshot_ids is [5] (commitment recomputed).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "authorization" && ((p.body as Obj).decision as Obj).decision === "permit", (p) => {
      const decision = (p.body as Obj).decision as Obj; decision.status_snapshot_ids = [5];
      decision.decision_commitment = domainHash("AAR-DECISION-RECORD-v1", withoutField(decision, "decision_commitment"));
    })],
    ["repair-d82-close-manifest-id-missing", "epoch/span-count-mismatch", 14, "The close event's body lacks manifest_id (event re-identified, chain relinked); the manifest falls back to the only carried one and the close names none.", (bundle) => { mutateArtifact(bundle, "epoch_events", (p) => p.event === "close", (p) => { delete (p.body as Obj).manifest_id; }); relinkEventChain(bundle); }],
    ["repair-d82-close-item-count-list", "epoch/span-count-mismatch", 14, "The close event's body item_count is a one-element list.", (bundle) => { mutateArtifact(bundle, "epoch_events", (p) => p.event === "close", (p) => { (p.body as Obj).item_count = [10]; }); relinkEventChain(bundle); }],
    ["repair-d82-merkle-batch-id-not-bytes", "schema/bad-type", 3, "The carried Merkle proof's batch_id is the integer 5; every member of a membership proof is typed at step 3 (amendment ab; round 4 had pinned merkle/batch-binding at 16).", (bundle) => { ((artifacts(bundle).merkle_proofs as Obj[])[0]!).batch_id = 5; }],
    ["repair-d82-anchor-manifest-id-not-bytes", "anchor/target-unplanned", 17, "The anchor record's manifest_id is the integer 5 (record re-identified, re-signed): an unresolved manifest has no plan, so the target is unplanned (step-17 order).", (bundle) => mutateArtifact(bundle, "anchors", () => true, (p) => { p.manifest_id = 5; })],
    ["repair-d82-range-manifest-id-missing", "schema/missing-field", 3, "The complete range lacks manifest_id; every member of a range proof is checked at step 3 (amendment ab; round 4 had pinned bundle/range-manifest-missing at 18).", (bundle) => { makeCompleteRange(bundle); delete (bundle.ranges as Obj[])[0]!.manifest_id; }],
    ["repair-d82-attestation-id-31-bytes", "evidence/time-class-unsatisfied", 19, "The inference root declares boot_bound time with a 31-byte boot_attestation_id; a non-32-byte id resolves to nothing (pyref formerly said manifest/payload-missing).", (bundle) => { clearJournal(bundle); keepReceipts(bundle, (p) => p.kind === "inference" && object(p.root)); mutateReceiptWhere(bundle, () => true, (p) => { const time = (p.evidence as Obj).time as Obj; time.class = "boot_bound"; time.boot_attestation_id = new Uint8Array(31); }); }],
    ["repair-d82-presentation-artifacts-ordinals", "receipt/manifest-inconsistent", 10, "The approval presentation carries two artifacts with ordinals [1, 0] (re-identified, re-signed); the round-3 harness never checked presentation ordinals.", (bundle) => mutatePresentation(bundle, (p) => { const first = (p.artifacts as Obj[])[0]!; p.artifacts = [{ ...first, ordinal: 1 }, { ...first, ordinal: 0 }]; })],
    ["repair-d82-presentation-artifacts-item-not-map", "receipt/manifest-inconsistent", 10, "The approval presentation's first artifact is the integer 5.", (bundle) => mutatePresentation(bundle, (p) => { p.artifacts = [5]; })],
    // Round 6 stage A (B-20): spec contradictions.
    ["repair-d82-delegation-scope-null", "delegation/scope", 13, "The embedded delegation's scope is null (amendment l; the harness had dereferenced it).", (bundle) => mutateEmbeddedDelegation(bundle, (d) => { d.scope = null; })],
    ["repair-d82-root-kind-list", "graph/root-forbidden", 12, "The parentless observation's root kind is a one-element list (amendment p; pyref had used it as a dict key).", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, (p) => (p.parents as CborValue[]).length === 0);
      mutateReceiptWhere(bundle, (p) => p.kind === "observation", (p) => { (p.root as Obj).kind = ["agent_request"]; });
    }],
    ["repair-d82-root-kind-constructor", "graph/root-forbidden", 12, "The parentless observation's root kind is the text constructor; own-property lookup leaves it unlisted (amendment af).", (bundle) => {
      clearJournal(bundle); keepReceipts(bundle, (p) => (p.parents as CborValue[]).length === 0);
      mutateReceiptWhere(bundle, (p) => p.kind === "observation", (p) => { (p.root as Obj).kind = "constructor"; });
    }],
    ["repair-d82-edge-type-constructor", "graph/edge-illegal", 12, "The derived observation's derived_from edge_type is the text constructor; own-property lookup leaves it unlisted (amendment af).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "observation" && !object(p.root), (p) => { ((p.parents as Obj[])[0]!).edge_type = "constructor"; })],
    ["repair-d82-scope-mixed-keys", "delegation/scope", 13, "The embedded delegation's scope is a map with text and integer keys (amendment af).", (bundle) => mutateEmbeddedDelegation(bundle, (d) => { d.scope = new Map<CborScalar, CborValue>([...Object.entries(d.scope as Obj), [1, 2]]); })],
    ["repair-d82-scope-purpose-null-contained", "delegation/scope", 13, "The dispatched attempt's legal.purpose_id is null and the delegation's purpose_ids is [null]; a non-text value is never contained (amendment ag).", (bundle) => {
      mutateEmbeddedDelegation(bundle, (d) => { (d.scope as Obj).purpose_ids = [null]; });
      mutateReceiptsCascade(bundle, (p) => p.kind === "action_attempt" && (p.body as Obj).disposition === "eligible_for_dispatch", (p) => { (p.legal as Obj).purpose_id = null; });
    }],
    ["repair-d82-scope-profile-int-contained", "delegation/scope", 13, "The permit decision's profile is 7 and the delegation's allowed_profiles is [7]; a non-text value is never contained (amendment ag).", (bundle) => {
      mutateEmbeddedDelegation(bundle, (d) => { (d.scope as Obj).allowed_profiles = [7]; });
      mutateReceiptsCascade(bundle, (p) => p.kind === "authorization" && ((p.body as Obj).decision as Obj).decision === "permit", (p) => {
        const decision = (p.body as Obj).decision as Obj; decision.profile = 7;
        decision.decision_commitment = domainHash("AAR-DECISION-RECORD-v1", withoutField(decision, "decision_commitment"));
      });
    }],
    ["repair-d82-root-null-with-parents", "graph/root-forbidden", 12, "The derived observation carries root: null beside its parents; a present null is a present root (amendment u).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "observation" && !object(p.root), (p) => { p.root = null; })],
    ["repair-d82-cross-epoch-null", "graph/cross-epoch-forbidden", 12, "The derived observation's same-epoch edge carries cross_epoch: null (amendment u).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "observation" && !object(p.root), (p) => { ((p.parents as Obj[])[0]!).cross_epoch = null; })],
    ["repair-d82-degraded-null", "receipt/attempt-disposition", 10, "The dispatched attempt's body.degraded is null (amendment u).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "action_attempt" && (p.body as Obj).disposition === "eligible_for_dispatch", (p) => { (p.body as Obj).degraded = null; })],
    ["repair-d82-hazard-class-null", "schema/enum-unknown", 10, "The dispatched attempt's action.hazard_class is null; a present non-life_safety value is unknown (amendment u).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "action_attempt" && (p.body as Obj).disposition === "eligible_for_dispatch", (p) => { ((p.body as Obj).action as Obj).hazard_class = null; })],
    ["repair-d82-event0-previous-null", "epoch/event-chain", 14, "The open event (event_seq 0) carries previous_event_digest: null; the chain is relinked after it (amendment u).", (bundle) => { mutateArtifact(bundle, "epoch_events", (p) => p.event_seq === 0, (p) => { p.previous_event_digest = null; }); relinkEventChain(bundle); }],
    ["repair-d82-manifest-predecessor-null", "epoch/predecessor-mismatch", 14, "The only manifest carries predecessor_manifest_digest: null (anchor rebound); a present value that is not a 32-byte digest mismatches (amendments u, w).", (bundle) => rebuildManifest(bundle, (m) => { m.predecessor_manifest_digest = null; }, true)],
    ["repair-d82-anchor-consistency-null", "schema/bad-type", 6, "The anchor record carries consistency: null; the optional proof is present and not a map (amendments u, ab).", (bundle) => mutateArtifact(bundle, "anchors", () => true, (p) => { p.consistency = null; })],
    ["repair-d82-manifest-predecessor-not-bytes", "epoch/predecessor-mismatch", 14, "The only manifest's predecessor_manifest_digest is the integer 5 (amendments u, w).", (bundle) => rebuildManifest(bundle, (m) => { m.predecessor_manifest_digest = 5; }, true)],
    ["repair-d82-anchor-consistency-unrelated", "anchor/consistency-invalid", 17, "The anchor carries a self-consistent proof (old = new = 1, equal roots, empty path) whose new head is not the record's anchor head (amendment x; pyref had accepted it).", (bundle) => mutateArtifact(bundle, "anchors", () => true, (p) => { p.consistency = { old_tree_size: 1, new_tree_size: 1, old_root: deterministicId("unrelated-tree"), new_root: deterministicId("unrelated-tree"), path: [] }; })],
    ["repair-d82-anchor-head-root-changed", "anchor/head-mismatch", 17, "The anchor record's head.root differs from the expected head at the same tree size (amendment y; the harness had compared anchor_root).", (bundle) => mutateArtifact(bundle, "anchors", () => true, (p) => { (p.head as Obj).root = deterministicId("other-head-root"); })],
    ["repair-d82-expected-head-larger-same-root", "anchor/head-mismatch", 17, "The expected head is one leaf larger than the record's head with the same root (amendment y; pyref had accepted it).", (bundle) => { const head = ((bundle.trust_inputs as Obj).expected_anchor_heads as Obj[])[0]!; head.tree_size = (head.tree_size as number) + 1; }],
    ["repair-d82-manifest-byte-length-mismatch", "hash/mismatch", 7, "The inference's prompt_manifest declares byte_length one more than the carried payload (amendment ac; the harness had not checked).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "inference", (p) => { const ref = (p.body as Obj).prompt_manifest as Obj; ref.byte_length = (ref.byte_length as number) + 1; })],
    ["repair-d82-presentation-id-mismatch", "identity/artifact-id-mismatch", 7, "The approval presentation's presentation_id does not recompute (re-signed; the authorization is re-identified around it) (amendment ac; the harness had said hash/mismatch).", (bundle) => mutateReceiptWhere(bundle, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => {
      const presentation = (p.body as Obj).presentation!; const next = clone(payload(presentation)); next.presentation_id = deterministicId("wrong-presentation-id");
      (p.body as Obj).presentation = signDetached(next, contentType(presentation), signerFor(presentation)).envelope;
    })],
    ["repair-d82-open-first-seq-mismatch", "epoch/span-count-mismatch", 14, "The open event's first_epoch_seq is one more than the manifest span's first (chain relinked) (amendment ad; the harness had not checked).", (bundle) => { mutateArtifact(bundle, "epoch_events", (p) => p.event === "open", (p) => { (p.body as Obj).first_epoch_seq = ((p.body as Obj).first_epoch_seq as number) + 1; }); relinkEventChain(bundle); }],
    ["repair-d82-range-boundary-proof-invalid", "bundle/range-proof-invalid", 18, "The complete range carries a left_boundary whose entry issuer_seq was changed after its proof was built (the harness had not verified boundary proofs).", (bundle) => { makeCompleteRange(bundle); const first = clone(((bundle.ranges as Obj[])[0]!.entries as Obj[])[0]!); (first.entry as Obj).issuer_seq = ((first.entry as Obj).issuer_seq as number) + 1; (bundle.ranges as Obj[])[0]!.left_boundary = first; }],
    ["repair-d82-provenance-on-observation", "evidence/provenance-class-unsatisfied", 10, "The root observation carries a provenance label its kind forbids (amendment ah; the harness had said receipt/kind-body-mismatch).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "observation" && object(p.root), (p) => { (p.evidence as Obj).provenance = { class: "self_asserted" }; })],
    ["repair-d82-outcome-label-on-wrong-kind", "evidence/outcome-class-unsatisfied", 10, "The root observation carries an outcome label its kind forbids (amendment ah).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "observation" && object(p.root), (p) => { (p.evidence as Obj).outcome = { level: "unknown" }; })],
    ["repair-d82-outcome-level-wrong-kind", "evidence/outcome-class-unsatisfied", 10, "The dispatched attempt's outcome level is dispatched, a level only a dispatch may carry (the harness had no per-kind level rule at step 10).", (bundle) => mutateReceiptsCascade(bundle, (p) => p.kind === "action_attempt" && (p.body as Obj).disposition === "eligible_for_dispatch", (p) => { ((p.evidence as Obj).outcome as Obj).level = "dispatched"; })],
    ["repair-d82-epoch-coordinate-equivocation", "identity/coordinate-equivocation", 9, "A second root observation reuses the first's epoch coordinate under another issuer_seq and nonce (amendment ah; pyref had said epoch-sequence-rollback).", (bundle) => {
      clearJournal(bundle);
      const envelope = receiptBy(bundle, (p) => p.kind === "observation" && object(p.root)); const next = clone(payload(envelope));
      (next.emission as Obj).issuer_seq = ((next.emission as Obj).issuer_seq as number) + 1000; (next.freshness as Obj).nonce = id16("equivocation");
      receiptList(bundle).push(resign(envelope, next, true)); sortArtifacts(bundle, "receipts");
    }],
    ["repair-d82-presentation-ordinal-bool", "receipt/manifest-inconsistent", 10, "The approval presentation's single artifact carries ordinal true; a bool is never a uint (amendment ah).", (bundle) => mutatePresentation(bundle, (p) => { ((p.artifacts as Obj[])[0]!).ordinal = true; })],
    ["repair-d82-cose-unprotected-text-label", "cose/unprotected-not-empty", 6, "The first credential's unprotected header is the text-keyed map {\"1\": 5}; a text label is not the alg label (amendment ah).", (bundle) => modifyCose(bundle, "credentials", 0, (value) => { value[1] = { "1": 5 }; })],
    ["repair-d82-trust-snapshot-zero", "schema/out-of-range", 5, "The trust store's snapshot_id is 32 zero bytes, the verdict's not-evaluated sentinel (digest recomputed) (amendment ah).", (bundle) => { (((bundle.trust_inputs as Obj).trust_store) as Obj).snapshot_id = new Uint8Array(32); recalcTrust(bundle); }],
    ["repair-d82-range-boundary-mismatch-and-bad-proof", "bundle/range-proof-invalid", 18, "The complete range's first entry proof names leaf_index 999 and its last entry is dropped: the proofs are judged before the temporal slice (amendment ai; the harness had said bundle/range-boundary).", (bundle) => { makeCompleteRange(bundle); const entries = (bundle.ranges as Obj[])[0]!.entries as Obj[]; (entries[0]!.inclusion as Obj).leaf_index = 999; entries.pop(); }],
    ["repair-d82-payload-depth-33", "resource/cbor-depth", 6, "The root observation's legal is 33 nested arrays (re-identified, re-signed, left in place: neither verifier sorts an array whose payload does not decode); the thirty-third nested container exceeds the bound inside a COSE payload (amendment ao).", (bundle) => {
      const list = receiptList(bundle); const index = list.findIndex((entry) => payload(entry).kind === "observation" && object(payload(entry).root)); const next = clone(payload(list[index]!)); next.legal = nest(33); list[index] = resign(list[index]!, next, true);
    }],
    ["repair-d82-parent-delegation-invocation-null", "delegation/chain-invalid", 13, "A carried parent delegation carries invocation_id: null and the embedded child none; a present null never equals an absent member (amendment u; pyref had compared None with None).", (bundle) => {
      const parent = addTopLevelDelegation(bundle, (d) => { d.invocation_id = null; (d.scope as Obj).actions = ["camera.ptz.preset", "camera.stream.view"]; (d.scope as Obj).allowed_profiles = ["AAR-1", "AAR-2", "AAR-2A", "AAR-3"]; d.not_before = (d.not_before as number) - 100; d.not_after = (d.not_after as number) + 100; d.replay_domain = deterministicId("u:parent"); });
      mutateEmbeddedDelegation(bundle, (d) => { d.parent_delegations = [parent.delegation_id!]; delete d.invocation_id; });
    }],
    ["repair-d82-anchor-target-id-int-planned", "anchor/target-unplanned", 17, "The plan's first target and the anchor record's target both carry target_id 5; a non-16-byte id resolves to nothing (amendment q; the harness had matched 5 to 5 and gone on to an indeterminate head-missing).", (bundle) => { rebuildManifest(bundle, (m) => { (((m.anchor_plan as Obj).targets as Obj[])[0]!).target_id = 5; }, true); mutateArtifact(bundle, "anchors", () => true, (p) => { (p.target as Obj).target_id = 5; }); }],
    ["repair-d82-merkle-path-length-impossible", "merkle/path-length", 16, "The carried Merkle proof carries one sibling more than its tree size admits (amendment ak).", (bundle) => { const proof = (artifacts(bundle).merkle_proofs as Obj[])[0]!; proof.siblings = [...(proof.siblings as Uint8Array[]), hash(encodeCbor("extra-sibling"))]; }],
    ["repair-d82-complete-extra-unindexed-receipt", "bundle/artifact-out-of-scope", 18, "A complete bundle carries a second root observation committed before the selector window that no index entry names and nothing selected reaches (amendment aj; the harness had tolerated unindexed extras).", (bundle) => {
      makeCompleteRange(bundle);
      const envelope = receiptBy(bundle, (p) => p.kind === "observation" && object(p.root)); const next = clone(payload(envelope)); const t = ((bundle.selector as Obj).committed_from as number) - 1;
      (next.binding as Obj).epoch_seq = 777; (next.emission as Obj).issuer_seq = 7777; (next.emission as Obj).committed_at = t; (next.freshness as Obj).issued_at = t - 1; (next.freshness as Obj).nonce = id16("extra-unindexed");
      receiptList(bundle).push(resign(envelope, next, true)); sortArtifacts(bundle, "receipts");
    }],
    ["repair-d82-range-below-previous-range", "bundle/range-noncontiguous", 18, "The selector window starts at a later index entry; range 1 is the valid slice and range 2 carries leaf 0 with a bad sibling: ranges of one manifest must carry strictly increasing leaf indices, judged before the proofs (amendment al; pyref had said range-proof-invalid).", (bundle) => {
      const manifest = payload((artifacts(bundle).epoch_manifests as CborValue[])[0]!); const entries = (manifest.receipt_index as Obj).entries as Obj[];
      const k = entries.findIndex((entry) => (entry.committed_at as number) > (entries[0]!.committed_at as number)); if (k < 0) throw new Error("all entries share committed_at");
      (bundle.selector as Obj).committed_from = entries[k]!.committed_at; recalcSelector(bundle); makeCompleteRange(bundle);
      const bad = indexProofs(manifest)[0]!; ((bad.inclusion as Obj).siblings as Uint8Array[])[0] = hash(encodeCbor("flip"));
      (bundle.ranges as Obj[]).push({ manifest_id: manifest.manifest_id!, selector_commitment: bundle.selector_commitment!, tree_size: (manifest.receipt_index as Obj).leaf_count!, first_leaf_index: 0, entries: [bad] });
    }],
    ["repair-d82-step7-receipt-hash-before-presentation-id", "hash/mismatch", 7, "The approval authorization's decision_commitment and its own presentation's presentation_id are both wrong; a receipt's commitments precede its nested presentation's id (amendment am).", (bundle) => mutateReceiptWhere(bundle, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => {
      ((p.body as Obj).decision as Obj).decision_commitment = deterministicId("wrong-decision-commitment");
      const presentation = (p.body as Obj).presentation!; const next = clone(payload(presentation)); next.presentation_id = deterministicId("wrong-presentation-id");
      (p.body as Obj).presentation = signDetached(next, contentType(presentation), signerFor(presentation)).envelope;
    })],
    ["repair-d82-step7-presentation-id-before-later-receipt", "identity/artifact-id-mismatch", 7, "The approval authorization's presentation_id is wrong and a later receipt's (the inference's, nonce salted until it sorts after the authorization) conclusion digest is wrong; the earlier receipt's nested id is reported first (amendment am; the harness had checked every id before any receipt).", (bundle) => {
      for (let salt = 0; salt < 2048; salt += 1) {
        const candidate = clone(bundle);
        mutateReceiptsCascade(candidate, (p) => p.kind === "inference", (p) => { ((p.body as Obj).conclusion as Obj).digest = deterministicId("wrong-conclusion-digest"); (p.freshness as Obj).nonce = id16(`step7-order:${salt}`); });
        mutateReceiptWhere(candidate, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined, (p) => {
          const presentation = (p.body as Obj).presentation!; const next = clone(payload(presentation)); next.presentation_id = deterministicId("wrong-presentation-id");
          (p.body as Obj).presentation = signDetached(next, contentType(presentation), signerFor(presentation)).envelope;
        });
        const authorizationId = payload(receiptBy(candidate, (p) => p.kind === "authorization" && (p.body as Obj).presentation !== undefined)).receipt_id!;
        const inferenceId = payload(receiptBy(candidate, (p) => p.kind === "inference")).receipt_id!;
        if (compare(authorizationId, inferenceId) < 0) { Object.assign(bundle, candidate); return; }
      }
      throw new Error("no salt orders the authorization before the inference");
    }],
    ["repair-d82-cose-truncated", "cbor/malformed", 6, "The first credential's COSE bstr lacks its last byte; an undecodable item takes the decoder's own code (amendment an; the harness had said cose/bad-structure).", (bundle) => modifyCose(bundle, "credentials", 0, (_value, envelope) => { envelope[1] = (envelope[1] as Uint8Array).slice(0, -1); })],
    ["repair-d82-cose-nested-tag", "cbor/tag-forbidden", 6, "The first credential's COSE signature bstr is wrapped in tag 24 inside the COSE array; a tag nested inside the item is cbor/tag-forbidden, cose/tagged is the wrapping tag only (amendment aq).", (bundle) => modifyCose(bundle, "credentials", 0, (_value, envelope) => {
      const c = envelope[1] as Uint8Array; if (c[c.length - 66] !== 0x58 || c[c.length - 65] !== 0x40) throw new Error("signature shape"); envelope[1] = concat(c.slice(0, -66), Uint8Array.of(0xd8, 0x18), c.slice(-66));
    })],
    ["repair-d82-verifier-key-not-found", "key/not-found", 20, "Drop the verifier_signing credential; the bundle reaches step 20 and the verdict is a signed indeterminate populated per the section 5 table.", (bundle) => {
      artifacts(bundle).credentials = (artifacts(bundle).credentials as CborValue[]).filter((entry) => payload(entry).key_usage !== "verifier_signing");
    }],
  );
  for (const [name, code, step, description, mutate] of d82Repairs) {
    const item = bundleFixture(code, description, mutate);
    add({ ...item, filename: name, descriptor: { ...item.descriptor, name, expected_result: code === "key/not-found" ? "indeterminate" : "nonconformant", expected_step: step } });
  }

  // D-82 part 8: the bounded step-6 schema table. One enum row each, then per
  // production one missing, one wrong-type, and one paired fault. A missing
  // top-level field is caught by the closed-map pass before the CDDL-ordered
  // traversal, so paired faults on flat productions pair a wrong type with an
  // unknown enum; receipts pair a nested absence with an enum, both orders.
  // The verifier credential signs nothing and no earlier credential resolves it;
  // the root is resolved (loosely) by credentials[0]'s signer lookup first.
  const credential = (p: Obj) => p.key_usage === "verifier_signing";
  const root = (p: Obj) => p.kind === "observation" && object(p.root);
  const schemaTable: [string, string, string, (bundle: Obj) => void][] = [
    ["schema-enum-credential-principal-role", "schema/enum-unknown", "Verifier credential principal_role root.", (b) => mutateArtifact(b, "credentials", credential, (p) => { p.principal_role = "root"; })],
    ["schema-enum-credential-key-usage", "schema/enum-unknown", "Verifier credential key_usage signing.", (b) => mutateArtifact(b, "credentials", credential, (p) => { p.key_usage = "signing"; })],
    ["schema-enum-delegation-use", "schema/enum-unknown", "Top-level delegation use twice.", (b) => mutateArtifact(b, "delegations", () => true, (p) => { p.use = "twice"; })],
    ["schema-enum-epoch-event-event", "schema/enum-unknown", "Last event event reopen.", (b) => mutateLastEvent(b, (p) => { p.event = "reopen"; })],
    ["schema-enum-manifest-close-reason", "schema/enum-unknown", "Manifest close_reason manual.", (b) => rebuildManifest(b, (p) => { p.close_reason = "manual"; }, true)],
    ["schema-enum-manifest-late-arrival-policy", "schema/enum-unknown", "Manifest late_arrival_policy same_epoch.", (b) => rebuildManifest(b, (p) => { p.late_arrival_policy = "same_epoch"; }, true)],
    ["schema-enum-manifest-fork-policy", "schema/enum-unknown", "Manifest fork_policy accept.", (b) => rebuildManifest(b, (p) => { p.fork_policy = "accept"; }, true)],
    ["schema-enum-transformation-operation", "schema/enum-unknown", "Root observation consumption item transformation operation rotate.", (b) => mutateReceiptsCascade(b, root, (p) => { (((p.body as Obj).consumption as Obj).items as Obj[])[0]!.transformations = [{ ...TRANSFORM, operation: "rotate" }]; })],
    ["schema-enum-correlation-phase", "schema/enum-unknown", "Root observation correlation phase settled.", (b) => mutateReceiptsCascade(b, root, (p) => { (p.correlation as Obj).phase = "settled"; })],
    ["schema-enum-native-attestation-format", "schema/enum-unknown", "Root observation native attestation format sigstore.", (b) => mutateReceiptsCascade(b, root, (p) => { ((p.body as Obj).native_attestations as Obj[])[0]!.format = "sigstore"; })],
    ["schema-enum-action-informational-reversibility", "schema/enum-unknown", "Action attempt informational_reversibility partially.", (b) => mutateReceiptsCascade(b, (p) => p.kind === "action_attempt", (p) => { ((p.body as Obj).action as Obj).informational_reversibility = "partially"; })],
    ["schema-enum-action-operational-reversibility", "schema/enum-unknown", "Action attempt operational_reversibility partial.", (b) => mutateReceiptsCascade(b, (p) => p.kind === "action_attempt", (p) => { ((p.body as Obj).action as Obj).operational_reversibility = "partial"; })],
    ["schema-enum-outcome-state", "schema/enum-unknown", "Outcome observation body state pending.", (b) => mutateReceipt(b, "outcome_observation", (p) => { (p.body as Obj).state = "pending"; })],
    ["schema-enum-evidence-time-class", "schema/enum-unknown", "Root observation evidence time class gps_bound; formerly an uncaught KeyError in pyref and an unvalidated string in the harness verdict.", (b) => mutateReceiptsCascade(b, root, (p) => { ((p.evidence as Obj).time as Obj).class = "gps_bound"; })],
    ["schema-enum-evidence-provenance-class", "schema/enum-unknown", "Inference evidence provenance class self_signed.", (b) => mutateReceiptsCascade(b, (p) => p.kind === "inference", (p) => { ((p.evidence as Obj).provenance as Obj).class = "self_signed"; })],
    ["schema-enum-evidence-outcome-level", "schema/enum-unknown", "Dispatch evidence outcome level acknowledged.", (b) => mutateReceiptsCascade(b, (p) => p.kind === "dispatch", (p) => { ((p.evidence as Obj).outcome as Obj).level = "acknowledged"; })],
    ["schema-enum-presentation-transform-operation", "schema/enum-unknown", "Presentation transform operation rotate.", (b) => mutatePresentation(b, (p) => { p.transforms = [{ ...TRANSFORM, operation: "rotate" }]; })],
    ["schema-d82-credential-missing", "schema/missing-field", "Verifier credential without key_usage.", (b) => mutateArtifact(b, "credentials", credential, (p) => { delete p.key_usage; })],
    ["schema-d82-credential-bad-type", "schema/bad-type", "Verifier credential valid_from text.", (b) => mutateArtifact(b, "credentials", credential, (p) => { p.valid_from = "yesterday"; })],
    ["schema-d82-credential-paired", "schema/enum-unknown", "Verifier credential principal_role root AND key_usage 7; principal_role is earlier in CDDL order.", (b) => mutateArtifact(b, "credentials", credential, (p) => { p.principal_role = "root"; p.key_usage = 7; })],
    ["schema-d82-delegation-missing", "schema/missing-field", "Top-level delegation without not_before.", (b) => mutateArtifact(b, "delegations", () => true, (p) => { delete p.not_before; })],
    ["schema-d82-delegation-bad-type", "schema/bad-type", "Top-level delegation not_after text.", (b) => mutateArtifact(b, "delegations", () => true, (p) => { p.not_after = "later"; })],
    ["schema-d82-delegation-paired", "schema/bad-type", "Top-level delegation not_before text AND use twice; not_before is earlier in CDDL order.", (b) => mutateArtifact(b, "delegations", () => true, (p) => { p.not_before = "early"; p.use = "twice"; })],
    ["schema-d82-epoch-event-missing", "schema/missing-field", "Last event without event_seq.", (b) => mutateLastEvent(b, (p) => { delete p.event_seq; })],
    ["schema-d82-epoch-event-bad-type", "schema/bad-type", "Last event occurred_at text.", (b) => mutateLastEvent(b, (p) => { p.occurred_at = "now"; })],
    ["schema-d82-epoch-event-paired", "schema/bad-type", "Last event event_seq text AND event reopen; event_seq is earlier in CDDL order.", (b) => mutateLastEvent(b, (p) => { p.event_seq = "one"; p.event = "reopen"; })],
    ["schema-d82-manifest-missing", "schema/missing-field", "Manifest without opened_at (anchor_deadline is mirrored into the close event, so it would carry a second fault).", (b) => rebuildManifest(b, (p) => { delete p.opened_at; }, true)],
    ["schema-d82-manifest-bad-type", "schema/bad-type", "Manifest closed_at text.", (b) => rebuildManifest(b, (p) => { p.closed_at = "soon"; }, true)],
    ["schema-d82-manifest-paired", "schema/enum-unknown", "Manifest close_reason manual AND fork_policy 1; close_reason is earlier in CDDL order.", (b) => rebuildManifest(b, (p) => { p.close_reason = "manual"; p.fork_policy = 1; }, true)],
    ["schema-d82-receipt-missing", "schema/missing-field", "Root observation freshness without nonce (binding members are mirrored into the protected header, so their absence cannot be single-fault).", (b) => mutateReceiptsCascade(b, root, (p) => { delete (p.freshness as Obj).nonce; })],
    ["schema-d82-receipt-bad-type", "schema/bad-type", "Root observation freshness invocation_id integer.", (b) => mutateReceiptsCascade(b, root, (p) => { (p.freshness as Obj).invocation_id = 5; })],
    ["schema-d82-receipt-paired-missing-first", "schema/missing-field", "Root observation freshness without nonce AND evidence time class gps_bound; freshness is earlier in CDDL order.", (b) => mutateReceiptsCascade(b, root, (p) => { delete (p.freshness as Obj).nonce; ((p.evidence as Obj).time as Obj).class = "gps_bound"; })],
    ["schema-d82-receipt-paired-enum-first", "schema/enum-unknown", "Root observation evidence time class gps_bound AND correlation without phase; evidence is earlier in CDDL order.", (b) => mutateReceiptsCascade(b, root, (p) => { ((p.evidence as Obj).time as Obj).class = "gps_bound"; delete (p.correlation as Obj).phase; })],
    ["schema-d82-presentation-missing", "schema/missing-field", "Presentation transform without operation.", (b) => mutatePresentation(b, (p) => { p.transforms = [withoutField(TRANSFORM, "operation")]; })],
    ["schema-d82-presentation-bad-type", "schema/bad-type", "Presentation transforms text.", (b) => mutatePresentation(b, (p) => { p.transforms = "none"; })],
    ["schema-d82-presentation-paired", "schema/enum-unknown", "Presentation transform operation rotate AND delivered_at text; transforms is earlier in CDDL order.", (b) => mutatePresentation(b, (p) => { p.transforms = [{ ...TRANSFORM, operation: "rotate" }]; p.delivered_at = "later"; })],
  ];
  // Amendment (b): every unix-time, sequence, and epoch-id field, nested and array members included.
  const outcome = (p: Obj) => p.kind === "outcome_observation";
  schemaTable.push(
    ["schema-d82-receipt-wall-time-text", "schema/bad-type", "Root observation evidence.time.wall_time text; formerly conformant in both verifiers.", (b) => mutateReceiptsCascade(b, root, (p) => { ((p.evidence as Obj).time as Obj).wall_time = "bad"; })],
    ["schema-d82-observation-observed-at-text", "schema/bad-type", "Root observation body observed_at text; formerly conformant in both verifiers.", (b) => mutateReceiptsCascade(b, root, (p) => { (p.body as Obj).observed_at = "bad"; })],
    ["schema-d82-event-epoch-id-list", "schema/bad-type", "The anchor_submitted event's epoch_id is a one-element list; formerly an unhashable-type crash in pyref.", (b) => mutateLastEvent(b, (p) => { p.epoch_id = [42]; })],
    ["schema-d82-event-close-last-seq-text", "schema/bad-type", "The close event's last_epoch_seq is text; the close event is re-identified and the chain rebuilt.", (b) => { mutateArtifact(b, "epoch_events", (p) => p.event === "close", (p) => { (p.body as Obj).last_epoch_seq = "nine"; }); relinkEventChain(b); }],
    ["schema-d82-dispatch-dispatched-at-text", "schema/bad-type", "The dispatch body dispatched_at is text.", (b) => mutateReceiptsCascade(b, (p) => p.kind === "dispatch", (p) => { (p.body as Obj).dispatched_at = "bad"; })],
    ["schema-d82-outcome-observed-at-text", "schema/bad-type", "The outcome observation body observed_at is text.", (b) => mutateReceipt(b, "outcome_observation", (p) => { (p.body as Obj).observed_at = "bad"; })],
    ["schema-d82-parent-edge-epoch-id-text", "schema/bad-type", "The outcome observation's parent edge parent_epoch_id is text.", (b) => mutateReceipt(b, "outcome_observation", (p) => { ((p.parents as Obj[])[0]!).parent_epoch_id = "bad"; })],
    ["schema-d82-manifest-span-first-text", "schema/bad-type", "The manifest sequence_span.first is text.", (b) => rebuildManifest(b, (m) => { (m.sequence_span as Obj).first = "zero"; }, true)],
    ["schema-d82-manifest-index-entry-committed-at-text", "schema/bad-type", "The first manifest index entry's committed_at is text (array member rule).", (b) => rebuildManifest(b, (m) => { (((m.receipt_index as Obj).entries as Obj[])[0]!).committed_at = "bad"; }, true)],
    ["schema-d82-anchor-head-observed-at-text", "schema/bad-type", "The anchor record head.observed_at is text.", (b) => mutateArtifact(b, "anchors", () => true, (p) => { (p.head as Obj).observed_at = "bad"; })],
    ["schema-d82-merkle-batch-epoch-id-text", "schema/bad-type", "The Merkle batch epoch_id is text; proofs re-point at the recomputed batch id.", (b) => mutateMerkleBatch(b, (p) => { p.epoch_id = "bad"; })],
  );
  // Amendment (ab): proof-bearing productions, presence then type of every member at step 6.
  schemaTable.push(
    ["schema-d82-anchor-head-root-missing", "schema/missing-field", "The anchor record's head lacks root; the harness had said conformant.", (b) => mutateArtifact(b, "anchors", () => true, (p) => { delete (p.head as Obj).root; })],
    ["schema-d82-anchor-inclusion-leaf-digest-missing", "schema/missing-field", "The anchor record's inclusion lacks leaf_digest.", (b) => mutateArtifact(b, "anchors", () => true, (p) => { delete (p.inclusion as Obj).leaf_digest; })],
    ["schema-d82-index-entry-receipt-id-missing", "schema/missing-field", "The first manifest index entry lacks receipt_id.", (b) => rebuildManifest(b, (m) => { delete (((m.receipt_index as Obj).entries as Obj[])[0]!).receipt_id; }, true)],
    ["schema-d82-batch-tree-size-text", "schema/bad-type", "The Merkle batch tree_size is text.", (b) => mutateMerkleBatch(b, (p) => { p.tree_size = "bad"; })],
  );
  schemaTable.push(
    ["schema-d82-index-root-null", "schema/bad-type", "The manifest index root is null (round 8; the harness had crashed in equalBytes).", (b) => rebuildManifest(b, (m) => { (m.receipt_index as Obj).root = null; }, true)],
    ["schema-d82-index-root-int-array", "schema/bad-type", "The manifest index root is the array of its own bytes (round 8; the harness had said conformant).", (b) => rebuildManifest(b, (m) => { (m.receipt_index as Obj).root = Array.from((m.receipt_index as Obj).root as Uint8Array); }, true)],
    ["schema-d82-anchor-root-null", "schema/bad-type", "The anchor record's anchor_root is null (round 8).", (b) => mutateArtifact(b, "anchors", () => true, (p) => { p.anchor_root = null; })],
    ["schema-d82-anchor-manifest-digest-null", "schema/bad-type", "The anchor record's manifest_digest is null (round 8).", (b) => mutateArtifact(b, "anchors", () => true, (p) => { p.manifest_digest = null; })],
    ["schema-d82-independence-groups-member-int", "schema/bad-type", "The manifest's independence.groups is [5] (round 8; pyref had crashed).", (b) => rebuildManifest(b, (m) => { ((m.anchor_plan as Obj).independence as Obj).groups = [5]; }, true)],
    ["schema-d82-independence-groups-missing", "schema/missing-field", "The manifest's independence lacks groups (round 8; both had crashed).", (b) => rebuildManifest(b, (m) => { delete ((m.anchor_plan as Obj).independence as Obj).groups; }, true)],
    ["schema-d82-batch-tree-size-over", "schema/out-of-range", "The Merkle batch tree_size is 1,048,577 (amendment ak).", (b) => mutateMerkleBatch(b, (p) => { p.tree_size = 1_048_577; })],
  );
  schemaTable.push(["schema-d82-plan-duplicate-target-id", "schema/duplicate-entry", "The manifest's anchor plan names its first target twice (the copy under another operator); the first matches the anchor record (amendment ap; pyref had taken the last, the harness the first).", (b) => rebuildManifest(b, (m) => { const t = ((m.anchor_plan as Obj).targets as Obj[])[0]!; (m.anchor_plan as Obj).targets = [t, { ...clone(t), operator_id: id16("other-operator") }]; }, true)]);
  schemaTable.push(["schema-d82-credential-path-nine", "schema/out-of-range", "The verifier credential's path names nine credentials; the bound is judged at step 6 (amendment ah).", (b) => mutateArtifact(b, "credentials", (p) => p.key_usage === "verifier_signing", (p) => { p.path = Array.from({ length: 9 }, (_, index) => hash(encodeCbor(index))); })]);
  schemaTable.push(["schema-d82-anchor-plan-mixed-keys", "schema/bad-type", "The manifest's anchor_plan is a map with text and integer keys (amendment af).", (b) => rebuildManifest(b, (m) => { m.anchor_plan = new Map<CborScalar, CborValue>([...Object.entries(m.anchor_plan as Obj), [1, 2]]); }, true)]);
  // Amendment (k): hand-written nested-map guards use the text-keyed-map rule.
  const intKeyed = () => new Map<CborScalar, CborValue>([[1, 2]]);
  schemaTable.push(
    ["schema-d82-presentation-transform-int-keyed", "schema/bad-type", "A presentation transform that is an int-keyed map.", (b) => mutatePresentation(b, (p) => { p.transforms = [intKeyed()]; })],
    ["schema-d82-native-attestation-int-keyed", "schema/bad-type", "A root observation native attestation that is an int-keyed map.", (b) => mutateReceiptsCascade(b, root, (p) => { (p.body as Obj).native_attestations = [intKeyed()]; })],
    ["schema-d82-action-int-keyed", "schema/bad-type", "An action attempt whose action is an int-keyed map.", (b) => mutateReceiptsCascade(b, (p) => p.kind === "action_attempt", (p) => { (p.body as Obj).action = intKeyed(); })],
    ["schema-d82-command-int-keyed", "schema/bad-type", "An action attempt whose command is an int-keyed map.", (b) => mutateReceiptsCascade(b, (p) => p.kind === "action_attempt", (p) => { (p.body as Obj).command = intKeyed(); })],
  );
  for (const [name, code, description, mutate] of schemaTable) {
    const item = bundleFixture(code, description, mutate);
    add({ ...item, filename: name, descriptor: { ...item.descriptor, name, expected_result: "nonconformant", expected_step: 6 } });
  }
  // Amendment (n): range-proof and boundary entries at step 3, on the coverage: complete base of the bundle/range-* KATs (makeCompleteRange over bundle-valid-subset).
  for (const [name, description, mutate] of [
    ["schema-d82-range-entry-committed-at-text", "The complete range's first entry committed_at is text.", (b: Obj) => { makeCompleteRange(b); ((((b.ranges as Obj[])[0]!.entries as Obj[])[0]!).entry as Obj).committed_at = "bad"; }],
    ["schema-d82-boundary-entry-epoch-seq-text", "The complete range carries a left_boundary whose entry epoch_seq is text.", (b: Obj) => { makeCompleteRange(b); const first = clone(((b.ranges as Obj[])[0]!.entries as Obj[])[0]!); (first.entry as Obj).epoch_seq = "bad"; (b.ranges as Obj[])[0]!.left_boundary = first; }],
    ["schema-d82-range-inclusion-missing", "The complete range's first entry lacks its inclusion proof (amendment ab).", (b: Obj) => { makeCompleteRange(b); delete (((b.ranges as Obj[])[0]!.entries as Obj[])[0]!).inclusion; }],
    ["schema-d82-merkle-proof-siblings-missing", "The carried Merkle proof lacks siblings (amendment ab).", (b: Obj) => { delete (artifacts(b).merkle_proofs as Obj[])[0]!.siblings; }],
    ["schema-d82-claimed-profile-int", "The bundle's claimed_profile is the integer 5 (round 6: pyref had said enum-unknown).", (b: Obj) => { b.claimed_profile = 5; }],
    ["schema-d82-v-negative-created-at-text", "The bundle's v is -1 and its created_at is text; v is typed first (round 6).", (b: Obj) => { b.v = -1; b.created_at = "x"; }],
    ["schema-d82-delegations-1001", "1,001 delegation envelope shells; the CDDL occurrence bound is step-3 schema (D-82).", (b: Obj) => { artifacts(b).delegations = Array.from({ length: 1_001 }, (_, index) => [encodeCbor({ delegation_id: hash(encodeCbor(index)) }), new Uint8Array()]); sortArtifacts(b, "delegations"); }],
    ["schema-d82-merkle-proof-21-siblings", "The carried Merkle proof carries 21 siblings; the CDDL bound is step-3 schema (amendment ak).", (b: Obj) => { (artifacts(b).merkle_proofs as Obj[])[0]!.siblings = Array.from({ length: 21 }, (_, index) => hash(encodeCbor(index))); }],
    ["schema-d82-expected-heads-duplicate-target-id", "The trust inputs name the expected head's target twice (the copy with another root); the first is the good one (amendment ap).", (b: Obj) => { const heads = (b.trust_inputs as Obj).expected_anchor_heads as Obj[]; const h = heads[0]!; (b.trust_inputs as Obj).expected_anchor_heads = [h, { ...clone(h), root: deterministicId("other-root") }]; }],
  ] as const) {
    const item = bundleFixture(name.endsWith("-missing") ? "schema/missing-field" : name.endsWith("-1001") || name.endsWith("-21-siblings") ? "schema/out-of-range" : name.endsWith("-duplicate-target-id") ? "schema/duplicate-entry" : "schema/bad-type", description, mutate);
    add({ ...item, filename: name, descriptor: { ...item.descriptor, name, expected_result: "nonconformant", expected_step: 3 } });
  }
  const leafProof = bundleFixture("schema/bad-type", "A Merkle proof leaf epoch_id is text; a bundle-level field, judged at step 3.", (b) => { ((artifacts(b).merkle_proofs as Obj[])[0]!.leaf as Obj).epoch_id = "bad"; });
  add({ ...leafProof, filename: "schema-d82-merkle-proof-leaf-epoch-id-text", descriptor: { ...leafProof.descriptor, name: "schema-d82-merkle-proof-leaf-epoch-id-text", expected_result: "nonconformant", expected_step: 3 } });

  add(fixture("resource/bundle-too-large", "Append bytes until the exact input exceeds the fixed bundle limit.", concat(validBytes, new Uint8Array(16_777_217 - validBytes.length))));
  add(fixture("resource/cbor-depth", "Wrap a scalar in 33 nested arrays.", concat(new Uint8Array(33).fill(0x81), Uint8Array.of(0xf6))));
  add(bundleFixture("resource/node-count", "Replace receipts with 10,001 compact, uniquely identified envelope shells.", (bundle) => {
    artifacts(bundle).receipts = Array.from({ length: 10_001 }, (_, index) => [encodeCbor({ receipt_id: hash(encodeCbor(index)) }), new Uint8Array()]);
    sortArtifacts(bundle, "receipts");
  }));
  add(bundleFixture("resource/parent-count", "Give one receipt 65 parent entries.", (bundle) => {
    const list = artifacts(bundle).receipts as CborValue[]; const entry = list[0]!; const next = clone(payload(entry));
    next.parents = Array.from({ length: 65 }, (_, index) => ({ parent_id: hash(encodeCbor(index)) }));
    list[0] = resign(entry, next, true); sortArtifacts(bundle, "receipts");
  }));
  add(bundleFixture("resource/edge-count", "Use 782 compact receipt shells with 64 parents each plus one with 3, totaling 50,051 edges.", (bundle) => {
    const list: CborValue[] = [];
    for (let index = 0; index < 783; index += 1) {
      const count = index < 782 ? 64 : 3;
      list.push([encodeCbor({ receipt_id: hash(encodeCbor(index)), parents: Array.from({ length: count }, (_, parent) => parent) }), new Uint8Array()]);
    }
    artifacts(bundle).receipts = list; sortArtifacts(bundle, "receipts");
  }));
  add(bundleFixture("resource/proof-too-large", "Give the complete range's first inclusion proof 2,000 siblings so that one encoded proof object exceeds 65,536 bytes (amendment ah: proofs are counted, not their containers).", (bundle) => {
    makeCompleteRange(bundle);
    ((((bundle.ranges as Obj[])[0]!.entries as Obj[])[0]!).inclusion as Obj).siblings = Array.from({ length: 2_000 }, (_, index) => hash(encodeCbor(index)));
  }));
  add(bundleFixture("resource/proofs-too-large", "Add valid-shape unique Merkle proofs until aggregate deterministic encoding exceeds 4 MiB.", (bundle) => {
    const batchId = (artifacts(bundle).merkle_proofs as Obj[])[0]!.batch_id!;
    const proofs: Obj[] = []; let total = 0; let index = 0;
    while (total <= 4_194_304) {
      const proof: Obj = { batch_id: batchId, tree_size: 1_000_000, leaf_index: index, leaf: { tree_size: 1_000_000, leaf_index: index, tenant_id: id16("tenant:acme-security"), site_id: id16("site:denver-lab"), epoch_id: 42, item_digest: hash(encodeCbor(index)) }, siblings: Array.from({ length: 20 }, (_, sibling) => hash(encodeCbor([index, sibling]))) }; // 20 siblings: the CDDL bound (amendment ak)
      proofs.push(proof); total += encodeCbor(proof).length; index += 1;
    }
    artifacts(bundle).merkle_proofs = proofs; sortArtifacts(bundle, "merkle_proofs");
  }));

  add(fixture("cbor/malformed", "Use a reserved CBOR simple value.", Uint8Array.of(0xf8, 0x00)));
  add(fixture("cbor/invalid-utf8", "Encode a one-byte text string containing invalid UTF-8.", Uint8Array.of(0x61, 0xff)));
  add(fixture("cbor/indefinite-length", "Use an indefinite-length top-level array.", Uint8Array.of(0x9f, 0xff)));
  add(fixture("cbor/duplicate-key", "Repeat the top-level v key.", Uint8Array.of(0xa2, 0x61, 0x76, 0x02, 0x61, 0x76, 0x02)));
  add(fixture("cbor/trailing-bytes", "Append one complete scalar after the valid bundle.", concat(validBytes, Uint8Array.of(0x00))));
  add(fixture("cbor/tag-forbidden", "Wrap the bundle in CBOR tag 0.", concat(Uint8Array.of(0xc0), validBytes)));
  add(fixture("cbor/float-forbidden", "Use a top-level IEEE-754 float.", Uint8Array.of(0xfa, 0, 0, 0, 0)));
  add(fixture("cbor/non-canonical", "Encode integer 2 with a non-shortest argument.", Uint8Array.of(0xa1, 0x61, 0x76, 0x18, 0x02)));
  // Amendment (ae): the whole item is walked before profile defects are reported.
  for (const [name, code, description, bytes] of [
    ["cbor-d82-noncanonical-then-malformed", "cbor/malformed", "A two-element array whose first item is non-shortest and whose second is a bare break byte.", Uint8Array.of(0x82, 0x18, 0x05, 0xff)],
    ["cbor-d82-uint-beyond-safe", "cbor/malformed", "The integer 2^53 (outside the profile).", Uint8Array.of(0x1b, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)],
    ["cbor-d82-half-float", "cbor/float-forbidden", "A top-level half-precision float (-1.0).", Uint8Array.of(0xf9, 0xbc, 0x00)],
    ["cbor-d82-float64", "cbor/float-forbidden", "A top-level double (1.0); the float is recognised before its bytes are read as an argument (amendment ao).", Uint8Array.of(0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0)],
    ["cbor-d82-negative-beyond-safe", "cbor/malformed", "The integer -2^53 (outside the profile; -(2^53 - 1) is inside).", Uint8Array.of(0x3b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)],
    ["cbor-d82-depth-32-ok", "schema/bad-type", "Thirty-two arrays nested in a top-level array, innermost empty: the thirty-second nested container does not exceed the bound, so step 2 passes and step 3 rejects the non-map (amendment ao).", concat(new Uint8Array(32).fill(0x81), Uint8Array.of(0x80))],
    ["cbor-d82-depth-33", "resource/cbor-depth", "Thirty-three arrays nested in a top-level array, innermost empty: the thirty-third nested container exceeds the bound (amendment ao).", concat(new Uint8Array(33).fill(0x81), Uint8Array.of(0x80))],
  ] as const) {
    const item = fixture(code, description, bytes);
    add({ ...item, filename: name, descriptor: { ...item.descriptor, name } });
  }

  add(bundleFixture("schema/unknown-field", "Add one field to the closed top-level bundle map.", (bundle) => { bundle.unknown = 1; }));
  add(bundleFixture("schema/missing-field", "Remove required top-level created_at.", (bundle) => { delete bundle.created_at; }));
  add(bundleFixture("schema/bad-type", "Change created_at from uint to text.", (bundle) => { bundle.created_at = "now"; }));
  add(bundleFixture("schema/version-wrong", "Change uint v from 2 to 3.", (bundle) => { bundle.v = 3; }));
  add(bundleFixture("schema/enum-unknown", "Use an unknown claimed profile.", (bundle) => { bundle.claimed_profile = "AAR-4"; }));
  add(bundleFixture("schema/out-of-range", "Exceed the 256 bundle-range occurrence bound.", (bundle) => { bundle.ranges = Array.from({ length: 257 }, () => ({})); }));
  add(bundleFixture("schema/string-size", "Set a canonical manifest media type to the empty string.", (bundle) => { (artifacts(bundle).manifest_payloads as Obj[])[0]!.media_type = ""; }));
  add(bundleFixture("schema/digest-size", "Shorten selector_commitment to 31 bytes.", (bundle) => { bundle.selector_commitment = new Uint8Array(31); }));
  add(bundleFixture("schema/unsorted-set", "Reverse the otherwise valid selector receipt-kind set.", (bundle) => { (bundle.selector as Obj).receipt_kinds = [...((bundle.selector as Obj).receipt_kinds as CborValue[])].reverse(); }));
  add(bundleFixture("schema/duplicate-entry", "Repeat the single selector subject id.", (bundle) => { const values = (bundle.selector as Obj).subject_ids as CborValue[]; values.push(values[0]!); }));

  const coseMutation = (code: string, description: string, mutation: (value: CborValue[], envelope: CborValue[]) => void, field = "credentials", index = 0): void => add(bundleFixture(code, description, (bundle) => modifyCose(bundle, field, index, mutation)));
  coseMutation("cose/tagged", "Tag the serialized COSE_Sign1 with tag 18.", (_value, envelope) => { envelope[1] = concat(Uint8Array.of(0xd2), envelope[1] as Uint8Array); });
  coseMutation("cose/bad-structure", "Replace COSE_Sign1 with an empty array.", (_value, envelope) => { envelope[1] = encodeCbor([]); });
  coseMutation("cose/protected-not-map", "Put an array inside the protected bstr.", (value) => { value[0] = encodeCbor([]); });
  coseMutation("cose/protected-label", "Add an unrecognized protected label.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.set(99, 1); value[0] = encodeCbor(map); });
  coseMutation("cose/alg-missing", "Remove protected alg label 1.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.delete(1); value[0] = encodeCbor(map); });
  coseMutation("cose/alg-wrong", "Change protected alg to -8.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.set(1, -8); value[0] = encodeCbor(map); });
  coseMutation("cose/content-type-missing", "Remove protected content type label 3.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.delete(3); value[0] = encodeCbor(map); });
  coseMutation("cose/content-type-wrong", "Select the request schema for a credential payload.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.set(3, "application/aar-request+cbor;v=0.2"); value[0] = encodeCbor(map); });
  coseMutation("cose/kid-missing", "Remove protected kid label 4.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.delete(4); value[0] = encodeCbor(map); });
  coseMutation("cose/receipt-coordinate-missing", "Remove protected receipt epoch-sequence coordinate.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.delete(-70004); value[0] = encodeCbor(map); }, "receipts", 0);
  coseMutation("cose/receipt-coordinate-mismatch", "Increment only the protected receipt epoch sequence.", (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.set(-70004, (map.get(-70004) as number) + 1); value[0] = encodeCbor(map); }, "receipts", 0);
  coseMutation("cose/alg-in-unprotected", "Put alg label 1 in the unprotected map.", (value) => { value[1] = new Map<CborScalar, CborValue>([[1, -7]]); });
  coseMutation("cose/unprotected-not-empty", "Put non-alg label 2 in the unprotected map.", (value) => { value[1] = new Map<CborScalar, CborValue>([[2, new Uint8Array()]]); });
  coseMutation("cose/payload-not-detached", "Embed an empty bstr instead of CBOR null.", (value) => { value[2] = new Uint8Array(); });

  coseMutation("sig/der-encoding", "Replace P1363 with a syntactically valid DER ECDSA pair.", (value) => { value[3] = Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01); });
  coseMutation("sig/bad-length", "Shorten the signature to a non-DER 63-byte string.", (value) => { value[3] = new Uint8Array(63).fill(1); });
  coseMutation("sig/zero-rs", "Set r and s to zero in a 64-byte P1363 signature.", (value) => { value[3] = new Uint8Array(64); });
  coseMutation("sig/high-s", "Set s to one above the P-256 half order.", (value) => { value[3] = concat(bigint32(1n), bigint32(P256_HALF_ORDER + 1n)); });
  coseMutation("sig/verify-failed", "Flip one bit in a valid low-S P1363 signature.", (value) => { const signature = new Uint8Array(value[3] as Uint8Array); signature[0] = signature[0]! ^ 1; value[3] = signature; });

  add(bundleFixture("key/not-found", "Change a request protected kid to an unavailable 32-byte kid.", (bundle) => modifyCose(bundle, "requests", 0, (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.set(4, deterministicId("missing-key")); value[0] = encodeCbor(map); })));
  add(bundleFixture("key/not-p256", "Carry a non-P-256 SPKI under a matching kid and select it from the request.", (bundle) => {
    const badSpki = Uint8Array.of(1, 2, 3); const kid = hash(badSpki);
    mutateArtifact(bundle, "credentials", (value) => equalBytes(value.subject_kid as Uint8Array, TEST_KEYS.agent_signing.kid), (value) => { value.public_key = badSpki; value.subject_kid = kid; }, false);
    modifyCose(bundle, "requests", 0, (value) => { const map = decodeCbor(value[0] as Uint8Array, { strict: true }) as Map<CborScalar, CborValue>; map.set(4, kid); value[0] = encodeCbor(map); });
  }));

  add(bundleFixture("hash/mismatch", "Flip the adjacent structured-claim digest without changing its canonical bytes.", (bundle) => mutateReceipt(bundle, "inference", (value) => { const body = value.body as Obj; (body.conclusion as Obj).digest = deterministicId("wrong-claim-digest"); })));
  add(bundleFixture("request/commitment-mismatch", "Replace an agent root request commitment and re-sign/re-identify the receipt.", (bundle) => mutateReceiptWhere(bundle, (value) => object(value.root) && value.root.kind === "agent_request", (value) => { (value.root as Obj).request_commitment = deterministicId("wrong-request-commitment"); })));
  // D-60. The request is re-signed under the same agent key and the root commitment is
  // repaired, so the bytes are genuinely agent-signed and the commitment check passes —
  // isolating the coordinate disagreement as the only defect. target_ep_kid is the
  // corpus case, since that field exists solely to bind a request to one enforcement
  // point. tenant_id, site_id, and the intra-request correlation binding are covered by
  // "every request coordinate is checked against the receipt binding" in
  // verifier.test.ts: the corpus carries exactly one fixture per reason code.
  add(bundleFixture("request/coordinate-mismatch", "Address the agent request to an enforcement point other than the epoch owner.", (bundle) => divergeRequest(bundle, (claims) => { claims.target_ep_kid = TEST_KEYS.verifier_signing.kid; (claims.correlation as Obj).target_ep_kid = TEST_KEYS.verifier_signing.kid; })));
  add(bundleFixture("bundle/selector-commitment", "Replace the fixed-size selector commitment with a different digest.", (bundle) => { bundle.selector_commitment = deterministicId("wrong-selector-commitment"); }));
  add(bundleFixture("bundle/dependency-missing", "Remove the request envelope required by an agent_request root.", (bundle) => { artifacts(bundle).requests = []; }));
  add(bundleFixture("manifest/payload-missing", "Declare boot-bound time with a boot artifact ID whose canonical payload is absent.", (bundle) => { clearJournal(bundle); keepReceipts(bundle, (value) => value.kind === "inference" && object(value.root)); mutateReceiptWhere(bundle, () => true, (value) => { const time = (value.evidence as Obj).time as Obj; time.class = "boot_bound"; time.boot_attestation_id = deterministicId("missing-attestation:boot"); }); }));
  add(bundleFixture("manifest/media-type-mismatch", "Change a supplied canonical payload media type while preserving its digest.", (bundle) => { (artifacts(bundle).manifest_payloads as Obj[])[0]!.media_type = "application/octet-stream"; }));

  add(bundleFixture("identity/receipt-id-mismatch", "Replace a receipt_id and re-sign without recomputing it.", (bundle) => {
    const list = artifacts(bundle).receipts as CborValue[]; const entry = list[0]!; const next = clone(payload(entry)); next.receipt_id = deterministicId("wrong-receipt-id"); list[0] = resign(entry, next); sortArtifacts(bundle, "receipts");
  }));
  add(bundleFixture("identity/artifact-id-mismatch", "Replace delegation_id and re-sign without recomputing it.", (bundle) => mutateArtifact(bundle, "delegations", () => true, (value) => { value.delegation_id = deterministicId("wrong-delegation-id"); }, false)));
  add(bundleFixture("identity/coordinate-equivocation", "Give two distinct receipts the same issuer sequence and re-sign/re-identify the changed receipt.", (bundle) => {
    const values = (artifacts(bundle).receipts as CborValue[]).map(payload).filter((value) => value.issuer_role === "agent");
    const first = values[0]!; const second = values[1]!; const firstSeq = (first.emission as Obj).issuer_seq!;
    mutateReceipt(bundle, second.kind as string, (value) => { (value.emission as Obj).issuer_seq = firstSeq; }, values.filter((value) => value.kind === second.kind).indexOf(second));
  }));

  // D-69: the observation body is shape-checked at step 6, so the mismatch is carried on an inference kind to keep this a step-10 trigger.
  add(bundleFixture("receipt/kind-body-mismatch", "Put a root observation body under an inference kind.", (bundle) => { const observation = (artifacts(bundle).receipts as CborValue[]).map(payload).find((value) => value.kind === "observation" && object(value.root))!; mutateReceipt(bundle, "inference", (value) => { value.body = clone(observation.body!); }); }));
  add(bundleFixture("receipt/signer-role-mismatch", "Name outcome_observer as an inference issuer while retaining the agent signing key.", (bundle) => mutateReceipt(bundle, "inference", (value) => { value.issuer_role = "outcome_observer"; })));
  add(bundleFixture("receipt/manifest-inconsistent", "Change a root observation consumption ordinal and recompute its direct commitment.", (bundle) => mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { const consumption = (value.body as Obj).consumption as Obj; ((consumption.items as Obj[])[0]!).ordinal = 1; consumption.manifest_digest = domainHash("AAR-CONSUMPTION-MANIFEST-v1", { items: consumption.items! }); })));
  add(bundleFixture("receipt/consumption-ref-unresolved", "Point an inference consumption reference at an unknown digest.", (bundle) => mutateReceipt(bundle, "inference", (value) => { (value.body as Obj).consumption_manifest_id = deterministicId("unresolved-consumption"); })));
  add(bundleFixture("receipt/decision-presentation", "Remove presentation from a permit_with_approval authorization.", (bundle) => mutateReceiptWhere(bundle, (value) => value.kind === "authorization" && ((value.body as Obj).decision as Obj).decision === "permit_with_approval", (value) => { delete (value.body as Obj).presentation; })));
  add(bundleFixture("receipt/attempt-disposition", "Add refusal_reason to an eligible_for_dispatch attempt.", (bundle) => mutateReceiptWhere(bundle, (value) => value.kind === "action_attempt" && (value.body as Obj).disposition === "eligible_for_dispatch", (value) => { (value.body as Obj).refusal_reason = "unexpected"; })));
  add(bundleFixture("receipt/action-command-mismatch", "Change normalized action name to another valid action without changing command.", (bundle) => mutateReceipt(bundle, "action_attempt", (value) => { ((value.body as Obj).action as Obj).action_name = "camera.ptz.preset"; }, 0)));
  add(bundleFixture("receipt/dispatch-attempt-mismatch", "Change dispatch attempt_id while retaining its attempted_as parent.", (bundle) => mutateReceipt(bundle, "dispatch", (value) => { (value.body as Obj).attempt_id = deterministicId("wrong-attempt"); })));
  add(bundleFixture("receipt/outcome-subject-mismatch", "Change outcome subject while retaining its observed_outcome parent.", (bundle) => mutateReceipt(bundle, "outcome_observation", (value) => { (value.body as Obj).subject_id = deterministicId("wrong-outcome-subject"); })));

  add(bundleFixture("credential/root-not-accepted", "Replace the accepted trust root kid and recompute the trust snapshot digest.", (bundle) => { ((((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[])[0]!).root_kid = deterministicId("unaccepted-root"); recalcTrust(bundle); }));
  add(bundleFixture("credential/path-invalid", "Put an unknown credential id in an otherwise unused credential path.", (bundle) => mutateArtifact(bundle, "credentials", (value) => value.key_usage === "verifier_signing", (value) => { value.path = [deterministicId("missing-path-credential")]; })));
  add(bundleFixture("credential/kid-key-mismatch", "Change the request-signing credential public key without changing subject_kid.", (bundle) => mutateArtifact(bundle, "credentials", (value) => value.key_usage === "agent_signing" && equalBytes(value.subject_kid as Uint8Array, TEST_KEYS.agent_signing.kid), (value) => { const spki = new Uint8Array(value.public_key as Uint8Array); spki[spki.length - 1] = spki[spki.length - 1]! ^ 1; value.public_key = spki; }, false)));
  add(bundleFixture("credential/usage-mismatch", "Give the request signing credential ep_signing usage.", (bundle) => mutateArtifact(bundle, "credentials", (value) => equalBytes(value.subject_kid as Uint8Array, TEST_KEYS.agent_signing.kid), (value) => { value.key_usage = "ep_signing"; })));
  add(bundleFixture("credential/not-yet-valid", "Move the trust-root credential valid_from beyond evaluation.", (bundle) => { const evaluation = (bundle.trust_inputs as Obj).evaluation_time as number; mutateArtifact(bundle, "credentials", (value) => value.key_usage === "credential_issuing", (value) => { value.valid_from = evaluation + 1; }, false); }));
  add(bundleFixture("credential/expired", "Move the trust-root credential valid_until before evaluation.", (bundle) => mutateArtifact(bundle, "credentials", (value) => value.key_usage === "credential_issuing", (value) => { value.valid_until = 1; }, false)));
  add(bundleFixture("credential/status-missing", "Remove the only stapled status snapshot referenced by authorization decisions.", (bundle) => { artifacts(bundle).status_snapshots = []; }));
  const statusFixture = (code: string, description: string, mutation: (status: Obj, evaluation: number, bundle: Obj) => void): void => add(bundleFixture(code, description, (bundle) => { const evaluation = (bundle.trust_inputs as Obj).evaluation_time as number; mutateArtifact(bundle, "status_snapshots", () => true, (value) => mutation(value, evaluation, bundle)); }));
  statusFixture("credential/status-stale", "Move status production before the AAR-2A maximum age.", (value, evaluation) => { value.produced_at = evaluation - 301; });
  statusFixture("credential/revoked", "Change stapled status from good to revoked, effective at the EP key's earliest signing time.", (value, _evaluation, bundle) => revokedBeforeUse(value, bundle));
  statusFixture("credential/compromised", "Declare compromise effective at the EP key's earliest signing time.", (value, _evaluation, bundle) => compromisedBeforeUse(value, bundle));
  statusFixture("credential/status-unknown", "Change stapled status from good to unknown.", (value) => { value.status = "unknown"; });
  statusFixture("credential/lease-too-long", "Extend an AAR-2A lease beyond 3,600 seconds.", (value) => { value.lease_not_after = (value.lease_not_before as number) + 3_601; });
  statusFixture("credential/lease-expired", "End an otherwise fresh lease before evaluation.", (value, evaluation) => { value.lease_not_after = evaluation; value.next_update = evaluation + 100; value.produced_at = evaluation - 1; });
  add(bundleFixture("credential/rotation-invalid", "Replace predecessor_kid while preserving referenced credentials.", (bundle) => mutateArtifact(bundle, "rotations", () => true, (value) => { value.predecessor_kid = deterministicId("wrong-predecessor-kid"); })));
  add(bundleFixture("credential/rotation-rollback", "Add a second rotation with a reused continuity sequence.", (bundle) => { const list = artifacts(bundle).rotations as CborValue[]; const original = list[0]!; const next = clone(payload(original)); next.effective_at = (next.effective_at as number) + 1; const fields = Object.fromEntries(Object.entries(next).filter(([key]) => key !== "rotation_id")); next.rotation_id = domainHash("AAR-ROTATION-ID-v1", fields); list.push(resign(original, next)); sortArtifacts(bundle, "rotations"); }));
  add(bundleFixture("credential/role-key-reuse", "Add unused Agent and EP credentials carrying the same verifier key.", (bundle) => {
    const list = artifacts(bundle).credentials as CborValue[];
    const source = list.find((entry) => payload(entry).key_usage === "verifier_signing")!;
    for (const [role, principal] of [["agent", "model_endpoint"], ["enforcement_point", "service"]] as const) {
      const next = clone(payload(source));
      next.principal_role = role; next.principal_type = principal; next.trust_anchor_id = deterministicId(`role-reuse:${role}`);
      const fields = Object.fromEntries(Object.entries(next).filter(([key]) => key !== "credential_id"));
      next.credential_id = domainHash("AAR-CREDENTIAL-ID-v1", fields);
      list.push(resign(source, next));
    }
    sortArtifacts(bundle, "credentials");
  }));

  const delegationFixture = (code: string, description: string, mutation: (value: Obj) => void): void => add(bundleFixture(code, description, (bundle) => mutateEmbeddedDelegation(bundle, mutation)));
  delegationFixture("delegation/not-yet-valid", "Move the embedded delegation not_before after carried attempts and rederive the authorization flow.", (value) => { value.not_before = (value.not_after as number) - 1; });
  delegationFixture("delegation/expired", "Move the embedded delegation not_after before carried attempts and rederive the authorization flow.", (value) => { value.not_after = 1; });
  delegationFixture("delegation/scope", "Restrict the embedded delegation to the other valid action and rederive the authorization flow.", (value) => { (value.scope as Obj).actions = ["camera.ptz.preset"]; });
  delegationFixture("delegation/chain-invalid", "Give the embedded delegation a missing parent and rederive the authorization flow.", (value) => { value.parent_delegations = [deterministicId("missing-parent-delegation")]; });

  add(bundleFixture("replay/not-yet-valid", "Move a root receipt issued_at after its committed_at.", (bundle) => mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { (value.freshness as Obj).issued_at = ((value.emission as Obj).committed_at as number) + 1; })));
  add(bundleFixture("replay/expired", "Move a root receipt expires_at to its committed_at.", (bundle) => mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { (value.freshness as Obj).expires_at = (value.emission as Obj).committed_at!; })));
  add(bundleFixture("replay/parent-binding", "Replace intended_parents without changing parent edges.", (bundle) => mutateReceipt(bundle, "dispatch", (value) => { (value.freshness as Obj).intended_parents = []; })));
  add(bundleFixture("replay/invocation-mismatch", "Change one receipt invocation id inside a shared correlation flow.", (bundle) => mutateReceipt(bundle, "dispatch", (value) => { (value.freshness as Obj).invocation_id = id16("different-invocation"); })));
  add(bundleFixture("replay/one-time-reused", "Mark two different root receipts one-time under their shared replay coordinate.", (bundle) => { mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { (value.freshness as Obj).use = "one_time"; }); mutateReceiptWhere(bundle, (value) => value.kind === "inference" && object(value.root), (value) => { (value.freshness as Obj).use = "one_time"; }); }));

  add(bundleFixture("resource/dag-depth", "Build a valid 129-node derived_from chain.", (bundle) => {
    clearJournal(bundle);
    const rootEnvelope = receiptBy(bundle, (value) => value.kind === "observation" && object(value.root));
    const root = payload(rootEnvelope);
    const chain: CborValue[] = [];
    let prior: Obj | undefined;
    for (let index = 0; index < 129; index += 1) {
      const next = clone(root);
      const binding = next.binding as Obj; const emission = next.emission as Obj; const freshness = next.freshness as Obj;
      binding.epoch_seq = index; emission.issuer_seq = index + 10_000; emission.committed_at = 1_735_689_700 + index; freshness.expires_at = 1_735_699_600; freshness.nonce = id16(`dag-depth:${index}`);
      if (prior === undefined) { next.parents = []; freshness.intended_parents = []; }
      else {
        delete next.root;
        next.parents = [{ edge_type: "derived_from", parent_id: prior.receipt_id!, parent_kind: "observation", parent_tenant_id: binding.tenant_id!, parent_site_id: binding.site_id!, parent_epoch_id: binding.epoch_id! }];
        freshness.intended_parents = [prior.receipt_id!];
      }
      const signed = resign(rootEnvelope, next, true); chain.push(signed); prior = payload(signed);
    }
    artifacts(bundle).receipts = chain; sortArtifacts(bundle, "receipts");
  }));
  add(bundleFixture("resource/dag-width", "Build 4,097 valid root observations at rank zero.", (bundle) => {
    clearJournal(bundle);
    const rootEnvelope = receiptBy(bundle, (value) => value.kind === "observation" && object(value.root));
    const root = payload(rootEnvelope); const roots: CborValue[] = [];
    for (let index = 0; index < 4_097; index += 1) {
      const next = clone(root); (next.binding as Obj).epoch_seq = index; (next.emission as Obj).issuer_seq = index + 20_000; (next.emission as Obj).committed_at = 1_735_689_700 + index;
      (next.freshness as Obj).expires_at = 1_735_699_600; (next.freshness as Obj).nonce = id16(`dag-width:${index}`);
      roots.push(resign(rootEnvelope, next, true));
    }
    artifacts(bundle).receipts = roots; sortArtifacts(bundle, "receipts");
  }));

  const graphFixture = (code: string, description: string, mutation: (bundle: Obj, child: Obj) => void): void => add(bundleFixture(code, description, (bundle) => {
    clearJournal(bundle);
    keepReceipts(bundle, (value) => value.kind === "observation" && (object(value.root) || (value.parents as CborValue[]).length > 0));
    const childEnvelope = receiptBy(bundle, (value) => value.kind === "observation" && !object(value.root));
    const child = clone(payload(childEnvelope)); mutation(bundle, child); replaceReceipt(bundle, childEnvelope, child);
  }));
  graphFixture("graph/dangling-parent", "Point a derived observation at a nonexistent parent.", (_bundle, child) => { ((child.parents as Obj[])[0]!).parent_id = deterministicId("dangling-parent"); (child.freshness as Obj).intended_parents = [((child.parents as Obj[])[0]!).parent_id!]; });
  graphFixture("graph/parent-metadata-mismatch", "Change the carried parent kind metadata only.", (_bundle, child) => { ((child.parents as Obj[])[0]!).parent_kind = "inference"; });
  graphFixture("graph/edge-illegal", "Use attempted_as between two observations.", (_bundle, child) => { ((child.parents as Obj[])[0]!).edge_type = "attempted_as"; });
  add(bundleFixture("graph/root-missing", "Remove the descriptor from a parentless observation.", (bundle) => { clearJournal(bundle); keepReceipts(bundle, (value) => value.kind === "observation" && object(value.root)); mutateReceiptWhere(bundle, () => true, (value) => { delete value.root; }); }));
  graphFixture("graph/root-forbidden", "Put a root descriptor on a non-root observation.", (_bundle, child) => { child.root = { kind: "human_request", request_id: id16("forbidden-root"), request_commitment: deterministicId("forbidden-root") }; });
  graphFixture("graph/tenant-site-splice", "Move the child to another tenant while retaining its parent.", (_bundle, child) => { (child.binding as Obj).tenant_id = id16("tenant:splice"); });
  graphFixture("graph/cross-epoch-forbidden", "Move the child to a later epoch without a cross_epoch declaration.", (_bundle, child) => { (child.binding as Obj).epoch_id = 43; });
  graphFixture("graph/cross-epoch-unanchored", "Use an allowed historical edge naming nonexistent source manifest and anchor.", (_bundle, child) => { (child.binding as Obj).epoch_id = 43; ((child.parents as Obj[])[0]!).cross_epoch = { source_manifest_id: deterministicId("missing-source-manifest"), source_anchor_id: deterministicId("missing-source-anchor"), reason: "historical_evidence" }; });

  add(bundleFixture("graph/dominator-missing", "Retain a trigger parent but remove the attempt's authorization edge.", (bundle) => {
    clearJournal(bundle);
    updateAttemptFlow(bundle, (attempt, receipts) => {
      const trigger = receipts.find((value) => value.kind === "inference" && !object(value.root))!;
      const binding = trigger.binding as Obj;
      attempt.parents = [{ edge_type: "triggered_by", parent_id: trigger.receipt_id!, parent_kind: "inference", parent_tenant_id: binding.tenant_id!, parent_site_id: binding.site_id!, parent_epoch_id: binding.epoch_id! }];
    });
  }));
  add(bundleFixture("graph/dominator-ambiguous", "Give the dispatched attempt two distinct authorization parents.", (bundle) => {
    clearJournal(bundle);
    updateAttemptFlow(bundle, (attempt, receipts) => {
      const other = receipts.find((value) => value.kind === "authorization" && object(value.root))!; const binding = other.binding as Obj;
      (attempt.parents as Obj[]).push({ edge_type: "authorized_by", parent_id: other.receipt_id!, parent_kind: "authorization", parent_tenant_id: binding.tenant_id!, parent_site_id: binding.site_id!, parent_epoch_id: binding.epoch_id! });
    });
  }));
  const wrongAttemptAuthorization = bundleFixture("graph/dominator-missing", "Bind the attempt body to a different authorization than its sole authorized_by edge.", (bundle) => {
    clearJournal(bundle);
    updateAttemptFlow(bundle, (attempt, receipts) => { (attempt.body as Obj).authorization_id = receipts.find((value) => value.kind === "authorization" && object(value.root))!.receipt_id!; });
  });
  wrongAttemptAuthorization.filename = "graph-dominator-wrong-attempt-authorization";
  wrongAttemptAuthorization.descriptor.name = wrongAttemptAuthorization.filename;
  add(wrongAttemptAuthorization);

  add(bundleFixture("epoch/event-chain", "Replace one previous_event_digest and re-sign the event.", (bundle) => mutateArtifact(bundle, "epoch_events", (value) => value.event_seq === 1, (value) => { value.previous_event_digest = deterministicId("broken-event-chain"); })));
  add(bundleFixture("epoch/open-close", "Remove close and later events so the epoch has only its open.", (bundle) => { artifacts(bundle).epoch_events = (artifacts(bundle).epoch_events as CborValue[]).filter((entry) => payload(entry).event === "open"); artifacts(bundle).anchors = []; }));
  add(bundleFixture("epoch/duration-exceeded", "Move close more than 86,400 seconds after open.", (bundle) => { artifacts(bundle).epoch_events = (artifacts(bundle).epoch_events as CborValue[]).filter((entry) => ["open", "close"].includes(payload(entry).event as string)); mutateArtifact(bundle, "epoch_events", (value) => value.event === "close", (value) => { value.occurred_at = 1_735_689_600 + 86_401; }); rebuildEventChain(bundle, payload((artifacts(bundle).epoch_manifests as CborValue[])[0]!)); artifacts(bundle).anchors = []; }));
  add(bundleFixture("epoch/span-count-mismatch", "Change the close event item count without changing the signed manifest.", (bundle) => { artifacts(bundle).epoch_events = (artifacts(bundle).epoch_events as CborValue[]).filter((entry) => ["open", "close"].includes(payload(entry).event as string)); rebuildEventChain(bundle, payload((artifacts(bundle).epoch_manifests as CborValue[])[0]!)); const close = (artifacts(bundle).epoch_events as CborValue[]).find((entry) => payload(entry).event === "close")!; const next = clone(payload(close)); (next.body as Obj).item_count = 9; next.event_id = domainHash("AAR-EPOCH-EVENT-ID-v1", Object.fromEntries(Object.entries(next).filter(([key]) => key !== "event_id"))); (artifacts(bundle).epoch_events as CborValue[])[(artifacts(bundle).epoch_events as CborValue[]).indexOf(close)] = resign(close, next); sortArtifacts(bundle, "epoch_events"); artifacts(bundle).anchors = []; }));
  add(bundleFixture("epoch/anchor-deadline", "Change the close event's declared anchor deadline.", (bundle) => { artifacts(bundle).epoch_events = (artifacts(bundle).epoch_events as CborValue[]).filter((entry) => ["open", "close"].includes(payload(entry).event as string)); const close = (artifacts(bundle).epoch_events as CborValue[]).find((entry) => payload(entry).event === "close")!; const next = clone(payload(close)); (next.body as Obj).anchor_deadline = ((next.body as Obj).anchor_deadline as number) + 1; next.event_id = domainHash("AAR-EPOCH-EVENT-ID-v1", Object.fromEntries(Object.entries(next).filter(([key]) => key !== "event_id"))); (artifacts(bundle).epoch_events as CborValue[])[(artifacts(bundle).epoch_events as CborValue[]).indexOf(close)] = resign(close, next); sortArtifacts(bundle, "epoch_events"); artifacts(bundle).anchors = []; }));
  add(bundleFixture("epoch/late-insertion", "Close the manifest before carried receipt commits while preserving its declared deadline.", (bundle) => rebuildManifest(bundle, (manifest) => { manifest.closed_at = 1_735_689_648; manifest.anchor_deadline = 1_735_689_648 + 86_400; })));
  add(bundleFixture("epoch/fork", "Carry two distinct manifests for the same owner and epoch.", (bundle) => { const envelope = (artifacts(bundle).epoch_manifests as CborValue[])[0]!; const next = clone(payload(envelope)); next.close_reason = "size"; next.manifest_id = domainHash("AAR-EPOCH-MANIFEST-ID-v1", Object.fromEntries(Object.entries(next).filter(([key]) => key !== "manifest_id"))); (artifacts(bundle).epoch_manifests as CborValue[]).push(resign(envelope, next)); sortArtifacts(bundle, "epoch_manifests"); artifacts(bundle).anchors = []; }));
  add(bundleFixture("epoch/id-nonmonotonic", "Link a successor manifest whose epoch ID decreases.", (bundle) => { const first = (artifacts(bundle).epoch_manifests as CborValue[])[0]!; if (!Array.isArray(first)) throw new Error("manifest envelope malformed"); addSecondEpoch(bundle, 41, hash(first[0] as Uint8Array)); }));
  add(bundleFixture("epoch/predecessor-mismatch", "Carry a later epoch naming an unknown predecessor manifest digest.", (bundle) => addSecondEpoch(bundle, 43, deterministicId("wrong-predecessor-manifest"))));

  const indexFixture = (code: string, description: string, mutation: (manifest: Obj) => void): void => add(bundleFixture(code, description, (bundle) => rebuildManifest(bundle, mutation)));
  indexFixture("manifest/index-order", "Swap two objective index entries without changing their leaf indices.", (manifest) => { const entries = ((manifest.receipt_index as Obj).entries as Obj[]); [entries[0], entries[1]] = [entries[1]!, entries[0]!]; });
  indexFixture("manifest/index-gap", "Make one objective leaf index noncontiguous.", (manifest) => { (((manifest.receipt_index as Obj).entries as Obj[])[1]!).leaf_index = 2; });
  indexFixture("manifest/index-duplicate", "Repeat an epoch sequence in two index entries.", (manifest) => { const entries = ((manifest.receipt_index as Obj).entries as Obj[]); entries[1]!.epoch_seq = entries[0]!.epoch_seq!; });
  indexFixture("manifest/index-receipt-mismatch", "Change one index receipt kind away from its carried receipt.", (manifest) => { (((manifest.receipt_index as Obj).entries as Obj[])[0]!).receipt_kind = "dispatch"; });
  indexFixture("manifest/index-root-mismatch", "Replace the signed objective index root.", (manifest) => { (manifest.receipt_index as Obj).root = deterministicId("wrong-index-root"); });

  add(bundleFixture("merkle/batch-binding", "Change the proof leaf epoch away from its signed batch.", (bundle) => { ((((artifacts(bundle).merkle_proofs as Obj[])[0]!).leaf as Obj).epoch_id) = 43; }));
  add(bundleFixture("merkle/duplicate-leaf", "Prove the same index-less content at two different indices in one signed batch.", (bundle) => {
    const batchEnvelope = (artifacts(bundle).merkle_batches as CborValue[])[0]!;
    const batch = clone(payload(batchEnvelope));
    const originalLeaf = clone(((artifacts(bundle).merkle_proofs as Obj[])[0]!.leaf as Obj));
    const leaves: Obj[] = [0, 1].map((leafIndex) => ({ ...originalLeaf, tree_size: 2, leaf_index: leafIndex }));
    const leafHashes = leaves.map((leaf) => domainHash("AAR-MERKLE-LEAF-v1", leaf));
    batch.tree_size = 2;
    batch.root = promotedRoot(leafHashes, "AAR-MERKLE-NODE-v1");
    batch.batch_id = domainHash("AAR-BATCH-ID-v1", Object.fromEntries(Object.entries(batch).filter(([key]) => key !== "batch_id")));
    artifacts(bundle).merkle_batches = [resign(batchEnvelope, batch)];
    artifacts(bundle).merkle_proofs = leaves.map((leaf, leafIndex) => ({
      batch_id: batch.batch_id!, tree_size: 2, leaf_index: leafIndex, leaf,
      siblings: promotedProofWithDomain(leafHashes, leafIndex, "AAR-MERKLE-NODE-v1"),
    }));
    sortArtifacts(bundle, "merkle_batches"); sortArtifacts(bundle, "merkle_proofs");
  }));
  add(bundleFixture("merkle/path-length", "Remove required siblings from a nontrivial batch proof.", (bundle) => { ((artifacts(bundle).merkle_proofs as Obj[])[0]!).siblings = []; }));
  add(bundleFixture("merkle/root-mismatch", "Flip a bit in a correctly sized Merkle sibling path.", (bundle) => { const proof = (artifacts(bundle).merkle_proofs as Obj[])[0]!; const siblings = proof.siblings as Uint8Array[]; const changed = new Uint8Array(siblings[0]!); changed[0] = changed[0]! ^ 1; siblings[0] = changed; }));

  const mutateAnchor = (bundle: Obj, mutation: (anchor: Obj) => void): void => mutateArtifact(bundle, "anchors", () => true, mutation);
  add(bundleFixture("anchor/target-unplanned", "Change the signed anchor target ID away from the manifest plan.", (bundle) => mutateAnchor(bundle, (anchor) => { (anchor.target as Obj).target_id = id16("anchor-target:unplanned"); })));
  add(bundleFixture("anchor/manifest-binding", "Bind a valid recomputed anchor proof to the wrong epoch.", (bundle) => {
    const anchors = artifacts(bundle).anchors as CborValue[]; const envelope = anchors[0]!; const next = clone(payload(envelope)); next.epoch_id = 43; delete next.consistency;
    const leafObject: Obj = { tenant_id: next.tenant_id!, site_id: next.site_id!, epoch_id: next.epoch_id!, manifest_id: next.manifest_id!, manifest_digest: next.manifest_digest! };
    const leaf = rfc6962Leaf(encodeCbor(["AAR-ANCHOR-LEAF-v1", leafObject])); const inclusion = next.inclusion as Obj; inclusion.leaf_digest = leaf;
    const root = rfcRootFromProof(leaf, inclusion.leaf_index as number, inclusion.tree_size as number, inclusion.siblings as Uint8Array[]); next.anchor_root = root; (next.head as Obj).root = root;
    next.anchor_id = domainHash("AAR-ANCHOR-ID-v1", Object.fromEntries(Object.entries(next).filter(([key]) => key !== "anchor_id"))); anchors[0] = resign(envelope, next);
    (((bundle.trust_inputs as Obj).expected_anchor_heads as Obj[])[0]!).root = root; sortArtifacts(bundle, "anchors");
  }));
  add(bundleFixture("anchor/inclusion-invalid", "Replace the RFC 6962 leaf digest while preserving the signed root.", (bundle) => mutateAnchor(bundle, (anchor) => { (anchor.inclusion as Obj).leaf_digest = deterministicId("wrong-anchor-leaf"); })));
  add(bundleFixture("anchor/consistency-invalid", "Replace the optional RFC 6962 consistency path.", (bundle) => mutateAnchor(bundle, (anchor) => { ((anchor.consistency as Obj).path as CborValue[])[0] = deterministicId("wrong-consistency-node"); })));
  add(bundleFixture("anchor/submission-late", "Move anchor submission beyond the manifest's 86,400-second deadline.", (bundle) => mutateAnchor(bundle, (anchor) => { anchor.submitted_at = 1_735_689_720 + 86_401; })));
  add(bundleFixture("anchor/head-missing", "Provide only an expected head for an unrelated anchor target.", (bundle) => { (((bundle.trust_inputs as Obj).expected_anchor_heads as Obj[])[0]!).target_id = id16("anchor-target:other"); }));
  add(bundleFixture("anchor/head-mismatch", "Change the trusted expected root at the same tree size.", (bundle) => { (((bundle.trust_inputs as Obj).expected_anchor_heads as Obj[])[0]!).root = deterministicId("wrong-expected-head"); }));
  add(bundleFixture("anchor/head-stale", "Age the trusted expected head beyond 86,400 seconds.", (bundle) => { const trust = bundle.trust_inputs as Obj; ((trust.expected_anchor_heads as Obj[])[0]!).observed_at = (trust.evaluation_time as number) - 86_401; }));
  add(bundleFixture("anchor/independence-invalid", "Make the independence declaration's operator disagree with its planned target.", (bundle) => rebuildManifest(bundle, (manifest) => { (((manifest.anchor_plan as Obj).independence as Obj).groups as Obj[])[0]!.operator_id = id16("operator:mismatched"); }, true)));

  add(bundleFixture("bundle/selector-interval", "Make the selector half-open interval empty.", (bundle) => { const selector = bundle.selector as Obj; selector.committed_until = selector.committed_from!; recalcSelector(bundle); }));
  add(bundleFixture("bundle/range-manifest-missing", "Make an otherwise valid range name an unknown manifest.", (bundle) => { makeCompleteRange(bundle); ((bundle.ranges as Obj[])[0]!).manifest_id = deterministicId("missing-range-manifest"); }));
  add(bundleFixture("bundle/range-selector-mismatch", "Change a range selector commitment away from the bundle commitment.", (bundle) => { makeCompleteRange(bundle); ((bundle.ranges as Obj[])[0]!).selector_commitment = deterministicId("wrong-range-selector"); }));
  add(bundleFixture("bundle/range-noncontiguous", "Repeat a leaf index inside an otherwise valid range.", (bundle) => { makeCompleteRange(bundle); const entries = ((bundle.ranges as Obj[])[0]!.entries as Obj[]); (entries[1]!.entry as Obj).leaf_index = (entries[0]!.entry as Obj).leaf_index!; }));
  add(bundleFixture("bundle/range-boundary", "Omit one matching objective entry from the claimed complete interval.", (bundle) => { makeCompleteRange(bundle); (((bundle.ranges as Obj[])[0]!.entries as Obj[])).pop(); }));
  add(bundleFixture("bundle/range-proof-invalid", "Flip a sibling in one objective range inclusion proof.", (bundle) => { makeCompleteRange(bundle); const inclusion = ((((bundle.ranges as Obj[])[0]!.entries as Obj[])[0]!).inclusion as Obj); const siblings = inclusion.siblings as Uint8Array[]; const changed = new Uint8Array(siblings[0]!); changed[0] = changed[0]! ^ 1; siblings[0] = changed; }));
  add(bundleFixture("bundle/selected-receipt-missing", "Remove a selected leaf receipt that is not a graph dependency.", (bundle) => { makeCompleteRange(bundle); keepReceipts(bundle, (value) => !(value.kind === "action_attempt" && (value.body as Obj).disposition === "not_dispatched")); }));
  add(bundleFixture("bundle/coverage-overclaim", "Claim complete coverage without any signed manifest ranges.", (bundle) => { bundle.coverage = "complete"; bundle.ranges = []; }));
  add(bundleFixture("bundle/artifact-out-of-scope", "Carry nondependency receipts outside a complete dispatch-only selector.", (bundle) => { const selector = bundle.selector as Obj; selector.receipt_kinds = ["dispatch"]; delete selector.subject_ids; delete selector.correlation_ids; recalcSelector(bundle); makeCompleteRange(bundle); }));

  add(bundleFixture("evidence/time-class-unsatisfied", "Declare boot_bound time without a boot attestation ID.", (bundle) => { clearJournal(bundle); keepReceipts(bundle, (value) => value.kind === "inference" && object(value.root)); mutateReceiptWhere(bundle, () => true, (value) => { ((value.evidence as Obj).time as Obj).class = "boot_bound"; }); }));
  add(bundleFixture("evidence/provenance-class-unsatisfied", "Declare proxy_captured provenance without a capture attestation ID.", (bundle) => { clearJournal(bundle); keepReceipts(bundle, (value) => value.kind === "inference" && object(value.root)); mutateReceiptWhere(bundle, () => true, (value) => { ((value.evidence as Obj).provenance as Obj).class = "proxy_captured"; }); }));
  add(bundleFixture("evidence/outcome-class-unsatisfied", "Declare independently_sensed without a qualifying predicate.", (bundle) => { clearJournal(bundle); mutateReceiptWhere(bundle, (value) => value.kind === "outcome_observation", (value) => { ((value.evidence as Obj).outcome as Obj).level = "independently_sensed"; }); }));
  add(bundleFixture("evidence/observer-not-independent", "Declare independently_sensed using the same failure domain as source observations.", (bundle) => { clearJournal(bundle); const predicateId = addOpaquePayload(bundle, "qualification:independent"); mutateReceiptWhere(bundle, (value) => value.kind === "outcome_observation", (value) => { const outcome = (value.evidence as Obj).outcome as Obj; outcome.level = "independently_sensed"; outcome.qualifying_predicate_id = predicateId; }); }));

  result.sort((a, b) => a.filename.localeCompare(b.filename));
  return result;
}

export function buildClassBoundaryFixtures(): ClassBoundaryFixture[] {
  const result: ClassBoundaryFixture[] = [];
  const addBoundary = (filename: string, boundary: string, expectation: "reject" | "conformant", expected: string, mutation: (bundle: Obj) => void): void => {
    const bundle = clone(baseBundle()); mutation(bundle);
    result.push({
      filename, bytes: encodeCbor(bundle),
      descriptor: { name: filename, boundary, expectation, ...(expectation === "reject" ? { expected_code: expected } : { expected_class: expected }) },
    });
  };
  const inferenceOnly = (bundle: Obj, mutation: (receipt: Obj) => void): void => {
    clearJournal(bundle); keepReceipts(bundle, (value) => value.kind === "inference" && object(value.root)); mutateReceiptWhere(bundle, () => true, mutation);
  };

  addBoundary("time-asserted-declared-boot-bound", "asserted_to_boot_bound", "reject", "evidence/time-class-unsatisfied", (bundle) => inferenceOnly(bundle, (receipt) => { ((receipt.evidence as Obj).time as Obj).class = "boot_bound"; }));
  addBoundary("time-boot-bound-satisfied", "asserted_to_boot_bound", "conformant", "boot_bound", (bundle) => { const bootId = addOpaquePayload(bundle, "attestation:boot"); inferenceOnly(bundle, (receipt) => { const time = (receipt.evidence as Obj).time as Obj; time.class = "boot_bound"; time.boot_attestation_id = bootId; }); });
  addBoundary("time-boot-bound-declared-externally-anchored", "boot_bound_to_externally_anchored", "reject", "evidence/time-class-unsatisfied", (bundle) => { const bootId = addOpaquePayload(bundle, "attestation:boot"); inferenceOnly(bundle, (receipt) => { const time = (receipt.evidence as Obj).time as Obj; time.class = "externally_anchored"; time.boot_attestation_id = bootId; }); });
  addBoundary("time-externally-anchored-satisfied", "boot_bound_to_externally_anchored", "conformant", "externally_anchored", (bundle) => {
    const bootId = addOpaquePayload(bundle, "attestation:boot");
    const priorAnchor = payload((artifacts(bundle).anchors as CborValue[])[0]!);
    keepReceipts(bundle, (value) => value.kind === "inference" && object(value.root));
    mutateReceiptWhere(bundle, () => true, (receipt) => {
      const binding = receipt.binding as Obj; const emission = receipt.emission as Obj; const time = (receipt.evidence as Obj).time as Obj;
      binding.epoch_id = (priorAnchor.epoch_id as number) + 1;
      emission.committed_at = (priorAnchor.accepted_at as number) + 1;
      time.class = "externally_anchored"; time.wall_time = emission.committed_at!; time.boot_attestation_id = bootId; time.anchor_id = priorAnchor.anchor_id!;
    });
  });

  addBoundary("provenance-self-asserted-declared-proxy-captured", "self_asserted_to_proxy_captured", "reject", "evidence/provenance-class-unsatisfied", (bundle) => inferenceOnly(bundle, (receipt) => { ((receipt.evidence as Obj).provenance as Obj).class = "proxy_captured"; }));
  addBoundary("provenance-proxy-captured-satisfied", "self_asserted_to_proxy_captured", "conformant", "proxy_captured", (bundle) => { const captureId = addOpaquePayload(bundle, "attestation:capture"); inferenceOnly(bundle, (receipt) => { const provenance = (receipt.evidence as Obj).provenance as Obj; provenance.class = "proxy_captured"; provenance.capture_attestation_id = captureId; }); });
  addBoundary("provenance-proxy-captured-declared-provider-attested", "proxy_captured_to_provider_attested", "reject", "evidence/provenance-class-unsatisfied", (bundle) => { const captureId = addOpaquePayload(bundle, "attestation:capture"); inferenceOnly(bundle, (receipt) => { const provenance = (receipt.evidence as Obj).provenance as Obj; provenance.class = "provider_attested"; provenance.capture_attestation_id = captureId; }); });
  addBoundary("provenance-provider-attested-satisfied", "proxy_captured_to_provider_attested", "conformant", "provider_attested", (bundle) => { const captureId = addOpaquePayload(bundle, "attestation:capture"); const providerId = addOpaquePayload(bundle, "attestation:provider"); inferenceOnly(bundle, (receipt) => { const provenance = (receipt.evidence as Obj).provenance as Obj; provenance.class = "provider_attested"; provenance.capture_attestation_id = captureId; provenance.provider_attestation_id = providerId; }); });

  addBoundary("outcome-device-acknowledged-declared-independently-sensed", "device_acknowledged_to_independently_sensed", "reject", "evidence/outcome-class-unsatisfied", (bundle) => { clearJournal(bundle); mutateReceiptWhere(bundle, (value) => value.kind === "outcome_observation", (receipt) => { ((receipt.evidence as Obj).outcome as Obj).level = "independently_sensed"; }); });
  addBoundary("outcome-independently-sensed-satisfied", "device_acknowledged_to_independently_sensed", "conformant", "independently_sensed", (bundle) => { clearJournal(bundle); const predicateId = addOpaquePayload(bundle, "qualification:independent"); mutateReceiptWhere(bundle, (value) => value.kind === "outcome_observation", (receipt) => { const outcome = (receipt.evidence as Obj).outcome as Obj; outcome.level = "independently_sensed"; outcome.qualifying_predicate_id = predicateId; (((receipt.body as Obj).observer as Obj).failure_domain_id) = id16("failure-domain:independent-observer"); }); });

  result.sort((a, b) => a.filename.localeCompare(b.filename));
  return result;
}

export function buildTerminalOutcomeFixtures(): TerminalOutcomeFixture[] {
  const result: TerminalOutcomeFixture[] = [];
  const makeTerminal = (source: CborValue, level: "contradicted" | "unknown", epochSeq: number, issuerSeq: number, committedAt: number, nonceLabel: string): CborValue[] => {
    const next = clone(payload(source));
    ((next.evidence as Obj).outcome as Obj).level = level;
    (next.binding as Obj).epoch_seq = epochSeq;
    (next.emission as Obj).issuer_seq = issuerSeq;
    (next.emission as Obj).committed_at = committedAt;
    (next.freshness as Obj).nonce = id16(`nonce:terminal-state:${nonceLabel}`);
    return resign(source, next, true);
  };
  const findTerminal = (
    source: CborValue,
    level: "contradicted" | "unknown",
    epochSeq: number,
    issuerSeq: number,
    committedAt: number,
    label: string,
    predicate: (candidate: CborValue[]) => boolean,
  ): CborValue[] => {
    for (let salt = 0; salt < 10_000; salt += 1) {
      const candidate = makeTerminal(source, level, epochSeq, issuerSeq, committedAt, `${label}:${salt}`);
      if (predicate(candidate)) return candidate;
    }
    throw new Error(`could not construct terminal outcome ordering for ${label}`);
  };
  const receiptId = (envelope: CborValue): CborValue => payload(envelope).receipt_id!;
  const add = (
    filename: string,
    terminalOrder: string,
    expectedClass: "contradicted" | "unknown",
    mutation: (bundle: Obj) => void,
  ): void => {
    const bundle = clone(baseBundle());
    clearJournal(bundle);
    mutation(bundle);
    result.push({
      filename,
      bytes: encodeCbor(bundle),
      descriptor: {
        name: filename,
        object_type: "bundle",
        terminal_order: terminalOrder,
        expectation: "conformant",
        expected_class: expectedClass,
      },
    });
  };

  add("outcome-terminal-ranked-after-unknown", "unknown_before_ranked", "unknown", (bundle) => {
    const source = receiptBy(bundle, (value) => value.kind === "outcome_observation");
    const ranked = receiptBy(bundle, (value) => value.kind === "dispatch");
    const sourcePayload = payload(source);
    const terminal = findTerminal(
      source,
      "unknown",
      (sourcePayload.binding as Obj).epoch_seq as number,
      (sourcePayload.emission as Obj).issuer_seq as number,
      (sourcePayload.emission as Obj).committed_at as number,
      "ranked-after",
      (candidate) => compare(receiptId(candidate), receiptId(ranked)) < 0,
    );
    const list = receiptList(bundle);
    list[list.indexOf(source)] = terminal;
    sortArtifacts(bundle, "receipts");
  });

  for (const contradictedFirst of [true, false]) {
    const order = contradictedFirst ? "contradicted_before_unknown" : "unknown_before_contradicted";
    add(`outcome-terminals-${order.replaceAll("_", "-")}`, order, "contradicted", (bundle) => {
      const source = receiptBy(bundle, (value) => value.kind === "outcome_observation");
      const sourcePayload = payload(source);
      const binding = sourcePayload.binding as Obj;
      const emission = sourcePayload.emission as Obj;
      const unknown = makeTerminal(
        source,
        "unknown",
        binding.epoch_seq as number,
        emission.issuer_seq as number,
        emission.committed_at as number,
        `${order}:unknown`,
      );
      const contradicted = findTerminal(
        source,
        "contradicted",
        (binding.epoch_seq as number) + 1,
        (emission.issuer_seq as number) + 1,
        (emission.committed_at as number) + 1,
        `${order}:contradicted`,
        (candidate) => contradictedFirst
          ? compare(receiptId(candidate), receiptId(unknown)) < 0
          : compare(receiptId(candidate), receiptId(unknown)) > 0,
      );
      const list = receiptList(bundle);
      list[list.indexOf(source)] = unknown;
      list.push(contradicted);
      sortArtifacts(bundle, "receipts");
    });
  }

  result.sort((a, b) => a.filename.localeCompare(b.filename));
  return result;
}

export function buildEvidenceCommitFixtures(): EvidenceCommitFixture[] {
  const result: EvidenceCommitFixture[] = [];
  const add = (
    filename: string,
    expectation: EvidenceCommitFixture["descriptor"]["expectation"],
    expectedObservations: string[],
    mutation: (bundle: Obj) => void,
    expectedCode?: EvidenceCommitFixture["descriptor"]["expected_code"],
  ): void => {
    const bundle = clone(baseBundle());
    bundle.claimed_profile = "AAR-3";
    mutation(bundle);
    result.push({
      filename,
      bytes: encodeCbor(bundle),
      descriptor: {
        name: filename,
        object_type: "bundle",
        expectation,
        ...(expectation === "nonconformant" ? { expected_code: expectedCode! } : {}),
        expected_observations: expectedObservations,
      },
    });
  };

  add("journal-refusal-conformant", "conformant", ["refused_pre_dispatch"], (bundle) => {
    clearJournal(bundle);
    keepReceipts(bundle, (receipt) => receipt.kind !== "dispatch"
      && receipt.kind !== "outcome_observation"
      && !(receipt.kind === "action_attempt" && (receipt.body as Obj).disposition === "eligible_for_dispatch"));
    const envelope = receiptBy(bundle, (receipt) => receipt.kind === "action_attempt");
    const next = clone(payload(envelope));
    (next.body as Obj).refusal_reason = "journal/unavailable";
    replaceReceipt(bundle, envelope, next);
  });

  add("journal-uncommitted-dispatch", "nonconformant", [], (bundle) => {
    updateAttemptFlow(bundle, (attempt, receipts) => {
      const dispatch = receipts.find((receipt) => receipt.kind === "dispatch")!;
      const dispatchedAt = ((dispatch.body as Obj).dispatched_at as number);
      (attempt.binding as Obj).epoch_seq = ((dispatch.binding as Obj).epoch_seq as number) + 1;
      (attempt.emission as Obj).committed_at = dispatchedAt + 1;
      (((attempt.evidence as Obj).time as Obj).wall_time) = dispatchedAt + 1;
    });
    clearJournal(bundle);
    keepReceipts(bundle, (receipt) => !(receipt.kind === "action_attempt" && (receipt.body as Obj).disposition === "not_dispatched")
      && receipt.kind !== "outcome_observation");
  }, "journal/uncommitted-dispatch");

  add("journal-array-order-uncommitted-first", "nonconformant", [], (bundle) => {
    updateAttemptFlow(bundle, (attempt, receipts) => {
      const dispatch = receipts.find((receipt) => receipt.kind === "dispatch")!;
      const dispatchedAt = ((dispatch.body as Obj).dispatched_at as number);
      (attempt.binding as Obj).epoch_seq = ((dispatch.binding as Obj).epoch_seq as number) + 1;
      (attempt.emission as Obj).committed_at = dispatchedAt + 1;
      (((attempt.evidence as Obj).time as Obj).wall_time) = dispatchedAt + 1;
    });
    addLaterDominatorDefect(bundle);
    clearJournal(bundle);
  }, "journal/uncommitted-dispatch");

  add("journal-life-safety-degraded", "conformant", ["degraded_dispatch"], (bundle) => {
    (bundle.trust_inputs as Obj).life_safety_action_names = ["camera.stream.view"];
    updateAttemptFlow(bundle, (attempt, receipts) => {
      const body = attempt.body as Obj;
      (body.action as Obj).hazard_class = "life_safety";
      body.degraded = { reason: "journal/unavailable" };
      const dispatch = receipts.find((receipt) => receipt.kind === "dispatch")!;
      const dispatchedAt = ((dispatch.body as Obj).dispatched_at as number);
      (attempt.binding as Obj).epoch_seq = ((dispatch.binding as Obj).epoch_seq as number) + 1;
      (attempt.emission as Obj).committed_at = dispatchedAt + 1;
      (((attempt.evidence as Obj).time as Obj).wall_time) = dispatchedAt + 1;
    });
    clearJournal(bundle);
    keepReceipts(bundle, (receipt) => !(receipt.kind === "action_attempt" && (receipt.body as Obj).disposition === "not_dispatched"));
  });

  // D-69: a same_operator anchor plan is accepted and yields existence/order only.
  add("repair-d69-anchor-basis-same-operator", "conformant", ["anchor_existence_order_only"], (bundle) => {
    rebuildManifest(bundle, (manifest) => { ((manifest.anchor_plan as Obj).independence as Obj).basis = "same_operator"; }, true);
  });

  add("journal-life-safety-unbound", "nonconformant", [], (bundle) => {
    (bundle.trust_inputs as Obj).life_safety_action_names = ["camera.ptz.preset"];
    updateAttemptFlow(bundle, (attempt) => {
      const body = attempt.body as Obj;
      (body.action as Obj).hazard_class = "life_safety";
      body.degraded = { reason: "journal/unavailable" };
    });
    clearJournal(bundle);
    keepReceipts(bundle, (receipt) => !(receipt.kind === "action_attempt" && (receipt.body as Obj).disposition === "not_dispatched"));
  }, "receipt/hazard-class-unbound");

  result.sort((left, right) => left.filename.localeCompare(right.filename));
  return result;
}
