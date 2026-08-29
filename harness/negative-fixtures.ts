import { CborScalar, CborValue, decodeCbor, encodeCbor, equalBytes, toHex } from "./cbor";
import { deterministicId, domainHash, hash, id16, P256_HALF_ORDER, signDetached } from "./crypto";
import { buildFixtures } from "./fixtures";
import { promotedProofWithDomain, promotedRoot, rfc6962Leaf } from "./merkle";
import { TEST_KEYS, TestKeyName } from "./testkeys";

type Obj = Record<string, CborValue>;

export interface NegativeDescriptor {
  name: string;
  expected_code: string;
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

function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

function clone<T extends CborValue>(value: T): T {
  return decodeCbor(encodeCbor(value), { strict: true }) as T;
}

function same(left: CborValue | undefined, right: CborValue | undefined): boolean {
  return left !== undefined && right !== undefined && equalBytes(encodeCbor(left), encodeCbor(right));
}

function baseBundle(): Obj {
  const kat = buildFixtures().kats.find((item) => item.filename === "bundle-valid-subset");
  if (kat === undefined) throw new Error("positive bundle fixture missing");
  const value = decodeCbor(kat.bytes, { strict: true });
  if (!object(value)) throw new Error("positive bundle is not a map");
  return value;
}

function artifacts(bundle: Obj): Obj {
  const value = bundle.artifacts;
  if (!object(value)) throw new Error("bundle artifacts missing");
  return value;
}

function payload(envelope: CborValue): Obj {
  if (!Array.isArray(envelope) || !(envelope[0] instanceof Uint8Array)) throw new Error("bad envelope");
  const value = decodeCbor(envelope[0], { strict: true });
  if (!object(value)) throw new Error("bad payload");
  return value;
}

function cose(envelope: CborValue): CborValue[] {
  if (!Array.isArray(envelope) || !(envelope[1] instanceof Uint8Array)) throw new Error("bad envelope");
  const value = decodeCbor(envelope[1], { strict: true });
  if (!Array.isArray(value)) throw new Error("bad cose");
  return value;
}

function protectedMap(envelope: CborValue): Map<CborScalar, CborValue> {
  const value = cose(envelope);
  if (!(value[0] instanceof Uint8Array)) throw new Error("bad protected");
  const decoded = decodeCbor(value[0], { strict: true });
  if (!(decoded instanceof Map)) throw new Error("protected is not a map");
  return decoded;
}

function signerFor(envelope: CborValue): TestKeyName {
  const kid = protectedMap(envelope).get(4);
  if (!(kid instanceof Uint8Array)) throw new Error("protected kid missing");
  const found = (Object.keys(TEST_KEYS) as TestKeyName[]).find((name) => equalBytes(TEST_KEYS[name].kid, kid));
  if (found === undefined) throw new Error(`unknown test kid ${toHex(kid)}`);
  return found;
}

function contentType(envelope: CborValue): string {
  const value = protectedMap(envelope).get(3);
  if (typeof value !== "string") throw new Error("content type missing");
  return value;
}

function receiptProtected(payloadValue: Obj): readonly (readonly [number, CborValue])[] {
  const binding = payloadValue.binding as Obj;
  const emission = payloadValue.emission as Obj;
  return [
    [-70000, payloadValue.issuer_principal_type!], [-70001, binding.tenant_id!], [-70002, binding.site_id!],
    [-70003, binding.epoch_id!], [-70004, binding.epoch_seq!], [-70005, emission.issuer_seq!], [-70006, payloadValue.issuer_role!],
  ];
}

function resign(envelope: CborValue, nextPayload: Obj, recalcId = false): CborValue[] {
  const type = contentType(envelope);
  const signer = signerFor(envelope);
  if (type === "application/aar-receipt+cbor;v=0.2") {
    if (recalcId) {
      const fields = Object.fromEntries(Object.entries(nextPayload).filter(([key]) => key !== "receipt_id"));
      const preliminary = signDetached(nextPayload, type, signer, receiptProtected(nextPayload));
      nextPayload.receipt_id = domainHash("AAR-RECEIPT-ID-v1", preliminary.protectedBytes, fields);
    }
    return signDetached(nextPayload, type, signer, receiptProtected(nextPayload)).envelope;
  }
  return signDetached(nextPayload, type, signer).envelope;
}

const ID_DOMAIN: Record<string, readonly [string, string]> = {
  delegations: ["delegation_id", "AAR-DELEGATION-ID-v1"], credentials: ["credential_id", "AAR-CREDENTIAL-ID-v1"],
  status_snapshots: ["snapshot_id", "AAR-STATUS-ID-v1"], rotations: ["rotation_id", "AAR-ROTATION-ID-v1"],
  epoch_events: ["event_id", "AAR-EPOCH-EVENT-ID-v1"], epoch_manifests: ["manifest_id", "AAR-EPOCH-MANIFEST-ID-v1"],
  anchors: ["anchor_id", "AAR-ANCHOR-ID-v1"], merkle_batches: ["batch_id", "AAR-BATCH-ID-v1"],
};

function mutateArtifact(bundle: Obj, field: string, predicate: (value: Obj) => boolean, mutation: (value: Obj) => void, recalcId = true): void {
  const list = artifacts(bundle)[field] as CborValue[];
  const index = list.findIndex((entry) => predicate(payload(entry)));
  if (index < 0) throw new Error(`${field} target not found`);
  const envelope = list[index]!;
  const next = clone(payload(envelope));
  mutation(next);
  const domain = ID_DOMAIN[field];
  if (recalcId && domain !== undefined) {
    const [idField, label] = domain;
    const fields = Object.fromEntries(Object.entries(next).filter(([key]) => key !== idField));
    next[idField] = domainHash(label, fields);
  }
  list[index] = resign(envelope, next);
  sortArtifacts(bundle, field);
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
    { label: "credential subject_kid array", code: "schema/bad-type", step: 6, build: (bundle) => swapPayload(bundle, "credentials", (value) => { value.subject_kid = [...(value.subject_kid as Uint8Array)]; }) },
    // Post-signature classes: re-signed so the guarded step is actually reached.
    { label: "canonical_command non-bstr", code: "schema/bad-type", step: 7, build: (bundle) => mutateReceipt(bundle, "action_attempt", (value) => { ((value.body as Obj).command as Obj).canonical_command = "not-bytes"; }) },
    { label: "binding epoch_owner_kid array", code: "schema/bad-type", step: 9, build: (bundle) => mutateReceiptWhere(bundle, (value) => !object(value.root), (value) => { const binding = value.binding as Obj; binding.epoch_owner_kid = [...(binding.epoch_owner_kid as Uint8Array)]; }) },
    { label: "freshness issued_at non-uint", code: "schema/bad-type", step: 11, build: (bundle) => mutateReceiptWhere(bundle, (value) => !object(value.root), (value) => { (value.freshness as Obj).issued_at = "soon"; }) },
    // Both impls must skip a non-map parent edge at the step-10 dispatch clause
    // and converge on the step-11 parents guard (gate-proven divergence class).
    { label: "dispatch parent edge non-map", code: "schema/bad-type", step: 11, build: (bundle) => mutateReceipt(bundle, "dispatch", (value) => { const parents = value.parents as CborValue[]; const index = parents.findIndex((parent) => object(parent) && parent.edge_type === "attempted_as"); if (index < 0) throw new Error("attempted_as edge missing"); parents[index] = 5; }) },
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

function mutateReceipt(bundle: Obj, kind: string, mutation: (value: Obj) => void, occurrence = 0): void {
  const list = artifacts(bundle).receipts as CborValue[];
  const matches = list.map((entry, index) => ({ entry, index, value: payload(entry) })).filter(({ value }) => value.kind === kind);
  const target = matches[occurrence];
  if (target === undefined) throw new Error(`receipt ${kind}[${occurrence}] missing`);
  const next = clone(target.value);
  mutation(next);
  list[target.index] = resign(target.entry, next, true);
  sortArtifacts(bundle, "receipts");
}

function mutateReceiptWhere(bundle: Obj, predicate: (value: Obj) => boolean, mutation: (value: Obj) => void): void {
  const list = artifacts(bundle).receipts as CborValue[];
  const index = list.findIndex((entry) => predicate(payload(entry)));
  if (index < 0) throw new Error("receipt predicate target missing");
  const next = clone(payload(list[index]!));
  mutation(next);
  list[index] = resign(list[index]!, next, true);
  sortArtifacts(bundle, "receipts");
}

function sortArtifacts(bundle: Obj, field: string): void {
  const list = artifacts(bundle)[field] as CborValue[];
  const idField: Record<string, string> = { receipts: "receipt_id", requests: "request_id", delegations: "delegation_id", credentials: "credential_id", status_snapshots: "snapshot_id", rotations: "rotation_id", epoch_events: "event_id", epoch_manifests: "manifest_id", anchors: "anchor_id", merkle_batches: "batch_id" };
  if (field === "manifest_payloads") list.sort((a, b) => compare((a as Obj).digest!, (b as Obj).digest!));
  else if (field === "merkle_proofs") list.sort((a, b) => compare([(a as Obj).batch_id!, (a as Obj).leaf_index!], [(b as Obj).batch_id!, (b as Obj).leaf_index!]));
  else list.sort((a, b) => compare(payload(a)[idField[field]!]!, payload(b)[idField[field]!]!));
}

function compare(a: CborValue, b: CborValue): number {
  const left = encodeCbor(a); const right = encodeCbor(b);
  if (left.length !== right.length) return left.length - right.length;
  for (let i = 0; i < left.length; i += 1) if (left[i] !== right[i]) return left[i]! - right[i]!;
  return 0;
}

function recalcSelector(bundle: Obj): void {
  bundle.selector_commitment = domainHash("AAR-BUNDLE-SELECTOR-v1", bundle.selector!);
}

function recalcTrust(bundle: Obj): void {
  const trust = bundle.trust_inputs as Obj;
  const store = trust.trust_store as Obj;
  store.digest = domainHash("AAR-TRUST-STORE-v1", Object.fromEntries(Object.entries(store).filter(([key]) => key !== "digest")));
}

function modifyCose(bundle: Obj, field: string, index: number, mutation: (value: CborValue[], envelope: CborValue[]) => void): void {
  const list = artifacts(bundle)[field] as CborValue[];
  const envelope = list[index];
  if (!Array.isArray(envelope)) throw new Error("envelope missing");
  const value = cose(envelope);
  const originalSerialized = envelope[1];
  mutation(value, envelope);
  if (envelope[1] === originalSerialized) envelope[1] = encodeCbor(value);
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

function receiptList(bundle: Obj): CborValue[] {
  return artifacts(bundle).receipts as CborValue[];
}

function keepReceipts(bundle: Obj, predicate: (value: Obj) => boolean): void {
  artifacts(bundle).receipts = receiptList(bundle).filter((entry) => predicate(payload(entry)));
  sortArtifacts(bundle, "receipts");
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

function withoutField(value: Obj, field: string): Obj {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

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

function rebuildEventChain(bundle: Obj, manifest: Obj): void {
  const events = (artifacts(bundle).epoch_events as CborValue[]).map((entry) => ({ envelope: entry, value: clone(payload(entry)) }))
    .sort((a, b) => (a.value.event_seq as number) - (b.value.event_seq as number));
  const rebuilt: CborValue[] = [];
  let priorPayload: Uint8Array | undefined;
  for (const event of events) {
    if (event.value.event === "close") {
      const body = event.value.body as Obj;
      body.manifest_id = manifest.manifest_id!;
      body.item_count = manifest.item_count!;
      body.last_epoch_seq = (manifest.sequence_span as Obj).last!;
      body.anchor_deadline = manifest.anchor_deadline!;
    }
    if (event.value.event === "anchor_submitted") (event.value.body as Obj).manifest_id = manifest.manifest_id!;
    if (priorPayload === undefined) delete event.value.previous_event_digest;
    else event.value.previous_event_digest = hash(priorPayload);
    event.value.event_id = domainHash("AAR-EPOCH-EVENT-ID-v1", Object.fromEntries(Object.entries(event.value).filter(([key]) => key !== "event_id")));
    const signed = resign(event.envelope, event.value);
    rebuilt.push(signed);
    priorPayload = signed[0] as Uint8Array;
  }
  artifacts(bundle).epoch_events = rebuilt;
  sortArtifacts(bundle, "epoch_events");
}

function rfcRootFromProof(leaf: Uint8Array, leafIndex: number, treeSize: number, proof: readonly Uint8Array[]): Uint8Array {
  let digest = leaf; let fn = leafIndex; let sn = treeSize - 1;
  for (const sibling of proof) {
    if ((fn & 1) === 1 || fn === sn) {
      digest = hash(Uint8Array.of(1), sibling, digest);
      while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else digest = hash(Uint8Array.of(1), digest, sibling);
    fn >>= 1; sn >>= 1;
  }
  return digest;
}

function rebuildAnchor(bundle: Obj, oldManifestId: Uint8Array, manifestEnvelopeValue: CborValue): void {
  const anchors = artifacts(bundle).anchors as CborValue[];
  if (anchors.length === 0) return;
  const envelope = anchors.find((entry) => equalBytes(payload(entry).manifest_id as Uint8Array, oldManifestId));
  if (envelope === undefined) throw new Error("anchor for rebuilt manifest missing");
  if (!Array.isArray(manifestEnvelopeValue)) throw new Error("rebuilt manifest envelope malformed");
  const manifestEnvelope = manifestEnvelopeValue;
  const manifest = payload(manifestEnvelope);
  const next = clone(payload(envelope));
  next.manifest_id = manifest.manifest_id!;
  next.manifest_digest = hash(manifestEnvelope[0] as Uint8Array);
  delete next.consistency;
  const leafObject: Obj = { tenant_id: next.tenant_id!, site_id: next.site_id!, epoch_id: next.epoch_id!, manifest_id: next.manifest_id!, manifest_digest: next.manifest_digest! };
  const leaf = rfc6962Leaf(encodeCbor(["AAR-ANCHOR-LEAF-v1", leafObject]));
  const inclusion = next.inclusion as Obj;
  inclusion.leaf_digest = leaf;
  const root = rfcRootFromProof(leaf, inclusion.leaf_index as number, inclusion.tree_size as number, inclusion.siblings as Uint8Array[]);
  next.anchor_root = root;
  (next.head as Obj).root = root;
  next.anchor_id = domainHash("AAR-ANCHOR-ID-v1", Object.fromEntries(Object.entries(next).filter(([key]) => key !== "anchor_id")));
  anchors[anchors.indexOf(envelope)] = resign(envelope, next);
  sortArtifacts(bundle, "anchors");
  const heads = ((bundle.trust_inputs as Obj).expected_anchor_heads as Obj[]);
  const expected = heads.find((entry) => same(entry.target_id, (next.target as Obj).target_id));
  if (expected !== undefined) expected.root = root;
}

function rebuildManifest(bundle: Obj, mutation: (manifest: Obj) => void, keepAnchor = false): void {
  const list = artifacts(bundle).epoch_manifests as CborValue[];
  const envelope = list[0]!;
  const oldManifestId = payload(envelope).manifest_id as Uint8Array;
  const next = clone(payload(envelope));
  mutation(next);
  next.manifest_id = domainHash("AAR-EPOCH-MANIFEST-ID-v1", Object.fromEntries(Object.entries(next).filter(([key]) => key !== "manifest_id")));
  const replacement = resign(envelope, next);
  list[0] = replacement;
  sortArtifacts(bundle, "epoch_manifests");
  rebuildEventChain(bundle, next);
  if (keepAnchor) rebuildAnchor(bundle, oldManifestId, replacement);
  else artifacts(bundle).anchors = [];
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

function addSecondEpoch(bundle: Obj, epochId: number, predecessorDigest: Uint8Array): void {
  const manifestEnvelope = (artifacts(bundle).epoch_manifests as CborValue[])[0]!;
  const manifest = clone(payload(manifestEnvelope));
  manifest.epoch_id = epochId;
  manifest.predecessor_manifest_digest = predecessorDigest;
  manifest.opened_at = (manifest.opened_at as number) + 100_000;
  manifest.closed_at = (manifest.closed_at as number) + 100_000;
  manifest.anchor_deadline = (manifest.closed_at as number) + 86_400;
  manifest.manifest_id = domainHash("AAR-EPOCH-MANIFEST-ID-v1", Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== "manifest_id")));
  const signedManifest = resign(manifestEnvelope, manifest);
  (artifacts(bundle).epoch_manifests as CborValue[]).push(signedManifest);
  sortArtifacts(bundle, "epoch_manifests");

  const baseEvents = (artifacts(bundle).epoch_events as CborValue[]).map((entry) => ({ envelope: entry, value: payload(entry) })).sort((a, b) => (a.value.event_seq as number) - (b.value.event_seq as number)).slice(0, 2);
  let priorPayload: Uint8Array | undefined;
  for (const base of baseEvents) {
    const event = clone(base.value);
    event.epoch_id = epochId;
    event.occurred_at = (event.occurred_at as number) + 100_000;
    if (event.event === "open") (event.body as Obj).predecessor_manifest_digest = predecessorDigest;
    if (event.event === "close") {
      (event.body as Obj).manifest_id = manifest.manifest_id!;
      (event.body as Obj).anchor_deadline = manifest.anchor_deadline!;
    }
    if (priorPayload === undefined) delete event.previous_event_digest;
    else event.previous_event_digest = hash(priorPayload);
    event.event_id = domainHash("AAR-EPOCH-EVENT-ID-v1", Object.fromEntries(Object.entries(event).filter(([key]) => key !== "event_id")));
    const signed = resign(base.envelope, event);
    (artifacts(bundle).epoch_events as CborValue[]).push(signed);
    priorPayload = signed[0] as Uint8Array;
  }
  sortArtifacts(bundle, "epoch_events");
  artifacts(bundle).anchors = [];
}

export function buildNegativeFixtures(): NegativeFixture[] {
  const result: NegativeFixture[] = [];
  const add = (value: NegativeFixture): void => { result.push(value); };
  const validBytes = encodeCbor(baseBundle());

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
  add(bundleFixture("resource/proof-too-large", "Repeat valid manifest range entries until one encoded proof object exceeds 65,536 bytes.", (bundle) => {
    const manifestEnvelope = (artifacts(bundle).epoch_manifests as CborValue[])[0]!;
    const manifest = payload(manifestEnvelope);
    const entries = (((manifest.receipt_index as Obj).entries) as Obj[]);
    const proofEntries: Obj[] = [];
    let range: Obj;
    do {
      const entry = clone(entries[proofEntries.length % entries.length]!);
      proofEntries.push({ entry, inclusion: { tree_size: 10_000, leaf_index: proofEntries.length - 1, siblings: Array.from({ length: 14 }, (_, index) => hash(encodeCbor([proofEntries.length, index]))) } });
      range = { manifest_id: manifest.manifest_id!, selector_commitment: bundle.selector_commitment!, tree_size: 10_000, first_leaf_index: 0, entries: proofEntries };
    } while (encodeCbor(range).length <= 65_536);
    bundle.ranges = [range!];
  }));
  add(bundleFixture("resource/proofs-too-large", "Add valid-shape unique Merkle proofs until aggregate deterministic encoding exceeds 4 MiB.", (bundle) => {
    const batchId = (artifacts(bundle).merkle_proofs as Obj[])[0]!.batch_id!;
    const proofs: Obj[] = []; let total = 0; let index = 0;
    while (total <= 4_194_304) {
      const proof: Obj = { batch_id: batchId, tree_size: 1_000_000, leaf_index: index, leaf: { tree_size: 1_000_000, leaf_index: index, tenant_id: id16("tenant:acme-security"), site_id: id16("site:denver-lab"), epoch_id: 42, item_digest: hash(encodeCbor(index)) }, siblings: Array.from({ length: 64 }, (_, sibling) => hash(encodeCbor([index, sibling]))) };
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

  add(bundleFixture("receipt/kind-body-mismatch", "Put an inference body under a root observation kind.", (bundle) => { const inference = (artifacts(bundle).receipts as CborValue[]).map(payload).find((value) => value.kind === "inference")!; mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { value.body = clone(inference.body!); }); }));
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
  const statusFixture = (code: string, description: string, mutation: (status: Obj, evaluation: number) => void): void => add(bundleFixture(code, description, (bundle) => { const evaluation = (bundle.trust_inputs as Obj).evaluation_time as number; mutateArtifact(bundle, "status_snapshots", () => true, (value) => mutation(value, evaluation)); }));
  statusFixture("credential/status-stale", "Move status production before the AAR-2A maximum age.", (value, evaluation) => { value.produced_at = evaluation - 301; });
  statusFixture("credential/revoked", "Change stapled status from good to revoked.", (value) => { value.status = "revoked"; });
  statusFixture("credential/compromised", "Declare compromise effective before evaluation.", (value, evaluation) => { value.status = "compromised"; value.compromise_at = evaluation - 1; });
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
