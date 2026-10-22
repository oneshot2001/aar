// Mutation primitives shared by the negative-fixture kit (negative-fixtures.ts)
// and the differential fuzz tool (difffuzz-operators.ts). Extracted unchanged
// in behaviour (Packet D, Stage A).
import { CborScalar, CborValue, decodeCbor, encodeCbor, equalBytes, toHex } from "./cbor";
import { domainHash, hash, signDetached } from "./crypto";
import { rfc6962Leaf } from "./merkle";
import { TEST_KEYS, TestKeyName } from "./testkeys";

export type Obj = Record<string, CborValue>;

export function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

export function clone<T extends CborValue>(value: T): T {
  return decodeCbor(encodeCbor(value), { strict: true }) as T;
}

export function same(left: CborValue | undefined, right: CborValue | undefined): boolean {
  return left !== undefined && right !== undefined && equalBytes(encodeCbor(left), encodeCbor(right));
}

export function artifacts(bundle: Obj): Obj {
  const value = bundle.artifacts;
  if (!object(value)) throw new Error("bundle artifacts missing");
  return value;
}

export function payload(envelope: CborValue): Obj {
  if (!Array.isArray(envelope) || !(envelope[0] instanceof Uint8Array)) throw new Error("bad envelope");
  const value = decodeCbor(envelope[0], { strict: true });
  if (!object(value)) throw new Error("bad payload");
  return value;
}

export function cose(envelope: CborValue): CborValue[] {
  if (!Array.isArray(envelope) || !(envelope[1] instanceof Uint8Array)) throw new Error("bad envelope");
  const value = decodeCbor(envelope[1], { strict: true });
  if (!Array.isArray(value)) throw new Error("bad cose");
  return value;
}

export function protectedMap(envelope: CborValue): Map<CborScalar, CborValue> {
  const value = cose(envelope);
  if (!(value[0] instanceof Uint8Array)) throw new Error("bad protected");
  const decoded = decodeCbor(value[0], { strict: true });
  if (!(decoded instanceof Map)) throw new Error("protected is not a map");
  return decoded;
}

export function signerFor(envelope: CborValue): TestKeyName {
  const kid = protectedMap(envelope).get(4);
  if (!(kid instanceof Uint8Array)) throw new Error("protected kid missing");
  const found = (Object.keys(TEST_KEYS) as TestKeyName[]).find((name) => equalBytes(TEST_KEYS[name].kid, kid));
  if (found === undefined) throw new Error(`unknown test kid ${toHex(kid)}`);
  return found;
}

export function contentType(envelope: CborValue): string {
  const value = protectedMap(envelope).get(3);
  if (typeof value !== "string") throw new Error("content type missing");
  return value;
}

export function receiptProtected(payloadValue: Obj): readonly (readonly [number, CborValue])[] {
  const binding = payloadValue.binding as Obj;
  const emission = payloadValue.emission as Obj;
  return [
    [-70000, payloadValue.issuer_principal_type!], [-70001, binding.tenant_id!], [-70002, binding.site_id!],
    [-70003, binding.epoch_id!], [-70004, binding.epoch_seq!], [-70005, emission.issuer_seq!], [-70006, payloadValue.issuer_role!],
  ];
}

export function resign(envelope: CborValue, nextPayload: Obj, recalcId = false): CborValue[] {
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

export const ID_DOMAIN: Record<string, readonly [string, string]> = {
  delegations: ["delegation_id", "AAR-DELEGATION-ID-v1"], credentials: ["credential_id", "AAR-CREDENTIAL-ID-v1"],
  status_snapshots: ["snapshot_id", "AAR-STATUS-ID-v1"], rotations: ["rotation_id", "AAR-ROTATION-ID-v1"],
  epoch_events: ["event_id", "AAR-EPOCH-EVENT-ID-v1"], epoch_manifests: ["manifest_id", "AAR-EPOCH-MANIFEST-ID-v1"],
  anchors: ["anchor_id", "AAR-ANCHOR-ID-v1"], merkle_batches: ["batch_id", "AAR-BATCH-ID-v1"],
};

export function mutateArtifact(bundle: Obj, field: string, predicate: (value: Obj) => boolean, mutation: (value: Obj) => void, recalcId = true): void {
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

export function mutateReceipt(bundle: Obj, kind: string, mutation: (value: Obj) => void, occurrence = 0): void {
  const list = artifacts(bundle).receipts as CborValue[];
  const matches = list.map((entry, index) => ({ entry, index, value: payload(entry) })).filter(({ value }) => value.kind === kind);
  const target = matches[occurrence];
  if (target === undefined) throw new Error(`receipt ${kind}[${occurrence}] missing`);
  const next = clone(target.value);
  mutation(next);
  list[target.index] = resign(target.entry, next, true);
  sortArtifacts(bundle, "receipts");
}

export function mutateReceiptWhere(bundle: Obj, predicate: (value: Obj) => boolean, mutation: (value: Obj) => void): void {
  const list = artifacts(bundle).receipts as CborValue[];
  const index = list.findIndex((entry) => predicate(payload(entry)));
  if (index < 0) throw new Error("receipt predicate target missing");
  const next = clone(payload(list[index]!));
  mutation(next);
  list[index] = resign(list[index]!, next, true);
  sortArtifacts(bundle, "receipts");
}

export function sortArtifacts(bundle: Obj, field: string): void {
  const list = artifacts(bundle)[field] as CborValue[];
  const idField: Record<string, string> = { receipts: "receipt_id", requests: "request_id", delegations: "delegation_id", credentials: "credential_id", status_snapshots: "snapshot_id", rotations: "rotation_id", epoch_events: "event_id", epoch_manifests: "manifest_id", anchors: "anchor_id", merkle_batches: "batch_id" };
  if (field === "manifest_payloads") list.sort((a, b) => compare((a as Obj).digest!, (b as Obj).digest!));
  else if (field === "merkle_proofs") list.sort((a, b) => compare([(a as Obj).batch_id!, (a as Obj).leaf_index!], [(b as Obj).batch_id!, (b as Obj).leaf_index!]));
  else list.sort((a, b) => compare(payload(a)[idField[field]!]!, payload(b)[idField[field]!]!));
}

export function compare(a: CborValue, b: CborValue): number {
  const left = encodeCbor(a); const right = encodeCbor(b);
  if (left.length !== right.length) return left.length - right.length;
  for (let i = 0; i < left.length; i += 1) if (left[i] !== right[i]) return left[i]! - right[i]!;
  return 0;
}

export function recalcSelector(bundle: Obj): void {
  bundle.selector_commitment = domainHash("AAR-BUNDLE-SELECTOR-v1", bundle.selector!);
}

export function recalcTrust(bundle: Obj): void {
  const trust = bundle.trust_inputs as Obj;
  const store = trust.trust_store as Obj;
  store.digest = domainHash("AAR-TRUST-STORE-v1", Object.fromEntries(Object.entries(store).filter(([key]) => key !== "digest")));
}

export function modifyCose(bundle: Obj, field: string, index: number, mutation: (value: CborValue[], envelope: CborValue[]) => void): void {
  const list = artifacts(bundle)[field] as CborValue[];
  const envelope = list[index];
  if (!Array.isArray(envelope)) throw new Error("envelope missing");
  const value = cose(envelope);
  const originalSerialized = envelope[1];
  mutation(value, envelope);
  if (envelope[1] === originalSerialized) envelope[1] = encodeCbor(value);
}

export function receiptList(bundle: Obj): CborValue[] {
  return artifacts(bundle).receipts as CborValue[];
}

export function keepReceipts(bundle: Obj, predicate: (value: Obj) => boolean): void {
  artifacts(bundle).receipts = receiptList(bundle).filter((entry) => predicate(payload(entry)));
  sortArtifacts(bundle, "receipts");
}

export function withoutField(value: Obj, field: string): Obj {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

export function rebuildEventChain(bundle: Obj, manifest: Obj): void {
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

export function rfcRootFromProof(leaf: Uint8Array, leafIndex: number, treeSize: number, proof: readonly Uint8Array[]): Uint8Array {
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

export function rebuildAnchor(bundle: Obj, oldManifestId: Uint8Array, manifestEnvelopeValue: CborValue): void {
  const anchors = artifacts(bundle).anchors as CborValue[];
  if (anchors.length === 0) return;
  const envelope = anchors.find((entry) => equalBytes(payload(entry).manifest_id as Uint8Array, oldManifestId));
  if (envelope === undefined) throw new Error("anchor for rebuilt manifest missing");
  if (!Array.isArray(manifestEnvelopeValue)) throw new Error("rebuilt manifest envelope malformed");
  const rebound = rebindAnchor(envelope, manifestEnvelopeValue);
  const next = payload(rebound);
  anchors[anchors.indexOf(envelope)] = rebound;
  sortArtifacts(bundle, "anchors");
  const heads = ((bundle.trust_inputs as Obj).expected_anchor_heads as Obj[]);
  const expected = heads.find((entry) => same(entry.target_id, (next.target as Obj).target_id));
  if (expected !== undefined) expected.root = next.anchor_root!;
}

export function rebuildManifest(bundle: Obj, mutation: (manifest: Obj) => void, keepAnchor = false): void {
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

export function addSecondEpoch(bundle: Obj, epochId: number, predecessorDigest: Uint8Array): void {
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

export function flipSignature(envelope: CborValue): CborValue[] {
  const value = cose(envelope);
  const signature = new Uint8Array(value[3] as Uint8Array);
  signature[0] = signature[0]! ^ 1;
  value[3] = signature;
  return [(envelope as CborValue[])[0]!, encodeCbor(value)];
}

// Re-link previous_event_digest along the event chain without touching bodies
// (rebuildEventChain rewrites close/anchor bodies from the manifest).
export function relinkEventChain(bundle: Obj): void {
  const list = artifacts(bundle).epoch_events as CborValue[];
  const events = list.map((envelope) => ({ envelope, value: clone(payload(envelope)) })).sort((a, b) => (a.value.event_seq as number) - (b.value.event_seq as number));
  let priorPayload: Uint8Array | undefined;
  const rebuilt: CborValue[] = [];
  for (const event of events) {
    if (priorPayload !== undefined) event.value.previous_event_digest = hash(priorPayload);
    event.value.event_id = domainHash("AAR-EPOCH-EVENT-ID-v1", withoutField(event.value, "event_id"));
    const signed = resign(event.envelope, event.value);
    rebuilt.push(signed);
    priorPayload = signed[0] as Uint8Array;
  }
  artifacts(bundle).epoch_events = rebuilt;
  sortArtifacts(bundle, "epoch_events");
}

// Mutate the last event of the chain (nothing links to it), re-identified and re-signed.
export function mutateLastEvent(bundle: Obj, mutate: (value: Obj) => void): void {
  mutateArtifact(bundle, "epoch_events", (p) => p.event === "anchor_submitted", mutate);
}

// Mutate the Merkle batch and point the carried proofs at its recomputed id (the leaf preimage excludes batch_id).
export function mutateMerkleBatch(bundle: Obj, mutate: (value: Obj) => void): void {
  mutateArtifact(bundle, "merkle_batches", () => true, mutate);
  const batchId = payload((artifacts(bundle).merkle_batches as CborValue[])[0]!).batch_id!;
  for (const proof of artifacts(bundle).merkle_proofs as Obj[]) proof.batch_id = batchId;
  sortArtifacts(bundle, "merkle_proofs");
}

// Re-bind an anchor record to a (possibly new) manifest envelope: leaf digest,
// inclusion root, head root, and anchor_id are recomputed and the record re-signed.
export function rebindAnchor(envelope: CborValue, manifestEnvelope: CborValue[], epochId?: number): CborValue[] {
  const manifest = payload(manifestEnvelope);
  const next = clone(payload(envelope));
  next.manifest_id = manifest.manifest_id!;
  next.manifest_digest = hash(manifestEnvelope[0] as Uint8Array);
  if (epochId !== undefined) next.epoch_id = epochId;
  delete next.consistency;
  const leafObject: Obj = { tenant_id: next.tenant_id!, site_id: next.site_id!, epoch_id: next.epoch_id!, manifest_id: next.manifest_id!, manifest_digest: next.manifest_digest! };
  const leaf = rfc6962Leaf(encodeCbor(["AAR-ANCHOR-LEAF-v1", leafObject]));
  const inclusion = next.inclusion as Obj;
  inclusion.leaf_digest = leaf;
  const root = rfcRootFromProof(leaf, inclusion.leaf_index as number, inclusion.tree_size as number, inclusion.siblings as Uint8Array[]);
  next.anchor_root = root;
  (next.head as Obj).root = root;
  next.anchor_id = domainHash("AAR-ANCHOR-ID-v1", withoutField(next, "anchor_id"));
  return resign(envelope, next);
}

// Add a second manifest (same plan) for epochId under owner, with an anchor
// record that binds it; no events accompany it (step 12 fixtures never reach 14).
export function addManifestWithAnchor(bundle: Obj, epochId: number, owner: TestKeyName): { manifest: Obj; anchor: Obj } {
  const manifestEnvelope = (artifacts(bundle).epoch_manifests as CborValue[])[0]!;
  const manifest = clone(payload(manifestEnvelope));
  manifest.epoch_id = epochId; manifest.epoch_owner_kid = TEST_KEYS[owner].kid;
  manifest.manifest_id = domainHash("AAR-EPOCH-MANIFEST-ID-v1", withoutField(manifest, "manifest_id"));
  const signed = signDetached(manifest, contentType(manifestEnvelope), owner).envelope;
  (artifacts(bundle).epoch_manifests as CborValue[]).push(signed); sortArtifacts(bundle, "epoch_manifests");
  const anchor = rebindAnchor((artifacts(bundle).anchors as CborValue[])[0]!, signed, epochId);
  (artifacts(bundle).anchors as CborValue[]).push(anchor); sortArtifacts(bundle, "anchors");
  return { manifest, anchor: payload(anchor) };
}

// Keep only the root observation and its derived child; move the child to a later
// epoch with a cross-epoch link naming the given manifest and anchor.
export function crossEpochChild(bundle: Obj, manifestId: Uint8Array, anchorId: Uint8Array): void {
  keepReceipts(bundle, (p) => p.kind === "observation");
  mutateReceiptWhere(bundle, (p) => p.kind === "observation" && !object(p.root), (p) => {
    (p.binding as Obj).epoch_id = 43;
    ((p.parents as Obj[])[0]!).cross_epoch = { source_manifest_id: manifestId, source_anchor_id: anchorId, reason: "historical_evidence" };
  });
}

// Clone the top-level delegation with a mutation, re-identify and re-sign it, and carry it.
export function addTopLevelDelegation(bundle: Obj, mutate: (delegation: Obj) => void): Obj {
  const list = artifacts(bundle).delegations as CborValue[];
  const next = clone(payload(list[0]!));
  mutate(next);
  next.delegation_id = domainHash("AAR-DELEGATION-ID-v1", withoutField(next, "delegation_id"));
  list.push(resign(list[0]!, next)); sortArtifacts(bundle, "delegations");
  return next;
}
