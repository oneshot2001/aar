import { CborScalar, CborValue, decodeCbor, encodeCbor, equalBytes, toHex } from "./cbor";
import { deterministicId, domainHash, hash, id16, P256_HALF_ORDER, signDetached } from "./crypto";
import { buildFixtures } from "./fixtures";
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

function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

function clone<T extends CborValue>(value: T): T {
  return decodeCbor(encodeCbor(value), { strict: true }) as T;
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
  add(bundleFixture("bundle/selector-commitment", "Replace the fixed-size selector commitment with a different digest.", (bundle) => { bundle.selector_commitment = deterministicId("wrong-selector-commitment"); }));
  add(bundleFixture("bundle/dependency-missing", "Remove the request envelope required by an agent_request root.", (bundle) => { artifacts(bundle).requests = []; }));
  add(bundleFixture("manifest/payload-missing", "Remove the canonical payload matching one referenced manifest digest.", (bundle) => { const inference = (artifacts(bundle).receipts as CborValue[]).map(payload).find((value) => value.kind === "inference")!; const digest = ((inference.body as Obj).prompt_manifest as Obj).digest as Uint8Array; artifacts(bundle).manifest_payloads = (artifacts(bundle).manifest_payloads as Obj[]).filter((value) => !equalBytes(value.digest as Uint8Array, digest)); }));
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

  const delegationFixture = (code: string, description: string, mutation: (value: Obj) => void): void => add(bundleFixture(code, description, (bundle) => mutateArtifact(bundle, "delegations", () => true, mutation)));
  delegationFixture("delegation/not-yet-valid", "Move delegation not_before after carried attempts.", (value) => { value.not_before = (value.not_after as number) - 1; });
  delegationFixture("delegation/expired", "Move delegation not_after before carried attempts.", (value) => { value.not_after = 1; });
  delegationFixture("delegation/scope", "Restrict delegation actions to the other valid action.", (value) => { (value.scope as Obj).actions = ["camera.ptz.preset"]; });
  delegationFixture("delegation/chain-invalid", "Name a missing parent delegation.", (value) => { value.parent_delegations = [deterministicId("missing-parent-delegation")]; });

  add(bundleFixture("replay/not-yet-valid", "Move a root receipt issued_at after its committed_at.", (bundle) => mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { (value.freshness as Obj).issued_at = ((value.emission as Obj).committed_at as number) + 1; })));
  add(bundleFixture("replay/expired", "Move a root receipt expires_at to its committed_at.", (bundle) => mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { (value.freshness as Obj).expires_at = (value.emission as Obj).committed_at!; })));
  add(bundleFixture("replay/parent-binding", "Replace intended_parents without changing parent edges.", (bundle) => mutateReceipt(bundle, "dispatch", (value) => { (value.freshness as Obj).intended_parents = []; })));
  add(bundleFixture("replay/invocation-mismatch", "Change one receipt invocation id inside a shared correlation flow.", (bundle) => mutateReceipt(bundle, "dispatch", (value) => { (value.freshness as Obj).invocation_id = id16("different-invocation"); })));
  add(bundleFixture("replay/one-time-reused", "Mark two different root receipts one-time under their shared replay coordinate.", (bundle) => { mutateReceiptWhere(bundle, (value) => value.kind === "observation" && object(value.root), (value) => { (value.freshness as Obj).use = "one_time"; }); mutateReceiptWhere(bundle, (value) => value.kind === "inference" && object(value.root), (value) => { (value.freshness as Obj).use = "one_time"; }); }));

  result.sort((a, b) => a.filename.localeCompare(b.filename));
  return result;
}
