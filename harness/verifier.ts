import { p256 } from "@noble/curves/nist.js";
import { CborScalar, CborValue, decodeCbor, encodeCbor, equalBytes, toHex } from "./cbor";
import { deterministicId, domainHash, hash, P256_HALF_ORDER, P256_ORDER, signDetached, signatureScalars } from "./crypto";
import { promotedRoot, rfc6962Leaf, verifyPromotedProof, verifyRfc6962Consistency, verifyRfc6962Inclusion } from "./merkle";
import { TEST_KEYS } from "./testkeys";

export type B1ReasonCode =
  | `resource/${string}` | `cbor/${string}` | `schema/${string}`
  | `cose/${string}` | `sig/${string}` | `key/${string}`
  | `hash/${string}` | `request/${string}` | `manifest/${string}`
  | `identity/${string}` | `receipt/${string}` | `credential/${string}`
  | `replay/${string}` | `delegation/${string}` | `bundle/${string}`
  | `graph/${string}` | `epoch/${string}` | `merkle/${string}`
  | `anchor/${string}` | `evidence/${string}`;

export type B1Failure = {
  ok: false;
  result: "nonconformant" | "indeterminate";
  reason: B1ReasonCode;
  step: number;
  path?: string;
  verdict?: Obj;
  verdictEnvelope?: Uint8Array;
};

export type B1Success = {
  ok: true;
  result: "conformant";
  completedThrough: 20;
  observations: readonly string[];
  verdict: Obj;
  verdictEnvelope: Uint8Array;
};

export type B1Verification = B1Failure | B1Success;

export interface ReplayUse {
  replayDomain: Uint8Array;
  invocationId: Uint8Array;
  contentDigest: Uint8Array;
}

export interface PriorEmission {
  issuerKid: Uint8Array;
  issuerSeq: number;
  epochOwnerKid: Uint8Array;
  epochId: number;
  epochSeq: number;
  receiptId: Uint8Array;
  envelopeDigest: Uint8Array;
}

export interface VerifyB1Options {
  replayState?: readonly ReplayUse[];
  priorEmissions?: readonly PriorEmission[];
  /** Used only when a bundle failure occurs before its evaluation time is known. */
  evaluationTime?: number;
  product?: string;
  version?: string;
  buildDigest?: Uint8Array;
  configDigest?: Uint8Array;
}

const LIMITS = {
  bundleBytes: 16_777_216,
  depth: 32,
  nodes: 10_000,
  edges: 50_000,
  parents: 64,
  proof: 65_536,
  proofs: 4_194_304,
  dagDepth: 128,
  dagWidth: 4_096,
  manifestEntries: 10_000,
  merkleLeaves: 1_048_576,
  credentialPath: 8,
} as const;

type Obj = Record<string, CborValue>;

function failure(step: number, reason: B1ReasonCode, path?: string, indeterminate = false): B1Failure {
  return { ok: false, result: indeterminate ? "indeterminate" : "nonconformant", reason, step, ...(path === undefined ? {} : { path }) };
}

function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

function uint(value: CborValue | undefined): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function bytes(value: CborValue | undefined, length?: number): value is Uint8Array {
  return value instanceof Uint8Array && (length === undefined || value.length === length);
}

function same(left: CborValue | undefined, right: CborValue | undefined): boolean {
  return left !== undefined && right !== undefined && equalBytes(encodeCbor(left), encodeCbor(right));
}

function without(value: Obj, field: string): Obj {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

function compareEncoded(left: CborValue, right: CborValue): number {
  const a = encodeCbor(left);
  const b = encodeCbor(right);
  if (a.length !== b.length) return a.length - b.length;
  for (let index = 0; index < a.length; index += 1) {
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  }
  return 0;
}

function observe(observations: string[], value: string): void {
  if (!observations.includes(value)) observations.push(value);
}

/* Step 2 needs category precedence, not merely the first parser exception.  This
 * scanner records all profile defects while retaining enough structure to decode
 * a clean item.  Syntax/depth are terminal because boundaries are then unknown. */
type Scan = {
  end: number;
  maxDepth: number;
  invalidUtf8: boolean;
  indefinite: boolean;
  duplicate: boolean;
  tag: boolean;
  float: boolean;
  nonCanonical: boolean;
};

class CborScanner {
  private readonly utf8 = new TextDecoder("utf-8", { fatal: true });
  constructor(private readonly input: Uint8Array) {}

  scan(): Scan {
    const state: Scan = { end: 0, maxDepth: 0, invalidUtf8: false, indefinite: false, duplicate: false, tag: false, float: false, nonCanonical: false };
    state.end = this.item(0, 0, state);
    return state;
  }

  private arg(offset: number, ai: number, state: Scan): { value: number; end: number } {
    if (ai < 24) return { value: ai, end: offset };
    const count = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : 0;
    if (count === 0) {
      if (ai === 31) state.indefinite = true;
      throw new Error(ai === 31 ? "indefinite" : "reserved");
    }
    if (offset + count > this.input.length) throw new Error("truncated");
    let value = 0;
    for (let i = 0; i < count; i += 1) value = value * 256 + this.input[offset + i]!;
    if (!Number.isSafeInteger(value)) throw new Error("unsafe integer");
    const shortest = value < 24 ? 0 : value <= 0xff ? 1 : value <= 0xffff ? 2 : value <= 0xffff_ffff ? 4 : 8;
    if (shortest !== count) state.nonCanonical = true;
    return { value, end: offset + count };
  }

  private item(offset: number, depth: number, state: Scan): number {
    state.maxDepth = Math.max(state.maxDepth, depth);
    if (depth > LIMITS.depth) throw new Error("depth");
    const initial = this.input[offset];
    if (initial === undefined) throw new Error("truncated");
    const major = initial >>> 5;
    const ai = initial & 31;
    if (major === 6) {
      state.tag = true;
      const tag = this.arg(offset + 1, ai, state);
      return this.item(tag.end, depth, state);
    }
    if (major === 7) {
      if (ai === 25 || ai === 26 || ai === 27) state.float = true;
      if (![20, 21, 22, 25, 26, 27].includes(ai)) throw new Error("simple");
      return this.arg(offset + 1, ai, state).end;
    }
    const argument = this.arg(offset + 1, ai, state);
    let cursor = argument.end;
    if (major === 0 || major === 1) return cursor;
    if (major === 2 || major === 3) {
      const end = cursor + argument.value;
      if (end > this.input.length) throw new Error("truncated");
      if (major === 3) {
        try { this.utf8.decode(this.input.slice(cursor, end)); } catch { state.invalidUtf8 = true; }
      }
      return end;
    }
    if (major === 4) {
      for (let i = 0; i < argument.value; i += 1) cursor = this.item(cursor, depth + 1, state);
      return cursor;
    }
    if (major === 5) {
      const seen = new Set<string>();
      let previous: Uint8Array | undefined;
      for (let i = 0; i < argument.value; i += 1) {
        const keyStart = cursor;
        cursor = this.item(cursor, depth + 1, state);
        const key = this.input.slice(keyStart, cursor);
        const keyHex = toHex(key);
        if (seen.has(keyHex)) state.duplicate = true;
        seen.add(keyHex);
        if (previous !== undefined && compareRaw(previous, key) >= 0) state.nonCanonical = true;
        previous = key;
        cursor = this.item(cursor, depth + 1, state);
      }
      return cursor;
    }
    throw new Error("major");
  }
}

function compareRaw(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

function profileDecode(input: Uint8Array, step: number, path: string, allowTopTag = false): CborValue | B1Failure {
  let scan: Scan;
  try {
    scan = new CborScanner(input).scan();
  } catch (error) {
    if (error instanceof Error && error.message === "depth") return failure(step, "resource/cbor-depth", path);
    if (error instanceof Error && error.message === "indefinite") return failure(step, "cbor/indefinite-length", path);
    return failure(step, "cbor/malformed", path);
  }
  if (scan.invalidUtf8) return failure(step, "cbor/invalid-utf8", path);
  if (scan.indefinite) return failure(step, "cbor/indefinite-length", path);
  if (scan.duplicate) return failure(step, "cbor/duplicate-key", path);
  if (scan.tag && !allowTopTag) return failure(step, "cbor/tag-forbidden", path);
  if (scan.float) return failure(step, "cbor/float-forbidden", path);
  if (scan.end !== input.length) return failure(step, "cbor/trailing-bytes", path);
  if (scan.nonCanonical) return failure(step, "cbor/non-canonical", path);
  try {
    return decodeCbor(input, { strict: true, maxDepth: LIMITS.depth });
  } catch {
    return failure(step, "cbor/malformed", path);
  }
}

const TOP_FIELDS = ["v", "created_at", "bundle_nonce", "claimed_profile", "selector", "selector_commitment", "coverage", "trust_inputs", "ranges", "artifacts"] as const;
const ARTIFACT_FIELDS = ["receipts", "requests", "delegations", "credentials", "status_snapshots", "rotations", "epoch_events", "epoch_manifests", "anchors", "merkle_batches", "merkle_proofs", "manifest_payloads"] as const;
const PROFILES = ["AAR-1", "AAR-2", "AAR-2A", "AAR-3"];
const KINDS = ["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"];
const KEY_USAGES = ["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "verifier_signing", "credential_issuing", "status_signing"];

function closed(value: Obj, allowed: readonly string[], required: readonly string[], step: number, path: string): B1Failure | undefined {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) return failure(step, "schema/unknown-field", `${path}.${key}`);
  for (const key of required) if (!(key in value)) return failure(step, "schema/missing-field", `${path}.${key}`, path.startsWith("bundle.trust_inputs"));
  return undefined;
}

function fixed(value: CborValue | undefined, length: number, step: number, path: string): B1Failure | undefined {
  if (!(value instanceof Uint8Array)) return failure(step, "schema/bad-type", path);
  if (value.length !== length) return failure(step, "schema/digest-size", path);
  return undefined;
}

function textSize(value: CborValue | undefined, max: number, step: number, path: string): B1Failure | undefined {
  if (typeof value !== "string") return failure(step, "schema/bad-type", path);
  const size = new TextEncoder().encode(value).length;
  if (size < 1 || size > max) return failure(step, "schema/string-size", path);
  return undefined;
}

function sortedUnique(values: CborValue[], path: string): B1Failure | undefined {
  for (let i = 1; i < values.length; i += 1) {
    const order = compareEncoded(values[i - 1]!, values[i]!);
    if (order === 0) return failure(3, "schema/duplicate-entry", path);
    if (order > 0) return failure(3, "schema/unsorted-set", path);
  }
  return undefined;
}

function validateBundleSchema(bundle: CborValue): B1Failure | undefined {
  if (!object(bundle)) return failure(3, "schema/bad-type", "bundle");
  let issue = closed(bundle, TOP_FIELDS, TOP_FIELDS, 3, "bundle");
  if (issue) return issue;
  if (typeof bundle.v !== "number" || !Number.isSafeInteger(bundle.v) || bundle.v < 0) return failure(3, "schema/bad-type", "bundle.v");
  if (bundle.v !== 2) return failure(3, "schema/version-wrong", "bundle.v");
  if (!uint(bundle.created_at)) return failure(3, "schema/bad-type", "bundle.created_at");
  if ((issue = fixed(bundle.bundle_nonce, 16, 3, "bundle.bundle_nonce"))) return issue;
  if (typeof bundle.claimed_profile !== "string") return failure(3, "schema/bad-type", "bundle.claimed_profile");
  if (!PROFILES.includes(bundle.claimed_profile)) return failure(3, "schema/enum-unknown", "bundle.claimed_profile");
  if (typeof bundle.coverage !== "string") return failure(3, "schema/bad-type", "bundle.coverage");
  if (!["valid_subset", "complete"].includes(bundle.coverage)) return failure(3, "schema/enum-unknown", "bundle.coverage");
  if ((issue = fixed(bundle.selector_commitment, 32, 3, "bundle.selector_commitment"))) return issue;
  if (!Array.isArray(bundle.ranges)) return failure(3, "schema/bad-type", "bundle.ranges");
  if (bundle.ranges.length > 256) return failure(3, "schema/out-of-range", "bundle.ranges");

  if (!object(bundle.selector)) return failure(3, "schema/bad-type", "bundle.selector");
  const selector = bundle.selector;
  issue = closed(selector, ["tenant_id", "site_id", "committed_from", "committed_until", "receipt_kinds", "subject_ids", "correlation_ids", "issuer_kids"], ["tenant_id", "site_id", "committed_from", "committed_until", "receipt_kinds"], 3, "bundle.selector");
  if (issue) return issue;
  if ((issue = fixed(selector.tenant_id, 16, 3, "bundle.selector.tenant_id")) || (issue = fixed(selector.site_id, 16, 3, "bundle.selector.site_id"))) return issue;
  if (!uint(selector.committed_from) || !uint(selector.committed_until)) return failure(3, "schema/bad-type", "bundle.selector.committed_from");
  if (!Array.isArray(selector.receipt_kinds)) return failure(3, "schema/bad-type", "bundle.selector.receipt_kinds");
  if (selector.receipt_kinds.length < 1 || selector.receipt_kinds.length > 6) return failure(3, "schema/out-of-range", "bundle.selector.receipt_kinds");
  for (const kind of selector.receipt_kinds) {
    if (typeof kind !== "string") return failure(3, "schema/bad-type", "bundle.selector.receipt_kinds");
    if (!KINDS.includes(kind)) return failure(3, "schema/enum-unknown", "bundle.selector.receipt_kinds");
  }
  if ((issue = sortedUnique(selector.receipt_kinds, "bundle.selector.receipt_kinds"))) return issue;
  for (const [name, size, max] of [["subject_ids", 16, 256], ["correlation_ids", 16, 256], ["issuer_kids", 32, 64]] as const) {
    const value = selector[name];
    if (value === undefined) continue;
    if (!Array.isArray(value)) return failure(3, "schema/bad-type", `bundle.selector.${name}`);
    if (value.length < 1 || value.length > max) return failure(3, "schema/out-of-range", `bundle.selector.${name}`);
    for (const entry of value) if ((issue = fixed(entry, size, 3, `bundle.selector.${name}`))) return issue;
    if ((issue = sortedUnique(value, `bundle.selector.${name}`))) return issue;
  }

  if (!object(bundle.trust_inputs)) return failure(3, "schema/bad-type", "bundle.trust_inputs");
  const trust = bundle.trust_inputs;
  issue = closed(trust, ["evaluation_time", "trust_store", "expected_anchor_heads", "verifier_policy_digest"], ["evaluation_time", "trust_store", "expected_anchor_heads", "verifier_policy_digest"], 3, "bundle.trust_inputs");
  if (issue) return issue;
  if (!uint(trust.evaluation_time)) return failure(3, "schema/bad-type", "bundle.trust_inputs.evaluation_time");
  if ((issue = fixed(trust.verifier_policy_digest, 32, 3, "bundle.trust_inputs.verifier_policy_digest"))) return issue;
  if (!Array.isArray(trust.expected_anchor_heads)) return failure(3, "schema/bad-type", "bundle.trust_inputs.expected_anchor_heads");
  if (trust.expected_anchor_heads.length < 1 || trust.expected_anchor_heads.length > 32) return failure(3, "schema/out-of-range", "bundle.trust_inputs.expected_anchor_heads");
  if (!object(trust.trust_store)) return failure(3, "schema/bad-type", "bundle.trust_inputs.trust_store");
  const store = trust.trust_store;
  issue = closed(store, ["digest", "snapshot_id", "created_at", "roots"], ["digest", "snapshot_id", "created_at", "roots"], 3, "bundle.trust_inputs.trust_store");
  if (issue) return issue;
  if ((issue = fixed(store.digest, 32, 3, "bundle.trust_inputs.trust_store.digest")) || (issue = fixed(store.snapshot_id, 32, 3, "bundle.trust_inputs.trust_store.snapshot_id"))) return issue;
  if (!uint(store.created_at) || !Array.isArray(store.roots)) return failure(3, "schema/bad-type", "bundle.trust_inputs.trust_store");
  if (store.roots.length < 1 || store.roots.length > 64) return failure(3, "schema/out-of-range", "bundle.trust_inputs.trust_store.roots");
  for (const [index, rootValue] of store.roots.entries()) {
    if (!object(rootValue)) return failure(3, "schema/bad-type", `bundle.trust_inputs.trust_store.roots[${index}]`);
    issue = closed(rootValue, ["root_id", "root_kid", "tenant_id", "allowed_sites", "allowed_key_usages"], ["root_id", "root_kid", "tenant_id", "allowed_sites", "allowed_key_usages"], 3, `bundle.trust_inputs.trust_store.roots[${index}]`);
    if (issue) return issue;
    if ((issue = fixed(rootValue.root_id, 32, 3, `bundle.trust_inputs.trust_store.roots[${index}].root_id`)) || (issue = fixed(rootValue.root_kid, 32, 3, `bundle.trust_inputs.trust_store.roots[${index}].root_kid`)) || (issue = fixed(rootValue.tenant_id, 16, 3, `bundle.trust_inputs.trust_store.roots[${index}].tenant_id`))) return issue;
    if (!Array.isArray(rootValue.allowed_sites) || !Array.isArray(rootValue.allowed_key_usages)) return failure(3, "schema/bad-type", `bundle.trust_inputs.trust_store.roots[${index}]`);
    if (rootValue.allowed_sites.length < 1 || rootValue.allowed_sites.length > 256 || rootValue.allowed_key_usages.length < 1 || rootValue.allowed_key_usages.length > 8) return failure(3, "schema/out-of-range", `bundle.trust_inputs.trust_store.roots[${index}]`);
    for (const site of rootValue.allowed_sites) if ((issue = fixed(site, 16, 3, `bundle.trust_inputs.trust_store.roots[${index}].allowed_sites`))) return issue;
    for (const usage of rootValue.allowed_key_usages) {
      if (typeof usage !== "string") return failure(3, "schema/bad-type", `bundle.trust_inputs.trust_store.roots[${index}].allowed_key_usages`);
      if (!KEY_USAGES.includes(usage)) return failure(3, "schema/enum-unknown", `bundle.trust_inputs.trust_store.roots[${index}].allowed_key_usages`);
    }
    if ((issue = sortedUnique(rootValue.allowed_sites, `bundle.trust_inputs.trust_store.roots[${index}].allowed_sites`)) || (issue = sortedUnique(rootValue.allowed_key_usages, `bundle.trust_inputs.trust_store.roots[${index}].allowed_key_usages`))) return issue;
  }
  for (const [index, headValue] of trust.expected_anchor_heads.entries()) {
    if (!object(headValue)) return failure(3, "schema/bad-type", `bundle.trust_inputs.expected_anchor_heads[${index}]`);
    issue = closed(headValue, ["target_id", "observed_at", "tree_size", "root"], ["target_id", "observed_at", "tree_size", "root"], 3, `bundle.trust_inputs.expected_anchor_heads[${index}]`);
    if (issue) return issue;
    if ((issue = fixed(headValue.target_id, 16, 3, `bundle.trust_inputs.expected_anchor_heads[${index}].target_id`)) || (issue = fixed(headValue.root, 32, 3, `bundle.trust_inputs.expected_anchor_heads[${index}].root`))) return issue;
    if (!uint(headValue.observed_at) || !uint(headValue.tree_size)) return failure(3, "schema/bad-type", `bundle.trust_inputs.expected_anchor_heads[${index}]`);
    if (headValue.tree_size < 1 || headValue.tree_size > 4_294_967_295) return failure(3, "schema/out-of-range", `bundle.trust_inputs.expected_anchor_heads[${index}].tree_size`);
  }

  if (!object(bundle.artifacts)) return failure(3, "schema/bad-type", "bundle.artifacts");
  issue = closed(bundle.artifacts, ARTIFACT_FIELDS, ARTIFACT_FIELDS, 3, "bundle.artifacts");
  if (issue) return issue;
  for (const field of ARTIFACT_FIELDS) if (!Array.isArray(bundle.artifacts[field])) return failure(3, "schema/bad-type", `bundle.artifacts.${field}`);
  for (const [index, value] of (bundle.artifacts.manifest_payloads as CborValue[]).entries()) {
    if (!object(value)) return failure(3, "schema/bad-type", `bundle.artifacts.manifest_payloads[${index}]`);
    issue = closed(value, ["digest", "media_type", "canonical_bytes"], ["digest", "media_type", "canonical_bytes"], 3, `bundle.artifacts.manifest_payloads[${index}]`);
    if (issue) return issue;
    if ((issue = fixed(value.digest, 32, 3, `bundle.artifacts.manifest_payloads[${index}].digest`))) return issue;
    if ((issue = textSize(value.media_type, 128, 3, `bundle.artifacts.manifest_payloads[${index}].media_type`))) return issue;
    if (!(value.canonical_bytes instanceof Uint8Array)) return failure(3, "schema/bad-type", `bundle.artifacts.manifest_payloads[${index}].canonical_bytes`);
    if (value.canonical_bytes.length < 1 || value.canonical_bytes.length > 1_048_576) return failure(3, "schema/out-of-range", `bundle.artifacts.manifest_payloads[${index}].canonical_bytes`);
  }

  // Artifact primary-ID sorting can only be checked when the envelope payload is
  // itself decodable; malformed embedded payloads remain step-6 failures.
  for (const field of ARTIFACT_FIELDS) {
    const array = bundle.artifacts[field] as CborValue[];
    const keys: CborValue[] = [];
    for (const entry of array) {
      const key = artifactSortKey(field, entry);
      if (key === undefined) { keys.length = 0; break; }
      keys.push(key);
    }
    if (keys.length > 1 && (issue = sortedUnique(keys, `bundle.artifacts.${field}`))) return issue;
  }

  // selector_commitment is deliberately last in step 3.
  if (!equalBytes(bundle.selector_commitment as Uint8Array, domainHash("AAR-BUNDLE-SELECTOR-v1", selector))) return failure(3, "bundle/selector-commitment", "bundle.selector_commitment");
  return undefined;
}

function artifactSortKey(field: typeof ARTIFACT_FIELDS[number], entry: CborValue): CborValue | undefined {
  if (field === "merkle_proofs") {
    return object(entry) && bytes(entry.batch_id, 32) && uint(entry.leaf_index) ? [entry.batch_id, entry.leaf_index] : undefined;
  }
  if (field === "manifest_payloads") return object(entry) && bytes(entry.digest, 32) ? entry.digest : undefined;
  if (!Array.isArray(entry) || !(entry[0] instanceof Uint8Array)) return undefined;
  try {
    const payload = decodeCbor(entry[0], { strict: true });
    if (!object(payload)) return undefined;
    const fieldName: Partial<Record<typeof ARTIFACT_FIELDS[number], string>> = {
      receipts: "receipt_id", requests: "request_id", delegations: "delegation_id", credentials: "credential_id",
      status_snapshots: "snapshot_id", rotations: "rotation_id", epoch_events: "event_id", epoch_manifests: "manifest_id",
      anchors: "anchor_id", merkle_batches: "batch_id",
    };
    return payload[fieldName[field]!];
  } catch { return undefined; }
}

function validateResourceCounts(bundle: Obj): B1Failure | undefined {
  const artifacts = bundle.artifacts as Obj;
  const receipts = artifacts.receipts as CborValue[];
  if (receipts.length > LIMITS.nodes) return failure(4, "resource/node-count", "bundle.artifacts.receipts");
  let edges = 0;
  for (let index = 0; index < receipts.length; index += 1) {
    const payload = envelopePayload(receipts[index]);
    if (!object(payload) || !Array.isArray(payload.parents)) continue;
    if (payload.parents.length > LIMITS.parents) return failure(4, "resource/parent-count", `bundle.artifacts.receipts[${index}].parents`);
    edges += payload.parents.length;
  }
  if (edges > LIMITS.edges) return failure(4, "resource/edge-count", "bundle.artifacts.receipts");
  let total = 0;
  for (let index = 0; index < (artifacts.merkle_proofs as CborValue[]).length; index += 1) {
    const length = encodeCbor((artifacts.merkle_proofs as CborValue[])[index]!).length;
    if (length > LIMITS.proof) return failure(4, "resource/proof-too-large", `bundle.artifacts.merkle_proofs[${index}]`);
    total += length;
  }
  for (const range of bundle.ranges as CborValue[]) {
    const length = encodeCbor(range).length;
    if (length > LIMITS.proof) return failure(4, "resource/proof-too-large", "bundle.ranges");
    total += length;
  }
  if (total > LIMITS.proofs) return failure(4, "resource/proofs-too-large", "bundle.artifacts.merkle_proofs");
  return undefined;
}

function envelopePayload(value: CborValue | undefined): CborValue | undefined {
  if (!Array.isArray(value) || !(value[0] instanceof Uint8Array)) return undefined;
  try { return decodeCbor(value[0], { strict: true }); } catch { return undefined; }
}

type ArtifactKind = "credential" | "rotation" | "status" | "request" | "delegation" | "epoch_event" | "epoch_manifest" | "anchor" | "merkle_batch" | "receipt" | "presentation";
type ParsedEnvelope = {
  kind: ArtifactKind;
  envelope: CborValue[];
  envelopeBytes: Uint8Array;
  payloadBytes: Uint8Array;
  payload: Obj;
  coseBytes: Uint8Array;
  protectedBytes: Uint8Array;
  protectedMap: Map<CborScalar, CborValue>;
  signature: Uint8Array;
  kid: Uint8Array;
};

const CONTENT_TYPE: Record<ArtifactKind, string> = {
  credential: "application/aar-credential+cbor;v=0.2", rotation: "application/aar-rotation+cbor;v=0.2",
  status: "application/aar-status+cbor;v=0.2", request: "application/aar-request+cbor;v=0.2",
  delegation: "application/aar-delegation+cbor;v=0.2", epoch_event: "application/aar-epoch-event+cbor;v=0.2",
  epoch_manifest: "application/aar-epoch-manifest+cbor;v=0.2", anchor: "application/aar-anchor-record+cbor;v=0.2",
  merkle_batch: "application/aar-merkle-batch+cbor;v=0.2", receipt: "application/aar-receipt+cbor;v=0.2",
  presentation: "application/aar-presentation+cbor;v=0.2",
};

const REQUIRED_PAYLOAD_FIELDS: Record<ArtifactKind, readonly string[]> = {
  credential: ["v", "credential_id", "subject_kid", "public_key", "issuer_kid", "principal_type", "principal_role", "tenant_id", "site_id", "valid_from", "valid_until", "cose_alg", "curve", "key_usage", "trust_anchor_id", "path", "profile_limits"],
  rotation: ["v", "rotation_id", "predecessor_credential_id", "successor_credential_id", "predecessor_kid", "successor_kid", "effective_at", "tenant_id", "site_id", "continuity_sequence"],
  status: ["v", "snapshot_id", "credential_id", "issuer_kid", "produced_at", "next_update", "lease_not_before", "lease_not_after", "profile", "status", "sequence", "tenant_id", "site_id"],
  request: ["v", "request_id", "action_intent_digest", "target_ep_kid", "tenant_id", "site_id", "correlation", "freshness", "legal"],
  delegation: ["v", "delegation_id", "issuer_credential_id", "subject_credential_id", "tenant_id", "site_id", "scope", "not_before", "not_after", "use", "replay_domain", "parent_delegations"],
  epoch_event: ["v", "event_id", "tenant_id", "site_id", "epoch_owner_kid", "epoch_id", "event_seq", "occurred_at", "event", "body"],
  epoch_manifest: ["v", "manifest_id", "tenant_id", "site_id", "epoch_owner_kid", "epoch_id", "opened_at", "closed_at", "sequence_span", "item_count", "close_reason", "max_duration_s", "late_arrival_policy", "anchor_deadline", "fork_policy", "receipt_index", "anchor_plan"],
  anchor: ["v", "anchor_id", "target", "tenant_id", "site_id", "epoch_id", "manifest_id", "manifest_digest", "submitted_at", "accepted_at", "anchor_tree_size", "anchor_leaf_index", "anchor_root", "inclusion", "head", "claim"],
  merkle_batch: ["v", "batch_id", "tenant_id", "site_id", "epoch_owner_kid", "epoch_id", "signer_kid", "tree_size", "root", "created_at", "claim"],
  receipt: ["v", "receipt_id", "kind", "issuer_principal_type", "issuer_role", "binding", "emission", "freshness", "legal", "evidence", "parents", "body"],
  presentation: ["presentation_id", "presenter_credential_id", "signer_mode", "artifacts", "transforms", "ui_implementation", "ui_version", "delivered_at", "session_id", "approval_scope_digest", "state"],
};

const OPTIONAL_PAYLOAD_FIELDS: Partial<Record<ArtifactKind, readonly string[]>> = {
  status: ["compromise_at"], delegation: ["invocation_id"], epoch_event: ["previous_event_digest"], epoch_manifest: ["predecessor_manifest_digest"], anchor: ["consistency"], receipt: ["root", "correlation"],
};

function parseEnvelope(entry: CborValue, kind: ArtifactKind, path: string): ParsedEnvelope | B1Failure {
  if (!Array.isArray(entry) || entry.length !== 2 || !(entry[0] instanceof Uint8Array) || !(entry[1] instanceof Uint8Array)) return failure(6, "schema/bad-type", path);
  const payloadBytes = entry[0];
  const coseBytes = entry[1];
  let coseScan: Scan;
  try { coseScan = new CborScanner(coseBytes).scan(); } catch (error) {
    if (error instanceof Error && error.message === "depth") return failure(6, "resource/cbor-depth", `${path}.cose`);
    return failure(6, "cose/bad-structure", `${path}.cose`);
  }
  if (coseBytes[0] !== undefined && (coseBytes[0]! >>> 5) === 6) return failure(6, "cose/tagged", `${path}.cose`);
  if (coseScan.end !== coseBytes.length || coseScan.nonCanonical || coseScan.invalidUtf8 || coseScan.indefinite || coseScan.duplicate || coseScan.tag || coseScan.float) {
    const decoded = profileDecode(coseBytes, 6, `${path}.cose`);
    if (!isFailure(decoded)) return failure(6, "cose/bad-structure", `${path}.cose`);
    return decoded;
  }
  let coseValue: CborValue;
  try { coseValue = decodeCbor(coseBytes, { strict: true }); } catch { return failure(6, "cose/bad-structure", `${path}.cose`); }
  if (!Array.isArray(coseValue) || coseValue.length !== 4 || !(coseValue[0] instanceof Uint8Array) || (!object(coseValue[1]) && !(coseValue[1] instanceof Map)) || !(coseValue[3] instanceof Uint8Array)) return failure(6, "cose/bad-structure", `${path}.cose`);
  const protectedBytes = coseValue[0];
  const protectedValue = profileDecode(protectedBytes, 6, `${path}.protected`);
  if (isFailure(protectedValue)) return protectedValue.reason.startsWith("cbor/") ? protectedValue : failure(6, "cose/protected-not-map", `${path}.protected`);
  if (!(protectedValue instanceof Map)) return failure(6, "cose/protected-not-map", `${path}.protected`);
  const protectedMap = protectedValue;
  const allowed = kind === "receipt" ? [1, 3, 4, -70000, -70001, -70002, -70003, -70004, -70005, -70006] : [1, 3, 4];
  for (const label of protectedMap.keys()) if (typeof label !== "number" || !allowed.includes(label)) return failure(6, "cose/protected-label", `${path}.protected`);
  if (!protectedMap.has(1)) return failure(6, "cose/alg-missing", `${path}.protected`);
  if (protectedMap.get(1) !== -7) return failure(6, "cose/alg-wrong", `${path}.protected`);
  if (!protectedMap.has(3)) return failure(6, "cose/content-type-missing", `${path}.protected`);
  if (protectedMap.get(3) !== CONTENT_TYPE[kind]) return failure(6, "cose/content-type-wrong", `${path}.protected`);
  if (!protectedMap.has(4)) return failure(6, "cose/kid-missing", `${path}.protected`);
  const kid = protectedMap.get(4);
  if (!(kid instanceof Uint8Array) || kid.length !== 32) return failure(6, "schema/digest-size", `${path}.protected.kid`);
  if (kind === "receipt") for (let label = -70000; label >= -70006; label -= 1) if (!protectedMap.has(label)) return failure(6, "cose/receipt-coordinate-missing", `${path}.protected.${label}`);
  const unprotected = coseValue[1];
  if ((unprotected instanceof Map && unprotected.has(1)) || (object(unprotected) && Object.prototype.hasOwnProperty.call(unprotected, "1"))) return failure(6, "cose/alg-in-unprotected", `${path}.unprotected`);
  if ((unprotected instanceof Map && unprotected.size !== 0) || (object(unprotected) && Object.keys(unprotected).length !== 0)) return failure(6, "cose/unprotected-not-empty", `${path}.unprotected`);
  if (coseValue[2] !== null) return failure(6, "cose/payload-not-detached", `${path}.payload`);
  const signature = coseValue[3];
  if (signature.length !== 64) return failure(6, looksLikeDer(signature) ? "sig/der-encoding" : "sig/bad-length", `${path}.signature`);
  const { r, s } = signatureScalars(signature);
  if (r === 0n || s === 0n) return failure(6, "sig/zero-rs", `${path}.signature`);
  if (s > P256_HALF_ORDER || r >= P256_ORDER || s >= P256_ORDER) return failure(6, "sig/high-s", `${path}.signature`);
  const payloadValue = profileDecode(payloadBytes, 6, `${path}.payload`);
  if (isFailure(payloadValue)) return payloadValue;
  if (!object(payloadValue)) return failure(6, "schema/bad-type", `${path}.payload`);
  const required = REQUIRED_PAYLOAD_FIELDS[kind];
  const allowedFields = [...required, ...(OPTIONAL_PAYLOAD_FIELDS[kind] ?? [])];
  let issue = closed(payloadValue, allowedFields, required, 6, `${path}.payload`);
  if (issue) return issue;
  if (kind !== "presentation") {
    if (typeof payloadValue.v !== "number" || !Number.isSafeInteger(payloadValue.v) || payloadValue.v < 0) return failure(6, "schema/bad-type", `${path}.payload.v`);
    if (payloadValue.v !== 2) return failure(6, "schema/version-wrong", `${path}.payload.v`);
  }
  if (kind === "credential") {
    if (typeof payloadValue.cose_alg !== "number" || typeof payloadValue.curve !== "string") return failure(6, "schema/bad-type", `${path}.payload.algorithm`);
    if (payloadValue.cose_alg !== -7 || payloadValue.curve !== "P-256") return failure(6, "schema/enum-unknown", `${path}.payload.algorithm`);
  }
  for (const [field, size] of payloadFixedFields(kind)) if ((issue = fixed(payloadValue[field], size, 6, `${path}.payload.${field}`))) return issue;
  if (kind === "receipt") {
    if (typeof payloadValue.kind !== "string" || !KINDS.includes(payloadValue.kind)) return failure(6, "schema/enum-unknown", `${path}.payload.kind`);
    if (!object(payloadValue.binding) || !object(payloadValue.emission) || !object(payloadValue.freshness) || !Array.isArray(payloadValue.parents) || !object(payloadValue.body)) return failure(6, "schema/bad-type", `${path}.payload`);
  }
  return { kind, envelope: entry, envelopeBytes: encodeCbor(entry), payloadBytes, payload: payloadValue, coseBytes, protectedBytes, protectedMap, signature, kid };
}

function payloadFixedFields(kind: ArtifactKind): readonly (readonly [string, number])[] {
  const primary: Partial<Record<ArtifactKind, string>> = { credential: "credential_id", rotation: "rotation_id", status: "snapshot_id", request: "request_id", delegation: "delegation_id", epoch_event: "event_id", epoch_manifest: "manifest_id", anchor: "anchor_id", merkle_batch: "batch_id", receipt: "receipt_id", presentation: "presentation_id" };
  return [[primary[kind]!, kind === "request" ? 16 : 32]];
}

function looksLikeDer(value: Uint8Array): boolean {
  if (value.length < 8 || value[0] !== 0x30 || value[1] !== value.length - 2 || value[2] !== 0x02) return false;
  const rLength = value[3];
  if (rLength === undefined) return false;
  const sTag = 4 + rLength;
  return value[sTag] === 0x02 && value[sTag + 1] !== undefined && sTag + 2 + value[sTag + 1]! === value.length;
}

function isFailure(value: unknown): value is B1Failure {
  return object(value as CborValue) && (value as unknown as B1Failure).ok === false;
}

type Parsed = Record<ArtifactKind, ParsedEnvelope[]> & {
  embeddedDelegations: { authorization: ParsedEnvelope; delegation: ParsedEnvelope }[];
};

function emptyParsed(): Parsed {
  return { credential: [], rotation: [], status: [], request: [], delegation: [], epoch_event: [], epoch_manifest: [], anchor: [], merkle_batch: [], receipt: [], presentation: [], embeddedDelegations: [] };
}

function parseAll(bundle: Obj): Parsed | B1Failure {
  const artifacts = bundle.artifacts as Obj;
  const parsed = emptyParsed();
  const order: readonly [keyof Obj, ArtifactKind][] = [
    ["credentials", "credential"], ["rotations", "rotation"], ["status_snapshots", "status"], ["requests", "request"], ["delegations", "delegation"],
    ["epoch_events", "epoch_event"], ["epoch_manifests", "epoch_manifest"], ["anchors", "anchor"], ["merkle_batches", "merkle_batch"], ["receipts", "receipt"],
  ];
  for (const [field, kind] of order) {
    const entries = artifacts[field] as CborValue[];
    for (let index = 0; index < entries.length; index += 1) {
      const result = parseEnvelope(entries[index]!, kind, `bundle.artifacts.${String(field)}[${index}]`);
      if (isFailure(result)) return result;
      parsed[kind].push(result);
      if (kind === "receipt" && object(result.payload.body)) {
        const presentation = result.payload.body.presentation;
        if (presentation !== undefined) {
          const nested = parseEnvelope(presentation, "presentation", `bundle.artifacts.${String(field)}[${index}].payload.body.presentation`);
          if (isFailure(nested)) return nested;
          parsed.presentation.push(nested);
        }
        const delegation = result.payload.body.delegation;
        if (delegation !== undefined) {
          const nested = parseEnvelope(delegation, "delegation", `bundle.artifacts.${String(field)}[${index}].payload.body.delegation`);
          if (isFailure(nested)) return nested;
          parsed.embeddedDelegations.push({ authorization: result, delegation: nested });
        }
      }
    }
  }
  return parsed;
}

function validateTrustInputs(bundle: Obj): B1Failure | undefined {
  const selector = bundle.selector as Obj;
  const trust = bundle.trust_inputs as Obj;
  const store = trust.trust_store as Obj;
  if (!equalBytes(store.digest as Uint8Array, domainHash("AAR-TRUST-STORE-v1", without(store, "digest")))) return failure(5, "hash/mismatch", "bundle.trust_inputs.trust_store.digest");
  for (const rootValue of store.roots as CborValue[]) {
    if (!object(rootValue)) return failure(5, "schema/bad-type", "bundle.trust_inputs.trust_store.roots");
    if (!same(rootValue.tenant_id, selector.tenant_id) || !Array.isArray(rootValue.allowed_sites) || !(rootValue.allowed_sites as CborValue[]).some((site) => same(site, selector.site_id))) return failure(5, "credential/root-not-accepted", "bundle.trust_inputs.trust_store.roots");
  }
  if ((trust.evaluation_time as number) < (store.created_at as number)) return failure(5, "schema/out-of-range", "bundle.trust_inputs.evaluation_time");
  return undefined;
}

function spkiPublicKey(spki: Uint8Array): Uint8Array | undefined {
  const prefix = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
  if (toHex(spki.slice(0, 26)) !== prefix || spki.length !== 91) return undefined;
  const key = spki.slice(26);
  return key.length === 65 && key[0] === 4 ? key : undefined;
}

function validateMechanics(bundle: Obj, parsed: Parsed): B1Failure | undefined {
  const credentialsByKid = new Map(parsed.credential.map((entry) => [toHex(entry.payload.subject_kid as Uint8Array), entry]));
  const roots = ((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[];
  const evaluationTime = ((bundle.trust_inputs as Obj).evaluation_time as number);
  const order: ArtifactKind[] = ["credential", "rotation", "status", "request", "delegation", "epoch_event", "epoch_manifest", "anchor", "merkle_batch", "receipt", "presentation"];
  for (const kind of order) for (const entry of kind === "delegation" ? [...parsed.delegation, ...parsed.embeddedDelegations.map((value) => value.delegation)] : parsed[kind]) {
    const credential = credentialsByKid.get(toHex(entry.kid));
    if (credential === undefined) return failure(6, "key/not-found", `${kind}.kid`, true);
    const publicKeyBytes = credential.payload.public_key;
    if (!(publicKeyBytes instanceof Uint8Array)) return failure(6, "schema/bad-type", "credential.public_key");
    if (!equalBytes(hash(publicKeyBytes), credential.payload.subject_kid as Uint8Array)) return failure(6, "credential/kid-key-mismatch", "credential.public_key");
    const publicKey = spkiPublicKey(publicKeyBytes);
    if (publicKey === undefined) return failure(6, "key/not-p256", "credential.public_key");
    const requiredUsage = usageFor(entry);
    if (credential.payload.key_usage !== requiredUsage) return failure(6, kind === "receipt" ? "receipt/signer-role-mismatch" : "credential/usage-mismatch", `${kind}.kid`);
    if (["epoch_event", "epoch_manifest", "merkle_batch"].includes(kind) && !same(entry.kid, entry.payload.epoch_owner_kid)) return failure(6, "credential/usage-mismatch", `${kind}.epoch_owner_kid`);
    if (kind === "merkle_batch" && !same(entry.payload.signer_kid, entry.payload.epoch_owner_kid)) return failure(6, "credential/usage-mismatch", "merkle_batch.signer_kid");
    const signingTime = kind === "receipt" && object(entry.payload.emission) && uint(entry.payload.emission.committed_at) ? entry.payload.emission.committed_at : evaluationTime;
    if (!uint(credential.payload.valid_from) || !uint(credential.payload.valid_until)) return failure(6, "schema/bad-type", "credential.validity");
    if (signingTime < credential.payload.valid_from) return failure(6, "credential/not-yet-valid", "credential.valid_from");
    if (signingTime >= credential.payload.valid_until) return failure(6, "credential/expired", "credential.valid_until");
    if (kind === "receipt") {
      const binding = entry.payload.binding as Obj;
      const emission = entry.payload.emission as Obj;
      const coordinateValues: readonly [number, CborValue | undefined][] = [[-70000, entry.payload.issuer_principal_type], [-70001, binding.tenant_id], [-70002, binding.site_id], [-70003, binding.epoch_id], [-70004, binding.epoch_seq], [-70005, emission.issuer_seq], [-70006, entry.payload.issuer_role]];
      if (coordinateValues.some(([label, value]) => !same(entry.protectedMap.get(label), value))) return failure(6, "cose/receipt-coordinate-mismatch", "receipt.protected");
    }
    const sigStructure = encodeCbor(["Signature1", entry.protectedBytes, new Uint8Array(), entry.payloadBytes]);
    if (!p256.verify(entry.signature, hash(sigStructure), publicKey, { prehash: false, lowS: true, format: "compact" })) return failure(6, "sig/verify-failed", `${kind}.signature`);
    if (kind === "credential" && (entry.payload.path as CborValue[]).length === 0) {
      if (!roots.some((root) => same(root.root_kid, entry.payload.subject_kid))) return failure(6, "credential/root-not-accepted", "credential.path");
    }
  }
  return undefined;
}

function usageFor(entry: ParsedEnvelope): string {
  if (entry.kind === "request") return "agent_signing";
  if (entry.kind === "delegation") return "authority_signing";
  if (entry.kind === "credential" || entry.kind === "rotation") return "credential_issuing";
  if (entry.kind === "status") return "status_signing";
  if (["epoch_event", "epoch_manifest", "merkle_batch"].includes(entry.kind)) return "ep_signing";
  if (entry.kind === "anchor") return "anchor_signing";
  if (entry.kind === "presentation") return entry.payload.signer_mode === "approver_originated" ? "approver_signing" : "ep_signing";
  const role = entry.payload.issuer_role;
  return role === "agent" ? "agent_signing" : role === "enforcement_point" ? "ep_signing" : role === "outcome_observer" ? "outcome_signing" : "";
}

const ID_DOMAINS: Partial<Record<ArtifactKind, readonly [string, string]>> = {
  credential: ["credential_id", "AAR-CREDENTIAL-ID-v1"], rotation: ["rotation_id", "AAR-ROTATION-ID-v1"], status: ["snapshot_id", "AAR-STATUS-ID-v1"],
  delegation: ["delegation_id", "AAR-DELEGATION-ID-v1"], epoch_event: ["event_id", "AAR-EPOCH-EVENT-ID-v1"], epoch_manifest: ["manifest_id", "AAR-EPOCH-MANIFEST-ID-v1"],
  anchor: ["anchor_id", "AAR-ANCHOR-ID-v1"], merkle_batch: ["batch_id", "AAR-BATCH-ID-v1"], presentation: ["presentation_id", "AAR-PRESENTATION-MANIFEST-v1"],
};

function validateContent(bundle: Obj, parsed: Parsed): B1Failure | undefined {
  for (const kind of ["delegation", "credential", "status", "rotation", "epoch_event", "epoch_manifest", "anchor", "merkle_batch", "presentation"] as ArtifactKind[]) {
    const domain = ID_DOMAINS[kind];
    if (domain === undefined) continue;
    for (const entry of parsed[kind]) {
      const [field, label] = domain;
      if (!equalBytes(entry.payload[field] as Uint8Array, domainHash(label, without(entry.payload, field)))) return failure(7, kind === "presentation" ? "hash/mismatch" : "identity/artifact-id-mismatch", `${kind}.${field}`);
    }
  }
  for (const { delegation } of parsed.embeddedDelegations) {
    if (!equalBytes(delegation.payload.delegation_id as Uint8Array, domainHash("AAR-DELEGATION-ID-v1", without(delegation.payload, "delegation_id")))) return failure(7, "identity/artifact-id-mismatch", "authorization.body.delegation.delegation_id");
  }
  for (const entry of parsed.receipt) {
    const expected = domainHash("AAR-RECEIPT-ID-v1", entry.protectedBytes, without(entry.payload, "receipt_id"));
    if (!equalBytes(entry.payload.receipt_id as Uint8Array, expected)) return failure(7, "identity/receipt-id-mismatch", "receipt.receipt_id");
    const hashIssue = receiptHashes(entry.payload);
    if (hashIssue) return hashIssue;
  }
  const artifacts = bundle.artifacts as Obj;
  const manifests = new Map<string, Obj>();
  for (const value of artifacts.manifest_payloads as CborValue[]) {
    if (!object(value) || !bytes(value.digest, 32) || !(value.canonical_bytes instanceof Uint8Array)) continue;
    if (!equalBytes(hash(value.canonical_bytes), value.digest)) return failure(7, "hash/mismatch", "bundle.artifacts.manifest_payloads");
    manifests.set(toHex(value.digest), value);
  }
  for (const entry of parsed.receipt) {
    if (entry.payload.kind !== "inference") continue;
    const body = entry.payload.body as Obj;
    for (const name of ["prompt_manifest", "retrieval_manifest", "tool_transcript_manifest"]) {
      const reference = body[name];
      if (!object(reference) || !bytes(reference.digest, 32)) continue;
      const supplied = manifests.get(toHex(reference.digest));
      if (supplied === undefined) return failure(7, "manifest/payload-missing", `receipt.body.${name}`);
      if (supplied.media_type !== reference.media_type) return failure(7, "manifest/media-type-mismatch", `receipt.body.${name}`);
      if (!(supplied.canonical_bytes instanceof Uint8Array) || !equalBytes(hash(supplied.canonical_bytes), reference.digest)) return failure(7, "hash/mismatch", `manifest_payloads.${name}`);
    }
  }
  const requests = new Map(parsed.request.map((entry) => [toHex(entry.payload.request_id as Uint8Array), entry]));
  for (const entry of parsed.receipt) {
    if (!object(entry.payload.root) || entry.payload.root.kind !== "agent_request") continue;
    const request = bytes(entry.payload.root.request_id, 16) ? requests.get(toHex(entry.payload.root.request_id)) : undefined;
    if (request === undefined) return failure(7, "bundle/dependency-missing", "receipt.root.request_id");
    if (!bytes(entry.payload.root.request_commitment, 32) || !equalBytes(entry.payload.root.request_commitment, hash(request.payloadBytes))) return failure(7, "request/commitment-mismatch", "receipt.root.request_commitment");
    // D-60. A correct commitment proves these are the bytes the agent signed; it does
    // not prove the agent signed them for THIS tenant, site, or enforcement point.
    // The request duplicates coordinates the receipt binding also carries, so require
    // agreement — the same rule every other duplicated-coordinate pair already gets.
    // BOTH sides are type-guarded: a missing or non-conforming coordinate is treated
    // as disagreement (normative, CONFORMANCE step 7). The binding-side guard also
    // closes an equalBytes type-confusion (Uint8Array.every against a plain array of
    // the same integers returns true) that made these clauses silent no-ops for
    // array-typed binding coordinates.
    const binding = entry.payload.binding;
    const correlation = request.payload.correlation;
    const coordinate = (container: CborValue | undefined, key: string, size: number): Uint8Array | undefined => {
      if (!object(container)) return undefined;
      const value = container[key];
      return bytes(value, size) ? value : undefined;
    };
    const pairs: readonly (readonly [Uint8Array | undefined, Uint8Array | undefined, string])[] = [
      [coordinate(request.payload, "tenant_id", 16), coordinate(binding, "tenant_id", 16), "request.tenant_id"],
      [coordinate(request.payload, "site_id", 16), coordinate(binding, "site_id", 16), "request.site_id"],
      [coordinate(request.payload, "target_ep_kid", 32), coordinate(binding, "epoch_owner_kid", 32), "request.target_ep_kid"],
      [coordinate(correlation, "target_ep_kid", 32), coordinate(request.payload, "target_ep_kid", 32), "request.correlation.target_ep_kid"],
    ];
    for (const [left, right, at] of pairs) {
      if (left === undefined || right === undefined || !equalBytes(left, right)) return failure(7, "request/coordinate-mismatch", at);
    }
  }
  return undefined;
}

function receiptHashes(payload: Obj): B1Failure | undefined {
  const body = payload.body as Obj;
  if (payload.kind === "observation" && object(body.consumption)) {
    if (!equalBytes(body.consumption.manifest_digest as Uint8Array, domainHash("AAR-CONSUMPTION-MANIFEST-v1", without(body.consumption, "manifest_digest")))) return failure(7, "hash/mismatch", "receipt.body.consumption.manifest_digest");
  }
  if (payload.kind === "inference" && object(body.conclusion) && body.conclusion.canonical_cbor instanceof Uint8Array && body.conclusion.digest instanceof Uint8Array) {
    if (!equalBytes(hash(body.conclusion.canonical_cbor), body.conclusion.digest)) return failure(7, "hash/mismatch", "receipt.body.conclusion.digest");
  }
  if (payload.kind === "authorization" && object(body.decision)) {
    if (!equalBytes(body.decision.decision_commitment as Uint8Array, domainHash("AAR-DECISION-RECORD-v1", without(body.decision, "decision_commitment")))) return failure(7, "hash/mismatch", "receipt.body.decision.decision_commitment");
  }
  if (payload.kind === "action_attempt" && object(body.action) && object(body.command)) {
    if (!equalBytes(body.action.parameters_digest as Uint8Array, hash(body.action.parameters_cbor as Uint8Array))) return failure(7, "hash/mismatch", "receipt.body.action.parameters_digest");
    if (!equalBytes(body.command.command_digest as Uint8Array, hash(body.command.canonical_command as Uint8Array))) return failure(7, "hash/mismatch", "receipt.body.command.command_digest");
    if (!equalBytes(body.command.command_id as Uint8Array, domainHash("AAR-COMMAND-MANIFEST-v1", without(body.command, "command_id")))) return failure(7, "hash/mismatch", "receipt.body.command.command_id");
  }
  return undefined;
}

function validateCredentialLifecycle(bundle: Obj, parsed: Parsed): B1Failure | undefined {
  const credentials = new Map(parsed.credential.map((entry) => [toHex(entry.payload.credential_id as Uint8Array), entry]));
  const roots = ((bundle.trust_inputs as Obj).trust_store as Obj).roots as Obj[];
  const evaluation = (bundle.trust_inputs as Obj).evaluation_time as number;
  const roleKids = new Map<string, string>();
  for (const entry of parsed.credential) {
    const role = entry.payload.principal_role as string;
    if (!["agent", "enforcement_point", "authority_source"].includes(role)) continue;
    const kid = toHex(entry.payload.subject_kid as Uint8Array);
    const prior = roleKids.get(kid);
    if (prior !== undefined && prior !== role) return failure(8, "credential/role-key-reuse", "credentials");
    roleKids.set(kid, role);
  }
  for (const entry of parsed.credential) {
    const payload = entry.payload;
    const path = payload.path;
    if (!Array.isArray(path) || path.length > 8) return failure(8, "schema/out-of-range", "credential.path");
    const seen = new Set([toHex(payload.credential_id as Uint8Array)]);
    let expectedIssuer = payload.issuer_kid as Uint8Array;
    for (const id of path) {
      if (!bytes(id, 32) || seen.has(toHex(id))) return failure(8, "credential/path-invalid", "credential.path");
      seen.add(toHex(id));
      const issuer = credentials.get(toHex(id));
      if (issuer === undefined || !equalBytes(issuer.payload.subject_kid as Uint8Array, expectedIssuer)) return failure(8, "credential/path-invalid", "credential.path");
      expectedIssuer = issuer.payload.issuer_kid as Uint8Array;
    }
  }
  for (const entry of parsed.credential) {
    const payload = entry.payload;
    const path = payload.path as CborValue[];
    const last = path.length === 0 ? payload : credentials.get(toHex(path[path.length - 1] as Uint8Array))?.payload;
    if (last === undefined || !roots.some((root) => same(root.root_kid, last.subject_kid) && same(root.tenant_id, payload.tenant_id) && Array.isArray(root.allowed_sites) && root.allowed_sites.some((site) => same(site, payload.site_id)))) return failure(8, "credential/root-not-accepted", "credential.path");
  }
  const rotations = [...parsed.rotation].sort((a, b) => (a.payload.continuity_sequence as number) - (b.payload.continuity_sequence as number));
  let previous: ParsedEnvelope | undefined;
  for (const rotation of rotations) {
    const predecessor = credentials.get(toHex(rotation.payload.predecessor_credential_id as Uint8Array));
    const successor = credentials.get(toHex(rotation.payload.successor_credential_id as Uint8Array));
    if (predecessor === undefined || successor === undefined || !same(predecessor.payload.subject_kid, rotation.payload.predecessor_kid) || !same(successor.payload.subject_kid, rotation.payload.successor_kid)) return failure(8, "credential/rotation-invalid", "rotation");
    if (previous !== undefined && ((rotation.payload.continuity_sequence as number) <= (previous.payload.continuity_sequence as number) || (rotation.payload.effective_at as number) <= (previous.payload.effective_at as number))) return failure(8, "credential/rotation-rollback", "rotation");
    previous = rotation;
  }
  for (const status of parsed.status) {
    const payload = status.payload;
    const maxAge = payload.profile === "AAR-1" || payload.profile === "AAR-2" ? 86_400 : 300;
    const maxLease = payload.profile === "AAR-1" || payload.profile === "AAR-2" ? 86_400 : 3_600;
    if ((payload.lease_not_after as number) - (payload.lease_not_before as number) > maxLease) return failure(8, "credential/lease-too-long", "status.lease_not_after");
    if (evaluation - (payload.produced_at as number) > maxAge || evaluation >= (payload.next_update as number)) return failure(8, "credential/status-stale", "status.produced_at");
    if (payload.status === "revoked") return failure(8, "credential/revoked", "status.status");
    if (payload.status === "compromised" && (!uint(payload.compromise_at) || evaluation >= payload.compromise_at)) return failure(8, "credential/compromised", "status.status");
    if (payload.status === "unknown") return failure(8, "credential/status-unknown", "status.status");
    if (evaluation < (payload.lease_not_before as number)) return failure(8, "credential/not-yet-valid", "status.lease_not_before");
    if (evaluation >= (payload.lease_not_after as number)) return failure(8, "credential/lease-expired", "status.lease_not_after");
  }
  for (const receipt of parsed.receipt) {
    if (receipt.payload.kind !== "authorization") continue;
    const decision = (receipt.payload.body as Obj).decision;
    if (!object(decision) || !Array.isArray(decision.status_snapshot_ids)) continue;
    for (const id of decision.status_snapshot_ids) if (!parsed.status.some((status) => same(status.payload.snapshot_id, id))) return failure(8, "credential/status-missing", "receipt.body.decision.status_snapshot_ids");
  }
  return undefined;
}

function validateEmission(parsed: Parsed, prior: readonly PriorEmission[], observations: string[]): B1Failure | undefined {
  const byId = new Map<string, ParsedEnvelope>();
  const issuerCoordinates = new Map<string, string>();
  const epochCoordinates = new Map<string, string>();
  for (const receipt of parsed.receipt) {
    const id = toHex(receipt.payload.receipt_id as Uint8Array);
    const existing = byId.get(id);
    if (existing !== undefined) {
      if (!equalBytes(existing.envelopeBytes, receipt.envelopeBytes)) return failure(9, "identity/reuse", "receipts");
      observe(observations, "duplicate_exact");
      continue;
    }
    byId.set(id, receipt);
    for (const old of prior) {
      if (equalBytes(old.receiptId, receipt.payload.receipt_id as Uint8Array)) {
        if (!equalBytes(old.envelopeDigest, hash(receipt.envelopeBytes))) return failure(9, "identity/reuse", "receipts");
        observe(observations, "duplicate_exact");
      }
    }
    const binding = receipt.payload.binding as Obj;
    const emission = receipt.payload.emission as Obj;
    const issuer = `${toHex(receipt.kid)}:${emission.issuer_seq as number}`;
    const epoch = `${toHex(binding.epoch_owner_kid as Uint8Array)}:${binding.epoch_id as number}:${binding.epoch_seq as number}`;
    if (issuerCoordinates.has(issuer) && issuerCoordinates.get(issuer) !== id) return failure(9, "identity/coordinate-equivocation", "receipt.emission.issuer_seq");
    if (epochCoordinates.has(epoch) && epochCoordinates.get(epoch) !== id) return failure(9, "identity/coordinate-equivocation", "receipt.binding.epoch_seq");
    issuerCoordinates.set(issuer, id); epochCoordinates.set(epoch, id);
    for (const old of prior) {
      if (same(old.issuerKid, receipt.kid) && (emission.issuer_seq as number) < old.issuerSeq) return failure(9, "identity/issuer-sequence-rollback", "receipt.emission.issuer_seq");
      if (same(old.epochOwnerKid, binding.epoch_owner_kid) && old.epochId === binding.epoch_id && (binding.epoch_seq as number) <= old.epochSeq) return failure(9, "identity/epoch-sequence-rollback", "receipt.binding.epoch_seq");
    }
  }
  return undefined;
}

const KIND_ROLES: Record<string, readonly string[]> = { observation: ["agent", "enforcement_point", "outcome_observer"], inference: ["agent"], authorization: ["enforcement_point"], action_attempt: ["enforcement_point"], dispatch: ["enforcement_point"], outcome_observation: ["outcome_observer"] };

function bodyKind(body: Obj): string | undefined {
  if ("source_device" in body && "consumption" in body) return "observation";
  if ("model" in body && "conclusion" in body) return "inference";
  if ("decision" in body && "delegation" in body) return "authorization";
  if ("action" in body && "command" in body && "disposition" in body) return "action_attempt";
  if ("attempt_id" in body && "dispatched_at" in body) return "dispatch";
  if ("observer" in body && "observation_commitment" in body) return "outcome_observation";
  return undefined;
}

function validateReceiptSemantics(bundle: Obj, parsed: Parsed): B1Failure | undefined {
  const byId = new Map(parsed.receipt.map((entry) => [toHex(entry.payload.receipt_id as Uint8Array), entry]));
  const manifestDigests = new Set(((bundle.artifacts as Obj).manifest_payloads as Obj[]).map((value) => toHex(value.digest as Uint8Array)));
  for (const receipt of parsed.receipt) {
    const payload = receipt.payload;
    const body = payload.body as Obj;
    if (bodyKind(body) !== payload.kind) return failure(10, "receipt/kind-body-mismatch", "receipt.body");
    if (!(KIND_ROLES[payload.kind as string] ?? []).includes(payload.issuer_role as string)) return failure(10, "receipt/signer-role-mismatch", "receipt.issuer_role");
    const evidence = payload.evidence as Obj;
    const needsProvenance = payload.kind === "inference";
    const needsOutcome = ["action_attempt", "dispatch", "outcome_observation"].includes(payload.kind as string);
    if (!object(evidence) || !object(evidence.time) || (needsProvenance !== object(evidence.provenance)) || (needsOutcome !== object(evidence.outcome))) return failure(10, "receipt/kind-body-mismatch", "receipt.evidence");
    if (payload.kind === "inference") {
      const consumption = body.consumption_manifest_id;
      let resolved = bytes(consumption, 32) && manifestDigests.has(toHex(consumption));
      if (!resolved) for (const edge of payload.parents as Obj[]) {
        if (edge.edge_type !== "derived_from") continue;
        if (!bytes(edge.parent_id, 32)) continue;
        const parent = byId.get(toHex(edge.parent_id));
        const parentConsumption = parent?.payload.kind === "observation" ? (parent.payload.body as Obj).consumption : undefined;
        if (object(parentConsumption) && same(parentConsumption.manifest_digest, consumption)) resolved = true;
      }
      if (!resolved) return failure(10, "receipt/consumption-ref-unresolved", "receipt.body.consumption_manifest_id");
    }
    if (payload.kind === "observation" && object(body.consumption) && Array.isArray(body.consumption.items)) {
      for (let index = 0; index < body.consumption.items.length; index += 1) {
        const item = body.consumption.items[index];
        if (!object(item) || item.ordinal !== index) return failure(10, "receipt/manifest-inconsistent", "receipt.body.consumption.items");
        if (Array.isArray(item.transformations)) for (let transformIndex = 0; transformIndex < item.transformations.length; transformIndex += 1) {
          const transform = item.transformations[transformIndex];
          if (!object(transform) || transform.ordinal !== transformIndex) return failure(10, "receipt/manifest-inconsistent", "receipt.body.consumption.items.transformations");
        }
      }
    }
    if (payload.kind === "authorization") {
      const decision = body.decision as Obj;
      const hasPresentation = body.presentation !== undefined;
      if ((decision.decision === "permit_with_approval") !== hasPresentation || (decision.decision === "permit_with_approval") !== (decision.approver_credential_id !== undefined)) return failure(10, "receipt/decision-presentation", "receipt.body");
    }
    if (payload.kind === "action_attempt") {
      if ((body.disposition === "not_dispatched") !== (body.refusal_reason !== undefined)) return failure(10, "receipt/attempt-disposition", "receipt.body.disposition");
      const action = body.action as Obj; const command = body.command as Obj;
      let decodedCommand: CborValue | undefined;
      try { decodedCommand = decodeCbor(command.canonical_command as Uint8Array, { strict: true }); } catch { /* hash checks already ran */ }
      if (!same(action.action_name, command.action_name) || !same(action.target_id, command.target_id) || !object(decodedCommand) || !same(decodedCommand.operation, action.action_name) || !same(decodedCommand.target, action.target_id) || !same(decodedCommand.parameters_digest, action.parameters_digest)) return failure(10, "receipt/action-command-mismatch", "receipt.body.command");
    }
    if (payload.kind === "dispatch") {
      const edge = (payload.parents as Obj[]).find((parent) => parent.edge_type === "attempted_as");
      const attempt = edge && bytes(edge.parent_id, 32) ? byId.get(toHex(edge.parent_id)) : undefined;
      if (attempt !== undefined && (!same(body.attempt_id, attempt.payload.receipt_id) || !same(body.command_id, (attempt.payload.body as Obj).command instanceof Object ? ((attempt.payload.body as Obj).command as Obj).command_id : undefined))) return failure(10, "receipt/dispatch-attempt-mismatch", "receipt.body");
    }
    if (payload.kind === "outcome_observation") {
      const edge = (payload.parents as Obj[]).find((parent) => parent.edge_type === "observed_outcome");
      if (edge !== undefined && !same(body.subject_id, edge.parent_id)) return failure(10, "receipt/outcome-subject-mismatch", "receipt.body.subject_id");
    }
  }
  return undefined;
}

function validateReplay(parsed: Parsed, replayState: readonly ReplayUse[]): B1Failure | undefined {
  const uses = new Map(replayState.map((use) => [`${toHex(use.replayDomain)}:${toHex(use.invocationId)}`, use.contentDigest]));
  const flow = new Map<string, string>();
  for (const receipt of parsed.receipt) {
    const payload = receipt.payload;
    const freshness = payload.freshness as Obj;
    const emission = payload.emission as Obj;
    if ((freshness.issued_at as number) > (emission.committed_at as number)) return failure(11, "replay/not-yet-valid", "receipt.freshness.issued_at");
    if ((emission.committed_at as number) >= (freshness.expires_at as number)) return failure(11, "replay/expired", "receipt.freshness.expires_at");
    const parents = (payload.parents as Obj[]).map((parent) => parent.parent_id!);
    if (!Array.isArray(freshness.intended_parents) || !same(freshness.intended_parents, parents)) return failure(11, "replay/parent-binding", "receipt.freshness.intended_parents");
    const correlation = object(payload.correlation) && bytes(payload.correlation.correlation_id, 16) ? toHex(payload.correlation.correlation_id) : undefined;
    const coordinate = `${toHex(freshness.replay_domain as Uint8Array)}:${toHex(freshness.invocation_id as Uint8Array)}`;
    if (correlation !== undefined) {
      const prior = flow.get(correlation);
      if (prior !== undefined && prior !== coordinate) return failure(11, "replay/invocation-mismatch", "receipt.freshness.invocation_id");
      flow.set(correlation, coordinate);
    }
    if (freshness.use === "one_time") {
      const digest = hash(receipt.envelopeBytes);
      const prior = uses.get(coordinate);
      if (prior !== undefined && !equalBytes(prior, digest)) return failure(11, "replay/one-time-reused", "receipt.freshness");
      uses.set(coordinate, digest);
    }
  }
  return undefined;
}

const EDGE_MATRIX: Readonly<Record<string, readonly [readonly string[], readonly string[]]>> = {
  derived_from: [["observation", "inference"], ["observation", "inference"]],
  requested_by: [["observation", "inference"], ["inference", "authorization", "action_attempt"]],
  authorized_by: [["authorization"], ["action_attempt"]],
  triggered_by: [["observation", "inference"], ["authorization", "action_attempt"]],
  attempted_as: [["action_attempt"], ["dispatch"]],
  observed_outcome: [["action_attempt", "dispatch"], ["outcome_observation"]],
  supports: [["observation", "inference", "outcome_observation"], ["inference", "authorization", "outcome_observation"]],
};

function receiptsById(parsed: Parsed): Map<string, ParsedEnvelope> {
  return new Map(parsed.receipt.map((entry) => [toHex(entry.payload.receipt_id as Uint8Array), entry]));
}

function validateGraph(parsed: Parsed): B1Failure | undefined {
  const byId = receiptsById(parsed);
  const manifests = new Map(parsed.epoch_manifest.map((entry) => [toHex(entry.payload.manifest_id as Uint8Array), entry]));
  const anchors = new Map(parsed.anchor.map((entry) => [toHex(entry.payload.anchor_id as Uint8Array), entry]));

  for (const child of parsed.receipt) for (const edgeValue of child.payload.parents as CborValue[]) {
    const edge = edgeValue as Obj;
    const parent = bytes(edge.parent_id, 32) ? byId.get(toHex(edge.parent_id)) : undefined;
    if (parent === undefined) return failure(12, "graph/dangling-parent", "receipt.parents.parent_id");
  }
  for (const child of parsed.receipt) for (const edgeValue of child.payload.parents as CborValue[]) {
    const edge = edgeValue as Obj;
    const parent = byId.get(toHex(edge.parent_id as Uint8Array))!;
    const parentBinding = parent.payload.binding as Obj;
    if (!same(edge.parent_kind, parent.payload.kind) || !same(edge.parent_tenant_id, parentBinding.tenant_id) || !same(edge.parent_site_id, parentBinding.site_id) || !same(edge.parent_epoch_id, parentBinding.epoch_id)) {
      return failure(12, "graph/parent-metadata-mismatch", "receipt.parents");
    }
  }
  for (const child of parsed.receipt) for (const edgeValue of child.payload.parents as CborValue[]) {
    const edge = edgeValue as Obj;
    const parent = byId.get(toHex(edge.parent_id as Uint8Array))!;
    const rule = EDGE_MATRIX[edge.edge_type as string];
    if (rule === undefined || !rule[0].includes(parent.payload.kind as string) || !rule[1].includes(child.payload.kind as string)) return failure(12, "graph/edge-illegal", "receipt.parents.edge_type");
  }
  for (const receipt of parsed.receipt) {
    const parents = receipt.payload.parents as CborValue[];
    const root = receipt.payload.root;
    if (parents.length === 0) {
      if (!object(root)) return failure(12, "graph/root-missing", "receipt.root");
      const allowed: Record<string, readonly string[]> = {
        agent_request: ["observation", "inference"], human_request: ["observation", "inference", "authorization"], standing_condition_trigger: ["observation", "authorization"],
      };
      if (!(allowed[root.kind as string] ?? []).includes(receipt.payload.kind as string)) return failure(12, "graph/root-forbidden", "receipt.root.kind");
    } else if (root !== undefined) return failure(12, "graph/root-forbidden", "receipt.root");
  }
  for (const child of parsed.receipt) for (const edgeValue of child.payload.parents as CborValue[]) {
    const edge = edgeValue as Obj;
    const parent = byId.get(toHex(edge.parent_id as Uint8Array))!;
    const childBinding = child.payload.binding as Obj;
    const parentBinding = parent.payload.binding as Obj;
    if (!same(childBinding.tenant_id, parentBinding.tenant_id) || !same(childBinding.site_id, parentBinding.site_id)) return failure(12, "graph/tenant-site-splice", "receipt.parents");
    const unequalEpoch = childBinding.epoch_id !== parentBinding.epoch_id;
    if (!unequalEpoch && edge.cross_epoch !== undefined) return failure(12, "graph/cross-epoch-forbidden", "receipt.parents.cross_epoch");
    if (!unequalEpoch) continue;
    const cross = edge.cross_epoch;
    const allowed = object(cross) && (
      ((edge.edge_type === "derived_from" || edge.edge_type === "supports") && cross.reason === "historical_evidence")
      || (edge.edge_type === "observed_outcome" && (cross.reason === "long_running_action" || cross.reason === "late_outcome"))
    );
    if (!allowed) return failure(12, "graph/cross-epoch-forbidden", "receipt.parents.cross_epoch");
    const manifest = bytes(cross.source_manifest_id, 32) ? manifests.get(toHex(cross.source_manifest_id)) : undefined;
    const anchor = bytes(cross.source_anchor_id, 32) ? anchors.get(toHex(cross.source_anchor_id)) : undefined;
    if (parentBinding.epoch_id as number >= (childBinding.epoch_id as number) || manifest === undefined || anchor === undefined
      || !same(manifest.payload.epoch_id, parentBinding.epoch_id) || !same(anchor.payload.manifest_id, manifest.payload.manifest_id)) {
      return failure(12, "graph/cross-epoch-unanchored", "receipt.parents.cross_epoch");
    }
  }

  const indegree = new Map<string, number>();
  const children = new Map<string, string[]>();
  const ranks = new Map<string, number>();
  for (const receipt of parsed.receipt) {
    const id = toHex(receipt.payload.receipt_id as Uint8Array);
    indegree.set(id, (receipt.payload.parents as CborValue[]).length);
    children.set(id, []);
  }
  for (const child of parsed.receipt) {
    const childId = toHex(child.payload.receipt_id as Uint8Array);
    for (const edgeValue of child.payload.parents as Obj[]) children.get(toHex(edgeValue.parent_id as Uint8Array))!.push(childId);
  }
  const queue = [...indegree.entries()].filter(([, count]) => count === 0).map(([id]) => id);
  for (const id of queue) ranks.set(id, 0);
  while (queue.length > 0) {
    const id = queue.shift()!;
    for (const childId of children.get(id)!) {
      ranks.set(childId, Math.max(ranks.get(childId) ?? 0, (ranks.get(id) ?? 0) + 1));
      const next = indegree.get(childId)! - 1;
      indegree.set(childId, next);
      if (next === 0) queue.push(childId);
    }
  }
  // Step 7 makes a cycle cryptographically unreachable. The finite queue is the
  // implementation's defensive traversal bound, not a wire-visible rejection.
  const maximumRank = Math.max(-1, ...ranks.values());
  if (maximumRank + 1 > LIMITS.dagDepth) return failure(12, "resource/dag-depth", "bundle.artifacts.receipts");
  const widths = new Map<number, number>();
  for (const rank of ranks.values()) widths.set(rank, (widths.get(rank) ?? 0) + 1);
  if ([...widths.values()].some((width) => width > LIMITS.dagWidth)) return failure(12, "resource/dag-width", "bundle.artifacts.receipts");
  return undefined;
}

function validateDominance(parsed: Parsed): B1Failure | undefined {
  const byId = receiptsById(parsed);
  const parentDelegations = new Map(parsed.delegation.map((entry) => [toHex(entry.payload.delegation_id as Uint8Array), entry]));
  const embeddedDelegations = new Map(parsed.embeddedDelegations.map((entry) => [toHex(entry.authorization.payload.receipt_id as Uint8Array), entry.delegation]));
  for (const dispatch of parsed.receipt.filter((entry) => entry.payload.kind === "dispatch")) {
    const attemptEdges = (dispatch.payload.parents as Obj[]).filter((edge) => edge.edge_type === "attempted_as");
    const attempt = attemptEdges.length === 1 ? byId.get(toHex(attemptEdges[0]!.parent_id as Uint8Array)) : undefined;
    if (attempt === undefined || attempt.payload.kind !== "action_attempt") return failure(13, "graph/dominator-missing", "dispatch.parents");
    const authorizationEdges = (attempt.payload.parents as Obj[]).filter((edge) => edge.edge_type === "authorized_by");
    if (authorizationEdges.length === 0) return failure(13, "graph/dominator-missing", "attempt.parents");
    if (authorizationEdges.length > 1) return failure(13, "graph/dominator-ambiguous", "attempt.parents");
    const authorization = byId.get(toHex(authorizationEdges[0]!.parent_id as Uint8Array));
    const attemptBody = attempt.payload.body as Obj;
    if (authorization?.payload.kind !== "authorization" || !same(attemptBody.authorization_id, authorization.payload.receipt_id)) return failure(13, "graph/dominator-missing", "attempt.body.authorization_id");
    const decision = (authorization.payload.body as Obj).decision as Obj;
    const delegation = embeddedDelegations.get(toHex(authorization.payload.receipt_id as Uint8Array));
    if (delegation === undefined || !same(decision.delegation_id, delegation.payload.delegation_id)) return failure(13, "graph/dominator-missing", "authorization.body.decision.delegation_id");
    const committed = (attempt.payload.emission as Obj).committed_at as number;
    if (committed < (delegation.payload.not_before as number)) return failure(13, "delegation/not-yet-valid", "authorization.body.delegation.not_before");
    if (committed >= (delegation.payload.not_after as number)) return failure(13, "delegation/expired", "authorization.body.delegation.not_after");
    const scope = delegation.payload.scope as Obj;
    const action = attemptBody.action as Obj;
    const legal = attempt.payload.legal as Obj;
    if (!Array.isArray(scope.actions) || !scope.actions.some((value) => same(value, action.action_name)) || !Array.isArray(scope.targets) || !scope.targets.some((value) => same(value, action.target_id)) || !Array.isArray(scope.purpose_ids) || !scope.purpose_ids.some((value) => same(value, legal.purpose_id)) || !Array.isArray(scope.allowed_profiles) || !scope.allowed_profiles.some((value) => same(value, decision.profile)) || !same(delegation.payload.tenant_id, (attempt.payload.binding as Obj).tenant_id) || !same(delegation.payload.site_id, (attempt.payload.binding as Obj).site_id) || (delegation.payload.use === "one_time" && !same(delegation.payload.invocation_id, (attempt.payload.freshness as Obj).invocation_id))) return failure(13, "delegation/scope", "authorization.body.delegation.scope");
    for (const parentId of delegation.payload.parent_delegations as CborValue[]) {
      const parent = bytes(parentId, 32) ? parentDelegations.get(toHex(parentId)) : undefined;
      if (parent === undefined || (parent.payload.not_before as number) > (delegation.payload.not_before as number) || (parent.payload.not_after as number) < (delegation.payload.not_after as number)) return failure(13, "delegation/chain-invalid", "authorization.body.delegation.parent_delegations");
    }
  }
  return undefined;
}

function validateEpochs(parsed: Parsed): B1Failure | undefined {
  const manifests = [...parsed.epoch_manifest].sort((a, b) => {
    const owner = toHex(a.payload.epoch_owner_kid as Uint8Array).localeCompare(toHex(b.payload.epoch_owner_kid as Uint8Array));
    return owner || (a.payload.epoch_id as number) - (b.payload.epoch_id as number);
  });
  const eventGroups = new Map<string, ParsedEnvelope[]>();
  for (const event of parsed.epoch_event) {
    const key = `${toHex(event.payload.epoch_owner_kid as Uint8Array)}:${event.payload.epoch_id as number}`;
    eventGroups.set(key, [...(eventGroups.get(key) ?? []), event]);
  }
  const states = [...eventGroups].map(([key, eventsValue]) => {
    const events = [...eventsValue].sort((a, b) => (a.payload.event_seq as number) - (b.payload.event_seq as number));
    const opens = events.filter((entry) => entry.payload.event === "open");
    const closes = events.filter((entry) => entry.payload.event === "close");
    const closeManifestId = object(closes[0]?.payload.body) ? closes[0]!.payload.body.manifest_id : undefined;
    const matchingManifests = manifests.filter((entry) => `${toHex(entry.payload.epoch_owner_kid as Uint8Array)}:${entry.payload.epoch_id as number}` === key);
    const manifest = matchingManifests.find((entry) => same(entry.payload.manifest_id, closeManifestId)) ?? matchingManifests[0];
    return { key, events, opens, closes, manifest };
  });

  for (const { events } of states) {
    for (let index = 0; index < events.length; index += 1) {
      const current = events[index]!;
      if (current.payload.event_seq !== index) return failure(14, "epoch/event-chain", "epoch_event.event_seq");
      if (index === 0) {
        if (current.payload.previous_event_digest !== undefined) return failure(14, "epoch/event-chain", "epoch_event.previous_event_digest");
      } else if (!equalBytes(current.payload.previous_event_digest as Uint8Array, hash(events[index - 1]!.payloadBytes))) return failure(14, "epoch/event-chain", "epoch_event.previous_event_digest");
    }
  }

  const byDigest = new Map(manifests.map((entry) => [toHex(hash(entry.payloadBytes)), entry]));
  for (const current of manifests) {
    if (current.payload.predecessor_manifest_digest === undefined) continue;
    const prior = byDigest.get(toHex(current.payload.predecessor_manifest_digest as Uint8Array));
    if (prior !== undefined && same(prior.payload.epoch_owner_kid, current.payload.epoch_owner_kid) && (current.payload.epoch_id as number) <= (prior.payload.epoch_id as number)) return failure(14, "epoch/id-nonmonotonic", "epoch_manifest.epoch_id");
  }
  for (const current of manifests) {
    if (current.payload.predecessor_manifest_digest === undefined) continue;
    const prior = byDigest.get(toHex(current.payload.predecessor_manifest_digest as Uint8Array));
    if (prior === undefined || !same(prior.payload.epoch_owner_kid, current.payload.epoch_owner_kid)) return failure(14, "epoch/predecessor-mismatch", "epoch_manifest.predecessor_manifest_digest");
  }
  const byOwner = new Map<string, ParsedEnvelope[]>();
  for (const manifest of manifests) {
    const owner = toHex(manifest.payload.epoch_owner_kid as Uint8Array);
    byOwner.set(owner, [...(byOwner.get(owner) ?? []), manifest]);
  }
  for (const ownerManifests of byOwner.values()) {
    const firstEpochs = new Set(ownerManifests.filter((entry) => entry.payload.predecessor_manifest_digest === undefined).map((entry) => entry.payload.epoch_id as number));
    if (firstEpochs.size !== 1) return failure(14, "epoch/predecessor-mismatch", "epoch_manifest.predecessor_manifest_digest");
  }

  for (const { opens, closes, manifest } of states) {
    if (opens.length !== 1 || closes.length !== 1 || (opens[0]!.payload.occurred_at as number) >= (closes[0]!.payload.occurred_at as number)) return failure(14, "epoch/open-close", "epoch_events");
    if (manifest === undefined) return failure(14, "epoch/open-close", "epoch_manifest");
  }
  for (const manifest of manifests) {
    const key = `${toHex(manifest.payload.epoch_owner_kid as Uint8Array)}:${manifest.payload.epoch_id as number}`;
    if (!eventGroups.has(key)) return failure(14, "epoch/open-close", "epoch_events");
  }

  for (const { opens, closes, manifest } of states) {
    if ((closes[0]!.payload.occurred_at as number) - (opens[0]!.payload.occurred_at as number) > 86_400) return failure(14, "epoch/duration-exceeded", "epoch_events");
    if ((manifest!.payload.closed_at as number) - (manifest!.payload.opened_at as number) > 86_400) return failure(14, "epoch/duration-exceeded", "epoch_manifest");
  }

  for (const { closes, manifest } of states) {
    const closeBody = closes[0]!.payload.body as Obj;
    const index = manifest!.payload.receipt_index as Obj;
    const span = manifest!.payload.sequence_span as Obj;
    if (!same(closeBody.manifest_id, manifest!.payload.manifest_id) || closeBody.item_count !== manifest!.payload.item_count || closeBody.last_epoch_seq !== span.last
      || manifest!.payload.item_count !== (index.entries as CborValue[]).length || index.leaf_count !== manifest!.payload.item_count) return failure(14, "epoch/span-count-mismatch", "epoch_manifest");
  }

  const manifestsByEpoch = new Map(states.filter((state) => state.manifest !== undefined).map((state) => [state.key, state.manifest!]));
  for (const receipt of parsed.receipt) {
    const binding = receipt.payload.binding as Obj;
    const manifest = manifestsByEpoch.get(`${toHex(binding.epoch_owner_kid as Uint8Array)}:${binding.epoch_id as number}`);
    if (manifest !== undefined && (receipt.payload.emission as Obj).committed_at as number > (manifest.payload.closed_at as number)) return failure(14, "epoch/late-insertion", "receipt.emission.committed_at");
    if (binding.late_for_epoch_id !== undefined && (binding.late_for_epoch_id as number) >= (binding.epoch_id as number)) return failure(14, "epoch/late-insertion", "receipt.binding.late_for_epoch_id");
  }

  for (const { events, closes, manifest } of states) {
    const closeBody = closes[0]!.payload.body as Obj;
    if (manifest!.payload.anchor_deadline !== (manifest!.payload.closed_at as number) + 86_400 || closeBody.anchor_deadline !== manifest!.payload.anchor_deadline) return failure(14, "epoch/anchor-deadline", "epoch_manifest.anchor_deadline");
    for (const submitted of events.filter((entry) => entry.payload.event === "anchor_submitted")) if (((submitted.payload.body as Obj).submitted_at as number) > (manifest!.payload.anchor_deadline as number)) return failure(14, "epoch/anchor-deadline", "epoch_event.body.submitted_at");
  }

  const seenEpoch = new Set<string>();
  for (const manifest of manifests) {
    const coordinate = `${toHex(manifest.payload.epoch_owner_kid as Uint8Array)}:${manifest.payload.epoch_id as number}`;
    if (seenEpoch.has(coordinate)) return failure(14, "epoch/fork", "bundle.artifacts.epoch_manifests");
    seenEpoch.add(coordinate);
  }
  if (parsed.epoch_event.some((entry) => entry.payload.event === "fork_declared")) return failure(14, "epoch/fork", "epoch_event.event");
  return undefined;
}

function compareIndexEntries(left: Obj, right: Obj): number {
  const time = (left.committed_at as number) - (right.committed_at as number);
  const sequence = (left.epoch_seq as number) - (right.epoch_seq as number);
  return time || sequence || compareEncoded(left.receipt_id!, right.receipt_id!);
}

function validateManifestIndexes(parsed: Parsed): B1Failure | undefined {
  const receipts = receiptsById(parsed);
  for (const manifest of parsed.epoch_manifest) {
    const index = manifest.payload.receipt_index as Obj;
    const entries = index.entries as Obj[];
    for (let position = 1; position < entries.length; position += 1) if (compareIndexEntries(entries[position - 1]!, entries[position]!) >= 0) return failure(15, "manifest/index-order", "epoch_manifest.receipt_index.entries");
    for (let position = 0; position < entries.length; position += 1) if (entries[position]!.leaf_index !== position) return failure(15, "manifest/index-gap", "epoch_manifest.receipt_index.entries.leaf_index");
    const ids = new Set<string>(); const sequences = new Set<number>();
    for (const entry of entries) {
      const id = toHex(entry.receipt_id as Uint8Array); const sequence = entry.epoch_seq as number;
      if (ids.has(id) || sequences.has(sequence)) return failure(15, "manifest/index-duplicate", "epoch_manifest.receipt_index.entries");
      ids.add(id); sequences.add(sequence);
    }
    for (const entry of entries) {
      const id = toHex(entry.receipt_id as Uint8Array);
      const receipt = receipts.get(id);
      const binding = receipt?.payload.binding as Obj | undefined;
      const emission = receipt?.payload.emission as Obj | undefined;
      if (receipt !== undefined && (entry.receipt_kind !== receipt.payload.kind || !same(entry.issuer_kid, receipt.kid) || entry.issuer_seq !== emission!.issuer_seq || entry.epoch_seq !== binding!.epoch_seq || entry.committed_at !== emission!.committed_at)) return failure(15, "manifest/index-receipt-mismatch", "epoch_manifest.receipt_index.entries");
    }
    const span = manifest.payload.sequence_span as Obj;
    if (index.leaf_count !== entries.length || manifest.payload.item_count !== entries.length
      || (entries.length > 0 && (span.first !== entries[0]!.epoch_seq || span.last !== entries[entries.length - 1]!.epoch_seq))) return failure(15, "epoch/span-count-mismatch", "epoch_manifest.receipt_index");
    const leaves = entries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry));
    if (leaves.length === 0 || !equalBytes(index.root as Uint8Array, promotedRoot(leaves, "AAR-MANIFEST-INDEX-NODE-v1"))) return failure(15, "manifest/index-root-mismatch", "epoch_manifest.receipt_index.root");
  }
  return undefined;
}

function expectedPromotedSiblings(index: number, treeSize: number): number {
  let count = 0; let position = index; let width = treeSize;
  while (width > 1) { if (position % 2 === 1 || position + 1 < width) count += 1; position = Math.floor(position / 2); width = Math.ceil(width / 2); }
  return count;
}

function validateMerkle(bundle: Obj, parsed: Parsed, observations: string[]): B1Failure | undefined {
  const batches = new Map(parsed.merkle_batch.map((entry) => [toHex(entry.payload.batch_id as Uint8Array), entry]));
  const seenLeaves = new Map<string, number>();
  for (const proofValue of (bundle.artifacts as Obj).merkle_proofs as CborValue[]) {
    const proof = proofValue as Obj;
    const batch = bytes(proof.batch_id, 32) ? batches.get(toHex(proof.batch_id)) : undefined;
    const leaf = proof.leaf as Obj;
    if (batch === undefined || proof.tree_size !== batch.payload.tree_size || proof.leaf_index !== leaf.leaf_index || leaf.tree_size !== batch.payload.tree_size
      || !same(leaf.tenant_id, batch.payload.tenant_id) || !same(leaf.site_id, batch.payload.site_id) || leaf.epoch_id !== batch.payload.epoch_id) return failure(16, "merkle/batch-binding", "merkle_proofs");
    const siblings = proof.siblings as Uint8Array[];
    if (siblings.length > 20 || siblings.length !== expectedPromotedSiblings(proof.leaf_index as number, proof.tree_size as number)) return failure(16, "merkle/path-length", "merkle_proofs.siblings");
    if (!verifyPromotedProof(domainHash("AAR-MERKLE-LEAF-v1", leaf), proof.leaf_index as number, proof.tree_size as number, siblings, "AAR-MERKLE-NODE-v1", batch.payload.root as Uint8Array)) return failure(16, "merkle/root-mismatch", "merkle_proofs");
    const indexlessKey = toHex(domainHash("AAR-MERKLE-DUPLICATE-v1", proof.batch_id!, {
      tenant_id: leaf.tenant_id!, site_id: leaf.site_id!, epoch_id: leaf.epoch_id!, item_digest: leaf.item_digest!,
    }));
    const priorIndex = seenLeaves.get(indexlessKey);
    if (priorIndex !== undefined && priorIndex !== proof.leaf_index) return failure(16, "merkle/duplicate-leaf", "merkle_proofs.leaf");
    seenLeaves.set(indexlessKey, proof.leaf_index as number);
    observe(observations, "membership_only");
  }
  return undefined;
}

function validateAnchors(bundle: Obj, parsed: Parsed, observations: string[]): B1Failure | undefined {
  const manifests = new Map(parsed.epoch_manifest.map((entry) => [toHex(entry.payload.manifest_id as Uint8Array), entry]));
  const expectedHeads = ((bundle.trust_inputs as Obj).expected_anchor_heads as Obj[]);
  const evaluation = (bundle.trust_inputs as Obj).evaluation_time as number;
  for (const anchor of parsed.anchor) {
    const manifest = manifests.get(toHex(anchor.payload.manifest_id as Uint8Array));
    const plan = manifest?.payload.anchor_plan as Obj | undefined;
    const target = anchor.payload.target as Obj;
    const planned = (plan?.targets as Obj[] | undefined)?.find((entry) => same(entry.target_id, target.target_id));
    if (planned === undefined || !same(planned, target)) return failure(17, "anchor/target-unplanned", "anchor.target");
    const leafObject: Obj = { tenant_id: anchor.payload.tenant_id!, site_id: anchor.payload.site_id!, epoch_id: anchor.payload.epoch_id!, manifest_id: anchor.payload.manifest_id!, manifest_digest: anchor.payload.manifest_digest! };
    const leafDigest = rfc6962Leaf(encodeCbor(["AAR-ANCHOR-LEAF-v1", leafObject]));
    const inclusion = anchor.payload.inclusion as Obj;
    if (!equalBytes(inclusion.leaf_digest as Uint8Array, leafDigest) || inclusion.tree_size !== anchor.payload.anchor_tree_size || inclusion.leaf_index !== anchor.payload.anchor_leaf_index
      || !verifyRfc6962Inclusion(leafDigest, inclusion.leaf_index as number, inclusion.tree_size as number, inclusion.siblings as Uint8Array[], anchor.payload.anchor_root as Uint8Array)) return failure(17, "anchor/inclusion-invalid", "anchor.inclusion");
    if (object(anchor.payload.consistency)) {
      const proof = anchor.payload.consistency;
      if (proof.new_tree_size !== anchor.payload.anchor_tree_size || !same(proof.new_root, anchor.payload.anchor_root)
        || !verifyRfc6962Consistency(proof.old_tree_size as number, proof.new_tree_size as number, proof.old_root as Uint8Array, proof.new_root as Uint8Array, proof.path as Uint8Array[])) return failure(17, "anchor/consistency-invalid", "anchor.consistency");
    }
    if (manifest === undefined || !same(anchor.payload.tenant_id, manifest.payload.tenant_id) || !same(anchor.payload.site_id, manifest.payload.site_id) || anchor.payload.epoch_id !== manifest.payload.epoch_id
      || !equalBytes(anchor.payload.manifest_digest as Uint8Array, hash(manifest.payloadBytes))) return failure(17, "anchor/manifest-binding", "anchor.manifest_id");
    if ((anchor.payload.submitted_at as number) - (manifest.payload.closed_at as number) > 86_400) return failure(17, "anchor/submission-late", "anchor.submitted_at");
    const expected = expectedHeads.find((entry) => same(entry.target_id, target.target_id));
    if (expected === undefined) return failure(17, "anchor/head-missing", "trust_inputs.expected_anchor_heads", true);
    if ((expected.tree_size as number) >= (anchor.payload.anchor_tree_size as number) && ((expected.tree_size !== anchor.payload.anchor_tree_size) || !same(expected.root, anchor.payload.anchor_root))) return failure(17, "anchor/head-mismatch", "trust_inputs.expected_anchor_heads");
    if (evaluation - (expected.observed_at as number) > 86_400) return failure(17, "anchor/head-stale", "trust_inputs.expected_anchor_heads");
    const independence = plan!.independence as Obj;
    const groups = independence.groups as Obj[];
    const group = groups.find((entry) => same(entry.independence_group, target.independence_group));
    if (independence.basis !== "distinct_operator_and_failure_domain" || group === undefined || !same(group.operator_id, target.operator_id)
      || groups.some((entry, index) => groups.some((other, otherIndex) => index !== otherIndex && (same(entry.operator_id, other.operator_id) || same(entry.failure_domain_id, other.failure_domain_id))))) return failure(17, "anchor/independence-invalid", "epoch_manifest.anchor_plan.independence");
    observe(observations, "anchor_existence_order_only");
  }
  return undefined;
}

function entryMatchesSelector(entry: Obj, selector: Obj): boolean {
  if ((entry.committed_at as number) < (selector.committed_from as number) || (entry.committed_at as number) >= (selector.committed_until as number)) return false;
  if (!(selector.receipt_kinds as CborValue[]).some((value) => same(value, entry.receipt_kind))) return false;
  for (const [selectorField, entryField] of [["subject_ids", "subject_ids"], ["correlation_ids", "correlation_ids"], ["issuer_kids", "issuer_kid"]] as const) {
    const selected = selector[selectorField];
    if (!Array.isArray(selected)) continue;
    const values = Array.isArray(entry[entryField]) ? entry[entryField] as CborValue[] : [entry[entryField]!];
    if (!selected.some((wanted) => values.some((value) => same(wanted, value)))) return false;
  }
  return true;
}

function validateRanges(bundle: Obj, parsed: Parsed, observations: string[]): B1Failure | undefined {
  const selector = bundle.selector as Obj;
  if ((selector.committed_from as number) >= (selector.committed_until as number)) return failure(18, "bundle/selector-interval", "bundle.selector");
  const manifests = new Map(parsed.epoch_manifest.map((entry) => [toHex(entry.payload.manifest_id as Uint8Array), entry]));
  const carriedReceipts = receiptsById(parsed);
  const selectedIds = new Set<string>();
  const previousLastByManifest = new Map<string, number>();
  for (const rangeValue of bundle.ranges as CborValue[]) {
    const range = rangeValue as Obj;
    const manifest = bytes(range.manifest_id, 32) ? manifests.get(toHex(range.manifest_id)) : undefined;
    if (manifest === undefined) return failure(18, "bundle/range-manifest-missing", "bundle.ranges.manifest_id");
    if (!same(range.selector_commitment, bundle.selector_commitment)) return failure(18, "bundle/range-selector-mismatch", "bundle.ranges.selector_commitment");
    const manifestKey = toHex(range.manifest_id as Uint8Array);
    let previousLast = previousLastByManifest.get(manifestKey) ?? -1;
    const entries = range.entries as Obj[];
    if (entries.length > 0) {
      if (range.first_leaf_index !== (entries[0]!.entry as Obj).leaf_index) return failure(18, "bundle/range-noncontiguous", "bundle.ranges.first_leaf_index");
      for (let index = 0; index < entries.length; index += 1) {
        const leaf = entries[index]!.entry as Obj;
        if (leaf.leaf_index !== (range.first_leaf_index as number) + index || (leaf.leaf_index as number) <= previousLast) return failure(18, "bundle/range-noncontiguous", "bundle.ranges.entries");
        previousLast = leaf.leaf_index as number;
      }
      previousLastByManifest.set(manifestKey, previousLast);
    } else if (range.first_leaf_index !== undefined) return failure(18, "bundle/range-noncontiguous", "bundle.ranges.first_leaf_index");
    const indexEntries = ((manifest.payload.receipt_index as Obj).entries as Obj[]);
    const temporalSlice = indexEntries.filter((entry) => (entry.committed_at as number) >= (selector.committed_from as number) && (entry.committed_at as number) < (selector.committed_until as number));
    if (entries.length !== temporalSlice.length || entries.some((wrapped, index) => !same(wrapped.entry, temporalSlice[index]))) return failure(18, "bundle/range-boundary", "bundle.ranges");
    for (const wrapped of entries) {
      const entry = wrapped.entry as Obj; const inclusion = wrapped.inclusion as Obj;
      if (inclusion.tree_size !== (manifest.payload.receipt_index as Obj).leaf_count || inclusion.leaf_index !== entry.leaf_index
        || !verifyPromotedProof(domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry), inclusion.leaf_index as number, inclusion.tree_size as number, inclusion.siblings as Uint8Array[], "AAR-MANIFEST-INDEX-NODE-v1", (manifest.payload.receipt_index as Obj).root as Uint8Array)) return failure(18, "bundle/range-proof-invalid", "bundle.ranges.entries.inclusion");
      if (entryMatchesSelector(entry, selector)) selectedIds.add(toHex(entry.receipt_id as Uint8Array));
    }
  }
  if (bundle.coverage === "complete") {
    if ((bundle.ranges as CborValue[]).length === 0) return failure(18, "bundle/coverage-overclaim", "bundle.coverage");
    for (const id of selectedIds) if (!carriedReceipts.has(id)) return failure(18, "bundle/selected-receipt-missing", "bundle.artifacts.receipts");
    const reachable = new Set(selectedIds); const queue = [...selectedIds];
    while (queue.length > 0) {
      const receipt = carriedReceipts.get(queue.shift()!); if (receipt === undefined) continue;
      for (const edge of receipt.payload.parents as Obj[]) { const id = toHex(edge.parent_id as Uint8Array); if (!reachable.has(id)) { reachable.add(id); queue.push(id); } }
    }
    for (const receipt of parsed.receipt) {
      const id = toHex(receipt.payload.receipt_id as Uint8Array);
      const entry = [...parsed.epoch_manifest].flatMap((manifest) => ((manifest.payload.receipt_index as Obj).entries as Obj[])).find((candidate) => same(candidate.receipt_id, receipt.payload.receipt_id));
      if (!reachable.has(id) && entry !== undefined && !entryMatchesSelector(entry, selector)) return failure(18, "bundle/artifact-out-of-scope", "bundle.artifacts.receipts");
    }
    observe(observations, "producer_declared_complete");
  }
  observe(observations, "ingress_completeness_not_established");
  return undefined;
}

type EvidenceLimits = { time: string; provenance: string; outcome: string };

function validateEvidence(bundle: Obj, parsed: Parsed): EvidenceLimits | B1Failure {
  const timeRank: Record<string, number> = { asserted: 0, boot_bound: 1, externally_anchored: 2 };
  const provenanceRank: Record<string, number> = { self_asserted: 0, proxy_captured: 1, provider_attested: 2 };
  const outcomeRank: Record<string, number> = { accepted: 0, dispatched: 1, device_acknowledged: 2, independently_sensed: 3 };
  let time = "not_evaluated"; let provenance = "not_evaluated"; let outcome = "not_evaluated";
  const manifestPayloads = new Set(((bundle.artifacts as Obj).manifest_payloads as Obj[]).map((entry) => toHex(entry.digest as Uint8Array)));
  // Content validation has already hash-checked every carried payload.
  const requirePayload = (id: CborValue | undefined, path: string): B1Failure | undefined => {
    if (!(id instanceof Uint8Array)) return undefined;
    if (!manifestPayloads.has(toHex(id))) return failure(19, "manifest/payload-missing", path);
    return undefined;
  };
  for (const receipt of parsed.receipt) {
    const evidence = receipt.payload.evidence as Obj;
    const timeEvidence = evidence.time as Obj;
    if (timeEvidence.class === "boot_bound" || timeEvidence.class === "externally_anchored") {
      if (!bytes(timeEvidence.boot_attestation_id, 32)) return failure(19, "evidence/time-class-unsatisfied", "receipt.evidence.time");
      const payloadIssue = requirePayload(timeEvidence.boot_attestation_id, "receipt.evidence.time.boot_attestation_id");
      if (payloadIssue) return payloadIssue;
    }
    if (timeEvidence.class === "externally_anchored") {
      if (!bytes(timeEvidence.anchor_id, 32)) return failure(19, "evidence/time-class-unsatisfied", "receipt.evidence.time");
      const anchor = parsed.anchor.find((entry) => same(entry.payload.anchor_id, timeEvidence.anchor_id));
      const manifest = anchor === undefined ? undefined : parsed.epoch_manifest.find((entry) => same(entry.payload.manifest_id, anchor.payload.manifest_id));
      const binding = receipt.payload.binding as Obj; const emission = receipt.payload.emission as Obj;
      if (anchor === undefined || manifest === undefined || (anchor.payload.epoch_id as number) >= (binding.epoch_id as number)
        || !same(anchor.payload.tenant_id, binding.tenant_id) || !same(anchor.payload.site_id, binding.site_id)
        || !same(manifest.payload.epoch_owner_kid, binding.epoch_owner_kid)
        || (anchor.payload.accepted_at as number) > (emission.committed_at as number)) return failure(19, "evidence/time-class-unsatisfied", "receipt.evidence.time.anchor_id");
    }
    if (time === "not_evaluated" || timeRank[timeEvidence.class as string]! > timeRank[time]!) time = timeEvidence.class as string;
    if (object(evidence.provenance)) {
      if (evidence.provenance.class === "proxy_captured" || evidence.provenance.class === "provider_attested") {
        if (!bytes(evidence.provenance.capture_attestation_id, 32)) return failure(19, "evidence/provenance-class-unsatisfied", "receipt.evidence.provenance");
        const payloadIssue = requirePayload(evidence.provenance.capture_attestation_id, "receipt.evidence.provenance.capture_attestation_id");
        if (payloadIssue) return payloadIssue;
      }
      if (evidence.provenance.class === "provider_attested") {
        if (!bytes(evidence.provenance.provider_attestation_id, 32)) return failure(19, "evidence/provenance-class-unsatisfied", "receipt.evidence.provenance");
        const payloadIssue = requirePayload(evidence.provenance.provider_attestation_id, "receipt.evidence.provenance.provider_attestation_id");
        if (payloadIssue) return payloadIssue;
      }
      if (provenance === "not_evaluated" || provenanceRank[evidence.provenance.class as string]! > provenanceRank[provenance]!) provenance = evidence.provenance.class as string;
    }
    if (object(evidence.outcome)) {
      const level = evidence.outcome.level as string;
      if (level === "independently_sensed") {
        if (!bytes(evidence.outcome.qualifying_predicate_id, 32)) return failure(19, "evidence/outcome-class-unsatisfied", "receipt.evidence.outcome");
        const payloadIssue = requirePayload(evidence.outcome.qualifying_predicate_id, "receipt.evidence.outcome.qualifying_predicate_id");
        if (payloadIssue) return payloadIssue;
        const observer = (receipt.payload.body as Obj).observer as Obj;
        const byId = receiptsById(parsed); const queue = (receipt.payload.parents as Obj[]).map((edge) => toHex(edge.parent_id as Uint8Array)); const ancestors: ParsedEnvelope[] = []; const seen = new Set<string>();
        while (queue.length > 0) { const id = queue.shift()!; if (seen.has(id)) continue; seen.add(id); const ancestor = byId.get(id); if (ancestor === undefined) continue; ancestors.push(ancestor); for (const edge of ancestor.payload.parents as Obj[]) queue.push(toHex(edge.parent_id as Uint8Array)); }
        const sourceDomains = ancestors.map((entry) => ((entry.payload.body as Obj).source_device as Obj | undefined)?.failure_domain_id).filter((value): value is CborValue => value !== undefined);
        if (sourceDomains.some((domain) => same(domain, observer.failure_domain_id))) return failure(19, "evidence/observer-not-independent", "receipt.body.observer.failure_domain_id");
      }
      if (level === "contradicted") outcome = level;
      else if (level === "unknown" && outcome !== "contradicted") outcome = level;
      else if (outcome !== "contradicted" && outcome !== "unknown"
        && (outcome === "not_evaluated" || outcomeRank[level]! > outcomeRank[outcome]!)) outcome = level;
    }
  }
  return { time, provenance, outcome };
}

const VERDICT_LIMITS: Obj = {
  exact_encoded_bundle_bytes: 16_777_216,
  cbor_container_nesting: 32,
  receipt_nodes: 10_000,
  directed_graph_edges: 50_000,
  parents_per_receipt: 64,
  dag_depth: 128,
  dag_width: 4_096,
  encoded_proof_bytes: 65_536,
  aggregate_proof_bytes: 4_194_304,
  epoch_manifest_entries: 10_000,
  merkle_batch_leaves: 1_048_576,
  credential_path_length: 8,
};

// Stable reference-harness identity preimages for release 0.2.0-b2.1. The
// deterministicId helper hashes UTF-8 "AAR-KAT-OPAQUE-ID:" plus these labels.
const DEFAULT_VERSION = "0.2.0-b2.1";
const DEFAULT_BUILD_DIGEST = deterministicId("verifier-build:aar-reference-verifier@0.2.0-b2.1");
const DEFAULT_CONFIG_DIGEST = deterministicId("verifier-config:aar-reference-verifier@0.2.0-default");
const ZERO_DIGEST = new Uint8Array(32);

function limitsDigest(): Uint8Array {
  return domainHash("AAR-VERDICT-LIMITS-v1", VERDICT_LIMITS);
}

function anchorHeadsDigest(heads: CborValue): Uint8Array {
  return domainHash("AAR-VERDICT-HEADS-v1", heads);
}

function replayStateMap(state: readonly ReplayUse[]): Obj {
  const entries = state.map((entry) => ({ replay_domain: entry.replayDomain, invocation_id: entry.invocationId, content_digest: entry.contentDigest }));
  entries.sort((left, right) => compareEncoded([left.replay_domain, left.invocation_id, left.content_digest], [right.replay_domain, right.invocation_id, right.content_digest]));
  return { entries };
}

function replayStateDigest(state: readonly ReplayUse[] | undefined): Uint8Array {
  return state === undefined ? ZERO_DIGEST : domainHash("AAR-VERDICT-REPLAY-v1", replayStateMap(state));
}

function emitVerdict(input: Uint8Array, bundle: Obj, parsed: Parsed, options: VerifyB1Options, observations: string[], evidence: EvidenceLimits): B1Success {
  const selector = bundle.selector as Obj; const trust = bundle.trust_inputs as Obj; const store = trust.trust_store as Obj;
  const fields: Obj = {
    v: 2,
    evaluated_at: trust.evaluation_time!,
    result: "conformant",
    bundle_digest: hash(input),
    selector_commitment: bundle.selector_commitment!,
    verifier: {
      product: options.product ?? "aar-reference-verifier",
      version: options.version ?? DEFAULT_VERSION,
      build_digest: options.buildDigest ?? DEFAULT_BUILD_DIGEST,
      config_digest: options.configDigest ?? DEFAULT_CONFIG_DIGEST,
      limits_digest: limitsDigest(),
    },
    trust_policy: {
      trust_store_snapshot_id: store.snapshot_id!,
      trust_store_digest: store.digest!,
      verifier_policy_digest: trust.verifier_policy_digest!,
      evaluation_time: trust.evaluation_time!,
      anchor_heads_digest: anchorHeadsDigest(trust.expected_anchor_heads!),
      replay_state_digest: replayStateDigest(options.replayState),
    },
    scope: {
      tenant_id: selector.tenant_id!, site_id: selector.site_id!, committed_from: selector.committed_from!, committed_until: selector.committed_until!,
      receipt_kinds: selector.receipt_kinds!, coverage: bundle.coverage!, ingress_completeness: "not_established",
    },
    limits: {
      requested_profile: bundle.claimed_profile!, evaluated_profile: bundle.claimed_profile!,
      maximum_time_class: evidence.time, maximum_provenance_class: evidence.provenance, maximum_outcome_level: evidence.outcome,
      technical_integrity: "satisfied", source_authenticity: "not_established",
      custody_continuity: parsed.anchor.length > 0 ? "partially_evidenced" : "not_established",
      discovery_completeness: bundle.coverage === "complete" ? "producer_declared_only" : "not_established",
      legal_admissibility: "not_established",
    },
    observations,
  };
  const protectedBytes = encodeCbor(new Map<CborScalar, CborValue>([[1, -7], [3, "application/aar-verdict+cbor;v=0.2"], [4, TEST_KEYS.verifier_signing.kid]]));
  const verdict: Obj = { verdict_id: domainHash("AAR-VERDICT-ID-v1", protectedBytes, fields), ...fields };
  const signed = signDetached(verdict, "application/aar-verdict+cbor;v=0.2", "verifier_signing");
  return { ok: true, result: "conformant", completedThrough: 20, observations, verdict, verdictEnvelope: signed.envelopeBytes };
}

function validateBundle(input: Uint8Array, options: VerifyB1Options = {}): B1Verification {
  if (input.length > LIMITS.bundleBytes) return failure(1, "resource/bundle-too-large", "bundle");
  const decoded = profileDecode(input, 2, "bundle");
  if (isFailure(decoded)) return decoded;
  const schemaIssue = validateBundleSchema(decoded);
  if (schemaIssue) return schemaIssue;
  const bundle = decoded as Obj;
  const resourceIssue = validateResourceCounts(bundle);
  if (resourceIssue) return resourceIssue;
  const trustIssue = validateTrustInputs(bundle);
  if (trustIssue) return trustIssue;
  const parsed = parseAll(bundle);
  if (isFailure(parsed)) return parsed;
  const mechanicsIssue = validateMechanics(bundle, parsed);
  if (mechanicsIssue) return mechanicsIssue;
  const contentIssue = validateContent(bundle, parsed);
  if (contentIssue) return contentIssue;
  const lifecycleIssue = validateCredentialLifecycle(bundle, parsed);
  if (lifecycleIssue) return lifecycleIssue;
  const observations: string[] = [];
  const emissionIssue = validateEmission(parsed, options.priorEmissions ?? [], observations);
  if (emissionIssue) return emissionIssue;
  const receiptIssue = validateReceiptSemantics(bundle, parsed);
  if (receiptIssue) return receiptIssue;
  const replayIssue = validateReplay(parsed, options.replayState ?? []);
  if (replayIssue) return replayIssue;
  const graphIssue = validateGraph(parsed);
  if (graphIssue) return graphIssue;
  const dominanceIssue = validateDominance(parsed);
  if (dominanceIssue) return dominanceIssue;
  const epochIssue = validateEpochs(parsed);
  if (epochIssue) return epochIssue;
  const indexIssue = validateManifestIndexes(parsed);
  if (indexIssue) return indexIssue;
  const merkleIssue = validateMerkle(bundle, parsed, observations);
  if (merkleIssue) return merkleIssue;
  const anchorIssue = validateAnchors(bundle, parsed, observations);
  if (anchorIssue) return anchorIssue;
  const rangeIssue = validateRanges(bundle, parsed, observations);
  if (rangeIssue) return rangeIssue;
  const evidence = validateEvidence(bundle, parsed);
  if (isFailure(evidence)) return evidence;
  const verifierCredential = parsed.credential.find((entry) => equalBytes(entry.payload.subject_kid as Uint8Array, TEST_KEYS.verifier_signing.kid));
  if (verifierCredential === undefined || verifierCredential.payload.key_usage !== "verifier_signing") return failure(20, "key/not-found", "verifier_signing", true);
  return emitVerdict(input, bundle, parsed, options, observations, evidence);
}

function emitFailureVerdict(input: Uint8Array, issue: B1Failure, options: VerifyB1Options): B1Failure {
  let decoded: Obj | undefined;
  try { const value = decodeCbor(input, { strict: true, maxDepth: LIMITS.depth }); if (object(value)) decoded = value; } catch { /* deterministic fallback below */ }
  const selector = object(decoded?.selector) ? decoded.selector : {};
  const trust = object(decoded?.trust_inputs) ? decoded.trust_inputs : {};
  const store = object(trust.trust_store) ? trust.trust_store : {};
  const zero16 = new Uint8Array(16); const zero32 = new Uint8Array(32);
  const evaluationTime = uint(trust.evaluation_time) ? trust.evaluation_time : (options.evaluationTime ?? Math.floor(Date.now() / 1000));
  const committedFrom = uint(selector.committed_from) ? selector.committed_from : 0;
  const committedUntil = uint(selector.committed_until) ? selector.committed_until : 0;
  const receiptKinds = Array.isArray(selector.receipt_kinds) && selector.receipt_kinds.length > 0 ? selector.receipt_kinds : ["observation"];
  const fields: Obj = {
    v: 2, evaluated_at: evaluationTime, result: issue.result, reason: issue.reason,
    bundle_digest: hash(input), selector_commitment: bytes(decoded?.selector_commitment, 32) ? decoded!.selector_commitment! : zero32,
    verifier: {
      product: options.product ?? "aar-reference-verifier", version: options.version ?? DEFAULT_VERSION,
      build_digest: options.buildDigest ?? DEFAULT_BUILD_DIGEST, config_digest: options.configDigest ?? DEFAULT_CONFIG_DIGEST, limits_digest: limitsDigest(),
    },
    trust_policy: {
      trust_store_snapshot_id: bytes(store.snapshot_id, 32) ? store.snapshot_id! : zero32,
      trust_store_digest: bytes(store.digest, 32) ? store.digest! : zero32,
      verifier_policy_digest: bytes(trust.verifier_policy_digest, 32) ? trust.verifier_policy_digest! : zero32,
      evaluation_time: evaluationTime,
      anchor_heads_digest: Array.isArray(trust.expected_anchor_heads) ? anchorHeadsDigest(trust.expected_anchor_heads) : ZERO_DIGEST,
      replay_state_digest: replayStateDigest(options.replayState),
    },
    scope: {
      tenant_id: bytes(selector.tenant_id, 16) ? selector.tenant_id! : zero16, site_id: bytes(selector.site_id, 16) ? selector.site_id! : zero16,
      committed_from: committedFrom, committed_until: committedUntil, receipt_kinds: receiptKinds,
      coverage: decoded?.coverage === "complete" ? "complete" : "valid_subset", ingress_completeness: "not_established",
    },
    limits: {
      requested_profile: ["AAR-1", "AAR-2", "AAR-2A", "AAR-3"].includes(decoded?.claimed_profile as string) ? decoded!.claimed_profile! : "AAR-1",
      evaluated_profile: "below_AAR-1", maximum_time_class: "not_evaluated", maximum_provenance_class: "not_evaluated", maximum_outcome_level: "not_evaluated",
      technical_integrity: "not_satisfied", source_authenticity: "not_established", custody_continuity: "not_established", discovery_completeness: "not_established", legal_admissibility: "not_established",
    },
    observations: [],
  };
  const protectedBytes = encodeCbor(new Map<CborScalar, CborValue>([[1, -7], [3, "application/aar-verdict+cbor;v=0.2"], [4, TEST_KEYS.verifier_signing.kid]]));
  const verdict: Obj = { verdict_id: domainHash("AAR-VERDICT-ID-v1", protectedBytes, fields), ...fields };
  const signed = signDetached(verdict, "application/aar-verdict+cbor;v=0.2", "verifier_signing");
  return { ...issue, verdict, verdictEnvelope: signed.envelopeBytes };
}

export function verifyBundle(input: Uint8Array, options: VerifyB1Options = {}): B1Verification {
  const result = validateBundle(input, options);
  return result.ok ? result : emitFailureVerdict(input, result, options);
}

export const verifyBundleB1 = verifyBundle;
