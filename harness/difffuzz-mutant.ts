// Mutant framework for the differential fuzz tool (Packet D, Stage C): the
// operator contract, the survival check, and the helpers the operator tables
// (difffuzz-operators.ts, difffuzz-operators-steps.ts) build on. An operator
// names its layer, target step, repair boundary and version; apply returns
// null when the seed lacks the shape; survives() proves the targeted value
// differs between seed and mutant after the repair boundary ran.
import { CborValue, decodeCbor, encodeCbor, toHex } from "./cbor";
import { Rng } from "./difffuzz-rng";
import { Obj, artifacts, clone, mutateArtifact, mutateReceiptWhere, payload, same } from "./mutate";

export interface SeedView { bundle: Obj; bytes: Uint8Array; policy: boolean; conformant: boolean; pinnedStep: number | null }
export interface Mutant { bytes: Uint8Array; target: string; detail: string }
export interface Operator {
  name: string;
  version: number;
  layer: "raw" | "cose" | "payload";
  targetStep: number | null;
  repairBoundary: string;
  applicable(seed: SeedView): boolean;
  apply(seed: SeedView, rng: Rng): Mutant | null;
}

export const ENVELOPED = ["receipts", "requests", "credentials", "delegations", "status_snapshots", "rotations", "epoch_events", "epoch_manifests", "anchors", "merkle_batches", "mediator_countersignatures"] as const;
export const list = (bundle: Obj, category: string): CborValue[] => (artifacts(bundle)[category] as CborValue[] | undefined) ?? [];
export const envelopes = (bundle: Obj): { category: string; index: number }[] => ENVELOPED.flatMap((category) => list(bundle, category).map((_, index) => ({ category, index })));
export const evaluationTime = (bundle: Obj): number => (bundle.trust_inputs as Obj).evaluation_time as number;

// Path projection for survival: tokens are keys, indices, `*` (every element,
// as a sorted multiset), `payload` (decode envelope[0]), `cose` (decode
// envelope[1]), `protected` (decode cose[0]) and `#n` (int map key).
function project(value: CborValue | undefined, tokens: readonly string[]): string[] {
  if (tokens.length === 0) return [value === undefined ? "<absent>" : toHex(encodeCbor(value))];
  const [head, ...rest] = tokens as [string, ...string[]];
  if (value === undefined || value === null) return ["<absent>"];
  if (head === "*") return Array.isArray(value) ? value.flatMap((item) => project(item, rest)).sort() : ["<absent>"];
  if (head === "payload" || head === "cose") return Array.isArray(value) && value[head === "payload" ? 0 : 1] instanceof Uint8Array ? project(decodeCbor(value[head === "payload" ? 0 : 1] as Uint8Array), rest) : ["<absent>"];
  if (head === "protected") return Array.isArray(value) && value[0] instanceof Uint8Array ? project(decodeCbor(value[0]), rest) : ["<absent>"];
  if (head.startsWith("#")) return value instanceof Map ? project(value.get(Number(head.slice(1))), rest) : ["<absent>"];
  if (/^\d+$/u.test(head)) return Array.isArray(value) ? project(value[Number(head)], rest) : ["<absent>"];
  return typeof value === "object" && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map) ? project((value as Obj)[head], rest) : ["<absent>"];
}
export function survives(seed: SeedView, mutant: Mutant): boolean {
  if (mutant.target === "") return toHex(seed.bytes) !== toHex(mutant.bytes);
  const tokens = mutant.target.split(".");
  let decoded: CborValue;
  try { decoded = decodeCbor(mutant.bytes); } catch { return true; } // undecodable mutant: the raw bytes differ by construction
  return project(seed.bundle, tokens).join("|") !== project(decoded, tokens).join("|");
}

// Nested field access on a decoded payload.
export const getAt = (value: CborValue | undefined, tokens: readonly string[]): CborValue | undefined => tokens.reduce<CborValue | undefined>((current, token) => current === undefined || current === null || typeof current !== "object" || current instanceof Uint8Array || current instanceof Map ? undefined : (current as Record<string, CborValue>)[token], value);
export function setAt(value: Obj, tokens: readonly string[], next: CborValue | undefined): void {
  const parent = getAt(value, tokens.slice(0, -1)) as Obj | undefined;
  if (parent === undefined) throw new Error(`path ${tokens.join(".")} missing`);
  if (next === undefined) delete parent[tokens.at(-1)!]; else parent[tokens.at(-1)!] = next;
}

// Mutate one enveloped artifact's payload and re-sign it on the kit's repair
// boundary: receipts re-identified + re-signed + sorted; ID_DOMAIN artifacts
// re-identified + re-signed + sorted; requests and countersignatures re-signed.
export function resignAt(bundle: Obj, category: string, index: number, mutation: (value: Obj) => void): void {
  const target = payload(list(bundle, category)[index]!);
  const matches = (candidate: Obj): boolean => same(candidate, target);
  if (category === "receipts") mutateReceiptWhere(bundle, matches, mutation);
  else mutateArtifact(bundle, category, matches, mutation);
}
export const encode = (bundle: Obj, target: string, detail: string): Mutant => ({ bytes: encodeCbor(bundle), target, detail });

// Closed CDDL enum tables (spec/aar-core.cddl), keyed by payload path.
export const ENUMS: Record<string, readonly string[]> = {
  kind: ["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"],
  issuer_role: ["agent", "enforcement_point", "authority_source", "approver", "outcome_observer", "anchor_service", "verifier"],
  issuer_principal_type: ["human", "service", "workload_instance", "model_endpoint"],
  principal_type: ["human", "service", "workload_instance", "model_endpoint"],
  principal_role: ["agent", "enforcement_point", "authority_source", "approver", "outcome_observer", "anchor_service", "verifier"],
  key_usage: ["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "verifier_signing", "credential_issuing", "status_signing"],
  "evidence.time.class": ["asserted", "boot_bound", "externally_anchored"],
  "evidence.provenance.class": ["self_asserted", "proxy_captured", "provider_attested"],
  "evidence.outcome.level": ["accepted", "dispatched", "device_acknowledged", "independently_sensed", "contradicted", "unknown"],
  "freshness.use": ["one_time", "reusable"],
  "body.disposition": ["eligible_for_dispatch", "not_dispatched"],
  "body.decision.decision": ["permit", "deny", "permit_with_approval"],
  "root.kind": ["agent_request", "human_request", "standing_condition_trigger"],
  "parents.0.edge_type": ["derived_from", "requested_by", "authorized_by", "triggered_by", "attempted_as", "observed_outcome", "supports"],
  "parents.0.parent_kind": ["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"],
  status: ["good", "revoked", "compromised", "unknown"],
  event: ["open", "close", "anchor_submitted", "fork_declared"],
  close_reason: ["duration", "size", "administrative", "padding"],
};
export const BUNDLE_ENUMS: Record<string, readonly string[]> = { coverage: ["valid_subset", "complete"], claimed_profile: ["AAR-1", "AAR-2", "AAR-2A", "AAR-3"] };
// unix-time / sequence / epoch fields by payload path (any enveloped category that carries them).
export const COUNTERS = ["emission.committed_at", "emission.issuer_seq", "binding.epoch_seq", "binding.epoch_id", "freshness.issued_at", "freshness.expires_at", "valid_from", "valid_until", "produced_at", "next_update", "lease_not_before", "lease_not_after", "sequence", "effective_at", "continuity_sequence", "occurred_at", "event_seq", "epoch_id", "opened_at", "closed_at", "anchor_deadline", "item_count", "sequence_span.first", "sequence_span.last", "submitted_at", "accepted_at", "inclusion.leaf_index", "inclusion.tree_size", "head.tree_size", "not_before", "not_after", "tree_size", "leaf_count", "mediator_observed_at"];

// Pick an enveloped artifact whose payload has a field at one of the paths; returns the hit or null.
export function pickField(bundle: Obj, rng: Rng, paths: readonly string[], accept: (value: CborValue) => boolean, exclude: (category: string, path: string) => boolean = () => false): { category: string; index: number; path: string; value: CborValue } | null {
  const hits = envelopes(bundle).flatMap(({ category, index }) => {
    const value = payload(list(bundle, category)[index]!);
    return paths.flatMap((path) => { const found = getAt(value, path.split(".")); return found !== undefined && accept(found) && !exclude(category, path) ? [{ category, index, path, value: found }] : []; });
  });
  return hits.length === 0 ? null : rng.pick(hits);
}
export const ids = (bundle: Obj): Uint8Array[] => envelopes(bundle).flatMap(({ category, index }) => Object.values(payload(list(bundle, category)[index]!)).filter((value): value is Uint8Array => value instanceof Uint8Array && value.length === 32));
export const REFERENCES = ["parents.0.parent_id", "body.attempt_id", "body.authorization_id", "body.subject_id", "freshness.intended_parents.0", "root.request_id", "path.0", "parent_delegations.0", "manifest_id", "body.manifest_id", "issuer_credential_id", "subject_credential_id", "predecessor_credential_id", "successor_credential_id", "credential_id"];

// The authorization the dispatched attempt names: the embedded delegation whose scope is load-bearing at step 13.
export const dispatchedAuthorization = (bundle: Obj): ((value: Obj) => boolean) | null => {
  const all = list(bundle, "receipts").map(payload); const attempts = new Set(all.filter((value) => value.kind === "dispatch").map((value) => toHex((value.body as Obj).attempt_id as Uint8Array)));
  const ids = new Set(all.filter((value) => value.kind === "action_attempt" && attempts.has(toHex(value.receipt_id as Uint8Array))).map((value) => toHex((value.body as Obj).authorization_id as Uint8Array)));
  const target = all.find((value) => value.kind === "authorization" && ids.has(toHex(value.receipt_id as Uint8Array)) && (value.body as Obj).delegation !== undefined);
  return target === undefined ? null : (value) => toHex(value.receipt_id as Uint8Array) === toHex(target.receipt_id as Uint8Array);
};

export const op = (name: string, layer: Operator["layer"], targetStep: number | null, repairBoundary: string, applicable: (seed: SeedView) => boolean, apply: (seed: SeedView, rng: Rng) => Mutant | null): Operator => ({ name, version: 1, layer, targetStep, repairBoundary, applicable, apply });
export const fresh = (seed: SeedView): Obj => clone(seed.bundle);
