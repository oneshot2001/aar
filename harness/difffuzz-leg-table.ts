// Leg oracle (Packet D, Stage D): for every positive seed, every evidence leg
// it carries, and every operator class the leg defines (corruption, removal,
// claim weakening), both verifiers must land inside the leg's declared allowed
// outcome set. Removal of optional evidence may leave the verdict unchanged; a
// corrupted retained leg that stays conformant, or a weakened claim whose
// governing field did not move, is a finding (D-03 item 1).
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CborValue, encodeCbor, toHex } from "./cbor";
import { dispatchedAuthorization, getAt, list, resignAt } from "./difffuzz-mutant";
import { SeedEntry } from "./difffuzz-mutants";
import { referencedPayloads } from "./difffuzz-operators-steps";
import { Inputs } from "./difffuzz-pyref";
import { Rng } from "./difffuzz-rng";
import { Obj, artifacts, clone, flipSignature, mutateReceiptWhere, payload, protectedMap, sortArtifacts } from "./mutate";
import { mutateEmbeddedDelegation } from "./mutate-graph";
import { loadConfiguration } from "./relying-party";
import { VerifyB1Options } from "./verifier";

export type LegClass = "corruption" | "removal" | "claimWeakening";
// Allowed outcome set: results, reason codes as code@step, whether verdict-limits/scope may stay as they were,
// which observations may disappear, and (claim weakening) the verdict fields that must move.
export interface Allowed { results: readonly string[]; codes: readonly string[]; limitsUnchangedOk: boolean; observationsMayDrop: readonly string[]; mustMove: readonly string[] }
export interface LegMutant { bytes: Uint8Array; detail: string; allowed: Allowed; inputs?: Inputs; options?: VerifyB1Options }
// `work()` yields a scratch directory outside the run directory for files a mutant must reference on disk (a rewritten policy).
type Apply = (entry: SeedEntry, rng: Rng, work: () => string, id: string) => LegMutant | null;
export interface Leg { leg: string; step: number; applicable(bundle: Obj, policy: boolean): boolean; classes: Partial<Record<LegClass, Apply>> }

const reject = (...codes: string[]): Allowed => ({ results: ["nonconformant"], codes, limitsUnchangedOk: false, observationsMayDrop: [], mustMove: [] });
const stays = (...observationsMayDrop: string[]): Allowed => ({ results: ["conformant"], codes: [], limitsUnchangedOk: true, observationsMayDrop, mustMove: [] });
const moves = (...mustMove: string[]): Allowed => ({ results: ["conformant"], codes: [], limitsUnchangedOk: false, observationsMayDrop: [], mustMove });
const receipts = (bundle: Obj): Obj[] => list(bundle, "receipts").map(payload);
const where = (bundle: Obj, predicate: (value: Obj) => boolean): number[] => receipts(bundle).flatMap((value, index) => predicate(value) ? [index] : []);
const done = (bundle: Obj, detail: string, allowed: Allowed): LegMutant => ({ bytes: encodeCbor(bundle), detail, allowed });
const fresh = (entry: SeedEntry): Obj => clone(entry.view.bundle);
const flipBit = (bytes: Uint8Array): Uint8Array => { const changed = new Uint8Array(bytes); changed[0] = changed[0]! ^ 1; return changed; };
const flipIn = (bundle: Obj, category: string, index: number): void => { const target = list(bundle, category); target[index] = flipSignature(target[index]!); };
const nestedEnvelopes = (bundle: Obj): CborValue[] => receipts(bundle).flatMap((value) => ["delegation", "presentation"].flatMap((key) => (value.body as Obj)[key] === undefined ? [] : [(value.body as Obj)[key]!]));
const signerKids = (bundle: Obj): Set<string> => new Set([...["receipts", "requests", "credentials", "delegations", "status_snapshots", "rotations", "epoch_events", "epoch_manifests", "anchors", "merkle_batches", "mediator_countersignatures"].flatMap((category) => list(bundle, category)), ...nestedEnvelopes(bundle)].map((envelope) => toHex(protectedMap(envelope).get(4) as Uint8Array)));
// Every 32-byte string in every payload (nested envelopes included), counted by value.
const idUses = (bundle: Obj): Map<string, number> => {
  const counts = new Map<string, number>();
  const walk = (value: CborValue): void => { if (value instanceof Uint8Array) { if (value.length === 32) counts.set(toHex(value), (counts.get(toHex(value)) ?? 0) + 1); } else if (Array.isArray(value)) value.forEach(walk); else if (value !== null && typeof value === "object" && !(value instanceof Map)) Object.values(value).forEach(walk); };
  for (const category of ["receipts", "requests", "credentials", "delegations", "status_snapshots", "rotations", "epoch_events", "epoch_manifests", "anchors", "merkle_batches", "mediator_countersignatures"]) for (const envelope of list(bundle, category)) walk(payload(envelope));
  for (const envelope of nestedEnvelopes(bundle)) walk(payload(envelope));
  return counts;
};
const byReceiptId = (bundle: Obj, index: number, mutation: (value: Obj) => void): void => { const id = toHex(receipts(bundle)[index]!.receipt_id as Uint8Array); mutateReceiptWhere(bundle, (value) => toHex(value.receipt_id as Uint8Array) === id, mutation); };
const CLASS_FIELD: Record<string, [path: string, base: string, limit: string]> = {
  boot_bound: ["evidence.time.class", "asserted", "limits.maximum_time_class"], externally_anchored: ["evidence.time.class", "asserted", "limits.maximum_time_class"],
  proxy_captured: ["evidence.provenance.class", "self_asserted", "limits.maximum_provenance_class"], provider_attested: ["evidence.provenance.class", "self_asserted", "limits.maximum_provenance_class"],
  independently_sensed: ["evidence.outcome.level", "device_acknowledged", "limits.maximum_outcome_level"],
};
const declaredClasses = (bundle: Obj): { index: number; declared: string }[] => receipts(bundle).flatMap((value, index) => ["evidence.time.class", "evidence.provenance.class", "evidence.outcome.level"].flatMap((path) => { const declared = getAt(value, path.split(".")); return typeof declared === "string" && declared in CLASS_FIELD ? [{ index, declared }] : []; }));
const unusedCredentials = (bundle: Obj, policy: boolean): number[] => {
  const used = signerKids(bundle); const uses = idUses(bundle);
  return list(bundle, "credentials").flatMap((envelope, index) => { const value = payload(envelope); return used.has(toHex(value.subject_kid as Uint8Array)) || (uses.get(toHex(value.credential_id as Uint8Array)) ?? 0) > 1 || (!policy && value.key_usage === "verifier_signing") ? [] : [index]; });
};
const dispatchedActions = (bundle: Obj): Set<string> => new Set(receipts(bundle).filter((value) => value.kind === "action_attempt").map((value) => ((value.body as Obj).action as Obj).action_name as string));

// Relying-party ceiling: drop one allowed_key_usages entry from the policy's artifact root; required when a carried
// credential of that usage signs something, in which case the policy must reject (relying_party.py:254).
const rpRemoval: Apply = (entry, rng, work, id) => {
  const { inputs, options } = entry.row.seed; if (inputs.policy === null || inputs.signing_key === null) return null;
  const policy = JSON.parse(readFileSync(inputs.policy, "utf8")); const roots = (policy.artifact_roots ?? []) as { allowed_key_usages: string[] }[];
  const candidates = roots.filter((root) => Array.isArray(root.allowed_key_usages) && root.allowed_key_usages.length > 1); if (candidates.length === 0) return null;
  const root = rng.pick(candidates); const usage = rng.pick(root.allowed_key_usages); root.allowed_key_usages = root.allowed_key_usages.filter((item) => item !== usage);
  const bundle = entry.view.bundle; const used = signerKids(bundle);
  const required = list(bundle, "credentials").some((envelope) => { const credential = payload(envelope); return credential.key_usage === usage && used.has(toHex(credential.subject_kid as Uint8Array)); });
  const path = join(work(), `${id}.policy.json`); writeFileSync(path, `${JSON.stringify(policy, null, 2)}\n`);
  return { bytes: entry.view.bytes, detail: `policy allowed_key_usages minus ${usage} (${required ? "a carried credential of that usage signs" : "no signer of that usage"})`, allowed: required ? reject("credential/root-not-accepted@8") : stays(),
    inputs: { ...inputs, policy: path }, options: { ...options, configuration: loadConfiguration(path, inputs.signing_key, inputs.evaluated_at) } };
};

export const LEGS: readonly Leg[] = [
  { leg: "receipt-signature", step: 6, applicable: (bundle) => list(bundle, "receipts").length > 0, classes: {
    corruption: (entry, rng) => { const bundle = fresh(entry); const index = rng.int(list(bundle, "receipts").length); flipIn(bundle, "receipts", index); return done(bundle, `receipts[${index}] signature flipped`, reject("sig/verify-failed@6")); } } },
  { leg: "commitment", step: 7, applicable: (bundle) => (list(bundle, "manifest_payloads") as Obj[]).some((entry) => entry.canonical_bytes instanceof Uint8Array && entry.canonical_bytes.length > 0), classes: {
    corruption: (entry, rng) => { const bundle = fresh(entry); const payloads = artifacts(bundle).manifest_payloads as Obj[]; const index = rng.pick(payloads.flatMap((item, i) => item.canonical_bytes instanceof Uint8Array && item.canonical_bytes.length > 0 ? [i] : [])); payloads[index]!.canonical_bytes = flipBit(payloads[index]!.canonical_bytes as Uint8Array); return done(bundle, `manifest_payloads[${index}] canonical_bytes flipped, digest kept`, reject("hash/mismatch@7")); } } },
  { leg: "credential-chain", step: 8, applicable: (bundle) => list(bundle, "credentials").some((envelope) => (payload(envelope).path as CborValue[]).length > 0), classes: {
    corruption: (entry, rng) => { const bundle = fresh(entry); const index = rng.pick(list(bundle, "credentials").flatMap((envelope, i) => (payload(envelope).path as CborValue[]).length > 0 ? [i] : [])); resignAt(bundle, "credentials", index, (value) => { (value.path as CborValue[])[0] = rng.bytes(32); }); return done(bundle, `credentials[${index}].path[0] -> unknown, re-identified and re-signed`, reject("credential/path-invalid@8", "countersign/credential-invalid@8")); },
    removal: (entry, rng) => { const candidates = unusedCredentials(entry.view.bundle, entry.view.policy); if (candidates.length === 0) return null; const bundle = fresh(entry); const index = rng.pick(candidates); list(bundle, "credentials").splice(index, 1); return done(bundle, `credentials[${index}] (unused) removed`, stays()); } } },
  // corruption needs the embedded delegation of the dispatched attempt's authorization; removal needs a top-level one
  { leg: "delegation", step: 13, applicable: (bundle) => dispatchedAuthorization(bundle) !== null || list(bundle, "delegations").length > 0, classes: {
    corruption: (entry) => { const bundle = fresh(entry); const authorization = dispatchedAuthorization(bundle); if (authorization === null) return null; const used = dispatchedActions(bundle); const other = ["camera.view", "camera.ptz.preset"].find((action) => !used.has(action)); if (other === undefined) return null; mutateEmbeddedDelegation(bundle, (delegation) => { (delegation.scope as Obj).actions = [other]; }, authorization); return done(bundle, `dispatched authorization's embedded delegation scope -> [${other}], excluding the attempted action(s) ${[...used].join(",")} (cascade)`, reject("delegation/scope@13")); },
    removal: (entry, rng) => { if (list(entry.view.bundle, "delegations").length === 0) return null; const bundle = fresh(entry); const index = rng.int(list(bundle, "delegations").length); const id = toHex(payload(list(bundle, "delegations")[index]!).delegation_id as Uint8Array);
      const parents = new Set([...list(bundle, "delegations").map(payload), ...receipts(bundle).flatMap((value) => (value.body as Obj).delegation ? [payload((value.body as Obj).delegation!)] : [])].flatMap((delegation) => ((delegation.parent_delegations as Uint8Array[]) ?? []).map(toHex)));
      list(bundle, "delegations").splice(index, 1); return done(bundle, `delegations[${index}] removed (${parents.has(id) ? "named as a parent" : "unreferenced"})`, parents.has(id) ? reject("delegation/chain-invalid@13") : stays()); } } },
  { leg: "inclusion-proof", step: 16, applicable: (bundle) => list(bundle, "merkle_proofs").length > 0, classes: {
    corruption: (entry, rng) => { const bundle = fresh(entry); const proofs = artifacts(bundle).merkle_proofs as Obj[]; const index = rng.int(proofs.length); const siblings = proofs[index]!.siblings as Uint8Array[]; if (siblings.length === 0) return null; siblings[0] = flipBit(siblings[0]!); return done(bundle, `merkle_proofs[${index}].siblings[0] flipped`, reject("merkle/root-mismatch@16")); },
    removal: (entry) => { const bundle = fresh(entry); artifacts(bundle).merkle_proofs = []; artifacts(bundle).merkle_batches = []; return done(bundle, "merkle proofs and batches removed", stays("membership_only")); } } },
  { leg: "range-proof", step: 18, applicable: (bundle) => ((bundle.ranges as Obj[]) ?? []).length > 0, classes: {
    corruption: (entry) => { const bundle = fresh(entry); const item = ((bundle.ranges as Obj[])[0]!.entries as Obj[]).find((candidate) => ((candidate.inclusion as Obj).siblings as Uint8Array[]).length > 0); if (!item) return null; const siblings = (item.inclusion as Obj).siblings as Uint8Array[]; siblings[0] = flipBit(siblings[0]!); return done(bundle, "range entry sibling flipped", reject("bundle/range-proof-invalid@18")); },
    removal: (entry) => { const bundle = fresh(entry); bundle.ranges = []; return done(bundle, "ranges removed under complete coverage", reject("bundle/coverage-overclaim@18")); },
    claimWeakening: (entry) => { const bundle = fresh(entry); bundle.ranges = []; bundle.coverage = "valid_subset"; return done(bundle, "coverage weakened to valid_subset, ranges dropped", moves("scope.coverage", "limits.discovery_completeness")); } } },
  { leg: "anchor", step: 17, applicable: (bundle) => list(bundle, "anchors").length > 0, classes: {
    corruption: (entry, rng) => { const bundle = fresh(entry); const index = rng.int(list(bundle, "anchors").length); resignAt(bundle, "anchors", index, (anchor) => { (anchor.inclusion as Obj).leaf_digest = rng.bytes(32); }); return done(bundle, `anchors[${index}].inclusion.leaf_digest random, re-identified and re-signed`, reject("anchor/inclusion-invalid@17")); },
    removal: (entry) => { const bundle = fresh(entry); const anchored = where(bundle, (value) => ((value.evidence as Obj).time as Obj).class === "externally_anchored").length > 0; artifacts(bundle).anchors = []; return done(bundle, `anchors removed (${anchored ? "an externally_anchored receipt names one" : "unused by any receipt"})`, anchored ? reject("evidence/time-class-unsatisfied@19") : stays("anchor_existence_order_only")); } } },
  { leg: "outcome-independence", step: 10, applicable: (bundle) => where(bundle, (value) => value.kind === "outcome_observation").length > 0, classes: {
    corruption: (entry, rng) => { const bundle = fresh(entry); const index = rng.pick(where(bundle, (value) => value.kind === "outcome_observation")); byReceiptId(bundle, index, (value) => { (value.body as Obj).subject_id = rng.bytes(32); }); return done(bundle, `outcome_observation[${index}].body.subject_id -> unknown`, reject("receipt/outcome-subject-mismatch@10")); },
    removal: (entry, rng) => { const bundle = fresh(entry); const parents = new Set(receipts(bundle).flatMap((value) => (value.parents as Obj[]).map((edge) => toHex(edge.parent_id as Uint8Array)))); const leaves = where(bundle, (value) => value.kind === "outcome_observation" && !parents.has(toHex(value.receipt_id as Uint8Array))); if (leaves.length === 0) return null; const index = rng.pick(leaves); list(bundle, "receipts").splice(index, 1); sortArtifacts(bundle, "receipts"); return done(bundle, `terminal outcome_observation[${index}] removed`, stays()); } } },
  { leg: "mediator-countersignature", step: 6, applicable: (bundle) => list(bundle, "mediator_countersignatures").length > 0, classes: {
    corruption: (entry) => { const bundle = fresh(entry); flipIn(bundle, "mediator_countersignatures", 0); return done(bundle, "mediator countersignature signature flipped", reject("countersign/invalid@6")); },
    removal: (entry) => { const bundle = fresh(entry); delete artifacts(bundle).mediator_countersignatures; return done(bundle, "mediator countersignatures removed", stays("mediator_countersigned")); } } },
  { leg: "relying-party-ceiling", step: 8, applicable: (_bundle, policy) => policy, classes: { removal: rpRemoval } },
  { leg: "step-19-evidence", step: 19, applicable: (bundle) => declaredClasses(bundle).length > 0, classes: {
    removal: (entry, rng) => { const refs = referencedPayloads(entry.view.bundle); if (refs.length === 0) return null; const bundle = fresh(entry); const digest = rng.pick(refs); artifacts(bundle).manifest_payloads = (artifacts(bundle).manifest_payloads as Obj[]).filter((item) => toHex(item.digest as Uint8Array) !== digest); return done(bundle, `manifest payload ${digest.slice(0, 8)} (declared-class evidence) removed`, reject("manifest/payload-missing@19")); },
    claimWeakening: (entry, rng) => { const bundle = fresh(entry); const { index, declared } = rng.pick(declaredClasses(bundle)); const [path, base, limit] = CLASS_FIELD[declared]!; byReceiptId(bundle, index, (value) => { const tokens = path.split("."); (getAt(value, tokens.slice(0, -1)) as Obj)[tokens.at(-1)!] = base; }); return done(bundle, `receipts[${index}].${path} ${declared} -> ${base}`, moves(limit)); } } },
];
