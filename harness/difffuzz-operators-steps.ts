// Step-targeted operators (Codex's deep table, D-02): each names the step it
// aims at and the repair boundary it runs, so a mutant that dies earlier is
// counted as masked rather than as coverage of that step.
import { CborValue, toHex } from "./cbor";
import { Mutant, Operator, SeedView, dispatchedAuthorization, encode, evaluationTime, fresh, getAt, list, op, resignAt } from "./difffuzz-mutant";
import { Rng } from "./difffuzz-rng";
import { Obj, artifacts, mutateArtifact, mutateLastEvent, payload, rebuildManifest, recalcSelector, sortArtifacts } from "./mutate";
import { mutateEmbeddedDelegation } from "./mutate-graph";

const receipts = (bundle: Obj): Obj[] => list(bundle, "receipts").map(payload);
const has = (category: string) => (seed: SeedView): boolean => list(seed.bundle, category).length > 0;
const receiptWhere = (bundle: Obj, predicate: (value: Obj) => boolean): number[] => receipts(bundle).flatMap((value, index) => predicate(value) ? [index] : []);
const otherReceiptId = (bundle: Obj, rng: Rng, not: Uint8Array): Uint8Array | null => { const pool = receipts(bundle).map((value) => value.receipt_id as Uint8Array).filter((id) => toHex(id) !== toHex(not)); return pool.length === 0 ? null : rng.pick(pool); };
const receiptMutant = (bundle: Obj, index: number, path: string, mutation: (value: Obj) => void, detail: string): Mutant => { resignAt(bundle, "receipts", index, mutation); return encode(bundle, `artifacts.receipts.*.payload.${path}`, detail); };
const artifactMutant = (bundle: Obj, category: string, index: number, path: string, mutation: (value: Obj) => void, detail: string): Mutant => { resignAt(bundle, category, index, mutation); return encode(bundle, `artifacts.${category}.*.payload.${path}`, detail); };

export const STEP_OPERATORS: readonly Operator[] = [
  op("credential/window", "payload", 6, "re-id + re-sign + sort (credential path references not rewritten)", has("credentials"), (seed, rng) => {
    const bundle = fresh(seed); const index = rng.int(list(bundle, "credentials").length); const at = evaluationTime(bundle);
    const times = receipts(bundle).map((value) => (value.emission as Obj).committed_at as number);
    const field = rng.pick(["valid_from", "valid_until"] as const); const boundary = rng.near(times.length > 0 && rng.bool() ? rng.pick(times) : at);
    return artifactMutant(bundle, "credentials", index, field, (value) => { value[field] = boundary; }, `credentials[${index}].${field} = ${boundary}`);
  }),
  op("status/boundary", "payload", 8, "re-id + re-sign + sort; no receipt cascade", has("status_snapshots"), (seed, rng) => {
    const bundle = fresh(seed); const index = rng.int(list(bundle, "status_snapshots").length); const at = evaluationTime(bundle); const status = payload(list(bundle, "status_snapshots")[index]!);
    const choice = rng.int(4);
    const [field, value] = choice === 0 ? ["produced_at", rng.near(at - 300)] : choice === 1 ? ["lease_not_after", rng.near((status.lease_not_before as number) + 3600)] : choice === 2 ? ["lease_not_after", rng.near(at)] : ["next_update", rng.near(at)];
    return artifactMutant(bundle, "status_snapshots", index, field, (next) => { next[field] = value; }, `status_snapshots[${index}].${field} = ${value}`);
  }),
  op("receipt/coordinate-collision", "payload", 9, "mutateReceipt only (re-id + re-sign + sort)", (seed) => receipts(seed.bundle).length > 1, (seed, rng) => {
    const bundle = fresh(seed); const all = receipts(bundle); const index = rng.int(all.length);
    const siblings = all.filter((value, other) => other !== index && value.issuer_role === all[index]!.issuer_role); if (siblings.length === 0) return null;
    const seq = (rng.pick(siblings).emission as Obj).issuer_seq as number;
    return receiptMutant(bundle, index, "emission.issuer_seq", (value) => { (value.emission as Obj).issuer_seq = seq; }, `receipts[${index}].emission.issuer_seq = ${seq}`);
  }),
  op("receipt/outcome-subject", "payload", 10, "mutateReceipt only", (seed) => receiptWhere(seed.bundle, (value) => value.kind === "outcome_observation").length > 0, (seed, rng) => {
    const bundle = fresh(seed); const index = rng.pick(receiptWhere(bundle, (value) => value.kind === "outcome_observation"));
    const current = (receipts(bundle)[index]!.body as Obj).subject_id as Uint8Array; const next = rng.bool() ? otherReceiptId(bundle, rng, current) : rng.bytes(32); if (next === null) return null;
    return receiptMutant(bundle, index, "body.subject_id", (value) => { (value.body as Obj).subject_id = next; }, `receipts[${index}].body.subject_id -> ${toHex(next).slice(0, 8)}`);
  }),
  op("replay/freshness", "payload", 11, "mutateReceipt only", has("receipts"), (seed, rng) => {
    const bundle = fresh(seed); const index = rng.int(receipts(bundle).length); const value = receipts(bundle)[index]!; const committed = (value.emission as Obj).committed_at as number;
    const field = rng.pick(["issued_at", "expires_at"] as const); const at = rng.near(committed);
    return receiptMutant(bundle, index, `freshness.${field}`, (next) => { (next.freshness as Obj)[field] = at; }, `receipts[${index}].freshness.${field} = ${at} (committed_at ${committed})`);
  }),
  op("replay/intended-parents", "payload", 11, "mutateReceipt only", (seed) => receiptWhere(seed.bundle, (value) => (value.parents as CborValue[]).length > 0).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const index = rng.pick(receiptWhere(bundle, (value) => (value.parents as CborValue[]).length > 0)); const current = receipts(bundle)[index]!;
    const other = otherReceiptId(bundle, rng, current.receipt_id as Uint8Array); const choice = rng.int(3);
    return receiptMutant(bundle, index, "freshness.intended_parents", (value) => {
      const intended = (value.freshness as Obj).intended_parents as Uint8Array[];
      if (choice === 0) intended.pop(); else if (choice === 1 && other) intended[rng.int(intended.length)] = other; else intended.push(other ?? rng.bytes(32));
    }, `receipts[${index}].freshness.intended_parents ${["pop", "replace", "push"][choice]}`);
  }),
  op("graph/child-edge", "payload", 12, "mutateReceipt; intended_parents synced only when parent_id changes", (seed) => receiptWhere(seed.bundle, (value) => (value.parents as CborValue[]).length > 0).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const index = rng.pick(receiptWhere(bundle, (value) => (value.parents as CborValue[]).length > 0)); const current = receipts(bundle)[index]!;
    const edgeIndex = rng.int((current.parents as CborValue[]).length); const field = rng.pick(["parent_kind", "edge_type", "parent_tenant_id", "parent_site_id", "parent_epoch_id", "parent_id"] as const);
    const other = otherReceiptId(bundle, rng, current.receipt_id as Uint8Array);
    return receiptMutant(bundle, index, `parents.${edgeIndex}.${field}`, (value) => {
      const edge = (value.parents as Obj[])[edgeIndex]!;
      if (field === "parent_kind") edge.parent_kind = rng.pick(["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"].filter((kind) => kind !== edge.parent_kind));
      else if (field === "edge_type") edge.edge_type = rng.pick(["derived_from", "requested_by", "authorized_by", "triggered_by", "attempted_as", "observed_outcome", "supports"].filter((type) => type !== edge.edge_type));
      else if (field === "parent_epoch_id") edge.parent_epoch_id = (edge.parent_epoch_id as number) + (rng.bool() ? 1 : -1);
      else if (field === "parent_id") { edge.parent_id = other ?? rng.bytes(32); (value.freshness as Obj).intended_parents = (value.parents as Obj[]).map((parent) => parent.parent_id!); }
      else edge[field] = rng.bytes(16);
    }, `receipts[${index}].parents[${edgeIndex}].${field}`);
  }),
  op("delegation/embedded", "payload", 13, "delegation re-id + decision commitment + descendant receipt cascade (mutateEmbeddedDelegation on the dispatched authorization)", (seed) => dispatchedAuthorization(seed.bundle) !== null, (seed, rng) => {
    const bundle = fresh(seed); const authorization = dispatchedAuthorization(bundle)!; const attempts = receipts(bundle).filter((value) => value.kind === "action_attempt").map((value) => (value.emission as Obj).committed_at as number);
    const choice = rng.int(4); let detail = "";
    mutateEmbeddedDelegation(bundle, (delegation) => {
      if (choice === 0) { const actions = (delegation.scope as Obj).actions as string[]; const next = actions.includes("camera.ptz.preset") ? ["camera.view"] : ["camera.ptz.preset"]; (delegation.scope as Obj).actions = next; detail = `scope.actions -> ${next[0]}`; }
      else if (choice === 1) { delegation.not_before = rng.near(attempts.length ? Math.min(...attempts) : (delegation.not_after as number) - 1); detail = `not_before = ${delegation.not_before}`; }
      else if (choice === 2) { delegation.not_after = rng.near(attempts.length ? Math.max(...attempts) : 1); detail = `not_after = ${delegation.not_after}`; }
      else { delegation.parent_delegations = [rng.bytes(32)]; detail = "parent_delegations -> unknown"; }
    }, authorization);
    return encode(bundle, "artifacts.receipts.*.payload.body.delegation", `embedded delegation ${detail}`);
  }),
  op("epoch/event", "payload", 14, "mutateArtifact (re-id + re-sign + sort); chain not relinked", (seed) => list(seed.bundle, "epoch_events").length > 1, (seed, rng) => {
    const bundle = fresh(seed);
    if (rng.bool()) { mutateArtifact(bundle, "epoch_events", (value) => value.event_seq === 1, (value) => { value.previous_event_digest = rng.bytes(32); }); return encode(bundle, "artifacts.epoch_events.*.payload.previous_event_digest", "event_seq 1 previous_event_digest random"); }
    let detail = ""; mutateLastEvent(bundle, (value) => { value.occurred_at = (value.occurred_at as number) + (rng.bool() ? 1 : -1); detail = `last event occurred_at = ${value.occurred_at}`; });
    return encode(bundle, "artifacts.epoch_events.*.payload.occurred_at", detail);
  }),
  op("manifest/index", "payload", 15, "rebuildManifest(keepAnchor) + rebuildEventChain + rebuildAnchor", (seed) => list(seed.bundle, "epoch_manifests").length > 0 && (((payload(list(seed.bundle, "epoch_manifests")[0]!).receipt_index as Obj)?.entries as CborValue[] | undefined)?.length ?? 0) > 1, (seed, rng) => {
    const bundle = fresh(seed); const choice = rng.int(6); let detail = "";
    rebuildManifest(bundle, (manifest) => {
      const index = manifest.receipt_index as Obj; const entries = index.entries as Obj[]; const i = rng.int(entries.length); const j = (i + 1) % entries.length;
      if (choice === 0) { [entries[i], entries[j]] = [entries[j]!, entries[i]!]; detail = `entries ${i}<->${j}`; }
      else if (choice === 1) { entries[i]!.leaf_index = (entries[i]!.leaf_index as number) + 1; detail = `entries[${i}].leaf_index +1`; }
      else if (choice === 2) { entries[i]!.epoch_seq = entries[j]!.epoch_seq!; detail = `entries[${i}].epoch_seq = entries[${j}]`; }
      else if (choice === 3) { entries[i]!.receipt_kind = rng.pick(["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"].filter((kind) => kind !== entries[i]!.receipt_kind)); detail = `entries[${i}].receipt_kind`; }
      else if (choice === 4) { index.root = rng.bytes(32); detail = "index root random"; }
      else { index.leaf_count = (index.leaf_count as number) + (rng.bool() ? 1 : -1); detail = "leaf_count +-1"; }
    }, true);
    return encode(bundle, "artifacts.epoch_manifests.*.payload.receipt_index", `manifest ${detail}`);
  }),
  op("merkle/sibling", "payload", 16, "none", (seed) => list(seed.bundle, "merkle_proofs").length > 0, (seed, rng) => {
    const bundle = fresh(seed); const proofs = artifacts(bundle).merkle_proofs as Obj[]; const index = rng.int(proofs.length); const proof = proofs[index]!; const siblings = proof.siblings as Uint8Array[];
    const choice = siblings.length > 0 ? rng.int(3) : 1 + rng.int(2); let detail = "";
    if (choice === 0) { const s = rng.int(siblings.length); const changed = new Uint8Array(siblings[s]!); const b = rng.int(32); changed[b] = changed[b]! ^ (1 << rng.int(8)); siblings[s] = changed; detail = `siblings[${s}] bit`; }
    else if (choice === 1) { proof.leaf_index = (proof.leaf_index as number) + (rng.bool() ? 1 : -1); detail = "leaf_index +-1"; }
    else { proof.tree_size = (proof.tree_size as number) + (rng.bool() ? 1 : -1); detail = "tree_size +-1"; }
    return encode(bundle, "artifacts.merkle_proofs", `merkle_proofs[${index}] ${detail}`);
  }),
  op("anchor/proof", "payload", 17, "re-id + re-sign + sort (expected head not rewritten)", has("anchors"), (seed, rng) => {
    const bundle = fresh(seed); const index = rng.int(list(bundle, "anchors").length); const deadline = list(bundle, "epoch_manifests").length ? payload(list(bundle, "epoch_manifests")[0]!).anchor_deadline as number : null;
    const choice = rng.int(deadline === null ? 3 : 4); let detail = "";
    return artifactMutant(bundle, "anchors", index, ["inclusion", "accepted_at", "head", "submitted_at"][choice]!, (anchor) => {
      if (choice === 0) { (anchor.inclusion as Obj).leaf_digest = rng.bytes(32); detail = "inclusion.leaf_digest random"; }
      else if (choice === 1) { anchor.accepted_at = (anchor.accepted_at as number) + (rng.bool() ? 1 : -1); detail = `accepted_at = ${anchor.accepted_at}`; }
      else if (choice === 2) { (anchor.head as Obj).tree_size = ((anchor.head as Obj).tree_size as number) + (rng.bool() ? 1 : -1); detail = "head.tree_size +-1"; }
      else { anchor.submitted_at = rng.near(deadline!); detail = `submitted_at = ${anchor.submitted_at} (deadline ${deadline})`; }
    }, `anchors[${index}] ${detail}`);
  }),
  op("anchor/head", "payload", 17, "none (trust input edited, trust digest untouched)", (seed) => ((seed.bundle.trust_inputs as Obj).expected_anchor_heads as CborValue[]).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const heads = (bundle.trust_inputs as Obj).expected_anchor_heads as Obj[]; const index = rng.int(heads.length); const head = heads[index]!; const at = evaluationTime(bundle);
    const choice = rng.int(4); const field = ["root", "observed_at", "tree_size", "target_id"][choice]!;
    if (choice === 0) head.root = rng.bytes(32); else if (choice === 1) head.observed_at = rng.near(at - 86_400); else if (choice === 2) head.tree_size = (head.tree_size as number) + (rng.bool() ? 1 : -1); else head.target_id = rng.bytes(16);
    return encode(bundle, `trust_inputs.expected_anchor_heads.${index}.${field}`, `expected_anchor_heads[${index}].${field}`);
  }),
  op("range/sibling", "payload", 18, "none", (seed) => ((seed.bundle.ranges as Obj[]) ?? []).some((range) => (range.entries as Obj[]).some((entry) => ((entry.inclusion as Obj).siblings as CborValue[]).length > 0)), (seed, rng) => {
    const bundle = fresh(seed); const ranges = bundle.ranges as Obj[]; const r = rng.int(ranges.length); const entries = ranges[r]!.entries as Obj[]; const candidates = entries.flatMap((entry, i) => ((entry.inclusion as Obj).siblings as CborValue[]).length > 0 ? [i] : []);
    if (candidates.length === 0) return null; const e = rng.pick(candidates); const siblings = (entries[e]!.inclusion as Obj).siblings as Uint8Array[]; const s = rng.int(siblings.length); const changed = new Uint8Array(siblings[s]!); const b = rng.int(32); changed[b] = changed[b]! ^ (1 << rng.int(8)); siblings[s] = changed;
    return encode(bundle, "ranges", `ranges[${r}].entries[${e}].inclusion.siblings[${s}] bit`);
  }),
  op("range/boundary", "payload", 18, "none", (seed) => ((seed.bundle.ranges as Obj[]) ?? []).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const ranges = bundle.ranges as Obj[]; const r = rng.int(ranges.length); const range = ranges[r]!; const entries = range.entries as Obj[]; const choice = rng.int(3); let detail = "";
    if (choice === 0 && entries.length > 0) { entries.splice(rng.int(entries.length), 1); if (entries.length === 0) delete range.first_leaf_index; detail = "entry removed"; }
    else if (choice === 1 && typeof range.first_leaf_index === "number") { range.first_leaf_index = range.first_leaf_index + (rng.bool() ? 1 : -1); detail = "first_leaf_index +-1"; }
    else { range.tree_size = (range.tree_size as number) + (rng.bool() ? 1 : -1); detail = "tree_size +-1"; }
    return encode(bundle, "ranges", `ranges[${r}] ${detail}`);
  }),
  op("bundle/selector", "payload", 18, "recalcSelector", () => true, (seed, rng) => {
    const bundle = fresh(seed); const selector = bundle.selector as Obj; const choice = rng.int(3); let detail = "";
    if (choice === 0) { selector.committed_until = rng.near(selector.committed_from as number); detail = `committed_until = ${selector.committed_until}`; }
    else if (choice === 1 && (selector.receipt_kinds as string[]).length > 1) { const kinds = selector.receipt_kinds as string[]; kinds.splice(rng.int(kinds.length), 1); detail = "receipt_kinds minus one"; }
    else { const keys = ["subject_ids", "correlation_ids"].filter((key) => selector[key] !== undefined); if (keys.length === 0) return null; const key = rng.pick(keys); delete selector[key]; detail = `drop ${key}`; }
    recalcSelector(bundle);
    return encode(bundle, "selector", `selector ${detail}`);
  }),
  op("evidence/payload-delete", "payload", 19, "none (referencing receipt untouched)", (seed) => referencedPayloads(seed.bundle).length > 0, (seed, rng) => {
    const bundle = fresh(seed); const refs = referencedPayloads(bundle); const digest = rng.pick(refs); const payloads = artifacts(bundle).manifest_payloads as Obj[];
    artifacts(bundle).manifest_payloads = payloads.filter((entry) => toHex(entry.digest as Uint8Array) !== digest);
    return encode(bundle, "artifacts.manifest_payloads", `manifest_payloads minus ${digest.slice(0, 8)} (declared-class evidence)`);
  }),
  op("key/verifier-credential-remove", "payload", 20, "none", (seed) => !seed.policy && list(seed.bundle, "credentials").some((entry) => payload(entry).key_usage === "verifier_signing"), (seed) => {
    const bundle = fresh(seed); artifacts(bundle).credentials = list(bundle, "credentials").filter((entry) => payload(entry).key_usage !== "verifier_signing"); sortArtifacts(bundle, "credentials");
    return encode(bundle, "artifacts.credentials", "verifier_signing credential removed");
  }),
];

// Digests of manifest payloads that a receipt's declared evidence class requires.
export function referencedPayloads(bundle: Obj): string[] {
  const present = new Set((list(bundle, "manifest_payloads") as Obj[]).map((entry) => toHex(entry.digest as Uint8Array)));
  const refs = receipts(bundle).flatMap((value) => ["evidence.time.boot_attestation_id", "evidence.provenance.capture_attestation_id", "evidence.provenance.provider_attestation_id", "evidence.outcome.qualifying_predicate_id"].flatMap((path) => { const id = getAt(value, path.split(".")); return id instanceof Uint8Array ? [toHex(id)] : []; }));
  return [...new Set(refs.filter((digest) => present.has(digest)))].sort();
}
