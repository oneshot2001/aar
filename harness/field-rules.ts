// CONFORMANCE step 6 field rules (D-82 part 8) and the closed enums they name: the
// bounded schema table and its apply helpers, moved out of verifier.ts unchanged.
// pyref/field_rules.py mirrors this module.
import { CborValue } from "./cbor";
import { ArtifactKind, B1Failure, failure, Obj, object, uint } from "./verifier";

// D-88: the three action-name productions and delegation-scope actions.
export const ACTION_NAMES = ["camera.stream.view", "camera.ptz.preset"];
export const TIME_CLASSES = ["asserted", "boot_bound", "externally_anchored"];
export const PROVENANCE_CLASSES = ["self_asserted", "proxy_captured", "provider_attested"];
export const OUTCOME_LEVELS = ["accepted", "dispatched", "device_acknowledged", "independently_sensed", "contradicted", "unknown"];
const TRANSFORMATION_OPERATIONS = ["decode", "crop", "embed", "ocr", "truncate", "retrieve", "normalize", "render", "redact"];
// A rule whose kind is a rule list is applied to every member of the array at
// its path; each member must be a text-keyed map (amendment b: array members).
type FieldKind = "uint" | "uint|nil" | "bytes" | "bstr32" | "bstr16" | "bstr32[]" | "bstr16[]" | "text" | "array" | "map" | readonly string[] | readonly FieldRule[];
type FieldRule = readonly [path: readonly string[], kind: FieldKind, optional?: boolean];
const INDEX_ENTRY_RULES: readonly FieldRule[] = [
  [["leaf_index"], "uint"], [["receipt_id"], "bstr32"], [["receipt_kind"], "text"], [["issuer_kid"], "bstr32"],
  [["issuer_seq"], "uint"], [["epoch_seq"], "uint"], [["committed_at"], "uint"], [["subject_ids"], "bstr16[]"], [["correlation_ids"], "bstr16[]"],
];
export const INDEPENDENCE_GROUP_RULES: readonly FieldRule[] = [[["independence_group"], "bstr16"], [["operator_id"], "bstr16"], [["failure_domain_id"], "bstr16"]];
const INCLUSION_RULES: readonly FieldRule[] = [[["tree_size"], "uint"], [["leaf_index"], "uint"], [["siblings"], "bstr32[]"]];
// Amendment (ab): the bare proof-bearing productions, typed at step 3.
export const MERKLE_PROOF_RULES: readonly FieldRule[] = [
  [["batch_id"], "bstr32"], [["tree_size"], "uint"], [["leaf_index"], "uint"],
  [["leaf"], "map"], [["leaf", "tree_size"], "uint"], [["leaf", "leaf_index"], "uint"], [["leaf", "tenant_id"], "bstr16"], [["leaf", "site_id"], "bstr16"],
  [["leaf", "epoch_id"], "uint"], [["leaf", "item_digest"], "bstr32"], [["siblings"], "bstr32[]"],
];
const RANGE_ITEM_RULES: readonly FieldRule[] = [[["entry"], "map"], [["entry"], INDEX_ENTRY_RULES], [["inclusion"], "map"], [["inclusion"], INCLUSION_RULES]];
export const RANGE_PROOF_RULES: readonly FieldRule[] = [
  [["manifest_id"], "bstr32"], [["selector_commitment"], "bstr32"], [["tree_size"], "uint"], [["first_leaf_index"], "uint", true],
  [["entries"], "array"], [["entries"], RANGE_ITEM_RULES],
  [["left_boundary"], "map", true], [["left_boundary"], RANGE_ITEM_RULES], [["right_boundary"], "map", true], [["right_boundary"], RANGE_ITEM_RULES],
];
const isRuleList = (kind: FieldKind): kind is readonly FieldRule[] => Array.isArray(kind) && kind.length > 0 && Array.isArray(kind[0]);
// D-82 part 8: the bounded step-6 schema table. Rules are in CDDL field order
// within each production; kind is a scalar type or a closed enum. A
// container's rule precedes its members' rules (D-81 UINT_FIELDS generalised;
// the credential and presentation blocks are inline because their pinned
// precedences interleave D-73 checks).
export const FIELD_RULES: Partial<Record<ArtifactKind, readonly FieldRule[]>> = {
  rotation: [[["effective_at"], "uint"], [["continuity_sequence"], "uint"]],
  delegation: [[["not_before"], "uint"], [["not_after"], "uint"], [["use"], ["one_time", "reusable"]]],
  epoch_event: [[["epoch_id"], "uint"], [["event_seq"], "uint"], [["occurred_at"], "uint"], [["event"], ["open", "close", "anchor_submitted", "fork_declared"]], [["body"], "map"]],
  epoch_manifest: [
    [["epoch_id"], "uint"], [["opened_at"], "uint"], [["closed_at"], "uint"],
    [["sequence_span"], "map"], [["sequence_span", "first"], "uint|nil"], [["sequence_span", "last"], "uint|nil"],
    [["close_reason"], ["duration", "size", "administrative", "padding"]],
    [["late_arrival_policy"], ["next_epoch_only"]], [["anchor_deadline"], "uint"], [["fork_policy"], ["reject_and_surface"]],
    [["receipt_index"], "map"], [["receipt_index", "leaf_count"], "uint"], [["receipt_index", "root"], "bstr32"],
    [["receipt_index", "entries"], "array"], [["receipt_index", "entries"], INDEX_ENTRY_RULES],
  ],
  anchor: [
    [["epoch_id"], "uint"], [["manifest_digest"], "bstr32"], [["submitted_at"], "uint"], [["accepted_at"], "uint"],
    [["anchor_tree_size"], "uint"], [["anchor_leaf_index"], "uint"], [["anchor_root"], "bstr32"],
    [["inclusion"], "map"], [["inclusion", "tree_size"], "uint"], [["inclusion", "leaf_index"], "uint"], [["inclusion", "leaf_digest"], "bstr32"], [["inclusion", "siblings"], "bstr32[]"],
    [["consistency"], "map", true], [["consistency", "old_tree_size"], "uint"], [["consistency", "new_tree_size"], "uint"], [["consistency", "old_root"], "bstr32"], [["consistency", "new_root"], "bstr32"], [["consistency", "path"], "bstr32[]"],
    [["head"], "map"], [["head", "observed_at"], "uint"], [["head", "tree_size"], "uint"], [["head", "root"], "bstr32"], [["head", "max_age_s"], "uint"],
  ],
  merkle_batch: [
    [["tenant_id"], "bstr16"], [["site_id"], "bstr16"], [["epoch_owner_kid"], "bstr32"], [["epoch_id"], "uint"], [["signer_kid"], "bstr32"],
    [["tree_size"], "uint"], [["root"], "bstr32"], [["created_at"], "uint"], [["claim"], "text"],
  ],
  mediator_countersignature: [[["mediator_observed_at"], "uint"]],
  receipt: [
    [["binding"], "map"], [["binding", "tenant_id"], "bytes"], [["binding", "site_id"], "bytes"], [["binding", "epoch_owner_kid"], "bytes"],
    [["binding", "epoch_id"], "uint"], [["binding", "epoch_seq"], "uint"], [["binding", "late_for_epoch_id"], "uint", true],
    [["emission"], "map"], [["emission", "issuer_seq"], "uint"], [["emission", "committed_at"], "uint"],
    [["freshness"], "map"], [["freshness", "issued_at"], "uint"], [["freshness", "expires_at"], "uint"], [["freshness", "nonce"], "bytes"],
    [["freshness", "replay_domain"], "bytes"], [["freshness", "invocation_id"], "bytes"], [["freshness", "use"], "text"], [["freshness", "intended_parents"], "array"],
    [["evidence"], "map"], [["evidence", "time"], "map"], [["evidence", "time", "class"], TIME_CLASSES], [["evidence", "time", "wall_time"], "uint"],
    [["evidence", "provenance"], "map", true], [["evidence", "provenance", "class"], PROVENANCE_CLASSES],
    [["evidence", "outcome"], "map", true], [["evidence", "outcome", "level"], OUTCOME_LEVELS],
    [["parents"], "array"], [["parents"], [[["parent_epoch_id"], "uint"]]],
    [["correlation"], "map", true], [["correlation", "phase"], ["request", "ingress_ack", "accounted"]],
    [["body"], "map"],
  ],
};

function typeOk(value: CborValue | undefined, kind: FieldKind): boolean {
  if (kind === "uint") return uint(value);
  if (kind === "bstr32" || kind === "bstr16") return value instanceof Uint8Array; // size is judged after type (schema/digest-size)
  if (kind === "bstr32[]" || kind === "bstr16[]") return Array.isArray(value);
  if (kind === "uint|nil") return value === null || uint(value); // sequence-span members
  if (kind === "bytes") return value instanceof Uint8Array;
  if (kind === "map") return object(value);
  if (kind === "array") return Array.isArray(value);
  return typeof value === "string"; // "text" and enums
}

// Presence (schema/missing-field), then type (schema/bad-type), then size (schema/digest-size) or enum (schema/enum-unknown).
export function checkField(container: Obj, name: string, kind: FieldKind, path: string, optional = false, step = 6): B1Failure | undefined {
  if (!(name in container)) return optional ? undefined : failure(step, "schema/missing-field", `${path}.${name}`);
  const value = container[name];
  if (!typeOk(value, kind)) return failure(step, "schema/bad-type", `${path}.${name}`);
  if ((kind === "bstr32" || kind === "bstr16") && (value as Uint8Array).length !== (kind === "bstr32" ? 32 : 16)) return failure(step, "schema/digest-size", `${path}.${name}`);
  if (kind === "bstr32[]" || kind === "bstr16[]") {
    for (const member of value as CborValue[]) {
      if (!(member instanceof Uint8Array)) return failure(step, "schema/bad-type", `${path}.${name}`);
      if (member.length !== (kind === "bstr32[]" ? 32 : 16)) return failure(step, "schema/digest-size", `${path}.${name}`);
    }
  }
  if (Array.isArray(kind) && !isRuleList(kind) && !(kind as readonly string[]).includes(value as string)) return failure(step, "schema/enum-unknown", `${path}.${name}`);
  return undefined;
}

export function applyRules(payload: Obj, rules: readonly FieldRule[], path: string, step = 6): B1Failure | undefined {
  for (const [fieldPath, kind, optional] of rules) {
    let container: Obj | undefined = payload;
    for (const key of isRuleList(kind) ? fieldPath : fieldPath.slice(0, -1)) {
      if (!(key in container)) { container = undefined; break; } // an absent optional ancestor; its own rule allowed that
      container = container[key] as Obj;
    }
    if (container === undefined) continue;
    if (isRuleList(kind)) {
      const members: CborValue[] = Array.isArray(container) ? container : [container];
      for (const [index, member] of members.entries()) {
        const memberPath = Array.isArray(container) ? `${path}.${fieldPath.join(".")}[${index}]` : `${path}.${fieldPath.join(".")}`;
        if (!typeOk(member, "map")) return failure(step, "schema/bad-type", memberPath);
        const issue = applyRules(member as Obj, kind, memberPath, step);
        if (issue) return issue;
      }
      continue;
    }
    const issue = checkField(container, fieldPath[fieldPath.length - 1]!, kind, `${path}.${fieldPath.slice(0, -1).join(".")}`, optional, step);
    if (issue) return issue;
  }
  return undefined;
}

// Each text-keyed transformation map validates its closed operation enum.
export function checkTransformations(transforms: CborValue[], path: string): B1Failure | undefined {
  for (const [index, transform] of transforms.entries()) {
    if (!object(transform)) continue;
    const issue = checkField(transform, "operation", TRANSFORMATION_OPERATIONS, `${path}[${index}]`);
    if (issue) return issue;
  }
  return undefined;
}
