import type { AdapterId, ActionName, LogicalTargetName, ScenarioId } from "../../adapters/shared/types";
import type { CborValue } from "../../harness/cbor";
import { encodeCbor, toHex } from "../../harness/cbor";
import { domainHash, hash } from "../../harness/crypto";
import { promotedProofWithDomain, promotedRoot } from "../../harness/merkle";
import type { LocalRfc6962Log } from "../anchor/log";
import type { DemoKey, DemoKeyRole } from "../keys/keys";
import type { BuiltCommandManifest } from "./command-manifest";
import { signDemoDetached, type DemoSignedEnvelope } from "./signing";
import { policyFields, type DemoTrustPolicy } from "./authorization";

type Obj = Record<string, CborValue>;

const CONTENT_TYPES = {
  receipt: "application/aar-receipt+cbor;v=0.2",
  request: "application/aar-request+cbor;v=0.2",
  delegation: "application/aar-delegation+cbor;v=0.2",
  credential: "application/aar-credential+cbor;v=0.2",
  epochManifest: "application/aar-epoch-manifest+cbor;v=0.2",
} as const;

export interface DelegationWindow {
  readonly notBefore: number;
  readonly notAfter: number;
}

// Optional real-narrative overrides for non-demo producers. Every field
// defaults to the original Gate-5 scenario value, so omitting this object
// reproduces the demo bundles byte-for-byte. A producer that supplies these
// makes the receipt BODIES real instead of scenario placeholders:
// timestamps from its own clock, its actual model/agent record, and the
// authorization decision it actually evaluated (policySetRoot = digest of the
// REAL policy; decision "deny" yields a not_dispatched attempt with the given
// refusal reason — the generalization of the S3 delegation-expiry special case).
export interface RealNarrative {
  // Real emission time for every receipt (ties order by epoch_seq). INVARIANT
  // (enforced below, because the non-overridable freshness window and bundle
  // selector stay pinned to evaluatedAt): committedAt must lie within
  // [evaluatedAt - 60, evaluatedAt], and epochClosedAt >= committedAt must be
  // supplied alongside it whenever committedAt > evaluatedAt - 40 (the default
  // closed_at) — otherwise the bundle fails epoch/late-insertion.
  readonly committedAt?: number;
  readonly observedAt?: number;         // observation body observed_at
  readonly dispatchedAt?: number;       // dispatch body dispatched_at
  readonly outcomeObservedAt?: number;  // outcome_observation body observed_at
  readonly epochOpenedAt?: number;
  readonly epochClosedAt?: number;
  readonly monotonicNs?: number;
  readonly bootId?: Uint8Array;         // 16 bytes
  readonly transportId?: string;
  readonly model?: { readonly provider: string; readonly model: string; readonly version: string };
  readonly uncertaintyBps?: number;
  // "deny" REQUIRES refusalReason (no confabulated default) and forbids a
  // dispatch input. Placeholder residue that stays demo-valued even with full
  // narrative supplied: the legal block (purpose incident-response,
  // jurisdiction US-CO, retention demo), delegation scope purpose_ids,
  // correlation peer_binding_digest, decision evaluated_inputs, and
  // counter_state_digest.
  readonly decision?: "permit" | "deny";
  readonly policySetRoot?: Uint8Array;  // digest of the policy actually evaluated
}

function validateNarrative(input: WireBuildInput): void {
  const narrative = input.narrative;
  if (!narrative) return;
  if (narrative.decision === "deny" && input.refusalReason === undefined) {
    throw new Error("narrative.decision \"deny\" requires an explicit refusalReason — the delegation-expired default would sign a false statement");
  }
  if (narrative.decision === "deny" && input.dispatch) {
    throw new Error("narrative.decision \"deny\" cannot carry a dispatch result");
  }
  if (narrative.decision === "permit" && input.scenarioId === "S3") {
    throw new Error("scenario S3 forces a refusal — narrative.decision \"permit\" would sign an incoherent permit + not_dispatched + delegation-expired artifact");
  }
  if (narrative.committedAt !== undefined) {
    if (narrative.committedAt < input.evaluatedAt - 60 || narrative.committedAt > input.evaluatedAt) {
      throw new Error("narrative.committedAt must lie within [evaluatedAt - 60, evaluatedAt] (freshness window and bundle selector are pinned to evaluatedAt)");
    }
    const closedAt = narrative.epochClosedAt ?? input.evaluatedAt - 40;
    if (closedAt < narrative.committedAt) {
      throw new Error("epoch closed_at precedes narrative.committedAt — supply epochClosedAt >= committedAt or the bundle fails epoch/late-insertion");
    }
  }
  if (narrative.uncertaintyBps !== undefined && (narrative.uncertaintyBps < 0 || narrative.uncertaintyBps > 10000)) {
    throw new Error("narrative.uncertaintyBps must be within [0, 10000]");
  }
}

export interface WireBuildInput {
  readonly scenarioId: ScenarioId;
  readonly evaluatedAt: number;
  readonly epochId: number;
  readonly invocationId: Uint8Array;
  readonly correlationId: Uint8Array;
  readonly tenantId: Uint8Array;
  readonly siteId: Uint8Array;
  readonly targetId: Uint8Array;
  readonly targetLogicalName: LogicalTargetName;
  readonly actionName: ActionName;
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  readonly sourceDeviceMetadata: { readonly manufacturer: string; readonly model: string; readonly firmware: string };
  readonly adapterId: AdapterId;
  readonly command: BuiltCommandManifest;
  readonly delegationWindows: readonly DelegationWindow[];
  readonly dispatch?: {
    readonly status: number;
    readonly responseBodyDigest: Uint8Array;
    readonly outcomeLevel: "device_acknowledged" | "contradicted" | "unknown";
    readonly outcomeState: "consistent" | "contradicted" | "unknown";
    readonly observationDigest: Uint8Array;
  };
  readonly refusalReason?: string;
  readonly narrative?: RealNarrative;
  readonly keys: Readonly<Record<DemoKeyRole, DemoKey>>;
  readonly anchorLog: LocalRfc6962Log;
  readonly anchorObservedAt?: number;
}

export interface ReceiptBuild {
  readonly id: Uint8Array;
  readonly kind: string;
  readonly fields: Obj;
  readonly signed: DemoSignedEnvelope;
  readonly issuerKid: Uint8Array;
  readonly epochSeq: number;
  readonly issuerSeq: number;
  readonly committedAt: number;
}

export interface TrustPolicyJson {
  readonly trust_store: {
    readonly digest: string;
    readonly snapshot_id: string;
    readonly created_at: number;
    readonly roots: readonly {
      readonly root_id: string;
      readonly root_kid: string;
      readonly tenant_id: string;
      readonly allowed_sites: readonly string[];
      readonly allowed_key_usages: readonly string[];
    }[];
  };
  readonly expected_anchor_heads: readonly {
    readonly target_id: string;
    readonly observed_at: number;
    readonly tree_size: number;
    readonly root: string;
  }[];
  readonly verifier_policy_digest: string;
}

export interface WireBuildResult {
  readonly bundle: Uint8Array;
  readonly trustPolicy: TrustPolicyJson;
  readonly receipts: readonly ReceiptBuild[];
  readonly request: DemoSignedEnvelope;
  readonly selectedDelegation: Obj;
  readonly allDelegations: readonly Obj[];
  readonly manifest: DemoSignedEnvelope;
}

export type AgentRequestInput = Pick<WireBuildInput,
  "evaluatedAt" | "invocationId" | "correlationId" | "tenantId" | "siteId" |
  "targetId" | "targetLogicalName" | "actionName" | "parameters" | "keys">;

function opaque(label: string): Uint8Array {
  return hash(new TextEncoder().encode(`AAR-DEMO-OPAQUE-ID:${label}`));
}

function id16(label: string): Uint8Array {
  return opaque(label).slice(0, 16);
}

function canonicalSort(values: CborValue[]): CborValue[] {
  return [...values].sort((left, right) => Buffer.compare(Buffer.from(encodeCbor(left)), Buffer.from(encodeCbor(right))));
}

function sortById<T>(values: readonly T[], id: (value: T) => Uint8Array): T[] {
  return [...values].sort((left, right) => Buffer.compare(Buffer.from(id(left)), Buffer.from(id(right))));
}

function legal(): Obj {
  return { purpose_id: "incident-response", jurisdiction_id: "US-CO", data_classification_id: "security-sensitive", retention_class_id: "demo", legal_hold: false };
}

function profileLimits(): Obj {
  return { profile: "AAR-3", status_max_age_s: 300, lease_max_s: 3600, anchor_max_cadence_s: 86400 };
}

function credentialSpec(role: DemoKeyRole): { principalType: string; principalRole: string; usage: string } {
  switch (role) {
    case "agent": return { principalType: "model_endpoint", principalRole: "agent", usage: "agent_signing" };
    case "ep": return { principalType: "service", principalRole: "enforcement_point", usage: "ep_signing" };
    case "authority": return { principalType: "service", principalRole: "authority_source", usage: "authority_signing" };
    case "outcome": return { principalType: "service", principalRole: "outcome_observer", usage: "outcome_signing" };
    case "anchor": return { principalType: "service", principalRole: "anchor_service", usage: "anchor_signing" };
    case "verifier-trust": return { principalType: "authority_source", principalRole: "authority_source", usage: "credential_issuing" };
  }
}

function buildCredentials(input: WireBuildInput): { envelopes: DemoSignedEnvelope[]; ids: Record<DemoKeyRole, Uint8Array> } {
  const rootKey = input.keys["verifier-trust"];
  const ids = {} as Record<DemoKeyRole, Uint8Array>;
  const fieldsByRole = {} as Record<DemoKeyRole, Obj>;
  const rootFields: Obj = {
    v: 2, subject_kid: rootKey.kid, public_key: rootKey.spki, issuer_kid: rootKey.kid,
    principal_type: "authority_source", principal_role: "authority_source",
    tenant_id: input.tenantId, site_id: input.siteId,
    valid_from: input.evaluatedAt - 3600, valid_until: input.evaluatedAt + 86400,
    cose_alg: -7, curve: "P-256", key_usage: "credential_issuing",
    trust_anchor_id: opaque(`trust-anchor:${toHex(rootKey.kid)}`), path: [], profile_limits: profileLimits(),
  };
  ids["verifier-trust"] = domainHash("AAR-CREDENTIAL-ID-v1", rootFields);
  fieldsByRole["verifier-trust"] = rootFields;
  for (const role of ["agent", "ep", "authority", "outcome", "anchor"] as DemoKeyRole[]) {
    const key = input.keys[role];
    const spec = credentialSpec(role);
    const fields: Obj = {
      v: 2, subject_kid: key.kid, public_key: key.spki, issuer_kid: rootKey.kid,
      principal_type: spec.principalType, principal_role: spec.principalRole,
      tenant_id: input.tenantId, site_id: input.siteId,
      valid_from: input.evaluatedAt - 3600, valid_until: input.evaluatedAt + 86400,
      cose_alg: -7, curve: "P-256", key_usage: spec.usage,
      trust_anchor_id: opaque(`trust-anchor:${toHex(rootKey.kid)}`), path: [ids["verifier-trust"]], profile_limits: profileLimits(),
    };
    ids[role] = domainHash("AAR-CREDENTIAL-ID-v1", fields);
    fieldsByRole[role] = fields;
  }
  const envelopes = (Object.keys(fieldsByRole) as DemoKeyRole[]).map((role) =>
    signDemoDetached({ credential_id: ids[role], ...fieldsByRole[role] }, CONTENT_TYPES.credential, rootKey));
  return { envelopes: sortById(envelopes, (item) => (item.payload as Obj).credential_id as Uint8Array), ids };
}

function receiptProtected(fields: Obj, key: DemoKey): readonly (readonly [number, CborValue])[] {
  const binding = fields.binding as Obj;
  const emission = fields.emission as Obj;
  return [
    [-70000, fields.issuer_principal_type!], [-70001, binding.tenant_id!], [-70002, binding.site_id!],
    [-70003, binding.epoch_id!], [-70004, binding.epoch_seq!], [-70005, emission.issuer_seq!], [-70006, fields.issuer_role!],
  ];
}

function makeReceipt(
  input: WireBuildInput,
  kind: string,
  role: "agent" | "ep" | "outcome",
  epochSeq: number,
  parents: Obj[],
  body: Obj,
  root?: Obj,
): ReceiptBuild {
  const key = input.keys[role];
  const spec = credentialSpec(role);
  const base = input.evaluatedAt - 60;
  const committedAt = input.narrative?.committedAt ?? base + 10 + epochSeq;
  const fields: Obj = {
    v: 2, kind, issuer_principal_type: spec.principalType, issuer_role: spec.principalRole,
    binding: { tenant_id: input.tenantId, site_id: input.siteId, epoch_owner_kid: input.keys.ep.kid, epoch_id: input.epochId, epoch_seq: epochSeq },
    emission: { issuer_seq: input.epochId * 100 + epochSeq, committed_at: committedAt },
    freshness: {
      issued_at: base, expires_at: input.evaluatedAt + 3600,
      nonce: id16(`nonce:${toHex(input.invocationId)}:${epochSeq}`), replay_domain: opaque(`replay:${toHex(input.tenantId)}:${toHex(input.siteId)}`),
      invocation_id: input.invocationId, use: "reusable", intended_parents: parents.map((parent) => parent.parent_id as Uint8Array),
    },
    legal: legal(),
    evidence: { time: { class: "asserted", wall_time: committedAt, monotonic_ns: input.narrative?.monotonicNs ?? 1_000_000 + epochSeq, boot_id: input.narrative?.bootId ?? id16(`boot:${input.epochId}`) } },
    parents,
    correlation: {
      correlation_id: input.correlationId, phase: "accounted", target_ep_kid: input.keys.ep.kid,
      transport_id: input.narrative?.transportId ?? `gate5:${input.adapterId}`, peer_binding_digest: opaque(`peer:${input.adapterId}`),
    },
    body,
  };
  if (root) fields.root = root;
  const evidence = fields.evidence as Obj;
  if (kind === "inference") evidence.provenance = { class: "self_asserted" };
  if (kind === "action_attempt") evidence.outcome = { level: "accepted", artifacts: [input.command.command_id] };
  if (kind === "dispatch") evidence.outcome = { level: "dispatched", artifacts: [input.command.command_digest] };
  if (kind === "outcome_observation") evidence.outcome = { level: input.dispatch!.outcomeLevel, artifacts: [input.dispatch!.observationDigest] };
  const extra = receiptProtected(fields, key);
  const protectedBytes = encodeCbor(new Map<number, CborValue>([[1, -7], [3, CONTENT_TYPES.receipt], [4, key.kid], ...extra]));
  const id = domainHash("AAR-RECEIPT-ID-v1", protectedBytes, fields);
  const signed = signDemoDetached({ receipt_id: id, ...fields }, CONTENT_TYPES.receipt, key, extra);
  return {
    id, kind, fields, signed, issuerKid: key.kid, epochSeq,
    issuerSeq: (fields.emission as Obj).issuer_seq as number,
    committedAt: (fields.emission as Obj).committed_at as number,
  };
}

function parent(receipt: ReceiptBuild, edgeType: string, input: WireBuildInput): Obj {
  return { edge_type: edgeType, parent_id: receipt.id, parent_kind: receipt.kind, parent_tenant_id: input.tenantId, parent_site_id: input.siteId, parent_epoch_id: input.epochId };
}

function delegationEnvelope(input: WireBuildInput, window: DelegationWindow, issuerCredentialId: Uint8Array, subjectCredentialId: Uint8Array): { payload: Obj; signed: DemoSignedEnvelope } {
  const fields: Obj = {
    v: 2, issuer_credential_id: issuerCredentialId, subject_credential_id: subjectCredentialId,
    tenant_id: input.tenantId, site_id: input.siteId,
    scope: { actions: [input.actionName], targets: [input.targetId], purpose_ids: ["incident-response"], allowed_profiles: ["AAR-3"] },
    not_before: window.notBefore, not_after: window.notAfter, use: "reusable",
    replay_domain: opaque(`delegation:${toHex(input.tenantId)}:${toHex(input.siteId)}`), invocation_id: input.invocationId, parent_delegations: [],
  };
  const delegationId = domainHash("AAR-DELEGATION-ID-v1", fields);
  const payload: Obj = { delegation_id: delegationId, ...fields };
  return { payload, signed: signDemoDetached(payload, CONTENT_TYPES.delegation, input.keys.authority) };
}

function trustPolicyJson(trust: Obj): TrustPolicyJson {
  const store = trust.trust_store as Obj;
  return {
    trust_store: {
      digest: toHex(store.digest as Uint8Array), snapshot_id: toHex(store.snapshot_id as Uint8Array), created_at: store.created_at as number,
      roots: (store.roots as Obj[]).map((root) => ({
        root_id: toHex(root.root_id as Uint8Array), root_kid: toHex(root.root_kid as Uint8Array), tenant_id: toHex(root.tenant_id as Uint8Array),
        allowed_sites: (root.allowed_sites as Uint8Array[]).map(toHex), allowed_key_usages: root.allowed_key_usages as string[],
      })),
    },
    expected_anchor_heads: (trust.expected_anchor_heads as Obj[]).map((head) => ({
      target_id: toHex(head.target_id as Uint8Array), observed_at: head.observed_at as number,
      tree_size: head.tree_size as number, root: toHex(head.root as Uint8Array),
    })),
    verifier_policy_digest: toHex(trust.verifier_policy_digest as Uint8Array),
  };
}

export function buildSignedAgentRequest(input: AgentRequestInput): DemoSignedEnvelope {
  const requestId = id16(`request:${toHex(input.invocationId)}:${toHex(input.correlationId)}`);
  const requestPayload: Obj = {
    v: 2, request_id: requestId,
    action_intent_digest: hash(encodeCbor({ action: input.actionName, target: input.targetId, parameters: input.parameters })),
    target_ep_kid: input.keys.ep.kid, tenant_id: input.tenantId, site_id: input.siteId,
    correlation: { correlation_id: input.correlationId, phase: "request", target_ep_kid: input.keys.ep.kid, transport_id: "gate5-cli", peer_binding_digest: opaque("peer:gate-cli") },
    freshness: {
      issued_at: input.evaluatedAt - 60, expires_at: input.evaluatedAt + 3600,
      nonce: id16(`request-nonce:${toHex(input.invocationId)}`), replay_domain: opaque("replay:gate-agent"), invocation_id: input.invocationId,
      use: "one_time", intended_parents: [],
    },
    legal: legal(),
  };
  return signDemoDetached(requestPayload, CONTENT_TYPES.request, input.keys.agent);
}

export async function buildDemoBundle(input: WireBuildInput): Promise<WireBuildResult> {
  validateNarrative(input);
  const credentials = buildCredentials(input);
  const request = buildSignedAgentRequest(input);
  const requestPayload = request.payload as Obj;
  const requestId = requestPayload.request_id as Uint8Array;
  const requestRoot: Obj = { kind: "agent_request", request_id: requestId, request_commitment: hash(request.payloadBytes) };

  const delegations = input.delegationWindows.map((window) => delegationEnvelope(input, window, credentials.ids.authority, credentials.ids.ep));
  const selected = input.scenarioId === "S3"
    ? delegations.find((item) => (item.payload.not_after as number) <= input.evaluatedAt)
    : delegations.find((item) => (item.payload.not_before as number) <= input.evaluatedAt && input.evaluatedAt < (item.payload.not_after as number));
  if (!selected) throw new Error(`no ${input.scenarioId === "S3" ? "expired" : "valid"} delegation candidate at evaluation time`);

  const consumptionFields: Obj = { items: [] };
  const consumption: Obj = { manifest_digest: domainHash("AAR-CONSUMPTION-MANIFEST-v1", consumptionFields), ...consumptionFields };
  const sourceDevice: Obj = {
    device_id: input.targetId, manufacturer: input.sourceDeviceMetadata.manufacturer, model: input.sourceDeviceMetadata.model,
    firmware: input.sourceDeviceMetadata.firmware, device_credential_id: opaque(`device-credential:${toHex(input.targetId)}`), failure_domain_id: opaque(`failure-domain:${toHex(input.targetId)}`),
  };
  const observation = makeReceipt(input, "observation", "agent", 0, [], { source_device: sourceDevice, consumption, observed_at: input.narrative?.observedAt ?? input.evaluatedAt - 49 }, requestRoot);

  const promptBytes = encodeCbor({ intent: input.actionName, target: input.targetLogicalName, provenance: "self-asserted" });
  const retrievalBytes = encodeCbor({ documents: [] });
  const toolsBytes = encodeCbor({ calls: [] });
  const promptDigest = hash(promptBytes);
  const retrievalDigest = hash(retrievalBytes);
  const toolsDigest = hash(toolsBytes);
  const conclusionBytes = encodeCbor({ action: input.actionName, target: input.targetLogicalName });
  // Explicit destructure: model-identity is a closed CDDL map — a spread of a
  // wider-typed caller object would smuggle extra keys past pyref undetected.
  const { provider, model, version } = input.narrative?.model ?? { provider: "AAR demo", model: "scripted-agent", version: "0.1.0" };
  const inference = makeReceipt(input, "inference", "agent", 1, [parent(observation, "derived_from", input)], {
    model: { provider, model, version, endpoint_credential_id: credentials.ids.agent },
    consumption_manifest_id: (consumption.manifest_digest as Uint8Array),
    prompt_manifest: { digest: promptDigest, media_type: "application/cbor", byte_length: promptBytes.length },
    retrieval_manifest: { digest: retrievalDigest, media_type: "application/cbor", byte_length: retrievalBytes.length },
    tool_transcript_manifest: { digest: toolsDigest, media_type: "application/cbor", byte_length: toolsBytes.length },
    conclusion: { schema_id: "aar.demo.intent.v1", canonical_cbor: conclusionBytes, digest: hash(conclusionBytes) }, uncertainty_bps: input.narrative?.uncertaintyBps ?? 0,
  });

  const decisionFields: Obj = {
    policy_set_root: input.narrative?.policySetRoot ?? domainHash("AAR-DEMO-TRUST-POLICY-v1", policyFields({
      version: 1, profile: "AAR-3", purposeId: "incident-response", authorityKid: input.keys.authority.kid,
      allowedActions: ["camera.ptz.preset", "camera.stream.view"], allowedTargets: [input.targetId],
    } satisfies DemoTrustPolicy)), effective_policy_epoch: 1,
    evaluated_inputs: [{ name: "delegation-time", value_digest: hash(encodeCbor({ not_before: selected.payload.not_before!, not_after: selected.payload.not_after!, evaluated_at: input.evaluatedAt })) }],
    decision: input.narrative?.decision ?? (input.scenarioId === "S3" ? "deny" : "permit"), counter_state_digest: opaque(`counter:${toHex(input.invocationId)}`),
    status_snapshot_ids: [], profile: "AAR-3", delegation_id: selected.payload.delegation_id!,
  };
  const decisionCommitment = domainHash("AAR-DECISION-RECORD-v1", decisionFields);
  const authorization = makeReceipt(input, "authorization", "ep", 2, [parent(inference, "supports", input)], {
    delegation: selected.signed.envelope, decision: { decision_commitment: decisionCommitment, ...decisionFields },
  });

  const parametersBytes = encodeCbor(input.parameters);
  const action: Obj = {
    action_name: input.actionName, target_id: input.targetId, parameters_cbor: parametersBytes, parameters_digest: hash(parametersBytes),
    informational_reversibility: "reversible", operational_reversibility: "reversible",
  };
  const command = input.command as unknown as Obj;
  const refused = input.scenarioId === "S3" || input.refusalReason !== undefined || input.narrative?.decision === "deny";
  const attemptBody: Obj = {
    action, command, authorization_id: authorization.id, decision_commitment: decisionCommitment,
    disposition: refused ? "not_dispatched" : "eligible_for_dispatch",
  };
  if (refused) attemptBody.refusal_reason = input.refusalReason ?? "delegation-expired";
  const attempt = makeReceipt(input, "action_attempt", "ep", 3, [parent(authorization, "authorized_by", input)], attemptBody);
  const receipts: ReceiptBuild[] = [observation, inference, authorization, attempt];

  if (!refused) {
    if (!input.dispatch) throw new Error("authorized scenario requires dispatch result");
    const dispatch = makeReceipt(input, "dispatch", "ep", 4, [parent(attempt, "attempted_as", input)], {
      attempt_id: attempt.id, command_id: input.command.command_id, dispatched_at: input.narrative?.dispatchedAt ?? input.evaluatedAt - 46,
      target_status: input.dispatch.status, target_response_body_digest: input.dispatch.responseBodyDigest, adapter_invocation_id: input.invocationId,
    });
    receipts.push(dispatch);
    const observer: Obj = { ...sourceDevice, failure_domain_id: sourceDevice.failure_domain_id! };
    receipts.push(makeReceipt(input, "outcome_observation", "outcome", 5, [parent(dispatch, "observed_outcome", input)], {
      subject_id: dispatch.id, observer, observed_at: input.narrative?.outcomeObservedAt ?? input.evaluatedAt - 45,
      state: input.dispatch.outcomeState, observation_commitment: input.dispatch.observationDigest,
    }));
  }

  const indexEntries: Obj[] = receipts.map((receipt, leafIndex) => ({
    leaf_index: leafIndex, receipt_id: receipt.id, receipt_kind: receipt.kind, issuer_kid: receipt.issuerKid,
    issuer_seq: receipt.issuerSeq, epoch_seq: receipt.epochSeq, committed_at: receipt.committedAt,
    subject_ids: [input.targetId], correlation_ids: [input.correlationId],
  }));
  const indexLeaves = indexEntries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry));
  const indexRoot = promotedRoot(indexLeaves, "AAR-MANIFEST-INDEX-NODE-v1");
  const anchorTarget: Obj = {
    target_id: id16("anchor-target:local-rfc6962"), operator_id: id16("operator:same-demo-operator"), endpoint: "file://same-operator-demo-log",
    protocol: "rfc6962_v1", anchor_kid: input.keys.anchor.kid, independence_group: id16("independence-group:same-operator"),
  };
  const closedAt = input.narrative?.epochClosedAt ?? input.evaluatedAt - 40;
  const manifestFields: Obj = {
    v: 2, tenant_id: input.tenantId, site_id: input.siteId, epoch_owner_kid: input.keys.ep.kid, epoch_id: input.epochId,
    opened_at: input.narrative?.epochOpenedAt ?? input.evaluatedAt - 60, closed_at: closedAt, sequence_span: { first: 0, last: receipts.length - 1 }, item_count: receipts.length,
    close_reason: "administrative", max_duration_s: 86400, late_arrival_policy: "next_epoch_only", anchor_deadline: closedAt + 86400, fork_policy: "reject_and_surface",
    receipt_index: { ordering: "committed_at_epoch_seq_receipt_id", leaf_count: receipts.length, root: indexRoot, entries: indexEntries },
    anchor_plan: {
      max_submission_delay_s: 86400, max_head_age_s: 86400, targets: [anchorTarget],
      independence: { basis: "same_operator_demo_only", groups: [{ independence_group: anchorTarget.independence_group!, operator_id: anchorTarget.operator_id!, failure_domain_id: id16("failure-domain:same-operator-log") }] },
    },
  };
  const manifestId = domainHash("AAR-EPOCH-MANIFEST-ID-v1", manifestFields);
  const manifest = signDemoDetached({ manifest_id: manifestId, ...manifestFields }, CONTENT_TYPES.epochManifest, input.keys.ep);
  // G5-D1-003: live runs supply the real anchor submission time; the offline
  // default keeps corpus determinism (fixed offset inside the epoch window).
  const logHead = await input.anchorLog.append(manifest.payloadBytes, input.anchorObservedAt ?? input.evaluatedAt - 39);

  const rootRecord: Obj = {
    root_id: opaque(`trust-root:${toHex(input.keys["verifier-trust"].kid)}`), root_kid: input.keys["verifier-trust"].kid,
    tenant_id: input.tenantId, allowed_sites: [input.siteId],
    allowed_key_usages: canonicalSort(["credential_issuing", "agent_signing", "ep_signing", "authority_signing", "outcome_signing", "anchor_signing"]),
  };
  const trustFields: Obj = { snapshot_id: opaque(`trust-snapshot:${toHex(input.keys["verifier-trust"].kid)}`), created_at: input.evaluatedAt - 3600, roots: [rootRecord] };
  const trustStore: Obj = { digest: domainHash("AAR-TRUST-STORE-v1", trustFields), ...trustFields };
  const trust: Obj = {
    evaluation_time: input.evaluatedAt, trust_store: trustStore,
    expected_anchor_heads: [{ target_id: anchorTarget.target_id!, observed_at: logHead.appended_at, tree_size: logHead.tree_size, root: Uint8Array.from(Buffer.from(logHead.root, "hex")) }],
    verifier_policy_digest: opaque("verifier-policy:gate5-demo-v0.1"),
  };
  const selector: Obj = {
    tenant_id: input.tenantId, site_id: input.siteId,
    committed_from: input.evaluatedAt - 60, committed_until: input.evaluatedAt + 1,
    receipt_kinds: canonicalSort(["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"]),
    subject_ids: [input.targetId], correlation_ids: [input.correlationId],
  };
  const selectorCommitment = domainHash("AAR-BUNDLE-SELECTOR-v1", selector);
  const rangeEntries = indexEntries.map((entry, index) => ({
    entry,
    inclusion: { leaf_index: index, tree_size: indexEntries.length, siblings: promotedProofWithDomain(indexLeaves, index, "AAR-MANIFEST-INDEX-NODE-v1") },
  }));
  const manifestPayloads: Obj[] = [
    { digest: promptDigest, media_type: "application/cbor", canonical_bytes: promptBytes },
    { digest: retrievalDigest, media_type: "application/cbor", canonical_bytes: retrievalBytes },
    { digest: toolsDigest, media_type: "application/cbor", canonical_bytes: toolsBytes },
  ].sort((left, right) => Buffer.compare(Buffer.from(left.digest as Uint8Array), Buffer.from(right.digest as Uint8Array)));
  const bundle: Obj = {
    v: 2, created_at: input.evaluatedAt, bundle_nonce: id16(`bundle:${toHex(input.invocationId)}`), claimed_profile: "AAR-3",
    selector, selector_commitment: selectorCommitment, coverage: "complete", trust_inputs: trust,
    ranges: [{ manifest_id: manifestId, selector_commitment: selectorCommitment, first_leaf_index: 0, entries: rangeEntries }],
    artifacts: {
      receipts: sortById(receipts, (item) => item.id).map((item) => item.signed.envelope), requests: [request.envelope],
      delegations: sortById(delegations, (item) => item.payload.delegation_id as Uint8Array).map((item) => item.signed.envelope),
      credentials: credentials.envelopes.map((item) => item.envelope), status_snapshots: [], rotations: [], epoch_events: [],
      epoch_manifests: [manifest.envelope], anchors: [], merkle_batches: [], merkle_proofs: [], manifest_payloads: manifestPayloads,
    },
  };
  return {
    bundle: encodeCbor(bundle), trustPolicy: trustPolicyJson(trust), receipts, request,
    selectedDelegation: selected.payload, allDelegations: delegations.map((item) => item.payload), manifest,
  };
}
