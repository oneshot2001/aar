import { CborValue, encodeCbor, equalBytes, toHex } from "./cbor";
import { deterministicId, domainHash, hash, id16, SignedEnvelope, signDetached } from "./crypto";
import {
  promotedProofWithDomain,
  promotedRoot,
  rfc6962InclusionProof,
  rfc6962Leaf,
  rfc6962PowerOfTwoConsistencyProof,
  rfc6962RootFromDigests,
  verifyPowerOfTwoConsistency,
  verifyPromotedProof,
  verifyRfc6962Inclusion,
} from "./merkle";
import { TEST_KEYS, TestKeyName } from "./testkeys";

type Obj = Record<string, CborValue>;

const TENANT = id16("tenant:acme-security");
const SITE = id16("site:denver-lab");
const TARGET = id16("device:camera-17");
const FAILURE_DOMAIN = id16("failure-domain:camera-17");
const EPOCH_ID = 42;
const BASE_TIME = 1_735_689_600;
const INVOCATION = id16("invocation:incident-2025-01-01");
const REPLAY_DOMAIN = deterministicId("replay-domain:camera-control");
const CORRELATION = id16("correlation:camera-control");

const CONTENT_TYPES = {
  receipt: "application/aar-receipt+cbor;v=0.2",
  request: "application/aar-request+cbor;v=0.2",
  delegation: "application/aar-delegation+cbor;v=0.2",
  credential: "application/aar-credential+cbor;v=0.2",
  status: "application/aar-status+cbor;v=0.2",
  rotation: "application/aar-rotation+cbor;v=0.2",
  presentation: "application/aar-presentation+cbor;v=0.2",
  epochEvent: "application/aar-epoch-event+cbor;v=0.2",
  epochManifest: "application/aar-epoch-manifest+cbor;v=0.2",
  anchor: "application/aar-anchor-record+cbor;v=0.2",
  merkleBatch: "application/aar-merkle-batch+cbor;v=0.2",
} as const;

export interface KatDescriptor {
  name: string;
  object_type: string;
  content_type: string | null;
  key_ids_used: Record<string, string>;
  computed_ids: Record<string, string>;
}

export interface Kat {
  filename: string;
  bytes: Uint8Array;
  descriptor: KatDescriptor;
}

export interface DerivedCheck {
  name: string;
  expected: Uint8Array;
  recompute: () => Uint8Array;
}

export interface SignatureCheck {
  name: string;
  envelopeBytes: Uint8Array;
  signer: TestKeyName;
}

export interface FixtureSet {
  kats: Kat[];
  signatures: SignatureCheck[];
  derived: DerivedCheck[];
  proofs: { name: string; verify: () => boolean }[];
}

interface CredentialFixture {
  id: Uint8Array;
  key: TestKeyName;
  profile: "AAR-1" | "AAR-2" | "AAR-2A" | "AAR-3";
  envelope: SignedEnvelope;
}

interface ReceiptFixture {
  id: Uint8Array;
  kind: string;
  fields: Obj;
  envelope: SignedEnvelope;
  issuerSeq: number;
  epochSeq: number;
  committedAt: number;
  subjectIds: Uint8Array[];
}

function keyIds(...names: TestKeyName[]): Record<string, string> {
  return Object.fromEntries(names.map((name) => [name, toHex(TEST_KEYS[name].kid)]));
}

function computedIds(values: Record<string, Uint8Array>): Record<string, string> {
  return Object.fromEntries(Object.entries(values).map(([name, value]) => [name, toHex(value)]));
}

function kat(
  filename: string,
  objectType: string,
  bytes: Uint8Array,
  contentType: string | null,
  keys: TestKeyName[],
  ids: Record<string, Uint8Array>,
): Kat {
  return {
    filename,
    bytes,
    descriptor: { name: filename, object_type: objectType, content_type: contentType, key_ids_used: keyIds(...keys), computed_ids: computedIds(ids) },
  };
}

function addSignedKat(
  state: FixtureSet,
  filename: string,
  objectType: string,
  signed: SignedEnvelope,
  ids: Record<string, Uint8Array>,
  extraKeys: TestKeyName[] = [],
): void {
  state.kats.push(kat(filename, objectType, signed.envelopeBytes, signed.contentType, [signed.signer, ...extraKeys], ids));
  state.signatures.push({ name: filename, envelopeBytes: signed.envelopeBytes, signer: signed.signer });
}

function legal(): Obj {
  return {
    purpose_id: "incident-response",
    jurisdiction_id: "US-CO",
    data_classification_id: "security-sensitive",
    retention_class_id: "ir-7y",
    legal_hold: false,
  };
}

function freshness(parentIds: Uint8Array[], use = "reusable", nonceLabel = "generic"): Obj {
  return {
    issued_at: BASE_TIME,
    expires_at: BASE_TIME + 3600,
    nonce: id16(`nonce:${nonceLabel}:${parentIds.map(toHex).join(":") || "root"}`),
    replay_domain: REPLAY_DOMAIN,
    invocation_id: INVOCATION,
    use,
    intended_parents: parentIds,
  };
}

function evidence(kind: string, sequence: number): Obj {
  const value: Obj = {
    time: {
      class: "asserted",
      wall_time: BASE_TIME + sequence,
      monotonic_ns: 1_000_000 + sequence,
      boot_id: id16("boot:ep-2025-01-01"),
    },
  };
  if (kind === "inference") value.provenance = { class: "self_asserted" };
  if (kind === "action_attempt") value.outcome = { level: "accepted", artifacts: [deterministicId("artifact:accepted")] };
  if (kind === "dispatch") value.outcome = { level: "dispatched", artifacts: [deterministicId("artifact:dispatch")] };
  if (kind === "outcome_observation") value.outcome = { level: "device_acknowledged", artifacts: [deterministicId("artifact:device-ack")] };
  return value;
}

function parent(receipt: ReceiptFixture, edgeType: string): Obj {
  return {
    edge_type: edgeType,
    parent_id: receipt.id,
    parent_kind: receipt.kind,
    parent_tenant_id: TENANT,
    parent_site_id: SITE,
    parent_epoch_id: EPOCH_ID,
  };
}

function profileLimits(profile: CredentialFixture["profile"]): Obj {
  const high = profile === "AAR-1" || profile === "AAR-2";
  return {
    profile,
    status_max_age_s: high ? 86400 : 300,
    lease_max_s: high ? 86400 : 3600,
    anchor_max_cadence_s: 86400,
  };
}

const CREDENTIAL_SPECS: readonly [TestKeyName, string, string, CredentialFixture["profile"]][] = [
  ["credential_issuing", "authority_source", "authority_source", "AAR-2A"],
  ["agent_signing", "model_endpoint", "agent", "AAR-2A"],
  ["agent_signing_successor", "model_endpoint", "agent", "AAR-2"],
  ["ep_signing", "service", "enforcement_point", "AAR-2A"],
  ["authority_signing", "service", "authority_source", "AAR-2A"],
  ["approver_signing", "human", "approver", "AAR-2A"],
  ["outcome_signing", "service", "outcome_observer", "AAR-3"],
  ["anchor_signing", "service", "anchor_service", "AAR-3"],
  ["verifier_signing", "service", "verifier", "AAR-1"],
  ["status_signing", "service", "authority_source", "AAR-2A"],
];

function buildCredentials(state: FixtureSet): Map<TestKeyName, CredentialFixture> {
  const rootId = deterministicId("credential:credential_issuing");
  const result = new Map<TestKeyName, CredentialFixture>();
  for (const [key, principalType, role, profile] of CREDENTIAL_SPECS) {
    const id = deterministicId(`credential:${key}`);
    const isRoot = key === "credential_issuing";
    const payload: Obj = {
      v: 2,
      credential_id: id,
      subject_kid: TEST_KEYS[key].kid,
      issuer_kid: TEST_KEYS.credential_issuing.kid,
      principal_type: principalType,
      principal_role: role,
      tenant_id: TENANT,
      site_id: SITE,
      valid_from: BASE_TIME - 86400,
      valid_until: BASE_TIME + 86400 * 30,
      cose_alg: -7,
      curve: "P-256",
      key_usage: key === "agent_signing_successor" ? "agent_signing" : key,
      trust_anchor_id: deterministicId("trust-anchor:credential-root"),
      path: isRoot ? [rootId] : [id, rootId],
      profile_limits: profileLimits(profile),
    };
    const envelope = signDetached(payload, CONTENT_TYPES.credential, "credential_issuing");
    const fixture = { id, key, profile, envelope };
    result.set(key, fixture);
    addSignedKat(state, `credential-${key.replaceAll("_", "-")}-${profile.toLowerCase()}`, "credential-envelope", envelope, { credential_id: id }, [key]);
  }
  return result;
}

function receiptProtected(fields: Obj, signer: TestKeyName): Map<number, CborValue> {
  const binding = fields.binding as Obj;
  const emission = fields.emission as Obj;
  return new Map<number, CborValue>([
    [1, -7],
    [3, CONTENT_TYPES.receipt],
    [4, TEST_KEYS[signer].kid],
    [-70000, fields.issuer_principal_type!],
    [-70001, binding.tenant_id!],
    [-70002, binding.site_id!],
    [-70003, binding.epoch_id!],
    [-70004, binding.epoch_seq!],
    [-70005, emission.issuer_seq!],
    [-70006, fields.issuer_role!],
  ]);
}

function makeReceipt(
  state: FixtureSet,
  name: string,
  kind: string,
  signer: TestKeyName,
  principalType: string,
  role: string,
  epochSeq: number,
  parents: Obj[],
  body: Obj,
  root: Obj | undefined,
  subjectIds: Uint8Array[],
  extraKeys: TestKeyName[] = [],
): ReceiptFixture {
  const parentIds = parents.map((edge) => edge.parent_id as Uint8Array);
  const fields: Obj = {
    v: 2,
    kind,
    issuer_principal_type: principalType,
    issuer_role: role,
    binding: {
      tenant_id: TENANT,
      site_id: SITE,
      epoch_owner_kid: TEST_KEYS.ep_signing.kid,
      epoch_id: EPOCH_ID,
      epoch_seq: epochSeq,
    },
    emission: { issuer_seq: epochSeq + 100, committed_at: BASE_TIME + 100 + epochSeq },
    freshness: freshness(parentIds, "reusable", `receipt:${epochSeq}`),
    legal: legal(),
    evidence: evidence(kind, epochSeq),
    parents,
    correlation: {
      correlation_id: CORRELATION,
      phase: "accounted",
      target_ep_kid: TEST_KEYS.ep_signing.kid,
      transport_id: "aar-kat-journal",
      peer_binding_digest: deterministicId("peer-binding:kat-journal"),
    },
    body,
  };
  if (root !== undefined) fields.root = root;
  const exactProtected = encodeCbor(receiptProtected(fields, signer));
  const id = domainHash("AAR-RECEIPT-ID-v1", exactProtected, fields);
  const payload: Obj = { receipt_id: id, ...fields };
  const binding = fields.binding as Obj;
  const emission = fields.emission as Obj;
  const signed = signDetached(payload, CONTENT_TYPES.receipt, signer, [
    [-70000, fields.issuer_principal_type!],
    [-70001, binding.tenant_id!],
    [-70002, binding.site_id!],
    [-70003, binding.epoch_id!],
    [-70004, binding.epoch_seq!],
    [-70005, emission.issuer_seq!],
    [-70006, fields.issuer_role!],
  ]);
  if (!equalBytes(signed.protectedBytes, exactProtected)) throw new Error("receipt protected preimage drift");
  const receipt: ReceiptFixture = {
    id,
    kind,
    fields,
    envelope: signed,
    issuerSeq: epochSeq + 100,
    epochSeq,
    committedAt: BASE_TIME + 100 + epochSeq,
    subjectIds,
  };
  addSignedKat(state, name, "receipt-envelope", signed, { receipt_id: id }, extraKeys);
  state.derived.push({ name: `${name}:receipt_id`, expected: id, recompute: () => domainHash("AAR-RECEIPT-ID-v1", signed.protectedBytes, fields) });
  return receipt;
}

function canonicalSort(values: CborValue[]): CborValue[] {
  return [...values].sort((left, right) => {
    const a = encodeCbor(left);
    const b = encodeCbor(right);
    if (a.length !== b.length) return a.length - b.length;
    for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return a[i]! - b[i]!;
    return 0;
  });
}

export function buildFixtures(): FixtureSet {
  const state: FixtureSet = { kats: [], signatures: [], derived: [], proofs: [] };
  const credentials = buildCredentials(state);

  const statusId = deterministicId("status:ep-good:1");
  const statusPayload: Obj = {
    v: 2,
    snapshot_id: statusId,
    credential_id: credentials.get("ep_signing")!.id,
    issuer_kid: TEST_KEYS.status_signing.kid,
    produced_at: BASE_TIME - 30,
    next_update: BASE_TIME + 270,
    lease_not_before: BASE_TIME - 30,
    lease_not_after: BASE_TIME + 3570,
    profile: "AAR-2A",
    status: "good",
    sequence: 1,
    tenant_id: TENANT,
    site_id: SITE,
  };
  const status = signDetached(statusPayload, CONTENT_TYPES.status, "status_signing");
  addSignedKat(state, "status-snapshot-good", "status-snapshot-envelope", status, { snapshot_id: statusId });

  const rotationId = deterministicId("rotation:agent:1");
  const rotationPayload: Obj = {
    v: 2,
    rotation_id: rotationId,
    predecessor_credential_id: credentials.get("agent_signing")!.id,
    successor_credential_id: credentials.get("agent_signing_successor")!.id,
    predecessor_kid: TEST_KEYS.agent_signing.kid,
    successor_kid: TEST_KEYS.agent_signing_successor.kid,
    effective_at: BASE_TIME + 7200,
    tenant_id: TENANT,
    site_id: SITE,
    continuity_sequence: 1,
  };
  const rotation = signDetached(rotationPayload, CONTENT_TYPES.rotation, "credential_issuing");
  addSignedKat(state, "rotation-agent-successor", "rotation-continuity-envelope", rotation, { rotation_id: rotationId }, ["agent_signing", "agent_signing_successor"]);

  const requestId = id16("request:camera-17-view");
  const requestClaims: Obj = {
    v: 2,
    request_id: requestId,
    action_intent_digest: deterministicId("action-intent:camera.stream.view:camera-17"),
    target_ep_kid: TEST_KEYS.ep_signing.kid,
    tenant_id: TENANT,
    site_id: SITE,
    correlation: {
      correlation_id: CORRELATION,
      phase: "request",
      target_ep_kid: TEST_KEYS.ep_signing.kid,
      transport_id: "mqtt:aar/request/17",
      peer_binding_digest: deterministicId("peer-binding:agent-to-ep"),
    },
    freshness: freshness([], "one_time", "agent-request"),
    legal: legal(),
  };
  const request = signDetached(requestClaims, CONTENT_TYPES.request, "agent_signing");
  const requestCommitment = hash(request.payloadBytes);
  addSignedKat(state, "request-envelope-agent", "request-envelope", request, { request_id: requestId, request_commitment: requestCommitment });
  state.derived.push({ name: "request:request_commitment", expected: requestCommitment, recompute: () => hash(request.payloadBytes) });

  const delegationId = deterministicId("delegation:camera-17-view");
  const delegationClaims: Obj = {
    v: 2,
    delegation_id: delegationId,
    issuer_credential_id: credentials.get("authority_signing")!.id,
    subject_credential_id: credentials.get("ep_signing")!.id,
    tenant_id: TENANT,
    site_id: SITE,
    scope: {
      actions: ["camera.stream.view"],
      targets: [TARGET],
      purpose_ids: ["incident-response"],
      allowed_profiles: ["AAR-2A"],
    },
    not_before: BASE_TIME - 60,
    not_after: BASE_TIME + 3600,
    use: "reusable",
    replay_domain: REPLAY_DOMAIN,
    invocation_id: INVOCATION,
    parent_delegations: [],
  };
  const delegation = signDetached(delegationClaims, CONTENT_TYPES.delegation, "authority_signing");
  addSignedKat(state, "delegation-camera-view", "delegation-envelope", delegation, { delegation_id: delegationId }, ["ep_signing"]);

  const presentedArtifact: Obj = {
    ordinal: 0,
    media_type: "image/jpeg",
    content_digest: deterministicId("presented-artifact:frame-17"),
    byte_length: 18342,
  };
  const presentationFields: Obj = {
    presenter_credential_id: credentials.get("approver_signing")!.id,
    signer_mode: "approver_originated",
    artifacts: [presentedArtifact],
    transforms: [],
    ui_implementation: "aar-review-console",
    ui_version: "0.2.0-kat",
    delivered_at: BASE_TIME + 20,
    session_id: id16("session:approver:1"),
    approval_scope_digest: deterministicId("approval-scope:camera-17-view"),
    state: "human_approved",
  };
  const presentationId = domainHash("AAR-PRESENTATION-MANIFEST-v1", presentationFields);
  const presentationPayload: Obj = { presentation_id: presentationId, ...presentationFields };
  const presentation = signDetached(presentationPayload, CONTENT_TYPES.presentation, "approver_signing");
  state.signatures.push({ name: "nested-presentation", envelopeBytes: presentation.envelopeBytes, signer: "approver_signing" });
  state.derived.push({ name: "presentation:presentation_id", expected: presentationId, recompute: () => domainHash("AAR-PRESENTATION-MANIFEST-v1", presentationFields) });

  const consumptionFields: Obj = {
    items: [{
      ordinal: 0,
      item_id: id16("media-item:frame-17"),
      media_type: "image/jpeg",
      content_commitment: deterministicId("media:frame-17"),
      transformations: [],
      disposition: "used",
    }],
  };
  const consumptionDigest = domainHash("AAR-CONSUMPTION-MANIFEST-v1", consumptionFields);
  const consumption: Obj = { manifest_digest: consumptionDigest, ...consumptionFields };
  state.derived.push({ name: "consumption:manifest_digest", expected: consumptionDigest, recompute: () => domainHash("AAR-CONSUMPTION-MANIFEST-v1", consumptionFields) });

  const canonicalPrompt = encodeCbor({ system: "Detect safety incidents", version: 1 });
  const canonicalRetrieval = encodeCbor({ documents: [] });
  const canonicalTools = encodeCbor({ calls: [] });
  const promptDigest = hash(canonicalPrompt);
  const retrievalDigest = hash(canonicalRetrieval);
  const toolsDigest = hash(canonicalTools);
  const conclusionBytes = encodeCbor({ event: "person_down", confidence_bps: 9300 });
  const conclusionDigest = hash(conclusionBytes);
  state.derived.push(
    { name: "inference:prompt_digest", expected: promptDigest, recompute: () => hash(canonicalPrompt) },
    { name: "inference:retrieval_digest", expected: retrievalDigest, recompute: () => hash(canonicalRetrieval) },
    { name: "inference:tools_digest", expected: toolsDigest, recompute: () => hash(canonicalTools) },
    { name: "inference:conclusion_digest", expected: conclusionDigest, recompute: () => hash(conclusionBytes) },
  );

  const device: Obj = {
    device_id: TARGET,
    manufacturer: "Acme Camera Co",
    model: "SecureCam 17",
    firmware: "5.4.2",
    device_credential_id: deterministicId("device-credential:camera-17"),
    failure_domain_id: FAILURE_DOMAIN,
  };
  const agentRoot: Obj = { kind: "agent_request", request_id: requestId, request_commitment: requestCommitment };
  const humanRoot: Obj = { kind: "human_request", request_id: id16("request:human:operator"), request_commitment: deterministicId("human-request:operator") };
  const standingRoot: Obj = { kind: "standing_condition_trigger", request_id: id16("request:standing:policy"), request_commitment: deterministicId("standing-condition:policy") };

  const observationRoot = makeReceipt(state, "receipt-observation-agent-root", "observation", "agent_signing", "model_endpoint", "agent", 0, [], {
    source_device: device,
    consumption,
    observed_at: BASE_TIME + 1,
    native_attestations: [{ format: "other", assertion_digest: deterministicId("attestation:camera-17"), pointer: "urn:aar:kat:attestation:camera-17" }],
  }, agentRoot, [TARGET]);

  const inferenceRoot = makeReceipt(state, "receipt-inference-human-root", "inference", "agent_signing", "model_endpoint", "agent", 1, [], {
    model: { provider: "Acme AI", model: "incident-detector", version: "2.1.0", endpoint_credential_id: credentials.get("agent_signing")!.id },
    consumption_manifest_id: promptDigest,
    prompt_manifest: { digest: promptDigest, media_type: "application/cbor", byte_length: canonicalPrompt.length },
    retrieval_manifest: { digest: retrievalDigest, media_type: "application/cbor", byte_length: canonicalRetrieval.length },
    tool_transcript_manifest: { digest: toolsDigest, media_type: "application/cbor", byte_length: canonicalTools.length },
    conclusion: { schema_id: "aar.claim.person-down.v1", canonical_cbor: conclusionBytes, digest: conclusionDigest },
    uncertainty_bps: 700,
  }, humanRoot, [TARGET]);

  const approvalDecisionFields: Obj = {
    policy_set_root: deterministicId("policy-set:camera-control"),
    effective_policy_epoch: 7,
    evaluated_inputs: [{ name: "operator-clearance", value_digest: deterministicId("clearance:operator") }],
    decision: "permit_with_approval",
    counter_state_digest: deterministicId("counter-state:approval"),
    status_snapshot_ids: [statusId],
    profile: "AAR-2A",
    delegation_id: delegationId,
    approver_credential_id: credentials.get("approver_signing")!.id,
  };
  const approvalDecisionCommitment = domainHash("AAR-DECISION-RECORD-v1", approvalDecisionFields);
  state.derived.push({ name: "decision:approval", expected: approvalDecisionCommitment, recompute: () => domainHash("AAR-DECISION-RECORD-v1", approvalDecisionFields) });
  const authorizationRoot = makeReceipt(state, "receipt-authorization-standing-root", "authorization", "ep_signing", "service", "enforcement_point", 2, [], {
    delegation: delegation.envelope,
    decision: { decision_commitment: approvalDecisionCommitment, ...approvalDecisionFields },
    presentation: presentation.envelope,
  }, standingRoot, [TARGET], ["authority_signing", "approver_signing"]);

  const observationDerived = makeReceipt(state, "receipt-observation-derived", "observation", "agent_signing", "model_endpoint", "agent", 3, [parent(observationRoot, "derived_from")], {
    source_device: device,
    consumption,
    observed_at: BASE_TIME + 4,
  }, undefined, [TARGET]);

  const inferenceRequested = makeReceipt(state, "receipt-inference-requested", "inference", "agent_signing", "model_endpoint", "agent", 4, [parent(observationDerived, "requested_by")], {
    model: { provider: "Acme AI", model: "incident-detector", version: "2.1.0", endpoint_credential_id: credentials.get("agent_signing")!.id },
    consumption_manifest_id: consumptionDigest,
    prompt_manifest: { digest: promptDigest, media_type: "application/cbor", byte_length: canonicalPrompt.length },
    retrieval_manifest: { digest: retrievalDigest, media_type: "application/cbor", byte_length: canonicalRetrieval.length },
    tool_transcript_manifest: { digest: toolsDigest, media_type: "application/cbor", byte_length: canonicalTools.length },
    conclusion: { schema_id: "aar.claim.person-down.v1", canonical_cbor: conclusionBytes, digest: conclusionDigest },
    uncertainty_bps: 700,
  }, undefined, [TARGET]);

  const permitDecisionFields: Obj = {
    policy_set_root: deterministicId("policy-set:camera-control"),
    effective_policy_epoch: 7,
    evaluated_inputs: [{ name: "incident", value_digest: conclusionDigest }],
    decision: "permit",
    counter_state_digest: deterministicId("counter-state:permit"),
    status_snapshot_ids: [statusId],
    profile: "AAR-2A",
    delegation_id: delegationId,
  };
  const permitDecisionCommitment = domainHash("AAR-DECISION-RECORD-v1", permitDecisionFields);
  state.derived.push({ name: "decision:permit", expected: permitDecisionCommitment, recompute: () => domainHash("AAR-DECISION-RECORD-v1", permitDecisionFields) });
  const authorization = makeReceipt(state, "receipt-authorization-supports", "authorization", "ep_signing", "service", "enforcement_point", 5, [parent(inferenceRequested, "supports")], {
    delegation: delegation.envelope,
    decision: { decision_commitment: permitDecisionCommitment, ...permitDecisionFields },
  }, undefined, [TARGET], ["authority_signing"]);

  const parametersBytes = encodeCbor({ preset: 3, dwell_seconds: 30 });
  const parametersDigest = hash(parametersBytes);
  const commandBytes = encodeCbor({ operation: "camera.stream.view", target: TARGET, parameters_digest: parametersDigest });
  const commandDigest = hash(commandBytes);
  const commandFields: Obj = {
    adapter_id: "onvif-adapter",
    adapter_version: "1.4.0",
    target_id: TARGET,
    action_name: "camera.stream.view",
    canonical_command: commandBytes,
    command_digest: commandDigest,
    excluded_fields: [{ name: "authorization", reason: "secret", value_commitment: deterministicId("secret:adapter-auth") }],
    idempotency_key: id16("idempotency:camera-view"),
  };
  const commandId = domainHash("AAR-COMMAND-MANIFEST-v1", commandFields);
  state.derived.push(
    { name: "action:parameters_digest", expected: parametersDigest, recompute: () => hash(parametersBytes) },
    { name: "command:command_digest", expected: commandDigest, recompute: () => hash(commandBytes) },
    { name: "command:command_id", expected: commandId, recompute: () => domainHash("AAR-COMMAND-MANIFEST-v1", commandFields) },
  );
  const refusedAttempt = makeReceipt(state, "receipt-action-attempt-triggered-refusal", "action_attempt", "ep_signing", "service", "enforcement_point", 6, [parent(authorization, "authorized_by"), parent(inferenceRequested, "triggered_by")], {
    action: {
      action_name: "camera.stream.view",
      target_id: TARGET,
      parameters_cbor: parametersBytes,
      parameters_digest: parametersDigest,
      informational_reversibility: "reversible",
      operational_reversibility: "reversible",
    },
    command: { command_id: commandId, ...commandFields },
    authorization_id: authorization.id,
    decision_commitment: permitDecisionCommitment,
    disposition: "not_dispatched",
    refusal_reason: "operator-session-ended-before-dispatch",
  }, undefined, [TARGET]);

  const attempt = makeReceipt(state, "receipt-action-attempt", "action_attempt", "ep_signing", "service", "enforcement_point", 7, [parent(authorization, "authorized_by")], {
    action: {
      action_name: "camera.stream.view",
      target_id: TARGET,
      parameters_cbor: parametersBytes,
      parameters_digest: parametersDigest,
      informational_reversibility: "reversible",
      operational_reversibility: "reversible",
    },
    command: { command_id: commandId, ...commandFields },
    authorization_id: authorization.id,
    decision_commitment: permitDecisionCommitment,
    disposition: "eligible_for_dispatch",
  }, undefined, [TARGET]);

  const dispatch = makeReceipt(state, "receipt-dispatch", "dispatch", "ep_signing", "service", "enforcement_point", 8, [parent(attempt, "attempted_as")], {
    attempt_id: attempt.id,
    command_id: commandId,
    dispatched_at: BASE_TIME + 108,
    target_status: 202,
    target_response_body_digest: deterministicId("response:adapter-accepted"),
    adapter_invocation_id: INVOCATION,
  }, undefined, [TARGET]);

  const outcome = makeReceipt(state, "receipt-outcome-observation", "outcome_observation", "outcome_signing", "service", "outcome_observer", 9, [parent(dispatch, "observed_outcome")], {
    subject_id: dispatch.id,
    observer: device,
    observed_at: BASE_TIME + 109,
    state: "consistent",
    observation_commitment: deterministicId("observation:stream-opened"),
  }, undefined, [TARGET]);

  const receipts = [observationRoot, inferenceRoot, authorizationRoot, observationDerived, inferenceRequested, authorization, refusedAttempt, attempt, dispatch, outcome];
  const indexEntries: Obj[] = receipts
    .map((receipt, leafIndex) => ({
      leaf_index: leafIndex,
      receipt_id: receipt.id,
      receipt_kind: receipt.kind,
      issuer_kid: receipt.envelope.protectedBytes.length > 0 ? TEST_KEYS[receipt.envelope.signer].kid : new Uint8Array(32),
      issuer_seq: receipt.issuerSeq,
      epoch_seq: receipt.epochSeq,
      committed_at: receipt.committedAt,
      subject_ids: canonicalSort(receipt.subjectIds),
      correlation_ids: [CORRELATION],
    }));
  const indexLeaves = indexEntries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry));
  const indexRoot = promotedRoot(indexLeaves, "AAR-MANIFEST-INDEX-NODE-v1");

  const anchorTarget: Obj = {
    target_id: id16("anchor-target:transparency-log"),
    operator_id: id16("operator:independent-log"),
    endpoint: "https://kat-anchor.example.invalid/log",
    protocol: "rfc6962_v1",
    anchor_kid: TEST_KEYS.anchor_signing.kid,
    independence_group: id16("independence-group:log-1"),
  };
  const manifestFields: Obj = {
    v: 2,
    tenant_id: TENANT,
    site_id: SITE,
    epoch_owner_kid: TEST_KEYS.ep_signing.kid,
    epoch_id: EPOCH_ID,
    opened_at: BASE_TIME,
    closed_at: BASE_TIME + 120,
    sequence_span: { first: 0, last: receipts.length - 1 },
    item_count: receipts.length,
    close_reason: "administrative",
    max_duration_s: 86400,
    late_arrival_policy: "next_epoch_only",
    anchor_deadline: BASE_TIME + 120 + 86400,
    fork_policy: "reject_and_surface",
    receipt_index: {
      ordering: "committed_at_epoch_seq_receipt_id",
      leaf_count: receipts.length,
      root: indexRoot,
      entries: indexEntries,
    },
    anchor_plan: {
      max_submission_delay_s: 86400,
      max_head_age_s: 86400,
      targets: [anchorTarget],
      independence: {
        basis: "distinct_operator_and_failure_domain",
        groups: [{
          independence_group: anchorTarget.independence_group!,
          operator_id: anchorTarget.operator_id!,
          failure_domain_id: id16("failure-domain:independent-log"),
        }],
      },
    },
  };
  const manifestId = domainHash("AAR-EPOCH-MANIFEST-ID-v1", manifestFields);
  const manifestPayload: Obj = { manifest_id: manifestId, ...manifestFields };
  const manifest = signDetached(manifestPayload, CONTENT_TYPES.epochManifest, "ep_signing");
  addSignedKat(state, "epoch-manifest-populated", "epoch-manifest-envelope", manifest, { manifest_id: manifestId, index_root: indexRoot });
  state.derived.push(
    { name: "manifest:index_root", expected: indexRoot, recompute: () => promotedRoot(indexEntries.map((entry) => domainHash("AAR-MANIFEST-INDEX-LEAF-v1", entry)), "AAR-MANIFEST-INDEX-NODE-v1") },
    { name: "manifest:manifest_id", expected: manifestId, recompute: () => domainHash("AAR-EPOCH-MANIFEST-ID-v1", manifestFields) },
  );

  const eventBodies: [string, Obj][] = [
    ["open", { state: "open", first_epoch_seq: 0, max_duration_s: 86400, late_arrival_policy: "next_epoch_only" }],
    ["close", { state: "closed", close_reason: "administrative", last_epoch_seq: receipts.length - 1, item_count: receipts.length, manifest_id: manifestId, anchor_deadline: BASE_TIME + 120 + 86400 }],
    ["anchor_submitted", { state: "awaiting_anchor", manifest_id: manifestId, target_ids: [anchorTarget.target_id as Uint8Array], submitted_at: BASE_TIME + 180 }],
    ["fork_declared", { state: "forked", conflicting_event_digests: [deterministicId("fork:a"), deterministicId("fork:b")], handling: "reject_and_surface" }],
  ];
  const epochEvents: SignedEnvelope[] = [];
  let previousPayload: Uint8Array | undefined;
  for (let index = 0; index < eventBodies.length; index += 1) {
    const [event, body] = eventBodies[index]!;
    const eventId = deterministicId(`epoch-event:${event}`);
    const payload: Obj = {
      v: 2,
      event_id: eventId,
      tenant_id: TENANT,
      site_id: SITE,
      epoch_owner_kid: TEST_KEYS.ep_signing.kid,
      epoch_id: EPOCH_ID,
      event_seq: index,
      occurred_at: BASE_TIME + [0, 120, 180, 240][index]!,
      event,
      body,
    };
    if (previousPayload !== undefined) payload.previous_event_digest = hash(previousPayload);
    const signed = signDetached(payload, CONTENT_TYPES.epochEvent, "ep_signing");
    epochEvents.push(signed);
    addSignedKat(state, `epoch-event-${event.replaceAll("_", "-")}`, "epoch-event-envelope", signed, { event_id: eventId, ...(previousPayload === undefined ? {} : { previous_event_digest: hash(previousPayload) }) });
    previousPayload = signed.payloadBytes;
  }

  const manifestDigest = hash(manifest.payloadBytes);
  const anchorLeafObject: Obj = { tenant_id: TENANT, site_id: SITE, epoch_id: EPOCH_ID, manifest_id: manifestId, manifest_digest: manifestDigest };
  const anchorLeafInput = encodeCbor(["AAR-ANCHOR-LEAF-v1", anchorLeafObject]);
  const rfcLeaves = [
    rfc6962Leaf(anchorLeafInput),
    rfc6962Leaf(encodeCbor(["synthetic", 1])),
    rfc6962Leaf(encodeCbor(["synthetic", 2])),
    rfc6962Leaf(encodeCbor(["synthetic", 3])),
  ];
  const anchorRoot = rfc6962RootFromDigests(rfcLeaves);
  const oldRoot = rfc6962RootFromDigests(rfcLeaves.slice(0, 2));
  const inclusionSiblings = rfc6962InclusionProof(rfcLeaves, 0);
  const consistencyPath = rfc6962PowerOfTwoConsistencyProof(rfcLeaves, 2);
  const anchorId = deterministicId("anchor-record:manifest-42");
  const anchorPayload: Obj = {
    v: 2,
    anchor_id: anchorId,
    target: anchorTarget,
    tenant_id: TENANT,
    site_id: SITE,
    epoch_id: EPOCH_ID,
    manifest_id: manifestId,
    manifest_digest: manifestDigest,
    submitted_at: BASE_TIME + 180,
    accepted_at: BASE_TIME + 181,
    anchor_tree_size: 4,
    anchor_leaf_index: 0,
    anchor_root: anchorRoot,
    inclusion: { tree_size: 4, leaf_index: 0, leaf_digest: rfcLeaves[0]!, siblings: inclusionSiblings },
    consistency: { old_tree_size: 2, new_tree_size: 4, old_root: oldRoot, new_root: anchorRoot, path: consistencyPath },
    head: { observed_at: BASE_TIME + 182, tree_size: 4, root: anchorRoot, max_age_s: 86400 },
    claim: "existence_and_order_by_time_only",
  };
  const anchor = signDetached(anchorPayload, CONTENT_TYPES.anchor, "anchor_signing");
  addSignedKat(state, "anchor-record-rfc6962", "anchor-record-envelope", anchor, { anchor_id: anchorId, manifest_id: manifestId, manifest_digest: manifestDigest, anchor_root: anchorRoot });
  state.derived.push(
    { name: "anchor:manifest_digest", expected: manifestDigest, recompute: () => hash(manifest.payloadBytes) },
    { name: "anchor:leaf_digest", expected: rfcLeaves[0]!, recompute: () => rfc6962Leaf(encodeCbor(["AAR-ANCHOR-LEAF-v1", anchorLeafObject])) },
    { name: "anchor:root", expected: anchorRoot, recompute: () => rfc6962RootFromDigests(rfcLeaves) },
  );
  state.proofs.push(
    { name: "anchor:rfc6962-inclusion", verify: () => verifyRfc6962Inclusion(rfcLeaves[0]!, 0, 4, inclusionSiblings, anchorRoot) },
    { name: "anchor:rfc6962-consistency", verify: () => verifyPowerOfTwoConsistency(oldRoot, anchorRoot, consistencyPath) },
  );

  const batchId = deterministicId("merkle-batch:epoch-42:1");
  const merkleLeaves: Obj[] = receipts.slice(0, 3).map((receipt, leafIndex) => ({
    batch_id: batchId,
    tree_size: 3,
    leaf_index: leafIndex,
    tenant_id: TENANT,
    site_id: SITE,
    epoch_id: EPOCH_ID,
    item_digest: receipt.id,
  }));
  const merkleLeafHashes = merkleLeaves.map((leaf) => domainHash("AAR-MERKLE-LEAF-v1", leaf));
  const batchRoot = promotedRoot(merkleLeafHashes, "AAR-MERKLE-NODE-v1");
  const batchPayload: Obj = {
    v: 2,
    batch_id: batchId,
    tenant_id: TENANT,
    site_id: SITE,
    epoch_owner_kid: TEST_KEYS.ep_signing.kid,
    epoch_id: EPOCH_ID,
    signer_kid: TEST_KEYS.ep_signing.kid,
    tree_size: 3,
    root: batchRoot,
    created_at: BASE_TIME + 130,
    claim: "membership_only",
  };
  const batch = signDetached(batchPayload, CONTENT_TYPES.merkleBatch, "ep_signing");
  addSignedKat(state, "merkle-batch-membership-only", "merkle-batch-envelope", batch, { batch_id: batchId, root: batchRoot });
  const membershipProof: Obj = {
    batch_id: batchId,
    tree_size: 3,
    leaf_index: 1,
    leaf: merkleLeaves[1]!,
    siblings: promotedProofWithDomain(merkleLeafHashes, 1, "AAR-MERKLE-NODE-v1"),
  };
  state.kats.push(kat("merkle-membership-proof", "merkle-membership-proof", encodeCbor(membershipProof), null, [], { batch_id: batchId, leaf_hash: merkleLeafHashes[1]!, root: batchRoot }));
  state.derived.push({ name: "merkle:batch_root", expected: batchRoot, recompute: () => promotedRoot(merkleLeaves.map((leaf) => domainHash("AAR-MERKLE-LEAF-v1", leaf)), "AAR-MERKLE-NODE-v1") });
  state.proofs.push({
    name: "merkle:membership",
    verify: () => verifyPromotedProof(merkleLeafHashes[1]!, 1, 3, membershipProof.siblings as Uint8Array[], "AAR-MERKLE-NODE-v1", batchRoot),
  });

  const selector: Obj = {
    tenant_id: TENANT,
    site_id: SITE,
    committed_from: BASE_TIME,
    committed_until: BASE_TIME + 3600,
    receipt_kinds: canonicalSort(["observation", "inference", "authorization", "action_attempt", "dispatch", "outcome_observation"]),
    subject_ids: [TARGET],
    correlation_ids: [CORRELATION],
  };
  const selectorCommitment = domainHash("AAR-BUNDLE-SELECTOR-v1", selector);
  const trustRoot: Obj = {
    root_id: deterministicId("trust-root:credential-issuing"),
    root_kid: TEST_KEYS.credential_issuing.kid,
    tenant_id: TENANT,
    allowed_sites: [SITE],
    allowed_key_usages: canonicalSort(["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "credential_issuing", "status_signing"]),
  };
  const trustFields: Obj = { snapshot_id: deterministicId("trust-store-snapshot:1"), created_at: BASE_TIME - 3600, roots: [trustRoot] };
  const trustDigest = domainHash("AAR-TRUST-STORE-v1", trustFields);
  const sortById = <T>(values: readonly T[], idOf: (value: T) => Uint8Array): T[] => [...values].sort((a, b) => toHex(idOf(a)).localeCompare(toHex(idOf(b))));
  const sortedReceipts = sortById(receipts, (receipt) => receipt.id).map((receipt) => receipt.envelope.envelope);
  const credentialValues = [...credentials.values()];
  const sortedCredentials = sortById(credentialValues, (credential) => credential.id).map((credential) => credential.envelope.envelope);
  const manifestPayloadObjects: Obj[] = [
    { digest: promptDigest, media_type: "application/cbor", canonical_bytes: canonicalPrompt },
    { digest: retrievalDigest, media_type: "application/cbor", canonical_bytes: canonicalRetrieval },
    { digest: toolsDigest, media_type: "application/cbor", canonical_bytes: canonicalTools },
  ].sort((a, b) => toHex(a.digest as Uint8Array).localeCompare(toHex(b.digest as Uint8Array)));
  const bundle: Obj = {
    v: 2,
    created_at: BASE_TIME + 200,
    bundle_nonce: id16("bundle:valid-subset:nonce"),
    claimed_profile: "AAR-2A",
    selector,
    selector_commitment: selectorCommitment,
    coverage: "valid_subset",
    trust_inputs: {
      evaluation_time: BASE_TIME + 200,
      trust_store: { digest: trustDigest, ...trustFields },
      expected_anchor_heads: [{ target_id: anchorTarget.target_id!, observed_at: BASE_TIME + 182, tree_size: 4, root: anchorRoot }],
      verifier_policy_digest: deterministicId("verifier-policy:kat"),
    },
    ranges: [],
    artifacts: {
      receipts: sortedReceipts,
      requests: [request.envelope],
      delegations: [delegation.envelope],
      credentials: sortedCredentials,
      status_snapshots: [status.envelope],
      rotations: [rotation.envelope],
      epoch_events: [...epochEvents.slice(0, 3)]
        .sort((a, b) => toHex((a.payload as Obj).event_id as Uint8Array).localeCompare(toHex((b.payload as Obj).event_id as Uint8Array)))
        .map((event) => event.envelope),
      epoch_manifests: [manifest.envelope],
      anchors: [anchor.envelope],
      merkle_batches: [batch.envelope],
      merkle_proofs: [membershipProof],
      manifest_payloads: manifestPayloadObjects,
    },
  };
  const bundleBytes = encodeCbor(bundle);
  const bundleDigest = hash(bundleBytes);
  state.kats.push(kat("bundle-valid-subset", "bundle", bundleBytes, null, ["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "credential_issuing", "status_signing"], {
    bundle_digest: bundleDigest,
    selector_commitment: selectorCommitment,
    trust_store_digest: trustDigest,
    manifest_id: manifestId,
    anchor_id: anchorId,
    batch_id: batchId,
  }));
  state.derived.push(
    { name: "bundle:selector_commitment", expected: selectorCommitment, recompute: () => domainHash("AAR-BUNDLE-SELECTOR-v1", selector) },
    { name: "bundle:trust_store_digest", expected: trustDigest, recompute: () => domainHash("AAR-TRUST-STORE-v1", trustFields) },
    { name: "bundle:bundle_digest", expected: bundleDigest, recompute: () => hash(bundleBytes) },
  );

  state.kats.sort((a, b) => a.filename.localeCompare(b.filename));
  return state;
}
