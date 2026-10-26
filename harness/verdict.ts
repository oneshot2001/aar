import { CborScalar, CborValue, encodeCbor, toHex } from "./cbor";
import { deterministicId, domainHash, hash, signDetachedWithKey } from "./crypto";
import { Configuration, signerKey } from "./relying-party";
import { bytes, compareEncoded, entryMatchesSelector, same } from "./verifier";
import type { B1Failure, B1Success, EvidenceLimits, Obj, Parsed, PriorEmission, ReplayUse, validateInputOrigins, VerifyB1Options } from "./verifier";

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

// D-81 build identity hashes the literal UTF-8 preimage; config identity is unchanged.
const DEFAULT_VERSION = "v0.3.1";
const DEFAULT_BUILD_DIGEST = hash(new TextEncoder().encode("harness-aar-v0.3.1-d86-emission-identity-build-v1"));
const VERDICT_CONTENT_TYPE = "application/aar-verdict+cbor;v=0.3";
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

function priorEmissionsDigest(state: readonly PriorEmission[] | undefined): Uint8Array {
  if (state === undefined) return ZERO_DIGEST;
  const entries = state.map((entry) => ({
    issuer_kid: entry.issuerKid, issuer_seq: entry.issuerSeq,
    epoch_owner_kid: entry.epochOwnerKid, epoch_id: entry.epochId, epoch_seq: entry.epochSeq,
    receipt_id: entry.receiptId, envelope_digest: entry.envelopeDigest,
  }));
  return domainHash("AAR-VERDICT-PRIOR-v1", { entries });
}

// D-83 part 5: the protected kid and signing key are the configured leaf's under a policy, the corpus verifier's otherwise.
function sign(fields: Obj, configuration: Configuration | undefined): { verdict: Obj; envelopeBytes: Uint8Array } {
  const key = signerKey(configuration);
  const protectedBytes = encodeCbor(new Map<CborScalar, CborValue>([[1, -7], [3, VERDICT_CONTENT_TYPE], [4, key.kid]]));
  const verdict: Obj = { verdict_id: domainHash("AAR-VERDICT-ID-v1", protectedBytes, fields), ...fields };
  return { verdict, envelopeBytes: signDetachedWithKey(verdict, VERDICT_CONTENT_TYPE, key).envelopeBytes };
}

function policyDigest(configuration: Configuration | undefined): Uint8Array {
  return configuration?.policyDigest ?? ZERO_DIGEST; // D-83 part 7: zero only without a policy
}

export function emitVerdict(input: Uint8Array, bundle: Obj, parsed: Parsed, options: VerifyB1Options, observations: string[], evidence: EvidenceLimits, inputOrigins: ReturnType<typeof validateInputOrigins>): B1Success {
  const selector = bundle.selector as Obj; const trust = bundle.trust_inputs as Obj; const store = trust.trust_store as Obj;
  const fields: Obj = {
    v: 5,
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
      prior_emissions_digest: priorEmissionsDigest(options.priorEmissions),
      relying_party_policy_digest: policyDigest(options.configuration),
    },
    scope: {
      tenant_id: selector.tenant_id!, site_id: selector.site_id!, committed_from: selector.committed_from!, committed_until: selector.committed_until!,
      receipt_kinds: selector.receipt_kinds!, coverage: bundle.coverage!, ingress_completeness: "not_established",
    },
    limits: {
      requested_profile: bundle.claimed_profile!, evaluated_profile: bundle.claimed_profile!,
      maximum_time_class: evidence.time, maximum_provenance_class: evidence.provenance, maximum_outcome_level: evidence.outcome,
      technical_integrity: "satisfied", source_authenticity: "not_established",
      custody_continuity: "not_established",
      discovery_completeness: bundle.coverage === "complete" ? "producer_declared_only" : "not_established",
      legal_admissibility: "not_established",
      input_origin_ancestry: inputOrigins.limit,
      control_path_completeness: "not_established", // D-84: on every result
    },
    observations,
  };
  const signed = sign(fields, options.configuration);
  const verdict = signed.verdict;
  const carriedIds = new Set(parsed.receipt.map((entry) => toHex(entry.payload.receipt_id as Uint8Array)));
  const selectedIds = new Set(parsed.epoch_manifest
    .filter((entry) => same(entry.payload.tenant_id, selector.tenant_id) && same(entry.payload.site_id, selector.site_id))
    .flatMap((entry) => ((entry.payload.receipt_index as Obj).entries as Obj[]))
    .filter((entry) => bytes(entry.receipt_id, 32) && carriedIds.has(toHex(entry.receipt_id)) && entryMatchesSelector(entry, selector))
    .map((entry) => toHex(entry.receipt_id as Uint8Array)));
  return { ok: true, result: "conformant", completedThrough: 20, observations, verdict, verdictEnvelope: signed.envelopeBytes,
    report: { selector_matching_receipts: selectedIds.size, input_origin_ancestry: { bundle_digest: toHex(fields.bundle_digest as Uint8Array), verdict_id: toHex(verdict.verdict_id as Uint8Array), attempts: inputOrigins.attempts } } };
}

// D-82 part 1: populated by the section 5 table and nothing else. Scope,
// requested profile, and selector commitment come from the bundle once step 3
// succeeded as a whole; the four trust values once step 5 has; replay and prior
// digests always bind the supplied inputs; everything else is the sentinel.
export function emitFailureVerdict(input: Uint8Array, issue: B1Failure, options: VerifyB1Options, bundle?: Obj): B1Failure {
  const selector = bundle?.selector as Obj | undefined;
  const trust = bundle !== undefined && issue.step > 5 ? bundle.trust_inputs as Obj : options.configuredTrustPolicy;
  const store = trust?.trust_store as Obj | undefined;
  const zero16 = new Uint8Array(16); const zero32 = new Uint8Array(32);
  // Failure verdicts bind the caller's time, including time-mismatch failures.
  const evaluationTime = options.evaluationTime;
  const fields: Obj = {
    v: 5, evaluated_at: evaluationTime, result: issue.result, reason: issue.reason,
    bundle_digest: hash(input), selector_commitment: bundle?.selector_commitment ?? zero32,
    verifier: {
      product: options.product ?? "aar-reference-verifier", version: options.version ?? DEFAULT_VERSION,
      build_digest: options.buildDigest ?? DEFAULT_BUILD_DIGEST, config_digest: options.configDigest ?? DEFAULT_CONFIG_DIGEST, limits_digest: limitsDigest(),
    },
    trust_policy: {
      trust_store_snapshot_id: store?.snapshot_id ?? zero32,
      trust_store_digest: store?.digest ?? zero32,
      verifier_policy_digest: trust?.verifier_policy_digest ?? zero32,
      evaluation_time: evaluationTime,
      anchor_heads_digest: trust === undefined ? ZERO_DIGEST : anchorHeadsDigest(trust.expected_anchor_heads!),
      replay_state_digest: replayStateDigest(options.replayState),
      prior_emissions_digest: priorEmissionsDigest(options.priorEmissions),
      relying_party_policy_digest: policyDigest(options.configuration),
    },
    scope: selector === undefined ? {
      tenant_id: zero16, site_id: zero16, committed_from: 0, committed_until: 0, receipt_kinds: ["observation"],
      coverage: "valid_subset", ingress_completeness: "not_established",
    } : {
      tenant_id: selector.tenant_id!, site_id: selector.site_id!, committed_from: selector.committed_from!, committed_until: selector.committed_until!,
      receipt_kinds: selector.receipt_kinds!, coverage: bundle!.coverage!, ingress_completeness: "not_established",
    },
    limits: {
      requested_profile: bundle?.claimed_profile ?? "AAR-1",
      evaluated_profile: "below_AAR-1", maximum_time_class: "not_evaluated", maximum_provenance_class: "not_evaluated", maximum_outcome_level: "not_evaluated",
      technical_integrity: issue.step <= 5 ? "not_evaluated" : "not_satisfied", source_authenticity: "not_established", custody_continuity: "not_established", discovery_completeness: "not_established", legal_admissibility: "not_established", input_origin_ancestry: "not_evaluated",
      control_path_completeness: "not_established",
    },
    observations: [],
  };
  const signed = sign(fields, options.configuration);
  return { ...issue, verdict: signed.verdict, verdictEnvelope: signed.envelopeBytes };
}
