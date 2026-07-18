import { mkdir, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { DemoAdapter, DispatchResult, ScenarioId } from "../../adapters/shared/types";
import { fromHex, toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import type { LocalRfc6962Log } from "../anchor/log";
import type { DemoKey, DemoKeyRole } from "../keys/keys";
import { buildCommandManifest } from "./command-manifest";
import { evaluateAuthorization, type DemoTrustPolicy } from "./authorization";
import { DurableInvocationJournal } from "./journal";
import { buildDemoBundle, buildSignedAgentRequest, type DelegationWindow, type WireBuildResult } from "./wire-builder";

export interface ProducerInput {
  readonly scenarioId: ScenarioId;
  readonly evaluatedAt: number;
  readonly epochId: number;
  readonly invocationId: Uint8Array;
  readonly correlationId: Uint8Array;
  readonly tenantId: Uint8Array;
  readonly siteId: Uint8Array;
  readonly targetId: Uint8Array;
  readonly targetLogicalName: "ptz-primary" | "fixed-primary";
  readonly actionName: "camera.ptz.preset" | "camera.stream.view";
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
  readonly sourceDeviceMetadata?: { readonly manufacturer: string; readonly model: string; readonly firmware: string };
  readonly delegationWindows: readonly DelegationWindow[];
  readonly bundlePath: string;
  readonly trustPolicyPath: string;
  readonly witnessLogPath: string;
  readonly journal: DurableInvocationJournal;
  readonly anchorLog: LocalRfc6962Log;
  readonly anchorObservedAt?: number;
  readonly adapter: DemoAdapter;
  readonly keys: Readonly<Record<DemoKeyRole, DemoKey>>;
  readonly afterDispatchCut?: () => Promise<void>;
}

export interface ProducerResult {
  readonly wire: WireBuildResult;
  readonly dispatchCount: number;
  readonly dispatchResult?: DispatchResult;
  readonly resumedWithoutRedispatch: boolean;
}

function validateId(name: string, value: Uint8Array, length: number): void {
  if (value.length !== length) throw new Error(`${name} must be ${length} bytes`);
}

async function atomicWrite(path: string, bytes: Uint8Array | string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, bytes);
  await rename(temporary, path);
}

export async function produce(input: ProducerInput): Promise<ProducerResult> {
  if (!Number.isSafeInteger(input.evaluatedAt) || input.evaluatedAt < 3600) {
    throw new Error("evaluatedAt must be a pinned non-negative safe integer");
  }
  validateId("invocationId", input.invocationId, 16);
  validateId("correlationId", input.correlationId, 16);
  validateId("tenantId", input.tenantId, 16);
  validateId("siteId", input.siteId, 16);
  validateId("targetId", input.targetId, 16);
  const invocationIdHex = toHex(input.invocationId);

  const request = buildSignedAgentRequest(input);
  await input.journal.append({
    invocation_id: invocationIdHex, at: input.evaluatedAt, event: "request_signed",
    data: { request_payload_digest: toHex(hash(request.payloadBytes)), correlation_id: toHex(input.correlationId) },
  });
  const policy: DemoTrustPolicy = {
    version: 1, profile: "AAR-3", purposeId: "incident-response", authorityKid: input.keys.authority.kid,
    allowedActions: ["camera.ptz.preset", "camera.stream.view"], allowedTargets: [input.targetId],
  };
  const authorization = evaluateAuthorization(
    input.scenarioId, input.evaluatedAt, input.actionName, input.targetId,
    input.keys.authority.kid, input.delegationWindows, policy,
  );
  await input.journal.append({
    invocation_id: invocationIdHex, at: input.evaluatedAt, event: "authorization_evaluated",
    data: { authorized: authorization.authorized, not_before: authorization.selected.notBefore, not_after: authorization.selected.notAfter, profile: "AAR-3", policy_root: toHex(authorization.policyRoot) },
  });

  const command = buildCommandManifest({
    actionName: input.actionName, targetId: input.targetId, targetLogicalName: input.targetLogicalName,
    parameters: input.parameters, invocationId: input.invocationId,
  }, input.adapter.id, input.adapter.version);
  let dispatchCount = 0;
  let dispatchResult: DispatchResult | undefined;
  let resumedWithoutRedispatch = false;

  if (!authorization.authorized) {
    await input.journal.append({ invocation_id: invocationIdHex, at: input.evaluatedAt, event: "refusal_persisted", data: { reason: "delegation-expired" } });
  } else if (await input.journal.mustNotRedispatch(invocationIdHex)) {
    resumedWithoutRedispatch = true;
    if (input.adapter.reconcile) {
      dispatchResult = await input.adapter.reconcile(command, {
        invocationIdHex, commandDigestHex: toHex(command.command_digest), witnessLogPath: input.witnessLogPath,
        observedAt: input.evaluatedAt,
      });
    } else {
      const observationDigest = hash(new TextEncoder().encode(`resume-unknown:${invocationIdHex}:${toHex(command.command_digest)}`));
      dispatchResult = {
        dispatched: true, status: 0, responseBodyDigest: hash(new Uint8Array()),
        effect: {
          adapter_id: input.adapter.id, invocation_id: invocationIdHex, command_digest: toHex(command.command_digest),
          target_logical_name: input.targetLogicalName, observed_at: input.evaluatedAt,
          state: "unknown", outcome_level: "unknown", observation_digest: toHex(observationDigest), backend_evidence: { resumed_without_redispatch: true },
        },
      };
    }
  } else {
    await input.journal.append({
      invocation_id: invocationIdHex, at: input.evaluatedAt, event: "dispatch_intent_persisted",
      data: { command_digest: toHex(command.command_digest), adapter_id: input.adapter.id },
    });
    dispatchResult = await input.adapter.dispatch(command, {
      invocationIdHex, commandDigestHex: toHex(command.command_digest), witnessLogPath: input.witnessLogPath,
      observedAt: input.evaluatedAt, afterActionDispatched: input.afterDispatchCut,
    });
    if (dispatchResult.dispatched) {
      dispatchCount = 1;
      await input.journal.append({
        invocation_id: invocationIdHex, at: input.evaluatedAt, event: "dispatch_observed",
        data: { status: dispatchResult.status, outcome_level: dispatchResult.effect.outcome_level, observation_digest: dispatchResult.effect.observation_digest },
      });
    } else {
      await input.journal.append({
        invocation_id: invocationIdHex, at: input.evaluatedAt, event: "pre_transport_refusal_observed",
        data: { reason: String(dispatchResult.effect.backend_evidence.application_status ?? "adapter-refused-before-transport") },
      });
    }
  }

  const wire = await buildDemoBundle({
    scenarioId: input.scenarioId, evaluatedAt: input.evaluatedAt, epochId: input.epochId,
    invocationId: input.invocationId, correlationId: input.correlationId, tenantId: input.tenantId, siteId: input.siteId, targetId: input.targetId,
    targetLogicalName: input.targetLogicalName, actionName: input.actionName, parameters: input.parameters,
    sourceDeviceMetadata: input.sourceDeviceMetadata ?? { manufacturer: "AXIS", model: "Gate5 synthetic", firmware: "D1-stub" },
    adapterId: input.adapter.id, command, delegationWindows: input.delegationWindows, keys: input.keys, anchorLog: input.anchorLog, anchorObservedAt: input.anchorObservedAt,
    dispatch: dispatchResult?.dispatched ? {
      status: dispatchResult.status, responseBodyDigest: dispatchResult.responseBodyDigest,
      outcomeLevel: dispatchResult.effect.outcome_level, outcomeState: dispatchResult.effect.state,
      observationDigest: fromHex(dispatchResult.effect.observation_digest),
    } : undefined,
    refusalReason: dispatchResult && !dispatchResult.dispatched
      ? String(dispatchResult.effect.backend_evidence.application_status ?? "adapter-refused-before-transport")
      : undefined,
  });
  await atomicWrite(input.bundlePath, wire.bundle);
  await atomicWrite(input.trustPolicyPath, `${JSON.stringify(wire.trustPolicy, null, 2)}\n`);
  await input.journal.append({
    invocation_id: invocationIdHex, at: input.evaluatedAt, event: "bundle_emitted",
    data: { bundle_path: input.bundlePath, bundle_digest: toHex(hash(wire.bundle)) },
  });
  return { wire, dispatchCount, dispatchResult, resumedWithoutRedispatch };
}
