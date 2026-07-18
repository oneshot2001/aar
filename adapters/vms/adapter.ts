import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CommandManifest, DemoAdapter, DispatchContext, DispatchResult, EffectOracle, LogicalTargetName } from "../shared/types";
import type { CborValue } from "../../harness/cbor";
import { decodeCbor, equalBytes, encodeCbor, toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import { DigestTransportError, type DigestResponse } from "../vapix/digest";
import { assertVmsConfig, type PtzPosition, type PtzPositionTolerance, type VmsDependencies, type VmsRuntimeConfig } from "./config";
import { MediatorHttpClient } from "./client";

// VmsAdapter — the D3 VMS-mediated leg. Every device effect goes through the
// vigil-control mediator (VigilCore.VAPIXClient in its own process); this
// adapter never speaks a device protocol and never holds a device secret. The
// action-bearing dispatch POST carries the canonical command CBOR as its body,
// so the witnessed request body hashes to the command digest the EP committed
// to (the online oracle's POST-body binding). F19 PTZ safety —
// baseline-capture, restore-verify, poll-to-tolerance, no-redispatch,
// exclusive-control — is orchestrated here as a sequence of atomic mediated
// commands, mirroring the D2b VAPIX adapter.

type Obj = Record<string, CborValue>;

interface RecoveryRecord {
  readonly version: 1;
  readonly invocation_id: string;
  readonly target_logical_name: "ptz-primary";
  readonly baseline: PtzPosition;
}

interface MediatorEffect {
  readonly op: string;
  readonly http_ok: boolean;
  readonly application_status: string;
  readonly pan?: number;
  readonly tilt?: number;
  readonly zoom?: number;
  readonly content_type?: string;
  readonly payload_bytes?: number;
  readonly media_valid?: boolean;
  readonly profile?: string;
}

interface Outcome {
  readonly state: EffectOracle["state"];
  readonly level: EffectOracle["outcome_level"];
  readonly status: number;
  readonly responseDigest: Uint8Array;
  readonly evidence: Record<string, string | number | boolean>;
  readonly dispatched?: boolean;
}

const EMPTY_DIGEST = hash(new Uint8Array());

function object(value: CborValue | undefined): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array) && !(value instanceof Map);
}

function parseEffect(response: DigestResponse): MediatorEffect | undefined {
  if (response.status !== 200) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf8", { fatal: false }).decode(response.body));
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
  const effect = parsed as Record<string, unknown>;
  if (typeof effect.op !== "string" || typeof effect.http_ok !== "boolean" || typeof effect.application_status !== "string") return undefined;
  return effect as unknown as MediatorEffect;
}

function effectStatus(response: DigestResponse, effect: MediatorEffect | undefined): string {
  if (response.status !== 200) return `mediator_http_${response.status}`;
  if (!effect) return "mediator_effect_unparseable";
  return effect.application_status;
}

function effectPosition(effect: MediatorEffect | undefined): PtzPosition | undefined {
  if (!effect || effect.application_status !== "ok") return undefined;
  const position = { pan: Number(effect.pan), tilt: Number(effect.tilt), zoom: Number(effect.zoom) };
  return Object.values(position).every(Number.isFinite) ? position : undefined;
}

function within(actual: PtzPosition, expected: PtzPosition, tolerance: PtzPositionTolerance): boolean {
  return Math.abs(actual.pan - expected.pan) <= tolerance.pan
    && Math.abs(actual.tilt - expected.tilt) <= tolerance.tilt
    && Math.abs(actual.zoom - expected.zoom) <= tolerance.zoom;
}

function rounded(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function sanitizedNumber(value: number): string | number {
  const valueRounded = rounded(value);
  return Number.isSafeInteger(valueRounded) ? valueRounded : valueRounded.toFixed(3);
}

function recoveryPath(config: VmsRuntimeConfig, invocationId: string): string {
  if (!/^[0-9a-f]{32}$/.test(invocationId)) throw new Error("invocation ID must be 16-byte lowercase hex");
  return join(config.recoveryDirectory, `${invocationId}.ptz-recovery.json`);
}

async function persistRecovery(path: string, record: RecoveryRecord): Promise<void> {
  await mkdir(join(path, ".."), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  await rename(temporary, path);
}

async function readRecovery(path: string, invocationId: string): Promise<RecoveryRecord | undefined> {
  try {
    const value = JSON.parse(await readFile(path, "utf8")) as RecoveryRecord;
    if (value.version !== 1 || value.invocation_id !== invocationId || value.target_logical_name !== "ptz-primary") {
      throw new Error("invalid PTZ recovery record");
    }
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function decodeCommand(command: CommandManifest): { operation: string; logicalTarget: LogicalTargetName; parameters: Obj } {
  if (!equalBytes(hash(command.canonical_command), command.command_digest)) throw new Error("command manifest digest mismatch");
  const decoded = decodeCbor(command.canonical_command, { strict: true });
  if (!object(decoded) || typeof decoded.operation !== "string" || typeof decoded.logical_target !== "string" || !object(decoded.parameters)) {
    throw new Error("invalid canonical command manifest");
  }
  if (decoded.operation !== command.action_name) throw new Error("command operation does not match manifest action");
  if (decoded.logical_target !== "ptz-primary" && decoded.logical_target !== "fixed-primary") throw new Error("unknown logical target");
  return { operation: decoded.operation, logicalTarget: decoded.logical_target, parameters: decoded.parameters };
}

export class VmsAdapter implements DemoAdapter {
  readonly id = "vms" as const;
  readonly version = "0.1.0-d3";
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly client: MediatorHttpClient;

  constructor(readonly config: VmsRuntimeConfig, readonly dependencies: VmsDependencies) {
    assertVmsConfig(config);
    this.now = dependencies.now ?? Date.now;
    this.sleep = dependencies.sleep ?? ((milliseconds) => Bun.sleep(milliseconds));
    this.client = new MediatorHttpClient(config.witnessProxyUrl, config.requestTimeoutMs, dependencies.httpTransport);
  }

  async dispatch(command: CommandManifest, context: DispatchContext): Promise<DispatchResult> {
    const decoded = decodeCommand(command);
    if (decoded.operation === "camera.ptz.preset" && decoded.logicalTarget === "ptz-primary") {
      return this.dispatchPreset(command, decoded.parameters, context);
    }
    if (decoded.operation === "camera.stream.view" && decoded.logicalTarget === "fixed-primary") {
      return this.dispatchStream(command, decoded.parameters, context);
    }
    throw new Error("action and logical target do not form a supported VMS command");
  }

  async reconcile(command: CommandManifest, context: DispatchContext): Promise<DispatchResult> {
    const decoded = decodeCommand(command);
    if (decoded.operation !== "camera.ptz.preset" || decoded.logicalTarget !== "ptz-primary") {
      return this.effectResult(command, context, decoded.logicalTarget, {
        state: "unknown", level: "unknown", status: 0, responseDigest: EMPTY_DIGEST,
        evidence: { http_status: 0, application_status: "resume_without_reconciliation", resumed_without_redispatch: true },
      });
    }
    this.assertExclusiveControl();
    const path = recoveryPath(this.config, context.invocationIdHex);
    const recovery = await readRecovery(path, context.invocationIdHex);
    if (!recovery) {
      return this.effectResult(command, context, "ptz-primary", {
        state: "unknown", level: "unknown", status: 0, responseDigest: EMPTY_DIGEST,
        evidence: { http_status: 0, application_status: "recovery_baseline_missing", resumed_without_redispatch: true, restore_verified: false },
      });
    }
    const restored = await this.restoreAndVerify(recovery.baseline, context);
    if (restored.verified) await unlink(path);
    return this.effectResult(command, context, "ptz-primary", {
      state: "unknown", level: "unknown", status: 0, responseDigest: EMPTY_DIGEST,
      evidence: {
        http_status: 0,
        application_status: restored.verified ? "outcome_unknown_restore_verified" : "outcome_unknown_restore_unverified",
        resumed_without_redispatch: true,
        restore_verified: restored.verified,
        reconciliation_redispatch_count: 0,
      },
    });
  }

  // Mediator URL: routing parameters identify the backend device to the
  // mediator; values are sanitized by the witness before logging. The
  // credential parameter is a reference, never a secret.
  private mediatorUrl(path: string, target: LogicalTargetName, parameters: Readonly<Record<string, string>>): URL {
    const routing = this.config.targets[target];
    const url = new URL(path, this.config.mediatorBaseUrl);
    for (const [name, value] of Object.entries(parameters)) url.searchParams.set(name, value);
    url.searchParams.set("host", routing.host);
    url.searchParams.set("port", String(routing.port));
    url.searchParams.set("username", routing.username);
    url.searchParams.set("cred", routing.credentialReference);
    return url;
  }

  private async readPosition(context: DispatchContext, timeoutMs?: number): Promise<{ response: DigestResponse; position?: PtzPosition }> {
    const response = await this.client.request({
      method: "GET",
      url: this.mediatorUrl("/ptz/position", "ptz-primary", {}),
      context: { invocationId: context.invocationIdHex, actionBearing: false },
      timeoutMs,
    });
    return { response, position: effectPosition(parseEffect(response)) };
  }

  private async pollPosition(expected: PtzPosition, context: DispatchContext): Promise<{ matched: boolean; position?: PtzPosition; status: number }> {
    const deadline = this.now() + this.config.settlingDeadlineMs;
    let last: PtzPosition | undefined;
    let status = 0;
    do {
      const remaining = deadline - this.now();
      if (remaining <= 0) break;
      const result = await this.readPosition(context, remaining);
      status = result.response.status;
      last = result.position;
      if (last && within(last, expected, this.config.positionTolerance)) return { matched: true, position: last, status };
      if (this.now() >= deadline) break;
      await this.sleep(Math.min(this.config.pollIntervalMs, Math.max(0, deadline - this.now())));
    } while (this.now() <= deadline);
    return { matched: false, position: last, status };
  }

  private assertExclusiveControl(): void {
    if (this.config.exclusiveControl !== true) {
      throw new Error("PTZ dispatch requires an asserted exclusive-control window");
    }
  }

  private async restoreAndVerify(baseline: PtzPosition, context: DispatchContext): Promise<{ verified: boolean; status: number }> {
    try {
      // F19 restore is action-bearing but intentionally NOT digest-bound: it
      // is safety orchestration, not the committed command.
      const response = await this.client.request({
        method: "POST",
        url: this.mediatorUrl("/dispatch", "ptz-primary", {
          op: "ptz.goto", pan: String(baseline.pan), tilt: String(baseline.tilt), zoom: String(baseline.zoom),
        }),
        context: { invocationId: context.invocationIdHex, actionBearing: true },
      });
      const effect = parseEffect(response);
      if (effectStatus(response, effect) !== "ok") return { verified: false, status: response.status };
      const poll = await this.pollPosition(baseline, context);
      return { verified: poll.matched, status: response.status };
    } catch {
      return { verified: false, status: 0 };
    }
  }

  private async dispatchPreset(command: CommandManifest, parameters: Obj, context: DispatchContext): Promise<DispatchResult> {
    this.assertExclusiveControl();
    if (parameters.preset_name !== "gate5-safe" || Object.keys(parameters).length !== 1) throw new Error("only logical preset gate5-safe is permitted");
    let baselineResult: Awaited<ReturnType<VmsAdapter["readPosition"]>>;
    try {
      baselineResult = await this.readPosition(context);
    } catch {
      return this.effectResult(command, context, "ptz-primary", {
        state: "unknown", level: "unknown", status: 0, responseDigest: EMPTY_DIGEST,
        evidence: { http_status: 0, application_status: "baseline_position_transport_failure", restore_verified: false }, dispatched: false,
      });
    }
    if (!baselineResult.position) {
      return this.effectResult(command, context, "ptz-primary", {
        state: "unknown", level: "unknown", status: baselineResult.response.status, responseDigest: hash(baselineResult.response.body),
        evidence: { http_status: baselineResult.response.status, application_status: "baseline_position_unavailable", restore_verified: false }, dispatched: false,
      });
    }
    const baseline = baselineResult.position;
    const path = recoveryPath(this.config, context.invocationIdHex);
    await persistRecovery(path, { version: 1, invocation_id: context.invocationIdHex, target_logical_name: "ptz-primary", baseline });
    let outcome: Outcome;
    let dispatched = false;
    try {
      const response = await this.client.request({
        method: "POST",
        url: this.mediatorUrl("/dispatch", "ptz-primary", {
          op: "ptz.goto_preset",
          preset: this.config.presetMappings["gate5-safe"],
          digest: context.commandDigestHex,
        }),
        body: command.canonical_command,
        context: { invocationId: context.invocationIdHex, actionBearing: true, commandDigest: context.commandDigestHex },
      });
      dispatched = true;
      await context.afterActionDispatched?.();
      const effect = parseEffect(response);
      const status = effectStatus(response, effect);
      if (status !== "ok") {
        const readback = await this.readPosition(context, this.config.settlingDeadlineMs);
        const contrary = readback.position !== undefined
          && !within(readback.position, this.config.presetPositions["gate5-safe"], this.config.positionTolerance);
        outcome = {
          state: contrary ? "contradicted" : "unknown", level: contrary ? "contradicted" : "unknown",
          status: response.status, responseDigest: hash(response.body),
          evidence: {
            http_status: response.status, application_status: status,
            position_observation: readback.position
              ? contrary ? "outside_tolerance" : "within_tolerance"
              : "unavailable",
          },
        };
      } else {
        const poll = await this.pollPosition(this.config.presetPositions["gate5-safe"], context);
        const position = poll.position;
        outcome = poll.matched && position ? {
          state: "consistent", level: "device_acknowledged", status: response.status, responseDigest: hash(response.body),
          evidence: {
            http_status: response.status, application_status: "position_within_tolerance",
            pan: sanitizedNumber(position.pan), tilt: sanitizedNumber(position.tilt), zoom: sanitizedNumber(position.zoom),
            pan_tolerance: sanitizedNumber(this.config.positionTolerance.pan), tilt_tolerance: sanitizedNumber(this.config.positionTolerance.tilt),
            zoom_tolerance: sanitizedNumber(this.config.positionTolerance.zoom),
          },
        } : {
          state: position ? "contradicted" : "unknown", level: position ? "contradicted" : "unknown",
          status: response.status, responseDigest: hash(response.body),
          evidence: { http_status: poll.status || response.status, application_status: position ? "position_outside_tolerance" : "position_readback_unavailable" },
        };
      }
    } catch (error) {
      const afterSend = error instanceof DigestTransportError && error.afterSend;
      if (error instanceof DigestTransportError && error.actionBearing && error.afterSend) dispatched = true;
      outcome = {
        state: "unknown", level: "unknown", status: 0, responseDigest: EMPTY_DIGEST,
        evidence: { http_status: 0, application_status: afterSend ? "transport_timeout_after_send" : "transport_failure_before_observation" }, dispatched,
      };
    }
    if (!dispatched) {
      await unlink(path);
      outcome.evidence.restore_verified = false;
      outcome.evidence.reconciliation_redispatch_count = 0;
      return this.effectResult(command, context, "ptz-primary", outcome);
    }
    const restored = await this.restoreAndVerify(baseline, context);
    if (restored.verified) await unlink(path);
    outcome.evidence.restore_verified = restored.verified;
    outcome.evidence.reconciliation_redispatch_count = 0;
    if (!restored.verified && outcome.level === "device_acknowledged") {
      outcome = {
        ...outcome,
        state: "unknown",
        level: "unknown",
        evidence: { ...outcome.evidence, application_status: "effect_observed_restore_unverified" },
      };
    }
    return this.effectResult(command, context, "ptz-primary", outcome);
  }

  private async dispatchStream(command: CommandManifest, parameters: Obj, context: DispatchContext): Promise<DispatchResult> {
    if (typeof parameters.stream_profile !== "string" || Object.keys(parameters).length !== 1) throw new Error("stream command requires exactly one stream_profile");
    const mappedProfile = this.config.streamProfileMappings[parameters.stream_profile];
    if (!mappedProfile) throw new Error("stream profile is not mapped by VMS configuration");
    let dispatched = false;
    try {
      const response = await this.client.request({
        method: "POST",
        url: this.mediatorUrl("/dispatch", "fixed-primary", {
          op: "stream.view",
          profile: mappedProfile,
          digest: context.commandDigestHex,
        }),
        body: command.canonical_command,
        context: { invocationId: context.invocationIdHex, actionBearing: true, commandDigest: context.commandDigestHex },
      });
      dispatched = true;
      await context.afterActionDispatched?.();
      const effect = parseEffect(response);
      const status = effectStatus(response, effect);
      const payloadBytes = typeof effect?.payload_bytes === "number" ? effect.payload_bytes : 0;
      const contentType = typeof effect?.content_type === "string" ? effect.content_type : "missing";
      // The mediator's media acknowledgement: it fetched and validated one
      // explicitly requested media unit via the VMS's own media seam.
      const validMedia = status === "media_payload_valid"
        && effect?.media_valid === true
        && contentType === "image/jpeg"
        && payloadBytes >= this.config.streamMinimumPayloadBytes;
      const outcome: Outcome = validMedia ? {
        state: "consistent", level: "device_acknowledged", status: response.status, responseDigest: hash(response.body),
        evidence: {
          http_status: response.status, application_status: "media_payload_valid", profile: parameters.stream_profile,
          content_type: contentType, payload_bytes: payloadBytes, media_unit_valid: true,
        },
      } : {
        state: "contradicted", level: "contradicted", status: response.status, responseDigest: hash(response.body),
        evidence: {
          http_status: response.status, application_status: status === "media_payload_valid" ? "media_payload_undersized" : status,
          profile: parameters.stream_profile, content_type: contentType, payload_bytes: payloadBytes,
          media_unit_valid: false,
        },
      };
      return this.effectResult(command, context, "fixed-primary", outcome);
    } catch (error) {
      const afterSend = error instanceof DigestTransportError && error.afterSend;
      if (error instanceof DigestTransportError && error.actionBearing && error.afterSend) dispatched = true;
      return this.effectResult(command, context, "fixed-primary", {
        state: "unknown", level: "unknown", status: 0, responseDigest: EMPTY_DIGEST,
        evidence: {
          http_status: 0, application_status: afterSend ? "transport_timeout_after_send" : "transport_failure_before_observation",
          profile: parameters.stream_profile, media_unit_valid: false,
        }, dispatched,
      });
    }
  }

  private effectResult(
    command: CommandManifest,
    context: DispatchContext,
    target: LogicalTargetName,
    outcome: Outcome,
  ): DispatchResult {
    const evidence: Record<string, string | number | boolean> = { ...outcome.evidence, vms_mediated: true };
    const oracleData = encodeCbor({
      adapter_id: this.id,
      invocation_id: context.invocationIdHex,
      command_digest: context.commandDigestHex,
      target_logical_name: target,
      observed_at: context.observedAt,
      state: outcome.state,
      outcome_level: outcome.level,
      backend_evidence: evidence,
    });
    return {
      dispatched: outcome.dispatched ?? true,
      status: outcome.status,
      responseBodyDigest: outcome.responseDigest,
      effect: {
        adapter_id: this.id,
        invocation_id: context.invocationIdHex,
        command_digest: context.commandDigestHex || toHex(command.command_digest),
        target_logical_name: target,
        observed_at: context.observedAt,
        state: outcome.state,
        outcome_level: outcome.level,
        observation_digest: toHex(hash(oracleData)),
        backend_evidence: evidence,
      },
    };
  }
}
