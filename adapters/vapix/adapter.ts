import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CommandManifest, DemoAdapter, DispatchContext, DispatchResult, EffectOracle, LogicalTargetName } from "../shared/types";
import type { CborValue } from "../../harness/cbor";
import { decodeCbor, encodeCbor, equalBytes, toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import { assertVapixConfig, type VapixDependencies, type VapixPosition, type VapixPositionTolerance, type VapixRuntimeConfig } from "./config";
import { DigestHttpClient, DigestTransportError, type DigestResponse } from "./digest";

type Obj = Record<string, CborValue>;

interface RecoveryRecord {
  readonly version: 1;
  readonly invocation_id: string;
  readonly target_logical_name: "ptz-primary";
  readonly baseline: VapixPosition;
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

function responseText(response: DigestResponse): string {
  return new TextDecoder("utf8", { fatal: false }).decode(response.body);
}

function applicationStatus(response: DigestResponse): string {
  if (response.status < 200 || response.status >= 300) return `http_rejected_${response.status}`;
  const text = responseText(response).trim();
  if (/^(?:error\s*[:=]|error\b|failed\b)/i.test(text) || /(?:^|\n)error\s*=/i.test(text)) return "vapix_application_error";
  return "ok";
}

function parsePosition(response: DigestResponse): VapixPosition | undefined {
  if (applicationStatus(response) !== "ok") return undefined;
  const values = Object.fromEntries(responseText(response).split(/\r?\n/).filter(Boolean).map((line) => {
    const at = line.indexOf("=");
    return at < 1 ? [line.trim().toLowerCase(), ""] : [line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim()];
  }));
  const position = { pan: Number(values.pan), tilt: Number(values.tilt), zoom: Number(values.zoom) };
  return Object.values(position).every(Number.isFinite) ? position : undefined;
}

function within(actual: VapixPosition, expected: VapixPosition, tolerance: VapixPositionTolerance): boolean {
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

function recoveryPath(config: VapixRuntimeConfig, invocationId: string): string {
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

export class VapixAdapter implements DemoAdapter {
  readonly id = "vapix" as const;
  readonly version = "0.1.0-d2a";
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly clients = new Map<LogicalTargetName, DigestHttpClient>();

  constructor(readonly config: VapixRuntimeConfig, readonly dependencies: VapixDependencies) {
    assertVapixConfig(config);
    this.now = dependencies.now ?? Date.now;
    this.sleep = dependencies.sleep ?? ((milliseconds) => Bun.sleep(milliseconds));
  }

  async dispatch(command: CommandManifest, context: DispatchContext): Promise<DispatchResult> {
    const decoded = decodeCommand(command);
    if (decoded.operation === "camera.ptz.preset" && decoded.logicalTarget === "ptz-primary") {
      return this.dispatchPreset(command, decoded.parameters, context);
    }
    if (decoded.operation === "camera.stream.view" && decoded.logicalTarget === "fixed-primary") {
      return this.dispatchStream(command, decoded.parameters, context);
    }
    throw new Error("action and logical target do not form a supported VAPIX command");
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

  private client(target: LogicalTargetName): DigestHttpClient {
    let client = this.clients.get(target);
    if (!client) {
      const config = this.config.targets[target];
      client = new DigestHttpClient(
        this.config.witnessProxyUrl, config.username, config.credentialReference,
        this.dependencies.credentials, this.config.requestTimeoutMs, this.dependencies.httpTransport,
      );
      this.clients.set(target, client);
    }
    return client;
  }

  private url(target: LogicalTargetName, path: string, parameters: Readonly<Record<string, string>>): URL {
    const url = new URL(path, this.config.targets[target].baseUrl);
    for (const [name, value] of Object.entries(parameters)) url.searchParams.set(name, value);
    return url;
  }

  private async request(
    target: LogicalTargetName,
    url: URL,
    context: DispatchContext,
    actionBearing: boolean,
    bindCommand: boolean,
    timeoutMs?: number,
  ): Promise<DigestResponse> {
    return this.client(target).request({
      method: "GET", url,
      context: {
        invocationId: context.invocationIdHex,
        actionBearing,
        commandDigest: bindCommand ? context.commandDigestHex : undefined,
      },
      timeoutMs,
    });
  }

  private async readPosition(context: DispatchContext, timeoutMs?: number): Promise<{ response: DigestResponse; position?: VapixPosition }> {
    const response = await this.request(
      "ptz-primary",
      this.url("ptz-primary", "/axis-cgi/com/ptz.cgi", { query: "position" }),
      context,
      false,
      false,
      timeoutMs,
    );
    return { response, position: parsePosition(response) };
  }

  private async pollPosition(expected: VapixPosition, context: DispatchContext): Promise<{ matched: boolean; position?: VapixPosition; status: number }> {
    const deadline = this.now() + this.config.settlingDeadlineMs;
    let last: VapixPosition | undefined;
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

  private async restoreAndVerify(baseline: VapixPosition, context: DispatchContext): Promise<{ verified: boolean; status: number }> {
    try {
      const response = await this.request(
        "ptz-primary",
        this.url("ptz-primary", "/axis-cgi/com/ptz.cgi", {
          pan: String(baseline.pan), tilt: String(baseline.tilt), zoom: String(baseline.zoom),
        }),
        context,
        true,
        false,
      );
      if (applicationStatus(response) !== "ok") return { verified: false, status: response.status };
      const poll = await this.pollPosition(baseline, context);
      return { verified: poll.matched, status: response.status };
    } catch {
      return { verified: false, status: 0 };
    }
  }

  private async dispatchPreset(command: CommandManifest, parameters: Obj, context: DispatchContext): Promise<DispatchResult> {
    this.assertExclusiveControl();
    if (parameters.preset_name !== "gate5-safe" || Object.keys(parameters).length !== 1) throw new Error("only logical preset gate5-safe is permitted");
    let baselineResult: Awaited<ReturnType<VapixAdapter["readPosition"]>>;
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
      const response = await this.request(
        "ptz-primary",
        this.url("ptz-primary", "/axis-cgi/com/ptz.cgi", { gotoserverpresetname: this.config.presetMappings["gate5-safe"] }),
        context,
        true,
        true,
      );
      dispatched = true;
      await context.afterActionDispatched?.();
      const status = applicationStatus(response);
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
    if (!mappedProfile) throw new Error("stream profile is not mapped by VAPIX configuration");
    let dispatched = false;
    try {
      const response = await this.request(
        "fixed-primary",
        this.url("fixed-primary", "/axis-cgi/jpg/image.cgi", { streamprofile: mappedProfile }),
        context,
        true,
        true,
      );
      dispatched = true;
      await context.afterActionDispatched?.();
      const status = applicationStatus(response);
      const contentType = String(response.headers["content-type"] ?? "").split(";", 1)[0]!.trim().toLowerCase();
      const validJpeg = contentType === "image/jpeg"
        && response.body.length >= this.config.streamMinimumPayloadBytes
        && response.body[0] === 0xff && response.body[1] === 0xd8
        && response.body.at(-2) === 0xff && response.body.at(-1) === 0xd9;
      const outcome: Outcome = status === "ok" && validJpeg ? {
        state: "consistent", level: "device_acknowledged", status: response.status, responseDigest: hash(response.body),
        evidence: {
          http_status: response.status, application_status: "media_payload_valid", profile: parameters.stream_profile,
          content_type: contentType, payload_bytes: response.body.length, media_unit_valid: true,
        },
      } : {
        state: "contradicted", level: "contradicted", status: response.status, responseDigest: hash(response.body),
        evidence: {
          http_status: response.status, application_status: status === "ok" ? "media_payload_invalid" : status,
          profile: parameters.stream_profile, content_type: contentType || "missing", payload_bytes: response.body.length,
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
    const evidence = { ...outcome.evidence };
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
