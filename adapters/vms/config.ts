import type { LogicalTargetName } from "../shared/types";
import type { HttpTransport } from "../vapix/digest";

// D3 runtime values that require the owned lab + a running vigil-control.
export const VMS_FILL_AT_D3 = {
  mediatorBaseUrl: "FILL-AT-D3:mediator-base-url",
  ptzHost: "FILL-AT-D3:ptz-host",
  streamHost: "FILL-AT-D3:stream-host",
  credentialReference: "FILL-AT-D3:credential-reference",
  username: "FILL-AT-D3:username",
  safePreset: "FILL-AT-D3:safe-preset",
  safePresetPosition: "FILL-AT-D3:safe-preset-position",
  panTiltTolerance: "FILL-AT-D3:pan-tilt-tolerance",
  zoomTolerance: "FILL-AT-D3:zoom-tolerance",
  pollIntervalMs: "FILL-AT-D3:poll-interval-ms",
  settlingDeadlineMs: "FILL-AT-D3:settling-deadline-ms",
  streamProfile: "FILL-AT-D3:stream-profile",
  streamMinimumPayloadBytes: "FILL-AT-D3:stream-minimum-payload-bytes",
} as const;

export interface PtzPosition {
  readonly pan: number;
  readonly tilt: number;
  readonly zoom: number;
}

export interface PtzPositionTolerance {
  readonly pan: number;
  readonly tilt: number;
  readonly zoom: number;
}

// Per-logical-target routing the mediator needs to reach its backend device.
// The credential value is a REFERENCE resolved inside vigil-control's own
// process; the TS adapter never holds a device secret.
export interface VmsTargetRouting {
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly credentialReference: string;
}

export interface VmsRuntimeConfig {
  readonly witnessProxyUrl: string;
  readonly mediatorBaseUrl: string;
  readonly targets: Readonly<Record<LogicalTargetName, VmsTargetRouting>>;
  readonly presetMappings: Readonly<Record<"gate5-safe", string>>;
  readonly presetPositions: Readonly<Record<"gate5-safe", PtzPosition>>;
  readonly streamProfileMappings: Readonly<Record<string, string>>;
  readonly positionTolerance: PtzPositionTolerance;
  readonly pollIntervalMs: number;
  readonly settlingDeadlineMs: number;
  readonly requestTimeoutMs: number;
  readonly streamMinimumPayloadBytes: number;
  readonly exclusiveControl: boolean;
  readonly recoveryDirectory: string;
}

// No CredentialProvider here by design: the TS process never holds a device
// secret. The mediator resolves the credential reference in its own process.
export interface VmsDependencies {
  readonly httpTransport?: HttpTransport;
  readonly now?: () => number;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

function finiteNonNegative(name: string, value: number): void {
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a finite non-negative number`);
}

function finite(name: string, value: number): void {
  if (!Number.isFinite(value)) throw new Error(`${name} must be finite`);
}

function containsPlaceholder(value: unknown): boolean {
  if (typeof value === "string") return value.startsWith("FILL-AT-D3:");
  if (Array.isArray(value)) return value.some(containsPlaceholder);
  return typeof value === "object" && value !== null && Object.values(value).some(containsPlaceholder);
}

export function assertVmsConfig(config: VmsRuntimeConfig): void {
  const mediator = new URL(config.mediatorBaseUrl);
  if (mediator.protocol !== "http:") throw new Error("mediator base URL must use HTTP through the transport witness");
  const proxy = new URL(config.witnessProxyUrl);
  if (proxy.protocol !== "http:") throw new Error("witness proxy must use HTTP");
  for (const [name, target] of Object.entries(config.targets)) {
    if (!target.host || !target.username || !target.credentialReference) throw new Error(`${name} mediator routing configuration is incomplete`);
    if (!Number.isSafeInteger(target.port) || target.port < 1 || target.port > 65535) throw new Error(`${name} mediator routing port is invalid`);
  }
  if (containsPlaceholder(config)) {
    throw new Error("VMS FILL-AT-D3 placeholders must be supplied by runtime configuration");
  }
  if (!config.presetMappings["gate5-safe"] || !config.presetPositions["gate5-safe"]) throw new Error("gate5-safe preset mapping and position are required");
  if (!Object.keys(config.streamProfileMappings).length) throw new Error("at least one stream profile mapping is required");
  for (const [name, value] of Object.entries(config.presetPositions["gate5-safe"])) finite(`gate5-safe ${name}`, value);
  for (const [name, value] of Object.entries(config.positionTolerance)) finiteNonNegative(`${name} tolerance`, value);
  finiteNonNegative("pollIntervalMs", config.pollIntervalMs);
  finiteNonNegative("settlingDeadlineMs", config.settlingDeadlineMs);
  finiteNonNegative("requestTimeoutMs", config.requestTimeoutMs);
  if (config.pollIntervalMs === 0 || config.settlingDeadlineMs === 0 || config.requestTimeoutMs === 0) {
    throw new Error("poll interval and settling/request deadlines must be greater than zero");
  }
  if (!Number.isSafeInteger(config.streamMinimumPayloadBytes) || config.streamMinimumPayloadBytes < 4) {
    throw new Error("streamMinimumPayloadBytes must be an integer of at least 4");
  }
}
