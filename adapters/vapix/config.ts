import type { CredentialProvider, LogicalTargetName } from "../shared/types";
import type { HttpTransport } from "./digest";

export const VAPIX_FILL_AT_D2 = {
  ptzBaseUrl: "FILL-AT-D2:ptz-base-url",
  streamBaseUrl: "FILL-AT-D2:stream-base-url",
  credentialReference: "FILL-AT-D2:credential-reference",
  username: "FILL-AT-D2:digest-username",
  safePreset: "FILL-AT-D2:safe-preset",
  safePresetPosition: "FILL-AT-D2:safe-preset-position",
  panTiltTolerance: "FILL-AT-D2:pan-tilt-tolerance",
  zoomTolerance: "FILL-AT-D2:zoom-tolerance",
  pollIntervalMs: "FILL-AT-D2:poll-interval-ms",
  settlingDeadlineMs: "FILL-AT-D2:settling-deadline-ms",
  streamProfile: "FILL-AT-D2:stream-profile",
  streamMinimumPayloadBytes: "FILL-AT-D2:stream-minimum-payload-bytes",
} as const;

export interface VapixTargetConfig {
  readonly baseUrl: string;
  readonly username: string;
  readonly credentialReference: string;
}

export interface VapixPositionTolerance {
  readonly pan: number;
  readonly tilt: number;
  readonly zoom: number;
}

export interface VapixPosition {
  readonly pan: number;
  readonly tilt: number;
  readonly zoom: number;
}

export interface VapixRuntimeConfig {
  readonly targets: Readonly<Record<LogicalTargetName, VapixTargetConfig>>;
  readonly witnessProxyUrl: string;
  readonly presetMappings: Readonly<Record<"gate5-safe", string>>;
  readonly presetPositions: Readonly<Record<"gate5-safe", VapixPosition>>;
  readonly streamProfileMappings: Readonly<Record<string, string>>;
  readonly positionTolerance: VapixPositionTolerance;
  readonly pollIntervalMs: number;
  readonly settlingDeadlineMs: number;
  readonly requestTimeoutMs: number;
  readonly streamMinimumPayloadBytes: number;
  readonly exclusiveControl: boolean;
  readonly recoveryDirectory: string;
}

export interface VapixDependencies {
  readonly credentials: CredentialProvider;
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
  if (typeof value === "string") return value.startsWith("FILL-AT-D2:");
  if (Array.isArray(value)) return value.some(containsPlaceholder);
  return typeof value === "object" && value !== null && Object.values(value).some(containsPlaceholder);
}

export function assertVapixConfig(config: VapixRuntimeConfig): void {
  for (const [name, target] of Object.entries(config.targets)) {
    const url = new URL(target.baseUrl);
    if (url.protocol !== "http:") throw new Error(`${name} base URL must use HTTP through the transport witness`);
    if (!target.username || !target.credentialReference) throw new Error(`${name} digest credential configuration is incomplete`);
  }
  const proxy = new URL(config.witnessProxyUrl);
  if (proxy.protocol !== "http:") throw new Error("witness proxy must use HTTP");
  if (containsPlaceholder(config)) {
    throw new Error("VAPIX FILL-AT-D2 placeholders must be supplied by runtime configuration");
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
