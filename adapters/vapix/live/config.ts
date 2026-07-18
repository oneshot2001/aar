import { homedir } from "node:os";
import { join } from "node:path";
import type { VapixPosition, VapixRuntimeConfig } from "../config";

// Locked FILL-AT-D2 values — spec/GATE5-D2B-PLAN.md, operator window 2026-07-18.
// Credential SECRETS are never here: only cred-store references, resolved at
// runtime via `cred get`.

export const CRED_BINARY = join(homedir(), ".claude", "bin", "cred");

export interface LiveTargetIdentity {
  readonly baseUrl: string;
  readonly username: string;
  readonly credentialReference: string;
  readonly expectedModel: string;
  readonly expectedSerial: string;
}

export const LIVE_TARGETS: Readonly<Record<"ptz" | "stream", LiveTargetIdentity>> = {
  ptz: {
    baseUrl: "http://192.168.1.33",
    username: "root",
    credentialReference: "cam-q6358-vapix",
    expectedModel: "AXIS Q6358-LE PTZ Camera",
    expectedSerial: "E82725146996",
  },
  stream: {
    baseUrl: "http://192.168.1.32",
    username: "root",
    credentialReference: "cam-q6325-vapix",
    expectedModel: "AXIS Q6325-LE PTZ Camera",
    expectedSerial: "E827252C9B9F",
  },
};

export const SAFE_PRESET_BACKEND_NAME = "Home";
// Measured 2026-07-18 by commanding Home and reading back (plan §Locked values).
export const SAFE_PRESET_POSITION: VapixPosition = { pan: 0.0, tilt: -44.99, zoom: 1 };
// Operator park — runs start here so motion, poll-to-tolerance, and the F19
// restore are observable, and S6-rejection readback is genuinely off-safe.
export const PARK_POSITION: VapixPosition = { pan: 173.94, tilt: -0.08, zoom: 7998 };
// S6-rejection variant: a backend preset name absent on the device (verified
// live 2026-07-18: HTTP 200 + "Error: goto preset: No such preset position found").
export const ABSENT_PRESET_BACKEND_NAME = "aar-gate5-absent";

export const STREAM_PROFILE_LOGICAL = "gate5-live";
export const STREAM_PROFILE_BACKEND = "gate5";

export interface LiveConfigOptions {
  /** S6-rejection: map gate5-safe to a preset the device does not have. */
  readonly rejectionVariant?: boolean;
  /** Set true ONLY inside the operator's physical exclusive-control window. */
  readonly exclusiveControl?: boolean;
}

export function liveVapixConfig(
  witnessProxyUrl: string,
  recoveryDirectory: string,
  options: LiveConfigOptions = {},
): VapixRuntimeConfig {
  return {
    targets: {
      "ptz-primary": {
        baseUrl: LIVE_TARGETS.ptz.baseUrl,
        username: LIVE_TARGETS.ptz.username,
        credentialReference: LIVE_TARGETS.ptz.credentialReference,
      },
      "fixed-primary": {
        baseUrl: LIVE_TARGETS.stream.baseUrl,
        username: LIVE_TARGETS.stream.username,
        credentialReference: LIVE_TARGETS.stream.credentialReference,
      },
    },
    witnessProxyUrl,
    presetMappings: { "gate5-safe": options.rejectionVariant ? ABSENT_PRESET_BACKEND_NAME : SAFE_PRESET_BACKEND_NAME },
    presetPositions: { "gate5-safe": SAFE_PRESET_POSITION },
    streamProfileMappings: { [STREAM_PROFILE_LOGICAL]: STREAM_PROFILE_BACKEND },
    positionTolerance: { pan: 0.5, tilt: 0.5, zoom: 100 },
    pollIntervalMs: 500,
    settlingDeadlineMs: 15_000,
    requestTimeoutMs: 10_000,
    streamMinimumPayloadBytes: 4096,
    exclusiveControl: options.exclusiveControl ?? false,
    recoveryDirectory,
  };
}
