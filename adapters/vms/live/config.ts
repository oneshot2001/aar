import type { VmsRuntimeConfig, VmsTargetRouting } from "../config";
// Same physical lab as D2b — device identities, park/safe positions, and the
// absent-preset rejection variant are the locked FILL-AT-D2 values, reused
// here as the D3 FILL-AT-D3 values (spec/GATE5-D2B-PLAN.md, GATE5-D3-PLAN.md).
import {
  ABSENT_PRESET_BACKEND_NAME,
  LIVE_TARGETS,
  SAFE_PRESET_BACKEND_NAME,
  SAFE_PRESET_POSITION,
} from "../../vapix/live/config";

export { CRED_BINARY, LIVE_TARGETS, PARK_POSITION, SAFE_PRESET_POSITION } from "../../vapix/live/config";

// The mediator fetches its media unit via the VMS snapshot seam; the profile
// is echo-only (G5-D3-003), so the logical/backend names matter for evidence,
// not for the fetch.
export const STREAM_PROFILE_LOGICAL = "gate5-live";
export const STREAM_PROFILE_BACKEND = "gate5";

function routing(target: typeof LIVE_TARGETS.ptz): VmsTargetRouting {
  const url = new URL(target.baseUrl);
  return {
    host: url.hostname,
    port: url.port ? Number(url.port) : 80,
    username: target.username,
    credentialReference: target.credentialReference,
  };
}

export interface LiveVmsConfigOptions {
  /** S6-rejection: map gate5-safe to a preset the device does not have. */
  readonly rejectionVariant?: boolean;
  /** Set true ONLY inside the operator's physical exclusive-control window. */
  readonly exclusiveControl?: boolean;
}

export function liveVmsConfig(
  witnessProxyUrl: string,
  mediatorBaseUrl: string,
  recoveryDirectory: string,
  options: LiveVmsConfigOptions = {},
): VmsRuntimeConfig {
  return {
    witnessProxyUrl,
    mediatorBaseUrl,
    targets: {
      "ptz-primary": routing(LIVE_TARGETS.ptz),
      "fixed-primary": routing(LIVE_TARGETS.stream),
    },
    presetMappings: { "gate5-safe": options.rejectionVariant ? ABSENT_PRESET_BACKEND_NAME : SAFE_PRESET_BACKEND_NAME },
    presetPositions: { "gate5-safe": SAFE_PRESET_POSITION },
    streamProfileMappings: { [STREAM_PROFILE_LOGICAL]: STREAM_PROFILE_BACKEND },
    positionTolerance: { pan: 0.5, tilt: 0.5, zoom: 100 },
    // The mediator runs `cred get` per request (noticed-not-fixed in the D3
    // ledger); 1 s polls leave it headroom vs D2b's 500 ms.
    pollIntervalMs: 1_000,
    settlingDeadlineMs: 15_000,
    requestTimeoutMs: 10_000,
    streamMinimumPayloadBytes: 4096,
    exclusiveControl: options.exclusiveControl ?? false,
    recoveryDirectory,
  };
}
