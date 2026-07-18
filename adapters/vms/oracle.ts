import type { GateInputFile, ScenarioRunResult } from "../../demo/run-scenario";

// VMS-leg oracle checks shared by the offline suite and the live runner
// (G5-D3 review P2-2: the shared assertOnlineOracle's adapter-specific
// branches are VAPIX-only; these are the VMS equivalents and must run in
// BOTH legs so the live run is not materially weaker than offline).

export const MEDIATOR_PATHS = new Set(["/dispatch", "/ptz/position", "/device/info", "/healthz"]);

export const DISPATCH_REQUEST_LINES = {
  "camera.ptz.preset": "POST /dispatch?cred=<sanitized>&digest=<sanitized>&host=<sanitized>&op=<sanitized>&port=<sanitized>&preset=<sanitized>&username=<sanitized> HTTP/1.1",
  "camera.stream.view": "POST /dispatch?cred=<sanitized>&digest=<sanitized>&host=<sanitized>&op=<sanitized>&port=<sanitized>&profile=<sanitized>&username=<sanitized> HTTP/1.1",
} as const;

// Full-mediation proof + dispatch shape + mediation marker. Every witnessed
// exchange must be with the mediator's HTTP surface — no direct device path
// (/axis-cgi/...) may ever appear at the AAR->mediator boundary.
export function assertVmsMediationDiscipline(result: ScenarioRunResult, input: GateInputFile): void {
  for (const entry of result.witness) {
    const path = entry.request_line.split(" ")[1]!.split("?")[0]!;
    if (!MEDIATOR_PATHS.has(path)) throw new Error(`non-mediated witnessed request: ${entry.request_line}`);
  }
  const attributable = result.witness.filter((entry) => entry.invocation_id === input.invocation_id && entry.action_bearing);
  const bound = attributable.filter((entry) => entry.command_digest !== null);
  if (bound.length && bound.some((entry) => entry.request_line !== DISPATCH_REQUEST_LINES[input.action_name])) {
    throw new Error("VMS dispatch request-line shape assertion failed");
  }
  const dispatchResult = result.producer.dispatchResult;
  if (dispatchResult && dispatchResult.dispatched && dispatchResult.effect.backend_evidence.vms_mediated !== true) {
    throw new Error("VMS mediation marker missing from effect evidence");
  }
}

// F19 restore evidence for an acknowledged PTZ dispatch: exactly one
// action-bearing unbound (null-digest) mediated command — the restore — and
// a verified restoration.
export function assertVmsPtzRestoreDiscipline(result: ScenarioRunResult, input: GateInputFile): void {
  const attributable = result.witness.filter((entry) => entry.invocation_id === input.invocation_id && entry.action_bearing);
  const restores = attributable.filter((entry) => entry.command_digest === null);
  const evidence = result.producer.dispatchResult?.effect.backend_evidence ?? {};
  if (restores.length !== 1 || evidence.restore_verified !== true) throw new Error("F19 restore evidence assertion failed");
}
