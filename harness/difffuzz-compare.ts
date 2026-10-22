// Comparator for the differential fuzz tool: one side per verifier in a shared
// vocabulary, five channels that are never summed, and the two no-op notions
// (verdict no-op, masked) the driver counts apart from findings.
import { BatchResponse, Identity, sha256Hex } from "./difffuzz-pyref";
import { harnessVerdict } from "./difffuzz-seeds";
import { VerifyB1Options } from "./verifier";

export type Channel = "bytes" | "classification" | "crash" | "unsupported" | "adapter" | "leg";
export interface Side { result: string | null; reason: string | null; step: number | null; verdict_hex: string | null; crash: { type: string; message: string } | null }

export const sideOf = (response: BatchResponse): Side => "crash" in response
  ? { result: null, reason: null, step: null, verdict_hex: null, crash: response.crash }
  : "result" in response ? { result: response.result, reason: response.reason, step: response.step, verdict_hex: response.verdict_hex, crash: null }
    : { result: null, reason: null, step: null, verdict_hex: null, crash: { type: "protocol_error", message: response.protocol_error } };

// The harness side; an exception escaping verifyBundle on a well-formed call is a crash.
export function harnessSide(bundle: Uint8Array, options: VerifyB1Options, identity: Identity): Side {
  try { return { ...harnessVerdict(bundle, options, identity), crash: null }; } catch (error) {
    return { result: null, reason: null, step: null, verdict_hex: null, crash: { type: (error as Error).constructor?.name ?? "Error", message: (error as Error).message ?? String(error) } };
  }
}

export type Comparison = "agree" | "bytes" | "classification" | "crash";
export function compare(harness: Side, pyref: Side): Comparison {
  if (harness.crash !== null || pyref.crash !== null) return "crash";
  if (harness.result !== pyref.result || harness.reason !== pyref.reason || harness.step !== pyref.step) return "classification";
  return harness.verdict_hex === pyref.verdict_hex ? "agree" : "bytes";
}

// Both sides reproduce the seed's own result and verdict bytes: the mutation changed nothing the verdict sees.
export const verdictNoop = (harness: Side, pyref: Side, seed: Side): boolean => compare(harness, pyref) === "agree" && harness.result === seed.result && harness.verdict_hex === seed.verdict_hex;
// Both sides rejected before the operator's target step: the target was never reached.
export const masked = (harness: Side, pyref: Side, targetStep: number | null): boolean => targetStep !== null && harness.step !== null && pyref.step !== null && harness.step < targetStep && pyref.step < targetStep;

export const stableSide = (side: Side): Record<string, unknown> => ({ result: side.result, reason: side.reason, step: side.step, verdict_sha256: side.verdict_hex === null ? null : sha256Hex(Buffer.from(side.verdict_hex, "hex")), crash_type: side.crash?.type ?? null });
