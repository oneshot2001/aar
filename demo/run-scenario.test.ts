import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, test } from "bun:test";
import { id16 } from "../harness/crypto";
import { toHex } from "../harness/cbor";
import { createVapixStub } from "./adapters/stub";
import { generateDemoKeys } from "./keys/keys";
import { runScenario, type GateInputFile } from "./run-scenario";

describe("Gate 5 D1 synthetic end to end", () => {
  test("S1 and S3 produce pyref-conformant bundles with content/oracle assertions", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-gate5-e2e-"));
    const keyDir = join(root, "keys");
    const outputDir = join(root, "artifacts");
    const priorState = join(root, "prior-state.json");
    const preflight = join(root, "preflight.json");
    await generateDemoKeys(keyDir, join(root, "public.json"));
    await writeFile(preflight, `${JSON.stringify({ ok: true })}\n`);
    const shared = {
      version: 1 as const,
      tenant_id: toHex(id16("demo-tenant")),
      site_id: toHex(id16("demo-site")),
      target_id: toHex(id16("demo-target")),
      adapter: "vapix" as const,
      key_dir: keyDir,
      output_dir: outputDir,
      prior_state_file: priorState,
    };
    // Stay within the existing harness encoder's confirmed uint32 limitation;
    // G5-D1-004 records why Gate 5 must adjudicate this before D2 wall-era time.
    const s1At = 8_000_000;
    const s1: GateInputFile = {
      ...shared, evaluated_at: s1At, epoch_id: 1001,
      invocation_id: toHex(id16("gate-supplied-s1-invocation")), correlation_id: toHex(id16("gate-supplied-s1-correlation")),
      target_logical_name: "ptz-primary", action_name: "camera.ptz.preset", parameters: { preset_name: "gate5-safe" },
      expected_outcome_level: "device_acknowledged",
      delegation_candidates: [{ not_before: s1At - 600, not_after: s1At + 600 }], preflight_result_file: preflight,
    };
    const s1Result = await runScenario("S1", s1, createVapixStub(), root);
    expect(s1Result.pyrefOutput).toContain("Result: conformant");
    expect(s1Result.pyrefOutput.includes("stateful_not_evaluated")).toBeFalse();
    expect(s1Result.witness).toHaveLength(1);

    const s3At = s1At + 100;
    const s3: GateInputFile = {
      ...shared, evaluated_at: s3At, epoch_id: 1002,
      invocation_id: toHex(id16("gate-supplied-s3-invocation")), correlation_id: toHex(id16("gate-supplied-s3-correlation")),
      target_logical_name: "ptz-primary", action_name: "camera.ptz.preset", parameters: { preset_name: "gate5-safe" },
      expected_outcome_level: "accepted",
      delegation_candidates: [
        { not_before: s3At - 600, not_after: s3At - 1 },
        { not_before: s3At - 1, not_after: s3At + 600 },
      ],
    };
    const s3Result = await runScenario("S3", s3, createVapixStub(), root);
    expect(s3Result.pyrefOutput).toContain("Result: conformant");
    expect(s3Result.witness).toHaveLength(0);
    expect(s3Result.producer.dispatchCount).toBe(0);
    const resultFile = process.env.AAR_D1_RESULTS_FILE;
    if (resultFile) {
      await mkdir(dirname(resultFile), { recursive: true });
      await writeFile(resultFile, ["Gate 5 D1 actual pyref output", "", "=== S1 ===", s1Result.pyrefOutput, "=== S3 ===", s3Result.pyrefOutput].join("\n"));
    }
  }, 30_000);
});
