// Smoke (Packet D, Stage C): a small run completes, every control fires, the
// whole baseline reproduces, and the three finding channels are printed, not
// asserted to be zero (a non-zero count is a finding for Claude, not a red test).
import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { root } from "./difffuzz-pyref";

test("difffuzz --seed 1 --mutants 200 exits 0 with controls 8/8 and the full baseline", () => {
  const out = mkdtempSync(join(tmpdir(), "difffuzz-smoke-"));
  const started = Date.now();
  const proc = Bun.spawnSync(["bun", "run", "harness/difffuzz.ts", "--seed", "1", "--mutants", "200", "--out", out], { cwd: root });
  const seconds = (Date.now() - started) / 1000;
  expect(proc.exitCode, proc.stderr.toString()).toBe(0);
  const report = JSON.parse(readFileSync(join(out, "report.json"), "utf8"));
  const { stable } = report;
  expect(stable.controls.filter((control: { passed: boolean }) => control.passed)).toHaveLength(8);
  expect(stable.baseline.reproduced).toBe(stable.baseline.seeds);
  expect(stable.baseline.seeds).toBeGreaterThanOrEqual(513);
  const { bytes, classification, crash } = stable.channels;
  console.log(`difffuzz smoke: ${seconds.toFixed(1)} s; bytes/classification/crash = ${bytes}/${classification}/${crash}; ${stable.accept}`);
  for (const finding of stable.findings) console.log(`  finding ${finding.id} [${finding.channel}] ${finding.operator} on ${finding.seed}: ${finding.detail}`);
  rmSync(out, { recursive: true, force: true });
}, 180_000);
