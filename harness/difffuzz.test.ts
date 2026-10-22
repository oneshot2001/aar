// Smoke (Packet D, Stage C; fix-first G): a small run completes, every control
// fires, the whole baseline reproduces, and the three finding channels are
// printed, not asserted to be zero (a non-zero count is a finding for Claude,
// not a red test). Budget 600 s: the repo's measured CI/local ratio on the
// cross-implementation tests is 3-4x over a ~150 s local run with the default
// lanes; the test prints its wall time.
import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { root } from "./difffuzz-pyref";

test("difffuzz --seed 1 --mutants 200 exits 0 with controls 8/8 and the full baseline (600 s budget)", () => {
  const out = mkdtempSync(join(tmpdir(), "difffuzz-smoke-"));
  const started = Date.now();
  const proc = Bun.spawnSync(["bun", "run", "harness/difffuzz.ts", "--seed", "1", "--mutants", "200", "--out", out], { cwd: root });
  const seconds = (Date.now() - started) / 1000;
  expect(proc.exitCode, proc.stderr.toString()).toBe(0);
  expect(seconds).toBeLessThan(600);
  const report = JSON.parse(readFileSync(join(out, "report.json"), "utf8"));
  const { stable } = report;
  expect(stable.controls.filter((control: { passed: boolean }) => control.passed)).toHaveLength(8);
  expect(stable.summary.baseline.reproduced).toBe(stable.summary.baseline.seeds);
  expect(stable.summary.baseline.seeds).toBeGreaterThanOrEqual(513);
  const { bytes, classification, crash } = stable.summary.channels;
  console.log(`difffuzz smoke wall time: ${seconds.toFixed(1)} s (budget 600 s); bytes/classification/crash = ${bytes}/${classification}/${crash}; ${stable.accept}`);
  for (const finding of stable.findings) console.log(`  finding ${finding.id} [${finding.channel}] ${finding.operator} on ${finding.seed}: ${finding.detail}`);
  rmSync(out, { recursive: true, force: true });
}, 600_000);
