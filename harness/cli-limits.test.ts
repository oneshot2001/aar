import { expect, test } from "bun:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Both CLIs print every signed limit from the decoded verdict; the two
// not_established lines are the ones a reader is most likely to need.
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BUNDLE = join("kats", "positive", "bundle-valid-subset.cbor");
const AT = "1735689800";

test("pyref CLI prints every signed limit", () => {
  const proc = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", BUNDLE, "--at", AT], { cwd: root });
  const output = proc.stdout.toString();
  expect(proc.exitCode, proc.stderr.toString()).toBe(0);
  expect(output).toContain("\n    custody_continuity: not_established\n");
  expect(output).toContain("\n    source_authenticity: not_established\n");
});

test("harness CLI prints every signed limit", () => {
  const proc = Bun.spawnSync(["bun", "run", join("harness", "verify.ts"), BUNDLE, "--at", AT], { cwd: root });
  const output = proc.stdout.toString();
  expect(proc.exitCode, proc.stderr.toString()).toBe(0);
  expect(output).toContain("\n  custody_continuity: not_established\n");
  expect(output).toContain("\n  source_authenticity: not_established\n");
});
