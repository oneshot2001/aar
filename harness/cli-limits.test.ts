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

test("both CLIs map an unreadable bundle to exit 2 with no verdict", () => {
  for (const bundle of ["kats/does-not-exist.cbor", "kats"]) {
    for (const argv of [["python3", "-B", "-m", "pyref", "verify", bundle, "--at", AT], ["bun", "run", join("harness", "verify.ts"), bundle, "--at", AT]]) {
      const proc = Bun.spawnSync(argv, { cwd: root });
      expect(proc.exitCode, `${argv[0]} ${bundle}: ${proc.stderr.toString()}`).toBe(2);
      expect(proc.stdout.toString(), `${argv[0]} ${bundle}`).not.toContain("CBOR hex");
      expect(proc.stderr.toString(), `${argv[0]} ${bundle}`).toContain("cannot read bundle file");
    }
  }
});

test("harness CLI prints every signed limit", () => {
  const proc = Bun.spawnSync(["bun", "run", join("harness", "verify.ts"), BUNDLE, "--at", AT], { cwd: root });
  const output = proc.stdout.toString();
  expect(proc.exitCode, proc.stderr.toString()).toBe(0);
  expect(output).toContain("\n  custody_continuity: not_established\n");
  expect(output).toContain("\n  source_authenticity: not_established\n");
});
