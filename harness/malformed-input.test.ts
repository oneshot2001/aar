import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CborValue, decodeCbor } from "./cbor";
import { buildMalformedTypeVariants } from "./negative-fixtures";
import { verifySigned } from "./crypto";
import { TEST_KEYS } from "./testkeys";
import { verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// Explicit evaluation time (caller-supplied always; the wall clock is never read — pyref --at symmetry). Matches the corpus.
const AT = 1_735_689_800;

// House invariant: a verifier always emits a SIGNED verdict on any decodable
// input — malformed input yields schema/bad-type (or the applicable code) at
// the right step, never a crash. These input classes previously crashed one
// implementation or the other (the non-map binding was proven live in pyref
// with an AttributeError before signature verification).
describe("malformed-input hardening", () => {
  test("every malformed-type variant yields a signed verdict with the expected code and step", () => {
    for (const variant of buildMalformedTypeVariants()) {
      const result = verifyBundle(variant.bytes, { evaluationTime: AT });
      expect(result.ok, variant.label).toBe(false);
      if (result.ok) continue;
      expect(result.reason, variant.label).toBe(variant.code as typeof result.reason);
      expect(result.step, variant.label).toBe(variant.step);
      expect(result.verdictEnvelope !== undefined, variant.label).toBe(true);
      if (result.verdictEnvelope !== undefined) expect(verifySigned(result.verdictEnvelope, TEST_KEYS.verifier_signing), variant.label).toBe(true);
    }
  });

  test("pyref agrees on every malformed-type variant (cross-impl: same code, same step, signed verdict, no crash)", async () => {
    const { mkdtemp, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const directory = await mkdtemp(join(tmpdir(), "aar-malformed-"));
    for (const variant of buildMalformedTypeVariants()) {
      const path = join(directory, `${variant.label.replaceAll(/[^a-z_]/gu, "-")}.cbor`);
      await writeFile(path, variant.bytes);
      const bundle = decodeCbor(variant.bytes, { strict: true }) as Record<string, CborValue>;
      const proc = Bun.spawnSync(["python3", "-m", "pyref", "verify", path, "--at", String(bundle.created_at)], { cwd: root });
      const output = proc.stdout.toString() + proc.stderr.toString();
      expect(proc.exitCode, `${variant.label}: ${output}`).toBe(1);
      expect(output.includes(`First failure: step ${variant.step} (${variant.code})`), `${variant.label}: ${output}`).toBe(true);
      expect(output.includes("Traceback"), variant.label).toBe(false);
    }
  });

  test("a missing evaluationTime is a hard caller error, never a wall-clock read", () => {
    const input = readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor"));
    expect(() => verifyBundle(input)).toThrow("evaluationTime");
  });
});
