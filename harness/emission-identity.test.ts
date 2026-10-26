// D-86 step-9 emission identity: the stateful KATs (moved here from verifier.test.ts),
// the six fuzz splits rebuilt from their recorded mutation, and the two history usage
// errors (rule 0) in the harness, the pyref library and the pyref CLI.
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { equalBytes } from "./cbor";
import { HISTORY_CONTRADICTS_ITSELF, HISTORY_CONTRADICTS_RECEIPT } from "./emission-identity";
import { buildStatefulFixtures, FUZZ_SPLITS, parseStatefulPrior, StatefulFixture } from "./stateful-fixtures";
import { verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;
const fixtures = buildStatefulFixtures();
const stem = (fixture: StatefulFixture): string => join(root, "kats", fixture.descriptor.expected_code === null ? "positive" : "negative", "stateful", fixture.name);

describe("D-86 emission identity", () => {
  test("every stateful fixture returns its expected code; a conformant one observes duplicate_exact", () => {
    for (const fixture of fixtures) {
      const result = verifyBundle(fixture.bundle, { evaluationTime: AT, ...(fixture.prior ? { priorEmissions: parseStatefulPrior(fixture.prior) } : {}) });
      expect(result.ok ? null : result.reason, fixture.name).toBe(fixture.descriptor.expected_code);
      if (result.ok) expect(result.verdict.observations, fixture.name).toContain("duplicate_exact");
    }
  });

  test("generated stateful files equal the in-memory fixtures; a fixture without prior state has no prior file", () => {
    for (const fixture of fixtures) {
      expect(equalBytes(readFileSync(`${stem(fixture)}.bundle.cbor`), fixture.bundle), fixture.name).toBe(true);
      if (fixture.prior) expect(JSON.parse(readFileSync(`${stem(fixture)}.prior.json`, "utf8")), fixture.name).toEqual(fixture.prior);
      else expect(existsSync(`${stem(fixture)}.prior.json`), fixture.name).toBe(false);
      expect(JSON.parse(readFileSync(`${stem(fixture)}.json`, "utf8")), fixture.name).toEqual(fixture.descriptor);
    }
  });

  test("each fuzz split rebuilds byte for byte from its recorded mutation and carries the recorded prior", () => {
    for (const [run, id] of FUZZ_SPLITS) {
      const fixture = fixtures.find((candidate) => candidate.name === `d86-fuzz-${id}`)!;
      const finding = join(root, "docs", "fuzz-runs", run, id);
      expect(equalBytes(readFileSync(join(finding, "bundle.cbor")), fixture.bundle), id).toBe(true);
      expect(JSON.parse(readFileSync(join(finding, "inputs.json"), "utf8")).prior_state, id).toEqual(fixture.prior);
      expect(fixture.descriptor.mutation_description, id).toContain(JSON.parse(readFileSync(join(finding, "both.json"), "utf8")).stable.detail);
    }
  });

  test("history contradicting itself (0a) or a carried receipt (0b) is a usage error: harness throw, pyref ValueError, pyref CLI exit 2 with no verdict", () => {
    const fixture = fixtures.find((candidate) => candidate.name === "d86-history-exact-represent")!;
    const exact = fixture.prior!.prior_emissions![0]!;
    const moved = { ...exact, epoch_owner_kid: "00".repeat(32) }; // same receipt ID and digest, other coordinates; sorts first
    const directory = mkdtempSync(join(tmpdir(), "aar-d86-"));
    const bundle = join(directory, "bundle.cbor");
    writeFileSync(bundle, fixture.bundle);
    try {
      for (const [label, prior, message] of [["0a", { prior_emissions: [moved, exact] }, HISTORY_CONTRADICTS_ITSELF], ["0b", { prior_emissions: [moved] }, HISTORY_CONTRADICTS_RECEIPT]] as const) {
        expect(() => verifyBundle(fixture.bundle, { evaluationTime: AT, priorEmissions: parseStatefulPrior(prior) }), label).toThrow(message);
        const path = join(directory, `${label}.json`);
        writeFileSync(path, JSON.stringify(prior));
        const library = Bun.spawnSync(["python3", "-B", "-c", `
import json, sys
from pyref.verifier import evaluate
try:
    evaluate(open(sys.argv[1], "rb").read(), evaluated_at=int(sys.argv[3]), prior_state=json.load(open(sys.argv[2])))
except ValueError as exc:
    print(exc)
`, bundle, path, String(AT)], { cwd: root });
        expect(library.stdout.toString().trim(), `${label} ${library.stderr}`).toBe(message);
        const cli = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", bundle, "--at", String(AT), "--prior-state", path], { cwd: root });
        expect(cli.exitCode, label).toBe(2);
        expect(cli.stdout.toString(), label).toBe("");
        expect(cli.stderr.toString(), label).toContain(message);
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
