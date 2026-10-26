// D-86 step-9 emission identity: the stateful KATs (moved here from verifier.test.ts),
// the six fuzz splits rebuilt from their recorded mutation, and the history usage
// errors (entry shape, rule 0) in the harness, the pyref library and the pyref CLI.
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { equalBytes } from "./cbor";
import { HISTORY_CONTRADICTS_ITSELF, HISTORY_CONTRADICTS_RECEIPT, parsePriorState } from "./emission-identity";
import { buildStatefulFixtures, FUZZ_SPLITS, parseStatefulPrior, StatefulFixture } from "./stateful-fixtures";
import { PriorEmission, verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;
const fixtures = buildStatefulFixtures();
const fixture = (name: string): StatefulFixture => fixtures.find((candidate) => candidate.name === name)!;
const stem = (fixture: StatefulFixture): string => join(root, "kats", fixture.descriptor.expected_code === null ? "positive" : "negative", "stateful", fixture.name);

// Writes the bundle to a scratch directory, runs the checks, removes the directory.
function withBundle(bytes: Uint8Array, run: (directory: string, bundle: string) => void): void {
  const directory = mkdtempSync(join(tmpdir(), "aar-d86-"));
  try {
    writeFileSync(join(directory, "bundle.cbor"), bytes);
    run(directory, join(directory, "bundle.cbor"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// The pyref library over several prior states in one process: [exception class, message]
// for a ValueError (UsageError is a subclass), or ["verdict", reason].
function pyrefLibrary(directory: string, bundle: string, priors: readonly unknown[]): [string, string | null][] {
  const path = join(directory, "priors.json");
  writeFileSync(path, JSON.stringify(priors));
  const run = Bun.spawnSync(["python3", "-B", "-c", `
import json, sys
from pyref.verifier import evaluate
for prior in json.load(open(sys.argv[2])):
    try:
        print(json.dumps(["verdict", evaluate(open(sys.argv[1], "rb").read(), evaluated_at=int(sys.argv[3]), prior_state=prior).reason]))
    except ValueError as exc:
        print(json.dumps([type(exc).__name__, str(exc)]))
`, bundle, path, String(AT)], { cwd: root });
  expect(run.exitCode, run.stderr.toString()).toBe(0);
  return run.stdout.toString().trim().split("\n").map((line) => JSON.parse(line));
}

function pyrefCli(directory: string, bundle: string, prior: unknown): { exitCode: number; stdout: string; stderr: string } {
  const path = join(directory, "prior.json");
  writeFileSync(path, JSON.stringify(prior));
  const run = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", bundle, "--at", String(AT), "--prior-state", path], { cwd: root });
  return { exitCode: run.exitCode, stdout: run.stdout.toString(), stderr: run.stderr.toString() };
}

// A usage error with one message everywhere: harness throw, pyref library ValueError
// (the named class), pyref CLI exit 2 with no verdict on stdout.
type UsageCase = readonly [label: string, prior: unknown, message: string, libraryClass: "ValueError" | "UsageError"];
function expectUsageError(bytes: Uint8Array, cases: readonly UsageCase[]): void {
  withBundle(bytes, (directory, bundle) => {
    for (const [label, prior, message] of cases) {
      expect(() => verifyBundle(bytes, { evaluationTime: AT, priorEmissions: parsePriorState(prior) }), label).toThrow(message);
    }
    expect(pyrefLibrary(directory, bundle, cases.map(([, prior]) => prior))).toEqual(cases.map(([, , message, libraryClass]) => [libraryClass, message]));
    for (const [label, prior, message] of cases) {
      const cli = pyrefCli(directory, bundle, prior);
      expect(cli.exitCode, label).toBe(2);
      expect(cli.stdout, label).toBe("");
      expect(cli.stderr, label).toContain(`error: ${message}\n`);
    }
  });
}

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
    const represent = fixture("d86-history-exact-represent");
    const exact = represent.prior!.prior_emissions![0]!;
    const moved = { ...exact, epoch_owner_kid: "00".repeat(32) }; // same receipt ID and digest, other coordinates; sorts first
    expectUsageError(represent.bundle, [
      ["0a", { prior_emissions: [moved, exact] }, HISTORY_CONTRADICTS_ITSELF, "ValueError"],
      ["0b", { prior_emissions: [moved] }, HISTORY_CONTRADICTS_RECEIPT, "UsageError"],
    ]);
  });

  test("a malformed prior-state entry is a usage error at every entry point, with one message (E-06: no bool-as-uint verdict in pyref)", () => {
    const represent = fixture("d86-history-exact-represent");
    const exact = represent.prior!.prior_emissions![0]!;
    const label = "prior-state.prior_emissions[0]";
    const cases: UsageCase[] = [
      ...["issuer_seq", "epoch_id", "epoch_seq"].flatMap((key) => [false, true, -1, 1.5].map((value): UsageCase =>
        [`${key}=${value}`, { prior_emissions: [{ ...exact, [key]: value }] }, `${label}.${key} must be an unsigned integer <= 9007199254740991`, "ValueError"])),
      ["31-byte hex", { prior_emissions: [{ ...exact, issuer_kid: "ab".repeat(31) }] }, `${label}.issuer_kid must decode to exactly 32 bytes`, "ValueError"],
      ["extra key", { prior_emissions: [{ ...exact, note: 0 }] }, `${label}: unknown note`, "ValueError"],
    ];
    expectUsageError(represent.bundle, cases);
    // A typed caller of verifyBundle meets the same check at the prior-state boundary.
    const typed = { ...parseStatefulPrior(represent.prior!)[0]!, epochSeq: false } as unknown as PriorEmission;
    expect(() => verifyBundle(represent.bundle, { evaluationTime: AT, priorEmissions: [typed] })).toThrow(`${label}.epoch_seq must be an unsigned integer <= 9007199254740991`);
  });
});
