// Prior-state usage-error probes shared by the emission-identity (D-86) and retained-epoch
// (D-87) tests: one input through the harness, the pyref library and the pyref CLI.
import { expect } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { statefulOptions } from "./stateful-fixtures";
import { verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;

// Writes the bundle to a scratch directory, runs the checks, removes the directory.
export function withBundle(bytes: Uint8Array, run: (directory: string, bundle: string) => void): void {
  const directory = mkdtempSync(join(tmpdir(), "aar-d86-"));
  try {
    writeFileSync(join(directory, "bundle.cbor"), bytes);
    run(directory, join(directory, "bundle.cbor"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// A prior state as the exact JSON text of a file, for spellings JSON.stringify cannot
// produce (1.0, 1e0); any other value is serialized.
export class RawJson { constructor(readonly text: string) {} }
export const jsonText = (prior: unknown): string => prior instanceof RawJson ? prior.text : JSON.stringify(prior);
// The harness reads the whole JSON prior state as pyref does (prior_emissions, then retained_epochs).
export const harnessPrior = (prior: unknown) => statefulOptions(JSON.parse(jsonText(prior)));

// The pyref library over several prior states in one process (json.loads of each text):
// [exception class, message] for a ValueError (UsageError is a subclass), or
// ["verdict", reason, prior_emissions_digest hex].
export function pyrefLibrary(directory: string, bundle: string, priors: readonly unknown[], at = AT): (string | null)[][] {
  const path = join(directory, "priors.json");
  writeFileSync(path, JSON.stringify(priors.map(jsonText)));
  const run = Bun.spawnSync(["python3", "-B", "-c", `
import json, sys
from pyref.verifier import evaluate
for text in json.load(open(sys.argv[2])):
    try:
        result = evaluate(open(sys.argv[1], "rb").read(), evaluated_at=int(sys.argv[3]), prior_state=json.loads(text))
        print(json.dumps(["verdict", result.reason, result.verdict["trust_policy"]["prior_emissions_digest"].hex()]))
    except ValueError as exc:
        print(json.dumps([type(exc).__name__, str(exc)]))
`, bundle, path, String(at)], { cwd: root });
  expect(run.exitCode, run.stderr.toString()).toBe(0);
  return run.stdout.toString().trim().split("\n").map((line) => JSON.parse(line));
}

export function pyrefCli(directory: string, bundle: string, prior: unknown, at = AT): { exitCode: number; stdout: string; stderr: string } {
  const path = join(directory, "prior.json");
  writeFileSync(path, jsonText(prior));
  const run = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", bundle, "--at", String(at), "--prior-state", path], { cwd: root });
  return { exitCode: run.exitCode, stdout: run.stdout.toString(), stderr: run.stderr.toString() };
}

// A usage error with one message everywhere: harness throw, pyref library ValueError
// (the named class), pyref CLI exit 2 with no verdict on stdout.
export type UsageCase = readonly [label: string, prior: unknown, message: string, libraryClass: "ValueError" | "UsageError"];
export function expectUsageError(bytes: Uint8Array, cases: readonly UsageCase[], at = AT): void {
  withBundle(bytes, (directory, bundle) => {
    for (const [label, prior, message] of cases) {
      expect(() => verifyBundle(bytes, { evaluationTime: at, ...harnessPrior(prior) }), label).toThrow(message);
    }
    expect(pyrefLibrary(directory, bundle, cases.map(([, prior]) => prior), at)).toEqual(cases.map(([, , message, libraryClass]) => [libraryClass, message]));
    for (const [label, prior, message] of cases) {
      const cli = pyrefCli(directory, bundle, prior, at);
      expect(cli.exitCode, label).toBe(2);
      expect(cli.stdout, label).toBe("");
      expect(cli.stderr, label).toContain(`error: ${message}\n`);
    }
  });
}
