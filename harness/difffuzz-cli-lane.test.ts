// CLI-lane comparator (fix-first B.1): a stubbed process pair that prints no
// verdict while its exit class promises one is a disagreement, as is a verdict
// printed on one side only; a usage failure on both sides promises none.
import { expect, spyOn, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { toHex } from "./cbor";
import { classify, laneApplicable, runCliLane } from "./difffuzz-cli-lane";
import { Planned, seedViews } from "./difffuzz-mutants";
import { root } from "./difffuzz-pyref";
import { Rng } from "./difffuzz-rng";
import { verifyBundle } from "./verifier";

const AT = 1_735_689_800;
const bundle = readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor"));
const hex = toHex(verifyBundle(bundle, { evaluationTime: AT }).verdictEnvelope!);
const pyrefOut = (verdict: string | null): string => `Result: conformant\n${verdict === null ? "" : `Signed verdict:\n  CBOR hex: ${verdict}\n`}`;
const harnessOut = (verdict: string | null): string => `Result: conformant\n${verdict === null ? "" : `Signed verdict CBOR hex: ${verdict}\n`}`;

test("two exit-0 processes that print no verdict disagree; one-sided verdicts disagree; usage/usage without verdicts agree", () => {
  const silent = classify("x", "mutant", { exitCode: 0, stdout: pyrefOut(null) }, { exitCode: 0, stdout: harnessOut(null) });
  expect(silent.exit_class_agree).toBe(true);
  expect(silent.verdict_missing).toBe(true);
  expect(silent.disagreement).toBe(true);
  expect(silent.reasons).toEqual(["pyref printed no verdict for a class that promises one", "harness printed no verdict for a class that promises one"]);

  const oneSided = classify("y", "mutant", { exitCode: 1, stdout: pyrefOut(hex) }, { exitCode: 1, stdout: harnessOut(null) });
  expect(oneSided.disagreement).toBe(true);
  expect(oneSided.reasons.some((reason) => reason.includes("one side only"))).toBe(true);

  const usage = classify("z", "rp-seed", { exitCode: 2, stdout: "" }, { exitCode: 2, stdout: "" });
  expect(usage.disagreement).toBe(false);
  expect(usage.payload_equal_modulo_identity).toBe(null);

  const same = classify("w", "mutant", { exitCode: 0, stdout: pyrefOut(hex) }, { exitCode: 0, stdout: harnessOut(hex) });
  expect(same.disagreement).toBe(false); expect(same.hex_equal).toBe(true); expect(same.payload_equal_modulo_identity).toBe(true);

  const exits = classify("v", "mutant", { exitCode: 3, stdout: pyrefOut(hex) }, { exitCode: 0, stdout: harnessOut(hex) });
  expect(exits.disagreement).toBe(true); expect(exits.reasons[0]).toContain("exit class");
});

test("rows with a prior/replay state or a trust-policy pin are not applicable to the lane", () => {
  const base = { evaluated_at: AT, prior_state: null, replay_state: { entries: [] }, policy: null, signing_key: null, trust_policy: null };
  expect(laneApplicable(base)).toBe(true);
  expect(laneApplicable({ ...base, prior_state: { prior_emissions: [] } })).toBe(false);
  expect(laneApplicable({ ...base, replay_state: { entries: [{}] } })).toBe(false);
  expect(laneApplicable({ ...base, trust_policy: "/pin.json" })).toBe(false);
});

function planned(id: string, bytes: Uint8Array = bundle): Planned {
  const side = { result: "conformant", reason: null, step: null, verdict_hex: hex, crash: null };
  const [entry] = seedViews([{
    seed: {
      path: "kats/positive/bundle-valid-subset.cbor", raw: bundle, context: null, bundle,
      inputs: { evaluated_at: AT, prior_state: null, replay_state: { entries: [] }, policy: null, signing_key: null, trust_policy: null },
      options: { evaluationTime: AT, replayState: [] },
      pinned: { result: "conformant", code: null, step: null, verdict_sha256: "" },
    },
    harness: side, pyref: side,
  }]);
  return {
    id, entry: entry!, mutant: { bytes, target: "", detail: "CLI lane hygiene input" },
    operator: { name: "test", version: 1, layer: "raw", targetStep: null, repairBoundary: "none", applicable: () => true, apply: () => null },
  };
}

test("fuzz cli lane hygiene: a real agreeing mutant leaves --out empty", () => {
  const out = mkdtempSync(join(tmpdir(), "difffuzz-cli-test-"));
  try {
    const lane = runCliLane(1, [planned("m-00000")], [], new Rng(1), out);
    expect(lane.sampled_mutants).toBe(1);
    expect(lane.rp_seeds).toBe(0);
    expect(lane.rows).toHaveLength(1);
    expect(lane.rows[0]!.disagreement).toBe(false);
    expect(lane.rows[0]!.payload_equal_modulo_identity).toBe(true);
    expect(lane.disagreements).toEqual([]);
    expect(readdirSync(out)).toEqual([]);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test("fuzz cli lane hygiene: only disagreement bytes are retained and scratch is removed after success", () => {
  const out = mkdtempSync(join(tmpdir(), "difffuzz-cli-test-"));
  const different = Buffer.from(bundle); different[0] = different[0]! ^ 1;
  const scratch = new Set<string>();
  const spy = spyOn(Bun, "spawnSync");
  try {
    spy.mockImplementation((command) => {
      if (!Array.isArray(command)) throw new Error("expected CLI command arguments");
      const file = command[command[0] === "python3" ? 5 : 3]!;
      scratch.add(dirname(file));
      expect(basename(dirname(file))).toStartWith("difffuzz-cli-");
      expect(dirname(file)).not.toBe(join(out, "cli"));
      const disagree = basename(file) === "m-00001.cbor";
      expect(readFileSync(file)).toEqual(disagree ? different : bundle);
      const stdout = command[0] === "python3" ? pyrefOut(hex) : harnessOut(disagree ? null : hex);
      return {
        exitCode: 0, stdout: Buffer.from(stdout), stderr: Buffer.alloc(0), success: true, pid: 1,
        resourceUsage: {
          contextSwitches: { voluntary: 0, involuntary: 0 }, cpuTime: { user: 0, system: 0, total: 0 },
          maxRSS: 0, messages: { sent: 0, received: 0 }, ops: { in: 0, out: 0 }, shmSize: 0, signalCount: 0, swapCount: 0,
        },
      };
    });
    const lane = runCliLane(2, [planned("m-00000"), planned("m-00001", different)], [], new Rng(1), out);
    expect(spy).toHaveBeenCalledTimes(4);
    expect(lane.sampled_mutants).toBe(2);
    expect(lane.rows).toHaveLength(2);
    expect(lane.rows.find((row) => row.id === "m-00000")!.disagreement).toBe(false);
    expect(lane.rows.find((row) => row.id === "m-00001")).toEqual({
      id: "m-00001", kind: "mutant", pyref_exit: 0, harness_exit: 0,
      pyref_class: "conformant", harness_class: "conformant", exit_class_agree: true,
      pyref_verdict: true, harness_verdict: false, verdict_missing: true,
      hex_equal: null, payload_equal_modulo_identity: null, disagreement: true,
      reasons: ["harness printed no verdict for a class that promises one", "verdict printed on one side only"],
    });
    expect(lane.disagreements).toEqual(["m-00001: harness printed no verdict for a class that promises one; verdict printed on one side only"]);
    expect(readdirSync(out)).toEqual(["cli"]);
    expect(readdirSync(join(out, "cli"))).toEqual(["m-00001.cbor"]);
    expect(readFileSync(join(out, "cli", "m-00001.cbor"))).toEqual(different);
    expect(scratch.size).toBe(1);
    for (const directory of scratch) expect(existsSync(directory)).toBe(false);
  } finally {
    spy.mockRestore();
    rmSync(out, { recursive: true, force: true });
  }
});

test("fuzz cli lane hygiene: scratch is removed after a spawn exception", () => {
  const out = mkdtempSync(join(tmpdir(), "difffuzz-cli-test-"));
  let scratch = "";
  const failure = new Error("forced spawn failure");
  const spy = spyOn(Bun, "spawnSync");
  try {
    spy.mockImplementation((command) => {
      if (!Array.isArray(command)) throw new Error("expected CLI command arguments");
      const file = command[5]!;
      scratch = dirname(file);
      expect(readFileSync(file)).toEqual(bundle);
      throw failure;
    });
    expect(() => runCliLane(1, [planned("m-00000")], [], new Rng(1), out)).toThrow(failure);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(basename(scratch)).toStartWith("difffuzz-cli-");
    expect(existsSync(scratch)).toBe(false);
    expect(readdirSync(out)).toEqual([]);
  } finally {
    spy.mockRestore();
    rmSync(out, { recursive: true, force: true });
  }
});
