// CLI-lane comparator (fix-first B.1): a stubbed process pair that prints no
// verdict while its exit class promises one is a disagreement, as is a verdict
// printed on one side only; a usage failure on both sides promises none.
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { toHex } from "./cbor";
import { classify, laneApplicable } from "./difffuzz-cli-lane";
import { root } from "./difffuzz-pyref";
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
