import { expect, test } from "bun:test";
import { encodeCbor } from "./cbor";
import { request, runBaseline } from "./difffuzz-baseline";
import { Comparison, Side, compare, verdictNoop } from "./difffuzz-compare";
import { LEGS } from "./difffuzz-leg-table";
import { runLegs } from "./difffuzz-legs";
import { Operator, list } from "./difffuzz-mutant";
import { Finding, runMutants, seedViews, tagHashSeedSensitivity } from "./difffuzz-mutants";
import { BatchResponse, PyrefBatch, sha256Hex } from "./difffuzz-pyref";
import { Rng } from "./difffuzz-rng";
import { loadSeeds } from "./difffuzz-seeds";
import { clone, flipSignature } from "./mutate";

const side: Side = { result: "nonconformant", reason: "sig/verify-failed", step: 6, verdict_hex: "aa", crash: null };
const crashed: Side = { result: null, reason: null, step: null, verdict_hex: null, crash: { type: "TypeError", message: "first execution" } };
const comparisons: [string, Side, Side, Comparison][] = [
  ["step-only disagreement", side, { ...side, step: 7 }, "classification"],
  ["reason-only disagreement", side, { ...side, reason: "hash/mismatch" }, "classification"],
  ["result-only disagreement", side, { ...side, result: "conformant" }, "classification"],
  ["bytes-only disagreement", side, { ...side, verdict_hex: "bb" }, "bytes"],
  ["harness crash", crashed, side, "crash"],
  ["pyref crash", side, crashed, "crash"],
  ["equal sides", side, { ...side }, "agree"],
];
for (const [name, harness, pyref, expected] of comparisons) {
  test(`fuzz oracle: compare ${name}`, () => {
    expect(compare(harness, pyref)).toBe(expected);
  });
}

test("fuzz oracle: agreed verdict bytes must match the seed for a verdict no-op", () => {
  expect(verdictNoop(side, { ...side }, { ...side, verdict_hex: "bb" })).toBe(false);
  expect(verdictNoop(side, { ...side }, { ...side })).toBe(true);
});

const seed = loadSeeds().find((candidate) => candidate.path === "kats/positive/bundle-valid-subset.cbor")!;
// Always corrupt receipt 0; only the declared target step varies between runs.
const signatureOperator = (targetStep: number): Operator => ({
  name: "oracle/receipt-signature", version: 1, layer: "cose", targetStep, repairBoundary: "none",
  applicable: (view) => list(view.bundle, "receipts").length > 0,
  apply: (view) => {
    const bundle = clone(view.bundle); const receipts = list(bundle, "receipts");
    receipts[0] = flipSignature(receipts[0]!);
    return { bytes: encodeCbor(bundle), target: "artifacts.receipts.0", detail: "receipt 0 signature flipped" };
  },
});

test("fuzz oracle: hash-seed sensitivity distinguishes crash types but ignores crash messages", () => {
  const identity = { product: "pyref", version: "test", build_digest: "11".repeat(32), config_digest: "22".repeat(32) };
  const finding: Finding = {
    id: "oracle-crash", channel: "crash", operator: signatureOperator(6), detail: "synthetic crash",
    seed, bundle: seed.bundle, harness: side, pyref: crashed,
    request: request("oracle-crash", seed, seed.bundle, null, identity),
  };
  const response = (type: string): BatchResponse => ({
    id: finding.id, input_sha256: sha256Hex(seed.bundle), crash: { type, message: "second execution" },
  });
  const changed = { ...finding }; const same = { ...finding };
  expect(tagHashSeedSensitivity([changed, same], [response("ValueError"), response("TypeError")])).toBe(1);
  expect(changed.hash_seed_sensitive).toBe(true);
  expect(same.hash_seed_sensitive).toBe(false);
});

test("fuzz oracle: runMutants counts a rejection before and exactly at its target", async () => {
  const batch = await PyrefBatch.start();
  try {
    const identity = batch.handshake.identity;
    const baseline = await runBaseline([seed], [batch], identity);
    expect(baseline.mismatches).toEqual([]);
    const entries = seedViews(baseline.rows);
    expect(entries).toHaveLength(1);
    for (const target of [7, 6]) {
      const operator = signatureOperator(target);
      const run = await runMutants(1, [operator], entries, new Rng(1), [batch], identity);
      expect(run.operatorErrors).toEqual({});
      expect(run.findings).toEqual([]);
      expect(run.outcomes).toHaveLength(1);
      const outcome = run.outcomes[0]!;
      expect(outcome.channel).toBe("agree");
      expect(outcome.kind).toBe(target === 7 ? "masked" : "agree");
      for (const result of [outcome.harness, outcome.pyref]) {
        expect(result.result).toBe("nonconformant");
        expect(result.reason).toBe("sig/verify-failed");
        expect(result.step).toBe(6);
        expect(result.crash).toBeNull();
        expect(result.verdict_hex).not.toBeNull();
        expect(result.verdict_hex).not.toBe(baseline.rows[0]!.pyref.verdict_hex);
      }
      expect(outcome.harness.verdict_hex).toBe(outcome.pyref.verdict_hex);
      const counts = { planned: 1, targeted: 1, reached: target === 6 ? 1 : 0, noop: 0, unsupported: 0,
        masked: target === 7 ? 1 : 0, verdict_noop: 0, findings: 0 };
      expect(run.perStep).toEqual({ [`step-${target}`]: counts });
      expect(run.perOperator).toEqual({ [operator.name]: counts });
    }
  } finally { await batch.close(); }
}, 180_000);

test.serial("fuzz oracle: a leg rejection at its own step passes only an allowed code and packages unexpected findings", async () => {
  const leg = LEGS.find((candidate) => candidate.leg === "receipt-signature")!;
  const original = leg.classes.corruption!;
  const batch = await PyrefBatch.start();
  try {
    const identity = batch.handshake.identity;
    const baseline = await runBaseline([seed], [batch], identity);
    expect(baseline.mismatches).toEqual([]);
    const entries = seedViews(baseline.rows);
    expect(entries).toHaveLength(1);
    const control = await runLegs(entries, new Rng(1), [batch], identity);
    expect(control.operatorErrors).toEqual({});
    expect(control.perLeg["receipt-signature/corruption"]).toMatchObject({ pass: 1, masked: 0, unexpected: 0 });
    expect(control.findings.filter((finding) => finding.leg === "receipt-signature")).toEqual([]);

    leg.classes.corruption = (...args) => {
      const mutant = original(...args);
      return mutant === null ? null : { ...mutant, allowed: { ...mutant.allowed, codes: ["sig/verify-failed@7"] } };
    };
    const changed = await runLegs(entries, new Rng(1), [batch], identity);
    expect(changed.operatorErrors).toEqual({});
    expect(changed.perLeg["receipt-signature/corruption"]).toMatchObject({ pass: 0, masked: 0, unexpected: 1 });
    const findings = changed.findings.filter((finding) => finding.leg === "receipt-signature");
    expect(findings.map((finding) => [finding.class, finding.outcome, finding.channel])).toEqual([["corruption", "unexpected", "agree"]]);
    for (const result of [findings[0]!.harness, findings[0]!.pyref]) {
      expect(result.result).toBe("nonconformant");
      expect(result.reason).toBe("sig/verify-failed");
      expect(result.step).toBe(6);
    }
  } finally {
    leg.classes.corruption = original;
    await batch.close();
  }
}, 180_000);
