// Synthetic reporting test (fix-first A.6): the real aggregation and formatter
// are fed one leg split, one unexpected leg outcome, one removal-accepted, one
// CLI disagreement and one leg operator error; each must reach the accept line
// with the right count, in the right field or channel.
import { expect, test } from "bun:test";
import type { StepCounts } from "./difffuzz-mutants";
import { aggregate, formatAccept, zeroLegCounts } from "./difffuzz-report";

const step = (planned: number, targeted: number, noop: number, unsupported: number): StepCounts => ({ planned, targeted, reached: targeted, noop, unsupported, masked: 0, verdict_noop: 0, findings: 0 });

test("a leg split, an unexpected outcome, a removal-accepted, a CLI disagreement and an operator error all reach the accept line", () => {
  const legCounts = { ...zeroLegCounts(), pass: 10, masked: 1, split: 1, unexpected: 1, "removal-accepted": 1, unsupported: 3, "operator-error": 1 };
  const summary = aggregate({
    seed: 7,
    perStep: { raw: step(4, 4, 0, 0), "step-6": step(3, 2, 1, 0), generic: step(3, 2, 0, 1) },
    mutantFindings: [],
    legs: { counts: legCounts, findings: [{ channel: "classification", outcome: "split" }, { channel: "agree", outcome: "unexpected" }, { channel: "agree", outcome: "removal-accepted" }] },
    cli: { rows: [{ disagreement: false }, { disagreement: true }, { disagreement: false }], notApplicable: 2 },
    controls: { fired: 8, total: 8 }, baseline: { reproduced: 513, seeds: 513 },
    saturation: { percent: 70.2, sites: 366, excluded: 4 }, hashSeedSensitive: 0,
  });
  expect(summary.channels.classification).toBe(1);      // the leg split landed in its comparison channel
  expect(summary.channels.bytes + summary.channels.crash).toBe(0);
  expect(summary.legs!.finding).toBe(1);                 // removal-accepted counts as a finding; unexpected does not
  expect(summary.executed).toBe(8); expect(summary.planned).toBe(10); expect(summary.noop).toBe(1); expect(summary.unsupported).toBe(1);
  const line = formatAccept(summary);
  expect(line).toBe("accept: seed 7, planned 10 / executed 8 / no-op 1 / unsupported 1 mutants, bytes/classification/crash = 0/1/0, controls 8/8, baseline 513/513, legs pass/masked/finding/unexpected/unsupported/operator-error = 10/1/1/1/3/1, cli disagreements = 1 of 3, saturation 70.2 % of 366 sites (4 excluded), hash-seed-sensitive = 0");
});

test("a mutant crash and a leg bytes split land in different channels; a clean run reads 0/0/0", () => {
  const base = { seed: 1, perStep: { raw: step(2, 2, 0, 0) }, controls: { fired: 8, total: 8 }, baseline: { reproduced: 513, seeds: 513 }, saturation: null, hashSeedSensitive: 1, cli: null } as const;
  const dirty = aggregate({ ...base, mutantFindings: [{ channel: "crash" }], legs: { counts: { ...zeroLegCounts(), split: 1 }, findings: [{ channel: "bytes", outcome: "split" }] } });
  expect([dirty.channels.bytes, dirty.channels.classification, dirty.channels.crash]).toEqual([1, 0, 1]);
  expect(formatAccept(dirty)).toContain("bytes/classification/crash = 1/0/1");
  expect(formatAccept(dirty)).toContain("cli not run");
  const clean = aggregate({ ...base, mutantFindings: [], legs: null, hashSeedSensitive: 0 });
  expect(formatAccept(clean)).toBe("accept: seed 1, planned 2 / executed 2 / no-op 0 / unsupported 0 mutants, bytes/classification/crash = 0/0/0, controls 8/8, baseline 513/513, legs not run, cli not run, saturation not measured, hash-seed-sensitive = 0");
});
