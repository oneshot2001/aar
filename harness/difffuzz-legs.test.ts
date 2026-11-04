import { expect, test } from "bun:test";
import { CborValue, decodeCbor, fromHex, toHex } from "./cbor";
import { deterministicId } from "./crypto";
import { BaselineRow, request, runBaseline } from "./difffuzz-baseline";
import { Side, compare, harnessSide, sideOf } from "./difffuzz-compare";
import { LEGS } from "./difffuzz-leg-table";
import { runLegs } from "./difffuzz-legs";
import { SeedEntry, seedViews } from "./difffuzz-mutants";
import { PyrefBatch } from "./difffuzz-pyref";
import { Rng } from "./difffuzz-rng";
import { Seed, loadSeeds } from "./difffuzz-seeds";
import { Obj } from "./mutate";
import { exactEntries, priorJson, statefulOptions, StatefulPriorJson } from "./stateful-fixtures";

const duplicate = "duplicate_exact";
const below = "sequence_below_observed_history";
const leg = LEGS.find((item) => item.leg === "outcome-independence")!;
const seeds = loadSeeds();
const stateful = (name: string): Seed => seeds.find((seed) => seed.path === `kats/positive/stateful/${name}.bundle.cbor`)!;
const observations = (side: Side): string[] => {
  expect(side.result).toBe("conformant");
  expect(side.verdict_hex).not.toBeNull();
  const envelope = decodeCbor(fromHex(side.verdict_hex!)) as CborValue[];
  return (decodeCbor(envelope[0] as Uint8Array) as Obj).observations as string[];
};
const historyObservations = (side: Side): string[] => observations(side).filter((value) => value === duplicate || value === below).sort();

async function evaluate(seed: Seed, bytes: Uint8Array, batch: PyrefBatch): Promise<BaselineRow> {
  const identity = batch.handshake.identity;
  const [response] = await batch.run([request("oracle", seed, bytes, null, identity)]);
  const harness = harnessSide(bytes, seed.options, identity); const pyref = sideOf(response!);
  expect(compare(harness, pyref)).toBe("agree");
  expect(harness.result).toBe("conformant");
  return { seed, harness, pyref };
}

async function checkRemoval(entry: SeedEntry, batch: PyrefBatch, allowed: string[], before: string[], after: string[]): Promise<void> {
  expect(compare(entry.row.harness, entry.row.pyref)).toBe("agree");
  expect(leg.applicable(entry.view.bundle, entry.view.policy)).toBe(true);
  const mutant = leg.classes.removal!(entry, new Rng(1), () => { throw new Error("removal needs no scratch files"); }, "oracle");
  expect(mutant).not.toBeNull();
  expect(mutant!.detail).toBe("terminal outcome_observation[7] removed");
  expect(mutant!.allowed.observationsMayDrop).toEqual(allowed);
  const result = await evaluate(entry.row.seed, mutant!.bytes, batch);
  for (const side of ["harness", "pyref"] as const) {
    expect(historyObservations(entry.row[side])).toEqual([...before].sort());
    expect(historyObservations(result[side])).toEqual([...after].sort());
    expect(observations(entry.row[side]).filter((value) => !observations(result[side]).includes(value))).toEqual(allowed);
  }
  const run = await runLegs([entry], new Rng(1), [batch], batch.handshake.identity);
  expect(run.perLeg["outcome-independence/removal"]!.pass).toBe(1);
  expect(run.counts.unexpected).toBe(0);
  expect(run.counts.split).toBe(0);
  expect(run.operatorErrors).toEqual({});
}

const cases: [string, Seed, string[], string[], string[]][] = [
  ["last exact witness", stateful("d86-partial-history-epoch-rollback"), [duplicate], [duplicate, below], [below]],
  ["nine exact witnesses remain", stateful("d86-history-full-reobservation"), [], [duplicate], [duplicate]],
  ["unremoved exact witness", stateful("d86-history-exact-represent"), [], [duplicate], [duplicate]],
  ["no prior history", seeds.find((seed) => seed.path === "kats/positive/bundle-valid-subset.cbor")!, [], [], []],
];
for (const [name, seed, allowed, before, after] of cases) {
  test(`fuzz leg oracle: ${name}`, async () => {
    const batch = await PyrefBatch.start();
    try {
      const baseline = await runBaseline([seed], [batch], batch.handshake.identity);
      expect(baseline.mismatches).toEqual([]);
      expect(baseline.count).toBe(1);
      await checkRemoval(seedViews(baseline.rows)[0]!, batch, allowed, before, after);
    } finally { await batch.close(); }
  });
}

async function checkPrior(seed: Seed, prior: StatefulPriorJson, allowed: string[], before: string[], after: string[]): Promise<void> {
  const batch = await PyrefBatch.start();
  try {
    const changed = { ...seed, inputs: { ...seed.inputs, prior_state: prior }, options: { ...seed.options, ...statefulOptions(prior) } };
    // These inputs have new verdict digests: evaluate both baselines afresh,
    // without comparing them to the original corpus row's pinned digest.
    const row = await evaluate(changed, changed.bundle, batch);
    await checkRemoval(seedViews([row])[0]!, batch, allowed, before, after);
  } finally { await batch.close(); }
}

for (const additional of [false, true]) {
  test(`fuzz leg oracle: uppercase history ids${additional ? " with unrelated prior entry" : ""}`, async () => {
    const seed = stateful("d86-partial-history-epoch-rollback");
    const leaf = exactEntries(seed.bundle)[7]!;
    const prior = priorJson(leaf, ...(additional ? [{ ...leaf,
      receiptId: deterministicId("oracle:unrelated-id"), envelopeDigest: deterministicId("oracle:unrelated-digest"),
      issuerKid: deterministicId("oracle:unrelated-issuer"), epochOwnerKid: deterministicId("oracle:unrelated-owner"),
    }] : []));
    for (const item of prior.prior_emissions!) item.receipt_id = item.receipt_id.toUpperCase();
    await checkPrior(seed, prior, [duplicate], [duplicate, below], [below]);
  });
}

for (const domain of ["issuer", "epoch"] as const) {
  test(`fuzz leg oracle: last ${domain}-only lower-sequence witness`, async () => {
    const seed = stateful("d86-history-full-reobservation");
    const entries = exactEntries(seed.bundle); const leaf = entries[7]!;
    expect(entries.length).toBe(10);
    entries[7] = { ...leaf, receiptId: deterministicId("oracle:higher-id"), envelopeDigest: deterministicId("oracle:higher-digest"),
      ...(domain === "issuer"
        ? { issuerSeq: 9_999_999, epochOwnerKid: deterministicId("oracle:other-owner") }
        : { epochSeq: 9_999_999, issuerKid: deterministicId("oracle:other-issuer") }),
    };
    expect(entries.filter((item) => toHex(item.receiptId) !== toHex(entries[7]!.receiptId)).length).toBe(9);
    await checkPrior(seed, priorJson(...entries), [below], [duplicate, below], [duplicate]);
  });
}

test("fuzz leg oracle: another non-duplicate lower-sequence witness prevents a drop", async () => {
  const seed = stateful("d86-history-full-reobservation");
  const entries = exactEntries(seed.bundle); const leaf = entries[7]!;
  entries[7] = { ...leaf, receiptId: deterministicId("oracle:higher-id"), envelopeDigest: deterministicId("oracle:higher-digest"),
    epochSeq: 9_999_999, issuerKid: deterministicId("oracle:other-issuer") };
  // Receipt 0 is no longer an exact duplicate and remains below the supplied epoch history.
  await checkPrior(seed, priorJson(...entries.slice(1)), [], [duplicate, below], [duplicate, below]);
});
