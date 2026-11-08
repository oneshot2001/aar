import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { decodeCbor, fromHex, toHex } from "./cbor";
import { deterministicId } from "./crypto";
import { compare, harnessSide, sideOf } from "./difffuzz-compare";
import { PyrefBatch, root } from "./difffuzz-pyref";
import { AT } from "./difffuzz-seeds";
import { Obj, payload, receiptList } from "./mutate";
import { exactEntries, priorJson, statefulOptions, StatefulPriorJson } from "./stateful-fixtures";
import { PriorEmission, ReplayUse } from "./verifier";

const bundle = readFileSync(join(root, "kats/positive/bundle-valid-subset.cbor"));
const own = exactEntries(bundle)[0]!;
const below = "sequence_below_observed_history";
const other = {
  receiptId: deterministicId("history keys: other receipt"),
  envelopeDigest: deterministicId("history keys: other digest"),
  issuerKid: deterministicId("history keys: other issuer"),
};
const otherOwner = deterministicId("history keys: other owner");

async function evaluate(batch: PyrefBatch, prior: StatefulPriorJson = {}, replay: ReplayUse[] = []) {
  const identity = batch.handshake.identity;
  const harness = harnessSide(bundle, { evaluationTime: AT, ...statefulOptions(prior), replayState: replay }, identity);
  const [response] = await batch.run([{
    id: "history keys", bundle_hex: toHex(bundle), context_hex: null, identity,
    inputs: {
      evaluated_at: AT, prior_state: prior,
      replay_state: { entries: replay.map((entry) => ({
        replay_domain: toHex(entry.replayDomain), invocation_id: toHex(entry.invocationId), content_digest: toHex(entry.contentDigest),
      })) },
      policy: null, signing_key: null, trust_policy: null,
    },
  }]);
  const pyref = sideOf(response!);
  expect(compare(harness, pyref)).toBe("agree");
  return [harness, pyref];
}

// Isolate the epoch domain from the issuer domain with a distinct signing kid.
// The last two rows instead isolate the issuer domain with an unrelated owner.
const sequenceCases: [string, Partial<PriorEmission>, boolean][] = [
  ["another epoch id does not establish lower sequence", { epochId: own.epochId + 1 }, false],
  ["another epoch owner does not establish lower sequence", { epochOwnerKid: otherOwner }, false],
  ["the same owner and epoch id establish lower sequence", {}, true],
  ["another signing kid does not establish lower sequence", { epochOwnerKid: otherOwner, issuerSeq: 9_999_999 }, false],
  ["the receipt's signing kid establishes lower sequence", { epochOwnerKid: otherOwner, issuerSeq: 9_999_999, issuerKid: own.issuerKid }, true],
];

for (const [name, changes, expectedBelow] of sequenceCases) {
  test(`history keys: ${name}`, async () => {
    const batch = await PyrefBatch.start();
    try {
      expect(own.epochId).toBe(42);
      const prior = priorJson({ ...own, ...other, epochSeq: 9_999_999, ...changes });
      for (const side of await evaluate(batch, prior)) {
        expect(side.result).toBe("conformant");
        const observations = payload(decodeCbor(fromHex(side.verdict_hex!))).observations as string[];
        expect(observations.includes(below)).toBe(expectedBelow);
      }
    } finally { await batch.close(); }
  }, 180_000);
}

for (const coordinate of ["issuerSeq", "epochSeq"] as const) {
  test(`history keys: same id with another digest and changed ${coordinate} is reuse at step 20`, async () => {
    const batch = await PyrefBatch.start();
    try {
      const prior = priorJson({ ...own, envelopeDigest: other.envelopeDigest, [coordinate]: own[coordinate] + 1000 });
      for (const side of await evaluate(batch, prior)) {
        expect(side.result).toBe("nonconformant");
        expect(side.reason).toBe("identity/reuse");
        expect(side.step).toBe(20);
      }
    } finally { await batch.close(); }
  }, 180_000);
}

test("history keys: reusable receipt ignores a conflicting replay entry", async () => {
  const batch = await PyrefBatch.start();
  try {
    const receipt = payload(receiptList(decodeCbor(bundle) as Obj)[0]!);
    const freshness = receipt.freshness as Obj;
    expect(freshness.use).toBe("reusable");
    const replay = [{
      replayDomain: freshness.replay_domain as Uint8Array,
      invocationId: freshness.invocation_id as Uint8Array,
      contentDigest: fromHex("ff".repeat(32)),
    }];
    expect(toHex(replay[0]!.contentDigest)).not.toBe(toHex(own.envelopeDigest));
    for (const side of await evaluate(batch, {}, replay)) expect(side.result).toBe("conformant");
  } finally { await batch.close(); }
}, 180_000);
