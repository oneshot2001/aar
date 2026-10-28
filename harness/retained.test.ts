// D-87 retained evidence and the history phase's external-replay class: every
// retained_epochs usage error with one message in the harness, the pyref library and
// the pyref CLI (section 5 order), the compatible-extension merge, no recursion into
// prior or replay state, and the supplied replay state judged at step 20.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { deterministicId, hash, id16 } from "./crypto";
import { artifacts, keepReceipts, mutateReceiptWhere, payload } from "./mutate";
import { expectUsageError, harnessPrior, pyrefCli, pyrefLibrary, UsageCase, withBundle } from "./prior-state-probe";
import { RETAINED_COORDINATES, RETAINED_RECEIPT_CONTRADICTION, RETAINED_UNLISTED } from "./retained";
import { buildD87Fixtures } from "./d87-fixtures";
import { exactEntries, priorJson, StatefulFixture } from "./stateful-fixtures";
import { Obj, verifyBundle } from "./verifier";

const AT = 1_735_689_800;
const fixtures = buildD87Fixtures();
const fixture = (name: string): StatefulFixture => fixtures.find((candidate) => candidate.name === name)!;
const edit = (bytes: Uint8Array, mutation: (bundle: Obj) => void): Uint8Array => { const bundle = decodeCbor(bytes, { strict: true }) as Obj; mutation(bundle); return encodeCbor(bundle); };
const carrier = (bytes: Uint8Array): Uint8Array => edit(bytes, (bundle) => keepReceipts(bundle, () => false));
// retained_epochs in the committed order: strictly sorted by SHA-256 of the bytes.
const retained = (...bundles: Uint8Array[]): string[] => bundles.map(toHex).sort((left, right) => toHex(hash(fromHex(left))) < toHex(hash(fromHex(right))) ? -1 : 1);
const LABEL = "prior-state.retained_epochs";

const superset = fixture("d87-retained-superset");
const base = superset.bundle;
const zero = fixture("d87-retained-zero-receipts").bundle;
const kept = fromHex(superset.prior!.retained_epochs![0]!);
const full = fixture("d87-retained-unretained-epoch").bundle; // carries every base receipt
const late = edit(kept, (bundle) => { (bundle.trust_inputs as Obj).evaluation_time = AT + 1; });
const fork = carrier(fixture("d87-retained-competing-manifest").bundle);
const event = carrier(fixture("d87-retained-conflicting-event").bundle);
// The epoch-42 carrier without its anchor_submitted event (and the anchor): a prefix of the retained chain.
const short = edit(kept, (bundle) => { artifacts(bundle).epoch_events = (artifacts(bundle).epoch_events as Obj[]).filter((entry) => payload(entry).event !== "anchor_submitted"); artifacts(bundle).anchors = []; });
const first = exactEntries(base)[0]!;
const prior = (...values: Parameters<typeof priorJson>) => priorJson(...values).prior_emissions!;
const usage = (label: string, value: unknown, message: string): UsageCase => [label, value, message, "UsageError"];

describe("D-87 retained evidence", () => {
  test("every retained_epochs usage error, in section 5 order, has one message in the harness, the pyref library and the pyref CLI (exit 2, no verdict)", () => {
    expectUsageError(zero, [
      usage("not an array", { retained_epochs: "00" }, `${LABEL} must be an array`),
      usage("more than 16 bundles", { retained_epochs: Array(17).fill("00") }, `${LABEL} must hold at most 16 bundles`),
      usage("not a string", { retained_epochs: [1] }, `${LABEL}[0] must be a hex string`),
      usage("not hex", { retained_epochs: ["zz"] }, `${LABEL}[0] is not valid hex`),
      usage("unsorted", { retained_epochs: retained(kept, fork).reverse() }, `${LABEL} must be strictly sorted and unique by SHA-256`),
      usage("duplicate", { retained_epochs: [toHex(kept), toHex(kept)] }, `${LABEL} must be strictly sorted and unique by SHA-256`),
      usage("fails at its own time", { retained_epochs: [toHex(fixture("d87-receipt-unindexed-in-bundle").bundle)] }, `${LABEL}[0] fails step 15 (manifest/receipt-unindexed)`),
      usage("later than now", { retained_epochs: [toHex(late)] }, `${LABEL}[0] evaluation time is later than the current evaluation time`),
      usage("conflicting manifests", { retained_epochs: retained(kept, fork) }, `${LABEL}[1] carries a manifest that conflicts with a retained manifest for the same owner and epoch`),
      usage("conflicting event chains", { retained_epochs: retained(kept, event) }, `${LABEL}[1] carries an epoch event chain that conflicts with a retained chain`),
      usage("prior entry vs retained receipt", { prior_emissions: prior({ ...first, issuerSeq: first.issuerSeq + 1 }), retained_epochs: [toHex(full)] }, RETAINED_RECEIPT_CONTRADICTION),
      usage("prior entry unlisted by a retained index", { prior_emissions: prior({ ...first, receiptId: deterministicId("d87:unlisted"), envelopeDigest: deterministicId("d87:unlisted") }), retained_epochs: [toHex(kept)] }, RETAINED_UNLISTED),
      usage("prior entry listed with other coordinates", { prior_emissions: prior({ ...first, issuerSeq: first.issuerSeq + 1, envelopeDigest: deterministicId("d87:other") }), retained_epochs: [toHex(kept)] }, RETAINED_COORDINATES),
    ]);
    expectUsageError(base, [usage("byte-identical to the current bundle", { retained_epochs: [toHex(base)] }, `${LABEL}[0] is byte-identical to the bundle being evaluated`)]);
  }, 120_000);

  test("more than 16 MiB in total is refused before any bundle is decoded (the bytes are not CBOR)", () => {
    const half = "00".repeat(8_388_609);
    expectUsageError(zero, [usage("17 MiB", { retained_epochs: [half, half] }, `${LABEL} must total at most 16777216 bytes`)]);
  }, 120_000);

  test("a compatible extension merges into the longer chain: a prefix carrier alone lets a divergent final event through, merged with the full chain it is epoch/fork", () => {
    const bundle = fixture("d87-retained-conflicting-event").bundle;
    withBundle(bundle, (directory, path) => {
      for (const [value, expected] of [[{ retained_epochs: [toHex(short)] }, null], [{ retained_epochs: retained(short, kept) }, "epoch/fork"]] as const) {
        const harness = verifyBundle(bundle, { evaluationTime: AT, ...harnessPrior(value) });
        expect(harness.ok ? null : [harness.reason, harness.step]).toEqual(expected === null ? null : [expected, 20]);
        expect(pyrefLibrary(directory, path, [value])[0]!.slice(0, 2)).toEqual(["verdict", expected]);
        const cli = pyrefCli(directory, path, value);
        expect(cli.exitCode).toBe(expected === null ? 0 : 1);
        expect(/retained_epochs_digest: ([0-9a-f]{64})/.exec(cli.stdout)?.[1]).toBe(toHex((harness.verdict!.trust_policy as Obj).retained_epochs_digest as Uint8Array));
      }
    });
  }, 120_000);

  test("no recursion into prior or replay state: a retained bundle is evaluated without them, so history that would fail it (equivocation on its receipt) does not", () => {
    const other = { ...first, receiptId: deterministicId("d87:other-receipt"), envelopeDigest: deterministicId("d87:other-envelope"), epochOwnerKid: deterministicId("d87:other-owner") };
    const value = { prior_emissions: prior(other), retained_epochs: [toHex(full)], entries: [{ replay_domain: toHex(deterministicId("d87:domain")), invocation_id: toHex(id16("d87:invocation")), content_digest: toHex(deterministicId("d87:content")) }] };
    withBundle(zero, (directory, path) => {
      expect(verifyBundle(zero, { evaluationTime: AT, ...harnessPrior(value) }).ok).toBe(true);
      expect(pyrefCli(directory, path, value).exitCode).toBe(0);
    });
    // The same entry against a bundle that carries that receipt is history-phase equivocation.
    const carried = verifyBundle(base, { evaluationTime: AT, ...harnessPrior({ prior_emissions: prior(other) }) });
    expect(carried.ok ? null : [carried.reason, carried.step]).toEqual(["identity/coordinate-equivocation", 20]);
  }, 60_000);

  test("the rule-0 row is the v0.3.1 d82-chain-two-levels bytes and the history-independence row is graph-dangling-parent", () => {
    expect(toHex(hash(fixture("d87-receipt-unindexed-in-bundle").bundle))).toBe("09a17bd25a6e85de5d794c6a068fe17ba3f1742516927581d86de5a16ff00f57");
    expect(toHex(fixture("d87-history-independence-dangling-parent").bundle)).toBe(toHex(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "kats", "negative", "graph-dangling-parent.cbor"))));
  });

  test("typed boundary: retainedEpochs needs priorEmissions and byte arrays", () => {
    expect(() => verifyBundle(base, { evaluationTime: AT, retainedEpochs: [kept] })).toThrow(`${LABEL} requires priorEmissions`);
    expect(() => verifyBundle(base, { evaluationTime: AT, priorEmissions: [], retainedEpochs: [toHex(kept) as unknown as Uint8Array] })).toThrow(`${LABEL}[0] must be a Uint8Array`);
  });
});

describe("D-87 history phase: the supplied replay state", () => {
  // One root observation marked one_time (no journal, nothing else carried).
  const single = edit(base, (bundle) => {
    for (const field of ["epoch_events", "epoch_manifests", "anchors", "merkle_batches", "merkle_proofs"]) artifacts(bundle)[field] = [];
    keepReceipts(bundle, (value) => value.kind === "observation" && typeof value.root === "object" && value.root !== null);
    mutateReceiptWhere(bundle, () => true, (value) => { (value.freshness as Obj).use = "one_time"; });
  });
  const envelope = (decodeCbor(single, { strict: true }) as Obj).artifacts as Obj;
  const receipt = (envelope.receipts as Obj[])[0]!;
  const freshness = payload(receipt).freshness as Obj;
  const state = (digest: Uint8Array) => ({ entries: [{ replay_domain: toHex(freshness.replay_domain as Uint8Array), invocation_id: toHex(freshness.invocation_id as Uint8Array), content_digest: toHex(digest) }] });
  const harnessReplay = (digest: Uint8Array) => [{ replayDomain: freshness.replay_domain as Uint8Array, invocationId: freshness.invocation_id as Uint8Array, contentDigest: digest }];

  test("a one-time coordinate the supplied replay state holds with other content is replay/one-time-reused at step 20 (moved from 11); the same content is a duplicate", () => {
    const same = hash(encodeCbor(receipt as unknown as Obj));
    withBundle(single, (directory, path) => {
      for (const [digest, expected] of [[deterministicId("d87:other-content"), "replay/one-time-reused"], [same, null]] as const) {
        const harness = verifyBundle(single, { evaluationTime: AT, replayState: harnessReplay(digest) });
        expect(harness.ok ? null : [harness.reason, harness.step]).toEqual(expected === null ? null : [expected, 20]);
        const cli = pyrefCli(directory, path, state(digest));
        expect(cli.exitCode).toBe(expected === null ? 0 : 1);
        if (expected !== null) expect(cli.stdout).toContain(`First failure: step 20 (${expected})`);
        if (expected !== null) expect(cli.stdout).toMatch(/20 FAIL +History and verdict/);
      }
    });
  }, 60_000);
});
