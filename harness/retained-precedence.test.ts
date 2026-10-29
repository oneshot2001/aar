// D-87 fix round 2: CONFORMANCE section 5 cross-entry precedence (check (6) over every entry
// before check (7); within (7), entry order), and the early-failure row's companions (rule 0(b)
// refuses its history once step 9 runs). Harness, pyref library and pyref CLI via the shared probe.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fromHex, toHex } from "./cbor";
import { deterministicId, domainHash, hash } from "./crypto";
import { buildD87Fixtures } from "./d87-fixtures";
import { HISTORY_CONTRADICTS_RECEIPT } from "./emission-identity";
import { expectUsageError, harnessPrior } from "./prior-state-probe";
import { RETAINED_COORDINATES, RETAINED_RECEIPT_CONTRADICTION } from "./retained";
import { exactEntries, priorJson } from "./stateful-fixtures";
import { Obj, verifyBundle } from "./verifier";

const AT = 1_735_689_800;
const fixtures = buildD87Fixtures();
const fixture = (name: string) => fixtures.find((candidate) => candidate.name === name)!;
const base = fixture("d87-retained-superset").bundle;
const zero = fixture("d87-retained-zero-receipts").bundle;
const kept = fixture("d87-retained-superset").prior!.retained_epochs![0]!;
const first = exactEntries(base)[0]!;
const unlisted = (issuerKid: Uint8Array) => ({ ...first, issuerKid, receiptId: deterministicId("d87:unlisted"), envelopeDigest: deterministicId("d87:unlisted") });

describe("D-87 section 5 cross-entry precedence", () => {
  test("check (6) over every entry before check (7): a later retained-receipt contradiction beats an earlier unlisted entry; within (7), an earlier miscoordinated entry beats a later unlisted one", () => {
    const sixOverSeven = priorJson(unlisted(new Uint8Array(32)), { ...first, issuerSeq: first.issuerSeq + 1 });
    const sevenInOrder = priorJson({ ...first, issuerSeq: first.issuerSeq + 1, envelopeDigest: deterministicId("d87:other") }, unlisted(new Uint8Array(32).fill(0xff)));
    // Committed order puts the entry the wrong implementation would report first.
    expect(sixOverSeven.prior_emissions![0]!.receipt_id).toBe(toHex(deterministicId("d87:unlisted")));
    expect(sevenInOrder.prior_emissions![1]!.receipt_id).toBe(toHex(deterministicId("d87:unlisted")));
    expectUsageError(zero, [
      ["(6) before (7)", { ...sixOverSeven, retained_epochs: [toHex(base)] }, RETAINED_RECEIPT_CONTRADICTION, "UsageError"],
      ["(7) in entry order", { ...sevenInOrder, retained_epochs: [kept] }, RETAINED_COORDINATES, "UsageError"],
    ]);
  }, 120_000);

  test("compound order: (2) sorting before (3) byte-identity, (3) before (4) steps, (5) merge before (6) and (7)", () => {
    const digest = (hex: string): string => toHex(hash(fromHex(hex)));
    const sorted = (...hexes: string[]): string[] => [...hexes].sort((left, right) => digest(left) < digest(right) ? -1 : 1);
    const current = toHex(zero);
    // (2) over (3): the current bundle's bytes in an unsorted list; sorted, the same list is (3).
    const unsorted = sorted(current, kept).reverse();
    // (3) over (4): a malformed bundle sorted before the current bundle's bytes (a per-bundle loop reports it first).
    const malformed = Array.from({ length: 256 }, (_, index) => `a16161${index.toString(16).padStart(2, "0")}`).find((hex) => digest(hex) < digest(current))!;
    // (5) over (6) and (7): two retained epoch-42 manifests that differ, plus an entry contradicting a retained receipt and one unlisted entry.
    const merge = sorted(toHex(base), toHex(fixture("d87-retained-competing-manifest").bundle));
    const history = priorJson({ ...first, issuerSeq: first.issuerSeq + 1 }, unlisted(new Uint8Array(32))).prior_emissions;
    expect(sorted(malformed, current)).toEqual([malformed, current]);
    expectUsageError(zero, [
      ["(2) before (3)", { retained_epochs: unsorted }, "prior-state.retained_epochs must be strictly sorted and unique by SHA-256", "UsageError"],
      ["(3) alone, sorted", { retained_epochs: sorted(current, kept) }, `prior-state.retained_epochs[${sorted(current, kept).indexOf(current)}] is byte-identical to the bundle being evaluated`, "UsageError"],
      ["(3) before (4)", { retained_epochs: [malformed, current] }, "prior-state.retained_epochs[1] is byte-identical to the bundle being evaluated", "UsageError"],
      ["(5) before (6) and (7)", { prior_emissions: history, retained_epochs: merge }, "prior-state.retained_epochs[1] carries a manifest that conflicts with a retained manifest for the same owner and epoch", "UsageError"],
    ]);
  }, 120_000);

  test("d87-history-early-failure: the hash-mismatch bytes, signed hash/mismatch@7 with the contradicting history bound; the same history on bundle-valid-subset is refused at step 9", () => {
    const row = fixture("d87-history-early-failure");
    expect(toHex(row.bundle)).toBe(toHex(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "kats", "negative", "hash-mismatch.cbor"))));
    const result = verifyBundle(row.bundle, { evaluationTime: AT, ...harnessPrior(row.prior) });
    expect(result.ok ? null : [result.reason, result.step]).toEqual(["hash/mismatch", 7]);
    const bound = toHex((result.verdict!.trust_policy as Obj).prior_emissions_digest as Uint8Array);
    expect(bound).toBe(toHex(domainHash("AAR-VERDICT-PRIOR-v1", { entries: harnessPrior(row.prior).priorEmissions!.map((entry) => ({
      issuer_kid: entry.issuerKid, issuer_seq: entry.issuerSeq, epoch_owner_kid: entry.epochOwnerKid, epoch_id: entry.epochId, epoch_seq: entry.epochSeq, receipt_id: entry.receiptId, envelope_digest: entry.envelopeDigest })) })));
    expectUsageError(base, [["rule 0(b) once step 9 runs", row.prior, HISTORY_CONTRADICTS_RECEIPT, "UsageError"]]);
  }, 60_000);
});
