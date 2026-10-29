// D-87 fix round 2: CONFORMANCE section 5 cross-entry precedence (check (6) over every entry
// before check (7); within (7), entry order), and the early-failure row's companions (rule 0(b)
// refuses its history once step 9 runs). Harness, pyref library and pyref CLI via the shared probe.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toHex } from "./cbor";
import { deterministicId, domainHash } from "./crypto";
import { buildD87Fixtures } from "./d87-fixtures";
import { HISTORY_CONTRADICTS_RECEIPT } from "./emission-identity";
import { expectUsageError, harnessPrior } from "./prior-state-probe";
import { exactEntries } from "./stateful-fixtures";
import { Obj, verifyBundle } from "./verifier";

const AT = 1_735_689_800;
const fixtures = buildD87Fixtures();
const fixture = (name: string) => fixtures.find((candidate) => candidate.name === name)!;
const base = fixture("d87-retained-superset").bundle;
const zero = fixture("d87-retained-zero-receipts").bundle;
const kept = fixture("d87-retained-superset").prior!.retained_epochs![0]!;
const first = exactEntries(base)[0]!;
const unlisted = (issuerKid: Uint8Array) => ({ ...first, issuerKid, receiptId: deterministicId("d87:unlisted"), envelopeDigest: deterministicId("d87:unlisted") });

describe("D-87 early failure with contradicting history", () => {
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
