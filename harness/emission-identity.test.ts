// D-86 step-9 emission identity and the D-87 history phase: the stateful KATs (moved
// here from verifier.test.ts), the six fuzz splits rebuilt from their recorded mutation,
// and the history usage errors (entry shape, rule 0) in the harness, the pyref library
// and the pyref CLI; the phase and witness orders the corpus cannot show (rule 0(b) over
// phase A, issuer before epoch coordinate by harness path).
import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { equalBytes, toHex } from "./cbor";
import { deterministicId } from "./crypto";
import { HISTORY_CONTRADICTS_ITSELF, HISTORY_CONTRADICTS_RECEIPT } from "./emission-identity";
import { expectUsageError, harnessPrior, pyrefCli, pyrefLibrary, RawJson, UsageCase, withBundle } from "./prior-state-probe";
import { buildStatefulFixtures, exactEntries, FUZZ_SPLITS, mutated, parseStatefulPrior, priorJson, StatefulFixture, statefulOptions } from "./stateful-fixtures";
import { emitFailureVerdict } from "./verdict";
import { failure, Obj, PriorEmission, verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;
const fixtures = buildStatefulFixtures();
const fixture = (name: string): StatefulFixture => fixtures.find((candidate) => candidate.name === name)!;
const stem = (fixture: StatefulFixture): string => join(root, "kats", fixture.descriptor.expected_code === null ? "positive" : "negative", "stateful", fixture.name);

describe("D-86 emission identity", () => {
  test("every stateful fixture returns its expected code and step; a conformant one has its expected observations and limits and not its absent observations", () => {
    for (const fixture of fixtures) {
      const result = verifyBundle(fixture.bundle, { evaluationTime: AT, ...(fixture.prior ? statefulOptions(fixture.prior) : {}) });
      expect(result.ok ? null : result.reason, fixture.name).toBe(fixture.descriptor.expected_code);
      if (!result.ok) { expect(result.step, fixture.name).toBe(fixture.descriptor.expected_step!); continue; }
      for (const [limit, value] of Object.entries(fixture.descriptor.expected_limits ?? {})) expect((result.verdict.limits as Obj)[limit], fixture.name).toBe(value);
      for (const observation of fixture.descriptor.expected_observations ?? []) expect(result.verdict.observations, fixture.name).toContain(observation);
      for (const observation of fixture.descriptor.absent_observations ?? []) expect(result.verdict.observations, fixture.name).not.toContain(observation);
    }
  });

  test("generated stateful files equal the in-memory fixtures; a fixture without prior state has no prior file", () => {
    for (const fixture of fixtures) {
      expect(equalBytes(readFileSync(`${stem(fixture)}.bundle.cbor`), fixture.bundle), fixture.name).toBe(true);
      if (fixture.prior) expect(JSON.parse(readFileSync(`${stem(fixture)}.prior.json`, "utf8")), fixture.name).toEqual(fixture.prior);
      else expect(existsSync(`${stem(fixture)}.prior.json`), fixture.name).toBe(false);
      expect(JSON.parse(readFileSync(`${stem(fixture)}.json`, "utf8")), fixture.name).toEqual(fixture.descriptor);
    }
  });

  test("each fuzz split rebuilds byte for byte from its recorded mutation and carries the recorded prior", () => {
    for (const [run, id] of FUZZ_SPLITS) {
      const fixture = fixtures.find((candidate) => candidate.name === `d86-fuzz-${id}`)!;
      const finding = join(root, "docs", "fuzz-runs", run, id);
      expect(equalBytes(readFileSync(join(finding, "bundle.cbor")), fixture.bundle), id).toBe(true);
      expect(JSON.parse(readFileSync(join(finding, "inputs.json"), "utf8")).prior_state, id).toEqual(fixture.prior);
      expect(fixture.descriptor.mutation_description, id).toContain(JSON.parse(readFileSync(join(finding, "both.json"), "utf8")).stable.detail);
    }
  });

  test("history contradicting itself (0a) or a carried receipt (0b) is a usage error whichever coordinate differs: harness throw, pyref ValueError (0b its UsageError subclass), pyref CLI exit 2 with no verdict", () => {
    const represent = fixture("d86-history-exact-represent");
    const exact = parseStatefulPrior(represent.prior!)[0]!;
    // Same receipt ID and digest, one coordinate moved: an issuer field, then two epoch fields.
    const moved: [string, PriorEmission][] = [
      ["issuer_seq", { ...exact, issuerSeq: exact.issuerSeq + 1 }],
      ["epoch_owner_kid", { ...exact, epochOwnerKid: new Uint8Array(32) }],
      ["epoch_seq", { ...exact, epochSeq: exact.epochSeq + 1 }],
    ];
    expectUsageError(represent.bundle, moved.flatMap(([field, entry]): UsageCase[] => [
      [`0a ${field}`, priorJson(entry, exact), HISTORY_CONTRADICTS_ITSELF, "ValueError"],
      [`0b ${field}`, priorJson(entry), HISTORY_CONTRADICTS_RECEIPT, "UsageError"],
    ]));
  });

  test("rule 0(b) outranks a phase-A failure: m-01770 fails phase A on its own, and with history contradicting one carried receipt it is a usage error, never a verdict", () => {
    const split = fixture("d86-fuzz-m-01770");
    const bare = verifyBundle(split.bundle, { evaluationTime: AT });
    expect(bare.ok ? null : [bare.reason, bare.step]).toEqual(["identity/coordinate-equivocation", 9]);
    const carried = exactEntries(split.bundle)[0]!;
    expectUsageError(split.bundle, [["0b over phase A", priorJson({ ...carried, issuerSeq: carried.issuerSeq + 1 }), HISTORY_CONTRADICTS_RECEIPT, "UsageError"]]);
  });

  test("a receipt whose issuer and epoch coordinates both equivocate fails on the issuer coordinate first (harness path), in phase A (step 9) and in the history phase (step 20)", () => {
    const source = fixture("d86-history-full-reobservation").bundle;
    const entries = exactEntries(source);
    const first = entries[0]!;
    // A later receipt from the same signer in the same epoch takes both of receipts[0]'s coordinates.
    const twin = entries.findIndex((entry, index) => index > 0 && equalBytes(entry.issuerKid, first.issuerKid) && equalBytes(entry.epochOwnerKid, first.epochOwnerKid) && entry.epochId === first.epochId);
    expect(twin).toBeGreaterThan(0);
    const both = mutated(source, twin, (value) => { (value.emission as Obj).issuer_seq = first.issuerSeq; (value.binding as Obj).epoch_seq = first.epochSeq; });
    const phaseA = verifyBundle(both, { evaluationTime: AT });
    expect(phaseA.ok ? null : [phaseA.reason, phaseA.step, phaseA.path]).toEqual(["identity/coordinate-equivocation", 9, "receipt.emission.issuer_seq"]);
    const history = priorJson({ ...first, receiptId: deterministicId("prior:both-coordinates-receipt"), envelopeDigest: deterministicId("prior:both-coordinates-envelope") });
    const phaseB = verifyBundle(source, { evaluationTime: AT, priorEmissions: parseStatefulPrior(history) });
    expect(phaseB.ok ? null : [phaseB.reason, phaseB.step, phaseB.path]).toEqual(["identity/coordinate-equivocation", 20, "receipt.emission.issuer_seq"]);
  });

  test("a malformed prior-state entry is a usage error at every entry point, with one message (E-06: no bool-as-uint verdict in pyref)", () => {
    const represent = fixture("d86-history-exact-represent");
    const exact = represent.prior!.prior_emissions![0]!;
    const label = "prior-state.prior_emissions[0]";
    const cases: UsageCase[] = [
      ...["issuer_seq", "epoch_id", "epoch_seq"].flatMap((key) => [false, true, -1, 1.5].map((value): UsageCase =>
        [`${key}=${value}`, { prior_emissions: [{ ...exact, [key]: value }] }, `${label}.${key} must be an unsigned integer <= 9007199254740991`, "ValueError"])),
      ["31-byte hex", { prior_emissions: [{ ...exact, issuer_kid: "ab".repeat(31) }] }, `${label}.issuer_kid must decode to exactly 32 bytes`, "ValueError"],
      ["extra key", { prior_emissions: [{ ...exact, note: 0 }] }, `${label}: unknown note`, "ValueError"],
    ];
    expectUsageError(represent.bundle, cases);
  });

  test("the prior-state top level is closed to prior_emissions, retained_epochs and entries at every entry point, with one message (E-11, D-87)", () => {
    const represent = fixture("d86-history-exact-represent");
    expectUsageError(represent.bundle, [
      ["prior_emissions null", { prior_emissions: null }, "prior-state.prior_emissions must be an array", "ValueError"],
      ["prior_emissions object", { prior_emissions: {} }, "prior-state.prior_emissions must be an array", "ValueError"],
      ["top-level array", [], "prior-state must be a JSON object", "ValueError"],
      ["top-level unknown key", { ...represent.prior, note: 1 }, "prior-state: unknown note", "ValueError"],
    ]);
    // A whole prior-state file, replay entries included, is still a prior state.
    const whole = { ...represent.prior, entries: [] };
    expect(verifyBundle(represent.bundle, { evaluationTime: AT, ...harnessPrior(whole) }).ok).toBe(true);
    withBundle(represent.bundle, (directory, bundle) => {
      expect(pyrefLibrary(directory, bundle, [whole])[0]!.slice(0, 2)).toEqual(["verdict", null]);
      expect(pyrefCli(directory, bundle, whole).exitCode).toBe(0);
    });
  });

  test("uint fields are compared by numeric value: integral JSON spellings verify like the integer at every entry point, the others are refused with one message (E-11)", () => {
    const represent = fixture("d86-history-exact-represent");
    // One unrelated entry (conformant against this bundle) with issuer_seq spelled as raw JSON.
    const text = (seq: string): RawJson => new RawJson(`{"prior_emissions": [{"issuer_kid": "${"ab".repeat(32)}", "issuer_seq": ${seq}, "epoch_owner_kid": "${"cd".repeat(32)}", "epoch_id": 1, "epoch_seq": 1, "receipt_id": "${"ef".repeat(32)}", "envelope_digest": "${"12".repeat(32)}"}]}`);
    const accepted = [["1", "1.0"], ["1", "1e0"], ["0", "-0.0"], ["9007199254740991", "9007199254740991.0"]] as const;
    withBundle(represent.bundle, (directory, bundle) => {
      const spellings = accepted.flat();
      const library = pyrefLibrary(directory, bundle, spellings.map(text));
      // [harness, pyref library, pyref CLI] prior_emissions_digest for each spelling.
      const digests = spellings.map((seq, index) => {
        const harness = verifyBundle(represent.bundle, { evaluationTime: AT, ...harnessPrior(text(seq)) });
        if (!harness.ok) throw new Error(`${seq}: harness ${harness.reason}`);
        expect(library[index]!.slice(0, 2), seq).toEqual(["verdict", null]);
        const cli = pyrefCli(directory, bundle, text(seq));
        expect(cli.exitCode, seq).toBe(0);
        return [toHex((harness.verdict.trust_policy as Obj).prior_emissions_digest as Uint8Array), library[index]![2], /prior_emissions_digest: ([0-9a-f]{64})/.exec(cli.stdout)?.[1]];
      });
      accepted.forEach(([integer, spelling], index) => {
        const [plain, spelled] = [digests[2 * index]!, digests[2 * index + 1]!];
        expect(new Set(plain).size, integer).toBe(1);
        expect(spelled, spelling).toEqual(plain);
      });
    });
    expectUsageError(represent.bundle, ["1.5", "-1.0", "9007199254740992.0", "1e400"].map((seq): UsageCase =>
      [seq, text(seq), "prior-state.prior_emissions[0].issuer_seq must be an unsigned integer <= 9007199254740991", "ValueError"]));
  }, 60_000);

  test("the typed boundary (verifyBundle and every verdict digest) refuses what pyref refuses and never decodes a string (E-11)", () => {
    const represent = fixture("d86-history-exact-represent");
    const entry = parseStatefulPrior(represent.prior!)[0]!;
    const label = "prior-state.prior_emissions[0]";
    const typed: [string, unknown, string][] = [
      ["bool uint", { ...entry, epochSeq: false }, `${label}.epoch_seq must be an unsigned integer <= 9007199254740991`],
      ["extra field", { ...entry, note: 0 }, `${label}: unknown note`],
      ["missing field", Object.fromEntries(Object.entries(entry).filter(([field]) => field !== "epochSeq")), `${label}: missing epoch_seq`],
      ["hex string", { ...entry, issuerKid: toHex(entry.issuerKid) }, `${label}.issuer_kid must be a 32-byte Uint8Array`],
      ["31 bytes", { ...entry, issuerKid: entry.issuerKid.slice(1) }, `${label}.issuer_kid must decode to exactly 32 bytes`],
    ];
    for (const [name, item, message] of typed) {
      const priorEmissions = [item as PriorEmission];
      expect(() => verifyBundle(represent.bundle, { evaluationTime: AT, priorEmissions }), name).toThrow(message);
      // The exported failure signer hashes the same history: it refuses before hashing.
      expect(() => emitFailureVerdict(new Uint8Array(), failure(2, "cbor/noncanonical"), { evaluationTime: AT, priorEmissions }), name).toThrow(message);
    }
    expect(() => verifyBundle(represent.bundle, { evaluationTime: AT, priorEmissions: {} as unknown as PriorEmission[] })).toThrow("prior-state.prior_emissions must be an array");
  });
});
