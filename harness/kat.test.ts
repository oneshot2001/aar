import { describe, expect, test } from "bun:test";
import { CborValue, decodeCbor, encodeCbor, equalBytes, toHex } from "./cbor";
import { verifySigned } from "./crypto";
import { buildFixtures } from "./fixtures";
import { buildD78ReportVariants, buildD78Fixtures, buildD77PositiveFixtures, buildClassBoundaryFixtures, buildEvidenceCommitFixtures, buildTerminalOutcomeFixtures } from "./negative-fixtures";
import { buildCountersignFixtures } from "./countersign-fixtures";
import { TEST_KEYS } from "./testkeys";
import { verifyBundle } from "./verifier";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
// Explicit evaluation time for failure verdicts on inputs whose trust_inputs are
// unreadable (caller-supplied always; the wall clock is never read — pyref --at symmetry). Matches the fixture corpus.
const AT = 1_735_689_800;

describe("positive KAT harness", () => {
  test("generation is byte-for-byte deterministic", () => {
    const first = buildFixtures();
    const second = buildFixtures();
    expect(first.kats.map((kat) => kat.filename)).toEqual(second.kats.map((kat) => kat.filename));
    for (let index = 0; index < first.kats.length; index += 1) {
      expect(equalBytes(first.kats[index]!.bytes, second.kats[index]!.bytes)).toBe(true);
      expect(first.kats[index]!.descriptor).toEqual(second.kats[index]!.descriptor);
    }
  });

  test("D-77 positive repairs remain conformant and deterministic", () => {
    const first = buildD77PositiveFixtures(); const second = buildD77PositiveFixtures();
    for (const [index, fixture] of first.entries()) {
      expect(equalBytes(fixture.bytes, second[index]!.bytes)).toBe(true);
      expect(equalBytes(fixture.bytes, readFileSync(join(root, "kats", "positive", `${fixture.filename}.cbor`)))).toBe(true);
      expect(JSON.parse(readFileSync(join(root, "kats", "positive", `${fixture.filename}.json`), "utf8"))).toEqual(fixture.descriptor);
      expect(verifyBundle(fixture.bytes, { evaluationTime: AT }).result).toBe(fixture.descriptor.expected_result);
    }
  });

  test("D-78 reports include undispatched attempts without signing their declarations and deduplicate diamonds", () => {
    for (const fixture of buildD78ReportVariants()) {
      const result = verifyBundle(fixture.bytes, { evaluationTime: AT });
      expect(result.ok, fixture.name).toBe(true);
      if (!result.ok) continue;
      expect((result.verdict.limits as Record<string, string>).input_origin_ancestry, fixture.name).toBe(fixture.limit);
      const report = result.report.input_origin_ancestry;
      expect(report.attempts.map((row) => row.dispatched), fixture.name).toEqual(fixture.dispatched);
      for (const row of report.attempts) {
        expect(row.declared_origins, fixture.name).toEqual(["principal", "third_party"]);
        expect(row.undeclared_slots, fixture.name).toBe(2);
      }
      expect(result.observations.includes("untrusted_origin_declared_in_action_ancestry"), fixture.name).toBe(fixture.dispatched.includes(true));
    }
  });

  test("verification CLI labels stateful and empty-scope observations as unsigned", () => {
    for (const [filename, empty] of [["positive/bundle-valid-subset", false], ["class-boundary/origin-no-input-ancestor", true]] as const) {
      const proc = Bun.spawnSync(["bun", "run", "harness/verify.ts", `kats/${filename}.cbor`, "--at", String(AT)], { cwd: root });
      expect(proc.exitCode, proc.stderr.toString()).toBe(0);
      const output = proc.stdout.toString();
      expect(output).toContain("  - stateful_not_evaluated [report layer; not signed]");
      expect(output.includes("  - empty_scope [report layer; not signed]")).toBe(empty);
      const hex = output.match(/^Signed verdict CBOR hex: ([a-f0-9]+)$/m)![1]!;
      const envelope = decodeCbor(Uint8Array.from(Buffer.from(hex, "hex")), { strict: true }) as Uint8Array[];
      const verdict = decodeCbor(envelope[0]!, { strict: true }) as Record<string, CborValue>;
      expect(verdict.observations).not.toContain("stateful_not_evaluated");
      expect(verdict.observations).not.toContain("empty_scope");
    }
  });

  test("D-78 fixtures match files, classes, observations, and first failures", () => {
    const first = buildD78Fixtures(); const second = buildD78Fixtures();
    for (const [index, fixture] of first.entries()) {
      expect(equalBytes(fixture.bytes, second[index]!.bytes), fixture.filename).toBe(true);
      expect(equalBytes(fixture.bytes, readFileSync(join(root, "kats", fixture.directory, `${fixture.filename}.cbor`))), fixture.filename).toBe(true);
      expect(JSON.parse(readFileSync(join(root, "kats", fixture.directory, `${fixture.filename}.json`), "utf8"))).toEqual(fixture.descriptor);
      const result = verifyBundle(fixture.bytes, { evaluationTime: AT });
      expect(result.result, fixture.filename).toBe(fixture.descriptor.expected_result);
      if (!result.ok) {
        expect(result.reason === fixture.descriptor.expected_code, fixture.filename).toBe(true);
        expect(result.step, fixture.filename).toBe(fixture.descriptor.expected_step!);
        expect(result.verdict!.observations).toEqual([]);
        expect((result.verdict!.limits as Record<string, string>).input_origin_ancestry).toBe("not_evaluated");
      } else {
        expect((result.verdict.limits as Record<string, string>).input_origin_ancestry, fixture.filename).toBe(fixture.descriptor.expected_class);
        for (const observation of fixture.descriptor.expected_observations) expect(result.observations.includes(observation), fixture.filename).toBe(true);
        for (const observation of fixture.descriptor.absent_observations) expect(result.observations.includes(observation), fixture.filename).toBe(false);
        const rows = result.report.input_origin_ancestry.attempts;
        if (fixture.filename === "origin-two-attempts-distinct-sets") {
          const bundle = decodeCbor(fixture.bytes, { strict: true }) as Record<string, any>;
          const receipts = bundle.artifacts.receipts.map((envelope: Uint8Array[]) => decodeCbor(envelope[0]!, { strict: true })) as Record<string, any>[];
          const dispatchOrder = receipts.filter((receipt) => receipt.kind === "dispatch").map((receipt) => toHex(receipt.body.attempt_id));
          expect(rows.map((row) => row.attempt_id)).toEqual(dispatchOrder);
          expect(rows.map((row) => row.dispatched)).toEqual([true, true]);
          expect(rows.map((row) => row.declared_origins).sort()).toEqual([["principal"], ["third_party"]]);
          expect(rows.map((row) => row.undeclared_slots)).toEqual([0, 0]);
        } else expect(rows).toHaveLength(1);
        if (fixture.filename === "origin-aar3-refused-and-untrusted") expect(result.verdict.observations).toEqual(fixture.descriptor.expected_observations);
        const row = rows[0]!;
        expect(row.undeclared_slots, fixture.filename).toBe(fixture.filename === "d78-origin-third-party-retrieval" || fixture.filename === "origin-unknown-only" || fixture.filename === "origin-cross-epoch-ancestry" ? 2 : fixture.filename === "origin-all-discarded" || fixture.filename === "origin-outcome-supports-ancestry" ? 1 : 0);
      }
    }
  });

  test("every KAT strict-decodes and round-trips exactly", () => {
    for (const kat of buildFixtures().kats) {
      const value = decodeCbor(kat.bytes, { strict: true, maxDepth: 32 });
      expect(equalBytes(encodeCbor(value), kat.bytes), kat.filename).toBe(true);
    }
  });

  test("every detached signature is valid P1363 low-S ES256", () => {
    for (const check of buildFixtures().signatures) {
      expect(verifySigned(check.envelopeBytes, TEST_KEYS[check.signer]), check.name).toBe(true);
    }
  });

  test("every normative content-derived value recomputes", () => {
    for (const check of buildFixtures().derived) {
      expect(equalBytes(check.expected, check.recompute()), check.name).toBe(true);
    }
  });

  test("RFC 6962 and AAR Merkle proofs verify", () => {
    for (const proof of buildFixtures().proofs) {
      expect(proof.verify(), proof.name).toBe(true);
    }
  });

  test("class-boundary KATs have their exact rejection or supported-class outcome", () => {
    for (const fixture of buildClassBoundaryFixtures()) {
      const result = verifyBundle(fixture.bytes, { evaluationTime: AT });
      if (fixture.descriptor.expectation === "reject") {
        expect(result.ok, fixture.filename).toBe(false);
        if (!result.ok) expect(result.reason, fixture.filename).toBe(fixture.descriptor.expected_code);
      } else {
        expect(result.ok, fixture.filename).toBe(true);
        if (result.ok) {
          const limits = result.verdict.limits as Record<string, string>;
          expect(Object.values(limits).includes(fixture.descriptor.expected_class!), fixture.filename).toBe(true);
        }
      }
    }
  });

  test("class-boundary generation is deterministic and matches generated files", () => {
    const first = buildClassBoundaryFixtures(); const second = buildClassBoundaryFixtures();
    expect(first.map((fixture) => fixture.filename)).toEqual(second.map((fixture) => fixture.filename));
    for (let index = 0; index < first.length; index += 1) {
      const fixture = first[index]!;
      expect(equalBytes(fixture.bytes, second[index]!.bytes), fixture.filename).toBe(true);
      expect(equalBytes(fixture.bytes, readFileSync(join(root, "kats", "class-boundary", `${fixture.filename}.cbor`))), fixture.filename).toBe(true);
      expect(JSON.parse(readFileSync(join(root, "kats", "class-boundary", `${fixture.filename}.json`), "utf8")), fixture.filename).toEqual(fixture.descriptor);
    }
  });

  test("terminal outcome aggregation is order-independent and matches generated files", () => {
    const first = buildTerminalOutcomeFixtures(); const second = buildTerminalOutcomeFixtures();
    expect(first.map((fixture) => fixture.filename)).toEqual(second.map((fixture) => fixture.filename));
    for (let index = 0; index < first.length; index += 1) {
      const fixture = first[index]!;
      expect(equalBytes(fixture.bytes, second[index]!.bytes), fixture.filename).toBe(true);
      expect(equalBytes(fixture.bytes, readFileSync(join(root, "kats", "terminal-state", `${fixture.filename}.cbor`))), fixture.filename).toBe(true);
      expect(JSON.parse(readFileSync(join(root, "kats", "terminal-state", `${fixture.filename}.json`), "utf8")), fixture.filename).toEqual(fixture.descriptor);
      const result = verifyBundle(fixture.bytes, { evaluationTime: AT });
      expect(result.ok, fixture.filename).toBe(true);
      if (result.ok) {
        const limits = result.verdict.limits as Record<string, string>;
        expect(limits.maximum_outcome_level, fixture.filename).toBe(fixture.descriptor.expected_class);
      }
      const bundle = decodeCbor(fixture.bytes, { strict: true }) as Record<string, CborValue>;
      const artifacts = bundle.artifacts as Record<string, CborValue>;
      const receipts = (artifacts.receipts as CborValue[]).map((entry) => decodeCbor((entry as CborValue[])[0] as Uint8Array, { strict: true }) as Record<string, CborValue>);
      const levels = receipts.map((receipt) => ((receipt.evidence as Record<string, CborValue>).outcome as Record<string, CborValue> | undefined)?.level);
      if (fixture.descriptor.terminal_order === "unknown_before_ranked") {
        expect(levels.indexOf("unknown"), fixture.filename).toBeLessThan(levels.indexOf("dispatched"));
      } else {
        const terminals = levels.filter((level) => level === "contradicted" || level === "unknown");
        expect(`${terminals[0]}_before_${terminals[1]}`, fixture.filename).toBe(fixture.descriptor.terminal_order);
      }
    }
  }, 180_000);

  test("D-66/D-69 evidence-commit fixtures match files and exact verdict behavior", () => {
    const first = buildEvidenceCommitFixtures(); const second = buildEvidenceCommitFixtures();
    expect(first).toHaveLength(6);
    for (let index = 0; index < first.length; index += 1) {
      const fixture = first[index]!;
      expect(equalBytes(fixture.bytes, second[index]!.bytes), fixture.filename).toBe(true);
      expect(equalBytes(fixture.bytes, readFileSync(join(root, "kats", "evidence-commit", `${fixture.filename}.cbor`))), fixture.filename).toBe(true);
      expect(JSON.parse(readFileSync(join(root, "kats", "evidence-commit", `${fixture.filename}.json`), "utf8")), fixture.filename).toEqual(fixture.descriptor);
      const result = verifyBundle(fixture.bytes, { evaluationTime: AT });
      if (fixture.descriptor.expectation === "nonconformant") {
        expect(result.ok, fixture.filename).toBe(false);
        if (!result.ok) {
          expect(result.reason, fixture.filename).toBe(fixture.descriptor.expected_code);
          expect(result.step, fixture.filename).toBe(
            fixture.descriptor.expected_code === "receipt/hazard-class-unbound" ? 10 : 13,
          );
        }
      } else {
        expect(result.ok, fixture.filename).toBe(true);
        if (result.ok) for (const observation of fixture.descriptor.expected_observations) {
          expect(result.observations.includes(observation), `${fixture.filename}:${observation}`).toBe(true);
        }
      }
    }
  }, 180_000);

  test("D-67 fixtures are deterministic and have exact countersign behavior", () => {
    const first = buildCountersignFixtures(); const second = buildCountersignFixtures();
    expect(first).toHaveLength(4);
    for (let index = 0; index < first.length; index += 1) {
      const fixture = first[index]!;
      expect(equalBytes(fixture.bytes, second[index]!.bytes), fixture.filename).toBe(true);
      expect(equalBytes(fixture.bytes, readFileSync(join(root, "kats", "countersign", `${fixture.filename}.cbor`))), fixture.filename).toBe(true);
      expect(JSON.parse(readFileSync(join(root, "kats", "countersign", `${fixture.filename}.json`), "utf8")), fixture.filename).toEqual(fixture.descriptor);
      const result = verifyBundle(fixture.bytes, { evaluationTime: AT });
      expect(result.result, fixture.filename).toBe(fixture.descriptor.expectation);
      if (!result.ok) {
        expect(result.reason, fixture.filename).toBe(fixture.descriptor.expected_code);
        expect(result.step, fixture.filename).toBe(
          fixture.descriptor.expected_code === "countersign/credential-invalid" ? 6 : 10,
        );
      } else if (fixture.filename.endsWith("valid")) {
        expect(result.observations.includes("mediator_countersigned"), fixture.filename).toBe(true);
      } else {
        expect(result.observations.includes("mediator_countersigned"), fixture.filename).toBe(false);
      }
    }
  }, 180_000);
});
