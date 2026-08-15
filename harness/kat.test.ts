import { describe, expect, test } from "bun:test";
import { decodeCbor, encodeCbor, equalBytes } from "./cbor";
import { verifySigned } from "./crypto";
import { buildFixtures } from "./fixtures";
import { buildClassBoundaryFixtures, buildTerminalOutcomeFixtures } from "./negative-fixtures";
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
  }, 30_000);
});
