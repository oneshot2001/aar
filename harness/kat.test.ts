import { describe, expect, test } from "bun:test";
import { decodeCbor, encodeCbor, equalBytes } from "./cbor";
import { verifySigned } from "./crypto";
import { buildFixtures } from "./fixtures";
import { TEST_KEYS } from "./testkeys";

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
});
