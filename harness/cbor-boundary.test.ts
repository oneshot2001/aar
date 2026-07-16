import { describe, expect, test } from "bun:test";
import { decodeCbor, encodeCbor, toHex } from "./cbor";

// D-56 regression: the 4-byte uint head wrote `value / 2^32` (always 0 after
// ToUint8 truncation) where `value >>> 24` belongs, silently zeroing the high
// byte of every uint in [2^24, 2^32) — the range containing every real Unix
// timestamp. Expected bytes below are RFC 8949 core-deterministic, computed
// independently (pyref dumps agrees on each).
const PINNED: readonly (readonly [number, string])[] = [
  [0, "00"],
  [23, "17"],
  [24, "1818"],
  [0xff, "18ff"],
  [0x100, "190100"],
  [0xffff, "19ffff"],
  [0x1_0000, "1a00010000"],
  [0xff_ffff, "1a00ffffff"],
  [0x100_0000, "1a01000000"],
  [0x1234_5678, "1a12345678"],
  [1_752_600_000, "1a68768dc0"], // lab-era Unix time
  [0xffff_ffff, "1affffffff"],
  [0x1_0000_0000, "1b0000000100000000"],
  [Number.MAX_SAFE_INTEGER, "1b001fffffffffffff"],
];

describe("CBOR unsigned-integer boundary encoding (D-56)", () => {
  for (const [value, hex] of PINNED) {
    test(`${value} encodes to ${hex} and round-trips`, () => {
      const encoded = encodeCbor(value);
      expect(toHex(encoded)).toBe(hex);
      expect(decodeCbor(encoded)).toBe(value);
    });
  }
});
