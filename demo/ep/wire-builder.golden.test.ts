// Golden-digest guard for the RealNarrative byte-compatibility contract:
// with `narrative` omitted, buildDemoBundle must reproduce the pre-RealNarrative
// demo bundles byte-for-byte. Pinned inputs + pinned keys → pinned bundle hash.
// If this test breaks, either the compat contract broke (fix the code) or a
// deliberate wire-affecting demo change landed (re-pin BOTH digests and say so
// in the commit message).
import { describe, expect, test } from "bun:test";
import { toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import { goldenBundle } from "./golden";

describe("RealNarrative byte-compatibility (golden digests)", () => {
  test("S1 dispatch bundle bytes unchanged with narrative omitted", async () => {
    expect(toHex(hash(await goldenBundle("S1")))).toBe("40ad0055eab0330236a84d2908269c772a968e68c9451bc9b88eb6c192939b3d");
  });
  test("S3 refusal bundle bytes unchanged with narrative omitted", async () => {
    expect(toHex(hash(await goldenBundle("S3")))).toBe("ed84406891995dbefd0a4ad757a512f72adee41bdaafb271d43037c86f9449a2");
  });
});
