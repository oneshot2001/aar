import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeCbor, encodeCbor, equalBytes } from "./cbor";
import { buildNegativeFixtures } from "./negative-fixtures";
import { verifyBundleB1 } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("B1 reference verifier", () => {
  test("the slice-A bundle passes normative steps 1 through 11", () => {
    const result = verifyBundleB1(readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor")));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.result).toBe("steps-1-11-passed");
      expect(result.completedThrough).toBe(11);
      expect(result.nextStep).toBe(12);
    }
  });

  test("negative generation is byte-for-byte deterministic", () => {
    const first = buildNegativeFixtures();
    const second = buildNegativeFixtures();
    expect(first.map((fixture) => fixture.filename)).toEqual(second.map((fixture) => fixture.filename));
    for (let index = 0; index < first.length; index += 1) {
      expect(equalBytes(first[index]!.bytes, second[index]!.bytes), first[index]!.filename).toBe(true);
      expect(first[index]!.descriptor).toEqual(second[index]!.descriptor);
    }
  });

  test("every negative fixture returns exactly its first expected reason", () => {
    for (const fixture of buildNegativeFixtures()) {
      const result = verifyBundleB1(fixture.bytes);
      expect(result.ok, fixture.filename).toBe(false);
      if (!result.ok) expect(result.reason, fixture.filename).toBe(fixture.descriptor.expected_code);
    }
  });

  test("generated negative files and descriptors equal the in-memory fixtures", () => {
    for (const fixture of buildNegativeFixtures()) {
      const bytes = readFileSync(join(root, "kats", "negative", `${fixture.filename}.cbor`));
      const descriptor = JSON.parse(readFileSync(join(root, "kats", "negative", `${fixture.filename}.json`), "utf8"));
      expect(equalBytes(bytes, fixture.bytes), fixture.filename).toBe(true);
      expect(descriptor, fixture.filename).toEqual(fixture.descriptor);
    }
  });

  test("unavailable key and trust policy classify as indeterminate", () => {
    const missingKey = buildNegativeFixtures().find((fixture) => fixture.descriptor.expected_code === "key/not-found")!;
    const keyResult = verifyBundleB1(missingKey.bytes);
    expect(keyResult.ok).toBe(false);
    if (!keyResult.ok) {
      expect(keyResult.result).toBe("indeterminate");
      expect(keyResult.reason).toBe("key/not-found");
    }

    const positive = decodeCbor(readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor")), { strict: true });
    if (typeof positive !== "object" || positive === null || Array.isArray(positive) || positive instanceof Uint8Array || positive instanceof Map) throw new Error("positive bundle is not a map");
    const trust = positive.trust_inputs;
    if (typeof trust !== "object" || trust === null || Array.isArray(trust) || trust instanceof Uint8Array || trust instanceof Map) throw new Error("trust inputs are not a map");
    delete trust.verifier_policy_digest;
    const trustResult = verifyBundleB1(encodeCbor(positive));
    expect(trustResult.ok).toBe(false);
    if (!trustResult.ok) {
      expect(trustResult.result).toBe("indeterminate");
      expect(trustResult.reason).toBe("schema/missing-field");
    }
  });
});
