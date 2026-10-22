// Finding records (fix-first C): a driver-side batch double whose second
// execution returns a different verdict_hex forces hash_seed_sensitive: true,
// and the tag is in the written both.json; the written directory is a complete
// replay package (file inputs copied under their sha256 names, inputs.json
// pointing at the copies, request identity carried).
import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Finding, tagHashSeedSensitivity, writeFinding } from "./difffuzz-mutants";
import { OPERATORS } from "./difffuzz-operators";
import { BatchResponse, root, sha256Hex } from "./difffuzz-pyref";
import { loadSeeds } from "./difffuzz-seeds";

test("hash-seed double tags the finding and the tag lands in both.json; file inputs are copied by sha256", () => {
  const seed = loadSeeds().find((candidate) => candidate.path === "kats/relying-party/rp-positive-strict-subset.cbor")!;
  const identity = { product: "pyref", version: "v0.3.0", build_digest: "11".repeat(32), config_digest: "22".repeat(32) };
  const pyref = { result: "conformant", reason: null, step: null, verdict_hex: "aa".repeat(8), crash: null };
  const finding: Finding = {
    id: "m-test", channel: "bytes", operator: OPERATORS[0]!, detail: "synthetic", seed, bundle: seed.bundle, harness: { ...pyref, verdict_hex: "bb".repeat(8) }, pyref,
    request: { id: "m-test", bundle_hex: Buffer.from(seed.bundle).toString("hex"), context_hex: null, inputs: seed.inputs, identity },
  };
  const again: BatchResponse = { id: "m-test", input_sha256: sha256Hex(seed.bundle), result: "conformant", reason: null, step: null, verdict_hex: "cc".repeat(8) };
  expect(tagHashSeedSensitivity([finding], [again])).toBe(1);
  expect(finding.hash_seed_sensitive).toBe(true);
  const same: BatchResponse = { ...again, verdict_hex: pyref.verdict_hex };
  expect(tagHashSeedSensitivity([{ ...finding, hash_seed_sensitive: undefined }], [same])).toBe(0);

  const out = mkdtempSync(join(tmpdir(), "difffuzz-finding-"));
  writeFinding(out, finding);
  const both = JSON.parse(readFileSync(join(out, "m-test", "both.json"), "utf8"));
  expect(both.stable.hash_seed_sensitive).toBe(true);
  expect(both.stable.identity).toEqual(identity);
  const inputs = JSON.parse(readFileSync(join(out, "m-test", "inputs.json"), "utf8"));
  for (const key of ["policy", "signing_key"] as const) {
    const original = readFileSync(seed.inputs[key]!);
    expect(inputs[key]).toBe(`${sha256Hex(original)}${seed.inputs[key]!.endsWith(".json") ? ".json" : ".key"}`);
    expect(readFileSync(join(out, "m-test", inputs[key])).equals(original)).toBe(true);
  }
  expect(inputs.trust_policy).toBe(null);
  expect(readFileSync(join(out, "m-test", "bundle.cbor")).equals(Buffer.from(seed.bundle))).toBe(true);
  expect(inputs.policy.startsWith(root)).toBe(false);
  rmSync(out, { recursive: true, force: true });
});
