import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CborValue, decodeCbor, encodeCbor, equalBytes } from "./cbor";
import { buildNegativeFixtures } from "./negative-fixtures";
import { buildStatefulFixtures, parseStatefulPrior } from "./stateful-fixtures";
import { domainHash, verifySigned } from "./crypto";
import { TEST_KEYS } from "./testkeys";
import { verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const negativeFixtures = buildNegativeFixtures();

describe("B2 reference verifier", () => {
  test("the full positive bundle passes steps 1 through 20 and yields a round-trippable signed verdict", () => {
    const input = readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor"));
    const result = verifyBundle(input);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.result).toBe("conformant");
      expect(result.completedThrough).toBe(20);
      const decoded = decodeCbor(result.verdictEnvelope, { strict: true });
      expect(equalBytes(encodeCbor(decoded), result.verdictEnvelope)).toBe(true);
      expect(verifySigned(result.verdictEnvelope, TEST_KEYS.verifier_signing)).toBe(true);
      if (!Array.isArray(decoded) || !(decoded[0] instanceof Uint8Array) || !(decoded[1] instanceof Uint8Array)) throw new Error("bad verdict envelope");
      const verdict = decodeCbor(decoded[0], { strict: true });
      const cose = decodeCbor(decoded[1], { strict: true });
      if (typeof verdict !== "object" || verdict === null || Array.isArray(verdict) || verdict instanceof Uint8Array || verdict instanceof Map || !Array.isArray(cose) || !(cose[0] instanceof Uint8Array)) throw new Error("bad verdict");
      const { verdict_id, ...fields } = verdict;
      expect(equalBytes(verdict_id as Uint8Array, domainHash("AAR-VERDICT-ID-v1", cose[0], fields))).toBe(true);
      const repeated = verifyBundle(input);
      expect(repeated.ok).toBe(true);
      if (repeated.ok) expect(equalBytes(repeated.verdictEnvelope, result.verdictEnvelope)).toBe(true);
    }
  });

  test("verdict configuration digests use the frozen domain-separated preimages", () => {
    const input = readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor"));
    const bundle = decodeCbor(input, { strict: true }) as Record<string, CborValue>;
    const trust = bundle.trust_inputs as Record<string, CborValue>;
    const limitsMap = {
      exact_encoded_bundle_bytes: 16_777_216, cbor_container_nesting: 32, receipt_nodes: 10_000,
      directed_graph_edges: 50_000, parents_per_receipt: 64, dag_depth: 128, dag_width: 4_096,
      encoded_proof_bytes: 65_536, aggregate_proof_bytes: 4_194_304, epoch_manifest_entries: 10_000,
      merkle_batch_leaves: 1_048_576, credential_path_length: 8,
    };
    const result = verifyBundle(input);
    expect(result.ok).toBe(true);
    if (result.ok) {
      const verifier = result.verdict.verifier as Record<string, CborValue>;
      const policy = result.verdict.trust_policy as Record<string, CborValue>;
      expect(equalBytes(verifier.limits_digest as Uint8Array, domainHash("AAR-VERDICT-LIMITS-v1", limitsMap))).toBe(true);
      expect(equalBytes(policy.anchor_heads_digest as Uint8Array, domainHash("AAR-VERDICT-HEADS-v1", trust.expected_anchor_heads!))).toBe(true);
      expect(equalBytes(policy.replay_state_digest as Uint8Array, new Uint8Array(32))).toBe(true);
    }
    const suppliedEmpty = verifyBundle(input, { replayState: [] });
    expect(suppliedEmpty.ok).toBe(true);
    if (suppliedEmpty.ok) {
      const policy = suppliedEmpty.verdict.trust_policy as Record<string, CborValue>;
      expect(equalBytes(policy.replay_state_digest as Uint8Array, domainHash("AAR-VERDICT-REPLAY-v1", { entries: [] }))).toBe(true);
    }
  });

  test("pre-decode failure verdict uses the normative zero sentinel and real evaluation time", () => {
    const evaluationTime = 1_735_700_000;
    const result = verifyBundle(Uint8Array.of(0xf8, 0), { evaluationTime });
    expect(result.ok).toBe(false);
    if (result.ok || result.verdict === undefined) return;
    const verdict = result.verdict;
    const policy = verdict.trust_policy as Record<string, CborValue>;
    const scope = verdict.scope as Record<string, CborValue>;
    const limits = verdict.limits as Record<string, CborValue>;
    const zero16 = new Uint8Array(16); const zero32 = new Uint8Array(32);
    expect(verdict.evaluated_at).toBe(evaluationTime);
    expect(policy.evaluation_time).toBe(evaluationTime);
    for (const field of ["trust_store_snapshot_id", "trust_store_digest", "verifier_policy_digest", "anchor_heads_digest", "replay_state_digest"]) {
      expect(equalBytes(policy[field] as Uint8Array, zero32), field).toBe(true);
    }
    expect(equalBytes(verdict.selector_commitment as Uint8Array, zero32)).toBe(true);
    expect(equalBytes(scope.tenant_id as Uint8Array, zero16)).toBe(true);
    expect(equalBytes(scope.site_id as Uint8Array, zero16)).toBe(true);
    expect(scope.committed_from).toBe(0); expect(scope.committed_until).toBe(0);
    expect(scope.receipt_kinds).toEqual(["observation"]); expect(scope.coverage).toBe("valid_subset");
    expect(limits.requested_profile).toBe("AAR-1");
  });

  test("negative generation is byte-for-byte deterministic", () => {
    const first = negativeFixtures;
    const second = buildNegativeFixtures();
    expect(first.map((fixture) => fixture.filename)).toEqual(second.map((fixture) => fixture.filename));
    for (let index = 0; index < first.length; index += 1) {
      expect(equalBytes(first[index]!.bytes, second[index]!.bytes), first[index]!.filename).toBe(true);
      expect(first[index]!.descriptor).toEqual(second[index]!.descriptor);
    }
  }, 30_000);

  test("every negative fixture returns exactly its first expected reason", () => {
    for (const fixture of negativeFixtures) {
      const result = verifyBundle(fixture.bytes);
      expect(result.ok, fixture.filename).toBe(false);
      if (!result.ok) expect(result.reason, fixture.filename).toBe(fixture.descriptor.expected_code);
    }
  }, 30_000);

  test("generated negative files and descriptors equal the in-memory fixtures", () => {
    for (const fixture of negativeFixtures) {
      const bytes = readFileSync(join(root, "kats", "negative", `${fixture.filename}.cbor`));
      const descriptor = JSON.parse(readFileSync(join(root, "kats", "negative", `${fixture.filename}.json`), "utf8"));
      expect(equalBytes(bytes, fixture.bytes), fixture.filename).toBe(true);
      expect(descriptor, fixture.filename).toEqual(fixture.descriptor);
    }
  });

  test("unavailable key and trust policy classify as indeterminate", () => {
    const missingKey = negativeFixtures.find((fixture) => fixture.descriptor.expected_code === "key/not-found")!;
    const keyResult = verifyBundle(missingKey.bytes);
    expect(keyResult.ok).toBe(false);
    if (!keyResult.ok) {
      expect(keyResult.result).toBe("indeterminate");
      expect(keyResult.reason).toBe("key/not-found");
      expect(keyResult.verdictEnvelope === undefined).toBe(false);
      expect(verifySigned(keyResult.verdictEnvelope!, TEST_KEYS.verifier_signing)).toBe(true);
    }

    const positive = decodeCbor(readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor")), { strict: true });
    if (typeof positive !== "object" || positive === null || Array.isArray(positive) || positive instanceof Uint8Array || positive instanceof Map) throw new Error("positive bundle is not a map");
    const trust = positive.trust_inputs;
    if (typeof trust !== "object" || trust === null || Array.isArray(trust) || trust instanceof Uint8Array || trust instanceof Map) throw new Error("trust inputs are not a map");
    delete trust.verifier_policy_digest;
    const trustResult = verifyBundle(encodeCbor(positive));
    expect(trustResult.ok).toBe(false);
    if (!trustResult.ok) {
      expect(trustResult.result).toBe("indeterminate");
      expect(trustResult.reason).toBe("schema/missing-field");
    }
  });

  test("stateful paired fixtures return their exact prior-state identity code", () => {
    for (const fixture of buildStatefulFixtures()) {
      const result = verifyBundle(fixture.bundle, { priorEmissions: parseStatefulPrior(fixture.prior) });
      expect(result.ok, fixture.name).toBe(false);
      if (!result.ok) expect(result.reason, fixture.name).toBe(fixture.descriptor.expected_code);
    }
  });

  test("generated stateful pairs and descriptors match in-memory fixtures", () => {
    for (const fixture of buildStatefulFixtures()) {
      const directory = join(root, "kats", "negative", "stateful");
      expect(equalBytes(readFileSync(join(directory, `${fixture.name}.bundle.cbor`)), fixture.bundle), fixture.name).toBe(true);
      expect(JSON.parse(readFileSync(join(directory, `${fixture.name}.prior.json`), "utf8")), fixture.name).toEqual(fixture.prior);
      expect(JSON.parse(readFileSync(join(directory, `${fixture.name}.json`), "utf8")), fixture.name).toEqual(fixture.descriptor);
    }
  });
});
