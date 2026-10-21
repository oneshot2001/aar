import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toHex } from "./cbor";
import { ConfigurationError, LEGACY_FIXTURE_KIDS, loadConfiguration } from "./relying-party";
import { AT, policyCases, PolicyCase, RP_KEY_HEX, rpPolicy, SAMPLE_ROOTS } from "./relying-party-fixtures";
import { TEST_KEYS, TestKeyName } from "./testkeys";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const PYREF = `
import sys
from pathlib import Path
from pyref.relying_party import UsageError, load_configuration
policy, key, at = sys.argv[1:]
try:
    c = load_configuration(Path(policy) if policy else None, Path(key) if key else None, int(at))
except UsageError as exc:
    print(f"usage: {exc}"); sys.exit(2)
print("ok" if c is None else f"ok {c.kid.hex()} {c.policy_digest.hex()}")
`;

// Write one case to disk and return the two paths (undefined = not supplied).
function materialise(directory: string, item: PolicyCase): [string | undefined, string | undefined] {
  const policyPath = item.policy === undefined ? undefined : join(directory, `${item.name}.policy.json`);
  const keyPath = item.key === undefined ? undefined : join(directory, `${item.name}.key`);
  if (policyPath) writeFileSync(policyPath, typeof item.policy === "string" ? item.policy : JSON.stringify(item.policy));
  if (keyPath) writeFileSync(keyPath, `${item.key}\n`);
  return [policyPath, keyPath];
}

function pyref(policyPath: string | undefined, keyPath: string | undefined): { code: number; out: string } {
  const proc = Bun.spawnSync(["python3", "-B", "-c", PYREF, policyPath ?? "", keyPath ?? "", String(AT)], { cwd: root });
  return { code: proc.exitCode, out: proc.stdout.toString() + proc.stderr.toString() };
}

describe("relying-party configuration (D-83, CONFORMANCE section 6)", () => {
  const directory = mkdtempSync(join(tmpdir(), "aar-rp-"));

  test("a valid policy and key load on both sides with the same leaf kid and policy digest", () => {
    const [policyPath, keyPath] = materialise(directory, { name: "valid", policy: rpPolicy(SAMPLE_ROOTS), key: RP_KEY_HEX });
    const configuration = loadConfiguration(policyPath, keyPath, AT)!;
    expect(toHex(configuration.kid)).toBe(toHex(TEST_KEYS.rp_verifier_signing.kid));
    expect(configuration.verifierKids.has(toHex(TEST_KEYS.rp_credential_issuing.kid))).toBe(true);
    expect(toHex(configuration.policyDigest)).not.toBe("00".repeat(32));
    const py = pyref(policyPath, keyPath);
    expect(py.code, py.out).toBe(0);
    expect(py.out.trim()).toBe(`ok ${toHex(configuration.kid)} ${toHex(configuration.policyDigest)}`);
    expect(loadConfiguration(undefined, undefined, AT)).toBeUndefined();
    expect(pyref(undefined, undefined).out.trim()).toBe("ok");
  });

  test("every section 6 failure is a usage error on both sides", () => {
    for (const item of policyCases()) {
      const [policyPath, keyPath] = materialise(directory, item);
      expect(() => loadConfiguration(policyPath, keyPath, AT), item.name).toThrow(ConfigurationError);
      const py = pyref(policyPath, keyPath);
      expect(py.code, `${item.name}: ${py.out}`).toBe(2);
      expect(py.out.startsWith("usage: "), `${item.name}: ${py.out}`).toBe(true);
    }
  });

  test("the legacy exclusion is exactly the thirteen v0.2.5 fixture kids, never the rp pair", () => {
    const legacy: TestKeyName[] = ["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "verifier_signing", "credential_issuing", "status_signing", "agent_signing_successor", "mediator_outcome_signing", "d77_outsider", "d77_leaf"];
    expect(new Set(legacy.map((name) => toHex(TEST_KEYS[name].kid)))).toEqual(new Set(LEGACY_FIXTURE_KIDS));
    expect(LEGACY_FIXTURE_KIDS.has(toHex(TEST_KEYS.rp_verifier_signing.kid))).toBe(false);
    expect(LEGACY_FIXTURE_KIDS.has(toHex(TEST_KEYS.rp_credential_issuing.kid))).toBe(false);
    const py = Bun.spawnSync(["python3", "-B", "-c", "from pyref.relying_party import LEGACY_FIXTURE_KIDS; from pyref.crypto import TEST_SCALARS, key_id; print(sorted(k.hex() for k in LEGACY_FIXTURE_KIDS) == sorted(key_id(s).hex() for n, s in TEST_SCALARS.items() if not n.startswith('rp_')))"], { cwd: root });
    expect(py.stdout.toString().trim()).toBe("True");
  });
});
