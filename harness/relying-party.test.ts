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
// One pyref process over the whole manifest: a line per case, "usage" or "ok <kid> <digest>".
const PYREF = `
import json, sys
from pathlib import Path
from pyref.relying_party import UsageError, load_configuration
for name, policy, key in json.load(open(sys.argv[1])):
    try:
        c = load_configuration(Path(policy) if policy else None, Path(key) if key else None, int(sys.argv[2]))
        print(name, "ok" if c is None else f"ok {c.kid.hex()} {c.policy_digest.hex()}")
    except UsageError as exc:
        print(name, "usage", str(exc))
`;

// Write one case to disk and return the two paths (undefined = not supplied).
function materialise(directory: string, item: PolicyCase): [string | undefined, string | undefined] {
  const policyPath = item.policy === undefined ? undefined : join(directory, `${item.name}.policy.json`);
  const keyPath = item.key === undefined ? undefined : join(directory, `${item.name}.key`);
  if (policyPath) writeFileSync(policyPath, typeof item.policy === "string" ? item.policy : JSON.stringify(item.policy));
  if (keyPath) writeFileSync(keyPath, item.keyText ?? `${item.key}\n`);
  return [policyPath, keyPath];
}

function pyref(directory: string, manifest: [string, string | undefined, string | undefined][]): Map<string, string> {
  const path = join(directory, "manifest.json"); writeFileSync(path, JSON.stringify(manifest));
  const proc = Bun.spawnSync(["python3", "-B", "-c", PYREF, path, String(AT)], { cwd: root });
  expect(proc.exitCode, proc.stderr.toString()).toBe(0);
  return new Map(proc.stdout.toString().trim().split("\n").map((line) => { const [name, ...rest] = line.split(" "); return [name!, rest.join(" ")]; }));
}

describe("relying-party configuration (D-83, CONFORMANCE section 6)", () => {
  const directory = mkdtempSync(join(tmpdir(), "aar-rp-"));

  test("a valid policy and key load on both sides with the same leaf kid and policy digest", () => {
    const [policyPath, keyPath] = materialise(directory, { name: "valid", policy: rpPolicy(SAMPLE_ROOTS), key: RP_KEY_HEX });
    const configuration = loadConfiguration(policyPath, keyPath, AT)!;
    expect(toHex(configuration.kid)).toBe(toHex(TEST_KEYS.rp_verifier_signing.kid));
    expect(configuration.verifierKids.has(toHex(TEST_KEYS.rp_credential_issuing.kid))).toBe(true);
    expect(toHex(configuration.policyDigest)).not.toBe("00".repeat(32));
    const py = pyref(directory, [["valid", policyPath, keyPath], ["none", undefined, undefined]]);
    expect(py.get("valid")).toBe(`ok ${toHex(configuration.kid)} ${toHex(configuration.policyDigest)}`);
    expect(loadConfiguration(undefined, undefined, AT)).toBeUndefined();
    expect(py.get("none")).toBe("ok");
  });

  test("the shared table drives both loaders: every failure case is a usage error, every valid case loads identically", () => {
    const cases = policyCases();
    const manifest: [string, string | undefined, string | undefined][] = [];
    const ts = new Map<string, string>();
    for (const item of cases) {
      const [policyPath, keyPath] = materialise(directory, item);
      manifest.push([item.name, policyPath, keyPath]);
      try { const c = loadConfiguration(policyPath, keyPath, AT)!; ts.set(item.name, `ok ${toHex(c.kid)} ${toHex(c.policyDigest)}`); } catch (error) {
        expect(error, item.name).toBeInstanceOf(ConfigurationError); ts.set(item.name, "usage");
      }
    }
    const py = pyref(directory, manifest);
    expect(py.size, "pyref saw the same number of cases").toBe(cases.length);
    for (const item of cases) {
      if (item.valid) { expect(ts.get(item.name), item.name).toMatch(/^ok /u); expect(py.get(item.name), item.name).toBe(ts.get(item.name)); }
      else { expect(ts.get(item.name), item.name).toBe("usage"); expect(py.get(item.name)?.startsWith("usage "), `${item.name}: ${py.get(item.name)}`).toBe(true); }
    }
    console.log(`shared configuration table: ${cases.length} cases (${cases.filter((item) => item.valid).length} valid), identical outcome on both loaders`);
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
