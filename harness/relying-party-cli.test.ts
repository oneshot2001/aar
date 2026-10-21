import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeCbor, fromHex, toHex } from "./cbor";
import { id16 } from "./crypto";
import { AT, policyCases, PolicyCase, RP_KEY_HEX, rootRecord, rpPolicy } from "./relying-party-fixtures";
import { TEST_KEYS } from "./testkeys";

// Both CLIs: every CONFORMANCE section 6 failure exits 2 with no verdict on
// stdout; a valid policy signs the verdict with the policy leaf.
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const BUNDLE = join("kats", "positive", "bundle-valid-subset.cbor");
const directory = mkdtempSync(join(tmpdir(), "aar-rp-cli-"));

function files(item: PolicyCase): string[] {
  const args: string[] = [];
  if (item.policy !== undefined) { const path = join(directory, `${item.name}.policy.json`); writeFileSync(path, typeof item.policy === "string" ? item.policy : JSON.stringify(item.policy)); args.push("--policy", path); }
  if (item.key !== undefined) { const path = join(directory, `${item.name}.key`); writeFileSync(path, `${item.key}\n`); args.push("--signing-key", path); }
  return args;
}

const clis = {
  pyref: (args: string[]) => Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", BUNDLE, "--at", String(AT), ...args], { cwd: root }),
  harness: (args: string[]) => Bun.spawnSync(["bun", "run", join("harness", "verify.ts"), BUNDLE, "--at", String(AT), ...args], { cwd: root }),
};

describe("relying-party CLI flags", () => {
  test("every section 6 failure is exit 2 with no verdict on either CLI", () => {
    for (const item of policyCases()) {
      const args = files(item);
      for (const [name, run] of Object.entries(clis)) {
        const proc = run(args);
        expect(proc.exitCode, `${name} ${item.name}: ${proc.stderr.toString()}`).toBe(2);
        expect(proc.stdout.toString(), `${name} ${item.name}`).not.toContain("CBOR hex");
        expect(proc.stderr.toString(), `${name} ${item.name}`).toContain("error");
      }
    }
  }, 180_000);

  test("a valid policy makes both CLIs sign with the policy leaf and print the identity line", () => {
    const usages = ["agent_signing", "ep_signing", "authority_signing", "approver_signing", "outcome_signing", "anchor_signing", "credential_issuing", "status_signing"];
    const policy = rpPolicy([rootRecord(TEST_KEYS.credential_issuing.kid, id16("tenant:acme-security"), [id16("site:denver-lab")], usages)]);
    const args = files({ name: "valid", policy, key: RP_KEY_HEX });
    for (const [name, run] of Object.entries(clis)) {
      const proc = run(args);
      const out = proc.stdout.toString();
      expect(proc.exitCode, `${name}: ${proc.stderr.toString()}`).toBe(0);
      expect(out, name).toMatch(/^Verifier identity: relying-party policy \(digest [0-9a-f]{64}\)$/m);
      expect(out, name).toContain("control_path_completeness: not_established");
      const envelope = decodeCbor(fromHex(out.match(/CBOR hex: ([0-9a-f]+)/)![1]!), { strict: true }) as Uint8Array[];
      const protectedMap = decodeCbor((decodeCbor(envelope[1]!, { strict: true }) as Uint8Array[])[0]!, { strict: true }) as Map<number, Uint8Array>;
      expect(toHex(protectedMap.get(4)!), name).toBe(toHex(TEST_KEYS.rp_verifier_signing.kid));
      expect(out, name).not.toContain(`relying_party_policy_digest: ${"00".repeat(32)}`);
    }
  });
});
