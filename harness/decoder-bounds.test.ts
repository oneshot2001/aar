// D-87 fix round 2: the harness CBOR decoder's memory stays bounded on nested declared
// counts (a retained entry is decoded before its guarded scan reaches step 2), and a
// policy credential reports the first error in byte order, as pyref does.
import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigurationError, loadConfiguration } from "./relying-party";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;
// The pre-fix decoder reserved every declared count at each of 32 levels: 6.68 GB peak RSS on
// this input; element-by-element growth peaks near 0.5-0.6 GB (the innermost array of zeros).
const BOUND_MB = 1_500;

// Peak RSS of a child that decodes 32 nested 9a headers, each declaring every byte after it, then zeros (16 MiB):
// directly, or as the one retained bundle of an evaluation. ru_maxrss is bytes on macOS, KiB on Linux.
function child(mode: "decode" | "retained"): { error: string | null; peakMb: number } {
  const code = `
const { decodeCbor } = await import(${JSON.stringify(join(root, "harness", "cbor.ts"))});
const { verifyBundle } = await import(${JSON.stringify(join(root, "harness", "verifier.ts"))});
const { readFileSync } = await import("node:fs");
const size = 16 * 1024 * 1024; const bytes = new Uint8Array(size); const view = new DataView(bytes.buffer);
for (let level = 0, offset = 0; level < 32; level += 1, offset += 5) { bytes[offset] = 0x9a; view.setUint32(offset + 1, size - offset - 5); }
let error = null;
try {
  if (${JSON.stringify(mode)} === "decode") decodeCbor(bytes);
  else verifyBundle(readFileSync(${JSON.stringify(join(root, "kats", "positive", "stateful", "d87-retained-zero-receipts.bundle.cbor"))}), { evaluationTime: ${AT}, priorEmissions: [], retainedEpochs: [bytes] });
} catch (e) { error = e.message; }
const raw = process.resourceUsage().maxRSS;
console.log(JSON.stringify({ error, peakMb: Math.round((process.platform === "darwin" ? raw : raw * 1024) / 1e6) }));`;
  const run = Bun.spawnSync(["bun", "-e", code], { cwd: root });
  expect(run.exitCode, run.stderr.toString()).toBe(0);
  return JSON.parse(run.stdout.toString());
}

test("nested declared counts: decodeCbor and a retained entry fail as before with peak RSS far below the pre-fix 6.68 GB", () => {
  const decoded = child("decode");
  console.log(`nested 16 MiB decode: ${decoded.error}, peak ${decoded.peakMb} MB`);
  expect(decoded.error).toBe("truncated CBOR item");
  expect(decoded.peakMb).toBeLessThan(BOUND_MB);
  const retained = child("retained");
  console.log(`nested 16 MiB retained entry: ${retained.error}, peak ${retained.peakMb} MB`);
  expect(retained.error).toBe("prior-state.retained_epochs[0] fails step 2 (cbor/malformed)");
  expect(retained.peakMb).toBeLessThan(BOUND_MB);
}, 300_000);

test("policy credential 829f is \"indefinite-length CBOR is forbidden\" in the harness, the pyref library and the pyref CLI (first error in byte order)", () => {
  const rp = join(root, "kats", "relying-party");
  const directory = mkdtempSync(join(tmpdir(), "aar-d87-policy-"));
  try {
    const policy = join(directory, "policy.json"); const key = join(rp, "rp-verifier.key");
    writeFileSync(policy, JSON.stringify({ ...JSON.parse(readFileSync(join(rp, "rp-positive-strict-subset.policy.json"), "utf8")), verifier_credentials: ["829f"] }));
    const message = "policy.verifier_credentials[0]: indefinite-length CBOR is forbidden";
    let harness = "";
    try { loadConfiguration(policy, key, AT); } catch (error) { if (!(error instanceof ConfigurationError)) throw error; harness = error.message; }
    expect(harness).toBe(message);
    const library = Bun.spawnSync(["python3", "-B", "-c", `
import sys
from pathlib import Path
from pyref.relying_party import UsageError, load_configuration
try:
    load_configuration(Path(sys.argv[1]), Path(sys.argv[2]), ${AT})
except UsageError as exc:
    print(exc)
`, policy, key], { cwd: root });
    expect(library.stdout.toString().trim()).toBe(message);
    const cli = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", join(rp, "rp-positive-strict-subset.cbor"), "--at", String(AT), "--policy", policy, "--signing-key", key], { cwd: root });
    expect(cli.exitCode).toBe(2);
    expect(cli.stderr.toString()).toContain(`error: ${message}\n`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}, 60_000);
