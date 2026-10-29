// D-87 fix rounds 2-3: the harness's peak memory stays bounded on 16 MiB CBOR of every shape
// that has expanded before (nested declared counts, huge map keys, many entries), directly and
// as a retained entry, measured per child process; and a policy credential reports the first
// error in byte order.
import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigurationError, loadConfiguration } from "./relying-party";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;
// Peak RSS bound for every 16 MiB shape below, directly and as a retained entry. Before the
// fixes some shapes peaked at 4-7 GB in the harness; pyref stays under ~0.5 GB on all of them.
const BOUND_MB = 1_500;
const SIZE = 16 * 1024 * 1024;

// The child's own peak: VmHWM on Linux (a Bun child inherits the parent's ru_maxrss high-water
// mark there), ru_maxrss in bytes on macOS.
const PEAK = `const peakBytes = () => process.platform === "linux" ? Number(/VmHWM:\\s+(\\d+) kB/.exec(require("node:fs").readFileSync("/proc/self/status", "utf8"))[1]) * 1024 : process.resourceUsage().maxRSS;`;

// Each shape is about 16 MiB of CBOR, built in the child.
const SHAPES: Record<string, string> = {
  "32 nested arrays, each declaring every byte after it": `const b = new Uint8Array(${SIZE}); const v = new DataView(b.buffer); for (let l = 0, o = 0; l < 32; l++, o += 5) { b[o] = 0x9a; v.setUint32(o + 1, ${SIZE} - o - 5); } return b;`,
  "one map, a 16 MiB byte-string key": `const b = new Uint8Array(${SIZE}); b[0] = 0xa1; b[1] = 0x5a; new DataView(b.buffer).setUint32(2, ${SIZE} - 7); return b;`,
  "one map, a 16 MiB text-string key": `const b = new Uint8Array(${SIZE}).fill(0x61); b[0] = 0xa1; b[1] = 0x7a; new DataView(b.buffer).setUint32(2, ${SIZE} - 7); b[${SIZE} - 1] = 0; return b;`,
  "one map, a 16 MiB byte-string value": `const b = new Uint8Array(${SIZE}); b[0] = 0xa1; b[1] = 0x61; b[2] = 0x61; b[3] = 0x5a; new DataView(b.buffer).setUint32(4, ${SIZE} - 8); return b;`,
  "one map, as many small entries as fit": `const n = Math.floor((${SIZE} - 5) / 6); const b = new Uint8Array(5 + n * 6); const v = new DataView(b.buffer); b[0] = 0xba; v.setUint32(1, n); for (let i = 0; i < n; i++) { b[5 + 6 * i] = 0x1a; v.setUint32(6 + 6 * i, i); } return b;`,
  "32 nested maps around a byte string": `const b = new Uint8Array(${SIZE}); let o = 0; for (let l = 0; l < 31; l++) { b[o++] = 0xa1; b[o++] = 0; } b[o] = 0x5a; new DataView(b.buffer).setUint32(o + 1, ${SIZE} - o - 5); return b;`,
};

function child(program: string): { error: string | null; peakMb: number } {
  const run = Bun.spawnSync(["bun", "-e", `${PEAK}\n${program}\nconsole.log(JSON.stringify({ error, peakMb: Math.round(peakBytes() / 1e6) }));`], { cwd: root });
  expect(run.exitCode, run.stderr.toString()).toBe(0);
  return JSON.parse(run.stdout.toString());
}

const program = (shape: string, retained: boolean): string => `
const { decodeCbor } = await import(${JSON.stringify(join(root, "harness", "cbor.ts"))});
const { verifyBundle } = await import(${JSON.stringify(join(root, "harness", "verifier.ts"))});
const { readFileSync } = await import("node:fs");
const bytes = (() => { ${SHAPES[shape]} })();
let error = null;
try {
  if (${retained}) verifyBundle(readFileSync(${JSON.stringify(join(root, "kats", "positive", "stateful", "d87-retained-zero-receipts.bundle.cbor"))}), { evaluationTime: ${AT}, priorEmissions: [], retainedEpochs: [bytes] });
  else decodeCbor(bytes);
} catch (e) { error = e.message; }`;

for (const shape of Object.keys(SHAPES)) {
  for (const retained of [false, true]) {
    test(`peak RSS under ${BOUND_MB} MB: ${shape}, ${retained ? "as a retained entry (a usage error)" : "decodeCbor"}`, () => {
      const result = child(program(shape, retained));
      console.log(`${shape} | ${retained ? "retained" : "decode"} | ${result.error ?? "decoded"} | peak ${result.peakMb} MB`);
      if (retained) expect(result.error).toMatch(/^prior-state\.retained_epochs\[0\] fails step [23] \(/u);
      expect(result.peakMb).toBeLessThan(BOUND_MB);
    }, 120_000);
  }
}

// The measurement isolates the child: on Linux a child spawned while the parent holds a large
// allocation must still report its own small peak (ru_maxrss would report the parent's).
test.skipIf(process.platform !== "linux")("Linux: a no-op child's VmHWM excludes the parent's high-water mark", () => {
  const held = Buffer.alloc(800_000_000, 1);
  const result = child("const error = null;");
  expect(held[held.length - 1]).toBe(1);
  expect(result.peakMb).toBeLessThan(200);
}, 60_000);

// Policy credentials report the first defect in byte order; these three agree in the harness, the
// pyref library and the pyref CLI (other defects' wording differs: a pre-existing BACKLOG item).
const POLICY_CREDENTIALS: [string, string][] = [
  ["829f", "indefinite-length CBOR is forbidden"],
  ["9b0000000100000000", "truncated CBOR item"], // a 2^32 array count (v0.3.1's harness threw a RangeError)
  ["9b00000001000000009f", "indefinite-length CBOR is forbidden"],
];

test("policy credentials 829f, 9b0000000100000000, 9b00000001000000009f: one message each in the harness, the pyref library and the pyref CLI", () => {
  const rp = join(root, "kats", "relying-party");
  const directory = mkdtempSync(join(tmpdir(), "aar-d87-policy-"));
  try {
    const key = join(rp, "rp-verifier.key");
    for (const [credential, detail] of POLICY_CREDENTIALS) {
      const policy = join(directory, `${credential}.json`);
      writeFileSync(policy, JSON.stringify({ ...JSON.parse(readFileSync(join(rp, "rp-positive-strict-subset.policy.json"), "utf8")), verifier_credentials: [credential] }));
      const message = `policy.verifier_credentials[0]: ${detail}`;
      let harness = "";
      try { loadConfiguration(policy, key, AT); } catch (error) { if (!(error instanceof ConfigurationError)) throw error; harness = error.message; }
      expect(harness, credential).toBe(message);
      const library = Bun.spawnSync(["python3", "-B", "-c", `
import sys
from pathlib import Path
from pyref.relying_party import UsageError, load_configuration
try:
    load_configuration(Path(sys.argv[1]), Path(sys.argv[2]), ${AT})
except UsageError as exc:
    print(exc)
`, policy, key], { cwd: root });
      expect(library.stdout.toString().trim(), credential).toBe(message);
      const cli = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", join(rp, "rp-positive-strict-subset.cbor"), "--at", String(AT), "--policy", policy, "--signing-key", key], { cwd: root });
      expect(cli.exitCode, credential).toBe(2);
      expect(cli.stderr.toString(), credential).toContain(`error: ${message}\n`);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}, 60_000);
