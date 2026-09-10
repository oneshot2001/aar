// Golden-digest guard for the RealNarrative byte-compatibility contract:
// with `narrative` omitted, buildDemoBundle must reproduce the pre-RealNarrative
// demo bundles byte-for-byte. Pinned inputs + pinned keys → pinned bundle hash.
// If this test breaks, either the compat contract broke (fix the code) or a
// deliberate wire-affecting demo change landed (re-pin BOTH digests and say so
// in the commit message).
import { describe, expect, test } from "bun:test";
import { fromHex, toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import { EVALUATED_AT, goldenBundle } from "./golden";
import { verifyBundle } from "../../harness/verifier";

// Re-pinned 2026-09-09 under D-73: the demo canonical command now carries
// parameters_digest, the epoch ships its open/close events, and the bundle
// credentials the published KAT verifier key (D-58 step 20), so both golden
// bundles changed bytes deliberately.
describe("RealNarrative byte-compatibility (golden digests)", () => {
  test("S1 dispatch bundle bytes unchanged with narrative omitted", async () => {
    expect(toHex(hash(await goldenBundle("S1")))).toBe("5b75d23aeba8945e0b7d0d41efa6878af75764e40efc249db0264ba5ef0ff45d");
  });
  test("S3 refusal bundle bytes unchanged with narrative omitted", async () => {
    expect(toHex(hash(await goldenBundle("S3")))).toBe("c35114650d8143f2d44c9ffdce96020e6951bbd6f4a1985ff56c75cbaaddad2a");
  });
});

// D-73 closure: the demo bundles verify conformant through BOTH reference
// verifiers with identical signed verdict bytes (under pyref's verifier
// identity supplied to the harness, exactly as harness/crossimpl.test.ts does:
// this pins rule agreement, not an independent verifier identity). Before D-73 the harness
// rejected them at step 10 (canonical command) and step 14 (no epoch events)
// while pyref accepted them, and pyref skipped the D-58 step-20 verifier
// credential check the harness enforced — three demo-only divergences the
// KAT corpus never exercised (pyref/DIVERGENCES.md).
const PYREF = `import sys, json
from pyref.verifier import evaluate
r = evaluate(sys.stdin.buffer.read(), evaluated_at=int(sys.argv[1]), replay_state={"entries": []})
print(json.dumps({"result": r.result, "reason": r.reason, "hex": r.verdict_bytes.hex(), "product": r.verdict["verifier"]["product"], "version": r.verdict["verifier"]["version"], "build": r.verdict["verifier"]["build_digest"].hex(), "config": r.verdict["verifier"]["config_digest"].hex()}))`;
describe("demo bundles verify (D-73)", () => {
  for (const scenario of ["S1", "S3"] as const) {
    test(`${scenario} golden bundle is conformant through harness and pyref with identical verdict bytes`, async () => {
      const bytes = await goldenBundle(scenario);
      const proc = Bun.spawnSync(["python3", "-B", "-c", PYREF, String(EVALUATED_AT)], { cwd: new URL("../..", import.meta.url).pathname, stdin: bytes });
      expect(proc.exitCode, proc.stderr.toString()).toBe(0);
      const py = JSON.parse(proc.stdout.toString());
      expect(py.result).toBe("conformant");
      const ts = verifyBundle(bytes, { evaluationTime: EVALUATED_AT, replayState: [], product: py.product, version: py.version, buildDigest: fromHex(py.build), configDigest: fromHex(py.config) });
      expect(ts.ok ? ts.result : `${ts.reason}@${ts.step}`).toBe("conformant");
      expect(ts.verdictEnvelope === undefined).toBe(false);
      expect(toHex(ts.verdictEnvelope!)).toBe(py.hex);
    });
  }
});
