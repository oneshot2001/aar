// Cross-implementation byte gate: given identical caller inputs and explicit
// verifier identity, the harness verifier and pyref must agree on result,
// reason, step, and the exact signed verdict bytes.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { buildEvidenceCommitFixtures, buildNegativeFixtures } from "./negative-fixtures";
import { verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;
const repairStep = (filename: string): number => filename.startsWith("repair-d70") ? 5 : filename.includes("independence") ? 17 : 6;

const PYREF = `
import sys, json
from pyref.verifier import evaluate
r = evaluate(sys.stdin.buffer.read(), evaluated_at=int(sys.argv[1]), replay_state={"entries": []})
v = r.verdict; i = v["verifier"]
print(json.dumps({"result": r.result, "reason": r.reason, "step": r.report["first_failure_step"], "hex": r.verdict_bytes.hex(),
  "product": i["product"], "version": i["version"], "build": i["build_digest"].hex(), "config": i["config_digest"].hex()}))
`;

interface Case { name: string; bytes: Uint8Array; at: number; code: string | null; step: number | null }

function cases(): Case[] {
  const base = readFileSync(join(root, "kats", "positive", "bundle-valid-subset.cbor"));
  const noAnchor = decodeCbor(base, { strict: true }) as Record<string, any>;
  noAnchor.artifacts.anchors = [];
  const sameOperator = buildEvidenceCommitFixtures().find((fixture) => fixture.filename === "repair-d69-anchor-basis-same-operator")!;
  return [
    { name: "positive", bytes: base, at: AT, code: null, step: null },
    { name: "positive-no-anchor", bytes: encodeCbor(noAnchor), at: AT, code: null, step: null },
    { name: "positive-same-operator", bytes: sameOperator.bytes, at: AT, code: null, step: null },
    { name: "caller-before", bytes: base, at: AT - 1, code: "schema/out-of-range", step: 5 },
    { name: "caller-after", bytes: base, at: AT + 1, code: "schema/out-of-range", step: 5 },
    ...buildNegativeFixtures().filter((fixture) => fixture.filename.startsWith("repair-")).map((fixture) => ({
      name: fixture.filename, bytes: fixture.bytes, at: AT, code: fixture.descriptor.expected_code, step: repairStep(fixture.filename),
    })),
  ];
}

describe("cross-implementation verdict bytes (harness vs pyref)", () => {
  test("every positive and repair case agrees on reason, step, and signed verdict bytes", () => {
    const all = cases();
    expect(all.length).toBeGreaterThanOrEqual(16);
    for (const item of all) {
      const proc = Bun.spawnSync(["python3", "-B", "-c", PYREF, String(item.at)], { cwd: root, stdin: item.bytes });
      expect(proc.exitCode, `${item.name}: ${proc.stderr.toString()}`).toBe(0);
      const py = JSON.parse(proc.stdout.toString());
      const ts = verifyBundle(item.bytes, {
        evaluationTime: item.at, replayState: [], product: py.product, version: py.version,
        buildDigest: fromHex(py.build), configDigest: fromHex(py.config),
      });
      expect(ts.ok ? null : ts.reason, item.name).toBe(item.code);
      expect(ts.ok ? null : ts.step, item.name).toBe(item.step);
      expect(py.reason, item.name).toBe(item.code);
      expect(py.step, item.name).toBe(item.step);
      expect(ts.result, item.name).toBe(py.result);
      expect(ts.verdictEnvelope === undefined, item.name).toBe(false);
      expect(toHex(ts.verdictEnvelope!), item.name).toBe(py.hex);
    }
  }, 120_000);
});
