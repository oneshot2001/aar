// Cross-implementation byte gate: given identical caller inputs and explicit
// verifier identity, the harness verifier and pyref must agree on result,
// reason, step, and the exact signed verdict bytes.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { buildD78ItemVariants, buildD78ReportVariants, buildD78Fixtures, buildD77PositiveFixtures, buildD80D81PositiveFixtures, buildD82PositiveFixtures, buildEvidenceCommitFixtures, buildNegativeFixtures, buildPresentationEnumVariants } from "./negative-fixtures";
import { verifyBundle } from "./verifier";
import { parseStatefulPrior } from "./stateful-fixtures";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;
const repairStep = (filename: string): number => filename.startsWith("repair-d70") ? 5 : filename.includes("independence") ? 17 : filename.startsWith("repair-d73-command") ? 10 : filename.startsWith("repair-d73-manifest") ? 14 : 6;

const PYREF = `
import sys, json
from pyref.verifier import evaluate
r = evaluate(sys.stdin.buffer.read(), evaluated_at=int(sys.argv[1]), replay_state={"entries": []})
v = r.verdict; i = v["verifier"]
print(json.dumps({"result": r.result, "reason": r.reason, "step": r.report["first_failure_step"], "hex": r.verdict_bytes.hex(),
  "origins_report": r.report["input_origin_ancestry"], "selected": r.report["selector_matching_receipts"], "product": i["product"], "version": i["version"], "build": i["build_digest"].hex(), "config": i["config_digest"].hex()}))
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
    ...buildD78ItemVariants().map((fixture) => ({ ...fixture, at: AT })),
    ...buildD78ReportVariants().map((fixture) => ({ name: fixture.name, bytes: fixture.bytes, at: AT, code: null, step: null })),
    ...buildD78Fixtures().map((fixture) => ({ name: fixture.filename, bytes: fixture.bytes, at: AT, code: fixture.descriptor.expected_code, step: fixture.descriptor.expected_step ?? null })),
    ...[...buildD77PositiveFixtures(), ...buildD80D81PositiveFixtures(), ...buildD82PositiveFixtures()].map((fixture) => ({ name: fixture.filename, bytes: fixture.bytes, at: AT, code: null, step: null })),
    ...buildPresentationEnumVariants().map((fixture) => ({ ...fixture, at: AT })),
    ...buildNegativeFixtures().filter((fixture) => fixture.filename.startsWith("repair-")).map((fixture) => ({
      name: fixture.filename, bytes: fixture.bytes, at: AT, code: fixture.descriptor.expected_code, step: fixture.descriptor.expected_step ?? repairStep(fixture.filename),
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
      if (ts.ok) {
        expect(ts.report.input_origin_ancestry, item.name).toEqual(py.origins_report);
        expect(ts.report.selector_matching_receipts, item.name).toBe(py.selected);
      } else if (item.name.startsWith("repair-d78-") || item.name.startsWith("d78-item-")) {
        expect(ts.verdict!.observations, item.name).toEqual([]);
        expect((ts.verdict!.limits as Record<string, string>).input_origin_ancestry, item.name).toBe("not_evaluated");
        expect(py.origins_report, item.name).toEqual({
          bundle_digest: toHex(ts.verdict!.bundle_digest as Uint8Array),
          verdict_id: toHex(ts.verdict!.verdict_id as Uint8Array), attempts: [],
        });
      }
      if (item.name.includes("d78-") || item.name.startsWith("origin-")) {
        console.log(`${item.name}: reason=${py.reason ?? "none"}, step=${py.step ?? "none"}, signed verdict bytes equal; report parity=${ts.ok ? "PASS" : "PASS (empty failure ancestry)"}`);
      }
    }
  }, 120_000);
});

// Standalone artifact fixtures are evaluated inside the same corpus bundle by
// both implementations. The production harness entry point accepts bundles.
const PYREF_CORPUS = `
import json
from pyref.kat import (ROOT, KAT_EVALUATION_TIME, _c2_fixture_paths, _sidecar_path,
                       _prior_path, _context_for_standalone, _expected_result)
from pyref.verifier import evaluate
base = (ROOT / "kats/positive/bundle-valid-subset.cbor").read_bytes()
rows = []
for path in _c2_fixture_paths():
    sidecar = json.loads(_sidecar_path(path).read_text())
    raw = path.read_bytes()
    context = _context_for_standalone(raw, sidecar, base) if sidecar.get("object_type") not in (None, "bundle") else None
    prior_path = _prior_path(path)
    prior = json.loads(prior_path.read_text()) if prior_path else None
    r = evaluate(context or raw, evaluated_at=KAT_EVALUATION_TIME, prior_state=prior, replay_state={"entries": []})
    i = r.verdict["verifier"]
    rows.append({"path": str(path), "context": context.hex() if context else None, "prior": prior,
      "expected_code": sidecar.get("expected_code"), "expected_result": sidecar.get("expected_result", _expected_result(sidecar.get("expected_code"))),
      "expected_step": sidecar.get("expected_step"),
      "result": r.result, "reason": r.reason, "step": r.report["first_failure_step"], "hex": r.verdict_bytes.hex(),
      "product": i["product"], "version": i["version"], "build": i["build_digest"].hex(), "config": i["config_digest"].hex()})
print(json.dumps({"count": len(_c2_fixture_paths()), "rows": rows}))
`;

// D-82 part 10: the full-corpus gate. Every fixture the Python enumeration
// lists must agree on result, reason, first-failure step, and signed verdict
// bytes; the row count comes from that enumeration, never a literal.
test("every corpus fixture has identical result, reason, step, and signed verdict bytes in shared context", () => {
  const proc = Bun.spawnSync(["python3", "-B", "-c", PYREF_CORPUS], { cwd: root });
  expect(proc.exitCode, proc.stderr.toString()).toBe(0);
  const { count, rows } = JSON.parse(proc.stdout.toString());
  expect(count).toBeGreaterThan(0);
  expect(rows).toHaveLength(count);
  for (const row of rows) {
    const ts = verifyBundle(row.context ? fromHex(row.context) : readFileSync(row.path), {
      evaluationTime: AT, replayState: [], priorEmissions: row.prior ? parseStatefulPrior(row.prior) : undefined,
      product: row.product, version: row.version, buildDigest: fromHex(row.build), configDigest: fromHex(row.config),
    });
    expect(row.result, row.path).toBe(row.expected_result);
    expect(row.reason, row.path).toBe(row.expected_code);
    if (row.expected_step !== null) expect(row.step, row.path).toBe(row.expected_step);
    expect(ts.result, row.path).toBe(row.result);
    expect(ts.ok ? null : ts.reason, row.path).toBe(row.reason);
    expect(ts.ok ? null : ts.step, row.path).toBe(row.step);
    expect(toHex(ts.verdictEnvelope!), row.path).toBe(row.hex);
  }
}, 300_000);
