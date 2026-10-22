// Seed enumeration for the differential fuzz tool: the corpus rows exactly as
// pyref.kat lists them (standalone objects in their shared context, rp rows
// through their inputs sidecars) with the pinned result of results-c2.json.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fromHex, toHex } from "./cbor";
import { Identity, Inputs, root } from "./difffuzz-pyref";
import { rpOptions } from "./relying-party-inputs";
import { parseStatefulPrior } from "./stateful-fixtures";
import { B1Verification, VerifyB1Options, verifyBundle } from "./verifier";

export const AT = 1_735_689_800;

export interface Pinned { result: string; code: string | null; step: number | null; verdict_sha256: string }
export interface Seed {
  path: string;                 // kats/... as results-c2.json keys it
  raw: Uint8Array;              // the row's own bytes
  context: Uint8Array | null;   // shared context bundle for a standalone object
  bundle: Uint8Array;           // what both verifiers evaluate as a bundle: context ?? raw
  inputs: Inputs;               // batch request inputs (absolute sidecar paths)
  options: VerifyB1Options;     // the harness's view of the same inputs
  pinned: Pinned;
}

const ENUMERATE = `
import json
from pyref.kat import ROOT, _c2_fixture_paths, _sidecar_path, _prior_path, _context_for_standalone, _inputs_path, _bundle_path
base = (ROOT / "kats/positive/bundle-valid-subset.cbor").read_bytes()
rows = []
for path in _c2_fixture_paths():
    sidecar = json.loads(_sidecar_path(path).read_text())
    raw = _bundle_path(path).read_bytes()
    context = _context_for_standalone(raw, sidecar, base) if sidecar.get("object_type") not in (None, "bundle") else None
    prior_path = _prior_path(path)
    inputs = _inputs_path(path)
    rows.append({"path": str(path.relative_to(ROOT)), "bundle": str(_bundle_path(path)), "context": context.hex() if context else None,
      "prior": json.loads(prior_path.read_text()) if prior_path else None, "inputs": str(inputs) if inputs else None})
print(json.dumps(rows))
`;

interface Row { path: string; bundle: string; context: string | null; prior: Record<string, unknown> | null; inputs: string | null }

export function loadSeeds(): Seed[] {
  const proc = Bun.spawnSync(["python3", "-B", "-c", ENUMERATE], { cwd: root });
  if (proc.exitCode !== 0) throw new Error(`seed enumeration failed: ${proc.stderr.toString()}`);
  const rows = JSON.parse(proc.stdout.toString()) as Row[];
  const pins = new Map<string, Pinned>();
  for (const fixture of (JSON.parse(readFileSync(join(root, "pyref", "results-c2.json"), "utf8")) as { fixtures: Record<string, any>[] }).fixtures) {
    pins.set(fixture.fixture, { result: fixture.produced_result, code: fixture.produced_code, step: fixture.first_failure_step, verdict_sha256: fixture.verdict_sha256 });
  }
  return rows.map((row) => {
    const raw = new Uint8Array(readFileSync(row.bundle));
    const context = row.context === null ? null : fromHex(row.context);
    const pinned = pins.get(row.path);
    if (pinned === undefined) throw new Error(`${row.path} has no results-c2.json row`);
    let inputs: Inputs; let options: VerifyB1Options;
    if (row.inputs === null) {
      inputs = { evaluated_at: AT, prior_state: row.prior, replay_state: { entries: [] }, policy: null, signing_key: null, trust_policy: null };
      options = { evaluationTime: AT, replayState: [], ...(row.prior ? { priorEmissions: parseStatefulPrior(row.prior) } : {}) };
    } else {
      const directory = dirname(row.inputs);
      const sidecar = JSON.parse(readFileSync(row.inputs, "utf8"));
      const file = (name: string | null): string | null => name === null ? null : join(directory, name);
      const state = (name: string | null): unknown => name === null ? null : JSON.parse(readFileSync(join(directory, name), "utf8"));
      inputs = { evaluated_at: sidecar.at, prior_state: state(sidecar.prior_state), replay_state: state(sidecar.replay_state), policy: file(sidecar.policy), signing_key: file(sidecar.signing_key), trust_policy: file(sidecar.trust_policy) };
      options = rpOptions(directory, sidecar);
    }
    return { path: row.path, raw, context, bundle: context ?? raw, inputs, options, pinned };
  });
}

// The harness under pyref's identity, in the batch response's vocabulary.
export function harnessVerdict(bundle: Uint8Array, options: VerifyB1Options, identity: Identity): { result: string; reason: string | null; step: number | null; verdict_hex: string } {
  const verification: B1Verification = verifyBundle(bundle, { ...options, product: identity.product, version: identity.version, buildDigest: fromHex(identity.build_digest), configDigest: fromHex(identity.config_digest) });
  return { result: verification.result, reason: verification.ok ? null : verification.reason, step: verification.ok ? null : verification.step, verdict_hex: toHex(verification.verdictEnvelope!) };
}
