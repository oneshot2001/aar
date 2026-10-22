// Baseline pass and controls for the differential fuzz driver. The baseline
// proves every seed reproduces its pinned row in pyref and that the harness
// agrees byte for byte before any mutant runs; the controls prove the
// comparator, the transport checks and the real batch can each fail.
import { Comparison, Side, compare, harnessSide, sideOf } from "./difffuzz-compare";
import { AdapterError, BatchRequest, BatchResponse, Identity, PyrefBatch, Site, checkChunk, runAcross, sha256Hex } from "./difffuzz-pyref";
import { Seed } from "./difffuzz-seeds";

export interface BaselineRow { seed: Seed; harness: Side; pyref: Side }
export interface Baseline { rows: BaselineRow[]; sites: Site[]; mismatches: string[]; count: number }

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
export const request = (id: string, seed: Seed, bundle: Uint8Array, context: Uint8Array | null, identity: Identity): BatchRequest => ({ id, bundle_hex: hex(bundle), context_hex: context === null ? null : hex(context), inputs: seed.inputs, identity });

function pinnedMismatch(seed: Seed, response: BatchResponse): string | null {
  if (!("result" in response)) return `${seed.path}: pyref ${"crash" in response ? `crashed ${response.crash.type}` : "protocol error"}`;
  const { result, code, step, verdict_sha256 } = seed.pinned;
  const produced = `${response.result}/${response.reason}@${response.step}`;
  if (response.result !== result || response.reason !== code || response.step !== step) return `${seed.path}: pyref ${produced}, pinned ${result}/${code}@${step}`;
  const digest = sha256Hex(Buffer.from(response.verdict_hex, "hex"));
  return digest === verdict_sha256 ? null : `${seed.path}: pyref verdict sha256 ${digest}, pinned ${verdict_sha256}`;
}

// Every seed through pyref as pyref.kat evaluates it (own bytes + context), pinned-row check, then the harness
// against pyref on the bundle both evaluate (standalone rows need one more pyref request on the context bundle).
export async function runBaseline(seeds: readonly Seed[], batches: readonly PyrefBatch[], identity: Identity): Promise<Baseline> {
  const requests: BatchRequest[] = [];
  seeds.forEach((seed, index) => {
    requests.push(request(`base-${index}`, seed, seed.raw, seed.context, identity));
    if (seed.context !== null) requests.push(request(`ctx-${index}`, seed, seed.context, null, identity));
  });
  const pending = runAcross(batches, requests); // pyref works on its first chunks while the harness evaluates every seed
  const harnessSides = seeds.map((seed) => harnessSide(seed.bundle, seed.options, identity));
  const responses = new Map((await pending).map((response, index) => [requests[index]!.id, response]));
  const rows: BaselineRow[] = []; const mismatches: string[] = []; const sites: Site[] = [];
  seeds.forEach((seed, index) => {
    const own = responses.get(`base-${index}`)!;
    const mismatch = pinnedMismatch(seed, own); if (mismatch !== null) mismatches.push(mismatch);
    if ("sites" in own && own.sites) sites.push(...own.sites);
    const pyref = sideOf(seed.context === null ? own : responses.get(`ctx-${index}`)!);
    const harness = harnessSides[index]!;
    const comparison = compare(harness, pyref);
    if (comparison !== "agree") mismatches.push(`${seed.path}: harness vs pyref ${comparison} (${harness.result}/${harness.reason}@${harness.step} vs ${pyref.result}/${pyref.reason}@${pyref.step})`);
    rows.push({ seed, harness, pyref });
  });
  return { rows, sites, mismatches, count: seeds.length };
}

export interface Control { name: string; expected: string; passed: boolean; detail: string }

// Eight controls, injected into the driver's copies of results, never into a verifier.
export async function runControls(baseline: Baseline, batch: PyrefBatch, identity: Identity): Promise<Control[]> {
  const row = baseline.rows.find((candidate) => candidate.harness.verdict_hex !== null)!;
  const flipped = { ...row.harness, verdict_hex: `${row.harness.verdict_hex!.slice(0, -1)}${row.harness.verdict_hex!.endsWith("0") ? "1" : "0"}` };
  const check = (name: string, expected: Comparison, actual: Comparison): Control => ({ name, expected, passed: actual === expected, detail: `comparator said ${actual}` });
  const controls: Control[] = [
    check("1 flipped harness verdict byte", "bytes", compare(flipped, row.pyref)),
    check("2 rewritten pyref result", "classification", compare(row.harness, { ...row.pyref, result: row.pyref.result === "conformant" ? "nonconformant" : "conformant" })),
    check("3 synthetic crash response", "crash", compare(row.harness, sideOf({ id: "control-3", input_sha256: "", crash: { type: "SyntheticError", message: "control" } }))),
  ];
  const three = [0, 1, 2].map((index) => request(`control-${index}`, row.seed, row.seed.bundle, null, identity));
  const lines = three.map((item) => JSON.stringify({ id: item.id, input_sha256: sha256Hex(row.seed.bundle), result: "conformant", reason: null, step: null, verdict_hex: "" }));
  const throws = (name: string, candidate: string[]): Control => { try { checkChunk(three, candidate); return { name, expected: "adapter", passed: false, detail: "checkChunk accepted the lines" }; } catch (error) { return { name, expected: "adapter", passed: error instanceof AdapterError, detail: (error as Error).message }; } };
  controls.push(throws("4 dropped response", lines.slice(0, 2)), throws("5 duplicate response", [lines[0]!, lines[0]!, lines[2]!]), throws("6 malformed response line", [lines[0]!, "{garbage", lines[2]!]));
  const canary = async (name: string, seed: Seed | undefined): Promise<Control> => {
    if (seed === undefined) return { name, expected: "pinned row", passed: false, detail: "canary row missing from the corpus" };
    const [response] = await batch.run([request(`canary-${name.charAt(0)}`, seed, seed.raw, seed.context, identity)]);
    const mismatch = pinnedMismatch(seed, response!);
    return { name, expected: "pinned row", passed: mismatch === null, detail: mismatch ?? `${seed.path} reproduced ${seed.pinned.result}/${seed.pinned.code}@${seed.pinned.step}` };
  };
  controls.push(await canary("7 pinned positive canary", baseline.rows.find((candidate) => candidate.seed.path === "kats/positive/bundle-valid-subset.cbor")?.seed));
  controls.push(await canary("8 pinned negative canary", baseline.rows.find((candidate) => candidate.seed.path.startsWith("kats/negative/repair-d82-"))?.seed));
  return controls;
}
