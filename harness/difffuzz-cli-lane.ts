// CLI lane (Packet D, Stage E; fix-first B): a sampled subset of executed
// mutants plus the relying-party seeds through both CLIs with the flags they
// share (bundle, --at, --policy, --signing-key), comparing the documented exit
// classes and the signed verdict. Exit classes that promise a signed verdict
// (pyref 0/1/3, harness 0/1) must print one: a missing or one-sided `CBOR hex`
// line is a disagreement, never an agreement by absence. The CLIs cannot be
// handed one identity, so the verdict is compared twice: raw hex, and the
// payload with the identity-dependent members (verifier, verdict_id) removed
// and the signature left out. Seeds whose inputs name a prior/replay state or
// a trust-policy pin have no harness CLI twin and are counted not applicable.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CborValue, decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { BaselineRow } from "./difffuzz-baseline";
import { Planned } from "./difffuzz-mutants";
import { Inputs, root } from "./difffuzz-pyref";
import { Rng } from "./difffuzz-rng";
import { Obj } from "./mutate";

const PYREF_CLASS: Record<number, string> = { 0: "conformant", 1: "nonconformant", 2: "usage", 3: "indeterminate", 70: "internal" };
const HARNESS_CLASS: Record<number, string> = { 0: "conformant", 1: "nonconformant-or-indeterminate", 2: "usage" };
const agree = (pyref: number, harness: number): boolean => (pyref === 0 && harness === 0) || ((pyref === 1 || pyref === 3) && harness === 1) || (pyref === 2 && harness === 2);
const promisesVerdict = { pyref: (exit: number): boolean => exit === 0 || exit === 1 || exit === 3, harness: (exit: number): boolean => exit === 0 || exit === 1 };

export interface CliOutput { exitCode: number; stdout: string }
export interface CliRow {
  id: string; kind: "mutant" | "rp-seed"; pyref_exit: number; harness_exit: number; pyref_class: string; harness_class: string;
  exit_class_agree: boolean; pyref_verdict: boolean; harness_verdict: boolean; verdict_missing: boolean; hex_equal: boolean | null; payload_equal_modulo_identity: boolean | null;
  disagreement: boolean; reasons: string[];
}
export interface CliLane { sampled_mutants: number; rp_seeds: number; not_applicable: number; rows: CliRow[]; disagreements: string[] }

const stripIdentity = (hex: string): string => { const envelope = decodeCbor(fromHex(hex)) as CborValue[]; const verdict = decodeCbor(envelope[0] as Uint8Array) as Obj; delete verdict.verifier; delete verdict.verdict_id; return toHex(encodeCbor(verdict)); };

// Pure comparison of one process pair's exit codes and printed verdicts.
export function classify(id: string, kind: CliRow["kind"], pyref: CliOutput, harness: CliOutput): CliRow {
  const pyrefHex = /^\s+CBOR hex: ([0-9a-f]+)$/mu.exec(pyref.stdout)?.[1] ?? null;
  const harnessHex = /^Signed verdict CBOR hex: ([0-9a-f]+)$/mu.exec(harness.stdout)?.[1] ?? null;
  const both = pyrefHex !== null && harnessHex !== null;
  const reasons: string[] = [];
  const exitAgree = agree(pyref.exitCode, harness.exitCode);
  if (!exitAgree) reasons.push(`exit class pyref ${PYREF_CLASS[pyref.exitCode] ?? pyref.exitCode} vs harness ${HARNESS_CLASS[harness.exitCode] ?? harness.exitCode}`);
  const missing = [promisesVerdict.pyref(pyref.exitCode) && pyrefHex === null ? "pyref printed no verdict for a class that promises one" : null, promisesVerdict.harness(harness.exitCode) && harnessHex === null ? "harness printed no verdict for a class that promises one" : null, (pyrefHex === null) !== (harnessHex === null) ? "verdict printed on one side only" : null].filter((reason): reason is string => reason !== null);
  reasons.push(...missing);
  const payloadEqual = both ? stripIdentity(pyrefHex) === stripIdentity(harnessHex) : null;
  if (both && payloadEqual !== true) reasons.push("verdict payloads differ beyond identity");
  return {
    id, kind, pyref_exit: pyref.exitCode, harness_exit: harness.exitCode, pyref_class: PYREF_CLASS[pyref.exitCode] ?? `exit ${pyref.exitCode}`, harness_class: HARNESS_CLASS[harness.exitCode] ?? `exit ${harness.exitCode}`,
    exit_class_agree: exitAgree, pyref_verdict: pyrefHex !== null, harness_verdict: harnessHex !== null, verdict_missing: missing.length > 0,
    hex_equal: both ? pyrefHex === harnessHex : null, payload_equal_modulo_identity: payloadEqual, disagreement: reasons.length > 0, reasons,
  };
}

// Only the flags both CLIs share can be passed; anything else makes the row not applicable to the lane.
export const laneApplicable = (inputs: Inputs): boolean => inputs.prior_state === null && (inputs.replay_state === null || ((inputs.replay_state as { entries?: unknown[] }).entries ?? []).length === 0) && inputs.trust_policy === null;

function one(id: string, kind: CliRow["kind"], bundle: Uint8Array, inputs: Inputs, directory: string): CliRow {
  const file = join(directory, `${id}.cbor`); writeFileSync(file, bundle);
  const shared = ["--at", String(inputs.evaluated_at), ...(inputs.policy !== null ? ["--policy", inputs.policy, "--signing-key", inputs.signing_key!] : [])];
  const pyref = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", file, ...shared], { cwd: root });
  const harness = Bun.spawnSync(["bun", "run", "harness/verify.ts", file, ...shared], { cwd: root });
  return classify(id, kind, { exitCode: pyref.exitCode, stdout: pyref.stdout.toString() }, { exitCode: harness.exitCode, stdout: harness.stdout.toString() });
}

export function runCliLane(sample: number, executed: readonly Planned[], rows: readonly BaselineRow[], rng: Rng, out: string): CliLane {
  const directory = join(out, "cli"); mkdirSync(directory, { recursive: true });
  const applicableMutants = executed.filter((item) => laneApplicable(item.entry.row.seed.inputs));
  const pool = [...applicableMutants]; const picked: Planned[] = [];
  while (picked.length < sample && pool.length > 0) picked.push(...pool.splice(rng.int(pool.length), 1));
  const rp = rows.filter((row) => row.seed.inputs.policy !== null);
  const applicableRp = rp.filter((row) => laneApplicable(row.seed.inputs));
  const result = [
    ...picked.map((item) => one(item.id, "mutant", item.mutant.bytes, item.entry.row.seed.inputs, directory)),
    ...applicableRp.map((row, index) => one(`rp-${String(index).padStart(2, "0")}`, "rp-seed", row.seed.raw, row.seed.inputs, directory)),
  ];
  return {
    sampled_mutants: picked.length, rp_seeds: applicableRp.length, not_applicable: (executed.length - applicableMutants.length) + (rp.length - applicableRp.length), rows: result,
    disagreements: result.filter((row) => row.disagreement).map((row) => `${row.id}: ${row.reasons.join("; ")}`),
  };
}
