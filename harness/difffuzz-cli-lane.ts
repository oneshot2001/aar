// CLI lane (Packet D, Stage E): a sampled subset of executed mutants plus the
// relying-party seeds through both CLIs with the flags they share (bundle,
// --at, --policy, --signing-key), comparing the documented exit classes and
// the signed verdict. The CLIs cannot be handed one identity, so the verdict
// is compared twice: raw hex, and the payload with the identity-dependent
// members (verifier, verdict_id) removed and the signature left out.
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

export interface CliRow { id: string; kind: "mutant" | "rp-seed"; pyref_exit: number; harness_exit: number; pyref_class: string; harness_class: string; exit_class_agree: boolean; hex_equal: boolean | null; payload_equal_modulo_identity: boolean | null }
export interface CliLane { sampled_mutants: number; rp_seeds: number; rows: CliRow[]; disagreements: string[] }

const stripIdentity = (hex: string): string => { const envelope = decodeCbor(fromHex(hex)) as CborValue[]; const verdict = decodeCbor(envelope[0] as Uint8Array) as Obj; delete verdict.verifier; delete verdict.verdict_id; return toHex(encodeCbor(verdict)); };

function one(id: string, kind: CliRow["kind"], bundle: Uint8Array, inputs: Inputs, directory: string): CliRow {
  const file = join(directory, `${id}.cbor`); writeFileSync(file, bundle);
  const shared = ["--at", String(inputs.evaluated_at), ...(inputs.policy !== null ? ["--policy", inputs.policy, "--signing-key", inputs.signing_key!] : [])];
  const pyref = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", file, ...shared], { cwd: root });
  const harness = Bun.spawnSync(["bun", "run", "harness/verify.ts", file, ...shared], { cwd: root });
  const pyrefHex = /^\s+CBOR hex: ([0-9a-f]+)$/mu.exec(pyref.stdout.toString())?.[1] ?? null;
  const harnessHex = /^Signed verdict CBOR hex: ([0-9a-f]+)$/mu.exec(harness.stdout.toString())?.[1] ?? null;
  const both = pyrefHex !== null && harnessHex !== null;
  return {
    id, kind, pyref_exit: pyref.exitCode, harness_exit: harness.exitCode, pyref_class: PYREF_CLASS[pyref.exitCode] ?? `exit ${pyref.exitCode}`, harness_class: HARNESS_CLASS[harness.exitCode] ?? `exit ${harness.exitCode}`,
    exit_class_agree: agree(pyref.exitCode, harness.exitCode), hex_equal: both ? pyrefHex === harnessHex : null, payload_equal_modulo_identity: both ? stripIdentity(pyrefHex) === stripIdentity(harnessHex) : null,
  };
}

export function runCliLane(sample: number, executed: readonly Planned[], rows: readonly BaselineRow[], rng: Rng, out: string): CliLane {
  const directory = join(out, "cli"); mkdirSync(directory, { recursive: true });
  const pool = [...executed]; const picked: Planned[] = [];
  while (picked.length < sample && pool.length > 0) picked.push(...pool.splice(rng.int(pool.length), 1));
  const rp = rows.filter((row) => row.seed.inputs.policy !== null);
  const result = [
    ...picked.map((item) => one(item.id, "mutant", item.mutant.bytes, item.entry.row.seed.inputs, directory)),
    ...rp.map((row, index) => one(`rp-${String(index).padStart(2, "0")}`, "rp-seed", row.seed.raw, row.seed.inputs, directory)),
  ];
  return { sampled_mutants: picked.length, rp_seeds: rp.length, rows: result, disagreements: result.filter((row) => !row.exit_class_agree || row.payload_equal_modulo_identity === false).map((row) => `${row.id}: pyref ${row.pyref_class}, harness ${row.harness_class}, payload-modulo-identity ${row.payload_equal_modulo_identity}`) };
}
