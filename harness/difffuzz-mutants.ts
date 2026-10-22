// Mutant planning and execution for the differential fuzz driver: per-step
// quotas, weighted seed choice, survival check, both verifiers, classification
// into findings / verdict no-ops / masked / agree, and the per-finding record.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { decodeCbor } from "./cbor";
import { Comparison, Side, compare, harnessSide, masked, sideOf, stableSide, verdictNoop } from "./difffuzz-compare";
import { Mutant, Operator, SeedView, survives } from "./difffuzz-mutant";
import { BatchRequest, Identity, PyrefBatch, Site, runAcross } from "./difffuzz-pyref";
import { Rng } from "./difffuzz-rng";
import { Seed } from "./difffuzz-seeds";
import { Obj } from "./mutate";
import { request, BaselineRow } from "./difffuzz-baseline";

export const MAX_SEED_BYTES = 1_048_576; // seeds above this (the resource/* negatives) are not mutated
export const RAW_SHARE = 0.2;

export interface SeedEntry { row: BaselineRow; view: SeedView }
export function seedViews(rows: readonly BaselineRow[]): SeedEntry[] {
  return rows.flatMap((row) => {
    if (row.seed.bundle.length > MAX_SEED_BYTES) return [];
    let bundle: Obj;
    try { bundle = decodeCbor(row.seed.bundle) as Obj; } catch { return []; }
    if (typeof bundle !== "object" || bundle === null || Array.isArray(bundle) || bundle instanceof Uint8Array || bundle instanceof Map || typeof bundle.artifacts !== "object") return [];
    return [{ row, view: { bundle, bytes: row.seed.bundle, policy: row.seed.inputs.policy !== null, conformant: row.seed.pinned.result === "conformant", pinnedStep: row.seed.pinned.step } }];
  });
}

export interface StepCounts { planned: number; executed: number; noop: number; unsupported: number; masked: number; verdict_noop: number; findings: number }
const zero = (): StepCounts => ({ planned: 0, executed: 0, noop: 0, unsupported: 0, masked: 0, verdict_noop: 0, findings: 0 });
export const groupOf = (operator: Operator): string => operator.layer === "raw" ? "raw" : operator.targetStep === null ? "generic" : `step-${operator.targetStep}`;

// Budget: raw <= RAW_SHARE; the rest split evenly over the targeted groups (every step >= 5 % as long as there are <= 16 groups).
export function quotas(total: number, operators: readonly Operator[]): Map<string, number> {
  const groups = [...new Set(operators.map(groupOf))].sort((a, b) => (a === "raw" ? -1 : b === "raw" ? 1 : a === "generic" ? 1 : b === "generic" ? -1 : Number(a.slice(5)) - Number(b.slice(5))));
  const raw = groups.includes("raw") ? Math.floor(total * RAW_SHARE) : 0;
  const targeted = groups.filter((group) => group !== "raw"); const each = Math.floor((total - raw) / targeted.length); let remainder = total - raw - each * targeted.length;
  return new Map(groups.map((group) => [group, group === "raw" ? raw : each + (remainder-- > 0 ? 1 : 0)]));
}

export interface Planned { id: string; operator: Operator; entry: SeedEntry; mutant: Mutant }
export interface Outcome { id: string; operator: string; seed: string; kind: "finding" | "verdict_noop" | "masked" | "agree"; channel: Comparison; harness: Side; pyref: Side; detail: string }
export interface Finding { id: string; channel: Comparison; operator: Operator; detail: string; seed: Seed; bundle: Uint8Array; harness: Side; pyref: Side; request: BatchRequest; hash_seed_sensitive?: boolean }
export interface MutantRun { perStep: Record<string, StepCounts>; perOperator: Record<string, StepCounts>; outcomes: Outcome[]; findings: Finding[]; operatorErrors: Record<string, string[]>; sites: Site[]; executed: Planned[] }

const bump = (table: Record<string, StepCounts>, key: string, field: keyof StepCounts): void => { (table[key] ??= zero())[field] += 1; };
// A seed shape the operator cannot even inspect is not applicable.
const applicable = (operator: Operator, view: SeedView): boolean => { try { return operator.applicable(view); } catch { return false; } };

export async function runMutants(total: number, operators: readonly Operator[], entries: readonly SeedEntry[], rng: Rng, batches: readonly PyrefBatch[], identity: Identity): Promise<MutantRun> {
  const perStep: Record<string, StepCounts> = {}; const perOperator: Record<string, StepCounts> = {}; const operatorErrors: Record<string, string[]> = {};
  const planned: Planned[] = []; let serial = 0;
  for (const [group, budget] of quotas(total, operators)) {
    const candidates = operators.filter((operator) => groupOf(operator) === group);
    for (let k = 0; k < budget; k += 1) {
      const operator = rng.pick(candidates); const id = `m-${String(serial++).padStart(5, "0")}`;
      bump(perStep, group, "planned"); bump(perOperator, operator.name, "planned");
      // Positives weigh 4, negatives that fail at or after the target step weigh 1, earlier-failing negatives are left out.
      const pool = entries.flatMap((entry) => !applicable(operator, entry.view) || (!entry.view.conformant && operator.targetStep !== null && entry.view.pinnedStep !== null && entry.view.pinnedStep < operator.targetStep) ? [] : Array<SeedEntry>(entry.view.conformant ? 4 : 1).fill(entry));
      if (pool.length === 0) { bump(perStep, group, "unsupported"); bump(perOperator, operator.name, "unsupported"); continue; }
      const entry = rng.pick(pool);
      let mutant: Mutant | null;
      try { mutant = operator.apply(entry.view, rng); } catch (error) { (operatorErrors[operator.name] ??= []).push(`${entry.row.seed.path}: ${(error as Error).message}`); mutant = null; }
      if (mutant === null) { bump(perStep, group, "unsupported"); bump(perOperator, operator.name, "unsupported"); continue; }
      if (!survives(entry.view, mutant)) { bump(perStep, group, "noop"); bump(perOperator, operator.name, "noop"); continue; }
      bump(perStep, group, "executed"); bump(perOperator, operator.name, "executed");
      planned.push({ id, operator, entry, mutant });
    }
  }
  const requests = planned.map((item) => request(item.id, item.entry.row.seed, item.mutant.bytes, null, identity));
  const pending = runAcross(batches, requests); // pyref works on its first chunks while the harness evaluates every mutant
  const harnessSides = planned.map((item) => harnessSide(item.mutant.bytes, item.entry.row.seed.options, identity));
  const responses = await pending;
  const outcomes: Outcome[] = []; const findings: Finding[] = []; const sites: Site[] = [];
  planned.forEach((item, index) => {
    const response = responses[index]!; if ("sites" in response && response.sites) sites.push(...response.sites);
    const pyref = sideOf(response); const harness = harnessSides[index]!;
    const channel = compare(harness, pyref); const group = groupOf(item.operator);
    const kind: Outcome["kind"] = channel !== "agree" ? "finding" : verdictNoop(harness, pyref, item.entry.row.pyref) ? "verdict_noop" : masked(harness, pyref, item.operator.targetStep) ? "masked" : "agree";
    if (kind === "finding") { bump(perStep, group, "findings"); bump(perOperator, item.operator.name, "findings"); findings.push({ id: item.id, channel, operator: item.operator, detail: item.mutant.detail, seed: item.entry.row.seed, bundle: item.mutant.bytes, harness, pyref, request: requests[index]! }); }
    else if (kind !== "agree") { bump(perStep, group, kind); bump(perOperator, item.operator.name, kind); }
    outcomes.push({ id: item.id, operator: item.operator.name, seed: item.entry.row.seed.path, kind, channel, harness, pyref, detail: item.mutant.detail });
  });
  return { perStep, perOperator, outcomes, findings, operatorErrors, sites, executed: planned };
}

// DIR/<id>/bundle.cbor, context.cbor (if any), inputs.json, both.json (stable and volatile objects apart).
export function writeFinding(out: string, finding: Finding, extra: Record<string, unknown> = {}): void {
  const directory = join(out, finding.id); mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "bundle.cbor"), finding.bundle);
  if (finding.request.context_hex !== null) writeFileSync(join(directory, "context.cbor"), Buffer.from(finding.request.context_hex, "hex"));
  writeFileSync(join(directory, "inputs.json"), `${JSON.stringify(finding.request.inputs, null, 2)}\n`);
  const both = {
    stable: { id: finding.id, channel: finding.channel, operator: { name: finding.operator.name, version: finding.operator.version, layer: finding.operator.layer, target_step: finding.operator.targetStep, repair_boundary: finding.operator.repairBoundary }, detail: finding.detail, seed: { path: finding.seed.path, pinned: finding.seed.pinned }, harness: stableSide(finding.harness), pyref: stableSide(finding.pyref), hash_seed_sensitive: finding.hash_seed_sensitive ?? false, ...extra },
    volatile: { harness: { verdict_hex: finding.harness.verdict_hex, crash: finding.harness.crash }, pyref: { verdict_hex: finding.pyref.verdict_hex, crash: finding.pyref.crash }, directory },
  };
  writeFileSync(join(directory, "both.json"), `${JSON.stringify(both, null, 2)}\n`);
}
