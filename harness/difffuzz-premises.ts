// Rejection-site saturation (Packet D, Stage E): the AST inventory from
// pyref/premises.py joined with the sites the batch recorded firing. This is a
// budget rule for a run, not a correctness claim: a site that never fired says
// the run did not reach it; a site that fired says nothing about the clause
// being driven both ways.
import { Site, root } from "./difffuzz-pyref";

export interface InventorySite { file: string; line: number; code: string | "dynamic"; step: number | "dynamic"; code_expr?: string }
export interface Inventory { inventory: InventorySite[]; excluded: (InventorySite & { reason: string })[]; counts: Record<string, number> }

export function inventory(): Inventory {
  const proc = Bun.spawnSync(["python3", "-B", "-m", "pyref.premises"], { cwd: root });
  if (proc.exitCode !== 0) throw new Error(`pyref.premises failed: ${proc.stderr.toString()}`);
  return JSON.parse(proc.stdout.toString()) as Inventory;
}

export interface Saturation {
  inventory_size: number; excluded: Inventory["excluded"]; fired_by_corpus: number; fired_by_run: number;
  never_fired: InventorySite[]; saturation_percent: number; fired_outside_inventory: string[];
}

const key = (file: string, line: number): string => `${file}:${line}`;

export function saturation(corpusSites: readonly Site[], allSites: readonly Site[]): Saturation {
  const { inventory: sites, excluded } = inventory();
  const known = new Set(sites.map((site) => key(site.file, site.line)));
  const excludedKeys = new Set(excluded.map((site) => key(site.file, site.line)));
  const corpus = new Set(corpusSites.map(([file, line]) => key(file, line)));
  const run = new Set(allSites.map(([file, line]) => key(file, line)));
  const neverFired = sites.filter((site) => !run.has(key(site.file, site.line)));
  const firedByRun = sites.length - neverFired.length;
  return {
    inventory_size: sites.length, excluded, fired_by_corpus: sites.filter((site) => corpus.has(key(site.file, site.line))).length, fired_by_run: firedByRun,
    never_fired: neverFired, saturation_percent: Math.round((firedByRun / sites.length) * 1000) / 10,
    fired_outside_inventory: [...run].filter((item) => !known.has(item) && !excludedKeys.has(item)).sort(),
  };
}
