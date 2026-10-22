// Leg oracle run (Packet D, Stage D; fix-first A): every (positive seed x
// applicable leg x class) through both verifiers, classified against the leg
// table's allowed outcome set (D-03 item 1). A split carries the channel
// compare() gave it; a required leg removed with both verifiers still
// conformant is removal-accepted; a leg operator exception is operator-error,
// never unsupported. Nothing is written here: the driver re-executes every
// finding under a random hash seed first, then writes.
import { CborValue, decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { request } from "./difffuzz-baseline";
import { Side, compare, harnessSide, sideOf } from "./difffuzz-compare";
import { Allowed, LEGS, LegClass, LegMutant, Leg } from "./difffuzz-leg-table";
import { getAt } from "./difffuzz-mutant";
import { Finding, SeedEntry } from "./difffuzz-mutants";
import { Identity, PyrefBatch, Site, runAcross } from "./difffuzz-pyref";
import { LegCounts, LegOutcome, zeroLegCounts } from "./difffuzz-report";
import { Rng } from "./difffuzz-rng";
import { Obj } from "./mutate";

const verdictFields = (side: Side): Obj | null => side.verdict_hex === null ? null : decodeCbor((decodeCbor(fromHex(side.verdict_hex)) as CborValue[])[0] as Uint8Array) as Obj;
const field = (verdict: Obj | null, path: string): string => verdict === null ? "<none>" : toHex(encodeCbor(getAt(verdict, path.split(".")) ?? null));

export interface LegFinding extends Finding { leg: string; class: LegClass; outcome: LegOutcome; allowed: Allowed }
export interface LegsRun { counts: LegCounts; perLeg: Record<string, LegCounts>; findings: LegFinding[]; operatorErrors: Record<string, string[]>; sites: Site[] }

export async function runLegs(entries: readonly SeedEntry[], rng: Rng, batches: readonly PyrefBatch[], identity: Identity, out: string): Promise<LegsRun> {
  const counts = zeroLegCounts(); const perLeg: Record<string, LegCounts> = {}; const operatorErrors: Record<string, string[]> = {};
  // counts per leg and per leg/class, so a removal that legitimately leaves the verdict unchanged is readable apart from a corruption
  const bump = (leg: string, klass: LegClass, outcome: LegOutcome): void => { counts[outcome] += 1; (perLeg[leg] ??= zeroLegCounts())[outcome] += 1; (perLeg[`${leg}/${klass}`] ??= zeroLegCounts())[outcome] += 1; };
  interface Planned { id: string; entry: SeedEntry; leg: Leg; klass: LegClass; mutant: LegMutant }
  const planned: Planned[] = []; let serial = 0;
  for (const entry of entries.filter((candidate) => candidate.view.conformant)) {
    for (const leg of LEGS) {
      for (const klass of Object.keys(leg.classes) as LegClass[]) {
        const id = `leg-${String(serial++).padStart(5, "0")}`;
        let mutant: LegMutant | null = null;
        try { if (leg.applicable(entry.view.bundle, entry.view.policy)) mutant = leg.classes[klass]!(entry, rng, out, id); } catch (error) {
          (operatorErrors[`${leg.leg}/${klass}`] ??= []).push(`${entry.row.seed.path}: ${(error as Error).message}`); bump(leg.leg, klass, "operator-error"); continue;
        }
        if (mutant === null) { bump(leg.leg, klass, "unsupported"); continue; }
        planned.push({ id, entry, leg, klass, mutant });
      }
    }
  }
  const requests = planned.map((item) => ({ ...request(item.id, item.entry.row.seed, item.mutant.bytes, null, identity), inputs: item.mutant.inputs ?? item.entry.row.seed.inputs }));
  const pending = runAcross(batches, requests);
  const harnessSides = planned.map((item) => harnessSide(item.mutant.bytes, item.mutant.options ?? item.entry.row.seed.options, identity));
  const responses = await pending;
  const findings: LegFinding[] = []; const sites: Site[] = [];
  planned.forEach((item, index) => {
    const response = responses[index]!; if ("sites" in response && response.sites) sites.push(...response.sites);
    const pyref = sideOf(response); const harness = harnessSides[index]!; const allowed = item.mutant.allowed;
    const comparison = compare(harness, pyref);
    let outcome: LegOutcome; let detail = item.mutant.detail;
    if (comparison !== "agree") outcome = "split";
    else if (harness.step !== null && harness.step < item.leg.step) outcome = "masked";
    else if (harness.result !== "conformant") outcome = allowed.results.includes(harness.result!) && allowed.codes.includes(`${harness.reason}@${harness.step}`) ? "pass" : "unexpected";
    else {
      const before = verdictFields(item.entry.row.harness)!; const after = verdictFields(harness)!;
      const paths = ["limits", "scope"].flatMap((group) => [...new Set([...Object.keys(before[group] as Obj), ...Object.keys(after[group] as Obj)])].sort().map((key) => `${group}.${key}`));
      const moved = paths.filter((path) => field(before, path) !== field(after, path));
      const dropped = (before.observations as string[]).filter((observation) => !(after.observations as string[]).includes(observation));
      if (!allowed.results.includes("conformant")) outcome = item.klass === "corruption" ? "corruption-accepted" : item.klass === "removal" ? "removal-accepted" : "unexpected";
      else if (allowed.mustMove.some((path) => field(before, path) === field(after, path))) outcome = "claim-weakening-unmoved";
      else outcome = dropped.some((observation) => !allowed.observationsMayDrop.includes(observation)) || (!allowed.limitsUnchangedOk && allowed.mustMove.length === 0 && moved.length === 0) ? "unexpected" : "pass";
      if (outcome !== "pass") detail += ` | moved: ${moved.join(",") || "none"}; dropped: ${dropped.join(",") || "none"}`;
    }
    bump(item.leg.leg, item.klass, outcome);
    if (outcome !== "pass" && outcome !== "masked") findings.push({
      id: item.id, channel: comparison, operator: { name: `leg/${item.leg.leg}/${item.klass}`, version: 1, layer: "payload", targetStep: item.leg.step, repairBoundary: "per leg table", applicable: () => true, apply: () => null },
      detail, seed: item.entry.row.seed, bundle: item.mutant.bytes, harness, pyref, request: requests[index]!, leg: item.leg.leg, class: item.klass, outcome, allowed,
    });
  });
  return { counts, perLeg, findings, operatorErrors, sites };
}
