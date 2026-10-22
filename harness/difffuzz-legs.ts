// Leg oracle run (Packet D, Stage D): every (positive seed x applicable leg x
// class) through both verifiers, classified as pass / masked / split /
// corruption-accepted / claim-weakening-unmoved / unexpected / unsupported
// against the leg table's allowed outcome set (D-03 item 1).
import { CborValue, decodeCbor, encodeCbor, fromHex, toHex } from "./cbor";
import { request } from "./difffuzz-baseline";
import { Side, compare, harnessSide, sideOf } from "./difffuzz-compare";
import { LEGS, LegClass, LegMutant, Leg } from "./difffuzz-leg-table";
import { getAt } from "./difffuzz-mutant";
import { Finding, SeedEntry, writeFinding } from "./difffuzz-mutants";
import { Identity, PyrefBatch, Site, runAcross } from "./difffuzz-pyref";
import { Rng } from "./difffuzz-rng";
import { Obj } from "./mutate";

export type LegOutcome = "pass" | "masked" | "corruption-accepted" | "claim-weakening-unmoved" | "split" | "unsupported" | "unexpected";

const verdictFields = (side: Side): Obj | null => side.verdict_hex === null ? null : decodeCbor((decodeCbor(fromHex(side.verdict_hex)) as CborValue[])[0] as Uint8Array) as Obj;
const field = (verdict: Obj | null, path: string): string => verdict === null ? "<none>" : toHex(encodeCbor(getAt(verdict, path.split(".")) ?? null));

export interface LegFinding extends Finding { leg: string; class: LegClass; outcome: LegOutcome }
export interface LegsRun { counts: Record<LegOutcome, number>; perLeg: Record<string, Record<LegOutcome, number>>; findings: LegFinding[]; splitFindings: Finding[]; sites: Site[] }

export async function runLegs(entries: readonly SeedEntry[], rng: Rng, batches: readonly PyrefBatch[], identity: Identity, out: string): Promise<LegsRun> {
  const zero = (): Record<LegOutcome, number> => ({ pass: 0, masked: 0, "corruption-accepted": 0, "claim-weakening-unmoved": 0, split: 0, unsupported: 0, unexpected: 0 });
  const counts = zero(); const perLeg: Record<string, Record<LegOutcome, number>> = {}; const bump = (leg: string, outcome: LegOutcome): void => { counts[outcome] += 1; (perLeg[leg] ??= zero())[outcome] += 1; };
  interface Planned { id: string; entry: SeedEntry; leg: Leg; klass: LegClass; mutant: LegMutant }
  const planned: Planned[] = []; let serial = 0;
  for (const entry of entries.filter((candidate) => candidate.view.conformant)) {
    for (const leg of LEGS) {
      for (const klass of Object.keys(leg.classes) as LegClass[]) {
        const id = `leg-${String(serial++).padStart(5, "0")}`;
        let mutant: LegMutant | null = null;
        try { if (leg.applicable(entry.view.bundle, entry.view.policy)) mutant = leg.classes[klass]!(entry, rng, out, id); } catch { mutant = null; }
        if (mutant === null) { bump(leg.leg, "unsupported"); continue; }
        planned.push({ id, entry, leg, klass, mutant });
      }
    }
  }
  const requests = planned.map((item) => ({ ...request(item.id, item.entry.row.seed, item.mutant.bytes, null, identity), inputs: item.mutant.inputs ?? item.entry.row.seed.inputs }));
  const pending = runAcross(batches, requests);
  const harnessSides = planned.map((item) => harnessSide(item.mutant.bytes, item.mutant.options ?? item.entry.row.seed.options, identity));
  const responses = await pending;
  const findings: LegFinding[] = []; const splitFindings: Finding[] = []; const sites: Site[] = [];
  planned.forEach((item, index) => {
    const response = responses[index]!; if ("sites" in response && response.sites) sites.push(...response.sites);
    const pyref = sideOf(response); const harness = harnessSides[index]!;
    const base = { id: item.id, operator: { name: `leg/${item.leg.leg}/${item.klass}`, version: 1, layer: "payload" as const, targetStep: item.leg.step, repairBoundary: "per leg table", applicable: () => true, apply: () => null }, detail: item.mutant.detail, seed: item.entry.row.seed, bundle: item.mutant.bytes, harness, pyref, request: requests[index]! };
    const comparison = compare(harness, pyref);
    let outcome: LegOutcome;
    if (comparison !== "agree") { outcome = "split"; splitFindings.push({ ...base, channel: comparison }); }
    else if (harness.step !== null && harness.step < item.leg.step) outcome = "masked";
    else if (harness.result !== "conformant") outcome = item.mutant.allowed.results.includes(harness.result!) && item.mutant.allowed.codes.includes(`${harness.reason}@${harness.step}`) ? "pass" : "unexpected";
    else {
      const allowed = item.mutant.allowed; const before = verdictFields(item.entry.row.harness)!; const after = verdictFields(harness)!;
      const moved = ["limits", "scope"].flatMap((group) => Object.keys(before[group] as Obj).map((key) => `${group}.${key}`)).filter((path) => field(before, path) !== field(after, path));
      const dropped = (before.observations as string[]).filter((observation) => !(after.observations as string[]).includes(observation));
      if (!allowed.results.includes("conformant")) outcome = item.klass === "corruption" ? "corruption-accepted" : "unexpected";
      else if (allowed.mustMove.some((path) => field(before, path) === field(after, path))) outcome = "claim-weakening-unmoved";
      else outcome = dropped.some((observation) => !allowed.observationsMayDrop.includes(observation)) || (!allowed.limitsUnchangedOk && allowed.mustMove.length === 0 && moved.length === 0) ? "unexpected" : "pass";
      if (outcome !== "pass") base.detail += ` | moved: ${moved.join(",") || "none"}; dropped: ${dropped.join(",") || "none"}`;
    }
    bump(item.leg.leg, outcome);
    if (outcome !== "pass" && outcome !== "masked") { const finding: LegFinding = { ...base, channel: comparison, leg: item.leg.leg, class: item.klass, outcome }; findings.push(finding); writeFinding(out, finding, { leg: item.leg.leg, class: item.klass, outcome, allowed: item.mutant.allowed }); }
  });
  return { counts, perLeg, findings, splitFindings, sites };
}
