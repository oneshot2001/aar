// Run aggregation and the accept-line formatter (Packet D, fix-first A): the
// one place a run's numbers are joined, so a leg split, an unexpected leg
// outcome, a CLI disagreement or a leg operator error cannot stay in a JSON
// file while the accept line reads clean. Pure functions; the synthetic test
// feeds them directly.
import type { Comparison } from "./difffuzz-compare";
import type { StepCounts } from "./difffuzz-mutants";

export type LegOutcome = "pass" | "masked" | "corruption-accepted" | "claim-weakening-unmoved" | "removal-accepted" | "split" | "unexpected" | "unsupported" | "operator-error";
export const LEG_FINDING_CLASSES: readonly LegOutcome[] = ["corruption-accepted", "claim-weakening-unmoved", "removal-accepted"];
export type LegCounts = Record<LegOutcome, number>;
export const zeroLegCounts = (): LegCounts => ({ pass: 0, masked: 0, "corruption-accepted": 0, "claim-weakening-unmoved": 0, "removal-accepted": 0, split: 0, unexpected: 0, unsupported: 0, "operator-error": 0 });

export interface AggregateInput {
  seed: number;
  perStep: Record<string, StepCounts>;
  mutantFindings: readonly { channel: Comparison }[];
  legs: { counts: LegCounts; findings: readonly { channel: Comparison; outcome: LegOutcome }[] } | null;
  cli: { rows: readonly { disagreement: boolean }[]; notApplicable: number } | null;
  controls: { fired: number; total: number };
  baseline: { reproduced: number; seeds: number };
  saturation: { percent: number; sites: number; excluded: number } | null;
  hashSeedSensitive: number;
}
export interface Summary {
  seed: number; planned: number; executed: number; noop: number; unsupported: number;
  channels: { bytes: number; classification: number; crash: number; unsupported: number; adapter: number; leg: number };
  controls: { fired: number; total: number }; baseline: { reproduced: number; seeds: number };
  legs: { counts: LegCounts; finding: number } | null;
  cli: { disagreements: number; rows: number; notApplicable: number } | null;
  saturation: { percent: number; sites: number; excluded: number } | null;
  hashSeedSensitive: number;
}

const sum = (perStep: Record<string, StepCounts>, field: keyof StepCounts): number => Object.values(perStep).reduce((total, counts) => total + counts[field], 0);

export function aggregate(input: AggregateInput): Summary {
  const channels = { bytes: 0, classification: 0, crash: 0, unsupported: sum(input.perStep, "unsupported"), adapter: 0, leg: 0 };
  // Every verifier disagreement lands in the channel compare() gave it, whether a mutant or a leg mutant produced it.
  for (const finding of input.mutantFindings) channels[finding.channel as "bytes" | "classification" | "crash"] += 1;
  for (const finding of input.legs?.findings ?? []) if (finding.outcome === "split") channels[finding.channel as "bytes" | "classification" | "crash"] += 1;
  channels.leg = input.legs === null ? 0 : LEG_FINDING_CLASSES.reduce((total, klass) => total + input.legs!.counts[klass], 0);
  return {
    seed: input.seed, planned: sum(input.perStep, "planned"), executed: sum(input.perStep, "targeted"), noop: sum(input.perStep, "noop"), unsupported: sum(input.perStep, "unsupported"),
    channels, controls: input.controls, baseline: input.baseline,
    legs: input.legs === null ? null : { counts: input.legs.counts, finding: channels.leg },
    cli: input.cli === null ? null : { disagreements: input.cli.rows.filter((row) => row.disagreement).length, rows: input.cli.rows.length, notApplicable: input.cli.notApplicable },
    saturation: input.saturation, hashSeedSensitive: input.hashSeedSensitive,
  };
}

// The only form a run result takes (BACKLOG.md fuzz item, CONTRIBUTING.md "Differential fuzz"); the three strings must stay identical.
export function formatAccept(s: Summary): string {
  const legs = s.legs === null ? "legs not run" : `legs pass/masked/finding/unexpected/unsupported/operator-error = ${s.legs.counts.pass}/${s.legs.counts.masked}/${s.legs.finding}/${s.legs.counts.unexpected}/${s.legs.counts.unsupported}/${s.legs.counts["operator-error"]}`;
  const cli = s.cli === null ? "cli not run" : `cli disagreements = ${s.cli.disagreements} of ${s.cli.rows}`;
  const saturation = s.saturation === null ? "saturation not measured" : `saturation ${s.saturation.percent} % of ${s.saturation.sites} sites (${s.saturation.excluded} excluded)`;
  return `accept: seed ${s.seed}, planned ${s.planned} / executed ${s.executed} / no-op ${s.noop} / unsupported ${s.unsupported} mutants, bytes/classification/crash = ${s.channels.bytes}/${s.channels.classification}/${s.channels.crash}, controls ${s.controls.fired}/${s.controls.total}, baseline ${s.baseline.reproduced}/${s.baseline.seeds}, ${legs}, ${cli}, ${saturation}, hash-seed-sensitive = ${s.hashSeedSensitive}`;
}
