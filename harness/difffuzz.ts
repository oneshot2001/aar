// Differential fuzz driver (Packet D). Usage:
//   bun run harness/difffuzz.ts --seed N --mutants N --out DIR [--chunk 250] [--premises] [--legs] [--cli-lane N]
// Exit 0 = run completed (findings, if any, are in DIR); 2 = baseline mismatch;
// 3 = a control did not fire; 4 = adapter (transport/handshake) failure.
// Nothing under kats/ is written; a run reports only with every number.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Baseline, runBaseline, runControls } from "./difffuzz-baseline";
import { runCliLane } from "./difffuzz-cli-lane";
import { runLegs } from "./difffuzz-legs";
import { Finding, MutantRun, runMutants, seedViews, writeFinding } from "./difffuzz-mutants";
import { OPERATORS } from "./difffuzz-operators";
import { saturation } from "./difffuzz-premises";
import { sideOf } from "./difffuzz-compare";
import { AdapterError, PyrefBatch, Site, root } from "./difffuzz-pyref";
import { RNG_SPEC, Rng } from "./difffuzz-rng";
import { loadSeeds } from "./difffuzz-seeds";

function args(): { seed: number; mutants: number; out: string; chunk: number; premises: boolean; legs: boolean; cliLane: number } {
  const argv = process.argv.slice(2); const flag = (name: string): string | undefined => { const index = argv.indexOf(name); return index >= 0 ? argv[index + 1] : undefined; };
  const seed = Number(flag("--seed")); const mutants = Number(flag("--mutants")); const out = flag("--out");
  if (!Number.isInteger(seed) || !Number.isInteger(mutants) || mutants < 0 || out === undefined) { console.error("usage: bun run harness/difffuzz.ts --seed N --mutants N --out DIR [--chunk 250] [--premises] [--legs] [--cli-lane N]"); process.exit(1); }
  return { seed, mutants, out, chunk: Number(flag("--chunk") ?? 250), premises: argv.includes("--premises"), legs: argv.includes("--legs"), cliLane: Number(flag("--cli-lane") ?? 0) };
}

// pyref is CPU-bound and single-threaded: the baseline and the mutant stream are spread over this many batch processes.
const PYREF_LANES = 3;
const git = (...command: string[]): string => Bun.spawnSync(["git", ...command], { cwd: root }).stdout.toString().trim();
const now = (): number => Date.now();
const progress = (message: string): void => { console.error(`[difffuzz] ${message}`); };

// Every finding once more through a fresh batch under PYTHONHASHSEED=random; a different pyref output tags it.
async function hashSeedReexecution(findings: Finding[], chunk: number, premises: boolean): Promise<number> {
  if (findings.length === 0) return 0;
  const batch = await PyrefBatch.start({ chunk, premises, env: { PYTHONHASHSEED: "random" } });
  const responses = await batch.run(findings.map((finding) => ({ ...finding.request, identity: batch.handshake.identity })));
  await batch.close();
  let sensitive = 0;
  findings.forEach((finding, index) => {
    const again = sideOf(responses[index]!);
    finding.hash_seed_sensitive = again.result !== finding.pyref.result || again.reason !== finding.pyref.reason || again.step !== finding.pyref.step || again.verdict_hex !== finding.pyref.verdict_hex || (again.crash?.type ?? null) !== (finding.pyref.crash?.type ?? null);
    if (finding.hash_seed_sensitive) sensitive += 1;
  });
  return sensitive;
}

async function main(): Promise<number> {
  const options = args(); const started = now(); const times: Record<string, number> = {};
  mkdirSync(options.out, { recursive: true });
  const seeds = loadSeeds(); times.seeds_ms = now() - started; progress(`${seeds.length} seeds loaded in ${times.seeds_ms} ms`);
  let batches: PyrefBatch[];
  try { batches = await Promise.all(Array.from({ length: PYREF_LANES }, () => PyrefBatch.start({ chunk: options.chunk, premises: options.premises }))); } catch (error) { console.error(`adapter: ${(error as Error).message}`); return 4; }
  const batch = batches[0]!; const identity = batch.handshake.identity;
  let baseline: Baseline;
  try {
    const t = now(); baseline = await runBaseline(seeds, batches, identity); times.baseline_ms = now() - t; progress(`baseline ${baseline.count - baseline.mismatches.length}/${baseline.count} in ${times.baseline_ms} ms`);
    if (baseline.mismatches.length > 0) { console.error(`baseline: ${baseline.mismatches.length} of ${baseline.count} seeds do not reproduce their pinned row; nothing else is reported`); for (const line of baseline.mismatches.slice(0, 20)) console.error(`  ${line}`); return 2; }
    const controls = await runControls(baseline, batch, identity);
    const fired = controls.filter((control) => control.passed).length; progress(`controls ${fired}/${controls.length}`);
    if (fired !== controls.length) { console.error(`controls: ${fired}/${controls.length} fired; nothing else is reported`); for (const control of controls) console.error(`  ${control.passed ? "ok " : "NOT"} ${control.name}: ${control.detail}`); return 3; }
    const rng = new Rng(options.seed); const entries = seedViews(baseline.rows);
    const t2 = now(); const mutants: MutantRun = await runMutants(options.mutants, OPERATORS, entries, rng, batches, identity); times.mutants_ms = now() - t2; progress(`${mutants.executed.length} mutants executed, ${mutants.findings.length} findings in ${times.mutants_ms} ms`);
    const sites: Site[] = [...baseline.sites, ...mutants.sites];
    let legs = null;
    if (options.legs) { const t3 = now(); legs = await runLegs(entries, rng, batches, identity, options.out); times.legs_ms = now() - t3; progress(`legs ${JSON.stringify(legs.counts)} in ${times.legs_ms} ms`); sites.push(...legs.sites); writeFileSync(join(options.out, "legs.json"), `${JSON.stringify({ counts: legs.counts, per_leg: legs.perLeg, findings: legs.findings.map((finding) => ({ id: finding.id, leg: finding.leg, class: finding.class, outcome: finding.outcome, seed: finding.seed.path, detail: finding.detail })) }, null, 2)}\n`); }
    const t4 = now(); const sensitive = await hashSeedReexecution([...mutants.findings, ...(legs?.splitFindings ?? [])], options.chunk, options.premises); times.hash_seed_ms = now() - t4; progress(`hash-seed re-execution: ${sensitive} sensitive in ${times.hash_seed_ms} ms`);
    for (const finding of mutants.findings) writeFinding(options.out, finding);
    const cliLane = options.cliLane > 0 ? runCliLane(options.cliLane, mutants.executed, baseline.rows, rng, options.out) : null;
    const sat = options.premises ? saturation(baseline.sites, sites) : null;
    if (sat !== null) writeFileSync(join(options.out, "saturation.json"), `${JSON.stringify(sat, null, 2)}\n`);
    for (const lane of batches) await lane.close();
    const channels = { bytes: 0, classification: 0, crash: 0, unsupported: 0, adapter: 0, leg: 0 };
    for (const finding of mutants.findings) channels[finding.channel as "bytes" | "classification" | "crash"] += 1;
    channels.unsupported = Object.values(mutants.perStep).reduce((sum, counts) => sum + counts.unsupported, 0);
    channels.leg = legs === null ? 0 : legs.counts["corruption-accepted"]! + legs.counts["claim-weakening-unmoved"]!;
    const legsLine = legs === null ? "legs not run" : `legs pass/masked/finding/unsupported = ${legs.counts.pass}/${legs.counts.masked}/${channels.leg}/${legs.counts.unsupported}`;
    const satLine = sat === null ? "saturation not measured" : `saturation ${sat.saturation_percent} % of ${sat.inventory_size} sites (${sat.excluded.length} excluded)`;
    const accept = `accept: seed ${options.seed}, ${options.mutants} mutants, bytes/classification/crash = ${channels.bytes}/${channels.classification}/${channels.crash}, controls ${fired}/${controls.length}, baseline ${baseline.count}/${seeds.length}, ${legsLine}, ${satLine}, hash-seed-sensitive = ${sensitive}`;
    const report = {
      stable: {
        source_revision: git("rev-parse", "HEAD"), dirty: git("status", "--porcelain", "--untracked-files=no").length > 0,
        seed: options.seed, mutants: options.mutants, rng: RNG_SPEC, operators: Object.fromEntries(OPERATORS.map((operator) => [operator.name, { version: operator.version, layer: operator.layer, target_step: operator.targetStep, repair_boundary: operator.repairBoundary }])),
        baseline: { seeds: seeds.length, reproduced: baseline.count - baseline.mismatches.length }, controls: controls.map((control) => ({ name: control.name, passed: control.passed })),
        channels, per_step: mutants.perStep, per_operator: mutants.perOperator, verdict_noops: Object.values(mutants.perStep).reduce((sum, counts) => sum + counts.verdict_noop, 0), masked: Object.values(mutants.perStep).reduce((sum, counts) => sum + counts.masked, 0),
        findings: mutants.findings.map((finding) => ({ id: finding.id, channel: finding.channel, operator: finding.operator.name, seed: finding.seed.path, detail: finding.detail, hash_seed_sensitive: finding.hash_seed_sensitive ?? false })),
        hash_seed_sensitive: sensitive, legs: legs === null ? null : { counts: legs.counts, findings: legs.findings.length }, saturation: sat === null ? null : { percent: sat.saturation_percent, inventory: sat.inventory_size, excluded: sat.excluded.length, never_fired: sat.never_fired.length },
        cli_lane: cliLane, operator_errors: mutants.operatorErrors, accept,
      },
      volatile: { bun: Bun.version, python: batch.handshake.python, python_hash_seed: batch.handshake.hash_seed, checkout: batch.handshake.checkout, out: options.out, times_ms: { ...times, total_ms: now() - started } },
    };
    writeFileSync(join(options.out, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
    console.log(accept);
    for (const finding of report.stable.findings) console.log(`finding ${finding.id} [${finding.channel}] ${finding.operator} on ${finding.seed}: ${finding.detail}${finding.hash_seed_sensitive ? " (hash-seed-sensitive)" : ""}`);
    if (legs !== null) for (const finding of legs.findings) console.log(`leg finding ${finding.id} [${finding.outcome}] ${finding.leg}/${finding.class} on ${finding.seed.path}: ${finding.detail}`);
    console.log(`report: ${join(options.out, "report.json")} (${Math.round((now() - started) / 1000)} s)`);
    return 0;
  } catch (error) {
    if (error instanceof AdapterError) { console.error(`adapter: ${error.message}`); return 4; }
    throw error;
  }
}

process.exit(await main());
