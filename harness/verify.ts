import { readFileSync } from "node:fs";
import { CborValue, toHex } from "./cbor";
import { ConfigurationError, loadConfiguration } from "./relying-party";
import { verifyBundle } from "./verifier";

function usage(): never {
  console.error("Usage: bun run harness/verify.ts BUNDLE --at UNIX_SECONDS [--policy FILE --signing-key FILE]");
  process.exit(2);
}
const [filename, ...rest] = process.argv.slice(2);
const flags = new Map<string, string>();
for (let index = 0; index < rest.length; index += 2) {
  const flag = rest[index]!; const value = rest[index + 1];
  if (!["--at", "--policy", "--signing-key"].includes(flag) || value === undefined || flags.has(flag)) usage();
  flags.set(flag, value);
}
const at = flags.get("--at");
const evaluationTime = Number(at);
if (!filename || at === undefined || !/^\d+$/.test(at) || !Number.isSafeInteger(evaluationTime)) usage();
// D-83 part 2: configuration is complete before the first bundle byte is read.
let configuration;
try { configuration = loadConfiguration(flags.get("--policy"), flags.get("--signing-key"), evaluationTime); } catch (error) {
  if (!(error instanceof ConfigurationError)) throw error;
  console.error(`harness/verify.ts: error: ${error.message}`);
  process.exit(2);
}
let input: Uint8Array;
try { input = readFileSync(filename!); } catch (error) {
  console.error(`harness/verify.ts: error: cannot read bundle file ${filename}: ${(error as NodeJS.ErrnoException).code ?? (error as Error).message}`);
  process.exit(2);
}
const result = verifyBundle(input, { evaluationTime, configuration });
console.log(`Result: ${result.result}`);
console.log(`Verifier identity: ${configuration === undefined ? "corpus test key" : `relying-party policy (digest ${toHex(configuration.policyDigest)})`}`);
if (!result.ok) console.log(`First failure: step ${result.step} (${result.reason})`);
console.log("Observations:");
for (const observation of result.verdict!.observations as string[]) console.log(`  - ${observation} [signed]`);
if (result.ok && result.report.selector_matching_receipts === 0) console.log("  - empty_scope [report layer; not signed]");
console.log("  - stateful_not_evaluated [report layer; not signed]");
if (result.ok) {
  const report = result.report.input_origin_ancestry;
  console.log("Input-origin ancestry [report layer; not signed]:");
  console.log(`  bundle_digest: ${report.bundle_digest}`);
  console.log(`  verdict_id: ${report.verdict_id}`);
  console.log("  attempt_id | dispatch status | declared origins | undeclared slots");
  for (const row of report.attempts) {
    console.log(`  ${row.attempt_id} | ${row.dispatched ? "dispatched" : "eligible, undispatched"} | ${row.declared_origins.join(", ") || "(none)"} | ${row.undeclared_slots}`);
  }
  if (!report.attempts.length) console.log("  (none)");
}
const verdict = result.verdict!;
console.log(`Signed verdict CBOR hex: ${toHex(result.verdictEnvelope!)}`);
console.log(`  v: ${verdict.v}`);
const limits = verdict.limits as Record<string, string>;
for (const name of ["maximum_time_class", "maximum_provenance_class", "maximum_outcome_level", "technical_integrity",
  "source_authenticity", "custody_continuity", "discovery_completeness", "legal_admissibility", "input_origin_ancestry", "control_path_completeness"]) {
  console.log(`  ${name}: ${limits[name]}`);
}
console.log(`  ingress_completeness: ${(verdict.scope as Record<string, string>).ingress_completeness}`);
for (const [name, value] of Object.entries(verdict.trust_policy as Record<string, CborValue>)) {
  if (value instanceof Uint8Array) console.log(`  ${name}: ${toHex(value)}`);
}
console.log(`  signed_observations: ${(verdict.observations as string[]).join(", ") || "(none)"}`);
process.exit(result.ok ? 0 : 1);
