import { readFileSync } from "node:fs";
import { toHex } from "./cbor";
import { verifyBundle } from "./verifier";

const [filename, flag, at, ...extra] = process.argv.slice(2);
const evaluationTime = Number(at);
if (!filename || flag !== "--at" || !at || !/^\d+$/.test(at) || !Number.isSafeInteger(evaluationTime) || extra.length) {
  console.error("Usage: bun run harness/verify.ts BUNDLE --at UNIX_SECONDS");
  process.exit(2);
}
const result = verifyBundle(readFileSync(filename), { evaluationTime });
console.log(`Result: ${result.result}`);
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
console.log(`  input_origin_ancestry: ${(verdict.limits as Record<string, string>).input_origin_ancestry}`);
console.log(`  signed_observations: ${(verdict.observations as string[]).join(", ") || "(none)"}`);
process.exit(result.ok ? 0 : 1);
