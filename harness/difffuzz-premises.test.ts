// The rejection-site inventory regenerates from the AST on every run; this test
// pins no line numbers. It fails only if pyref.premises errors or if a _fail
// site has neither a literal code nor a place in the dynamic list below.
import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inventory } from "./difffuzz-premises";

// Every _fail call whose reason code is computed at runtime, by the expression that computes it.
const DYNAMIC_CODE_EXPRESSIONS = new Set([
  "exc.code",
  "code",
  "f\"credential/{snapshot['status']}\"",
  "'sig/der-encoding' if is_der_ecdsa_signature(signature) else 'sig/bad-length'",
  "'countersign/credential-invalid' if category == 'mediator_countersignatures' else 'schema/bad-type'",
  "'countersign/credential-invalid' if credential_error else 'countersign/invalid'",
  "'countersign/digest-mismatch' if category == 'mediator_countersignatures' else 'identity/artifact-id-mismatch'",
  "'countersign/credential-invalid' if mediator_credential else 'credential/path-invalid'",
]);

test("pyref.premises inventory: every _fail site has a literal code or is in the dynamic list; exclusions carry their comment", () => {
  const { inventory: sites, excluded, counts } = inventory();
  expect(sites.length).toBeGreaterThan(0);
  for (const site of sites) {
    if (site.code === "dynamic") expect(DYNAMIC_CODE_EXPRESSIONS.has(site.code_expr!), `${site.file}:${site.line} ${site.code_expr}`).toBe(true);
    else expect(site.code).toMatch(/^[a-z]+\/[a-z0-9-]+$/u);
  }
  for (const site of excluded) expect(site.reason.includes("unreachable")).toBe(true);
  console.log(`rejection-site inventory: ${counts["pyref/verifier.py"]} verifier.py / ${counts["pyref/emission_identity.py"]} emission_identity.py / ${counts["pyref/relying_party.py"]} relying_party.py / ${counts["pyref/cbor.py"]} cbor.py (${excluded.length} excluded as documented unreachable)`);
});

// D-90 review: step 13 moved to pyref/dominance.py and its sites dropped out of the inventory
// unnoticed. Every pyref module that calls _fail (bare or as verifier._fail) must be inventoried.
test("pyref.premises inventory: every pyref module with a _fail call is inventoried", () => {
  const { counts } = inventory();
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "pyref");
  const callers = readdirSync(dir).filter((name) => name.endsWith(".py") && name !== "premises.py"
    && /(^|[^\w])_fail\(/mu.test(readFileSync(join(dir, name), "utf8"))).map((name) => `pyref/${name}`);
  expect(callers).toContain("pyref/dominance.py");
  for (const file of callers) expect(counts[file], file).toBeGreaterThan(0);
});
