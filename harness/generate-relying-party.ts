// Standalone: writes kats/relying-party/ (D-83 part 11). Run after generate-negative.ts.
import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { RP_KEY_HEX } from "./relying-party-fixtures";
import { buildRelyingPartyFixtures } from "./relying-party-kats";

const outputDirectory = join(dirname(fileURLToPath(import.meta.url)), "..", "kats", "relying-party");
await mkdir(outputDirectory, { recursive: true });
for (const entry of await readdir(outputDirectory)) if (/\.(cbor|json|key)$/u.test(entry)) await rm(join(outputDirectory, entry));

const json = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
const rows = buildRelyingPartyFixtures();
for (const row of rows) {
  if (row.inputs.bundle === undefined) await writeFile(join(outputDirectory, `${row.name}.cbor`), row.bytes);
  await writeFile(join(outputDirectory, `${row.name}.json`), json(row.descriptor));
  await writeFile(join(outputDirectory, `${row.name}.inputs.json`), json(row.inputs));
  await writeFile(join(outputDirectory, `${row.name}.policy.json`), json(row.policy));
  for (const [name, value] of Object.entries(row.sidecars)) await writeFile(join(outputDirectory, name), json(value));
}
await writeFile(join(outputDirectory, "rp-verifier.key"), `${RP_KEY_HEX}\n`);
console.log(`generated ${rows.length} relying-party KATs in ${outputDirectory}`);
