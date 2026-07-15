import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildNegativeFixtures } from "./negative-fixtures";

const harnessDirectory = dirname(fileURLToPath(import.meta.url));
const outputDirectory = join(harnessDirectory, "..", "kats", "negative");

await mkdir(outputDirectory, { recursive: true });
for (const entry of await readdir(outputDirectory)) {
  if (entry.endsWith(".cbor") || entry.endsWith(".json")) await rm(join(outputDirectory, entry));
}

const fixtures = buildNegativeFixtures();
for (const fixture of fixtures) {
  await writeFile(join(outputDirectory, `${fixture.filename}.cbor`), fixture.bytes);
  await writeFile(join(outputDirectory, `${fixture.filename}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}

console.log(`generated ${fixtures.length} negative KATs in ${outputDirectory}`);
