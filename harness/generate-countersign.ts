import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCountersignFixtures } from "./countersign-fixtures";

const harnessDirectory = dirname(fileURLToPath(import.meta.url));
const outputDirectory = join(harnessDirectory, "..", "kats", "countersign");

await mkdir(outputDirectory, { recursive: true });
for (const entry of await readdir(outputDirectory)) {
  if (entry.endsWith(".cbor") || entry.endsWith(".json")) await rm(join(outputDirectory, entry));
}
const fixtures = buildCountersignFixtures();
for (const fixture of fixtures) {
  await writeFile(join(outputDirectory, `${fixture.filename}.cbor`), fixture.bytes);
  await writeFile(join(outputDirectory, `${fixture.filename}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}
console.log(`generated ${fixtures.length} mediator-countersignature KATs in ${outputDirectory}`);
