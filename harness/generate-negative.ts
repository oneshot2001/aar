import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildClassBoundaryFixtures, buildNegativeFixtures } from "./negative-fixtures";
import { buildStatefulFixtures } from "./stateful-fixtures";

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

const statefulDirectory = join(outputDirectory, "stateful");
await mkdir(statefulDirectory, { recursive: true });
for (const entry of await readdir(statefulDirectory)) if (entry.endsWith(".cbor") || entry.endsWith(".json")) await rm(join(statefulDirectory, entry));
const stateful = buildStatefulFixtures();
for (const fixture of stateful) {
  await writeFile(join(statefulDirectory, `${fixture.name}.bundle.cbor`), fixture.bundle);
  await writeFile(join(statefulDirectory, `${fixture.name}.prior.json`), `${JSON.stringify(fixture.prior, null, 2)}\n`);
  await writeFile(join(statefulDirectory, `${fixture.name}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}

const classDirectory = join(outputDirectory, "..", "class-boundary");
await mkdir(classDirectory, { recursive: true });
for (const entry of await readdir(classDirectory)) if (entry.endsWith(".cbor") || entry.endsWith(".json")) await rm(join(classDirectory, entry));
const classBoundaries = buildClassBoundaryFixtures();
for (const fixture of classBoundaries) {
  await writeFile(join(classDirectory, `${fixture.filename}.cbor`), fixture.bytes);
  await writeFile(join(classDirectory, `${fixture.filename}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}

console.log(`generated ${fixtures.length} stateless, ${stateful.length} stateful, and ${classBoundaries.length} class-boundary KATs`);
