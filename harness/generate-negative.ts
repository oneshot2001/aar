import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildD78Fixtures, buildD77PositiveFixtures, buildD80D81PositiveFixtures, buildD82PositiveFixtures, buildClassBoundaryFixtures, buildNegativeFixtures, buildTerminalOutcomeFixtures } from "./negative-fixtures";
import { buildStatefulFixtures } from "./stateful-fixtures";
import { buildFixtures } from "./fixtures";

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

const fork = buildFixtures().forkDeclared;
await writeFile(join(outputDirectory, `${fork.filename}.cbor`), fork.bytes);
await writeFile(join(outputDirectory, `${fork.filename}.json`), `${JSON.stringify(fork.descriptor, null, 2)}\n`);

// D-86: conformant stateful rows live under kats/positive/stateful/, the rest under kats/negative/stateful/.
const statefulDirectory = (code: string | null): string => join(outputDirectory, "..", code === null ? "positive" : "negative", "stateful");
for (const directory of [statefulDirectory(null), statefulDirectory("")]) {
  await mkdir(directory, { recursive: true });
  for (const entry of await readdir(directory)) if (entry.endsWith(".cbor") || entry.endsWith(".json")) await rm(join(directory, entry));
}
const stateful = buildStatefulFixtures();
for (const fixture of stateful) {
  const directory = statefulDirectory(fixture.descriptor.expected_code);
  await writeFile(join(directory, `${fixture.name}.bundle.cbor`), fixture.bundle);
  if (fixture.prior) await writeFile(join(directory, `${fixture.name}.prior.json`), `${JSON.stringify(fixture.prior, null, 2)}\n`);
  await writeFile(join(directory, `${fixture.name}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}

const classDirectory = join(outputDirectory, "..", "class-boundary");
await mkdir(classDirectory, { recursive: true });
for (const entry of await readdir(classDirectory)) if (entry.endsWith(".cbor") || entry.endsWith(".json")) await rm(join(classDirectory, entry));
const classBoundaries = buildClassBoundaryFixtures();
for (const fixture of classBoundaries) {
  await writeFile(join(classDirectory, `${fixture.filename}.cbor`), fixture.bytes);
  await writeFile(join(classDirectory, `${fixture.filename}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}

const terminalDirectory = join(outputDirectory, "..", "terminal-state");
await mkdir(terminalDirectory, { recursive: true });
for (const entry of await readdir(terminalDirectory)) if (entry.endsWith(".cbor") || entry.endsWith(".json")) await rm(join(terminalDirectory, entry));
const terminalOutcomes = buildTerminalOutcomeFixtures();
for (const fixture of terminalOutcomes) {
  await writeFile(join(terminalDirectory, `${fixture.filename}.cbor`), fixture.bytes);
  await writeFile(join(terminalDirectory, `${fixture.filename}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}

console.log(`generated ${fixtures.length} stateless, ${stateful.length} stateful, ${classBoundaries.length} class-boundary, and ${terminalOutcomes.length} terminal-state KATs`);

for (const fixture of [...buildD77PositiveFixtures(), ...buildD80D81PositiveFixtures(), ...buildD82PositiveFixtures()]) {
  const directory = join(outputDirectory, "..", "positive");
  await writeFile(join(directory, `${fixture.filename}.cbor`), fixture.bytes);
  await writeFile(join(directory, `${fixture.filename}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}

for (const fixture of buildD78Fixtures()) {
  const directory = join(outputDirectory, "..", fixture.directory);
  await writeFile(join(directory, `${fixture.filename}.cbor`), fixture.bytes);
  await writeFile(join(directory, `${fixture.filename}.json`), `${JSON.stringify(fixture.descriptor, null, 2)}\n`);
}
