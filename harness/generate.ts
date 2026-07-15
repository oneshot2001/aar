import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFixtures } from "./fixtures";

const harnessDirectory = dirname(fileURLToPath(import.meta.url));
const outputDirectory = join(harnessDirectory, "..", "kats", "positive");

await mkdir(outputDirectory, { recursive: true });
for (const entry of await readdir(outputDirectory)) {
  if (entry.endsWith(".cbor") || entry.endsWith(".json")) {
    await rm(join(outputDirectory, entry));
  }
}

const fixtures = buildFixtures();
for (const kat of fixtures.kats) {
  await writeFile(join(outputDirectory, `${kat.filename}.cbor`), kat.bytes);
  await writeFile(join(outputDirectory, `${kat.filename}.json`), `${JSON.stringify(kat.descriptor, null, 2)}\n`);
}

console.log(`generated ${fixtures.kats.length} positive KATs in ${outputDirectory}`);
