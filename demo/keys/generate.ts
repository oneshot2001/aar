import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateDemoKeys } from "./keys";

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}

const here = dirname(fileURLToPath(import.meta.url));
const privateDirectory = option("--private-dir") ?? join(homedir(), ".aar-demo", "keys");
const publicOutput = option("--public-out") ?? join(here, "public-keys.json");
await generateDemoKeys(privateDirectory, publicOutput);
console.log(`generated distinct P-256 demo keys; private material: ${privateDirectory}`);
console.log(`public keys/kids: ${publicOutput}`);
