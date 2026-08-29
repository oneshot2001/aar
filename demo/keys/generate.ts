import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generateDemoKeys } from "./keys";
import { mintMediatorCredential } from "./mediator";
import { hash } from "../../harness/crypto";

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}

const here = dirname(fileURLToPath(import.meta.url));
const privateDirectory = option("--private-dir") ?? join(homedir(), ".aar-demo", "keys");
const publicOutput = option("--public-out") ?? join(here, "public-keys.json");
const keys = await generateDemoKeys(privateDirectory, publicOutput);
const mediatorIdentityDirectory = option("--mediator-identity-dir") ?? join(homedir(), ".aar-demo", "vigil-control");
const mediatorBinary = option("--mediator-binary") ?? resolve(here, "../../adapters/vms/vigil-control/.build/debug/vigil-control");
const demoId = (label: string): Uint8Array => hash(new TextEncoder().encode(`AAR-DEMO-MEDIATOR:${label}`)).slice(0, 16);
await mintMediatorCredential({
  binary: mediatorBinary,
  identityDirectory: mediatorIdentityDirectory,
  issuer: keys["verifier-trust"],
  tenantId: demoId("tenant"),
  siteId: demoId("site"),
  evaluatedAt: Math.floor(Date.now() / 1000),
});
console.log(`generated distinct P-256 demo keys; private material: ${privateDirectory}`);
console.log(`public keys/kids: ${publicOutput}`);
console.log(`vigil-control mediator identity and credential: ${mediatorIdentityDirectory}`);
