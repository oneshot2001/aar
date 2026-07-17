import { writeFile } from "node:fs/promises";
import type { CredentialProvider } from "../../shared/types";
import { runScenario, type GateInputFile } from "../../../demo/run-scenario";
import { VapixAdapter } from "../adapter";
import type { VapixRuntimeConfig } from "../config";
import { MockVapixBackend, type MockVapixConfig } from "../mock/server";
import { InMemoryWitnessTransport } from "../mock/transport";

interface CrashWorkerInput {
  readonly gate: GateInputFile;
  readonly baseDirectory: string;
  readonly adapterConfig: VapixRuntimeConfig;
  readonly credentialSecret: string;
  readonly cutMarkerPath: string;
  readonly witnessLogPath: string;
  readonly mockConfig: MockVapixConfig;
}

if (!import.meta.main) throw new Error("crash-worker must be executed as a process");

const input = JSON.parse(await Bun.stdin.text()) as CrashWorkerInput;
const credentials: CredentialProvider = {
  async get(reference) {
    return { reference, secret: input.credentialSecret };
  },
};
const backend = new MockVapixBackend(input.mockConfig);
const adapter = new VapixAdapter(input.adapterConfig, {
  credentials,
  httpTransport: new InMemoryWitnessTransport(backend, input.witnessLogPath),
});
await runScenario("S5", input.gate, adapter, input.baseDirectory, {
  afterDispatchCut: async () => {
    await writeFile(input.cutMarkerPath, "dispatch-complete-outcome-not-observed\n", { mode: 0o600 });
    await new Promise<void>(() => {});
  },
});
