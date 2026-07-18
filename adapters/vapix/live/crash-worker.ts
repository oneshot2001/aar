import { writeFile } from "node:fs/promises";
import { runScenario, type GateInputFile } from "../../../demo/run-scenario";
import { CredStoreProvider } from "../../../demo/preflight";
import { VapixAdapter } from "../adapter";
import type { VapixRuntimeConfig } from "../config";

// Live S5 crash worker: same cut mechanics as offline/crash-worker.ts but the
// adapter dispatches through the REAL witness proxy to the real camera, and
// credentials are resolved inside the worker via `cred get` — no secret
// crosses the stdin boundary.

interface LiveCrashWorkerInput {
  readonly gate: GateInputFile;
  readonly baseDirectory: string;
  readonly adapterConfig: VapixRuntimeConfig;
  readonly credBinary: string;
  readonly cutMarkerPath: string;
}

if (!import.meta.main) throw new Error("live crash-worker must be executed as a process");

const input = JSON.parse(await Bun.stdin.text()) as LiveCrashWorkerInput;
const adapter = new VapixAdapter(input.adapterConfig, { credentials: new CredStoreProvider(input.credBinary) });
await runScenario("S5", input.gate, adapter, input.baseDirectory, {
  afterDispatchCut: async () => {
    await writeFile(input.cutMarkerPath, "dispatch-complete-outcome-not-observed\n", { mode: 0o600 });
    await new Promise<void>(() => {});
  },
});
