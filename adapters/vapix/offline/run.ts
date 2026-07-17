import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { CborValue } from "../../../harness/cbor";
import { decodeCbor, encodeCbor } from "../../../harness/cbor";
import type { CredentialAccess, CredentialProvider } from "../../shared/types";
import { runPreflight, type PreflightTransport } from "../../../demo/preflight";
import { generateDemoKeys } from "../../../demo/keys/keys";
import { sweepCanary } from "../../../demo/hygiene-sweep";
import { runScenario, type GateInputFile, type ScenarioRunResult } from "../../../demo/run-scenario";
import { AppendOnlyWitnessLog } from "../../../demo/witness/log";
import { VapixAdapter } from "../adapter";
import type { VapixRuntimeConfig } from "../config";
import { DigestHttpClient } from "../digest";
import { MockVapixBackend, type MockFaultMode, type MockVapixConfig } from "../mock/server";
import { InMemoryWitnessTransport } from "../mock/transport";

type Obj = Record<string, CborValue>;

export interface OfflineScenarioSummary {
  readonly scenario: "S1" | "S2" | "S3" | "S4" | "S5" | "S6-rejection" | "S6-after-send-timeout";
  readonly verification: "conformant" | "nonconformant";
  readonly outcome: string;
  readonly oracle: "PASS";
}

export interface OfflineSuiteResult {
  readonly root: string;
  readonly scenarios: readonly OfflineScenarioSummary[];
  readonly hygieneHits: number;
  readonly backendCounters: ReturnType<MockVapixBackend["counters"]>;
}

function hex16(): string {
  return randomBytes(16).toString("hex");
}

function tamperPinnedRequestSignature(bundleBytes: Uint8Array): Uint8Array {
  const bundle = decodeCbor(bundleBytes, { strict: true });
  if (typeof bundle !== "object" || bundle === null || Array.isArray(bundle) || bundle instanceof Uint8Array || bundle instanceof Map) {
    throw new Error("S4 source is not an AAR bundle map");
  }
  const artifacts = (bundle as Obj).artifacts as Obj;
  const requests = artifacts.requests as CborValue[];
  const envelope = requests[0] as CborValue[];
  const coseBytes = envelope[1] as Uint8Array;
  const cose = decodeCbor(coseBytes, { strict: true }) as CborValue[];
  const signature = new Uint8Array(cose[3] as Uint8Array);
  signature[0] = signature[0]! ^ 0x01;
  cose[3] = signature;
  envelope[1] = encodeCbor(cose);
  return encodeCbor(bundle);
}

async function exists(path: string): Promise<boolean> {
  try { await readFile(path); return true; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function waitFor(check: () => Promise<boolean>, description: string, deadlineMs = 10_000): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await Bun.sleep(10);
  }
  throw new Error(`timed out waiting for ${description}`);
}

export async function runOfflineSuite(requestedRoot?: string): Promise<OfflineSuiteResult> {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const root = requestedRoot ? resolve(requestedRoot) : await mkdtemp(join(tmpdir(), "aar-vapix-d2a-"));
  await mkdir(root, { recursive: true });
  const keyDirectory = join(root, "keys");
  const priorState = join(root, "prior-state.json");
  const recoveryDirectory = join(root, "recovery");
  await generateDemoKeys(keyDirectory, join(root, "public-keys.json"));

  const credentialSecret = randomBytes(24).toString("base64url");
  const username = "gate5-offline-user";
  const realm = "AAR Gate 5 Offline";
  const credentialReference = "mock-vapix-runtime";
  const credentials: CredentialProvider = {
    async get(reference) {
      if (reference !== credentialReference) throw new Error("unknown offline credential reference");
      return { reference, secret: credentialSecret };
    },
  };
  const mockConfig: MockVapixConfig = {
    username,
    password: credentialSecret,
    realm,
    presetBackendName: "mock-safe-preset",
    streamBackendProfile: "mock-stream-profile",
    model: "AXIS VAPIX Offline Test Double",
    firmware: "D2a-offline",
    serial: "OFFLINE-NOT-A-DEVICE",
    baseline: { pan: 0, tilt: 0, zoom: 1 },
    safePreset: { pan: 12, tilt: -4, zoom: 2 },
    settlingReads: 2,
  };
  const backend = new MockVapixBackend(mockConfig);
  const backendUrl = "http://mock-vapix.invalid";

  const adapterConfig = (witnessProxyUrl: string): VapixRuntimeConfig => ({
    targets: {
      "ptz-primary": { baseUrl: backendUrl, username, credentialReference },
      "fixed-primary": { baseUrl: backendUrl, username, credentialReference },
    },
    witnessProxyUrl,
    presetMappings: { "gate5-safe": "mock-safe-preset" },
    presetPositions: { "gate5-safe": { pan: 12, tilt: -4, zoom: 2 } },
    streamProfileMappings: { "gate5-offline": "mock-stream-profile" },
    positionTolerance: { pan: 0.01, tilt: 0.01, zoom: 0.01 },
    pollIntervalMs: 5,
    settlingDeadlineMs: 2_000,
    requestTimeoutMs: 300,
    streamMinimumPayloadBytes: 16,
    exclusiveControl: true,
    recoveryDirectory,
  });

  const preflightPath = join(root, "preflight.json");
  const preflightWitnessPath = join(root, "preflight.witness.jsonl");
  const preflightHttpTransport = new InMemoryWitnessTransport(backend, preflightWitnessPath);
  {
    const transport: PreflightTransport = {
      async get(url: string, credential: CredentialAccess) {
        const provider: CredentialProvider = { async get(reference) { return { reference, secret: credential.secret }; } };
        const client = new DigestHttpClient("http://witness.invalid", username, credential.reference, provider, 1_000, preflightHttpTransport);
        const response = await client.request({
          method: "GET", url: new URL(url),
          context: { invocationId: hex16(), actionBearing: false },
        });
        return { status: response.status, body: new TextDecoder().decode(response.body) };
      },
    };
    const preflight = await runPreflight({
      baseUrl: backendUrl,
      credentialReference,
      expectedModel: "AXIS VAPIX Offline Test Double",
      expectedSerial: "OFFLINE-NOT-A-DEVICE",
      presetName: "gate5-safe",
      streamProfile: "gate5-offline",
      backendMapping: { "ptz-primary": backendUrl, "fixed-primary": backendUrl },
    }, transport, credentials);
    if (!preflight.ok) throw new Error(`offline preflight failed: ${JSON.stringify(preflight.checks)}`);
    await writeFile(preflightPath, `${JSON.stringify(preflight, null, 2)}\n`);
  }

  const shared = {
    version: 1 as const,
    tenant_id: hex16(),
    site_id: hex16(),
    target_id: hex16(),
    adapter: "vapix" as const,
    source_device: { manufacturer: "AXIS", model: "VAPIX Offline Test Double", firmware: "D2a-offline" },
    key_dir: keyDirectory,
    prior_state_file: priorState,
  };
  const fixedAt = 1_800_000_000;
  let epoch = 20_000;
  const gate = (
    label: string,
    action: GateInputFile["action_name"],
    expected: GateInputFile["expected_outcome_level"],
    outputDirectory: string,
  ): GateInputFile => {
    const evaluatedAt = fixedAt + epoch;
    epoch += 1;
    return {
      ...shared,
      evaluated_at: evaluatedAt,
      epoch_id: epoch,
      invocation_id: hex16(),
      correlation_id: hex16(),
      output_dir: outputDirectory,
      target_logical_name: action === "camera.ptz.preset" ? "ptz-primary" : "fixed-primary",
      action_name: action,
      parameters: action === "camera.ptz.preset" ? { preset_name: "gate5-safe" } : { stream_profile: "gate5-offline" },
      expected_outcome_level: expected,
      delegation_candidates: [{ not_before: evaluatedAt - 600, not_after: evaluatedAt + 600 }],
      preflight_result_file: label === "S1" ? preflightPath : undefined,
    };
  };

  const summaries: OfflineScenarioSummary[] = [];
  const execute = async (
    name: OfflineScenarioSummary["scenario"],
    scenarioId: "S1" | "S2" | "S3" | "S4" | "S6",
    input: GateInputFile,
    mode: MockFaultMode = "normal",
    tamper = false,
  ): Promise<ScenarioRunResult> => {
    backend.setFaultMode(mode);
    const witnessPath = join(input.output_dir, `${scenarioId}.witness.jsonl`);
    const httpTransport = new InMemoryWitnessTransport(backend, witnessPath);
    {
      const adapter = new VapixAdapter(adapterConfig("http://witness.invalid"), { credentials, httpTransport });
      const result = await runScenario(scenarioId, input, adapter, root, tamper ? {
        expectedVerification: "nonconformant",
        expectedFailureReason: "sig/verify-failed",
        transformBundle: tamperPinnedRequestSignature,
      } : {});
      const applicationStatus = result.producer.dispatchResult?.effect.backend_evidence.application_status;
      if (name === "S1" && applicationStatus !== "position_within_tolerance") throw new Error("S1 position evidence assertion failed");
      if (name === "S2" && applicationStatus !== "media_payload_valid") throw new Error("S2 media evidence assertion failed");
      if (name === "S6-rejection" && applicationStatus !== "http_rejected_503") throw new Error("S6 rejection evidence assertion failed");
      if (name === "S6-rejection" && result.producer.dispatchResult?.effect.backend_evidence.position_observation !== "outside_tolerance") {
        throw new Error("S6 rejection lacked positive contrary position evidence");
      }
      if (name === "S6-after-send-timeout" && applicationStatus !== "transport_timeout_after_send") throw new Error("S6 timeout evidence assertion failed");
      if (result.witness.some((entry) => entry.response_line.includes("401") && entry.action_bearing)) throw new Error("Digest challenge was classified as dispatch");
      summaries.push({
        scenario: name,
        verification: result.verificationResult,
        outcome: result.producer.dispatchResult?.effect.outcome_level ?? "not_dispatched",
        oracle: "PASS",
      });
      return result;
    }
  };

  {
    const s1Dir = join(root, "artifacts", "S1");
    await execute("S1", "S1", gate("S1", "camera.ptz.preset", "device_acknowledged", s1Dir));

    const s2Dir = join(root, "artifacts", "S2");
    await execute("S2", "S2", gate("S2", "camera.stream.view", "device_acknowledged", s2Dir));

    const s3Dir = join(root, "artifacts", "S3");
    const s3Base = gate("S3", "camera.ptz.preset", "accepted", s3Dir);
    const s3: GateInputFile = { ...s3Base, delegation_candidates: [
      { not_before: s3Base.evaluated_at - 600, not_after: s3Base.evaluated_at - 1 },
      { not_before: s3Base.evaluated_at - 1, not_after: s3Base.evaluated_at + 600 },
    ] };
    await execute("S3", "S3", s3);

    const s4Dir = join(root, "artifacts", "S4");
    await execute("S4", "S4", gate("S4", "camera.ptz.preset", "device_acknowledged", s4Dir), "normal", true);

    const s5Dir = join(root, "artifacts", "S5");
    const s5 = gate("S5", "camera.ptz.preset", "unknown", s5Dir);
    const s5WitnessPath = join(s5Dir, "S5.witness.jsonl");
    {
      const config = adapterConfig("http://witness.invalid");
      const cutMarkerPath = join(s5Dir, "dispatch-cut.marker");
      const stateFile = join(s5Dir, "mock-state.json");
      await mkdir(dirname(cutMarkerPath), { recursive: true });
      const workerPath = fileURLToPath(new URL("./crash-worker.ts", import.meta.url));
      const child = Bun.spawn(["bun", "run", workerPath], { cwd: resolve(dirname(fileURLToPath(import.meta.url)), "../../.."), stdin: "pipe", stdout: "pipe", stderr: "pipe" });
      child.stdin.write(JSON.stringify({ gate: s5, baseDirectory: root, adapterConfig: config, credentialSecret, cutMarkerPath, witnessLogPath: s5WitnessPath, mockConfig: { ...mockConfig, stateFile } }));
      child.stdin.end();
      await waitFor(() => exists(cutMarkerPath), "S5 dispatch cut marker");
      await waitFor(async () => (await new AppendOnlyWitnessLog(s5WitnessPath).entries()).some((entry) => entry.action_bearing && entry.command_digest !== null), "S5 witnessed requested dispatch");
      const recoveryPath = join(recoveryDirectory, `${s5.invocation_id}.ptz-recovery.json`);
      await waitFor(() => exists(recoveryPath), "S5 durable PTZ recovery baseline");
      child.kill(9);
      if (await child.exited === 0) throw new Error("S5 EP process was not killed at the crash cut");
      const resumedBackend = new MockVapixBackend({ ...mockConfig, stateFile });
      const adapter = new VapixAdapter(config, { credentials, httpTransport: new InMemoryWitnessTransport(resumedBackend, s5WitnessPath) });
      const result = await runScenario("S5", s5, adapter, root);
      if (result.producer.dispatchResult?.effect.backend_evidence.application_status !== "outcome_unknown_restore_verified") {
        throw new Error("S5 recovery evidence assertion failed");
      }
      if (await exists(recoveryPath)) throw new Error("S5 recovery record remained after verified restoration");
      summaries.push({ scenario: "S5", verification: result.verificationResult, outcome: result.producer.dispatchResult!.effect.outcome_level, oracle: "PASS" });
    }

    const s6RejectDir = join(root, "artifacts", "S6-rejection");
    await execute("S6-rejection", "S6", gate("S6-rejection", "camera.ptz.preset", "contradicted", s6RejectDir), "reject");

    const s6TimeoutDir = join(root, "artifacts", "S6-after-send-timeout");
    await execute("S6-after-send-timeout", "S6", gate("S6-timeout", "camera.ptz.preset", "unknown", s6TimeoutDir), "after-send-timeout");

    const hits = await sweepCanary({ canary: credentialSecret, roots: [repoRoot, root], digestUsername: username, digestRealm: realm });
    if (hits.length) throw new Error(`secret hygiene sweep found ${hits.length} hit(s)`);
    return { root, scenarios: summaries, hygieneHits: hits.length, backendCounters: backend.counters() };
  }
}

if (import.meta.main) {
  const result = await runOfflineSuite(process.argv[2]);
  console.log(`D2a offline artifacts: ${result.root}`);
  for (const scenario of result.scenarios) {
    console.log(`${scenario.scenario}: ${scenario.verification}; outcome=${scenario.outcome}; oracle=${scenario.oracle}`);
  }
  console.log(`secret hygiene sweep: ${result.hygieneHits} hits`);
}
