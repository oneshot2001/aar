import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sweepCanary } from "../../../demo/hygiene-sweep";
import { runScenario, type GateInputFile, type ScenarioRunResult } from "../../../demo/run-scenario";
import { tamperPinnedRequestSignature } from "../../vapix/offline/run";
import { VmsAdapter } from "../adapter";
import type { VmsRuntimeConfig } from "../config";
import { MediatorHttpClient } from "../client";
import { MockVigilControl, type MockVigilControlConfig, type MockVmsFaultMode } from "../mock/vigil-control";
import { InMemoryMediatorWitnessTransport } from "../mock/transport";

// D3 offline suite — the VMS-mediated leg (S1–S4 + S6; S5 crash-cut runs once
// on the EP+VAPIX leg per Q5-2, the VMS leg encodes outcome_unknown via
// S6-after-send-timeout). Everything runs through EP -> witness transport ->
// VmsAdapter -> mock vigil-control mediator -> pyref, with the same content
// assertions and hygiene discipline as the D2a VAPIX offline suite.

export interface VmsOfflineScenarioSummary {
  readonly scenario: "S1" | "S2" | "S3" | "S4" | "S6-rejection" | "S6-after-send-timeout";
  readonly verification: "conformant" | "nonconformant";
  readonly outcome: string;
  readonly oracle: "PASS";
}

export interface VmsOfflineSuiteResult {
  readonly root: string;
  readonly scenarios: readonly VmsOfflineScenarioSummary[];
  readonly hygieneHits: number;
  readonly mediatorCounters: ReturnType<MockVigilControl["counters"]>;
}

const MEDIATOR_PATHS = new Set(["/dispatch", "/ptz/position", "/healthz"]);
const DISPATCH_REQUEST_LINES = {
  "camera.ptz.preset": "POST /dispatch?cred=<sanitized>&digest=<sanitized>&host=<sanitized>&op=<sanitized>&port=<sanitized>&preset=<sanitized>&username=<sanitized> HTTP/1.1",
  "camera.stream.view": "POST /dispatch?cred=<sanitized>&digest=<sanitized>&host=<sanitized>&op=<sanitized>&port=<sanitized>&profile=<sanitized>&username=<sanitized> HTTP/1.1",
} as const;

function hex16(): string {
  return randomBytes(16).toString("hex");
}

export async function runVmsOfflineSuite(requestedRoot?: string): Promise<VmsOfflineSuiteResult> {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const root = requestedRoot ? resolve(requestedRoot) : await mkdtemp(join(tmpdir(), "aar-vms-d3-"));
  await mkdir(root, { recursive: true });
  const keyDirectory = join(root, "keys");
  const priorState = join(root, "prior-state.json");
  const recoveryDirectory = join(root, "recovery");
  const { generateDemoKeys } = await import("../../../demo/keys/keys");
  await generateDemoKeys(keyDirectory, join(root, "public-keys.json"));

  // The canary secret lives INSIDE the mock mediator, exactly as the real
  // secret lives inside vigil-control's process. The TS run never receives
  // it; the sweep proves no artifact carries it in any form.
  const canarySecret = randomBytes(24).toString("base64url");
  const credentialReference = "mock-vms-runtime";
  const expectedHost = "mock-camera.invalid";
  const expectedUsername = "gate5-vms-offline-user";
  const mediatorConfig: MockVigilControlConfig = {
    credentialReference,
    secret: canarySecret,
    expectedHost,
    expectedUsername,
    presetBackendName: "mock-vms-safe-preset",
    streamBackendProfile: "mock-vms-stream-profile",
    baseline: { pan: 0, tilt: 0, zoom: 1 },
    safePreset: { pan: 12, tilt: -4, zoom: 2 },
    settlingReads: 2,
  };
  const mediator = new MockVigilControl(mediatorConfig);

  const adapterConfig: VmsRuntimeConfig = {
    witnessProxyUrl: "http://witness.invalid",
    mediatorBaseUrl: "http://mock-vigil-control.invalid",
    targets: {
      "ptz-primary": { host: expectedHost, port: 80, username: expectedUsername, credentialReference },
      "fixed-primary": { host: expectedHost, port: 80, username: expectedUsername, credentialReference },
    },
    presetMappings: { "gate5-safe": "mock-vms-safe-preset" },
    presetPositions: { "gate5-safe": { pan: 12, tilt: -4, zoom: 2 } },
    streamProfileMappings: { "gate5-offline": "mock-vms-stream-profile" },
    positionTolerance: { pan: 0.01, tilt: 0.01, zoom: 0.01 },
    pollIntervalMs: 5,
    settlingDeadlineMs: 2_000,
    requestTimeoutMs: 300,
    streamMinimumPayloadBytes: 16,
    exclusiveControl: true,
    recoveryDirectory,
  };

  // VMS preflight: mediator health, a live position readback through the
  // mediator, and the logical mappings this run depends on. Witnessed like
  // every other exchange.
  const preflightPath = join(root, "preflight.json");
  {
    const witnessPath = join(root, "preflight.witness.jsonl");
    const client = new MediatorHttpClient("http://witness.invalid", 1_000, new InMemoryMediatorWitnessTransport(mediator, witnessPath));
    const routing = adapterConfig.targets["ptz-primary"];
    const routed = (path: string): URL => {
      const url = new URL(path, adapterConfig.mediatorBaseUrl);
      url.searchParams.set("host", routing.host);
      url.searchParams.set("port", String(routing.port));
      url.searchParams.set("username", routing.username);
      url.searchParams.set("cred", routing.credentialReference);
      return url;
    };
    const health = await client.request({ method: "GET", url: new URL("/healthz", adapterConfig.mediatorBaseUrl), context: { invocationId: hex16(), actionBearing: false } });
    const position = await client.request({ method: "GET", url: routed("/ptz/position"), context: { invocationId: hex16(), actionBearing: false } });
    const positionEffect = JSON.parse(new TextDecoder().decode(position.body)) as { application_status?: string; pan?: number };
    const checks = {
      mediator_healthz: health.status === 200,
      mediator_position_readback: position.status === 200 && positionEffect.application_status === "ok" && Number.isFinite(positionEffect.pan),
      preset_mapping_present: Boolean(adapterConfig.presetMappings["gate5-safe"]),
      stream_profile_mapping_present: Boolean(adapterConfig.streamProfileMappings["gate5-offline"]),
    };
    const ok = Object.values(checks).every(Boolean);
    await writeFile(preflightPath, `${JSON.stringify({ ok, checks, mediator: "vigil-control-mock" }, null, 2)}\n`);
    if (!ok) throw new Error(`VMS offline preflight failed: ${JSON.stringify(checks)}`);
  }

  const shared = {
    version: 1 as const,
    tenant_id: hex16(),
    site_id: hex16(),
    target_id: hex16(),
    adapter: "vms" as const,
    source_device: { manufacturer: "AXIS", model: "VMS-Mediated Offline Test Double", firmware: "D3-offline" },
    key_dir: keyDirectory,
    prior_state_file: priorState,
  };
  const fixedAt = 1_800_000_000;
  let epoch = 30_000;
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

  const summaries: VmsOfflineScenarioSummary[] = [];
  const execute = async (
    name: VmsOfflineScenarioSummary["scenario"],
    scenarioId: "S1" | "S2" | "S3" | "S4" | "S6",
    input: GateInputFile,
    mode: MockVmsFaultMode = "normal",
    tamper = false,
  ): Promise<ScenarioRunResult> => {
    mediator.setFaultMode(mode);
    const witnessPath = join(input.output_dir, `${scenarioId}.witness.jsonl`);
    const httpTransport = new InMemoryMediatorWitnessTransport(mediator, witnessPath);
    const adapter = new VmsAdapter(adapterConfig, { httpTransport });
    const result = await runScenario(scenarioId, input, adapter, root, tamper ? {
      expectedVerification: "nonconformant",
      expectedFailureReason: "sig/verify-failed",
      transformBundle: tamperPinnedRequestSignature,
    } : {});
    const evidence = result.producer.dispatchResult?.effect.backend_evidence ?? {};
    const applicationStatus = evidence.application_status;
    if (name === "S1" && applicationStatus !== "position_within_tolerance") throw new Error("S1 position evidence assertion failed");
    if (name === "S2" && applicationStatus !== "media_payload_valid") throw new Error("S2 media evidence assertion failed");
    if (name === "S6-rejection" && applicationStatus !== "http_rejected_503") throw new Error("S6 rejection evidence assertion failed");
    if (name === "S6-rejection" && evidence.position_observation !== "outside_tolerance") {
      throw new Error("S6 rejection lacked positive contrary position evidence");
    }
    if (name === "S6-after-send-timeout" && applicationStatus !== "transport_timeout_after_send") throw new Error("S6 timeout evidence assertion failed");
    if (result.producer.dispatchResult && result.producer.dispatchResult.dispatched && evidence.vms_mediated !== true) {
      throw new Error("VMS mediation marker missing from effect evidence");
    }
    // Full-mediation proof: every witnessed exchange is with the mediator's
    // HTTP surface — no direct device path (/axis-cgi/...) ever appears at
    // the AAR->mediator boundary.
    for (const entry of result.witness) {
      const path = entry.request_line.split(" ")[1]!.split("?")[0]!;
      if (!MEDIATOR_PATHS.has(path)) throw new Error(`non-mediated witnessed request: ${entry.request_line}`);
    }
    const attributable = result.witness.filter((entry) => entry.invocation_id === input.invocation_id && entry.action_bearing);
    const bound = attributable.filter((entry) => entry.command_digest !== null);
    if (bound.length && bound.some((entry) => entry.request_line !== DISPATCH_REQUEST_LINES[input.action_name])) {
      throw new Error("VMS dispatch request-line shape assertion failed");
    }
    if (name === "S1") {
      const restores = attributable.filter((entry) => entry.command_digest === null);
      if (restores.length !== 1 || evidence.restore_verified !== true) throw new Error("S1 F19 restore evidence assertion failed");
    }
    summaries.push({
      scenario: name,
      verification: result.verificationResult,
      outcome: result.producer.dispatchResult?.effect.outcome_level ?? "not_dispatched",
      oracle: "PASS",
    });
    return result;
  };

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

  const s6RejectDir = join(root, "artifacts", "S6-rejection");
  await execute("S6-rejection", "S6", gate("S6-rejection", "camera.ptz.preset", "contradicted", s6RejectDir), "reject");

  const s6TimeoutDir = join(root, "artifacts", "S6-after-send-timeout");
  await execute("S6-after-send-timeout", "S6", gate("S6-timeout", "camera.ptz.preset", "unknown", s6TimeoutDir), "after-send-timeout");

  const hits = await sweepCanary({ canary: canarySecret, roots: [repoRoot, root] });
  if (hits.length) throw new Error(`secret hygiene sweep found ${hits.length} hit(s)`);
  return { root, scenarios: summaries, hygieneHits: hits.length, mediatorCounters: mediator.counters() };
}

if (import.meta.main) {
  const result = await runVmsOfflineSuite(process.argv[2]);
  console.log(`D3 offline artifacts: ${result.root}`);
  for (const scenario of result.scenarios) {
    console.log(`${scenario.scenario}: ${scenario.verification}; outcome=${scenario.outcome}; oracle=${scenario.oracle}`);
  }
  console.log(`secret hygiene sweep: ${result.hygieneHits} hits`);
}
