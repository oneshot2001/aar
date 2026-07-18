import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Server } from "node:http";
import { CredStoreProvider, runPreflight, type PreflightResult, type PreflightTransport } from "../../../demo/preflight";
import { generateDemoKeys } from "../../../demo/keys/keys";
import { sweepCanary, type HygieneHit } from "../../../demo/hygiene-sweep";
import { runScenario, type GateInputFile, type ScenarioRunResult } from "../../../demo/run-scenario";
import { AppendOnlyWitnessLog } from "../../../demo/witness/log";
import { createWitnessProxy, type WitnessFaultInjection } from "../../../demo/witness/proxy";
import { VapixAdapter } from "../adapter";
import type { VapixPosition } from "../config";
import { DigestHttpClient, parseDigestChallenge } from "../digest";
import { tamperPinnedRequestSignature } from "../offline/run";
import {
  ABSENT_PRESET_BACKEND_NAME,
  CRED_BINARY,
  LIVE_TARGETS,
  PARK_POSITION,
  SAFE_PRESET_BACKEND_NAME,
  STREAM_PROFILE_BACKEND,
  STREAM_PROFILE_LOGICAL,
  liveVapixConfig,
} from "./config";

export interface LiveScenarioSummary {
  readonly scenario: "S1" | "S2" | "S3" | "S4" | "S5" | "S6-rejection" | "S6-after-send-timeout";
  readonly verification: "conformant" | "nonconformant";
  readonly outcome: string;
  readonly applicationStatus: string;
  readonly oracle: "PASS";
}

export interface LiveSuiteResult {
  readonly root: string;
  readonly scenarios: readonly LiveScenarioSummary[];
  readonly hygieneHits: number;
}

interface WitnessProxyHandle {
  readonly url: string;
  close(): Promise<void>;
}

function hex16(): string {
  return randomBytes(16).toString("hex");
}

async function startWitnessProxy(logPath: string, fault?: WitnessFaultInjection): Promise<WitnessProxyHandle> {
  const server: Server = createWitnessProxy(logPath, fault);
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("witness proxy did not report a bound port");
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolveClose) => { server.closeAllConnections?.(); server.close(() => resolveClose()); }),
  };
}

async function exists(path: string): Promise<boolean> {
  try { await readFile(path); return true; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function waitFor(check: () => Promise<boolean>, description: string, deadlineMs = 60_000): Promise<void> {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await Bun.sleep(100);
  }
  throw new Error(`timed out waiting for ${description}`);
}

// Park verification reuses the adapter config's tolerance so there is one
// source of truth for what "settled" means (no drift vs config.ts).
const PARK_TOLERANCE = liveVapixConfig("http://127.0.0.1:1", "/tmp/aar-park").positionTolerance;

function withinTolerance(actual: VapixPosition, expected: VapixPosition): boolean {
  return Math.abs(actual.pan - expected.pan) <= PARK_TOLERANCE.pan
    && Math.abs(actual.tilt - expected.tilt) <= PARK_TOLERANCE.tilt
    && Math.abs(actual.zoom - expected.zoom) <= PARK_TOLERANCE.zoom;
}

function parsePositionBody(body: Uint8Array): VapixPosition | undefined {
  const values = Object.fromEntries(new TextDecoder().decode(body).split(/\r?\n/).filter(Boolean).map((line) => {
    const at = line.indexOf("=");
    return at < 1 ? [line.trim().toLowerCase(), ""] : [line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim()];
  }));
  const position = { pan: Number(values.pan), tilt: Number(values.tilt), zoom: Number(values.zoom) };
  return Object.values(position).every(Number.isFinite) ? position : undefined;
}

export class LiveSuite {
  private readonly credentials: CredStoreProvider;

  constructor(private readonly credBinary: string = CRED_BINARY) {
    this.credentials = new CredStoreProvider(credBinary);
  }

  private operatorClient(proxyUrl: string): DigestHttpClient {
    return new DigestHttpClient(
      proxyUrl, LIVE_TARGETS.ptz.username, LIVE_TARGETS.ptz.credentialReference,
      this.credentials, 10_000,
    );
  }

  /** Operator park move: real motion, witnessed, never invocation-attributable. */
  async park(proxyUrl: string): Promise<void> {
    const client = this.operatorClient(proxyUrl);
    const context = { invocationId: "operator-park", actionBearing: true } as const;
    const move = new URL("/axis-cgi/com/ptz.cgi", LIVE_TARGETS.ptz.baseUrl);
    move.searchParams.set("pan", String(PARK_POSITION.pan));
    move.searchParams.set("tilt", String(PARK_POSITION.tilt));
    move.searchParams.set("zoom", String(PARK_POSITION.zoom));
    const response = await client.request({ method: "GET", url: move, context });
    if (response.status < 200 || response.status >= 300) throw new Error(`park move rejected with HTTP ${response.status}`);
    await waitFor(async () => {
      const readback = await client.request({
        method: "GET",
        url: new URL("/axis-cgi/com/ptz.cgi?query=position", LIVE_TARGETS.ptz.baseUrl),
        context: { invocationId: "operator-park", actionBearing: false },
      });
      const position = parsePositionBody(readback.body);
      return position !== undefined && withinTolerance(position, PARK_POSITION);
    }, "park position settle", 30_000);
  }

  private preflightTransport(proxyUrl: string, username: string): PreflightTransport {
    const credentials = this.credentials;
    return {
      async get(url: string, credential) {
        const client = new DigestHttpClient(proxyUrl, username, credential.reference, credentials, 10_000);
        const response = await client.request({
          method: "GET", url: new URL(url),
          context: { invocationId: hex16(), actionBearing: false },
        });
        return { status: response.status, body: new TextDecoder().decode(response.body) };
      },
    };
  }

  /**
   * Live preflight runs once per device (PTZ leg and stream leg are separate
   * cameras since ruling G5-D2b-001); the merged file is green only when the
   * PTZ target proves identity+preset and the stream target proves
   * identity+profile.
   */
  async preflight(proxyUrl: string, resultPath: string): Promise<{ ok: boolean; firmware: { ptz: string; stream: string } }> {
    const backendMapping = { "ptz-primary": LIVE_TARGETS.ptz.baseUrl, "fixed-primary": LIVE_TARGETS.stream.baseUrl };
    const run = (target: typeof LIVE_TARGETS.ptz): Promise<PreflightResult> => runPreflight({
      baseUrl: target.baseUrl,
      credentialReference: target.credentialReference,
      expectedModel: target.expectedModel,
      expectedSerial: target.expectedSerial,
      presetName: SAFE_PRESET_BACKEND_NAME,
      streamProfile: STREAM_PROFILE_BACKEND,
      backendMapping,
    }, this.preflightTransport(proxyUrl, target.username), this.credentials);
    const ptz = await run(LIVE_TARGETS.ptz);
    const stream = await run(LIVE_TARGETS.stream);
    const checks = {
      credential_access: ptz.checks.credential_access && stream.checks.credential_access,
      identity: ptz.checks.identity && stream.checks.identity,
      model_firmware: ptz.checks.model_firmware && stream.checks.model_firmware,
      preset: ptz.checks.preset,
      stream_profile: stream.checks.stream_profile,
      backend_mapping: ptz.checks.backend_mapping && stream.checks.backend_mapping,
    };
    const merged = { ok: Object.values(checks).every(Boolean), checks, targets: { ptz, stream } };
    await mkdir(dirname(resultPath), { recursive: true });
    await writeFile(resultPath, `${JSON.stringify(merged, null, 2)}\n`);
    return { ok: merged.ok, firmware: { ptz: ptz.sanitized.firmware, stream: stream.sanitized.firmware } };
  }
}

/**
 * Live action-bearing 401s are legitimate ONLY as the first half of an RFC
 * 7616 stale-nonce repair (same request line, non-401 completion follows).
 */
function assertNoUnrepairedActionBearing401(witness: ScenarioRunResult["witness"]): void {
  witness.forEach((entry, index) => {
    if (!entry.action_bearing || !entry.response_line.includes(" 401 ")) return;
    const repaired = witness.slice(index + 1).some((later) =>
      later.action_bearing && later.request_line === entry.request_line && !later.response_line.includes(" 401 "));
    if (!repaired) throw new Error("action-bearing 401 without a stale-nonce repair");
  });
}

export async function runLiveSuite(requestedRoot?: string): Promise<LiveSuiteResult> {
  if (process.env.AAR_LIVE_WINDOW !== "1") {
    throw new Error("live suite requires AAR_LIVE_WINDOW=1 — set only inside the operator's exclusive-control window (F19)");
  }
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const root = resolve(requestedRoot ?? join(homedir(), ".aar-demo", `d2b-${Date.now()}`));
  await mkdir(root, { recursive: true });
  const keyDirectory = join(root, "keys");
  const priorState = join(root, "prior-state.json");
  const recoveryDirectory = join(root, "recovery");
  await generateDemoKeys(keyDirectory, join(root, "public-keys.json"));

  const suite = new LiveSuite();
  const operatorProxy = await startWitnessProxy(join(root, "operator.witness.jsonl"));
  const preflightPath = join(root, "preflight.json");
  let firmware: { ptz: string; stream: string };
  try {
    const preflight = await suite.preflight(operatorProxy.url, preflightPath);
    if (!preflight.ok) throw new Error(`live preflight failed: ${await readFile(preflightPath, "utf8")}`);
    firmware = preflight.firmware;
    if (!firmware.ptz || !firmware.stream) throw new Error("preflight did not read back device firmware");
    await suite.park(operatorProxy.url);
  } finally {
    await operatorProxy.close();
  }

  const shared = {
    version: 1 as const,
    tenant_id: hex16(),
    site_id: hex16(),
    target_id: hex16(),
    adapter: "vapix" as const,
    key_dir: keyDirectory,
    prior_state_file: priorState,
  };
  // Firmware comes from the live preflight readback, not a hardcoded constant,
  // so the source-device content assertion is a real device cross-check
  // (G5-D2b-007), not a gate constant compared against itself.
  const sourceDevice = (leg: "ptz" | "stream") => ({
    manufacturer: "AXIS", model: LIVE_TARGETS[leg].expectedModel, firmware: firmware[leg],
  });
  let lastAt = 0;
  let epoch = 30_000;
  const gate = (
    label: string,
    action: GateInputFile["action_name"],
    expected: GateInputFile["expected_outcome_level"],
    outputDirectory: string,
  ): GateInputFile => {
    const now = Math.floor(Date.now() / 1000);
    const evaluatedAt = Math.max(now, lastAt + 1);
    lastAt = evaluatedAt;
    epoch += 1;
    return {
      ...shared,
      evaluated_at: evaluatedAt,
      // G5-D1-003: real anchor submission time — the same real second the
      // epoch manifest is appended to the same-operator log.
      anchor_observed_at: evaluatedAt,
      epoch_id: epoch,
      invocation_id: hex16(),
      correlation_id: hex16(),
      output_dir: outputDirectory,
      target_logical_name: action === "camera.ptz.preset" ? "ptz-primary" : "fixed-primary",
      action_name: action,
      parameters: action === "camera.ptz.preset" ? { preset_name: "gate5-safe" } : { stream_profile: STREAM_PROFILE_LOGICAL },
      source_device: sourceDevice(action === "camera.ptz.preset" ? "ptz" : "stream"),
      expected_outcome_level: expected,
      delegation_candidates: [{ not_before: evaluatedAt - 600, not_after: evaluatedAt + 600 }],
      preflight_result_file: label === "S1" ? preflightPath : undefined,
    };
  };

  const summaries: LiveScenarioSummary[] = [];
  const credentials = new CredStoreProvider(CRED_BINARY);

  const execute = async (
    name: LiveScenarioSummary["scenario"],
    scenarioId: "S1" | "S2" | "S3" | "S4" | "S6",
    input: GateInputFile,
    options: { rejectionVariant?: boolean; fault?: WitnessFaultInjection; tamper?: boolean; parkFirst?: boolean } = {},
  ): Promise<ScenarioRunResult> => {
    const witnessPath = join(input.output_dir, `${scenarioId}.witness.jsonl`);
    await mkdir(input.output_dir, { recursive: true });
    if (options.parkFirst) {
      const parkProxy = await startWitnessProxy(join(input.output_dir, "park.witness.jsonl"));
      try { await suite.park(parkProxy.url); } finally { await parkProxy.close(); }
    }
    const proxy = await startWitnessProxy(witnessPath, options.fault);
    try {
      const adapter = new VapixAdapter(
        liveVapixConfig(proxy.url, recoveryDirectory, { rejectionVariant: options.rejectionVariant, exclusiveControl: true }),
        { credentials },
      );
      const result = await runScenario(scenarioId, input, adapter, root, options.tamper ? {
        expectedVerification: "nonconformant",
        expectedFailureReason: "sig/verify-failed",
        transformBundle: tamperPinnedRequestSignature,
      } : {});
      const evidence = result.producer.dispatchResult?.effect.backend_evidence;
      const applicationStatus = String(evidence?.application_status ?? "not_dispatched");
      if (name === "S1" && applicationStatus !== "position_within_tolerance") throw new Error(`S1 position evidence assertion failed: ${applicationStatus}`);
      if (name === "S2" && applicationStatus !== "media_payload_valid") throw new Error(`S2 media evidence assertion failed: ${applicationStatus}`);
      if (name === "S6-rejection") {
        if (applicationStatus !== "vapix_application_error" && !applicationStatus.startsWith("http_rejected_")) {
          throw new Error(`S6 rejection evidence assertion failed: ${applicationStatus}`);
        }
        if (evidence?.position_observation !== "outside_tolerance") throw new Error("S6 rejection lacked positive contrary position evidence");
      }
      if (name === "S6-after-send-timeout" && applicationStatus !== "transport_timeout_after_send") {
        throw new Error(`S6 timeout evidence assertion failed: ${applicationStatus}`);
      }
      assertNoUnrepairedActionBearing401(result.witness);
      summaries.push({
        scenario: name,
        verification: result.verificationResult,
        outcome: result.producer.dispatchResult?.effect.outcome_level ?? "not_dispatched",
        applicationStatus,
        oracle: "PASS",
      });
      return result;
    } finally {
      await proxy.close();
    }
  };

  const s1Dir = join(root, "artifacts", "S1");
  await execute("S1", "S1", gate("S1", "camera.ptz.preset", "device_acknowledged", s1Dir), { parkFirst: true });

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
  await execute("S4", "S4", gate("S4", "camera.ptz.preset", "device_acknowledged", s4Dir), { tamper: true, parkFirst: true });

  // S5 live crash-cut: the EP process dies after the action-bearing send to
  // the real camera; the witness proxy survives in this process.
  const s5Dir = join(root, "artifacts", "S5");
  await mkdir(s5Dir, { recursive: true });
  {
    const s5 = gate("S5", "camera.ptz.preset", "unknown", s5Dir);
    const parkProxy = await startWitnessProxy(join(s5Dir, "park.witness.jsonl"));
    try { await suite.park(parkProxy.url); } finally { await parkProxy.close(); }
    const s5WitnessPath = join(s5Dir, "S5.witness.jsonl");
    const s5Proxy = await startWitnessProxy(s5WitnessPath);
    try {
      const config = liveVapixConfig(s5Proxy.url, recoveryDirectory, { exclusiveControl: true });
      const cutMarkerPath = join(s5Dir, "dispatch-cut.marker");
      const workerPath = fileURLToPath(new URL("./crash-worker.ts", import.meta.url));
      const child = Bun.spawn(["bun", "run", workerPath], { cwd: repoRoot, stdin: "pipe", stdout: "pipe", stderr: "pipe" });
      // Drain the worker's pipes so it never blocks on a full stdout buffer.
      void new Response(child.stdout).text();
      void new Response(child.stderr).text();
      child.stdin.write(JSON.stringify({ gate: s5, baseDirectory: root, adapterConfig: config, credBinary: CRED_BINARY, cutMarkerPath }));
      child.stdin.end();
      const recoveryPath = join(recoveryDirectory, `${s5.invocation_id}.ptz-recovery.json`);
      try {
        await waitFor(() => exists(cutMarkerPath), "S5 dispatch cut marker");
        await waitFor(async () => (await new AppendOnlyWitnessLog(s5WitnessPath).entries()).some((entry) => entry.action_bearing && entry.command_digest !== null), "S5 witnessed dispatch");
        await waitFor(() => exists(recoveryPath), "S5 durable PTZ recovery baseline");
      } catch (error) {
        // Never leak a still-credentialed worker if a wait times out.
        child.kill(9);
        await child.exited;
        throw error;
      }
      child.kill(9);
      if (await child.exited === 0) throw new Error("S5 EP process was not killed at the crash cut");
      const adapter = new VapixAdapter(config, { credentials });
      const result = await runScenario("S5", s5, adapter, root);
      const applicationStatus = String(result.producer.dispatchResult?.effect.backend_evidence.application_status);
      if (applicationStatus !== "outcome_unknown_restore_verified") throw new Error(`S5 recovery evidence assertion failed: ${applicationStatus}`);
      if (await exists(recoveryPath)) throw new Error("S5 recovery record remained after verified restoration");
      assertNoUnrepairedActionBearing401(result.witness);
      summaries.push({ scenario: "S5", verification: result.verificationResult, outcome: result.producer.dispatchResult!.effect.outcome_level, applicationStatus, oracle: "PASS" });
    } finally {
      await s5Proxy.close();
    }
  }

  const s6RejectDir = join(root, "artifacts", "S6-rejection");
  await execute("S6-rejection", "S6", gate("S6-rejection", "camera.ptz.preset", "contradicted", s6RejectDir), { rejectionVariant: true, parkFirst: true });

  const s6TimeoutDir = join(root, "artifacts", "S6-after-send-timeout");
  await execute("S6-after-send-timeout", "S6", gate("S6-timeout", "camera.ptz.preset", "unknown", s6TimeoutDir), {
    fault: { withholdResponseAfterForward: true }, parkFirst: true,
  });

  // Leave the camera at the operator park (the revert-list resting state).
  {
    const parkProxy = await startWitnessProxy(join(root, "final-park.witness.jsonl"));
    try { await suite.park(parkProxy.url); } finally { await parkProxy.close(); }
  }

  // Hygiene: runtime-fetched REAL secrets are the canaries. Digest realms come
  // from each device's live challenge so HA1 transforms are covered too.
  const hits: HygieneHit[] = [];
  for (const target of [LIVE_TARGETS.ptz, LIVE_TARGETS.stream]) {
    const challenge = await fetch(`${target.baseUrl}/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName`);
    // Parse the Digest challenge specifically (not a first-`realm=` regex that
    // a Basic scheme could poison); throw if the realm can't be recovered so
    // the HA1 transform legs are never silently dropped (G5-D2b-006).
    const digestRealm = parseDigestChallenge(challenge.headers.get("www-authenticate") ?? undefined).realm;
    if (!digestRealm) throw new Error(`could not recover Digest realm for ${target.credentialReference}; HA1 hygiene coverage would be dropped`);
    const secret = (await credentials.get(target.credentialReference)).secret;
    // Full transforms over the generated artifact tree (any occurrence of the
    // runtime secret there is a real leak); collision-free hash transforms
    // over the committed source tree (G5-D2b-011 — short literals false-match).
    hits.push(...await sweepCanary({
      canary: secret, roots: [root], hashOnlyRoots: [repoRoot],
      digestUsername: target.username, digestRealm,
    }));
  }
  if (hits.length) throw new Error(`secret hygiene sweep found ${hits.length} hit(s): ${hits.map((hit) => hit.path).join(", ")}`);

  await writeFile(join(root, "summary.json"), `${JSON.stringify({ scenarios: summaries, hygiene_hits: hits.length }, null, 2)}\n`);
  return { root, scenarios: summaries, hygieneHits: hits.length };
}

if (import.meta.main) {
  const result = await runLiveSuite(process.argv[2]);
  console.log(`D2b live artifacts: ${result.root}`);
  for (const scenario of result.scenarios) {
    console.log(`${scenario.scenario}: ${scenario.verification}; outcome=${scenario.outcome}; application_status=${scenario.applicationStatus}; oracle=${scenario.oracle}`);
  }
  console.log(`secret hygiene sweep: ${result.hygieneHits} hits`);
}
