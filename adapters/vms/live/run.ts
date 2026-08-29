import { randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Server } from "node:http";
import { CredStoreProvider } from "../../../demo/preflight";
import { generateDemoKeys } from "../../../demo/keys/keys";
import { sweepCanary, type HygieneHit } from "../../../demo/hygiene-sweep";
import { runScenario, type GateInputFile, type ScenarioRunResult } from "../../../demo/run-scenario";
import { createWitnessProxy, type WitnessFaultInjection } from "../../../demo/witness/proxy";
import { parseDigestChallenge } from "../../vapix/digest";
import { tamperPinnedRequestSignature } from "../../vapix/offline/run";
import { LiveSuite } from "../../vapix/live/run";
import { VmsAdapter } from "../adapter";
import { MediatorHttpClient } from "../client";
import { assertVmsMediationDiscipline, assertVmsPtzRestoreDiscipline } from "../oracle";
import { CRED_BINARY, LIVE_TARGETS, STREAM_PROFILE_LOGICAL, liveVmsConfig } from "./config";

// D3 live leg — S1–S4 + S6–S7 through EP -> transport witness -> REAL
// vigil-control (VigilCore.VAPIXClient in its own process) -> owned cameras.
// S5 crash-cut ran once on the EP+VAPIX leg (Q5-2); this leg encodes
// outcome_unknown via S6-after-send-timeout. Operator-plane park moves reuse
// the D2b LiveSuite on the operator's own witnessed channel — they are not
// part of the mediated claim.

export interface VmsLiveScenarioSummary {
  readonly scenario: "S1" | "S2" | "S3" | "S4" | "S6-rejection" | "S6-after-send-timeout" | "S7";
  readonly verification: "conformant" | "nonconformant";
  readonly outcome: string;
  readonly applicationStatus: string;
  readonly oracle: "PASS";
}

export interface VmsLiveSuiteResult {
  readonly root: string;
  readonly scenarios: readonly VmsLiveScenarioSummary[];
  readonly hygieneHits: number;
}

interface WitnessProxyHandle {
  readonly url: string;
  close(): Promise<void>;
}

interface MediatorHandle {
  readonly baseUrl: string;
  stop(): void;
}

interface MediatorEffectJson {
  readonly application_status?: string;
  readonly pan?: number;
  readonly model?: string;
  readonly serial?: string;
  readonly firmware?: string;
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

async function startMediator(repoRoot: string): Promise<MediatorHandle> {
  const binary = join(repoRoot, "adapters", "vms", "vigil-control", ".build", "debug", "vigil-control");
  if (!existsSync(binary)) {
    throw new Error(`vigil-control binary missing — run: swift build --package-path adapters/vms/vigil-control`);
  }
  const child = Bun.spawn([binary, "0"], { stdout: "pipe", stderr: "pipe" });
  void new Response(child.stderr).text();
  const reader = child.stdout.getReader();
  const deadline = Date.now() + 15_000;
  let banner = "";
  const decoder = new TextDecoder();
  while (!banner.includes("listening on") && Date.now() < deadline) {
    const { value, done } = await reader.read();
    if (done) break;
    banner += decoder.decode(value);
  }
  reader.releaseLock();
  const match = banner.match(/listening on 127\.0\.0\.1:(\d+)/);
  if (!match) {
    child.kill(9);
    throw new Error(`vigil-control did not report a listen port: ${banner}`);
  }
  return { baseUrl: `http://127.0.0.1:${match[1]}`, stop: () => child.kill(9) };
}

export async function runVmsLiveSuite(requestedRoot?: string): Promise<VmsLiveSuiteResult> {
  if (process.env.AAR_LIVE_WINDOW !== "1") {
    throw new Error("live suite requires AAR_LIVE_WINDOW=1 — set only inside the operator's exclusive-control window (F19)");
  }
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const root = resolve(requestedRoot ?? join(homedir(), ".aar-demo", `d3-${Date.now()}`));
  await mkdir(root, { recursive: true });
  const keyDirectory = join(root, "keys");
  const priorState = join(root, "prior-state.json");
  const recoveryDirectory = join(root, "recovery");
  await generateDemoKeys(keyDirectory, join(root, "public-keys.json"));

  const operatorSuite = new LiveSuite();
  const mediator = await startMediator(repoRoot);
  try {
    // Operator park before anything else (D2b discipline: runs start off-safe).
    {
      const parkProxy = await startWitnessProxy(join(root, "operator.witness.jsonl"));
      try { await operatorSuite.park(parkProxy.url); } finally { await parkProxy.close(); }
    }

    // VMS preflight through the witnessed mediator channel: health, identity
    // (model/serial vs locked expectations, firmware READBACK — G5-D2b-007
    // parity), and a PTZ position readback whose "ok" is itself the
    // G5-D3-001 park sanity check (the zero-sentinel refuses fabrications).
    const preflightPath = join(root, "preflight.json");
    let firmware: { ptz: string; stream: string };
    {
      const witnessPath = join(root, "preflight.witness.jsonl");
      const proxy = await startWitnessProxy(witnessPath);
      try {
        const client = new MediatorHttpClient(proxy.url, 10_000);
        const config = liveVmsConfig(proxy.url, mediator.baseUrl, recoveryDirectory);
        const routed = (path: string, target: "ptz-primary" | "fixed-primary"): URL => {
          const routing = config.targets[target];
          const url = new URL(path, mediator.baseUrl);
          url.searchParams.set("host", routing.host);
          url.searchParams.set("port", String(routing.port));
          url.searchParams.set("username", routing.username);
          url.searchParams.set("cred", routing.credentialReference);
          return url;
        };
        const get = async (url: URL): Promise<{ status: number; effect: MediatorEffectJson }> => {
          const response = await client.request({ method: "GET", url, context: { invocationId: hex16(), actionBearing: false } });
          let effect: MediatorEffectJson = {};
          try { effect = JSON.parse(new TextDecoder().decode(response.body)) as MediatorEffectJson; } catch { /* non-JSON stays {} */ }
          return { status: response.status, effect };
        };
        const health = await get(new URL("/healthz", mediator.baseUrl));
        const ptzIdentity = await get(routed("/device/info", "ptz-primary"));
        const streamIdentity = await get(routed("/device/info", "fixed-primary"));
        const position = await get(routed("/ptz/position", "ptz-primary"));
        const checks = {
          mediator_healthz: health.status === 200,
          ptz_identity: ptzIdentity.status === 200 && ptzIdentity.effect.application_status === "ok"
            && ptzIdentity.effect.model === LIVE_TARGETS.ptz.expectedModel && ptzIdentity.effect.serial === LIVE_TARGETS.ptz.expectedSerial,
          stream_identity: streamIdentity.status === 200 && streamIdentity.effect.application_status === "ok"
            && streamIdentity.effect.model === LIVE_TARGETS.stream.expectedModel && streamIdentity.effect.serial === LIVE_TARGETS.stream.expectedSerial,
          firmware_readback: Boolean(ptzIdentity.effect.firmware) && Boolean(streamIdentity.effect.firmware),
          park_position_readback: position.status === 200 && position.effect.application_status === "ok" && Number.isFinite(position.effect.pan),
        };
        const ok = Object.values(checks).every(Boolean);
        await mkdir(dirname(preflightPath), { recursive: true });
        await writeFile(preflightPath, `${JSON.stringify({
          ok, checks, mediator: "vigil-control",
          sanitized: {
            ptz: { model: ptzIdentity.effect.model, firmware: ptzIdentity.effect.firmware },
            stream: { model: streamIdentity.effect.model, firmware: streamIdentity.effect.firmware },
          },
        }, null, 2)}\n`);
        if (!ok) throw new Error(`VMS live preflight failed: ${JSON.stringify(checks)}`);
        firmware = { ptz: ptzIdentity.effect.firmware!, stream: streamIdentity.effect.firmware! };
      } finally {
        await proxy.close();
      }
    }

    const shared = {
      version: 1 as const,
      tenant_id: hex16(),
      site_id: hex16(),
      target_id: hex16(),
      adapter: "vms" as const,
      key_dir: keyDirectory,
      prior_state_file: priorState,
    };
    // Firmware from the live mediator readback, not a gate constant
    // (G5-D2b-007): the source-device assertion is a real device cross-check.
    const sourceDevice = (leg: "ptz" | "stream") => ({
      manufacturer: "AXIS", model: LIVE_TARGETS[leg].expectedModel, firmware: firmware[leg],
    });
    let lastAt = 0;
    let epoch = 40_000;
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

    const summaries: VmsLiveScenarioSummary[] = [];
    const execute = async (
      name: VmsLiveScenarioSummary["scenario"],
      scenarioId: "S1" | "S2" | "S3" | "S4" | "S6" | "S7",
      input: GateInputFile,
      options: { rejectionVariant?: boolean; fault?: WitnessFaultInjection; tamper?: boolean; parkFirst?: boolean; journalDown?: boolean } = {},
    ): Promise<ScenarioRunResult> => {
      const witnessPath = join(input.output_dir, `${scenarioId}.witness.jsonl`);
      await mkdir(input.output_dir, { recursive: true });
      if (options.parkFirst) {
        const parkProxy = await startWitnessProxy(join(input.output_dir, "park.witness.jsonl"));
        try { await operatorSuite.park(parkProxy.url); } finally { await parkProxy.close(); }
      }
      const proxy = await startWitnessProxy(witnessPath, options.fault);
      try {
        const adapter = new VmsAdapter(
          liveVmsConfig(proxy.url, mediator.baseUrl, recoveryDirectory, { rejectionVariant: options.rejectionVariant, exclusiveControl: true }),
          {},
        );
        const result = await runScenario(scenarioId, input, adapter, root, options.tamper
          ? { expectedVerification: "nonconformant", expectedFailureReason: "sig/verify-failed", transformBundle: tamperPinnedRequestSignature }
          : options.journalDown ? { journalUnavailableBeforeSend: true } : {});
        const evidence = result.producer.dispatchResult?.effect.backend_evidence;
        const applicationStatus = String(evidence?.application_status ?? "not_dispatched");
        if (name === "S1" && applicationStatus !== "position_within_tolerance") throw new Error(`S1 position evidence assertion failed: ${applicationStatus}`);
        if (name === "S2" && applicationStatus !== "media_payload_valid") throw new Error(`S2 media evidence assertion failed: ${applicationStatus}`);
        // Live S6-rejection: an absent backend preset is an error-in-200 the
        // VMS seam reports as "ok" (G5-D3-003), so the contrary evidence is
        // the position readback — the camera demonstrably did not go to
        // gate5-safe. Contradiction with positive observation, as in D2b.
        if (name === "S6-rejection" && applicationStatus !== "position_outside_tolerance") {
          throw new Error(`S6 rejection evidence assertion failed: ${applicationStatus}`);
        }
        if (name === "S6-after-send-timeout" && applicationStatus !== "transport_timeout_after_send") {
          throw new Error(`S6 timeout evidence assertion failed: ${applicationStatus}`);
        }
        assertVmsMediationDiscipline(result, input);
        if (name === "S1") assertVmsPtzRestoreDiscipline(result, input);
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

    const s7Dir = join(root, "artifacts", "S7");
    await execute("S7", "S7", gate("S7", "camera.ptz.preset", "accepted", s7Dir), { parkFirst: true, journalDown: true });

    const s4Dir = join(root, "artifacts", "S4");
    await execute("S4", "S4", gate("S4", "camera.ptz.preset", "device_acknowledged", s4Dir), { tamper: true, parkFirst: true });

    const s6RejectDir = join(root, "artifacts", "S6-rejection");
    await execute("S6-rejection", "S6", gate("S6-rejection", "camera.ptz.preset", "contradicted", s6RejectDir), { rejectionVariant: true, parkFirst: true });

    const s6TimeoutDir = join(root, "artifacts", "S6-after-send-timeout");
    await execute("S6-after-send-timeout", "S6", gate("S6-timeout", "camera.ptz.preset", "unknown", s6TimeoutDir), {
      fault: { withholdResponseAfterForward: true }, parkFirst: true,
    });

    // Leave the camera at the operator park (the revert-list resting state).
    {
      const parkProxy = await startWitnessProxy(join(root, "final-park.witness.jsonl"));
      try { await operatorSuite.park(parkProxy.url); } finally { await parkProxy.close(); }
    }

    // Hygiene: runtime-fetched REAL secrets are the canaries (the TS adapter
    // never held them — the sweep proves nothing else did either). Digest
    // realms from each device's live challenge cover the HA1 legs
    // (G5-D2b-006/-011 discipline carried).
    const credentials = new CredStoreProvider(CRED_BINARY);
    const hits: HygieneHit[] = [];
    for (const target of [LIVE_TARGETS.ptz, LIVE_TARGETS.stream]) {
      const challenge = await fetch(`${target.baseUrl}/axis-cgi/param.cgi?action=list&group=Brand.ProdShortName`);
      const digestRealm = parseDigestChallenge(challenge.headers.get("www-authenticate") ?? undefined).realm;
      if (!digestRealm) throw new Error(`could not recover Digest realm for ${target.credentialReference}; HA1 hygiene coverage would be dropped`);
      const secret = (await credentials.get(target.credentialReference)).secret;
      hits.push(...await sweepCanary({
        canary: secret, roots: [root], hashOnlyRoots: [repoRoot],
        digestUsername: target.username, digestRealm,
      }));
    }
    if (hits.length) throw new Error(`secret hygiene sweep found ${hits.length} hit(s): ${hits.map((hit) => hit.path).join(", ")}`);

    await writeFile(join(root, "summary.json"), `${JSON.stringify({ scenarios: summaries, hygiene_hits: hits.length }, null, 2)}\n`);
    return { root, scenarios: summaries, hygieneHits: hits.length };
  } finally {
    mediator.stop();
  }
}

if (import.meta.main) {
  const result = await runVmsLiveSuite(process.argv[2]);
  console.log(`D3 live artifacts: ${result.root}`);
  for (const scenario of result.scenarios) {
    console.log(`${scenario.scenario}: ${scenario.verification}; outcome=${scenario.outcome}; application_status=${scenario.applicationStatus}; oracle=${scenario.oracle}`);
  }
  console.log(`secret hygiene sweep: ${result.hygieneHits} hits`);
}
