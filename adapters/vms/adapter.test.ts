import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { domainHash, hash, id16, signDetached } from "../../harness/crypto";
import { toHex } from "../../harness/cbor";
import { buildCommandManifest } from "../../demo/ep/command-manifest";
import { AppendOnlyWitnessLog } from "../../demo/witness/log";
import type { DispatchContext } from "../shared/types";
import { VmsAdapter } from "./adapter";
import { MediatorHttpClient } from "./client";
import { assertVmsConfig, type VmsRuntimeConfig } from "./config";
import { MockVigilControl, type MockVigilControlConfig } from "./mock/vigil-control";
import { InMemoryMediatorWitnessTransport } from "./mock/transport";
import { TEST_KEYS } from "../../harness/testkeys";

function testMediatorConfig(secret = "offline-test-canary-secret"): MockVigilControlConfig {
  return {
    credentialReference: "camera-ref", secret,
    expectedHost: "cam.invalid", expectedUsername: "operator",
    presetBackendName: "preset-7", streamBackendProfile: "profile-1",
    model: "mock", serial: "mock", firmware: "mock",
    baseline: { pan: 0, tilt: 0, zoom: 1 }, safePreset: { pan: 5, tilt: 3, zoom: 2 }, settlingReads: 1,
  };
}

function testRuntimeConfig(root: string): VmsRuntimeConfig {
  return {
    witnessProxyUrl: "http://witness.invalid",
    mediatorBaseUrl: "http://mock-vigil-control.invalid",
    targets: {
      "ptz-primary": { host: "cam.invalid", port: 80, username: "operator", credentialReference: "camera-ref" },
      "fixed-primary": { host: "cam.invalid", port: 80, username: "operator", credentialReference: "camera-ref" },
    },
    presetMappings: { "gate5-safe": "preset-7" },
    presetPositions: { "gate5-safe": { pan: 5, tilt: 3, zoom: 2 } },
    streamProfileMappings: { test: "profile-1" },
    positionTolerance: { pan: 0, tilt: 0, zoom: 0 },
    pollIntervalMs: 1, settlingDeadlineMs: 100, requestTimeoutMs: 100,
    streamMinimumPayloadBytes: 16, exclusiveControl: true, recoveryDirectory: join(root, "recovery"),
  };
}

let sequence = 0;

function testContext(root: string, commandDigestHex: string): DispatchContext {
  sequence += 1;
  return {
    invocationIdHex: toHex(id16(`vms-test-invocation-${sequence}`)),
    commandDigestHex,
    witnessLogPath: join(root, "witness.jsonl"),
    observedAt: 1_800_030_000,
  };
}

function presetManifest() {
  return buildCommandManifest({
    actionName: "camera.ptz.preset", targetId: id16("vms-test-target"), targetLogicalName: "ptz-primary",
    parameters: { preset_name: "gate5-safe" }, invocationId: id16("vms-test-invocation"),
  }, "vms", "0.1.0-d3");
}

function testHarness(root: string, mediator: MockVigilControl): { adapter: VmsAdapter; witnessPath: string } {
  const witnessPath = join(root, "witness.jsonl");
  return {
    adapter: new VmsAdapter(testRuntimeConfig(root), { httpTransport: new InMemoryMediatorWitnessTransport(mediator, witnessPath) }),
    witnessPath,
  };
}

describe("VMS adapter", () => {
  test("config rejects FILL-AT-D3 placeholders and non-HTTP mediator", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
    const config = testRuntimeConfig(root);
    expect(() => assertVmsConfig({ ...config, mediatorBaseUrl: "https://mediator.invalid" })).toThrow("mediator base URL must use HTTP");
    expect(() => assertVmsConfig({
      ...config,
      targets: { ...config.targets, "ptz-primary": { ...config.targets["ptz-primary"], host: "FILL-AT-D3:ptz-host" } },
    })).toThrow("FILL-AT-D3");
  });

  test("PTZ preset dispatch through the mediator acknowledges, restores, and binds the command body", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
    const mediator = new MockVigilControl(testMediatorConfig());
    const { adapter, witnessPath } = testHarness(root, mediator);
    const manifest = presetManifest();
    const context = testContext(root, toHex(manifest.command_digest));
    const result = await adapter.dispatch(manifest, context);
    expect(result.dispatched).toBeTrue();
    expect(result.effect.outcome_level).toBe("device_acknowledged");
    expect(result.effect.backend_evidence.application_status).toBe("position_within_tolerance");
    expect(result.effect.backend_evidence.restore_verified).toBe(true);
    expect(result.effect.backend_evidence.vms_mediated).toBe(true);
    const witness = await new AppendOnlyWitnessLog(witnessPath).entries();
    const bound = witness.filter((entry) => entry.command_digest === context.commandDigestHex);
    expect(bound).toHaveLength(1);
    expect(bound[0]!.request_body_sha256).toBe(context.commandDigestHex);
    expect(mediator.counters().restoreDispatches).toBe(1);
    expect(mediator.currentPosition()).toEqual({ pan: 0, tilt: 0, zoom: 1 });
  });

  test("mediator refuses a dispatch whose body does not hash to the digest", async () => {
    const mediator = new MockVigilControl(testMediatorConfig());
    const client = new MediatorHttpClient("http://witness.invalid", 100, {
      exchange: (request) => mediator.exchange(request),
    });
    const url = new URL("/dispatch?op=ptz.goto_preset&preset=preset-7&host=cam.invalid&port=80&username=operator&cred=camera-ref", "http://mock-vigil-control.invalid");
    url.searchParams.set("digest", "00".repeat(32));
    const response = await client.request({
      method: "POST", url, body: new TextEncoder().encode("not-the-canonical-command"),
      context: { invocationId: toHex(id16("vms-test-digest-mismatch")), actionBearing: true, commandDigest: "00".repeat(32) },
    });
    const effect = JSON.parse(new TextDecoder().decode(response.body)) as { application_status: string };
    expect(effect.application_status).toBe("body_digest_mismatch");
  });

  test("contract v3 keeps attempt_digest optional and fails closed only when an offered value cannot be countersigned", async () => {
    const manifest = buildCommandManifest({
      actionName: "camera.stream.view", targetId: id16("vms-test-optional-attempt-target"), targetLogicalName: "fixed-primary",
      parameters: { stream_profile: "test" }, invocationId: id16("vms-test-optional-attempt-invocation"),
    }, "vms", "0.1.0-d3");
    const mediator = new MockVigilControl({
      ...testMediatorConfig(), mediatorSigner: TEST_KEYS.mediator_outcome_signing,
    });
    const client = new MediatorHttpClient("http://witness.invalid", 100, {
      exchange: (request) => mediator.exchange(request),
    });
    const dispatchUrl = new URL("/dispatch?op=stream.view&profile=profile-1&host=cam.invalid&port=80&username=operator&cred=camera-ref", "http://mock-vigil-control.invalid");
    dispatchUrl.searchParams.set("digest", toHex(manifest.command_digest));
    const absent = await client.request({
      method: "POST", url: dispatchUrl, body: manifest.canonical_command,
      context: { invocationId: toHex(id16("vms-test-optional-attempt-absent")), actionBearing: true, commandDigest: toHex(manifest.command_digest) },
    });
    const absentEffect = JSON.parse(new TextDecoder().decode(absent.body)) as { application_status: string; countersignature?: string };
    expect(absentEffect.application_status).toBe("media_payload_valid");
    expect(absentEffect.countersignature).toBeUndefined();

    const malformedUrl = new URL(dispatchUrl);
    malformedUrl.searchParams.set("attempt_digest", "not-a-digest");
    const malformed = await client.request({
      method: "POST", url: malformedUrl, body: manifest.canonical_command,
      context: { invocationId: toHex(id16("vms-test-optional-attempt-malformed")), actionBearing: true, commandDigest: toHex(manifest.command_digest) },
    });
    const malformedEffect = JSON.parse(new TextDecoder().decode(malformed.body)) as { application_status: string };
    expect(malformedEffect.application_status).toBe("countersignature_failed");
    expect(mediator.counters().streamDispatches).toBe(1);
  });

  test("preserves an offered signed digest mismatch even with a malformed mediator credential", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
    const manifest = buildCommandManifest({
      actionName: "camera.stream.view", targetId: id16("vms-test-countersign-target"), targetLogicalName: "fixed-primary",
      parameters: { stream_profile: "test" }, invocationId: id16("vms-test-countersign-invocation"),
    }, "vms", "0.1.0-d3");
    const attemptDigest = hash(new TextEncoder().encode("vms-test-attempt-envelope"));
    const fields = {
      v: 2,
      action_attempt_receipt_digest: attemptDigest,
      command_digest: hash(new TextEncoder().encode("signed-but-wrong-command")),
      mediator_observed_at: 1_800_030_000,
    };
    const signed = signDetached({
      countersignature_id: domainHash("AAR-MEDIATOR-COUNTERSIGNATURE-ID-v1", fields), ...fields,
    }, "application/aar-mediator-countersignature+cbor;v=0.2", "outcome_signing");
    const effect = new TextEncoder().encode(JSON.stringify({
      op: "stream.view", http_ok: true, application_status: "media_payload_valid",
      media_valid: true, content_type: "image/jpeg", payload_bytes: 100,
      countersignature_payload: Buffer.from(signed.payloadBytes).toString("base64"),
      countersignature: Buffer.from(signed.coseBytes).toString("base64"),
      mediator_credential: "not-base64",
    }));
    const adapter = new VmsAdapter(testRuntimeConfig(root), {
      httpTransport: { exchange: async () => ({ status: 200, statusMessage: "OK", headers: {}, body: effect }) },
    });
    const result = await adapter.dispatch(manifest, {
      ...testContext(root, toHex(manifest.command_digest)), actionAttemptReceiptDigestHex: toHex(attemptDigest),
    });
    expect(result.mediatorCountersignature).toBeDefined();
    expect(result.mediatorCountersignature?.credentialEnvelope).toBeUndefined();
    expect(result.mediatorCountersignature?.envelope).toEqual(signed.envelope);
  });

  test("backend rejection with contrary readback is contradicted; F19 restore still runs", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
    const mediator = new MockVigilControl(testMediatorConfig());
    const { adapter } = testHarness(root, mediator);
    mediator.setFaultMode("reject");
    const manifest = presetManifest();
    const result = await adapter.dispatch(manifest, testContext(root, toHex(manifest.command_digest)));
    expect(result.effect.outcome_level).toBe("contradicted");
    expect(result.effect.backend_evidence.application_status).toBe("http_rejected_503");
    expect(result.effect.backend_evidence.position_observation).toBe("outside_tolerance");
    expect(mediator.counters().restoreDispatches).toBe(1);
  });

  test("after-send timeout latches dispatch and reports transport_timeout_after_send", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
    const mediator = new MockVigilControl(testMediatorConfig());
    const { adapter } = testHarness(root, mediator);
    mediator.setFaultMode("after-send-timeout");
    const manifest = presetManifest();
    const result = await adapter.dispatch(manifest, testContext(root, toHex(manifest.command_digest)));
    expect(result.dispatched).toBeTrue();
    expect(result.effect.outcome_level).toBe("unknown");
    expect(result.effect.backend_evidence.application_status).toBe("transport_timeout_after_send");
  });

  test("stream: observed invalid media is contradicted; mediator-internal failure stays unknown", async () => {
    const streamManifest = () => buildCommandManifest({
      actionName: "camera.stream.view", targetId: id16("vms-test-stream-target"), targetLogicalName: "fixed-primary",
      parameters: { stream_profile: "test" }, invocationId: id16("vms-test-stream-invocation"),
    }, "vms", "0.1.0-d3");
    {
      const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
      const mediator = new MockVigilControl(testMediatorConfig());
      const { adapter } = testHarness(root, mediator);
      mediator.setFaultMode("invalid-media");
      const manifest = streamManifest();
      const result = await adapter.dispatch(manifest, testContext(root, toHex(manifest.command_digest)));
      expect(result.effect.outcome_level).toBe("contradicted");
      expect(result.effect.backend_evidence.application_status).toBe("media_payload_invalid");
    }
    {
      const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
      const mediator = new MockVigilControl(testMediatorConfig());
      const { adapter } = testHarness(root, mediator);
      mediator.setFaultMode("backend-transport-error");
      const manifest = streamManifest();
      const result = await adapter.dispatch(manifest, testContext(root, toHex(manifest.command_digest)));
      expect(result.effect.outcome_level).toBe("unknown");
      expect(result.effect.state).toBe("unknown");
      expect(result.effect.backend_evidence.application_status).toBe("transport_error");
    }
  });

  test("only the gate5-safe logical preset is permitted", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vms-unit-"));
    const mediator = new MockVigilControl(testMediatorConfig());
    const { adapter } = testHarness(root, mediator);
    const manifest = buildCommandManifest({
      actionName: "camera.ptz.preset", targetId: id16("vms-test-guard-target"), targetLogicalName: "ptz-primary",
      parameters: { preset_name: "somewhere-else" }, invocationId: id16("vms-test-guard-invocation"),
    }, "vms", "0.1.0-d3");
    await expect(adapter.dispatch(manifest, testContext(root, toHex(manifest.command_digest)))).rejects.toThrow("gate5-safe");
  });
});
