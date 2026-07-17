import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { id16 } from "../../harness/crypto";
import { toHex } from "../../harness/cbor";
import { buildCommandManifest } from "../../demo/ep/command-manifest";
import { produce } from "../../demo/ep/producer";
import { DurableInvocationJournal } from "../../demo/ep/journal";
import { LocalRfc6962Log } from "../../demo/anchor/log";
import { generateDemoKeys } from "../../demo/keys/keys";
import { AppendOnlyWitnessLog } from "../../demo/witness/log";
import { VapixAdapter } from "./adapter";
import type { VapixRuntimeConfig } from "./config";
import { parseDigestChallenge } from "./digest";
import { MockVapixBackend, type MockVapixConfig } from "./mock/server";
import { InMemoryWitnessTransport } from "./mock/transport";

function testMockConfig(password = "offline-test-password"): MockVapixConfig {
  return {
    username: "operator", password, realm: "test", presetBackendName: "preset-7", streamBackendProfile: "profile-1",
    model: "mock", firmware: "mock", serial: "mock", baseline: { pan: 0, tilt: 0, zoom: 1 },
    safePreset: { pan: 5, tilt: 3, zoom: 2 }, settlingReads: 1,
  };
}

function testRuntimeConfig(root: string): VapixRuntimeConfig {
  return {
    targets: {
      "ptz-primary": { baseUrl: "http://mock-vapix.invalid", username: "operator", credentialReference: "camera" },
      "fixed-primary": { baseUrl: "http://mock-vapix.invalid", username: "operator", credentialReference: "camera" },
    },
    witnessProxyUrl: "http://witness.invalid",
    presetMappings: { "gate5-safe": "preset-7" },
    presetPositions: { "gate5-safe": { pan: 5, tilt: 3, zoom: 2 } },
    streamProfileMappings: { test: "profile-1" },
    positionTolerance: { pan: 0, tilt: 0, zoom: 0 },
    pollIntervalMs: 1, settlingDeadlineMs: 100, requestTimeoutMs: 100,
    streamMinimumPayloadBytes: 16, exclusiveControl: true, recoveryDirectory: join(root, "recovery"),
  };
}

function testAdapter(root: string, backend: MockVapixBackend, password = "offline-test-password"): { adapter: VapixAdapter; witnessPath: string } {
  const witnessPath = join(root, "witness.jsonl");
  const credentials = { async get(reference: string) { return { reference, secret: password }; } };
  return {
    adapter: new VapixAdapter(testRuntimeConfig(root), { credentials, httpTransport: new InMemoryWitnessTransport(backend, witnessPath) }),
    witnessPath,
  };
}

describe("VAPIX adapter", () => {
  test("parses an RFC 7616 SHA-256 challenge", () => {
    expect(parseDigestChallenge('Digest realm="camera", nonce="n", algorithm=SHA-256, qop="auth"')).toEqual({
      realm: "camera", nonce: "n", algorithm: "SHA-256", qop: "auth", opaque: undefined, stale: false,
    });
  });

  test("selects Digest from a multi-scheme challenge", () => {
    expect(parseDigestChallenge('Basic realm="fallback", Digest realm="camera", nonce="fresh", algorithm=SHA-256, qop="auth", stale=true')).toEqual({
      realm: "camera", nonce: "fresh", algorithm: "SHA-256", qop: "auth", opaque: undefined, stale: true,
    });
  });

  test("treats a VAPIX application error inside HTTP 200 as contradicted and restores", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vapix-app-error-"));
    const password = "offline-test-password";
    const mockConfig: MockVapixConfig = {
      username: "operator", password, realm: "test", presetBackendName: "preset-7", streamBackendProfile: "profile-1",
      model: "mock", firmware: "mock", serial: "mock", baseline: { pan: 0, tilt: 0, zoom: 1 },
      safePreset: { pan: 5, tilt: 3, zoom: 2 }, settlingReads: 1,
    };
    const backend = new MockVapixBackend(mockConfig);
    backend.setFaultMode("application-error");
    const witnessPath = join(root, "witness.jsonl");
    const config: VapixRuntimeConfig = {
      targets: {
        "ptz-primary": { baseUrl: "http://mock-vapix.invalid", username: "operator", credentialReference: "camera" },
        "fixed-primary": { baseUrl: "http://mock-vapix.invalid", username: "operator", credentialReference: "camera" },
      },
      witnessProxyUrl: "http://witness.invalid",
      presetMappings: { "gate5-safe": "preset-7" },
      presetPositions: { "gate5-safe": { pan: 5, tilt: 3, zoom: 2 } },
      streamProfileMappings: { test: "profile-1" },
      positionTolerance: { pan: 0, tilt: 0, zoom: 0 },
      pollIntervalMs: 1, settlingDeadlineMs: 100, requestTimeoutMs: 100,
      streamMinimumPayloadBytes: 16, exclusiveControl: true, recoveryDirectory: join(root, "recovery"),
    };
    const credentials = { async get(reference: string) { return { reference, secret: password }; } };
    const adapter = new VapixAdapter(config, { credentials, httpTransport: new InMemoryWitnessTransport(backend, witnessPath) });
    const command = buildCommandManifest({
      actionName: "camera.ptz.preset", targetId: id16("vapix-test-target"), targetLogicalName: "ptz-primary",
      parameters: { preset_name: "gate5-safe" }, invocationId: id16("vapix-test-invocation"),
    }, adapter.id, adapter.version);
    const invocationIdHex = toHex(id16("vapix-test-invocation"));
    const result = await adapter.dispatch(command, {
      invocationIdHex, commandDigestHex: toHex(command.command_digest), witnessLogPath: witnessPath, observedAt: 1_800_000_000,
    });
    expect(result.status).toBe(200);
    expect(result.effect.outcome_level).toBe("contradicted");
    expect(result.effect.backend_evidence.application_status).toBe("vapix_application_error");
    expect(result.effect.backend_evidence.position_observation).toBe("outside_tolerance");
    expect(result.effect.backend_evidence.restore_verified).toBeTrue();
    expect(backend.counters().presetDispatches).toBe(1);
    expect(backend.counters().restoreDispatches).toBe(1);
    const observations = await new AppendOnlyWitnessLog(witnessPath).entries();
    expect(observations.filter((entry) => entry.action_bearing)).toHaveLength(2);
    expect(observations.filter((entry) => entry.response_line.includes("401")).every((entry) => !entry.action_bearing)).toBeTrue();
    expect(JSON.stringify(observations)).not.toContain(password);
  });

  test("refuses PTZ before transport when exclusive control is not asserted", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vapix-exclusive-"));
    const backend = new MockVapixBackend({
      username: "operator", password: "test", realm: "test", presetBackendName: "p", streamBackendProfile: "s",
      model: "mock", firmware: "mock", serial: "mock", baseline: { pan: 0, tilt: 0, zoom: 1 }, safePreset: { pan: 1, tilt: 1, zoom: 1 }, settlingReads: 1,
    });
    const witnessPath = join(root, "witness.jsonl");
    const adapter = new VapixAdapter({
      targets: {
        "ptz-primary": { baseUrl: "http://mock-vapix.invalid", username: "operator", credentialReference: "camera" },
        "fixed-primary": { baseUrl: "http://mock-vapix.invalid", username: "operator", credentialReference: "camera" },
      }, witnessProxyUrl: "http://witness.invalid", presetMappings: { "gate5-safe": "p" },
      presetPositions: { "gate5-safe": { pan: 1, tilt: 1, zoom: 1 } }, streamProfileMappings: { test: "s" },
      positionTolerance: { pan: 0, tilt: 0, zoom: 0 }, pollIntervalMs: 1, settlingDeadlineMs: 100, requestTimeoutMs: 100,
      streamMinimumPayloadBytes: 4, exclusiveControl: false, recoveryDirectory: join(root, "recovery"),
    }, {
      credentials: { async get(reference) { return { reference, secret: "test" }; } },
      httpTransport: new InMemoryWitnessTransport(backend, witnessPath),
    });
    const command = buildCommandManifest({
      actionName: "camera.ptz.preset", targetId: id16("exclusive-target"), targetLogicalName: "ptz-primary",
      parameters: { preset_name: "gate5-safe" }, invocationId: id16("exclusive-invocation"),
    }, adapter.id, adapter.version);
    await expect(adapter.dispatch(command, {
      invocationIdHex: toHex(id16("exclusive-invocation")), commandDigestHex: toHex(command.command_digest), witnessLogPath: witnessPath, observedAt: 1_800_000_000,
    })).rejects.toThrow("exclusive-control");
    expect(await new AppendOnlyWitnessLog(witnessPath).entries()).toHaveLength(0);
  });

  test("latches dispatch across a transient first settling-poll failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vapix-poll-failure-"));
    const backend = new MockVapixBackend(testMockConfig());
    backend.setFaultMode("settling-poll-transport-error");
    const { adapter, witnessPath } = testAdapter(root, backend);
    const invocationId = id16("poll-failure-invocation");
    const keys = await generateDemoKeys(join(root, "keys"));
    const journal = new DurableInvocationJournal(join(root, "journal.jsonl"));
    const result = await produce({
      scenarioId: "S6", evaluatedAt: 8_100_000, epochId: 3101,
      invocationId, correlationId: id16("poll-failure-correlation"), tenantId: id16("tenant"), siteId: id16("site"), targetId: id16("target"),
      targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset", parameters: { preset_name: "gate5-safe" },
      delegationWindows: [{ notBefore: 8_099_000, notAfter: 8_101_000 }],
      bundlePath: join(root, "S6.cbor"), trustPolicyPath: join(root, "S6.policy.json"), witnessLogPath: witnessPath,
      journal, anchorLog: new LocalRfc6962Log(join(root, "anchor.jsonl")), adapter, keys,
    });
    expect(result.dispatchCount).toBe(1);
    expect(result.dispatchResult?.dispatched).toBeTrue();
    expect(result.dispatchResult?.effect.outcome_level).toBe("unknown");
    expect(result.wire.receipts.map((receipt) => receipt.kind)).toContain("dispatch");
    expect(backend.counters().presetDispatches).toBe(1);
  });

  test("repairs stale authentication for an action without redispatching it", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vapix-stale-action-"));
    const backend = new MockVapixBackend(testMockConfig());
    backend.rotateNonceOnNext("action");
    const { adapter, witnessPath } = testAdapter(root, backend);
    const invocationId = id16("stale-action-invocation");
    const command = buildCommandManifest({
      actionName: "camera.ptz.preset", targetId: id16("stale-action-target"), targetLogicalName: "ptz-primary",
      parameters: { preset_name: "gate5-safe" }, invocationId,
    }, adapter.id, adapter.version);
    const result = await adapter.dispatch(command, {
      invocationIdHex: toHex(invocationId), commandDigestHex: toHex(command.command_digest), witnessLogPath: witnessPath, observedAt: 1_800_000_000,
    });
    expect(result.effect.outcome_level).toBe("device_acknowledged");
    expect(backend.counters().presetDispatches).toBe(1);
    const action = (await new AppendOnlyWitnessLog(witnessPath).entries())
      .filter((entry) => entry.action_bearing && entry.command_digest === toHex(command.command_digest));
    expect(action).toHaveLength(2);
    expect(action[0]!.response_line).toContain(" 401 ");
    expect(action[0]!.request_line).toBe(action[1]!.request_line);
  });

  test("repairs stale authentication for a position poll", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vapix-stale-poll-"));
    const backend = new MockVapixBackend(testMockConfig());
    backend.rotateNonceOnNext("poll");
    const { adapter, witnessPath } = testAdapter(root, backend);
    const invocationId = id16("stale-poll-invocation");
    const command = buildCommandManifest({
      actionName: "camera.ptz.preset", targetId: id16("stale-poll-target"), targetLogicalName: "ptz-primary",
      parameters: { preset_name: "gate5-safe" }, invocationId,
    }, adapter.id, adapter.version);
    const result = await adapter.dispatch(command, {
      invocationIdHex: toHex(invocationId), commandDigestHex: toHex(command.command_digest), witnessLogPath: witnessPath, observedAt: 1_800_000_000,
    });
    expect(result.effect.outcome_level).toBe("device_acknowledged");
    const pollFailures = (await new AppendOnlyWitnessLog(witnessPath).entries())
      .filter((entry) => !entry.action_bearing && entry.request_line.includes("query=<sanitized>") && entry.response_line.includes(" 401 "));
    expect(pollFailures).toHaveLength(2);
    expect(backend.counters().presetDispatches).toBe(1);
  });

  test("receipts and journals a baseline-unavailable refusal without dispatch", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-vapix-baseline-refusal-"));
    const backend = new MockVapixBackend(testMockConfig());
    backend.setFaultMode("position-unavailable");
    const { adapter, witnessPath } = testAdapter(root, backend);
    const invocationId = id16("baseline-refusal-invocation");
    const keys = await generateDemoKeys(join(root, "keys"));
    const journal = new DurableInvocationJournal(join(root, "journal.jsonl"));
    const result = await produce({
      scenarioId: "S6", evaluatedAt: 8_200_000, epochId: 3102,
      invocationId, correlationId: id16("baseline-refusal-correlation"), tenantId: id16("tenant"), siteId: id16("site"), targetId: id16("target"),
      targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset", parameters: { preset_name: "gate5-safe" },
      delegationWindows: [{ notBefore: 8_199_000, notAfter: 8_201_000 }],
      bundlePath: join(root, "refusal.cbor"), trustPolicyPath: join(root, "refusal.policy.json"), witnessLogPath: witnessPath,
      journal, anchorLog: new LocalRfc6962Log(join(root, "anchor.jsonl")), adapter, keys,
    });
    expect(result.dispatchCount).toBe(0);
    expect(result.dispatchResult?.dispatched).toBeFalse();
    expect(result.wire.receipts.map((receipt) => receipt.kind)).toEqual(["observation", "inference", "authorization", "action_attempt"]);
    expect((result.wire.receipts.at(-1)!.fields.body as Record<string, unknown>).disposition).toBe("not_dispatched");
    expect(await journal.mustNotRedispatch(toHex(invocationId))).toBeFalse();
    expect((await new AppendOnlyWitnessLog(witnessPath).entries()).filter((entry) => entry.action_bearing)).toHaveLength(0);
  });
});
