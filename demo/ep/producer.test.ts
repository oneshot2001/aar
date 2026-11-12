import { existsSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import type { DemoAdapter } from "../../adapters/shared/types";
import { decodeCbor, encodeCbor, equalBytes, toHex, type CborValue } from "../../harness/cbor";
import { hash, id16 } from "../../harness/crypto";
import { LocalRfc6962Log } from "../anchor/log";
import { generateDemoKeys } from "../keys/keys";
import { DurableInvocationJournal } from "./journal";
import { produce } from "./producer";

test("resume after persisted dispatch intent never redispatches and emits unknown", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-producer-resume-"));
  const keys = await generateDemoKeys(join(root, "keys"));
  const invocationId = id16("resume-invocation");
  const journal = new DurableInvocationJournal(join(root, "journal.jsonl"));
  await journal.append({ invocation_id: toHex(invocationId), at: 8_100_000, event: "dispatch_intent_persisted", data: { command_digest: "00".repeat(32) } });
  let calls = 0;
  const adapter: DemoAdapter = {
    id: "vapix-stub", version: "test",
    async dispatch() { calls += 1; throw new Error("must not dispatch on resume"); },
  };
  const result = await produce({
    scenarioId: "S5", evaluatedAt: 8_100_000, epochId: 2001,
    invocationId, correlationId: id16("resume-correlation"), tenantId: id16("tenant"), siteId: id16("site"), targetId: id16("target"),
    targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset", parameters: { preset_name: "gate5-safe" },
    delegationWindows: [{ notBefore: 8_099_000, notAfter: 8_101_000 }],
    bundlePath: join(root, "S5.cbor"), trustPolicyPath: join(root, "S5.policy.json"), witnessLogPath: join(root, "witness.jsonl"),
    journal, anchorLog: new LocalRfc6962Log(join(root, "anchor.jsonl")), adapter, keys,
  });
  expect(calls).toBe(0);
  expect(result.resumedWithoutRedispatch).toBeTrue();
  expect(result.dispatchResult?.effect.outcome_level).toBe("unknown");
});

const malformedCredentials: readonly (readonly [string, CborValue[]])[] = [
  ["element 0 not a bstr", [7, new Uint8Array()]],
  ["element 0 not CBOR", [Uint8Array.of(0xff), new Uint8Array()]],
  ["no bstr credential_id", [encodeCbor({ other: 1 }), new Uint8Array()]],
];

for (const [shape, credentialEnvelope] of malformedCredentials) {
  test(`malformed mediator credential is dropped and the bundle is still emitted: ${shape}`, async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-producer-credential-"));
    const keys = await generateDemoKeys(join(root, "keys"));
    const invocationId = id16(`credential-invocation:${shape}`);
    const journal = new DurableInvocationJournal(join(root, "journal.jsonl"));
    const adapter: DemoAdapter = {
      id: "vapix-stub", version: "test",
      async dispatch(_command, context) {
        return {
          dispatched: true, status: 200, responseBodyDigest: hash(new Uint8Array()),
          effect: {
            adapter_id: "vapix-stub", invocation_id: context.invocationIdHex, command_digest: context.commandDigestHex,
            target_logical_name: "ptz-primary", observed_at: context.observedAt, state: "consistent", outcome_level: "device_acknowledged",
            observation_digest: "11".repeat(32), backend_evidence: {},
          },
          mediatorCountersignature: { envelope: [Uint8Array.of(1), Uint8Array.of(2)], credentialEnvelope },
        };
      },
    };
    const bundlePath = join(root, "S1.cbor");
    await produce({
      scenarioId: "S1", evaluatedAt: 8_100_000, epochId: 2001,
      invocationId, correlationId: id16("credential-correlation"), tenantId: id16("tenant"), siteId: id16("site"), targetId: id16("target"),
      targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset", parameters: { preset_name: "gate5-safe" },
      delegationWindows: [{ notBefore: 8_099_000, notAfter: 8_101_000 }],
      bundlePath, trustPolicyPath: join(root, "S1.policy.json"), witnessLogPath: join(root, "witness.jsonl"),
      journal, anchorLog: new LocalRfc6962Log(join(root, "anchor.jsonl")), adapter, keys,
    });
    expect((await journal.records(toHex(invocationId))).at(-1)?.event).toBe("bundle_emitted");
    const artifacts = (decodeCbor(new Uint8Array(await readFile(bundlePath))) as { artifacts: { mediator_countersignatures: CborValue[]; credentials: CborValue[] } }).artifacts;
    expect(artifacts.mediator_countersignatures).toEqual([[Uint8Array.of(1), Uint8Array.of(2)]]);
    const offered = encodeCbor(credentialEnvelope);
    expect(artifacts.credentials.some((entry) => equalBytes(encodeCbor(entry), offered))).toBeFalse();
  });
}

type ProduceOverrides = {
  readonly adapterId?: string;
  readonly adapterVersion?: string;
  readonly presetName?: string;
  readonly sourceDeviceMetadata?: { readonly manufacturer: string; readonly model: string; readonly firmware: string };
  readonly refuseWith?: string;
};

async function produceWith(name: string, overrides: ProduceOverrides) {
  const root = await mkdtemp(join(tmpdir(), "aar-producer-bounds-"));
  const keys = await generateDemoKeys(join(root, "keys"));
  const invocationId = id16(`bounds-invocation:${name}`);
  const journal = new DurableInvocationJournal(join(root, "journal.jsonl"));
  let dispatchCalls = 0;
  const adapter = {
    id: overrides.adapterId ?? "vapix-stub", version: overrides.adapterVersion ?? "test",
    async dispatch(_command, context) {
      dispatchCalls += 1;
      const refused = overrides.refuseWith !== undefined;
      return {
        dispatched: !refused, status: refused ? 0 : 200, responseBodyDigest: hash(new Uint8Array()),
        effect: {
          adapter_id: "vapix-stub", invocation_id: context.invocationIdHex, command_digest: context.commandDigestHex,
          target_logical_name: "ptz-primary", observed_at: context.observedAt,
          state: refused ? "unknown" : "consistent", outcome_level: refused ? "unknown" : "device_acknowledged",
          observation_digest: "11".repeat(32), backend_evidence: refused ? { application_status: overrides.refuseWith! } : {},
        },
      };
    },
  } as DemoAdapter;
  const bundlePath = join(root, "S1.cbor");
  const run = produce({
    scenarioId: "S1", evaluatedAt: 8_100_000, epochId: 2001,
    invocationId, correlationId: id16("bounds-correlation"), tenantId: id16("tenant"), siteId: id16("site"), targetId: id16("target"),
    targetLogicalName: "ptz-primary", actionName: "camera.ptz.preset", parameters: { preset_name: overrides.presetName ?? "gate5-safe" },
    sourceDeviceMetadata: overrides.sourceDeviceMetadata,
    delegationWindows: [{ notBefore: 8_099_000, notAfter: 8_101_000 }],
    bundlePath, trustPolicyPath: join(root, "S1.policy.json"), witnessLogPath: join(root, "witness.jsonl"),
    journal, anchorLog: new LocalRfc6962Log(join(root, "anchor.jsonl")), adapter, keys,
  });
  const receiptBody = async (kind: string) => {
    const bundle = decodeCbor(new Uint8Array(await readFile(bundlePath))) as { artifacts: { receipts: CborValue[][] } };
    const receipts = bundle.artifacts.receipts.map((envelope) => decodeCbor(envelope[0] as Uint8Array) as { kind: string; body: Record<string, CborValue> });
    return receipts.find((receipt) => receipt.kind === kind)!.body;
  };
  return { run, journal, invocationId, bundlePath, receiptBody, dispatchCalls: () => dispatchCalls };
}

const device = { manufacturer: "AXIS", model: "Gate5 synthetic", firmware: "D1-stub" };
const e65 = "é".repeat(65);
const e64 = "é".repeat(64);

const outOfBounds: readonly (readonly [string, ProduceOverrides])[] = [
  ["empty firmware", { sourceDeviceMetadata: { ...device, firmware: "" } }],
  ["129-byte firmware", { sourceDeviceMetadata: { ...device, firmware: "f".repeat(129) } }],
  ["firmware é×65", { sourceDeviceMetadata: { ...device, firmware: e65 } }],
  ["model é×65", { sourceDeviceMetadata: { ...device, model: e65 } }],
  ["manufacturer é×65", { sourceDeviceMetadata: { ...device, manufacturer: e65 } }],
  ["adapter version é×65", { adapterVersion: e65 }],
  ["123-byte adapter id", { adapterId: `${"a".repeat(118)}-stub` }],
  ["70 KB parameters_cbor", { presetName: "x".repeat(70_000) }],
  ["canonical_command 65537 bytes", { presetName: "x".repeat(65_378) }],
];

for (const [name, overrides] of outOfBounds) {
  test(`out-of-bounds producer input is refused before the journal is touched: ${name}`, async () => {
    const h = await produceWith(name, overrides);
    await expect(h.run).rejects.toThrow();
    expect(await h.journal.records()).toEqual([]);
    expect(existsSync(h.bundlePath)).toBeFalse();
    expect(h.dispatchCalls()).toBe(0);
  });
}

const inBounds: readonly (readonly [string, ProduceOverrides, ((h: Awaited<ReturnType<typeof produceWith>>) => Promise<void>) | undefined])[] = [
  ["firmware é×64", { sourceDeviceMetadata: { ...device, firmware: e64 } }, async (h) => { expect(((await h.receiptBody("observation")).source_device as Record<string, CborValue>).firmware).toBe(e64); }],
  ["model é×64", { sourceDeviceMetadata: { ...device, model: e64 } }, async (h) => { expect(((await h.receiptBody("observation")).source_device as Record<string, CborValue>).model).toBe(e64); }],
  ["manufacturer é×64", { sourceDeviceMetadata: { ...device, manufacturer: e64 } }, async (h) => { expect(((await h.receiptBody("observation")).source_device as Record<string, CborValue>).manufacturer).toBe(e64); }],
  ["adapter version é×64", { adapterVersion: e64 }, async (h) => { expect(((await h.receiptBody("action_attempt")).command as Record<string, CborValue>).adapter_version).toBe(e64); }],
  ["122-byte adapter id", { adapterId: `${"a".repeat(117)}-stub` }, undefined],
  ["canonical_command exactly 65536 bytes", { presetName: "x".repeat(65_377) }, async (h) => { expect((((await h.receiptBody("action_attempt")).command as Record<string, CborValue>).canonical_command as Uint8Array).length).toBe(65_536); }],
];

for (const [name, overrides, check] of inBounds) {
  test(`in-bounds producer input at the limit is accepted: ${name}`, async () => {
    const h = await produceWith(name, overrides);
    await h.run;
    expect((await h.journal.records(toHex(h.invocationId))).at(-1)?.event).toBe("bundle_emitted");
    await check?.(h);
  }, 30_000);
}

const refusalReasons: readonly (readonly [string, string, string])[] = [
  ["0 bytes", "", "adapter-refused-before-transport"],
  ["129 bytes", "r".repeat(129), "adapter-refused-before-transport"],
  ["é×65", e65, "adapter-refused-before-transport"],
  ["128 bytes", "r".repeat(128), "r".repeat(128)],
  ["é×64", e64, e64],
];

for (const [name, status, signed] of refusalReasons) {
  test(`adapter refusal reason outside the bounded-text range is signed as the default reason: ${name}`, async () => {
    const h = await produceWith(`refusal:${name}`, { refuseWith: status });
    await h.run;
    expect((await h.receiptBody("action_attempt")).refusal_reason).toBe(signed);
    const observed = (await h.journal.records(toHex(h.invocationId))).find((record) => record.event === "pre_transport_refusal_observed");
    expect(observed?.data).toEqual({ reason: signed });
  });
}
