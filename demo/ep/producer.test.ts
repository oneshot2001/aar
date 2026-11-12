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
