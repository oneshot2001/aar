import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import type { DemoAdapter } from "../../adapters/shared/types";
import { id16 } from "../../harness/crypto";
import { toHex } from "../../harness/cbor";
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
