import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { id16 } from "../../harness/crypto";
import { buildCommandManifest } from "../ep/command-manifest";
import { AppendOnlyWitnessLog } from "../witness/log";
import { createVapixStub } from "./stub";

test("synthetic adapter emits one witness-bound dispatch", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-adapter-"));
  const witnessLogPath = join(root, "witness.jsonl");
  const adapter = createVapixStub();
  const command = buildCommandManifest({ actionName: "camera.ptz.preset", targetId: id16("target"), targetLogicalName: "ptz-primary", parameters: { preset_name: "gate5-safe" }, invocationId: id16("invocation") }, adapter.id, adapter.version);
  const result = await adapter.dispatch(command, { invocationIdHex: "aa".repeat(16), commandDigestHex: Buffer.from(command.command_digest).toString("hex"), witnessLogPath, observedAt: 10 });
  expect(result.effect.outcome_level).toBe("device_acknowledged");
  expect(await new AppendOnlyWitnessLog(witnessLogPath).attributableDispatches("aa".repeat(16))).toHaveLength(1);
});
