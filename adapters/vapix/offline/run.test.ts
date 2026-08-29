import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { runOfflineSuite } from "./run";

test("D2a S1-S7 run through VAPIX, witness, oracle, and pyref", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-vapix-offline-test-"));
  const result = await runOfflineSuite(root);
  expect(result.hygieneHits).toBe(0);
  expect(result.scenarios).toHaveLength(8);
  expect(result.scenarios.map((item) => [item.scenario, item.verification, item.outcome])).toEqual([
    ["S1", "conformant", "device_acknowledged"],
    ["S2", "conformant", "device_acknowledged"],
    ["S3", "conformant", "not_dispatched"],
    ["S7", "conformant", "not_dispatched"],
    ["S4", "nonconformant", "device_acknowledged"],
    ["S5", "conformant", "unknown"],
    ["S6-rejection", "conformant", "contradicted"],
    ["S6-after-send-timeout", "conformant", "unknown"],
  ]);
  expect(result.scenarios.every((item) => item.oracle === "PASS")).toBeTrue();
}, 30_000);
