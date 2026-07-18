import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { runVmsOfflineSuite } from "./run";

test("D3 S1-S4+S6 run through EP, witness, VMS mediator mock, oracle, and pyref", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-vms-offline-test-"));
  const result = await runVmsOfflineSuite(root);
  expect(result.hygieneHits).toBe(0);
  expect(result.scenarios).toHaveLength(6);
  expect(result.scenarios.map((item) => [item.scenario, item.verification, item.outcome])).toEqual([
    ["S1", "conformant", "device_acknowledged"],
    ["S2", "conformant", "device_acknowledged"],
    ["S3", "conformant", "not_dispatched"],
    ["S4", "nonconformant", "device_acknowledged"],
    ["S6-rejection", "conformant", "contradicted"],
    ["S6-after-send-timeout", "conformant", "unknown"],
  ]);
  expect(result.scenarios.every((item) => item.oracle === "PASS")).toBeTrue();
  // Every device effect went through the mediator; the mock's counters show
  // the F19 shape: S1/S4/S6-r/S6-t preset dispatches + S1/S4/S6-t restores.
  expect(result.mediatorCounters.presetDispatches).toBeGreaterThanOrEqual(4);
  expect(result.mediatorCounters.restoreDispatches).toBeGreaterThanOrEqual(3);
  expect(result.mediatorCounters.streamDispatches).toBe(1);
}, 60_000);
