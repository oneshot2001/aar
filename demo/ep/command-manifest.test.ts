import { expect, test } from "bun:test";
import { id16 } from "../../harness/crypto";
import { buildCommandManifest } from "./command-manifest";

test("command manifest is built from secret-free logical data", () => {
  const command = buildCommandManifest({
    actionName: "camera.ptz.preset",
    targetId: id16("demo-target"),
    targetLogicalName: "ptz-primary",
    parameters: { preset_name: "gate5-safe" },
    invocationId: id16("demo-invocation"),
  }, "vapix-stub", "0.1.0");
  expect(command.excluded_fields).toEqual([{ name: "authorization", reason: "injected_only_at_transport" }]);
  expect(JSON.stringify(command)).not.toContain("password");
  expect(command.command_digest.length).toBe(32);
});
