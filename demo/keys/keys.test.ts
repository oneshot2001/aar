import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { DEMO_KEY_ROLES, generateDemoKeys, loadDemoKeys } from "./keys";

describe("demo key generation", () => {
  test("writes distinct P-256 roles and reloads them", async () => {
    const root = await mkdtemp(join(tmpdir(), "aar-demo-keys-"));
    const privateDirectory = join(root, "keys");
    const publicOutput = join(root, "public.json");
    const generated = await generateDemoKeys(privateDirectory, publicOutput);
    const loaded = await loadDemoKeys(privateDirectory);
    expect(new Set(DEMO_KEY_ROLES.map((role) => Buffer.from(generated[role].kid).toString("hex"))).size).toBe(DEMO_KEY_ROLES.length);
    expect(Buffer.from(loaded.ep.kid).equals(Buffer.from(generated.ep.kid))).toBeTrue();
    expect((await stat(join(privateDirectory, "agent.private.json"))).mode & 0o777).toBe(0o600);
    expect((await readFile(publicOutput, "utf8")).includes("private_key")).toBeFalse();
  });
});
