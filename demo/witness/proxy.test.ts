import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { createWitnessProxy } from "./proxy";

test("witness proxy is constructible without opening a test network socket", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-proxy-"));
  const server = createWitnessProxy(join(root, "witness.jsonl"));
  expect(server.listening).toBeFalse();
});
