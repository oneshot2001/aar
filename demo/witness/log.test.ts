import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { AppendOnlyWitnessLog } from "./log";

test("witness distinguishes challenge traffic from attributable dispatch", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-witness-"));
  const log = new AppendOnlyWitnessLog(join(root, "witness.jsonl"));
  const common = { timestamp: "2026-01-01T00:00:00.000Z", invocation_id: "aa".repeat(16), command_digest: "bb".repeat(32), request_body_sha256: "00".repeat(32), response_body_sha256: "00".repeat(32) };
  await log.append({ ...common, action_bearing: false, request_line: "GET /challenge HTTP/1.1", response_line: "HTTP/1.1 401 Unauthorized" });
  await log.append({ ...common, action_bearing: true, request_line: "GET /command HTTP/1.1", response_line: "HTTP/1.1 204 No Content" });
  expect(await log.attributableDispatches(common.invocation_id)).toHaveLength(1);
});
