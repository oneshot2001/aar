import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { DurableInvocationJournal } from "./journal";

test("journal fsync point prevents redispatch on resume", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-journal-"));
  const journal = new DurableInvocationJournal(join(root, "invocations.jsonl"));
  await journal.append({ invocation_id: "00".repeat(16), at: 1, event: "dispatch_intent_persisted", data: { command_digest: "11".repeat(32) } });
  expect(await journal.mustNotRedispatch("00".repeat(16))).toBeTrue();
});

test("pre-transport refusal closes a dispatch intent", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-journal-refusal-"));
  const journal = new DurableInvocationJournal(join(root, "invocations.jsonl"));
  const invocationId = "22".repeat(16);
  await journal.append({ invocation_id: invocationId, at: 1, event: "dispatch_intent_persisted", data: { command_digest: "33".repeat(32) } });
  await journal.append({ invocation_id: invocationId, at: 2, event: "pre_transport_refusal_observed", data: { reason: "baseline_position_unavailable" } });
  expect(await journal.mustNotRedispatch(invocationId)).toBeFalse();
});
