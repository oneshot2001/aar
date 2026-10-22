// Transport deadline (fix-first D): one absolute deadline per exchange. Three
// simulated slow responses that jointly exceed the budget must throw, even
// though each arrives well inside it (Codex's reproduction passed in 98 ms
// against a 50 ms budget; it must fail now).
import { expect, test } from "bun:test";
import { AdapterError, PyrefBatch, ProcessLike } from "./difffuzz-pyref";

function slowProcess(lines: readonly string[], gapMs: number): ProcessLike {
  const encoder = new TextEncoder();
  const stdout = new ReadableStream<Uint8Array>({
    start(controller) {
      lines.forEach((line, index) => setTimeout(() => { controller.enqueue(encoder.encode(`${line}\n`)); if (index === lines.length - 1) controller.close(); }, gapMs * (index + 1)));
    },
  });
  return { stdin: { write: () => 0, flush: () => undefined, end: () => undefined }, stdout, stderr: new ReadableStream<Uint8Array>({ start(controller) { controller.close(); } }), kill: () => undefined, exited: Promise.resolve(0) };
}

test("three 30 ms responses against a 50 ms exchange deadline throw AdapterError", async () => {
  const batch = PyrefBatch.fromProcess(slowProcess(["a", "b", "c"], 30), { deadlineMs: 50 });
  const started = Date.now();
  await expect(batch.exchange(["1", "2", "3"])).rejects.toBeInstanceOf(AdapterError);
  expect(Date.now() - started).toBeLessThan(90);
});

test("the same three responses inside a 500 ms deadline are read in order", async () => {
  const batch = PyrefBatch.fromProcess(slowProcess(["a", "b", "c"], 30), { deadlineMs: 500 });
  expect(await batch.exchange(["1", "2", "3"])).toEqual(["a", "b", "c"]);
});
