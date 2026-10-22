// Stage B gate: the pyref batch transport round-trips corpus rows with the
// harness's own verdict under the same identity, survives a malformed line,
// and reports an escaping exception as a crash response.
import { expect, test } from "bun:test";
import { toHex } from "./cbor";
import { AdapterError, BatchRequest, PyrefBatch, checkChunk, sourceDigests } from "./difffuzz-pyref";
import { harnessVerdict, loadSeeds } from "./difffuzz-seeds";

test("batch handshake, 20-row round-trip, malformed line, crash shape, done count", async () => {
  const batch = await PyrefBatch.start();
  expect(batch.handshake.sources).toEqual(sourceDigests());
  expect(batch.handshake.hash_seed).toBe("0");
  const identity = batch.handshake.identity;

  const seeds = loadSeeds();
  expect(seeds.length).toBeGreaterThanOrEqual(500);
  const sample = seeds.filter((_, index) => index % 25 === 0).slice(0, 20);
  expect(sample).toHaveLength(20);
  const requests: BatchRequest[] = sample.map((seed, index) => ({ id: `row-${index}`, bundle_hex: toHex(seed.bundle), context_hex: null, inputs: seed.inputs, identity }));
  const responses = await batch.run(requests);
  for (const [index, response] of responses.entries()) {
    const seed = sample[index]!;
    expect("crash" in response, seed.path).toBe(false);
    if (!("result" in response)) continue;
    const ts = harnessVerdict(seed.bundle, seed.options, identity);
    expect({ result: response.result, reason: response.reason, step: response.step, verdict_hex: response.verdict_hex }, seed.path).toEqual(ts);
  }

  // A malformed request line is a protocol_error response, and the batch keeps serving.
  const [malformed] = await batch.exchange(["{not json"]);
  expect(JSON.parse(malformed!)).toHaveProperty("protocol_error");
  const again = await batch.run([requests[0]!]);
  expect("result" in again[0]!).toBe(true);

  // Well-formed request whose bundle is null: evaluate() raises, so the response is a crash.
  const [crash] = await batch.run([{ ...requests[0]!, id: "crash-0", bundle_hex: null }]);
  expect("crash" in crash! && crash.crash.type).toBe("TypeError");

  expect(await batch.close()).toBe(23);

  // The response checker rejects a dropped, duplicated and malformed line.
  const lines = responses.slice(0, 3).map((response) => JSON.stringify(response));
  const three = requests.slice(0, 3);
  expect(() => checkChunk(three, lines.slice(0, 2))).toThrow(AdapterError);
  expect(() => checkChunk(three, [lines[0]!, lines[0]!, lines[2]!])).toThrow(AdapterError);
  expect(() => checkChunk(three, [lines[0]!, "garbage", lines[2]!])).toThrow(AdapterError);
}, 180_000);
