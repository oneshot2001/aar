import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { fromHex } from "../../harness/cbor";
import { rfc6962Leaf, verifyRfc6962Inclusion } from "../../harness/merkle";
import { LocalRfc6962Log } from "./log";

test("local anchor log appends and proves RFC 6962 leaves", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-anchor-"));
  const log = new LocalRfc6962Log(join(root, "anchor.jsonl"));
  await log.append(new TextEncoder().encode("one"), 1);
  const second = await log.append(new TextEncoder().encode("two"), 2);
  const proof = await log.inclusionProof(0);
  expect(verifyRfc6962Inclusion(rfc6962Leaf(new TextEncoder().encode("one")), 0, 2, proof, fromHex(second.root))).toBeTrue();
});
