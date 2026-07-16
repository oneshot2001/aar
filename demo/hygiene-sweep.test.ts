import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { canaryTransforms, sweepCanary } from "./hygiene-sweep";

test("hygiene sweep detects literal and transformed canaries", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-hygiene-"));
  const transforms = canaryTransforms({ canary: "p@ss word", digestUsername: "user", digestRealm: "realm" });
  await writeFile(join(root, "capture.log"), Buffer.from(transforms.get("digest_ha1")!));
  const hits = await sweepCanary({ canary: "p@ss word", roots: [root], digestUsername: "user", digestRealm: "realm" });
  expect(hits).toEqual([{ path: join(root, "capture.log"), transform: "digest_ha1" }]);
});
