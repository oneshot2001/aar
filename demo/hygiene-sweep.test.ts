import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { canaryTransforms, sweepCanary } from "./hygiene-sweep";

test("hygiene sweep detects literal and transformed canaries", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-hygiene-"));
  const transforms = canaryTransforms({ canary: "p@ss word", digestUsername: "user", digestRealm: "realm" });
  expect(transforms.has("digest_ha1_sha256")).toBeTrue();
  await writeFile(join(root, "capture.log"), Buffer.from(transforms.get("digest_ha1")!));
  const hits = await sweepCanary({ canary: "p@ss word", roots: [root], digestUsername: "user", digestRealm: "realm" });
  expect(hits).toEqual([{ path: join(root, "capture.log"), transform: "digest_ha1" }]);
});

test("hashOnlyRoots skips reversible transforms so short literals do not false-match committed text", async () => {
  const artifactRoot = await mkdtemp(join(tmpdir(), "aar-hyg-artifact-"));
  const repoRoot = await mkdtemp(join(tmpdir(), "aar-hyg-repo-"));
  const secret = "ab12"; // 4-char literal, like the real camera password
  // Committed tree contains the 4-char literal by coincidence (common substring)
  // AND, hypothetically, a hashed form (a real leak signal).
  await writeFile(join(repoRoot, "spec.md"), "deadbeefab1234567890"); // literal substring present
  await writeFile(join(repoRoot, "leak.log"), Buffer.from(canaryTransforms({ canary: secret }).get("sha256_literal")!));
  // Generated artifact tree accidentally contains the literal secret (a real leak).
  await writeFile(join(artifactRoot, "bundle.txt"), `token=${secret}`);
  const hits = await sweepCanary({ canary: secret, roots: [artifactRoot], hashOnlyRoots: [repoRoot] });
  const paths = hits.map((hit) => `${hit.transform}:${hit.path.split("/").pop()}`).sort();
  // Reversible transforms caught in the artifact tree; sha256 caught in the
  // committed tree; the coincidental 4-char literal in spec.md is NOT reported.
  expect(paths).toEqual(["literal:bundle.txt", "percent_encoded:bundle.txt", "sha256_literal:leak.log"]);
});
