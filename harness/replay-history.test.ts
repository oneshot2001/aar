// D-87 history class (c): every supplied replay entry is compared, not only the first or the
// last. rp-replay-two-entries pins [other, own]; this pins the mirror [own, other] in the
// harness, the pyref library and the pyref CLI.
import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fromHex } from "./cbor";
import { verifyBundle } from "./verifier";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const AT = 1_735_689_800;

test("replay state [own digest, ff..ff] for a one-time receipt's coordinate is replay/one-time-reused at step 20 everywhere", () => {
  const rp = join(root, "kats", "relying-party");
  const bundle = readFileSync(join(rp, "rp-replay-two-entries.cbor"));
  const [, own] = JSON.parse(readFileSync(join(rp, "rp-replay-two-entries.replay.json"), "utf8")).entries as Record<string, string>[];
  const entries = [own!, { ...own!, content_digest: "ff".repeat(32) }]; // strictly sorted: the own digest is below ff..ff
  const harness = verifyBundle(bundle, { evaluationTime: AT, replayState: entries.map((entry) => ({ replayDomain: fromHex(entry.replay_domain!), invocationId: fromHex(entry.invocation_id!), contentDigest: fromHex(entry.content_digest!) })) });
  expect(harness.ok ? null : [harness.reason, harness.step]).toEqual(["replay/one-time-reused", 20]);
  const directory = mkdtempSync(join(tmpdir(), "aar-d87-replay-"));
  try {
    const path = join(directory, "bundle.cbor"); const state = join(directory, "prior.json");
    writeFileSync(path, bundle); writeFileSync(state, JSON.stringify({ entries }));
    const library = Bun.spawnSync(["python3", "-B", "-c", `
import json, sys
from pyref.kat_inputs import replay_bytes
from pyref.verifier import evaluate
r = evaluate(open(sys.argv[1], "rb").read(), evaluated_at=${AT}, replay_state=replay_bytes(json.load(open(sys.argv[2]))))
print(r.reason, r.step)
`, path, state], { cwd: root });
    expect(library.stdout.toString().trim()).toBe("replay/one-time-reused 20");
    const cli = Bun.spawnSync(["python3", "-B", "-m", "pyref", "verify", path, "--at", String(AT), "--prior-state", state], { cwd: root });
    expect(cli.exitCode).toBe(1);
    expect(cli.stdout.toString()).toContain("First failure: step 20 (replay/one-time-reused)");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}, 60_000);
