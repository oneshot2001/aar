// D5 release gate: the external CDDL schema oracle (pyref/schema_kat.py) must
// pass. A missing or mismatched engine is a failure, never a skip.
import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

test("CDDL schema oracle accepts the corpus and matches every probe", () => {
  const run = spawnSync("python3", ["-B", "-m", "pyref.schema_kat"], {
    cwd: join(dirname(fileURLToPath(import.meta.url)), ".."), encoding: "utf8",
  });
  expect(run.status, `${run.stdout}${run.stderr}`).toBe(0);
}, 600_000);
