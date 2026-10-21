import { expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

// Source files stay at or under LIMIT bytes. Files already over it are pinned in
// size-baseline.json at their exact size and may only shrink (see CONTRIBUTING.md).
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const LIMIT = 20_000;
const SCOPE = ["harness", "pyref", "demo", "adapters", "scripts"];
const GENERATED = ["demo/results"];
const RECIPE = "extract a cohesive responsibility behind a narrow interface, mirror it in the other implementation, preserve behaviour, update imports, run the cross-implementation suites, and lower the baseline";

function* sourceFiles(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    const file = relative(root, path);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "kats" || entry.name.startsWith(".") || GENERATED.includes(file)) continue;
      yield* sourceFiles(path);
    } else if (/\.(ts|py)$/u.test(entry.name) && !entry.name.endsWith(".d.ts") && !entry.name.includes(".generated.")) {
      yield file;
    }
  }
}

test("every source file is at or under the size ratchet", () => {
  const baseline = JSON.parse(readFileSync(join(root, "harness", "size-baseline.json"), "utf8")) as Record<string, number>;
  const failures: string[] = [];
  for (const dir of SCOPE) {
    for (const file of sourceFiles(join(root, dir))) {
      const size = statSync(join(root, file)).size;
      const pinned = baseline[file];
      if (pinned === undefined) {
        if (size > LIMIT) failures.push(`${file} is ${size} bytes, over the ${LIMIT}-byte limit: ${RECIPE}`);
      } else if (size > pinned) {
        failures.push(`${file} is ${size} bytes, over its ${pinned}-byte baseline: ${RECIPE}`);
      } else if (size < pinned) {
        failures.push(`${file} is ${size} bytes, under its ${pinned}-byte baseline: lower the baseline in this commit`);
      }
    }
  }
  expect(failures.join("\n")).toBe("");
});
