import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

export interface HygieneSweepOptions {
  readonly canary: string;
  readonly roots: readonly string[];
  readonly digestUsername?: string;
  readonly digestRealm?: string;
}

export interface HygieneHit {
  readonly path: string;
  readonly transform: string;
}

const SKIP_DIRECTORIES = new Set([".git", "node_modules", "__pycache__"]);

function md5(value: string): string {
  return createHash("md5").update(value, "utf8").digest("hex");
}

export function canaryTransforms(options: Pick<HygieneSweepOptions, "canary" | "digestUsername" | "digestRealm">): ReadonlyMap<string, Uint8Array> {
  if (!options.canary) throw new Error("canary must be non-empty");
  const values = new Map<string, string>([
    ["literal", options.canary],
    ["base64", Buffer.from(options.canary, "utf8").toString("base64")],
    ["percent_encoded", encodeURIComponent(options.canary)],
    ["md5_literal", md5(options.canary)],
  ]);
  if (options.digestUsername !== undefined && options.digestRealm !== undefined) {
    values.set("digest_ha1", md5(`${options.digestUsername}:${options.digestRealm}:${options.canary}`));
  }
  return new Map([...values].map(([name, value]) => [name, new TextEncoder().encode(value)]));
}

async function filesUnder(path: string): Promise<string[]> {
  const info = await stat(path);
  if (info.isFile()) return [path];
  if (!info.isDirectory()) return [];
  const entries = await readdir(path, { withFileTypes: true });
  const nested = await Promise.all(entries
    .filter((entry) => !(entry.isDirectory() && SKIP_DIRECTORIES.has(entry.name)))
    .map((entry) => filesUnder(resolve(path, entry.name))));
  return nested.flat();
}

export async function sweepCanary(options: HygieneSweepOptions): Promise<HygieneHit[]> {
  const transforms = canaryTransforms(options);
  const roots = [...new Set(options.roots.map((root) => resolve(root)))];
  const fileGroups = await Promise.all(roots.map(async (root) => {
    try { return await filesUnder(root); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }));
  const hits: HygieneHit[] = [];
  for (const path of [...new Set(fileGroups.flat())]) {
    const contents = new Uint8Array(await readFile(path));
    for (const [name, needle] of transforms) {
      if (Buffer.from(contents).indexOf(needle) >= 0) hits.push({ path, transform: name });
    }
  }
  return hits;
}

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}

function repeated(name: string): string[] {
  return process.argv.flatMap((value, index) => value === name && process.argv[index + 1] ? [process.argv[index + 1]!] : []);
}

if (import.meta.main) {
  const canary = option("--canary");
  if (!canary) throw new Error("usage: bun run demo/hygiene-sweep.ts --canary VALUE [--username U --realm R] [--root PATH ...]");
  const roots = repeated("--root");
  const hits = await sweepCanary({ canary, roots: roots.length ? roots : [process.cwd()], digestUsername: option("--username"), digestRealm: option("--realm") });
  if (hits.length) {
    for (const hit of hits) console.error(`${hit.transform}: ${hit.path}`);
    process.exitCode = 1;
  } else {
    console.log(`secret hygiene sweep clean across ${roots.length || 1} root(s)`);
  }
}
