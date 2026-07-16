import { mkdir, open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fromHex, toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";
import { rfc6962InclusionProof, rfc6962Leaf, rfc6962RootFromDigests } from "../../harness/merkle";

export interface AnchorLogEntry {
  readonly version: 1;
  readonly leaf_index: number;
  readonly input_digest: string;
  readonly leaf_digest: string;
  readonly tree_size: number;
  readonly root: string;
  readonly appended_at: number;
}

export class LocalRfc6962Log {
  constructor(readonly path: string) {}

  async entries(): Promise<AnchorLogEntry[]> {
    let source: string;
    try {
      source = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    return source.split("\n").filter(Boolean).map((line) => JSON.parse(line) as AnchorLogEntry);
  }

  async append(input: Uint8Array, appendedAt: number): Promise<AnchorLogEntry> {
    const prior = await this.entries();
    const leaves = [...prior.map((entry) => fromHex(entry.leaf_digest)), rfc6962Leaf(input)];
    const entry: AnchorLogEntry = {
      version: 1,
      leaf_index: prior.length,
      input_digest: toHex(hash(input)),
      leaf_digest: toHex(leaves.at(-1)!),
      tree_size: leaves.length,
      root: toHex(rfc6962RootFromDigests(leaves)),
      appended_at: appendedAt,
    };
    await mkdir(dirname(this.path), { recursive: true });
    const handle = await open(this.path, "a", 0o600);
    try {
      await handle.write(`${JSON.stringify(entry)}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
    return entry;
  }

  async inclusionProof(index: number): Promise<Uint8Array[]> {
    const leaves = (await this.entries()).map((entry) => fromHex(entry.leaf_digest));
    return rfc6962InclusionProof(leaves, index);
  }
}
