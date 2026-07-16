import { mkdir, open, readFile } from "node:fs/promises";
import { dirname } from "node:path";

export type JournalEvent =
  | "request_signed"
  | "authorization_evaluated"
  | "dispatch_intent_persisted"
  | "dispatch_observed"
  | "refusal_persisted"
  | "bundle_emitted";

export interface JournalRecord {
  readonly version: 1;
  readonly invocation_id: string;
  readonly at: number;
  readonly event: JournalEvent;
  readonly data: Readonly<Record<string, string | number | boolean | null>>;
}

export class DurableInvocationJournal {
  constructor(readonly path: string) {}

  async append(record: Omit<JournalRecord, "version">): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const handle = await open(this.path, "a", 0o600);
    try {
      await handle.write(`${JSON.stringify({ version: 1, ...record })}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  async records(invocationId?: string): Promise<JournalRecord[]> {
    let source: string;
    try {
      source = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    return source.split("\n").filter(Boolean).map((line) => JSON.parse(line) as JournalRecord)
      .filter((record) => invocationId === undefined || record.invocation_id === invocationId);
  }

  async mustNotRedispatch(invocationId: string): Promise<boolean> {
    return (await this.records(invocationId)).some((record) =>
      record.event === "dispatch_intent_persisted" || record.event === "dispatch_observed");
  }
}
