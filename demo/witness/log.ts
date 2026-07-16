import { mkdir, open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { WitnessObservation } from "../../adapters/shared/types";

export class AppendOnlyWitnessLog {
  constructor(readonly path: string) {}

  async append(observation: WitnessObservation): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const handle = await open(this.path, "a", 0o600);
    try {
      await handle.write(`${JSON.stringify(observation)}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  async entries(): Promise<WitnessObservation[]> {
    let source: string;
    try {
      source = await readFile(this.path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    return source.split("\n").filter(Boolean).map((line) => JSON.parse(line) as WitnessObservation);
  }

  async attributableDispatches(invocationId: string): Promise<WitnessObservation[]> {
    return (await this.entries()).filter((entry) => entry.invocation_id === invocationId && entry.action_bearing);
  }
}
