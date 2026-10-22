// pyref batch transport (Packet D, Stage B): spawns `python3 -B -m pyref.batch`,
// checks its handshake against this checkout, sends NDJSON requests in chunks
// under a per-chunk deadline, and checks one response per request, in order,
// with the input digest echoed back. Every check failure is an AdapterError.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fromHex, toHex } from "./cbor";
import { hash } from "./crypto";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SOURCES = ["pyref/verifier.py", "pyref/cbor.py", "pyref/relying_party.py", "pyref/verdict.py", "pyref/batch.py"];

export interface Inputs {
  evaluated_at: number;
  prior_state: unknown | null;
  replay_state: unknown | null;
  policy: string | null;
  signing_key: string | null;
  trust_policy: string | null;
}
export interface Identity { product: string; version: string; build_digest: string; config_digest: string }
export interface BatchRequest { id: string; bundle_hex: string | null; context_hex: string | null; inputs: Inputs; identity: Identity }
export type Site = [file: string, line: number, code: string, step: number | null];
export interface Verdict { result: string; reason: string | null; step: number | null; verdict_hex: string }
export type BatchResponse =
  | ({ id: string; input_sha256: string; sites?: Site[] } & Verdict)
  | { id: string; input_sha256: string; crash: { type: string; message: string }; sites?: Site[] }
  | { id?: string; protocol_error: string };
export interface Handshake {
  hello: 1; python: string; checkout: string; hash_seed: string | null;
  sources: Record<string, string>; identity: Identity;
}

export class AdapterError extends Error {}

export const sha256Hex = (bytes: Uint8Array): string => toHex(hash(bytes));
export const sourceDigests = (): Record<string, string> => Object.fromEntries(SOURCES.map((name) => [name, sha256Hex(readFileSync(join(root, name)))]));

// Pure response check for one chunk: count, JSON, id order, protocol errors, input digest echo.
export function checkChunk(requests: readonly BatchRequest[], lines: readonly string[]): BatchResponse[] {
  if (lines.length !== requests.length) throw new AdapterError(`expected ${requests.length} responses, read ${lines.length}`);
  return requests.map((request, index) => {
    let response: BatchResponse;
    try { response = JSON.parse(lines[index]!) as BatchResponse; } catch { throw new AdapterError(`response ${index} is not JSON: ${lines[index]!.slice(0, 120)}`); }
    if ("protocol_error" in response) throw new AdapterError(`protocol error on ${request.id}: ${response.protocol_error}`);
    if (response.id !== request.id) throw new AdapterError(`response ${index} answers ${response.id}, expected ${request.id}`);
    const expected = sha256Hex(request.bundle_hex === null ? new Uint8Array() : fromHex(request.bundle_hex));
    if (response.input_sha256 !== expected) throw new AdapterError(`${request.id}: input digest echo ${response.input_sha256} differs from ${expected}`);
    return response;
  });
}

export interface BatchOptions { premises?: boolean; chunk?: number; deadlineMs?: number; env?: Record<string, string> }

export class PyrefBatch {
  readonly chunk: number;
  readonly deadlineMs: number;
  sent = 0;
  stderr = "";
  private buffer = "";
  private readonly decoder = new TextDecoder();
  private readonly stdin: { write(data: string): number; flush(): void; end(): void };
  private constructor(private readonly proc: ReturnType<typeof Bun.spawn>, private readonly reader: ReadableStreamDefaultReader<Uint8Array>, readonly handshake: Handshake, options: BatchOptions) {
    this.chunk = options.chunk ?? 250;
    this.deadlineMs = options.deadlineMs ?? 300_000;
    this.stdin = proc.stdin as unknown as PyrefBatch["stdin"];
  }

  static async start(options: BatchOptions = {}): Promise<PyrefBatch> {
    const proc = Bun.spawn(["python3", "-B", "-m", "pyref.batch", ...(options.premises ? ["--premises"] : [])], {
      cwd: root, stdin: "pipe", stdout: "pipe", stderr: "pipe", env: { ...process.env, PYTHONHASHSEED: "0", ...options.env },
    });
    const batch = new PyrefBatch(proc, proc.stdout.getReader(), undefined as unknown as Handshake, options);
    void batch.drainStderr(proc.stderr.getReader());
    const line = await batch.readLine(30_000);
    if (line === null) throw new AdapterError(`pyref batch exited before its handshake: ${batch.stderr}`);
    const handshake = JSON.parse(line) as Handshake;
    const expected = sourceDigests();
    if (handshake.hello !== 1) throw new AdapterError("handshake is not hello 1");
    if (handshake.checkout !== join(root, "pyref")) throw new AdapterError(`pyref checkout ${handshake.checkout} is not ${join(root, "pyref")}`);
    for (const name of SOURCES) if (handshake.sources[name] !== expected[name]) throw new AdapterError(`${name}: pyref sha256 ${handshake.sources[name]} differs from the driver's ${expected[name]}`);
    (batch as { handshake: Handshake }).handshake = handshake;
    return batch;
  }

  private async drainStderr(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      this.stderr += this.decoder.decode(value);
    }
  }

  // One stdout line, or null at EOF; a deadline kills the batch.
  private async readLine(deadlineMs: number): Promise<string | null> {
    const started = Date.now();
    for (;;) {
      const newline = this.buffer.indexOf("\n");
      if (newline >= 0) { const line = this.buffer.slice(0, newline); this.buffer = this.buffer.slice(newline + 1); return line; }
      const remaining = deadlineMs - (Date.now() - started);
      if (remaining <= 0) { this.proc.kill(); throw new AdapterError(`pyref batch produced no line within ${deadlineMs} ms; stderr: ${this.stderr}`); }
      const timer = new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), remaining));
      const read = await Promise.race([this.reader.read(), timer]);
      if (read === "timeout") { this.proc.kill(); throw new AdapterError(`pyref batch produced no line within ${deadlineMs} ms; stderr: ${this.stderr}`); }
      if (read.done) { if (this.buffer.length === 0) return null; const line = this.buffer; this.buffer = ""; return line; }
      this.buffer += this.decoder.decode(read.value, { stream: true });
    }
  }

  // Write raw lines, read exactly as many response lines (the deadline covers the whole exchange).
  async exchange(lines: readonly string[]): Promise<string[]> {
    this.stdin.write(lines.map((line) => `${line}\n`).join(""));
    this.stdin.flush();
    this.sent += lines.length;
    const responses: string[] = [];
    for (let index = 0; index < lines.length; index += 1) {
      const line = await this.readLine(this.deadlineMs);
      if (line === null) throw new AdapterError(`pyref batch closed stdout after ${responses.length} of ${lines.length} responses; stderr: ${this.stderr}`);
      responses.push(line);
    }
    return responses;
  }

  async run(requests: readonly BatchRequest[]): Promise<BatchResponse[]> {
    const out: BatchResponse[] = [];
    for (let start = 0; start < requests.length; start += this.chunk) {
      const slice = requests.slice(start, start + this.chunk);
      out.push(...checkChunk(slice, await this.exchange(slice.map((request) => JSON.stringify(request)))));
    }
    return out;
  }

  // EOF, then the done count must equal every line sent (well-formed or not).
  async close(): Promise<number> {
    this.stdin.end();
    const line = await this.readLine(this.deadlineMs);
    const done = line === null ? undefined : (JSON.parse(line) as { done?: number }).done;
    if (done !== this.sent) { this.proc.kill(); throw new AdapterError(`pyref batch reported done=${done}, driver sent ${this.sent}`); }
    await this.proc.exited;
    return done;
  }
}
