// L2 reference emitter — shared machinery.
// CANDIDATE WIRE (D-62/D-63, unratified): payloads use draft content types and
// are NOT v0.2-conformant AAR receipts. This emitter exists to make the L2
// vantage point concrete and to generate candidate fixtures for ratification.
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { encodeCbor, decodeCbor, toHex, fromHex, strictUtf8, type CborValue } from "../../harness/cbor";
import { mkdirSync, readFileSync, writeFileSync, appendFileSync, existsSync, renameSync, openSync, closeSync } from "node:fs";
import { join } from "node:path";
import { Database } from "bun:sqlite";

export const RECEIPT_CONTENT_TYPE = "application/aar-l2-receipt+cbor;v=0.3-draft";
export const CLOSE_CONTENT_TYPE = "application/aar-session-close+cbor;v=0.3-draft";
export const PROMPT_CONTENT_TYPE = "application/aar-l2-prompt+cbor;v=0.3-draft";

export const BASE_DIR = join(process.env.AAR_L2_DIR ?? join(process.env.HOME ?? "", ".aar-l2"));

// Fixed demo coordinates, same posture as the demo-EP: an L2 recorder on a
// developer machine has no tenant/site authority — these are disclosed
// placeholders, not claims.
export const TENANT_ID = sha256(new TextEncoder().encode("AAR-L2-DEMO-TENANT")).slice(0, 16);
export const SITE_ID = sha256(new TextEncoder().encode("AAR-L2-DEMO-SITE")).slice(0, 16);

const SPKI_PREFIX = fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

export interface RecorderKey {
  privateKey: Uint8Array;
  spki: Uint8Array;
  kid: Uint8Array;
}

// Runs fn while holding an exclusive SQLite transaction on <dir>/lock.db. The
// operating system holds the file lock and releases it when the process dies,
// so there is no stale lock to reclaim. No wait cap: the hook timeout bounds
// the wait.
export function withLock<T>(dir: string, fn: () => T): T {
  const path = join(dir, "lock.db");
  // Create privately before SQLite opens it; an existing database keeps its mode.
  closeSync(openSync(path, "a", 0o600));
  const db = new Database(path);
  try {
    while (true) {
      try {
        db.run("BEGIN EXCLUSIVE");
        break;
      } catch (error) {
        if ((error as { code?: string }).code !== "SQLITE_BUSY") throw error;
        Bun.sleepSync(10);
      }
    }
    let result: T;
    try {
      result = fn();
    } catch (error) {
      // fn's own error is the one to report, whatever the rollback does.
      try {
        db.run("ROLLBACK");
      } catch {}
      throw error;
    }
    db.run("COMMIT");
    return result;
  } finally {
    db.close();
  }
}

// Writes under a temporary name and renames it into place, so a kill
// mid-write never leaves a partial file at the final path.
export function writeFileAtomic(path: string, data: string | Uint8Array, mode = 0o600): void {
  const tmpPath = `${path}.${process.pid}.tmp`;
  writeFileSync(tmpPath, data, { mode });
  renameSync(tmpPath, path);
}

function recorderKey(privateKey: Uint8Array): RecorderKey {
  const publicKey = p256.getPublicKey(privateKey, false);
  const spki = new Uint8Array(SPKI_PREFIX.length + publicKey.length);
  spki.set(SPKI_PREFIX);
  spki.set(publicKey, SPKI_PREFIX.length);
  return { privateKey, spki, kid: sha256(spki) };
}

export function loadOrCreateRecorderKey(): RecorderKey {
  mkdirSync(BASE_DIR, { recursive: true, mode: 0o700 });
  const keyPath = join(BASE_DIR, "recorder.key");
  const pubPath = join(BASE_DIR, "recorder.pub");
  const readKey = (): Uint8Array => fromHex(readFileSync(keyPath, "utf8").trim());
  // Both files are renamed into place whole, so once both exist the pair is
  // read without the lock.
  if (existsSync(keyPath) && existsSync(pubPath)) return recorderKey(readKey());
  // Otherwise under the base lock: concurrent first use creates exactly one
  // key pair. The private key is the completion marker: a new pair publishes
  // the public key first, so a private key on disk always has its public key.
  return withLock(BASE_DIR, () => {
    const created = !existsSync(keyPath);
    // recorderKey rejects the (astronomically unlikely) out-of-range scalar
    // rather than reduce, before anything is written.
    const key = recorderKey(created ? crypto.getRandomValues(new Uint8Array(32)) : readKey());
    const pubHex = toHex(key.spki) + "\n";
    if (!existsSync(pubPath) || readFileSync(pubPath, "utf8") !== pubHex) writeFileAtomic(pubPath, pubHex);
    if (created) writeFileAtomic(keyPath, toHex(key.privateKey) + "\n", 0o600);
    return key;
  });
}

export function sessionDir(sessionId16: Uint8Array): string {
  const dir = join(BASE_DIR, "sessions", toHex(sessionId16));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function sessionId16(rawSessionId: string): Uint8Array {
  return sha256(new TextEncoder().encode(rawSessionId)).slice(0, 16);
}

// A string's well-formed form: each lone UTF-16 surrogate becomes U+FFFD, as
// the UTF-8 encoder (and so the CBOR encoder) would write it. A string that is
// not its own well-formed form would be signed as a different string.
export function toWellFormed(text: string): string {
  return strictUtf8.decode(new TextEncoder().encode(text));
}

export function isWellFormed(text: string): boolean {
  return toWellFormed(text) === text;
}

// A hook input value usable as a text field: a non-empty, well-formed string.
export function isText(value: unknown): value is string {
  return typeof value === "string" && value !== "" && isWellFormed(value);
}

// The commitment a prompt entry carries in place of the prompt text. The
// 32-byte opening stays off the chain: whoever holds it can test guesses.
export function promptCommitment(opening: Uint8Array, prompt: string): Uint8Array {
  return sha256(encodeCbor(["AAR-L2-PROMPT-COMMITMENT-v1", opening, prompt]));
}

// One line appended to a file whose current content is `existing`: a final
// line left without its newline must not merge with the new one.
function framedLine(existing: string, line: string): string {
  return (existing.length > 0 && !existing.endsWith("\n") ? "\n" : "") + line + "\n";
}

// Appends one signed, hash-chained entry to the session log, under the session
// lock: close check, chain head, sign, append, state.json. On a closed session
// nothing is appended and `droppedLine` goes to the session errors.log.
// `buildFields` returns the entry's own payload fields and is called only
// after the close check. `afterAppend` runs last, still under the lock.
export function appendEntry(
  key: RecorderKey, sid: Uint8Array, contentType: string, droppedLine: string,
  buildFields: () => [string, CborValue][], afterAppend?: () => void,
): void {
  const dir = sessionDir(sid);
  const receiptsPath = join(dir, "receipts.hexl");
  const statePath = join(dir, "state.json");

  withLock(dir, () => {
    if (existsSync(join(dir, "close.hex"))) {
      // D-63: a closed session is never re-opened or re-closed. Entries after
      // close would be unverifiable; record the starvation visibly instead.
      appendFileSync(join(dir, "errors.log"), droppedLine + "\n", { mode: 0o600 });
      return;
    }

    // Continue from the log: its head is the payload-bstr digest (the signed
    // bytes, per D-63) of its last line. A last line that is not an envelope
    // throws: nothing is appended after a torn line.
    const log = existsSync(receiptsPath) ? readFileSync(receiptsPath, "utf8") : "";
    const lines = log.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
    const lastPayload = lines.length > 0 ? payloadOf(lines.at(-1)!) : undefined;
    let prevDigest = lastPayload ? toHex(sha256(lastPayload)) : "";
    // seq is the larger of the last line's own seq plus one and the next seq
    // recorded in state.json; the line count stands in when the last line's
    // seq cannot be read. So losing lines or state.json does not make the
    // recorder sign a number again or count backwards.
    let seq = lines.length;
    try {
      const lastSeq = lastPayload && (decodeCbor(lastPayload) as Record<string, CborValue>).seq;
      if (typeof lastSeq === "number") seq = lastSeq + 1;
    } catch {}
    const state = existsSync(statePath)
      ? JSON.parse(readFileSync(statePath, "utf8")) as { seq: number; prevDigest: string; openedAt?: unknown }
      : undefined;
    if (state) {
      seq = Math.max(seq, state.seq);
      if (!logContainsHead(lines, state.prevDigest)) {
        // Entries were lost or the log is a different chain: chain from the
        // recorded head, so the verifier reports the break.
        prevDigest = state.prevDigest;
        appendFileSync(join(dir, "errors.log"), "receipt log does not contain the recorded chain head\n", { mode: 0o600 });
      }
    }
    // openedAt: the recorded value; now for the first entry of a new session;
    // left out after a lost state.json (the close then takes opened_at from
    // the earliest receipt).
    const openedAt = typeof state?.openedAt === "number" ? state.openedAt
      : !state && lines.length === 0 ? Math.floor(Date.now() / 1000) : undefined;

    const payload = new Map<string, CborValue>([
      ["v", 3],
      ["session_id", sid],
      ["tenant_id", TENANT_ID],
      ["site_id", SITE_ID],
      ["seq", seq],
      ["session_prev_digest", prevDigest === "" ? null : fromHex(prevDigest)],
      ["attestation", new Map<string, CborValue>([
        ["point", "harness_hook"],
        ["recorder_kid", key.kid],
        // No agent credential exists at the Claude Code hook boundary; per the
        // D-62 candidate this entry ranks as undeclared for self-report purposes.
        ["agent_kid", null],
      ])],
      ["committed_at", Math.floor(Date.now() / 1000)],
      ...buildFields(),
    ]);

    const line = toHex(signEnvelope(payload, contentType, key));
    appendFileSync(receiptsPath, framedLine(log, line), { mode: 0o600 });
    // Always rewritten, so checkpointing resumes after a lost state.json.
    writeFileAtomic(statePath, JSON.stringify({ seq: seq + 1, prevDigest: toHex(sha256(payloadOf(line))), openedAt }));
    afterAppend?.();
  });
}

// The payload bstr of a receipt line; throws unless the line is an envelope
// (a two-element array, byte string first).
function payloadOf(line: string): Uint8Array {
  const envelope = decodeCbor(fromHex(line));
  if (!Array.isArray(envelope) || envelope.length !== 2 || !(envelope[0] instanceof Uint8Array)) {
    throw new Error("receipt line is not an envelope");
  }
  return envelope[0];
}

// The log contains the recorded head when some line's payload digest equals it
// and every later line links to the line before it. Searched backwards: the
// log may be any number of entries ahead of state.json. A line that cannot be
// decoded does not match.
function logContainsHead(lines: string[], head: string): boolean {
  try {
    for (let i = lines.length - 1; i >= 0; i--) {
      const payloadBytes = payloadOf(lines[i]!);
      if (toHex(sha256(payloadBytes)) === head) return true;
      const prev = (decodeCbor(payloadBytes) as Record<string, CborValue>).session_prev_digest;
      if (i === 0 || !(prev instanceof Uint8Array) || toHex(prev) !== toHex(sha256(payloadOf(lines[i - 1]!)))) return false;
    }
  } catch {}
  return false;
}

export function signEnvelope(payload: CborValue, contentType: string, key: RecorderKey): Uint8Array {
  const protectedMap = new Map<number, CborValue>([[1, -7], [3, contentType], [4, key.kid]]);
  const protectedBytes = encodeCbor(protectedMap);
  const payloadBytes = encodeCbor(payload);
  const sigStructure = encodeCbor(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
  const signature = p256.sign(sha256(sigStructure), key.privateKey, {
    prehash: false, lowS: true, format: "compact", extraEntropy: false,
  });
  return encodeCbor([payloadBytes, encodeCbor([protectedBytes, new Map(), null, signature])]);
}

export interface OpenedEnvelope {
  payloadBytes: Uint8Array;
  payload: CborValue;
  contentType: CborValue;
  kidMatchesSpki: boolean;
  signatureValid: boolean;
}

export function openEnvelope(envelopeBytes: Uint8Array, spki: Uint8Array): OpenedEnvelope {
  const envelope = decodeCbor(envelopeBytes) as CborValue[];
  const payloadBytes = envelope[0] as Uint8Array;
  const cose = decodeCbor(envelope[1] as Uint8Array) as CborValue[];
  const protectedBytes = cose[0] as Uint8Array;
  const signature = cose[3] as Uint8Array;
  const sigStructure = encodeCbor(["Signature1", protectedBytes, new Uint8Array(), payloadBytes]);
  const publicKey = spki.slice(SPKI_PREFIX.length);
  let signatureValid = false;
  try {
    signatureValid = p256.verify(signature, sha256(sigStructure), publicKey, {
      prehash: false, lowS: true, format: "compact",
    });
  } catch {
    signatureValid = false;
  }
  const protectedMap = decodeCbor(protectedBytes) as Map<CborValue, CborValue>;
  const kidValue = protectedMap instanceof Map ? protectedMap.get(4) : undefined;
  const expectedKid = sha256(spki);
  const kidMatchesSpki = kidValue instanceof Uint8Array && kidValue.length === expectedKid.length
    && kidValue.every((b, i) => b === expectedKid[i]);
  return {
    payloadBytes,
    payload: decodeCbor(payloadBytes),
    contentType: protectedMap instanceof Map ? (protectedMap.get(3) as CborValue) : null,
    kidMatchesSpki,
    signatureValid,
  };
}

export function readHexLines(path: string): Uint8Array[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((l) => l.trim().length > 0).map(fromHex);
}

export { sha256, encodeCbor, decodeCbor, toHex, fromHex };
export type { CborValue };
