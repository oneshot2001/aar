// Offline session verifier for the L2 candidate wire. Implements the D-63
// evaluation: signatures, the six chain checks (successor uniqueness — the
// walk MUST be a function), coordinate agreement, and single-close. On an
// intact session it also reports the prompt entries: which tool receipts are
// bound to an earlier prompt entry in the chain walk, and whether the local
// prompts.jsonl reproduces each entry's commitment. Every entry payload is
// checked against its kind's closed field list before any other use; evidence
// that cannot be read or decoded is a reason code, never a thrown error.
// Usage: bun run verify.ts [--json] <session-dir> <recorder-spki-hex-file> <session-id-hex>
// The expected session id is a REQUIRED input: a verifier that infers the
// session from the evidence it is checking can be replayed a genuine close
// from a different session (round-2 P1). Exit 0 = intact; exit 1 = reason code.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  openEnvelope, promptCommitment, isWellFormed, sha256, toHex, fromHex,
  RECEIPT_CONTENT_TYPE, PROMPT_CONTENT_TYPE, CLOSE_CONTENT_TYPE, type CborValue,
} from "./lib";

type Receipt = Record<string, CborValue>;
const get = (m: CborValue, k: string): CborValue => (m as Receipt)[k] as CborValue;

const args = process.argv.slice(2);
const json = args.includes("--json");
// Only evaluated checks are reported; verification still stops at the first failure.
const chainChecks: { name: string; pass: boolean }[] = [];
// Set only once every check has passed: a session that fails reports no
// prompt, binding or prompt-text counts.
let promptReport: Record<string, unknown> = {};
function report(ok: boolean, message: string): void {
  console.log(json ? JSON.stringify({
    ok, receipts: receiptEnvs?.length ?? 0, chain_checks: chainChecks, close_present: (closeEnvs?.length ?? 0) > 0, ...promptReport,
  }) : message);
}

// A decoded value in a diagnostic: a number as itself, anything else as the
// name of its type. Coercing a decoded value to text can throw.
function typeOrNumber(v: CborValue | undefined): string {
  if (typeof v === "number") return `${v}`;
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (v instanceof Uint8Array) return "bytes";
  return typeof v === "object" ? "map" : typeof v;
}

function fail(code: string, detail: string): never {
  report(false, `nonconformant ${code} — ${detail}`);
  process.exit(1);
}

function chainCheck(name: string, pass: boolean, detail: string): void {
  chainChecks.push({ name, pass });
  if (!pass) fail("session/chain-broken", detail);
}

const [dir, spkiFile, expectedSidHex] = args.filter((arg) => arg !== "--json");
if (!dir || !spkiFile || !/^[0-9a-f]{32}$/.test(expectedSidHex ?? "")) {
  console.error("usage: verify.ts [--json] <session-dir> <recorder-spki-hex-file> <session-id-hex (32 hex chars)>");
  process.exit(2);
}
const spki = fromHex(readFileSync(spkiFile, "utf8").trim());

// A file's lines, [] when it does not exist, undefined when it exists and
// cannot be read (no permission, a directory) or is not valid UTF-8. The
// decoding is strict: a lenient one would repair invalid bytes to U+FFFD
// and let them pass for text.
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function readLines(path: string): string[] | undefined {
  if (!existsSync(path)) return [];
  try {
    return strictUtf8.decode(readFileSync(path)).split("\n");
  } catch {
    return undefined;
  }
}
// Non-blank lines as bytes; a line that is not hex stays undefined.
const hexLines = (path: string): (Uint8Array | undefined)[] | undefined =>
  readLines(path)?.filter((l) => l.trim().length > 0).map((l) => {
    try {
      return fromHex(l);
    } catch {
      return undefined;
    }
  });

// Field checks. `undefined` is an absent field.
type Check = (v: CborValue | undefined) => boolean;
const isMap = (v: CborValue | undefined): v is Receipt =>
  typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof Uint8Array) && !(v instanceof Map);
const bytes = (length: number): Check => (v) => v instanceof Uint8Array && v.length === length;
const integer: Check = (v) => typeof v === "number" && Number.isInteger(v);
const text: Check = (v) => typeof v === "string" && v !== "";
const absentOr = (check: Check): Check => (v) => v === undefined || check(v);
// The first violation of a closed field list, or undefined when the map conforms.
function shapeError(payload: CborValue | undefined, shape: Record<string, Check>): string | undefined {
  if (!isMap(payload)) return "not a map";
  const unknown = Object.keys(payload).find((field) => !Object.hasOwn(shape, field));
  if (unknown !== undefined) return `unknown field ${JSON.stringify(unknown)}`;
  const bad = Object.keys(shape).find((field) => !shape[field]!(payload[field]));
  return bad === undefined ? undefined : `field ${bad} missing or malformed`;
}
const COMMON: Record<string, Check> = {
  v: (v) => v === 3,
  seq: (v) => integer(v) && (v as number) >= 0,
  committed_at: integer,
  session_id: bytes(16),
  tenant_id: bytes(16),
  site_id: bytes(16),
  session_prev_digest: (v) => v === null || bytes(32)(v),
  attestation: (v) => shapeError(v, {
    point: (p) => typeof p === "string",
    recorder_kid: bytes(32),
    agent_kid: (k) => k === null || k instanceof Uint8Array,
  }) === undefined,
};
const RECEIPT_SHAPE: Record<string, Check> = {
  ...COMMON,
  tool_name: text,
  input_digest: bytes(32),
  response_digest: absentOr(bytes(32)),
  error_digest: absentOr(bytes(32)),
  prompt_id: absentOr(text),
  tool_use_id: absentOr(text),
  hook_event_name: absentOr(text),
};
const PROMPT_SHAPE: Record<string, Check> = {
  ...COMMON,
  prompt_id: text,
  prompt_commitment: bytes(32),
  hook_source: absentOr((v) => typeof v === "string"),
};

const receiptEnvs = hexLines(join(dir, "receipts.hexl"));
const closeEnvs = hexLines(join(dir, "close.hex"));
if (!receiptEnvs) fail("cose/receipt-signature", "receipts.hexl: unreadable");
if (!closeEnvs) fail("cose/close-signature", "close.hex: unreadable");
if (closeEnvs.length === 0) {
  report(false, `no session-close — completeness not_established (${receiptEnvs.length} receipt(s) present)`);
  process.exit(1);
}
if (closeEnvs.length > 1) fail("session/duplicate-close", `${closeEnvs.length} close records`);

const openedReceipts = receiptEnvs.map((env, i) => {
  let opened: ReturnType<typeof openEnvelope>;
  try {
    if (!env) throw new Error("not hex");
    opened = openEnvelope(env, spki);
  } catch {
    fail("cose/receipt-signature", `receipt index ${i}: undecodable`);
  }
  if (!opened.signatureValid) fail("cose/receipt-signature", `receipt index ${i}`);
  if (!opened.kidMatchesSpki) fail("cose/receipt-signature", `receipt index ${i}: kid does not match spki`);
  const isPrompt = opened.contentType === PROMPT_CONTENT_TYPE;
  if (!isPrompt && opened.contentType !== RECEIPT_CONTENT_TYPE) fail("session/fields-inconsistent", `receipt index ${i}: wrong content type`);
  const kind = isPrompt ? "prompt entry" : "receipt";
  const error = shapeError(opened.payload, isPrompt ? PROMPT_SHAPE : RECEIPT_SHAPE);
  if (error) fail("session/fields-inconsistent", `${kind} index ${i}: ${error}`);
  const payload = opened.payload as Receipt;
  // A tool receipt carries exactly one result digest: error_digest on a
  // PostToolUseFailure receipt, response_digest on every other.
  const failed = payload.hook_event_name === "PostToolUseFailure";
  if (!isPrompt && ((payload.error_digest !== undefined) !== failed || (payload.response_digest !== undefined) === failed))
    fail("session/fields-inconsistent", `${kind} index ${i}: response_digest and error_digest do not fit hook_event_name`);
  return { payload, digest: sha256(opened.payloadBytes), isPrompt };
});
let openedClose: ReturnType<typeof openEnvelope>;
try {
  if (!closeEnvs[0]) throw new Error("not hex");
  openedClose = openEnvelope(closeEnvs[0], spki);
} catch {
  fail("cose/close-signature", "session-close: undecodable");
}
if (!openedClose.signatureValid) fail("cose/close-signature", "session-close");
if (!openedClose.kidMatchesSpki) fail("cose/close-signature", "close kid does not match spki");
if (openedClose.contentType !== CLOSE_CONTENT_TYPE) fail("session/fields-inconsistent", "close has wrong content type");
// The close fields the checks below read as bytes; the rest are validated where used.
if (!isMap(openedClose.payload)) fail("session/fields-inconsistent", "close: not a map");
const close = openedClose.payload;
for (const [field, check] of Object.entries({ tenant_id: bytes(16), site_id: bytes(16), recorder_kid: bytes(32) })) {
  if (!check(close[field])) fail("session/fields-inconsistent", `close: field ${field} missing or malformed`);
}

const hex = (v: CborValue): string => toHex(v as Uint8Array);

// Bind the close to the session the caller asked about: a genuine close
// replayed from a different session fails here (round-2 P1).
const closeSid = get(close, "session_id");
if (!(closeSid instanceof Uint8Array) || toHex(closeSid) !== expectedSidHex)
  fail("session/close-coordinate-mismatch", "close session_id does not match the requested session");

// Malformed fields are disagreements, never skips (D-60 discipline): validate
// close field shapes BEFORE any branch keys off them.
const itemCountRaw = get(close, "item_count");
if (typeof itemCountRaw !== "number" || !Number.isInteger(itemCountRaw) || itemCountRaw < 0 || itemCountRaw > 10000)
  fail("session/fields-inconsistent", `item_count not an integer in [0,10000]: ${typeOrNumber(itemCountRaw)}`);
const itemCount = itemCountRaw;
for (const f of ["opened_at", "closed_at"]) {
  const v = get(close, f);
  if (typeof v !== "number" || !Number.isInteger(v)) fail("session/fields-inconsistent", `${f} not an integer`);
}
const firstDigest = get(close, "first_receipt_digest");
const finalDigest = get(close, "final_chain_digest");
if (itemCount === 0 && (firstDigest !== null || finalDigest !== null))
  fail("session/fields-inconsistent", "item_count 0 with non-nil endpoint digest");
if (itemCount > 0 && (!(firstDigest instanceof Uint8Array) || !(finalDigest instanceof Uint8Array)))
  fail("session/fields-inconsistent", "item_count > 0 with nil/malformed endpoint digest");

// Chain checks (1)-(6), in the D-63 order. `walk` is the entries in chain
// order, from genesis along the digest links.
const walk: typeof openedReceipts = [];
const genesis = openedReceipts.filter((r) => get(r.payload, "session_prev_digest") === null);
chainCheck("genesis", itemCount > 0 ? genesis.length === 1 : openedReceipts.length === 0,
  itemCount > 0 ? `genesis count ${genesis.length}` : "receipts present under empty close");

if (itemCount > 0) {
  chainCheck("first_receipt_digest", hex(get(close, "first_receipt_digest")) === toHex(genesis[0]!.digest),
    "first_receipt_digest does not match genesis");
  const byDigest = new Map(openedReceipts.map((r) => [toHex(r.digest), r]));
  const successors = new Map<string, number>();
  for (const r of openedReceipts) {
    const prev = get(r.payload, "session_prev_digest");
    if (prev === null) continue;
    const prevHex = hex(prev);
    successors.set(prevHex, (successors.get(prevHex) ?? 0) + 1);
    if ((successors.get(prevHex) ?? 0) > 1) chainCheck("successor_uniqueness", false, `fork at ${prevHex.slice(0, 12)}`);
    if (!byDigest.has(prevHex)) chainCheck("predecessor_resolution", false, `dangling predecessor ${prevHex.slice(0, 12)}`);
  }
  chainCheck("successor_uniqueness", true, "");
  chainCheck("predecessor_resolution", true, "");
  walk.push(genesis[0]!);
  let cursor = toHex(genesis[0]!.digest);
  while (true) {
    const next = openedReceipts.find((r) => get(r.payload, "session_prev_digest") !== null && hex(get(r.payload, "session_prev_digest")) === cursor);
    if (!next) break;
    cursor = toHex(next.digest);
    walk.push(next);
  }
  chainCheck("final_chain_digest", cursor === hex(get(close, "final_chain_digest")), "walk does not terminate at final_chain_digest");
  chainCheck("walked_length", walk.length === itemCount && walk.length === openedReceipts.length,
    walk.length !== itemCount ? `walked ${walk.length}, item_count ${itemCount}` : "carried receipt off the single walk");
}

// Coordinate agreement.
const openedAt = get(close, "opened_at") as number;
const closedAt = get(close, "closed_at") as number;
if (closedAt < openedAt) fail("session/close-coordinate-mismatch", "closed_at < opened_at");
for (const [i, r] of openedReceipts.entries()) {
  for (const field of ["tenant_id", "site_id", "session_id"]) {
    if (hex(get(r.payload, field)) !== hex(get(close, field)))
      fail("session/close-coordinate-mismatch", `${field} receipt ${i}`);
  }
  const att = get(r.payload, "attestation") as Receipt;
  if (get(att, "point") !== get(close, "attestation_point"))
    fail("session/close-coordinate-mismatch", `attestation_point receipt ${i}`);
  if (hex(get(att, "recorder_kid")) !== hex(get(close, "recorder_kid")))
    fail("session/close-signer-mismatch", `receipt ${i}`);
  const at = get(r.payload, "committed_at") as number;
  if (at < openedAt || at > closedAt) fail("session/close-coordinate-mismatch", `committed_at receipt ${i} outside close window`);
}

// Binding follows the chain walk, never file order, timestamps or seq: a tool
// receipt is bound when a prompt entry earlier in the walk has its prompt_id.
// Unbound receipts and repeated prompt ids are reported, not failed.
const promptEntries = walk.filter((r) => r.isPrompt);
const seenPromptIds = new Set<CborValue>();
let bound = 0;
let duplicatePromptIds = 0;
for (const r of walk) {
  const promptId = get(r.payload, "prompt_id");
  if (!r.isPrompt) {
    if (typeof promptId === "string" && seenPromptIds.has(promptId)) bound += 1;
    continue;
  }
  if (seenPromptIds.has(promptId)) duplicatePromptIds += 1;
  seenPromptIds.add(promptId);
}
const toolReceipts = walk.length - promptEntries.length;

// Prompt text: prompts.jsonl is local and unsigned. A prompt entry's text is
// available only when a line reproduces that entry's commitment. A file or
// line that cannot be read, or a line that names an entry's prompt_id and
// reproduces no such entry's commitment, fails. A line naming no entry is an
// orphan. Without the file, or without its line, an entry's text is
// unavailable; that is not a failure.
const available = new Set<(typeof walk)[number]>();
let orphanLines = 0;
const textLines = readLines(join(dir, "prompts.jsonl"));
if (!textLines) fail("session/prompt-text-mismatch", "prompts.jsonl: unreadable file");
for (const [i, line] of textLines.entries()) {
  if (line.trim().length === 0) continue;
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {}
  const { prompt_id: promptId, opening, prompt } = (parsed ?? {}) as Record<string, unknown>;
  if (typeof promptId !== "string" || !isWellFormed(promptId) || typeof opening !== "string" || !/^[0-9a-f]{64}$/.test(opening)
    || typeof prompt !== "string" || !isWellFormed(prompt))
    fail("session/prompt-text-mismatch", `prompts.jsonl line ${i + 1}: unreadable`);
  const named = promptEntries.filter((r) => r.payload.prompt_id === promptId);
  if (named.length === 0) {
    orphanLines += 1;
    continue;
  }
  const commitment = toHex(promptCommitment(fromHex(opening), prompt));
  const reproduced = named.filter((r) => hex(r.payload.prompt_commitment!) === commitment);
  if (reproduced.length === 0) fail("session/prompt-text-mismatch", `prompts.jsonl line ${i + 1}: does not reproduce the commitment`);
  for (const r of reproduced) available.add(r);
}

promptReport = {
  prompts: promptEntries.length,
  tool_receipts: toolReceipts,
  bound,
  unbound: toolReceipts - bound,
  duplicate_prompt_ids: duplicatePromptIds,
  prompt_text: { available: available.size, unavailable: promptEntries.length - available.size, orphan_lines: orphanLines },
};
report(true,
  `intact — session_close_declared, ${toolReceipts} action(s), attestation harness_hook (agent_kid nil → ranks undeclared). ` +
  `${promptEntries.length} prompt(s), ${duplicatePromptIds} with a repeated prompt_id; tool receipts: ${bound} bound, ${toolReceipts - bound} unbound; ` +
  `prompt text: ${available.size} available, ${promptEntries.length - available.size} unavailable, ${orphanLines} orphan line(s). ` +
  `NOT proven: recorder honesty (T-H1), external anchoring (A2 retroactive re-close), producer conformance to AAR v0.2.`,
);
