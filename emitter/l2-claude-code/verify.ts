// Offline session verifier for the L2 candidate wire. Implements the D-63
// evaluation: signatures, the six chain checks (successor uniqueness — the
// walk MUST be a function), coordinate agreement, and single-close.
// Usage: bun run verify.ts <session-dir> <recorder-spki-hex-file> <session-id-hex>
// The expected session id is a REQUIRED input: a verifier that infers the
// session from the evidence it is checking can be replayed a genuine close
// from a different session (round-2 P1). Exit 0 = intact; exit 1 = reason code.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  openEnvelope, readHexLines, sha256, toHex, fromHex,
  RECEIPT_CONTENT_TYPE, CLOSE_CONTENT_TYPE, type CborValue,
} from "./lib";

type Receipt = Record<string, CborValue>;
const get = (m: CborValue, k: string): CborValue => (m as Receipt)[k] as CborValue;

function fail(code: string, detail: string): never {
  console.log(`nonconformant ${code} — ${detail}`);
  process.exit(1);
}

const [dir, spkiFile, expectedSidHex] = process.argv.slice(2);
if (!dir || !spkiFile || !/^[0-9a-f]{32}$/.test(expectedSidHex ?? "")) {
  console.error("usage: verify.ts <session-dir> <recorder-spki-hex-file> <session-id-hex (32 hex chars)>");
  process.exit(2);
}
const spki = fromHex(readFileSync(spkiFile, "utf8").trim());

const receiptEnvs = readHexLines(join(dir, "receipts.hexl"));
const closeEnvs = readHexLines(join(dir, "close.hex"));
if (closeEnvs.length === 0) {
  console.log(`no session-close — completeness not_established (${receiptEnvs.length} receipt(s) present)`);
  process.exit(1);
}
if (closeEnvs.length > 1) fail("session/duplicate-close", `${closeEnvs.length} close records`);

const openedReceipts = receiptEnvs.map((env, i) => {
  const opened = openEnvelope(env, spki);
  if (!opened.signatureValid) fail("cose/receipt-signature", `receipt index ${i}`);
  if (!opened.kidMatchesSpki) fail("cose/receipt-signature", `receipt index ${i}: kid does not match spki`);
  if (opened.contentType !== RECEIPT_CONTENT_TYPE) fail("session/fields-inconsistent", `receipt index ${i}: wrong content type`);
  return { payload: opened.payload as Receipt, digest: sha256(opened.payloadBytes) };
});
const openedClose = openEnvelope(closeEnvs[0]!, spki);
if (!openedClose.signatureValid) fail("cose/close-signature", "session-close");
if (!openedClose.kidMatchesSpki) fail("cose/close-signature", "close kid does not match spki");
if (openedClose.contentType !== CLOSE_CONTENT_TYPE) fail("session/fields-inconsistent", "close has wrong content type");
const close = openedClose.payload as Receipt;

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
  fail("session/fields-inconsistent", `item_count not an integer in [0,10000]: ${String(itemCountRaw)}`);
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

// Chain checks (1)-(6), in the D-63 order.
const genesis = openedReceipts.filter((r) => get(r.payload, "session_prev_digest") === null);
if (itemCount > 0 && genesis.length !== 1) fail("session/chain-broken", `genesis count ${genesis.length}`);
if (itemCount === 0 && openedReceipts.length > 0) fail("session/chain-broken", "receipts present under empty close");

if (itemCount > 0) {
  if (hex(get(close, "first_receipt_digest")) !== toHex(genesis[0]!.digest))
    fail("session/chain-broken", "first_receipt_digest does not match genesis");
  const byDigest = new Map(openedReceipts.map((r) => [toHex(r.digest), r]));
  const successors = new Map<string, number>();
  for (const r of openedReceipts) {
    const prev = get(r.payload, "session_prev_digest");
    if (prev === null) continue;
    const prevHex = hex(prev);
    successors.set(prevHex, (successors.get(prevHex) ?? 0) + 1);
    if ((successors.get(prevHex) ?? 0) > 1) fail("session/chain-broken", `fork at ${prevHex.slice(0, 12)}`);
    if (!byDigest.has(prevHex)) fail("session/chain-broken", `dangling predecessor ${prevHex.slice(0, 12)}`);
  }
  let walked = 1;
  let cursor = toHex(genesis[0]!.digest);
  while (true) {
    const next = openedReceipts.find((r) => get(r.payload, "session_prev_digest") !== null && hex(get(r.payload, "session_prev_digest")) === cursor);
    if (!next) break;
    cursor = toHex(next.digest);
    walked += 1;
  }
  if (cursor !== hex(get(close, "final_chain_digest"))) fail("session/chain-broken", "walk does not terminate at final_chain_digest");
  if (walked !== itemCount) fail("session/chain-broken", `walked ${walked}, item_count ${itemCount}`);
  if (walked !== openedReceipts.length) fail("session/chain-broken", "carried receipt off the single walk");
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

console.log(
  `intact — session_close_declared, ${itemCount} action(s), attestation harness_hook (agent_kid nil → ranks undeclared). ` +
  `NOT proven: recorder honesty (T-H1), external anchoring (A2 retroactive re-close), producer conformance to AAR v0.2.`,
);
