// SessionEnd hook entrypoint: emits the signed session-close record (D-63
// candidate) exactly once per session. A later run on an already-closed
// session does nothing (a resuming recorder MUST NOT re-close). Runs under the
// session lock, so no receipt lands between the log read and the close write.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  loadOrCreateRecorderKey, sessionDir, sessionId16, signEnvelope, openEnvelope,
  readHexLines, sha256, toHex, encodeCbor, withLock, writeFileAtomic, CLOSE_CONTENT_TYPE, TENANT_ID, SITE_ID,
  type CborValue,
} from "./lib";

function main(): void {
  const event = JSON.parse(readFileSync(0, "utf8")) as { session_id?: string };
  if (!event.session_id) return;

  const key = loadOrCreateRecorderKey();
  const sid = sessionId16(event.session_id);
  const dir = sessionDir(sid);
  const closePath = join(dir, "close.hex");
  withLock(dir, () => {
    if (existsSync(closePath)) return;

    const receipts = readHexLines(join(dir, "receipts.hexl"));
    const statePath = join(dir, "state.json");
    const recorded: unknown = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")).openedAt : undefined;
    const openedAt = typeof recorded === "number"
      ? recorded
      : receipts.reduce<number | undefined>((earliest, receipt) => {
        let opened: ReturnType<typeof openEnvelope>;
        try {
          opened = openEnvelope(receipt, key.spki);
        } catch {
          return earliest;
        }
        const payload = opened.payload as Record<string, CborValue>;
        if (!opened.signatureValid || !opened.kidMatchesSpki
          || !(payload.session_id instanceof Uint8Array) || toHex(payload.session_id) !== toHex(sid)) return earliest;
        return Math.min(earliest ?? Infinity, payload.committed_at as number);
      }, undefined) ?? Math.floor(Date.now() / 1000);

    const payloadDigest = (envelopeBytes: Uint8Array): Uint8Array =>
      sha256(openEnvelope(envelopeBytes, key.spki).payloadBytes);

    const fields = new Map<string, CborValue>([
      ["v", 3],
      ["session_id", sid],
      ["tenant_id", TENANT_ID],
      ["site_id", SITE_ID],
      ["recorder_kid", key.kid],
      ["attestation_point", "harness_hook"],
      ["opened_at", openedAt],
      ["closed_at", Math.floor(Date.now() / 1000)],
      ["item_count", receipts.length],
      ["first_receipt_digest", receipts.length === 0 ? null : payloadDigest(receipts[0]!)],
      ["final_chain_digest", receipts.length === 0 ? null : payloadDigest(receipts[receipts.length - 1]!)],
      ["close_reason", "session_end"],
    ]);
    const closeId = sha256(encodeCbor(["AAR-SESSION-CLOSE-ID-v1", fields]));
    const payload = new Map<string, CborValue>([["close_id", closeId], ...fields]);

    writeFileAtomic(closePath, toHex(signEnvelope(payload, CLOSE_CONTENT_TYPE, key)) + "\n");
  });
}

import { appendFileSync } from "node:fs";
import { BASE_DIR } from "./lib";
try {
  main();
} catch (err) {
  try {
    appendFileSync(join(BASE_DIR, "errors.log"), `close: ${String(err)}\n`);
  } catch {}
}
