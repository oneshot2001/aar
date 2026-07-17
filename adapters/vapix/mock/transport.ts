import { toHex } from "../../../harness/cbor";
import { hash } from "../../../harness/crypto";
import { AppendOnlyWitnessLog } from "../../../demo/witness/log";
import type { DigestResponse, HttpTransport, HttpTransportRequest } from "../digest";
import { DigestTransportError } from "../digest";
import type { MockVapixBackend } from "./server";
import { sanitizedRequestTarget } from "../../../demo/witness/hygiene";

export class InMemoryWitnessTransport implements HttpTransport {
  constructor(readonly backend: MockVapixBackend, readonly witnessLogPath: string) {}

  async exchange(request: HttpTransportRequest): Promise<DigestResponse> {
    const invocationId = String(request.headers["x-aar-invocation-id"] ?? "");
    const commandDigestHeader = request.headers["x-aar-command-digest"];
    const commandDigest = typeof commandDigestHeader === "string" ? commandDigestHeader : null;
    const actionBearing = request.headers["x-aar-action-bearing"] === "1";
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const response = await Promise.race([
        this.backend.exchange(request),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("request deadline exceeded")), request.timeoutMs);
        }),
      ]);
      await new AppendOnlyWitnessLog(this.witnessLogPath).append({
        timestamp: new Date().toISOString(),
        invocation_id: invocationId,
        command_digest: commandDigest,
        action_bearing: actionBearing,
        request_line: `${request.method} ${sanitizedRequestTarget(request.url)} HTTP/1.1`,
        request_body_sha256: toHex(hash(request.body)),
        response_line: `HTTP/1.1 ${response.status} ${response.statusMessage}`.trimEnd(),
        response_body_sha256: toHex(hash(response.body)),
      });
      return response;
    } catch (error) {
      await new AppendOnlyWitnessLog(this.witnessLogPath).append({
        timestamp: new Date().toISOString(),
        invocation_id: invocationId,
        command_digest: commandDigest,
        action_bearing: actionBearing,
        request_line: `${request.method} ${sanitizedRequestTarget(request.url)} HTTP/1.1`,
        request_body_sha256: toHex(hash(request.body)),
        response_line: error instanceof DigestTransportError && !error.afterSend
          ? "CLIENT_FAILURE_BEFORE_SEND"
          : "CLIENT_ABORTED_AFTER_SEND",
        response_body_sha256: toHex(hash(new Uint8Array())),
      });
      throw error;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
