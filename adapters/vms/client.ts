import { request as httpRequest, type RequestOptions } from "node:http";
// The transport shapes and the before/after-send error carrier are shared with
// the VAPIX adapter (DigestTransportError is the latching semantic the witness
// transports and the EP dispatch accounting already understand). vigil-control
// itself has no HTTP authentication — it is a loopback mediator — so this
// client is the plain witnessed HTTP half of DigestHttpClient.
import { DigestTransportError, type DigestResponse, type HttpTransport } from "../vapix/digest";

export interface MediatorRequestContext {
  readonly invocationId: string;
  readonly commandDigest?: string;
  readonly actionBearing: boolean;
}

export interface MediatorRequestInput {
  readonly method: "GET" | "POST";
  readonly url: URL;
  readonly body?: Uint8Array;
  readonly context: MediatorRequestContext;
  readonly timeoutMs?: number;
}

export class MediatorHttpClient {
  constructor(
    private readonly proxyUrl: string,
    private readonly timeoutMs: number,
    private readonly transport?: HttpTransport,
  ) {}

  async request(input: MediatorRequestInput): Promise<DigestResponse> {
    const body = input.body ?? new Uint8Array();
    const headers: Record<string, string | number> = {
      host: input.url.host,
      "content-length": body.length,
      "x-aar-invocation-id": input.context.invocationId,
      "x-aar-action-bearing": input.context.actionBearing ? "1" : "0",
    };
    if (input.context.commandDigest !== undefined) headers["x-aar-command-digest"] = input.context.commandDigest;
    const timeoutMs = Math.min(this.timeoutMs, input.timeoutMs ?? this.timeoutMs);
    if (this.transport) {
      try {
        return await this.transport.exchange({ method: input.method, url: input.url, headers, body, timeoutMs });
      } catch (error) {
        if (error instanceof DigestTransportError) throw error;
        throw new DigestTransportError(`mediator request failed: ${error instanceof Error ? error.message : String(error)}`, true, input.context.actionBearing);
      }
    }
    const proxy = new URL(this.proxyUrl);
    const options: RequestOptions = {
      protocol: proxy.protocol,
      hostname: proxy.hostname,
      port: proxy.port,
      method: input.method,
      path: input.url.toString(),
      headers,
    };
    let sent = false;
    return new Promise<DigestResponse>((resolve, reject) => {
      let settled = false;
      let deadline: ReturnType<typeof setTimeout>;
      const finish = (callback: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        callback();
      };
      let responseStarted = false;
      const request = httpRequest(options, (response) => {
        responseStarted = true;
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        response.on("end", () => finish(() => resolve({
          status: response.statusCode ?? 0,
          statusMessage: response.statusMessage ?? "",
          headers: response.headers,
          body: new Uint8Array(Buffer.concat(chunks)),
        })));
        response.on("error", (error) => finish(() => reject(new DigestTransportError(`mediator response failed: ${error.message}`, sent, input.context.actionBearing))));
        // A response that starts but never ends (socket cut mid-body) settles
        // here; if "end" already fired, finish() is latched and this is inert.
        response.on("close", () => finish(() => reject(new DigestTransportError("mediator response failed: socket closed mid-body", sent, input.context.actionBearing))));
      });
      request.setTimeout(timeoutMs, () => request.destroy(new Error("request deadline exceeded")));
      deadline = setTimeout(() => request.destroy(new Error("total request deadline exceeded")), timeoutMs);
      request.on("error", (error) => finish(() => reject(new DigestTransportError(`mediator request failed: ${error.message}`, sent, input.context.actionBearing))));
      // G5-D2b-002 carried: Bun's client emits only "close" (no "error") when
      // the request is destroyed by the deadline timers. If no response ever
      // arrived, that IS the after-send withhold/failure — reject now.
      request.on("close", () => { if (!responseStarted) finish(() => reject(new DigestTransportError("mediator request failed: socket closed before response", sent, input.context.actionBearing))); });
      sent = true;
      request.end(body);
    });
  }
}
