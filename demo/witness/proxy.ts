import { request as httpRequest, createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { hash } from "../../harness/crypto";
import { toHex } from "../../harness/cbor";
import { AppendOnlyWitnessLog } from "./log";
import { sanitizedRequestTarget } from "./hygiene";

async function bodyOf(message: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of message) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return new Uint8Array(Buffer.concat(chunks));
}

async function handle(
  clientRequest: IncomingMessage,
  clientResponse: ServerResponse,
  log: AppendOnlyWitnessLog,
): Promise<void> {
  const method = clientRequest.method ?? "GET";
  const rawUrl = clientRequest.url ?? "";
  const invocationId = String(clientRequest.headers["x-aar-invocation-id"] ?? "");
  const commandDigest = clientRequest.headers["x-aar-command-digest"];
  const actionBearing = clientRequest.headers["x-aar-action-bearing"] === "1";
  const requestBody = await bodyOf(clientRequest);

  if (method === "CONNECT") {
    clientResponse.writeHead(501, "TLS interception is not supported");
    clientResponse.end();
    await log.append({
      timestamp: new Date().toISOString(), invocation_id: invocationId,
      command_digest: typeof commandDigest === "string" ? commandDigest : null,
      action_bearing: false, request_line: `${method} ${rawUrl} HTTP/${clientRequest.httpVersion}`,
      request_body_sha256: toHex(hash(requestBody)), response_line: "HTTP/1.1 501 TLS interception is not supported",
      response_body_sha256: toHex(hash(new Uint8Array())),
    });
    return;
  }

  let target: URL;
  try {
    target = new URL(rawUrl);
    if (target.protocol !== "http:") throw new Error("only HTTP targets are allowed");
  } catch {
    clientResponse.writeHead(400, "Absolute HTTP URL required");
    clientResponse.end();
    return;
  }

  let upstreamRequest: ReturnType<typeof httpRequest> | undefined;
  let recorded = false;
  const record = async (responseLine: string, responseBody: Uint8Array): Promise<void> => {
    if (recorded) return;
    recorded = true;
    await log.append({
      timestamp: new Date().toISOString(), invocation_id: invocationId,
      command_digest: typeof commandDigest === "string" ? commandDigest : null,
      action_bearing: actionBearing,
      request_line: `${method} ${sanitizedRequestTarget(target)} HTTP/${clientRequest.httpVersion}`,
      request_body_sha256: toHex(hash(requestBody)),
      response_line: responseLine,
      response_body_sha256: toHex(hash(responseBody)),
    });
  };
  clientResponse.on("close", async () => {
    if (!clientResponse.writableEnded && !recorded) {
      upstreamRequest?.destroy();
      await record("CLIENT_ABORTED_AFTER_SEND", new Uint8Array());
    }
  });

  let response: { statusCode: number; statusMessage: string; headers: IncomingMessage["headers"]; body: Uint8Array };
  try {
    response = await new Promise((resolve, reject) => {
      const upstream = httpRequest(target, {
        method,
        headers: Object.fromEntries(Object.entries(clientRequest.headers).filter(([name]) => !name.startsWith("x-aar-") && name !== "proxy-connection")),
      }, async (upstreamResponse) => resolve({
        statusCode: upstreamResponse.statusCode ?? 502,
        statusMessage: upstreamResponse.statusMessage ?? "",
        headers: upstreamResponse.headers,
        body: await bodyOf(upstreamResponse),
      }));
      upstreamRequest = upstream;
      upstream.on("error", reject);
      upstream.end(requestBody);
    });
  } catch {
    await record("UPSTREAM_FAILURE_AFTER_SEND", new Uint8Array());
    if (!clientResponse.headersSent) clientResponse.writeHead(502, "Upstream failure");
    clientResponse.end();
    return;
  }
  const responseLine = `HTTP/1.1 ${response.statusCode} ${response.statusMessage}`.trimEnd();
  await record(responseLine, response.body);
  clientResponse.writeHead(response.statusCode, response.statusMessage, response.headers);
  clientResponse.end(response.body);
}

export function createWitnessProxy(logPath: string) {
  const log = new AppendOnlyWitnessLog(logPath);
  return createServer((request, response) => {
    handle(request, response, log).catch((error) => {
      response.writeHead(502, "Upstream failure");
      response.end();
      process.stderr.write(`witness proxy error: ${error instanceof Error ? error.message : String(error)}\n`);
    });
  });
}

if (import.meta.main) {
  const port = Number(process.argv[2] ?? "18080");
  const logPath = process.argv[3] ?? "witness.jsonl";
  createWitnessProxy(logPath).listen(port, "127.0.0.1", () => console.log(`witness proxy listening on 127.0.0.1:${port}`));
}
