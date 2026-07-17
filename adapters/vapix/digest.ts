import { createHash, randomBytes } from "node:crypto";
import { request as httpRequest, type IncomingHttpHeaders, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import type { CredentialProvider } from "../shared/types";

type DigestAlgorithm = "MD5" | "MD5-sess" | "SHA-256" | "SHA-256-sess";

export interface DigestRequestContext {
  readonly invocationId: string;
  readonly commandDigest?: string;
  readonly actionBearing: boolean;
}

export interface DigestResponse {
  readonly status: number;
  readonly statusMessage: string;
  readonly headers: IncomingHttpHeaders;
  readonly body: Uint8Array;
}

export interface HttpTransportRequest {
  readonly method: "GET" | "POST";
  readonly url: URL;
  readonly headers: Readonly<Record<string, string | number>>;
  readonly body: Uint8Array;
  readonly timeoutMs: number;
}

export interface HttpTransport {
  exchange(request: HttpTransportRequest): Promise<DigestResponse>;
}

export class DigestTransportError extends Error {
  constructor(message: string, readonly afterSend: boolean, readonly actionBearing: boolean) {
    super(message);
    this.name = "DigestTransportError";
  }
}

interface DigestChallenge {
  readonly realm: string;
  readonly nonce: string;
  readonly algorithm: DigestAlgorithm;
  readonly qop?: "auth";
  readonly opaque?: string;
  readonly stale: boolean;
}

interface RequestInput {
  readonly method: "GET" | "POST";
  readonly url: URL;
  readonly body?: Uint8Array;
  readonly headers?: Readonly<Record<string, string>>;
  readonly context: DigestRequestContext;
  readonly timeoutMs?: number;
}

function digestName(algorithm: DigestAlgorithm): "md5" | "sha256" {
  return algorithm.startsWith("MD5") ? "md5" : "sha256";
}

function hexDigest(algorithm: DigestAlgorithm, value: string): string {
  return createHash(digestName(algorithm)).update(value, "utf8").digest("hex");
}

function quoted(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function challengeParameters(value: string): Map<string, string> {
  const result = new Map<string, string>();
  const source = value.replace(/^\s*Digest\s+/i, "");
  const pattern = /([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^,\s]+))\s*(?:,|$)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const raw = match[2] !== undefined ? match[2].replace(/\\(.)/g, "$1") : match[3]!;
    result.set(match[1]!.toLowerCase(), raw);
  }
  return result;
}

function digestChallengeValue(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const schemes = [...header.matchAll(/(?:^|,\s*)([A-Za-z][A-Za-z0-9_-]*)\s+/g)];
  const digest = schemes.find((match) => match[1]!.toLowerCase() === "digest");
  if (!digest || digest.index === undefined) return undefined;
  const start = digest.index + digest[0].indexOf(digest[1]!);
  const next = schemes.find((match) => match.index !== undefined && match.index > start);
  return header.slice(start, next?.index).replace(/,\s*$/, "");
}

export function parseDigestChallenge(header: string | undefined): DigestChallenge {
  const digest = digestChallengeValue(header);
  if (!digest) throw new Error("server did not return an RFC 7616 Digest challenge");
  const values = challengeParameters(digest);
  const realm = values.get("realm");
  const nonce = values.get("nonce");
  if (!realm || !nonce) throw new Error("Digest challenge is missing realm or nonce");
  const rawAlgorithm = values.get("algorithm") ?? "MD5";
  const normalized = rawAlgorithm.toUpperCase();
  const algorithm = normalized === "MD5" ? "MD5"
    : normalized === "MD5-SESS" ? "MD5-sess"
      : normalized === "SHA-256" ? "SHA-256"
        : normalized === "SHA-256-SESS" ? "SHA-256-sess"
          : undefined;
  if (!algorithm) throw new Error(`unsupported Digest algorithm ${rawAlgorithm}`);
  const qops = (values.get("qop") ?? "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  if (qops.length && !qops.includes("auth")) throw new Error("Digest challenge does not offer qop=auth");
  return {
    realm, nonce, algorithm, qop: qops.length ? "auth" : undefined,
    opaque: values.get("opaque"), stale: values.get("stale")?.toLowerCase() === "true",
  };
}

function challengeHeader(response: DigestResponse): string | undefined {
  const header = response.headers["www-authenticate"];
  return Array.isArray(header) ? header.find((value) => digestChallengeValue(value) !== undefined) : header;
}

function authorization(
  challenge: DigestChallenge,
  method: string,
  uri: string,
  username: string,
  password: string,
  nonceCount: number,
): string {
  const cnonce = randomBytes(16).toString("hex");
  const nc = nonceCount.toString(16).padStart(8, "0");
  const initialHa1 = hexDigest(challenge.algorithm, `${username}:${challenge.realm}:${password}`);
  const ha1 = challenge.algorithm.endsWith("-sess")
    ? hexDigest(challenge.algorithm, `${initialHa1}:${challenge.nonce}:${cnonce}`)
    : initialHa1;
  const ha2 = hexDigest(challenge.algorithm, `${method}:${uri}`);
  const response = challenge.qop
    ? hexDigest(challenge.algorithm, `${ha1}:${challenge.nonce}:${nc}:${cnonce}:${challenge.qop}:${ha2}`)
    : hexDigest(challenge.algorithm, `${ha1}:${challenge.nonce}:${ha2}`);
  const fields = [
    `username=${quoted(username)}`,
    `realm=${quoted(challenge.realm)}`,
    `nonce=${quoted(challenge.nonce)}`,
    `uri=${quoted(uri)}`,
    `algorithm=${challenge.algorithm}`,
    `response=${quoted(response)}`,
  ];
  if (challenge.opaque !== undefined) fields.push(`opaque=${quoted(challenge.opaque)}`);
  if (challenge.qop) fields.push(`qop=${challenge.qop}`, `nc=${nc}`, `cnonce=${quoted(cnonce)}`);
  return `Digest ${fields.join(", ")}`;
}

export class DigestHttpClient {
  private readonly challenges = new Map<string, DigestChallenge>();
  private readonly nonceCounts = new Map<string, number>();

  constructor(
    private readonly proxyUrl: string,
    private readonly username: string,
    private readonly credentialReference: string,
    private readonly credentialProvider: CredentialProvider,
    private readonly timeoutMs: number,
    private readonly transport?: HttpTransport,
  ) {}

  async request(input: RequestInput): Promise<DigestResponse> {
    const origin = input.url.origin;
    let challenge = this.challenges.get(origin);
    if (!challenge) {
      const discoveryInput: RequestInput = {
        method: "GET",
        url: new URL("/axis-cgi/com/ptz.cgi?query=position", origin),
        context: { ...input.context, actionBearing: false, commandDigest: undefined },
        timeoutMs: input.timeoutMs,
      };
      const challengeResponse = await this.requestOnce(discoveryInput, undefined, discoveryInput.context);
      if (challengeResponse.status !== 401) throw new Error(`Digest discovery expected HTTP 401, received ${challengeResponse.status}`);
      challenge = parseDigestChallenge(challengeHeader(challengeResponse));
      this.challenges.set(origin, challenge);
    }
    const credential = await this.credentialProvider.get(this.credentialReference);
    const uri = `${input.url.pathname}${input.url.search}`;
    const authenticated = async (current: DigestChallenge): Promise<DigestResponse> => {
      const count = (this.nonceCounts.get(origin) ?? 0) + 1;
      this.nonceCounts.set(origin, count);
      const header = authorization(current, input.method, uri, this.username, credential.secret, count);
      return this.requestOnce(input, header, input.context);
    };
    const response = await authenticated(challenge);
    if (response.status !== 401) return response;
    const fresh = parseDigestChallenge(challengeHeader(response));
    if (!fresh.stale) return response;
    this.challenges.set(origin, fresh);
    this.nonceCounts.set(origin, 0);
    // RFC 7616 stale=true means the server rejected authentication before
    // executing the request. Re-authentication is therefore the same F15
    // attempt, not a consequential action retry; both exchanges stay witnessed.
    return authenticated(fresh);
  }

  private async requestOnce(input: RequestInput, authorizationHeader: string | undefined, context: DigestRequestContext): Promise<DigestResponse> {
    const proxy = new URL(this.proxyUrl);
    const body = input.body ?? new Uint8Array();
    const headers: Record<string, string | number> = {
      host: input.url.host,
      "content-length": body.length,
      "x-aar-invocation-id": context.invocationId,
      "x-aar-action-bearing": context.actionBearing ? "1" : "0",
      ...input.headers,
    };
    if (context.commandDigest !== undefined) headers["x-aar-command-digest"] = context.commandDigest;
    if (authorizationHeader !== undefined) headers.authorization = authorizationHeader;
    const timeoutMs = Math.min(this.timeoutMs, input.timeoutMs ?? this.timeoutMs);
    if (this.transport) {
      try {
        return await this.transport.exchange({ method: input.method, url: input.url, headers, body, timeoutMs });
      } catch (error) {
        if (error instanceof DigestTransportError) throw error;
        throw new DigestTransportError(`VAPIX request failed: ${error instanceof Error ? error.message : String(error)}`, true, context.actionBearing);
      }
    }
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
      const request = (proxy.protocol === "https:" ? httpsRequest : httpRequest)(options, (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        response.on("end", () => finish(() => resolve({
          status: response.statusCode ?? 0,
          statusMessage: response.statusMessage ?? "",
          headers: response.headers,
          body: new Uint8Array(Buffer.concat(chunks)),
        })));
        response.on("error", (error) => finish(() => reject(new DigestTransportError(`VAPIX response failed: ${error.message}`, sent, context.actionBearing))));
      });
      request.setTimeout(timeoutMs, () => request.destroy(new Error("request deadline exceeded")));
      deadline = setTimeout(() => request.destroy(new Error("total request deadline exceeded")), timeoutMs);
      request.on("error", (error) => finish(() => reject(new DigestTransportError(`VAPIX request failed: ${error.message}`, sent, context.actionBearing))));
      sent = true;
      request.end(body);
    });
  }
}
