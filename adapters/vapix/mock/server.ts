import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import { mkdir, unlink } from "node:fs/promises";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { VapixPosition } from "../config";
import { DigestTransportError, type DigestResponse, type HttpTransportRequest } from "../digest";

export type MockFaultMode = "normal" | "reject" | "application-error" | "after-send-timeout" | "settling-poll-transport-error" | "position-unavailable";

export interface MockVapixConfig {
  readonly username: string;
  readonly password: string;
  readonly realm: string;
  readonly presetBackendName: string;
  readonly streamBackendProfile: string;
  readonly model: string;
  readonly firmware: string;
  readonly serial: string;
  readonly baseline: VapixPosition;
  readonly safePreset: VapixPosition;
  readonly settlingReads: number;
  readonly stateFile?: string;
}

export interface MockVapixCounters {
  readonly challenges: number;
  readonly presetDispatches: number;
  readonly restoreDispatches: number;
  readonly streamDispatches: number;
  readonly positionReads: number;
}

const JPEG = Uint8Array.from([
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
  0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
]);

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function digestFields(value: string): Map<string, string> {
  const result = new Map<string, string>();
  const source = value.replace(/^\s*Digest\s+/i, "");
  const pattern = /([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^,\s]+))\s*(?:,|$)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    result.set(match[1]!.toLowerCase(), match[2] !== undefined ? match[2].replace(/\\(.)/g, "$1") : match[3]!);
  }
  return result;
}

function interpolate(current: VapixPosition, target: VapixPosition, remaining: number): VapixPosition {
  if (remaining <= 1) return { ...target };
  return {
    pan: current.pan + (target.pan - current.pan) / remaining,
    tilt: current.tilt + (target.tilt - current.tilt) / remaining,
    zoom: current.zoom + (target.zoom - current.zoom) / remaining,
  };
}

export class MockVapixBackend {
  private server?: Server;
  private socketPath?: string;
  private readonly sockets = new Set<Socket>();
  private nonce = "mock-vapix-nonce";
  private position: VapixPosition;
  private target: VapixPosition;
  private remaining = 0;
  private mode: MockFaultMode = "normal";
  private failNextSettlingPoll = false;
  private staleKind?: "action" | "poll";
  private counts = { challenges: 0, presetDispatches: 0, restoreDispatches: 0, streamDispatches: 0, positionReads: 0 };

  constructor(readonly config: MockVapixConfig) {
    const persisted = config.stateFile && existsSync(config.stateFile)
      ? JSON.parse(readFileSync(config.stateFile, "utf8")) as { position: VapixPosition; target: VapixPosition; remaining: number }
      : undefined;
    this.position = { ...(persisted?.position ?? config.baseline) };
    this.target = { ...(persisted?.target ?? config.baseline) };
    this.remaining = persisted?.remaining ?? 0;
  }

  setFaultMode(mode: MockFaultMode): void {
    this.mode = mode;
  }

  rotateNonceOnNext(kind: "action" | "poll"): void {
    this.staleKind = kind;
  }

  counters(): MockVapixCounters {
    return { ...this.counts };
  }

  currentPosition(): VapixPosition {
    return { ...this.position };
  }

  async listen(socketPath?: string): Promise<string> {
    if (this.server) throw new Error("mock VAPIX backend is already listening");
    this.server = createServer((request, response) => this.handle(request, response));
    this.server.on("connection", (socket) => {
      this.sockets.add(socket);
      socket.on("close", () => this.sockets.delete(socket));
    });
    if (socketPath) await mkdir(dirname(socketPath), { recursive: true });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      if (socketPath) this.server!.listen(socketPath, () => resolve());
      else this.server!.listen(0, "127.0.0.1", () => resolve());
    });
    this.socketPath = socketPath;
    if (socketPath) return "http://mock-vapix.invalid";
    const address = this.server.address();
    if (!address || typeof address === "string") throw new Error("mock VAPIX TCP listener did not return an address");
    return `http://127.0.0.1:${address.port}`;
  }

  async close(): Promise<void> {
    const server = this.server;
    if (!server) return;
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    this.server = undefined;
    if (this.socketPath) {
      try { await unlink(this.socketPath); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      this.socketPath = undefined;
    }
  }

  private authenticated(method: string, header: string | undefined, url: URL): boolean {
    if (!header?.startsWith("Digest ")) return false;
    const fields = digestFields(header);
    if (fields.get("username") !== this.config.username || fields.get("realm") !== this.config.realm || fields.get("nonce") !== this.nonce) return false;
    if ((fields.get("algorithm") ?? "").toUpperCase() !== "SHA-256" || fields.get("qop") !== "auth") return false;
    const uri = `${url.pathname}${url.search}`;
    if (fields.get("uri") !== uri) return false;
    const ha1 = sha256(`${this.config.username}:${this.config.realm}:${this.config.password}`);
    const ha2 = sha256(`${method}:${uri}`);
    const expected = sha256(`${ha1}:${this.nonce}:${fields.get("nc")}:${fields.get("cnonce")}:auth:${ha2}`);
    return fields.get("response") === expected;
  }

  private stepPosition(): VapixPosition {
    if (this.remaining > 0) {
      this.position = interpolate(this.position, this.target, this.remaining);
      this.remaining -= 1;
      this.persistState();
    }
    return this.position;
  }

  private moveTo(position: VapixPosition): void {
    this.target = { ...position };
    this.remaining = Math.max(1, this.config.settlingReads);
    this.persistState();
  }

  private persistState(): void {
    if (!this.config.stateFile) return;
    mkdirSync(dirname(this.config.stateFile), { recursive: true });
    writeFileSync(this.config.stateFile, `${JSON.stringify({ position: this.position, target: this.target, remaining: this.remaining })}\n`, { mode: 0o600 });
  }

  private faultResponse(onTimeout?: () => void): DigestResponse | "hang" | undefined {
    const mode = this.mode;
    this.mode = "normal";
    if (mode === "reject") {
      return this.response(503, "Backend Rejected", "text/plain", new TextEncoder().encode("rejected\n"));
    }
    if (mode === "application-error") {
      return this.response(200, "OK", "text/plain", new TextEncoder().encode("Error: application rejected command\n"));
    }
    if (mode === "after-send-timeout") {
      onTimeout?.();
      return "hang";
    }
    return undefined;
  }

  private response(status: number, statusMessage: string, contentType: string, body: Uint8Array): DigestResponse {
    return { status, statusMessage, headers: { "content-type": contentType, "content-length": String(body.length) }, body };
  }

  async exchange(request: Pick<HttpTransportRequest, "method" | "url" | "headers">): Promise<DigestResponse> {
    const authorization = request.headers.authorization;
    if (!this.authenticated(request.method, typeof authorization === "string" ? authorization : undefined, request.url)) {
      this.counts.challenges += 1;
      return {
        status: 401,
        statusMessage: "Unauthorized",
        headers: { "www-authenticate": `Digest realm="${this.config.realm}", nonce="${this.nonce}", algorithm=SHA-256, qop="auth"`, "content-type": "text/plain" },
        body: new TextEncoder().encode("authentication required\n"),
      };
    }

    const url = request.url;
    const requestKind = url.pathname === "/axis-cgi/com/ptz.cgi" && url.searchParams.get("query") === "position"
      ? "poll"
      : url.pathname === "/axis-cgi/com/ptz.cgi" && url.searchParams.has("gotoserverpresetname")
        ? "action"
        : undefined;
    if (requestKind && this.staleKind === requestKind) {
      this.staleKind = undefined;
      this.nonce = `mock-vapix-nonce-${this.counts.challenges + 1}`;
      this.counts.challenges += 1;
      return {
        status: 401,
        statusMessage: "Unauthorized",
        headers: {
          "www-authenticate": `Basic realm="fallback", Digest realm="${this.config.realm}", nonce="${this.nonce}", algorithm=SHA-256, qop="auth", stale=true`,
          "content-type": "text/plain",
        },
        body: new TextEncoder().encode("stale digest nonce\n"),
      };
    }

    if (url.pathname === "/axis-cgi/param.cgi") {
      return this.response(200, "OK", "text/plain", new TextEncoder().encode([
        `root.Brand.ProdFullName=${this.config.model}`,
        `root.Properties.Firmware.Version=${this.config.firmware}`,
        `root.Properties.System.SerialNumber=${this.config.serial}`,
        "root.PTZ.Preset.P0.Name=gate5-safe",
        "root.StreamProfile.S0.Name=gate5-offline",
      ].join("\n")));
    }

    if (url.pathname === "/axis-cgi/com/ptz.cgi" && url.searchParams.get("query") === "position") {
      this.counts.positionReads += 1;
      if (this.mode === "position-unavailable") {
        this.mode = "normal";
        return this.response(200, "OK", "text/plain", new TextEncoder().encode("position unavailable\n"));
      }
      if (this.failNextSettlingPoll) {
        this.failNextSettlingPoll = false;
        throw new DigestTransportError("transient settling poll failure", true, false);
      }
      const position = this.stepPosition();
      return this.response(200, "OK", "text/plain", new TextEncoder().encode(`pan=${position.pan}\ntilt=${position.tilt}\nzoom=${position.zoom}\n`));
    }

    if (url.pathname === "/axis-cgi/com/ptz.cgi" && url.searchParams.has("gotoserverpresetname")) {
      this.counts.presetDispatches += 1;
      if (url.searchParams.get("gotoserverpresetname") !== this.config.presetBackendName) {
        return this.response(200, "OK", "text/plain", new TextEncoder().encode("Error: unknown preset\n"));
      }
      const settlingPollError = this.mode === "settling-poll-transport-error";
      if (settlingPollError) this.mode = "normal";
      const fault = settlingPollError ? undefined : this.faultResponse(() => this.moveTo(this.config.safePreset));
      if (fault === "hang") return new Promise<DigestResponse>(() => {});
      if (fault) return fault;
      this.moveTo(this.config.safePreset);
      if (settlingPollError) this.failNextSettlingPoll = true;
      return this.response(200, "OK", "text/plain", new TextEncoder().encode("OK\n"));
    }

    if (url.pathname === "/axis-cgi/com/ptz.cgi" && ["pan", "tilt", "zoom"].every((name) => url.searchParams.has(name))) {
      this.counts.restoreDispatches += 1;
      const restored = {
        pan: Number(url.searchParams.get("pan")),
        tilt: Number(url.searchParams.get("tilt")),
        zoom: Number(url.searchParams.get("zoom")),
      };
      if (!Object.values(restored).every(Number.isFinite)) {
        return this.response(200, "OK", "text/plain", new TextEncoder().encode("Error: invalid position\n"));
      }
      this.moveTo(restored);
      return this.response(200, "OK", "text/plain", new TextEncoder().encode("OK\n"));
    }

    if (url.pathname === "/axis-cgi/jpg/image.cgi") {
      this.counts.streamDispatches += 1;
      if (url.searchParams.get("streamprofile") !== this.config.streamBackendProfile) {
        return this.response(200, "OK", "text/plain", new TextEncoder().encode("Error: unknown stream profile\n"));
      }
      const fault = this.faultResponse();
      if (fault === "hang") return new Promise<DigestResponse>(() => {});
      if (fault) return fault;
      return this.response(200, "OK", "image/jpeg", JPEG);
    }

    return this.response(404, "Not Found", "text/plain", new TextEncoder().encode("not found\n"));
  }

  private handle(request: IncomingMessage, response: ServerResponse): void {
    const url = new URL(request.url ?? "/", "http://mock.invalid");
    const headers = Object.fromEntries(Object.entries(request.headers).flatMap(([name, value]) => typeof value === "string" ? [[name, value]] : []));
    this.exchange({ method: (request.method === "POST" ? "POST" : "GET"), url, headers }).then((result) => {
      response.writeHead(result.status, result.statusMessage, result.headers);
      response.end(result.body);
    }).catch(() => {
      response.writeHead(500, "Mock failure");
      response.end();
    });
  }
}
