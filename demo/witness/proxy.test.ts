import { mkdtemp } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { AppendOnlyWitnessLog } from "./log";
import { createWitnessProxy } from "./proxy";

test("witness proxy is constructible without opening a test network socket", async () => {
  const root = await mkdtemp(join(tmpdir(), "aar-proxy-"));
  const server = createWitnessProxy(join(root, "witness.jsonl"));
  expect(server.listening).toBeFalse();
});

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port)));
}

// Raw socket that reads one response the way a close-honoring client (curl) does:
// headers, then exactly Content-Length bytes.
function exchange(proxyPort: number, target: string): Promise<{ head: string; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = connect(proxyPort, "127.0.0.1");
    let raw = "";
    const timer = setTimeout(() => { socket.destroy(); reject(new Error(`no complete response: ${raw.slice(0, 200)}`)); }, 2000);
    socket.on("data", (chunk) => {
      raw += chunk.toString();
      const at = raw.indexOf("\r\n\r\n");
      const length = Number(/^content-length: *(\d+)$/im.exec(raw.slice(0, at))?.[1]);
      if (at >= 0 && raw.length - at - 4 >= length) {
        clearTimeout(timer);
        socket.destroy();
        resolve({ head: raw.slice(0, at), body: raw.slice(at + 4) });
      }
    });
    socket.on("error", reject);
    socket.write(`GET ${target} HTTP/1.1\r\nHost: camera\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
  });
}

test("W-01: every response says Connection: close, drops the camera's hop-by-hop headers, and arrives whole", async () => {
  // Shaped like an Axis Digest challenge: the camera asks to keep its connection alive.
  // Snapshot-sized: an early socket close once truncated a 1 MiB body here.
  const challenge = "c".repeat(1 << 20);
  const camera = createServer((_request, response) => {
    response.writeHead(401, "Unauthorized", { connection: "Keep-Alive", "keep-alive": "timeout=5, max=100", "www-authenticate": "Digest" });
    response.end(challenge);
  });
  const logPath = join(await mkdtemp(join(tmpdir(), "aar-proxy-")), "witness.jsonl");
  const proxy = createWitnessProxy(logPath);
  try {
    const cameraPort = await listen(camera);
    const proxyPort = await listen(proxy);
    for (const n of [1, 2]) {
      const { head, body } = await exchange(proxyPort, `http://127.0.0.1:${cameraPort}/axis-cgi/param.cgi?n=${n}`);
      expect(head).toStartWith("HTTP/1.1 401");
      expect(body.length).toBe(challenge.length);
      expect(head).toMatch(/^connection: close$/im);
      expect(head).not.toMatch(/^keep-alive:/im);
    }
    const entries = await new AppendOnlyWitnessLog(logPath).entries();
    expect(entries.map((entry) => entry.response_line)).toEqual(["HTTP/1.1 401 Unauthorized", "HTTP/1.1 401 Unauthorized"]);
  } finally {
    proxy.close();
    camera.close();
  }
});
