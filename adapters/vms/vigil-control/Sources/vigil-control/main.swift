import AxisEngine
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

// vigil-control — AAR D3 VMS-leg mediator.
//
// A loopback HTTP service that wraps VigilCore.AxisEngine.VAPIXClient. The AAR
// TS VmsAdapter POSTs an abstract op to /dispatch (through the transport
// witness); this service resolves the camera credential via `cred get`,
// executes ONE device operation via VAPIXClient, and returns a JSON effect.
// F19 PTZ safety (baseline/restore/poll) is orchestrated by the TS adapter as
// a sequence of atomic ops, so each request here is a single device action.
//
// Credentials: the request carries a credential REFERENCE, never a secret.
// This service runs `cred get <reference>` in its own process; the secret
// never crosses argv/stdin and is never logged or echoed.

struct DispatchRequest: Decodable {
  let op: String  // "ptz.position" | "ptz.goto_preset" | "ptz.goto" | "stream.view"
  let host: String
  let port: Int?
  let username: String
  let credentialReference: String
  let preset: String?
  let profile: String?  // stream profile name → mapped to a snapshot compression proxy; VAPIX stream-view is /jpg/image.cgi?streamprofile=
  let pan: Double?
  let tilt: Double?
  let zoom: Double?
}

struct DispatchEffect: Encodable {
  var op: String
  var http_ok: Bool
  var application_status: String
  var pan: Double?
  var tilt: Double?
  var zoom: Double?
  var content_type: String?
  var payload_bytes: Int?
  var media_valid: Bool?
  var error: String?
}

enum CredError: Error { case failed(String) }

func credGet(_ reference: String) throws -> String {
  let home = FileManager.default.homeDirectoryForCurrentUser.path
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "\(home)/.claude/bin/cred")
  process.arguments = ["get", reference]
  let out = Pipe()
  process.standardOutput = out
  process.standardError = Pipe()
  try process.run()
  process.waitUntilExit()
  guard process.terminationStatus == 0 else { throw CredError.failed("cred get exited \(process.terminationStatus)") }
  let data = out.fileHandleForReading.readDataToEndOfFile()
  let secret = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
  guard !secret.isEmpty else { throw CredError.failed("cred get returned empty secret") }
  return secret
}

func handle(_ request: DispatchRequest) async -> DispatchEffect {
  var effect = DispatchEffect(op: request.op, http_ok: false, application_status: "not_executed")
  do {
    let secret = try credGet(request.credentialReference)
    let client = try VAPIXClient(
      host: request.host, port: request.port ?? 80,
      username: request.username, password: secret, useHTTPS: false)
    switch request.op {
    case "ptz.position":
      let pos = try await client.ptzGetPosition()
      effect.http_ok = true
      effect.application_status = "ok"
      effect.pan = pos.pan; effect.tilt = pos.tilt; effect.zoom = pos.zoom
    case "ptz.goto_preset":
      guard let preset = request.preset else { effect.application_status = "missing_preset"; return effect }
      try await client.ptzGotoPreset(name: preset)
      effect.http_ok = true
      effect.application_status = "ok"
    case "ptz.goto":
      guard let pan = request.pan, let tilt = request.tilt, let zoom = request.zoom else {
        effect.application_status = "missing_coordinates"; return effect
      }
      try await client.ptzGoto(pan: pan, tilt: tilt, zoom: zoom)
      effect.http_ok = true
      effect.application_status = "ok"
    case "stream.view":
      // VAPIX stream-view for the demo = one explicitly requested JPEG frame
      // via the configured stream profile (same channel D2b's adapter used).
      let data = try await client.getSnapshot()
      effect.http_ok = true
      effect.payload_bytes = data.count
      // JPEG SOI 0xFFD8 .. EOI 0xFFD9 — a real media unit, not an error page.
      let valid = data.count >= 4 && data.first == 0xFF && data[data.index(after: data.startIndex)] == 0xD8
        && data[data.index(data.endIndex, offsetBy: -2)] == 0xFF && data.last == 0xD9
      effect.media_valid = valid
      effect.content_type = valid ? "image/jpeg" : "unknown"
      effect.application_status = valid ? "media_payload_valid" : "media_payload_invalid"
    default:
      effect.application_status = "unsupported_op"
    }
  } catch let VAPIXError.httpError(status) {
    effect.application_status = "http_rejected_\(status)"
  } catch {
    effect.application_status = "transport_error"
    effect.error = "\(error)"
  }
  return effect
}

// MARK: - HTTP server (NIOHTTP1, loopback)

final class DispatchHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = HTTPServerRequestPart
  typealias OutboundOut = HTTPServerResponsePart

  private var bodyBuffer = ByteBuffer()
  private var requestHead: HTTPRequestHead?

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    switch unwrapInboundIn(data) {
    case .head(let head):
      requestHead = head
      bodyBuffer.clear()
    case .body(var chunk):
      bodyBuffer.writeBuffer(&chunk)
    case .end:
      guard let head = requestHead else { return }
      let bytes = Data(bodyBuffer.readBytes(length: bodyBuffer.readableBytes) ?? [])
      let loop = context.eventLoop
      let channel = context.channel
      if head.method == .POST && head.uri.hasPrefix("/dispatch") {
        Task {
          let effect: DispatchEffect
          do {
            let request = try JSONDecoder().decode(DispatchRequest.self, from: bytes)
            effect = await handle(request)
          } catch {
            effect = DispatchEffect(op: "unknown", http_ok: false, application_status: "bad_request", error: "\(error)")
          }
          let payload = (try? JSONEncoder().encode(effect)) ?? Data("{}".utf8)
          loop.execute { Self.respond(channel: channel, status: .ok, body: payload) }
        }
      } else if head.method == .GET && head.uri.hasPrefix("/healthz") {
        Self.respond(channel: channel, status: .ok, body: Data("{\"ok\":true}".utf8))
      } else {
        Self.respond(channel: channel, status: .notFound, body: Data("{\"error\":\"not_found\"}".utf8))
      }
    }
  }

  static func respond(channel: Channel, status: HTTPResponseStatus, body: Data) {
    var headers = HTTPHeaders()
    headers.add(name: "Content-Type", value: "application/json")
    headers.add(name: "Content-Length", value: String(body.count))
    let head = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
    channel.write(HTTPServerResponsePart.head(head), promise: nil)
    var buffer = channel.allocator.buffer(capacity: body.count)
    buffer.writeBytes(body)
    channel.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
    channel.writeAndFlush(HTTPServerResponsePart.end(nil)).whenComplete { _ in
      channel.close(promise: nil)
    }
  }
}

let requestedPort = CommandLine.arguments.count > 1 ? Int(CommandLine.arguments[1]) ?? 0 : 0
let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let bootstrap = ServerBootstrap(group: group)
  .serverChannelOption(ChannelOptions.backlog, value: 16)
  .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
  .childChannelInitializer { channel in
    channel.pipeline.configureHTTPServerPipeline().flatMap {
      channel.pipeline.addHandler(DispatchHandler())
    }
  }

let serverChannel = try bootstrap.bind(host: "127.0.0.1", port: requestedPort).wait()
if let addr = serverChannel.localAddress, let port = addr.port {
  // The launcher reads this line to learn the ephemeral port. Write via
  // FileHandle so it is not lost to stdio block-buffering on a pipe.
  FileHandle.standardOutput.write(Data("vigil-control listening on 127.0.0.1:\(port)\n".utf8))
}
try serverChannel.closeFuture.wait()
