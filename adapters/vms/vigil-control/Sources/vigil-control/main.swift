import AxisEngine
import CryptoKit
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

// vigil-control — AAR D3 VMS-leg mediator (contract v2).
//
// A loopback HTTP service that wraps VigilCore.AxisEngine.VAPIXClient. The AAR
// TS VmsAdapter calls this service THROUGH the transport witness, so the wire
// this service speaks is what the witness attests. Contract:
//
//   GET  /healthz
//   GET  /ptz/position?host=&port=&username=&cred=
//   POST /dispatch?op=ptz.goto_preset&preset=&digest=&host=&port=&username=&cred=
//   POST /dispatch?op=ptz.goto&pan=&tilt=&zoom=&host=&port=&username=&cred=
//   POST /dispatch?op=stream.view&profile=&digest=&host=&port=&username=&cred=
//
// Digest-bound ops (`digest` present): the POST body is the AAR canonical
// command CBOR, and this service refuses to act unless sha256(body) equals the
// `digest` value. That makes the witnessed request body the exact command the
// EP committed to in the AAR bundle — the mediator-side half of the online
// oracle's POST-body/command-digest binding. The restore op (ptz.goto) is
// action-bearing but intentionally unbound: it is F19 safety orchestration by
// the adapter, not the committed command.
//
// Credentials: requests carry a credential REFERENCE (`cred`), never a secret.
// This service runs `cred get <reference>` in its own process; the secret
// never crosses argv/stdin and is never present in any response or log. The
// stream profile name is a logical identifier echoed back for evidence; the
// media unit itself is fetched via the VMS's own snapshot seam.

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
  var profile: String?
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

struct Route {
  let query: [String: String]
  func value(_ name: String) -> String? { query[name] }
}

func parseQuery(_ uri: String) -> Route {
  guard let components = URLComponents(string: uri) else { return Route(query: [:]) }
  var query: [String: String] = [:]
  for item in components.queryItems ?? [] { query[item.name] = item.value ?? "" }
  return Route(query: query)
}

func makeClient(_ route: Route) throws -> VAPIXClient {
  guard let host = route.value("host"), !host.isEmpty,
    let username = route.value("username"), !username.isEmpty,
    let reference = route.value("cred"), !reference.isEmpty
  else { throw CredError.failed("missing host/username/cred routing parameters") }
  let port = route.value("port").flatMap(Int.init) ?? 80
  let secret = try credGet(reference)
  return try VAPIXClient(host: host, port: port, username: username, password: secret, useHTTPS: false)
}

func sha256Hex(_ data: Data) -> String {
  SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func position(_ route: Route) async -> DispatchEffect {
  var effect = DispatchEffect(op: "ptz.position", http_ok: false, application_status: "not_executed")
  do {
    let client = try makeClient(route)
    let pos = try await client.ptzGetPosition()
    // G5-D3-001: PTZPosition.parse never fails — an error body inside HTTP
    // 2xx (a class proven reachable live in D2b) parses to defaulted zeros.
    // Axis PTZ zoom is 1-based (1..9999), so a true all-zeros triple cannot
    // occur on a real readback; refuse to report a fabricated position as a
    // positive observation.
    if pos.pan == 0 && pos.tilt == 0 && pos.zoom == 0 {
      effect.application_status = "position_unavailable"
      return effect
    }
    effect.http_ok = true
    effect.application_status = "ok"
    effect.pan = pos.pan
    effect.tilt = pos.tilt
    effect.zoom = pos.zoom
  } catch let VAPIXError.httpError(status) {
    effect.application_status = "http_rejected_\(status)"
  } catch let error as CredError {
    effect.application_status = "routing_error"
    effect.error = "\(error)"
  } catch {
    effect.application_status = "transport_error"
    effect.error = "\(error)"
  }
  return effect
}

func dispatch(_ route: Route, body: Data) async -> DispatchEffect {
  let op = route.value("op") ?? "unknown"
  var effect = DispatchEffect(op: op, http_ok: false, application_status: "not_executed")
  // Digest-bound ops must carry the canonical command as the body.
  if let digest = route.value("digest") {
    guard sha256Hex(body) == digest.lowercased() else {
      effect.application_status = "body_digest_mismatch"
      return effect
    }
  }
  do {
    let client = try makeClient(route)
    switch op {
    case "ptz.goto_preset":
      guard route.value("digest") != nil else { effect.application_status = "digest_required"; return effect }
      guard let preset = route.value("preset"), !preset.isEmpty else { effect.application_status = "missing_preset"; return effect }
      try await client.ptzGotoPreset(name: preset)
      effect.http_ok = true
      effect.application_status = "ok"
    case "ptz.goto":
      guard let pan = route.value("pan").flatMap(Double.init),
        let tilt = route.value("tilt").flatMap(Double.init),
        let zoom = route.value("zoom").flatMap(Double.init)
      else { effect.application_status = "missing_coordinates"; return effect }
      try await client.ptzGoto(pan: pan, tilt: tilt, zoom: zoom)
      effect.http_ok = true
      effect.application_status = "ok"
    case "stream.view":
      guard route.value("digest") != nil else { effect.application_status = "digest_required"; return effect }
      guard let profile = route.value("profile"), !profile.isEmpty else { effect.application_status = "missing_profile"; return effect }
      // One explicitly requested media unit via the VMS's own snapshot seam.
      let data = try await client.getSnapshot()
      effect.http_ok = true
      effect.profile = profile
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
  } catch let error as CredError {
    effect.application_status = "routing_error"
    effect.error = "\(error)"
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
      let route = parseQuery(head.uri)
      let path = URLComponents(string: head.uri)?.path ?? head.uri
      if head.method == .POST && path == "/dispatch" {
        Task {
          let effect = await dispatch(route, body: bytes)
          let payload = (try? JSONEncoder().encode(effect)) ?? Data("{}".utf8)
          loop.execute { Self.respond(channel: channel, status: .ok, body: payload) }
        }
      } else if head.method == .GET && path == "/ptz/position" {
        Task {
          let effect = await position(route)
          let payload = (try? JSONEncoder().encode(effect)) ?? Data("{}".utf8)
          loop.execute { Self.respond(channel: channel, status: .ok, body: payload) }
        }
      } else if head.method == .GET && path == "/healthz" {
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
