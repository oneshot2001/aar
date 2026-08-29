import CryptoKit
import Foundation

private enum CBORValue {
  case unsigned(UInt64)
  case negative(Int64)
  case bytes(Data)
  case text(String)
  case array([CBORValue])
  case map([(CBORValue, CBORValue)])
  case null

  func encoded() -> Data {
    switch self {
    case .unsigned(let value): return Self.head(major: 0, value: value)
    case .negative(let value): return Self.head(major: 1, value: UInt64(-1 - value))
    case .bytes(let value): return Self.head(major: 2, value: UInt64(value.count)) + value
    case .text(let value):
      let bytes = Data(value.utf8)
      return Self.head(major: 3, value: UInt64(bytes.count)) + bytes
    case .array(let values):
      return values.reduce(into: Self.head(major: 4, value: UInt64(values.count))) { $0 += $1.encoded() }
    case .map(let entries):
      let sorted = entries.map { ($0.0.encoded(), $0.1.encoded()) }.sorted {
        $0.0.count == $1.0.count ? $0.0.lexicographicallyPrecedes($1.0) : $0.0.count < $1.0.count
      }
      return sorted.reduce(into: Self.head(major: 5, value: UInt64(sorted.count))) { result, entry in
        result += entry.0
        result += entry.1
      }
    case .null: return Data([0xf6])
    }
  }

  private static func head(major: UInt8, value: UInt64) -> Data {
    let prefix = major << 5
    if value < 24 { return Data([prefix | UInt8(value)]) }
    if value <= 0xff { return Data([prefix | 24, UInt8(truncatingIfNeeded: value)]) }
    if value <= 0xffff {
      return Data([prefix | 25, UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
    }
    if value <= 0xffff_ffff {
      return Data([prefix | 26, UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
    }
    return Data([prefix | 27,
      UInt8(truncatingIfNeeded: value >> 56), UInt8(truncatingIfNeeded: value >> 48), UInt8(truncatingIfNeeded: value >> 40), UInt8(truncatingIfNeeded: value >> 32),
      UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16), UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)])
  }
}

private extension Data {
  init?(hex: String) {
    guard hex.count.isMultiple(of: 2) else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self = Data(bytes)
  }

  var hex: String { map { String(format: "%02x", $0) }.joined() }
}

struct MediatorCountersignature {
  let payloadBase64: String
  let coseBase64: String
  let credentialBase64: String
}

struct MediatorSigner {
  private static let contentType = "application/aar-mediator-countersignature+cbor;v=0.2"
  private static let spkiPrefix = Data(hex: "3059301306072a8648ce3d020106082a8648ce3d030107034200")!
  private static let p256Order = [UInt8](Data(hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")!)
  private static let p256HalfOrder = [UInt8](Data(hex: "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")!)
  private let privateKey: P256.Signing.PrivateKey
  private let kid: Data
  private let credentialURL: URL

  static func mintKey(in directory: String) throws {
    let manager = FileManager.default
    try manager.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory)
    let keyURL = URL(fileURLWithPath: directory).appendingPathComponent("mediator-key.raw")
    let key: P256.Signing.PrivateKey
    if manager.fileExists(atPath: keyURL.path) {
      key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: keyURL))
    } else {
      key = P256.Signing.PrivateKey()
      try key.rawRepresentation.write(to: keyURL, options: .atomic)
    }
    try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
    let spki = spkiPrefix + key.publicKey.x963Representation
    let publicDocument: [String: Any] = [
      "version": 1,
      "kid": Data(SHA256.hash(data: spki)).hex,
      "spki": spki.hex,
    ]
    let publicData = try JSONSerialization.data(withJSONObject: publicDocument, options: [.prettyPrinted, .sortedKeys]) + Data("\n".utf8)
    try publicData.write(to: URL(fileURLWithPath: directory).appendingPathComponent("public.json"), options: .atomic)
  }

  init(directory: String) throws {
    let root = URL(fileURLWithPath: directory)
    privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: root.appendingPathComponent("mediator-key.raw")))
    credentialURL = root.appendingPathComponent("credential.cbor")
    kid = Data(SHA256.hash(data: Self.spkiPrefix + privateKey.publicKey.x963Representation))
  }

  func sign(actionAttemptDigestHex: String, commandDigestHex: String, observedAt: UInt64) throws -> MediatorCountersignature {
    guard let attemptDigest = Data(hex: actionAttemptDigestHex), attemptDigest.count == 32,
      let commandDigest = Data(hex: commandDigestHex), commandDigest.count == 32
    else { throw SignerError.invalidDigest }
    let fields: [(CBORValue, CBORValue)] = [
      (.text("v"), .unsigned(2)),
      (.text("action_attempt_receipt_digest"), .bytes(attemptDigest)),
      (.text("command_digest"), .bytes(commandDigest)),
      (.text("mediator_observed_at"), .unsigned(observedAt)),
    ]
    let idPreimage = CBORValue.array([
      .text("AAR-MEDIATOR-COUNTERSIGNATURE-ID-v1"),
      .map(fields),
    ]).encoded()
    let countersignatureID = Data(SHA256.hash(data: idPreimage))
    let payload = CBORValue.map([(.text("countersignature_id"), .bytes(countersignatureID))] + fields).encoded()
    let protected = CBORValue.map([
      (.unsigned(1), .negative(-7)),
      (.unsigned(3), .text(Self.contentType)),
      (.unsigned(4), .bytes(kid)),
    ]).encoded()
    let sigStructure = CBORValue.array([
      .text("Signature1"), .bytes(protected), .bytes(Data()), .bytes(payload),
    ]).encoded()
    let signature = Self.normalizedLowS(try privateKey.signature(for: sigStructure).rawRepresentation)
    let cose = CBORValue.array([
      .bytes(protected), .map([]), .null, .bytes(signature),
    ]).encoded()
    return MediatorCountersignature(
      payloadBase64: payload.base64EncodedString(),
      coseBase64: cose.base64EncodedString(),
      credentialBase64: try Data(contentsOf: credentialURL).base64EncodedString()
    )
  }

  private static func normalizedLowS(_ signature: Data) -> Data {
    var compact = [UInt8](signature)
    precondition(compact.count == 64)
    let s = Array(compact[32..<64])
    guard s.lexicographicallyPrecedes(p256HalfOrder) == false && s != p256HalfOrder else {
      return signature
    }
    var normalized = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
      var difference = Int(p256Order[index]) - Int(s[index]) - borrow
      if difference < 0 {
        difference += 256
        borrow = 1
      } else {
        borrow = 0
      }
      normalized[index] = UInt8(difference)
    }
    compact.replaceSubrange(32..<64, with: normalized)
    return Data(compact)
  }

  enum SignerError: Error { case invalidDigest }
}
