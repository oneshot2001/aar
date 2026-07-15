export type CborScalar = null | boolean | number | string | Uint8Array;
export type CborValue =
  | CborScalar
  | CborValue[]
  | { [key: string]: CborValue }
  | Map<CborScalar, CborValue>;

const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function head(major: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`CBOR integer/length is not a non-negative safe integer: ${value}`);
  }
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value <= 0xff) return Uint8Array.of((major << 5) | 24, value);
  if (value <= 0xffff) {
    return Uint8Array.of((major << 5) | 25, value >>> 8, value);
  }
  if (value <= 0xffff_ffff) {
    return Uint8Array.of(
      (major << 5) | 26,
      value / 0x1_00_00_00_00,
      value >>> 16,
      value >>> 8,
      value,
    );
  }
  const high = Math.floor(value / 0x1_00_00_00_00);
  const low = value - high * 0x1_00_00_00_00;
  return Uint8Array.of(
    (major << 5) | 27,
    high >>> 24,
    high >>> 16,
    high >>> 8,
    high,
    low >>> 24,
    low >>> 16,
    low >>> 8,
    low,
  );
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  if (left.length !== right.length) return left.length - right.length;
  for (let i = 0; i < left.length; i += 1) {
    const difference = left[i]! - right[i]!;
    if (difference !== 0) return difference;
  }
  return 0;
}

function encodeMap(entries: readonly (readonly [CborScalar, CborValue])[]): Uint8Array {
  const encoded = entries.map(([key, value]) => ({
    key: encodeCbor(key),
    value: encodeCbor(value),
  }));
  encoded.sort((a, b) => compareBytes(a.key, b.key));
  for (let i = 1; i < encoded.length; i += 1) {
    if (compareBytes(encoded[i - 1]!.key, encoded[i]!.key) === 0) {
      throw new TypeError("duplicate CBOR map key");
    }
  }
  return concat([
    head(5, encoded.length),
    ...encoded.flatMap(({ key, value }) => [key, value]),
  ]);
}

export function encodeCbor(value: CborValue): Uint8Array {
  if (value === null) return Uint8Array.of(0xf6);
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("CBOR profile permits only safe integers, not floats");
    }
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = utf8.encode(value);
    return concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return concat([head(2, value.length), value]);
  }
  if (Array.isArray(value)) {
    return concat([head(4, value.length), ...value.map(encodeCbor)]);
  }
  if (value instanceof Map) {
    return encodeMap([...value.entries()] as [CborScalar, CborValue][]);
  }
  if (typeof value === "object") {
    return encodeMap(
      Object.entries(value).map(([key, item]) => [key, item] as const),
    );
  }
  throw new TypeError(`unsupported CBOR value: ${String(value)}`);
}

export interface DecodeOptions {
  strict?: boolean;
  maxDepth?: number;
}

class Decoder {
  private offset = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly maxDepth: number,
  ) {}

  decode(): CborValue {
    const value = this.item(0);
    if (this.offset !== this.bytes.length) throw new Error("trailing CBOR bytes");
    return value;
  }

  private take(): number {
    const byte = this.bytes[this.offset];
    if (byte === undefined) throw new Error("truncated CBOR item");
    this.offset += 1;
    return byte;
  }

  private argument(additional: number): number {
    if (additional < 24) return additional;
    const count = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (count === 0) {
      if (additional === 31) throw new Error("indefinite-length CBOR is forbidden");
      throw new Error("reserved CBOR additional information");
    }
    let value = 0;
    for (let i = 0; i < count; i += 1) value = value * 256 + this.take();
    if (!Number.isSafeInteger(value)) throw new Error("CBOR integer exceeds safe range");
    return value;
  }

  private bytesOf(length: number): Uint8Array {
    const end = this.offset + length;
    if (end > this.bytes.length) throw new Error("truncated CBOR string");
    const value = this.bytes.slice(this.offset, end);
    this.offset = end;
    return value;
  }

  private item(depth: number): CborValue {
    if (depth > this.maxDepth) throw new Error("CBOR nesting exceeds configured maximum");
    const initial = this.take();
    const major = initial >>> 5;
    const additional = initial & 31;
    if (major === 6) throw new Error("CBOR tags are forbidden");
    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      if (additional === 25 || additional === 26 || additional === 27) {
        throw new Error("CBOR floats are forbidden");
      }
      throw new Error("unsupported CBOR simple value");
    }
    const argument = this.argument(additional);
    if (major === 0) return argument;
    if (major === 1) return -1 - argument;
    if (major === 2) return this.bytesOf(argument);
    if (major === 3) {
      try {
        return strictUtf8.decode(this.bytesOf(argument));
      } catch {
        throw new Error("invalid UTF-8 in CBOR text string");
      }
    }
    if (major === 4) {
      return Array.from({ length: argument }, () => this.item(depth + 1));
    }
    if (major === 5) {
      const entries: [CborScalar, CborValue][] = [];
      const keys = new Set<string>();
      let stringsOnly = true;
      for (let i = 0; i < argument; i += 1) {
        const key = this.item(depth + 1);
        if (!isScalar(key)) throw new Error("compound CBOR map keys are outside the AAR profile");
        const keyId = toHex(encodeCbor(key));
        if (keys.has(keyId)) throw new Error("duplicate CBOR map key");
        keys.add(keyId);
        stringsOnly &&= typeof key === "string";
        entries.push([key, this.item(depth + 1)]);
      }
      if (!stringsOnly) return new Map(entries);
      const object: Record<string, CborValue> = {};
      for (const [key, value] of entries) {
        Object.defineProperty(object, key as string, {
          value,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
      return object;
    }
    throw new Error(`unsupported CBOR major type ${major}`);
  }
}

function isScalar(value: CborValue): value is CborScalar {
  return value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string" || value instanceof Uint8Array;
}

export function decodeCbor(bytes: Uint8Array, options: DecodeOptions = {}): CborValue {
  const decoded = new Decoder(bytes, options.maxDepth ?? 32).decode();
  if (options.strict) {
    const canonical = encodeCbor(decoded);
    if (!equalBytes(bytes, canonical)) throw new Error("non-canonical CBOR encoding");
  }
  return decoded;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) throw new TypeError("invalid hex");
  return Uint8Array.from(hex.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}
