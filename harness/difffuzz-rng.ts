// Deterministic RNG for the differential fuzz tool. xorshift32 over uint32:
//   s ^= s << 13;  s ^= s >>> 17;  s ^= s << 5;   (every step reduced mod 2^32)
// The state is never zero: seed 0 maps to 0x9E3779B9. int(n) is next() % n
// (modulo bias accepted; n is always small). No other randomness exists.
export const RNG_SPEC = "xorshift32/uint32: s^=s<<13; s^=s>>>17; s^=s<<5; seed 0 -> 0x9E3779B9; int(n)=next()%n";

export class Rng {
  private s: number;
  constructor(seed: number) { this.s = (seed >>> 0) || 0x9E3779B9; }
  next(): number {
    let s = this.s;
    s = (s ^ (s << 13)) >>> 0;
    s = (s ^ (s >>> 17)) >>> 0;
    s = (s ^ (s << 5)) >>> 0;
    this.s = s;
    return s;
  }
  int(n: number): number { return this.next() % n; }
  pick<T>(items: readonly T[]): T { return items[this.int(items.length)]!; }
  bool(): boolean { return (this.next() & 1) === 1; }
  bytes(n: number): Uint8Array { return Uint8Array.from({ length: n }, () => this.next() & 0xff); }
  // ±1 around a boundary, or the boundary itself.
  near(boundary: number): number { return boundary + this.pick([-1, 0, 1]); }
}
