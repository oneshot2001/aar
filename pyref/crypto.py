"""Dependency-free P-256, RFC 6979, and AAR ES256 helpers."""

from __future__ import annotations

import hashlib
import hmac


P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G = (GX, GY)

TEST_SCALARS = {
    "agent_signing": 1,
    "ep_signing": 2,
    "authority_signing": 3,
    "approver_signing": 4,
    "outcome_signing": 5,
    "anchor_signing": 6,
    "verifier_signing": 7,
    "credential_issuing": 8,
    "status_signing": 9,
    "agent_signing_successor": 10,
}


def _inverse(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def _add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + A) * _inverse(2 * y1 % P, P) % P
    else:
        slope = (y2 - y1) * _inverse((x2 - x1) % P, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def _multiply(scalar: int, point: tuple[int, int] = G) -> tuple[int, int] | None:
    result = None
    addend: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def public_spki(private_scalar: int) -> bytes:
    point = _multiply(private_scalar)
    if point is None:
        raise ValueError("invalid P-256 private scalar")
    x, y = point
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    return prefix + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def key_id(private_scalar: int) -> bytes:
    return hashlib.sha256(public_spki(private_scalar)).digest()


TEST_KEYS_BY_KID = {key_id(scalar): (role, scalar) for role, scalar in TEST_SCALARS.items()}


def _rfc6979_candidates(private_scalar: int, digest: bytes):
    octets = private_scalar.to_bytes(32, "big")
    reduced_digest = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + octets + reduced_digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + octets + reduced_digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < N:
            yield candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def sign_es256(private_scalar: int, message: bytes) -> bytes:
    """Return deterministic RFC 6979 ES256 as low-S P1363 r||s."""
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    for nonce in _rfc6979_candidates(private_scalar, digest):
        point = _multiply(nonce)
        if point is None:
            continue
        r = point[0] % N
        if r == 0:
            continue
        s = (_inverse(nonce, N) * (z + r * private_scalar)) % N
        if s == 0:
            continue
        if s > N // 2:
            s = N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise RuntimeError("RFC 6979 failed to produce an ECDSA nonce")


SPKI_P256_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
)


def parse_p256_spki(spki: bytes) -> tuple[int, int]:
    """Parse the one DER SubjectPublicKeyInfo form admitted by the KAT profile."""
    if len(spki) != 91 or not spki.startswith(SPKI_P256_PREFIX):
        raise ValueError("not a DER P-256 SubjectPublicKeyInfo")
    point = (int.from_bytes(spki[-64:-32], "big"), int.from_bytes(spki[-32:], "big"))
    x, y = point
    if not (0 <= x < P and 0 <= y < P) or (y * y - (x * x * x + A * x + B)) % P:
        raise ValueError("P-256 point is not on the curve")
    return point


def verify_es256(spki: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte P1363 ES256 signature against a carried P-256 SPKI."""
    if len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    try:
        public = parse_p256_spki(spki)
    except ValueError:
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = _inverse(s, N)
    point = _add(_multiply(z * w % N), _multiply(r * w % N, public))
    return point is not None and point[0] % N == r


def is_der_ecdsa_signature(value: bytes) -> bool:
    """Recognize a strict short-form DER SEQUENCE(INTEGER r, INTEGER s)."""
    if len(value) < 8 or value[0] != 0x30 or value[1] != len(value) - 2:
        return False
    offset = 2
    for _ in range(2):
        if offset + 2 > len(value) or value[offset] != 0x02:
            return False
        size = value[offset + 1]
        offset += 2
        if size == 0 or offset + size > len(value):
            return False
        integer = value[offset : offset + size]
        if integer[0] & 0x80 or (size > 1 and integer[0] == 0 and not integer[1] & 0x80):
            return False
        offset += size
    return offset == len(value)
