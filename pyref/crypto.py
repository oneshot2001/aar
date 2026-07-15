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

