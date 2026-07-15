"""Minimal RFC 8949 core deterministic CBOR codec used by the C1 KATs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class CBORError(ValueError):
    """Raised for CBOR outside the AAR deterministic encoding profile."""

    def __init__(self, message: str, code: str = "cbor/malformed") -> None:
        super().__init__(message)
        self.code = code


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise CBORError("negative CBOR argument")
    prefix = major << 5
    if value < 24:
        return bytes((prefix | value,))
    if value <= 0xFF:
        return bytes((prefix | 24, value))
    if value <= 0xFFFF:
        return bytes((prefix | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes((prefix | 26,)) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes((prefix | 27,)) + value.to_bytes(8, "big")
    raise CBORError("integer exceeds CBOR uint64")


def dumps(value: Any) -> bytes:
    """Encode an AAR value with RFC 8949 section 4.2.1 ordering."""
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(dumps(item) for item in value)
    if isinstance(value, dict):
        entries = [(dumps(key), dumps(item)) for key, item in value.items()]
        entries.sort(key=lambda entry: (len(entry[0]), entry[0]))
        return _head(5, len(entries)) + b"".join(
            key_bytes + item_bytes for key_bytes, item_bytes in entries
        )
    raise CBORError(f"unsupported CBOR type: {type(value).__name__}")


@dataclass
class _Decoder:
    data: bytes
    offset: int = 0
    max_depth: int = 32

    def _take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise CBORError("truncated CBOR item", "cbor/malformed")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        size = sizes.get(additional)
        if size is None:
            if additional == 31:
                raise CBORError(
                    "indefinite-length CBOR is forbidden", "cbor/indefinite-length"
                )
            raise CBORError("reserved CBOR additional information")
        value = int.from_bytes(self._take(size), "big")
        if (size == 1 and value < 24) or (
            size == 2 and value <= 0xFF
        ) or (size == 4 and value <= 0xFFFF) or (
            size == 8 and value <= 0xFFFFFFFF
        ):
            raise CBORError("non-shortest CBOR argument", "cbor/non-canonical")
        return value

    def item(self, depth: int = 0) -> Any:
        initial = self._take(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        if major == 0:
            return self._argument(additional)
        if major == 1:
            return -1 - self._argument(additional)
        if major == 2:
            return self._take(self._argument(additional))
        if major == 3:
            raw = self._take(self._argument(additional))
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CBORError("invalid UTF-8 text string", "cbor/invalid-utf8") from exc
        if major == 4:
            if depth >= self.max_depth:
                raise CBORError("CBOR nesting depth exceeds 32", "resource/cbor-depth")
            return [self.item(depth + 1) for _ in range(self._argument(additional))]
        if major == 5:
            if depth >= self.max_depth:
                raise CBORError("CBOR nesting depth exceeds 32", "resource/cbor-depth")
            count = self._argument(additional)
            result: dict[Any, Any] = {}
            encoded_keys: set[bytes] = set()
            previous_order: tuple[int, bytes] | None = None
            for _ in range(count):
                key_start = self.offset
                key = self.item(depth + 1)
                key_bytes = self.data[key_start:self.offset]
                if key_bytes in encoded_keys:
                    raise CBORError("duplicate map key", "cbor/duplicate-key")
                encoded_keys.add(key_bytes)
                order = (len(key_bytes), key_bytes)
                if previous_order is not None and order <= previous_order:
                    raise CBORError(
                        "non-deterministic map-key ordering", "cbor/non-canonical"
                    )
                previous_order = order
                try:
                    result[key] = self.item(depth + 1)
                except TypeError as exc:
                    raise CBORError("unhashable map key") from exc
            return result
        if major == 6:
            raise CBORError("CBOR tags are forbidden", "cbor/tag-forbidden")
        if additional == 20:
            return False
        if additional == 21:
            return True
        if additional == 22:
            return None
        if additional in {25, 26, 27}:
            raise CBORError("CBOR floating-point values are forbidden", "cbor/float-forbidden")
        raise CBORError("unsupported CBOR simple value")


def loads(data: bytes, *, max_depth: int = 32) -> Any:
    """Decode exactly one deterministic AAR-profile CBOR item."""
    decoder = _Decoder(data, max_depth=max_depth)
    value = decoder.item()
    if decoder.offset != len(data):
        raise CBORError("trailing bytes after CBOR item", "cbor/trailing-bytes")
    return value
