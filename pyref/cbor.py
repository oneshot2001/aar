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
    """Second phase: decode an item the scanner accepted (amendment ao). The
    scanner owns depth, canonical form, duplicates, tags, floats, and UTF-8;
    what remains here is structural belt-and-braces (unreachable after the
    scanner) plus the two defects only this phase sees: a negative integer
    beyond the profile and a compound map key, both cbor/malformed."""

    data: bytes
    offset: int = 0

    def _take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise CBORError("truncated CBOR item")  # unreachable: the scanner walked the whole item
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if size is None:
            raise CBORError("reserved CBOR additional information")  # unreachable: the scanner raised first
        return int.from_bytes(self._take(size), "big")

    def item(self) -> Any:
        initial = self._take(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        if major == 0:
            return self._argument(additional)
        if major == 1:
            value = self._argument(additional)
            if value >= 2 ** 53 - 1:  # -2^53 and below are outside the profile (harness safe-integer parity)
                raise CBORError("negative integer beyond the profile's safe range")
            return -1 - value
        if major == 2:
            return self._take(self._argument(additional))
        if major == 3:
            return self._take(self._argument(additional)).decode("utf-8")
        if major == 4:
            return [self.item() for _ in range(self._argument(additional))]
        if major == 5:
            result: dict[Any, Any] = {}
            for _ in range(self._argument(additional)):
                key = self.item()
                try:
                    result[key] = self.item()
                except TypeError as exc:
                    raise CBORError("unhashable map key") from exc
            return result
        if major == 6:
            raise CBORError("CBOR tags are forbidden", "cbor/tag-forbidden")  # unreachable: the scanner flagged it
        if additional == 20:
            return False
        if additional == 21:
            return True
        if additional == 22:
            return None
        raise CBORError("unsupported CBOR simple value")  # floats included; unreachable: the scanner flagged or raised


@dataclass
class _Scan:
    invalid_utf8: bool = False
    duplicate: bool = False
    tag: bool = False
    float: bool = False
    non_canonical: bool = False


@dataclass
class _Scanner:
    """Harness CborScanner parity (D-82 amendment ae): the whole item is walked
    first; structural defects (depth, indefinite length, truncation, reserved
    additional information, unsupported simple values, integers beyond 2^53 - 1)
    raise at once, while profile defects are flagged and reported afterwards in
    a fixed precedence, so an item that is non-canonical and later malformed is
    cbor/malformed."""

    data: bytes
    max_depth: int

    def _arg(self, offset: int, additional: int, scan: _Scan) -> tuple[int, int]:
        if additional < 24:
            return additional, offset
        count = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional, 0)
        if count == 0:
            if additional == 31:
                raise CBORError("indefinite-length CBOR is forbidden", "cbor/indefinite-length")
            raise CBORError("reserved CBOR additional information")
        if offset + count > len(self.data):
            raise CBORError("truncated CBOR item")
        value = int.from_bytes(self.data[offset:offset + count], "big")
        if value > 2 ** 53 - 1:
            raise CBORError("CBOR integer exceeds the profile's safe range")
        shortest = 0 if value < 24 else 1 if value <= 0xFF else 2 if value <= 0xFFFF else 4 if value <= 0xFFFFFFFF else 8
        if shortest != count:
            scan.non_canonical = True
        return value, offset + count

    def item(self, offset: int, depth: int, scan: _Scan) -> int:
        if depth > self.max_depth:
            raise CBORError("CBOR nesting depth exceeds 32", "resource/cbor-depth")
        if offset >= len(self.data):
            raise CBORError("truncated CBOR item")
        initial = self.data[offset]
        major, additional = initial >> 5, initial & 0x1F
        if major == 6:
            scan.tag = True
            return self.item(self._arg(offset + 1, additional, scan)[1], depth, scan)
        if major == 7:
            if additional in (25, 26, 27):  # amendment (ao): a float is recognised before its bytes are read as an argument
                scan.float = True
                end = offset + 1 + {25: 2, 26: 4, 27: 8}[additional]
                if end > len(self.data):
                    raise CBORError("truncated CBOR item")
                return end
            if additional not in (20, 21, 22):
                raise CBORError("unsupported CBOR simple value")
            return offset + 1
        value, cursor = self._arg(offset + 1, additional, scan)
        if major in (0, 1):
            return cursor
        if major in (2, 3):
            end = cursor + value
            if end > len(self.data):
                raise CBORError("truncated CBOR item")
            if major == 3:
                try:
                    self.data[cursor:end].decode("utf-8")
                except UnicodeDecodeError:
                    scan.invalid_utf8 = True
            return end
        if major == 4:
            for _ in range(value):
                cursor = self.item(cursor, depth + 1, scan)
            return cursor
        seen: set[bytes] = set()
        previous: bytes | None = None
        for _ in range(value):
            key_start = cursor
            cursor = self.item(cursor, depth + 1, scan)
            key = self.data[key_start:cursor]
            if key in seen:
                scan.duplicate = True
            seen.add(key)
            if previous is not None and (len(previous), previous) >= (len(key), key):
                scan.non_canonical = True
            previous = key
            cursor = self.item(cursor, depth + 1, scan)
        return cursor


def loads(data: bytes, *, max_depth: int = 32) -> Any:
    """Decode exactly one deterministic AAR-profile CBOR item."""
    scan = _Scan()
    end = _Scanner(data, max_depth).item(0, 0, scan)
    if scan.invalid_utf8:
        raise CBORError("invalid UTF-8 text string", "cbor/invalid-utf8")
    if scan.duplicate:
        raise CBORError("duplicate map key", "cbor/duplicate-key")
    if scan.tag:
        raise CBORError("CBOR tags are forbidden", "cbor/tag-forbidden")
    if scan.float:
        raise CBORError("CBOR floating-point values are forbidden", "cbor/float-forbidden")
    if end != len(data):
        raise CBORError("trailing bytes after CBOR item", "cbor/trailing-bytes")
    if scan.non_canonical:
        raise CBORError("non-canonical CBOR encoding", "cbor/non-canonical")
    return _Decoder(data).item()
