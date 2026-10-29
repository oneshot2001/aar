"""Text-field contract (page 05) and operator-log line selection (page 04)."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

from ..cbor import CBORError, loads
from ..verifier import CONTENT_TYPES

EMBEDDED_KEYS = frozenset({"parameters_cbor", "canonical_command", "canonical_cbor", "canonical_bytes"})
# A two-byte-string list is an envelope only under an artifact category or an embedded slot.
ENVELOPE_KEYS = frozenset(CONTENT_TYPES) | {"delegation", "presentation"}
IDENTIFIER_SIZES = (16, 32)

# Counted set (spec 05): default-ignorable code points, bidi controls, zero-width and joiner
# characters, BOM and variation selectors, by range (inclusive).
INVISIBLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
MARKDOWN_ACTIVE = set("\\|`*_[]<>&~#")


def is_invisible(code: int) -> bool:
    return any(low <= code <= high for low, high in INVISIBLE_RANGES)


def is_escaped_uncounted(code: int) -> bool:
    """C0/C1 controls, DEL, U+2028/2029 and format characters outside the counted set."""
    return code < 0x20 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029) or unicodedata.category(chr(code)) == "Cf"


def escape_code(code: int) -> str:
    return f"\\u{code:04X}" if code <= 0xFFFF else f"\\u{{{code:X}}}"


def visible(text: str) -> str:
    out = []
    for char in text:
        code = ord(char)
        if is_invisible(code) or is_escaped_uncounted(code):
            out.append(escape_code(code))
        elif char in MARKDOWN_ACTIVE:
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def escaped(text: str) -> str:
    return "".join(
        "\\\\" if char == "\\" else "\\|" if char == "|" else char if 0x20 <= ord(char) <= 0x7E else escape_code(ord(char))
        for char in text
    )


def text_rows(bundle: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Traverse the decoded bundle: every text key and value, embedded CBOR decoded where it
    decodes (envelope payload, COSE and protected header under ENVELOPE_KEYS; the keys in
    EMBEDDED_KEYS). Every other byte string is inventoried: ``kind`` is ``decoded``,
    ``not-decoded`` (a decode attempt failed), ``identifier`` (16 or 32 bytes, never attempted)
    or ``opaque`` (any other byte string, never attempted)."""
    texts: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []

    def text(path: str, value: str) -> None:
        positions = [(index, ord(char)) for index, char in enumerate(value) if is_invisible(ord(char))]
        texts.append({"path": path, "text": value, "invisible": positions})

    def record(path: str, raw: bytes, kind: str, error: str | None = None) -> None:
        payloads.append({"path": path, "bytes": raw, "kind": kind, "decoded": kind == "decoded",
                         "sha256": hashlib.sha256(raw).hexdigest(), **({"error": error} if error else {})})

    def embedded(path: str, raw: bytes) -> Any:
        try:
            decoded = loads(raw)
        except CBORError as exc:
            record(path, raw, "not-decoded", str(exc))
            return None
        record(path, raw, "decoded")
        return decoded

    def walk(value: Any, path: str, key: Any = None) -> None:
        if isinstance(value, dict):
            for name, item in value.items():
                if isinstance(name, str):
                    text(f"{path}.<key:{name}>", name)
                    walk(item, f"{path}.{name}", name)
                else:
                    walk(item, f"{path}[{name}]", name)
        elif isinstance(value, list):
            if key in ENVELOPE_KEYS and len(value) == 2 and all(isinstance(item, bytes) for item in value):
                payload = embedded(f"{path}[0]", value[0])
                if payload is not None:
                    walk(payload, f"{path}[0]{{payload}}")
                cose = embedded(f"{path}[1]", value[1])
                if isinstance(cose, list) and len(cose) == 4 and isinstance(cose[0], bytes):
                    protected = embedded(f"{path}[1]{{cose}}[0]", cose[0])
                    if protected is not None:
                        walk(protected, f"{path}[1]{{cose}}[0]{{protected}}")
                    walk(cose[1], f"{path}[1]{{cose}}[1]")
                    walk(cose[3], f"{path}[1]{{cose}}[3]", "signature")
                elif cose is not None:
                    walk(cose, f"{path}[1]{{cose}}")
                return
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]", key)
        elif isinstance(value, bytes):
            if key in EMBEDDED_KEYS:
                decoded = embedded(path, value)
                if decoded is not None:
                    walk(decoded, f"{path}{{cbor}}")
            else:
                record(path, value, "identifier" if len(value) in IDENTIFIER_SIZES else "opaque")
        elif isinstance(value, str):
            text(path, value)

    walk(bundle, "bundle")
    return texts, payloads


# --- operator logs (04) ---------------------------------------------------------------

LOG_RULES = {
    "journal.jsonl": "a line is kept when its `invocation_id` equals a carried receipt's `freshness.invocation_id` "
                     "or its `receipt_id` equals a carried receipt's `receipt_id` (hex, lowercase)",
    "anchor.jsonl": "a line is kept when its integer `appended_at` lies in the selector window "
                    "[`committed_from`, `committed_until`], inclusive",
    "chain.jsonl": "a line is kept when its `ts` (ISO 8601 with an explicit UTC offset), truncated to whole seconds, lies "
                   "in the selector window [`committed_from`, `committed_until`], inclusive; a `ts` without an offset is "
                   "never interpreted and is listed as undated",
}


def find_log(logs_dir: Path, name: str) -> Path | None:
    for candidate in (logs_dir / name, logs_dir / "aar" / name):
        if candidate.is_file():
            return candidate
    return None


def iso_seconds(value: str) -> int | None:
    """Whole seconds for an ISO 8601 timestamp carrying an explicit offset; ``None`` otherwise."""
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return None if parsed.tzinfo is None else int(parsed.timestamp())


def select_lines(name: str, raw: bytes, window: tuple[int, int], invocation_ids: set[str],
                 receipt_ids: set[str]) -> tuple[list[tuple[int, bytes]], list[tuple[int, str]]]:
    """The written rule per log (04 companion files). Returns (kept lines byte for byte,
    undated lines as (number, sha256)) — an offset-free timestamp is never interpreted."""
    low, high = window
    kept: list[tuple[int, bytes]] = []
    undated: list[tuple[int, str]] = []
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        try:
            record_ = json.loads(line)
        except (UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(record_, dict):
            continue
        if name == "journal.jsonl":
            hit = record_.get("invocation_id") in invocation_ids or record_.get("receipt_id") in receipt_ids
        elif name == "anchor.jsonl":
            hit = isinstance(record_.get("appended_at"), int) and low <= record_["appended_at"] <= high
        else:
            stamp = record_.get("ts")
            seconds = iso_seconds(stamp) if isinstance(stamp, str) else None
            if isinstance(stamp, str) and seconds is None:
                undated.append((number, hashlib.sha256(line).hexdigest()))
            hit = seconds is not None and low <= seconds <= high
        if hit:
            kept.append((number, line))
    return kept, undated
