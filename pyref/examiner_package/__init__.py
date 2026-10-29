"""Examiner package builder (custody profile v0.1). Not part of the verifier.

Packages one onvif-mcp specimen bundle with the unchanged verifier's raw
outputs. The verifier runs as a subprocess (``python3 -B -m pyref verify``);
this module never evaluates a bundle itself and never generates narrative:
page-00 facts and the acquisition record are frozen inputs rendered verbatim.
Writes only under ``--out``. Spec: ``docs/custody-profile/examiner-package-v0.1.md``.
"""

from __future__ import annotations

import datetime as _dt
import gzip
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import unicodedata
from pathlib import Path
from typing import Any

from ..cbor import CBORError, loads
from ..verifier import CONTENT_TYPES

REPO = Path(__file__).resolve().parents[2]
SIDECARS = ("meta.json", "trust-policy.json", "prior-state.json")
LOG_NAMES = ("journal.jsonl", "anchor.jsonl", "chain.jsonl")
EMBEDDED_KEYS = frozenset({"parameters_cbor", "canonical_command", "canonical_cbor", "canonical_bytes"})
# A two-byte-string list is an envelope only under an artifact category or an embedded slot.
ENVELOPE_KEYS = frozenset(CONTENT_TYPES) | {"delegation", "presentation"}
PACKAGE_NAME = "examiner-package-v0.1"
LIMITS_FIRST = ("custody_continuity", "legal_admissibility", "source_authenticity")

# Counted set (spec 05): default-ignorable code points, bidi controls, zero-width
# and joiner characters, BOM and variation selectors, by range (inclusive).
INVISIBLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)


class PackageError(Exception):
    """A required input is missing or malformed; nothing partial is trusted."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"cannot read {label} {path}: {exc}") from exc


# --- verifier subprocess -----------------------------------------------------

def run_verifier(cwd: Path, bundle: str, at: int, trust_policy: str, prior_state: str,
                 policy: str | None = None, signing_key: str | None = None) -> dict[str, Any]:
    """Run the unchanged CLI; keep raw stdout, stderr, exit and the verdict envelope."""
    argv = ["python3", "-B", "-m", "pyref", "verify", bundle, "--at", str(at),
            "--trust-policy", trust_policy, "--prior-state", prior_state]
    if policy is not None:
        argv += ["--policy", policy, "--signing-key", signing_key or ""]
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    proc = subprocess.run([sys.executable, *argv[1:]], cwd=cwd, capture_output=True, env=env)
    stdout = proc.stdout.decode("utf-8", "replace")
    return {"command": argv, "cwd": str(cwd), "exit": proc.returncode, "stdout": stdout,
            "stderr": proc.stderr.decode("utf-8", "replace"), **parse_report(stdout)}


def parse_report(stdout: str) -> dict[str, Any]:
    def one(pattern: str) -> str | None:
        found = re.search(pattern, stdout, re.MULTILINE)
        return found.group(1) if found else None
    observations = re.findall(r"^  - (\S+) \[(signed|report layer; not signed)\]$", stdout, re.MULTILINE)
    return {
        "result": one(r"^Result: (\S+)$"),
        "verdict_id": one(r"^    verdict_id: ([0-9a-f]{64})$"),
        "bundle_digest": one(r"^    bundle_digest: ([0-9a-f]{64})$"),
        "verdict_cbor_hex": one(r"^  CBOR hex: ([0-9a-f]+)$"),
        "selector_matching_receipts": one(r"^Selector-matching receipts: (.+)$"),
        "observations": [{"name": name, "signed": kind == "signed"} for name, kind in observations],
    }


def decode_verdict(cbor_hex: str) -> dict[str, Any]:
    payload_bytes, cose_bytes = loads(bytes.fromhex(cbor_hex))
    cose = loads(cose_bytes)
    return {"verdict": loads(payload_bytes), "protected": loads(cose[0]), "signature": cose[3],
            "payload_bytes": payload_bytes, "protected_bytes": cose[0]}


# --- bundle access -------------------------------------------------------------

def receipt_payloads(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return [loads(envelope[0]) for envelope in bundle["artifacts"]["receipts"]]


def media_digests(bundle: dict[str, Any]) -> tuple[set[bytes], set[bytes]]:
    """Every dispatch ``target_response_body_digest`` and outcome ``observation_commitment``."""
    dispatch: set[bytes] = set()
    observed: set[bytes] = set()
    for receipt in receipt_payloads(bundle):
        body = receipt.get("body", {})
        if receipt.get("kind") == "dispatch" and isinstance(body.get("target_response_body_digest"), bytes):
            dispatch.add(body["target_response_body_digest"])
        if receipt.get("kind") == "outcome_observation" and isinstance(body.get("observation_commitment"), bytes):
            observed.add(body["observation_commitment"])
    return dispatch, observed


# --- S2: specimen rule ---------------------------------------------------------

def sweep(candidates_dir: Path, stills_dir: Path) -> list[dict[str, Any]]:
    """Run every candidate under its own unchanged sidecars and pair the conformant ones with a still."""
    stills: dict[str, list[str]] = {}
    for still in sorted(stills_dir.glob("snap-*.jpg")):
        stills.setdefault(file_sha256(still), []).append(still.name)
    rows: list[dict[str, Any]] = []
    for directory in sorted(p for p in candidates_dir.iterdir() if p.is_dir() and (p / "bundle.cbor").is_file()):
        row: dict[str, Any] = {"dir": directory.name, "exit": None, "result": None, "bundle_digest": None,
                               "still": None, "selected": False}
        rows.append(row)
        missing = [name for name in SIDECARS if not (directory / name).is_file()]
        if missing:
            row["reason"] = f"missing sidecar: {', '.join(missing)}"
            continue
        meta = read_json(directory / "meta.json", "meta.json")
        row.update(evaluated_at=meta.get("evaluated_at"), camera=meta.get("camera"), tool_action=meta.get("tool_action"))
        if not isinstance(meta.get("evaluated_at"), int):
            row["reason"] = "meta.json evaluated_at is not an integer"
            continue
        run = run_verifier(candidates_dir, f"{directory.name}/bundle.cbor", meta["evaluated_at"],
                           f"{directory.name}/trust-policy.json", f"{directory.name}/prior-state.json")
        row.update(exit=run["exit"], result=run["result"], bundle_digest=run["bundle_digest"])
        if run["exit"] != 0:
            detail = run["stderr"].strip().splitlines()[-1] if run["stderr"].strip() else f"Result: {run['result']}"
            row["reason"] = f"verifier exit {run['exit']}: {detail}"
            continue
        dispatch, observed = media_digests(loads((directory / "bundle.cbor").read_bytes()))
        committed = dispatch | observed
        names = stills.get(next(iter(committed)).hex(), []) if len(committed) == 1 else []
        if dispatch and observed and len(names) == 1:
            row["still"] = names[0]
            row["reason"] = "conformant, exact still match"
        else:
            row["reason"] = "no-exact-still-match"
    return rows


def select_specimen(candidates_dir: Path, stills_dir: Path, camera: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Spec section 2: exit 0 under the unchanged sidecars, both committed digests equal the
    SHA-256 of exactly one still, newest ``evaluated_at`` then ``bundle_digest``, first entry
    for ``camera``. Returns the pick and the full candidate inventory."""
    rows = sweep(candidates_dir, stills_dir)
    eligible = sorted((row for row in rows if row["still"]), key=lambda row: (-row["evaluated_at"], row["bundle_digest"]))
    for rank, row in enumerate(eligible, 1):
        row["rank"] = rank
    pick = next((row for row in eligible if row.get("camera") == camera), None)
    if pick is None:
        raise PackageError(f"no conformant candidate with an exact still match for camera {camera!r}")
    pick["selected"] = True
    for row in eligible:
        if row is not pick:
            row["reason"] += f", not selected (rank {row['rank']}, camera {row.get('camera')})"
    return pick, rows


# --- text fields (05) ---------------------------------------------------------------

def is_invisible(code: int) -> bool:
    return any(low <= code <= high for low, high in INVISIBLE_RANGES)


def is_control(code: int) -> bool:
    return code < 0x20 or 0x7F <= code <= 0x9F


def escape_code(code: int) -> str:
    return f"\\u{code:04X}" if code <= 0xFFFF else f"\\u{{{code:X}}}"


MARKDOWN_ACTIVE = set("\\|`*_[]<>&~#")


def visible(text: str) -> str:
    out = []
    for char in text:
        code = ord(char)
        if is_invisible(code) or is_control(code):
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
    decodes (envelope payload, COSE and protected header; the keys in EMBEDDED_KEYS).
    Returns (text rows, payload rows); a payload row is ``decoded`` or not."""
    texts: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []

    def text(path: str, value: str) -> None:
        positions = [(index, ord(char)) for index, char in enumerate(value) if is_invisible(ord(char))]
        texts.append({"path": path, "text": value, "invisible": positions})

    def embedded(path: str, raw: bytes) -> Any:
        try:
            decoded = loads(raw)
        except CBORError as exc:
            payloads.append({"path": path, "bytes": raw, "decoded": False, "error": str(exc)})
            return None
        payloads.append({"path": path, "bytes": raw, "decoded": True})
        return decoded

    def walk(value: Any, path: str, key: Any = None, slot: str | None = None) -> None:
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
        elif isinstance(value, str):
            text(path, value)

    walk(bundle, "bundle")
    return texts, payloads


# --- operator logs (04) ---------------------------------------------------------------

def find_log(logs_dir: Path, name: str) -> Path | None:
    for candidate in (logs_dir / name, logs_dir / "aar" / name):
        if candidate.is_file():
            return candidate
    return None


def _iso_seconds(value: str) -> int | None:
    try:
        return int(_dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except (ValueError, AttributeError):
        return None


def select_lines(name: str, raw: bytes, window: tuple[int, int], invocation_ids: set[str],
                 receipt_ids: set[str]) -> list[tuple[int, bytes]]:
    """The written rule per log (04 companion files). Lines are kept byte for byte."""
    low, high = window
    kept = []
    for number, line in enumerate(raw.splitlines(keepends=True), 1):
        try:
            record = json.loads(line)
        except (UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        if name == "journal.jsonl":
            hit = record.get("invocation_id") in invocation_ids or record.get("receipt_id") in receipt_ids
        elif name == "anchor.jsonl":
            hit = isinstance(record.get("appended_at"), int) and low <= record["appended_at"] <= high
        else:
            seconds = _iso_seconds(record.get("ts", "")) if isinstance(record.get("ts"), str) else None
            hit = seconds is not None and low <= seconds <= high
        if hit:
            kept.append((number, line))
    return kept


LOG_RULES = {
    "journal.jsonl": "a line is kept when its `invocation_id` equals a carried receipt's `freshness.invocation_id` "
                     "or its `receipt_id` equals a carried receipt's `receipt_id` (hex, lowercase)",
    "anchor.jsonl": "a line is kept when its integer `appended_at` lies in the selector window "
                    "[`committed_from`, `committed_until`], inclusive",
    "chain.jsonl": "a line is kept when its `ts` (ISO 8601, UTC), truncated to whole seconds, lies in the selector "
                   "window [`committed_from`, `committed_until`], inclusive",
}


# --- git and source inventory (03) ------------------------------------------------------

def git(*args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def source_inventory() -> list[dict[str, Any]]:
    head_blobs = dict(line.split()[2:4][::-1] for line in git("ls-tree", "-r", "HEAD", "pyref", "spec/CONFORMANCE.md", "spec/aar-core.cddl").splitlines())
    tag_blobs = dict(line.split()[2:4][::-1] for line in git("ls-tree", "-r", "v0.4.0", "pyref", "spec/CONFORMANCE.md", "spec/aar-core.cddl").splitlines())
    rows = []
    for path in sorted(head_blobs):
        file = REPO / path
        if not file.is_file():
            continue
        head, tag = head_blobs[path], tag_blobs.get(path)
        status = "same as v0.4.0" if head == tag else ("added since v0.4.0" if tag is None else "changed since v0.4.0")
        rows.append({"path": path, "mode": oct(file.stat().st_mode & 0o777), "bytes": file.stat().st_size,
                     "sha256": file_sha256(file), "blob": head, "vs_v0_4_0": status})
    return rows


# --- package build ----------------------------------------------------------------------

def _window(bundle: dict[str, Any]) -> tuple[int, int]:
    selector = bundle["selector"]
    return selector["committed_from"], selector["committed_until"]


def copy_specimen(src: Path, still: Path, dest: Path) -> list[dict[str, Any]]:
    dest.mkdir(parents=True)
    files = []
    for source in [src / "bundle.cbor", *(src / name for name in SIDECARS), still]:
        before = file_sha256(source)
        target = dest / source.name
        shutil.copyfile(source, target)
        files.append({"name": source.name, "source_path": str(source), "byte_length": source.stat().st_size,
                      "source_sha256": before, "destination_sha256": file_sha256(target)})
    return files


def fill_acquisition(record: dict[str, Any], files: list[dict[str, Any]], specimen_dir: str) -> dict[str, Any]:
    """The acquisition record is an input. On the first copy (``collection_time_utc`` null) the
    builder fills the copy facts; a filled record is checked against the copy and kept verbatim."""
    record = dict(record)
    if record.get("collection_time_utc") is None:
        record["source"] = {**record.get("source", {}),
                            "repo_path": record.get("source", {}).get("repo_path", "").replace("<specimen-dir>", specimen_dir)}
        record["files"] = files
        record["copy_method"] = "python3 shutil.copyfile (byte copy); SHA-256 of source and destination with hashlib (stdlib)"
        record["tool_versions"] = {"python": platform.python_version(), "copy": "shutil.copyfile", "hash": "hashlib.sha256",
                                   "pyref": "v0.4.0 CLI at the commit recorded in 03-source-and-run.md"}
        record["collection_time_utc"] = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
        record["platform"] = platform.platform()
        return record
    expected = [{key: row[key] for key in ("name", "byte_length", "source_sha256", "destination_sha256")} for row in files]
    actual = [{key: row.get(key) for key in ("name", "byte_length", "source_sha256", "destination_sha256")} for row in record.get("files", [])]
    if expected != actual:
        raise PackageError("acquisition.json files do not match this copy; refresh the input from a fresh first build")
    return record


def build(candidates: Path, stills: Path, logs: Path, inputs: Path, out: Path, camera: str) -> int:
    for label, path in (("candidates", candidates), ("stills", stills), ("logs", logs), ("inputs", inputs)):
        if not path.is_dir():
            raise PackageError(f"--{label} {path} is not a directory")
    facts = read_json(inputs / "specimen-facts.json", "specimen-facts.json")
    acquisition_input = read_json(inputs / "acquisition.json", "acquisition.json")
    for key in ("specimen_kind", "facts", "coverage_sentence", "d66_sentence"):
        if key not in facts:
            raise PackageError(f"specimen-facts.json lacks {key}")
    if out.exists() and any(out.iterdir()):
        raise PackageError(f"--out {out} exists and is not empty")
    package = out / "package"
    package.mkdir(parents=True)

    pick, rows = select_specimen(candidates, stills, camera)
    if any(row["exit"] == 0 and row.get("tool_action") == "camera.ptz.preset" for row in rows):
        raise PackageError("a conformant PTZ-action candidate exists; specimen-facts.json specimen_kind must be re-checked")
    (package / "appendix").mkdir()
    (package / "appendix" / "candidates.json").write_text(json_text({
        "_doc": "Every directory under the candidates path holding bundle.cbor, with the verifier exit code under its own "
                "unchanged sidecars, the exclusion reason, and the matched still. Refused sidecars were not modified.",
        "rule": "exit 0 under --at meta.evaluated_at --trust-policy --prior-state; dispatch target_response_body_digest and "
                "outcome_observation observation_commitment both equal the SHA-256 of exactly one snap-*.jpg; order by "
                "evaluated_at descending then bundle_digest; first entry whose meta.camera equals the requested camera",
        "camera": camera, "candidates": rows}))

    # 01-copy
    specimen_dir = candidates / pick["dir"]
    files = copy_specimen(specimen_dir, stills / pick["still"], package / "01-copy")
    acquisition = fill_acquisition(acquisition_input, files, pick["dir"])
    (package / "01-copy" / "acquisition.json").write_text(json_text(acquisition))
    meta = read_json(package / "01-copy" / "meta.json", "meta.json")
    trust_policy = read_json(package / "01-copy" / "trust-policy.json", "trust-policy.json")
    raw = (package / "01-copy" / "bundle.cbor").read_bytes()
    bundle = loads(raw)
    receipts = receipt_payloads(bundle)
    still_digest = file_sha256(package / "01-copy" / pick["still"])

    # 02-verify, run 1 against the copied files, relative paths from the package root
    verify = package / "02-verify"
    verify.mkdir()
    at = meta["evaluated_at"]
    run1 = run_verifier(package, "01-copy/bundle.cbor", at, "01-copy/trust-policy.json", "01-copy/prior-state.json")
    (verify / "run1.stdout.txt").write_text(run1["stdout"])
    (verify / "run1.stderr.txt").write_text(run1["stderr"])
    pinned = {key: run1[key] for key in ("command", "exit", "result", "verdict_id", "bundle_digest", "selector_matching_receipts", "observations")}
    pinned.update(cwd="the package root (this directory's parent)", PYTHONPATH="the aar checkout named in 03-source-and-run.md",
                  evaluated_at=at, evaluated_at_source="01-copy/meta.json (a producer file)")
    decoded = decode_verdict(run1["verdict_cbor_hex"]) if run1["verdict_cbor_hex"] else None
    if decoded is not None:
        (verify / "run1.verdict.cbor").write_bytes(bytes.fromhex(run1["verdict_cbor_hex"]))
        pinned["verdict_kid"] = decoded["protected"][4].hex()
        pinned["verdict_cbor_sha256"] = sha256_hex(bytes.fromhex(run1["verdict_cbor_hex"]))
    (verify / "run1.json").write_text(json_text(pinned))
    (verify / "README.md").write_text(page_02(pinned, at))

    # 03
    (package / "03-source-and-run.md").write_text(page_03(run1, pinned, files, still_digest))

    # 04
    records = package / "04-operator-records"
    records.mkdir()
    window = _window(bundle)
    invocation_ids = {r["freshness"]["invocation_id"].hex() for r in receipts if isinstance(r.get("freshness", {}).get("invocation_id"), bytes)}
    receipt_ids = {r["receipt_id"].hex() for r in receipts}
    for name in LOG_NAMES:
        source = find_log(logs, name)
        companion = [f"# {name} — companion", "",
                     "Operator record, same administrative domain as the producer, not AAR custody "
                     "(`custody_continuity: not_established` is signed on every verdict).", "",
                     f"Selection rule: {LOG_RULES[name]}. Selector window: {window[0]}..{window[1]} (producer host clock)."]
        if name == "journal.jsonl":
            companion.append(f"Journal keys for this specimen: invocation ids {sorted(invocation_ids)}; receipt ids {sorted(receipt_ids)}.")
        companion.append("")
        if source is None:
            companion += [f"Missing-file behaviour: `{name}` was not found under the logs path (checked `{name}` and `aar/{name}`). "
                          "Nothing was copied and nothing was fabricated; this companion is the only output for this log."]
        else:
            raw_log = source.read_bytes()
            kept = select_lines(name, raw_log, window, invocation_ids, receipt_ids)
            (records / name).write_bytes(b"".join(line for _, line in kept))
            companion += [f"Source: `{source}` ({len(raw_log)} bytes, SHA-256 `{sha256_hex(raw_log)}`, "
                          f"{len(raw_log.splitlines())} lines).",
                          f"Kept {len(kept)} line(s), byte for byte, source line numbers {[n for n, _ in kept]}; "
                          f"written to `{name}` in this directory. Lines that do not parse as a JSON object are never kept.",
                          "Missing-file behaviour: had the source been absent, no file would be written and this companion would say so."]
        (records / f"{name}.md").write_text("\n".join(companion) + "\n")
    (records / "legal-maps.md").write_text(legal_maps(receipts))

    # 05
    texts, payloads = text_rows(bundle)
    payload_dir = package / "05-payloads"
    payload_dir.mkdir()
    for index, row in enumerate(payloads):
        if row["path"].split(".")[-1].split("[")[0] in EMBEDDED_KEYS:
            row["file"] = f"05-payloads/{index:03d}-{re.sub(r'[^A-Za-z0-9_]+', '-', row['path'])[-80:]}.bin"
            (package / row["file"]).write_bytes(row["bytes"])
    (package / "05-text-fields.md").write_text(page_05(texts, payloads, body=True))
    (package / "appendix" / "text-fields-zero.md").write_text(page_05(texts, payloads, body=False))

    # 06, 07, appendix
    (package / "06-worksheet-902-14.md").write_text(page_06(pinned, decoded, acquisition, files, still_digest))
    (package / "07-questions.md").write_text(page_07(pick, decoded))
    (package / "appendix" / "prohibited-claims.md").write_text(prohibited_claims())

    # 00
    (package / "00-READ-FIRST.md").write_text(
        page_00(facts, pick, run1, pinned, decoded, bundle, receipts, trust_policy, still_digest))

    # inventory last, then the tarball
    inventory = []
    for file in sorted(p for p in package.rglob("*") if p.is_file()):
        rel = file.relative_to(package).as_posix()
        inventory.append({"path": rel, "byte_length": file.stat().st_size, "sha256": file_sha256(file)})
    (package / "01-copy" / "inventory.json").write_text(json_text({
        "_doc": "Inventory for recomputation, not a copy foundation. Unsigned. Scope: every file distributed in this "
                "package directory except this file. The copy foundation is 01-copy/acquisition.json.",
        "files": inventory}))
    tarball = out / f"{PACKAGE_NAME}.tar.gz"
    write_tarball(package, tarball, mtime=at)
    (out / f"{PACKAGE_NAME}.tar.gz.sha256").write_text(f"{file_sha256(tarball)}  {tarball.name}\n")
    print(f"specimen: {pick['dir']}")
    print(f"run 1: exit {run1['exit']} Result {run1['result']} verdict_id {run1['verdict_id']} bundle_digest {run1['bundle_digest']}")
    print(f"tarball: {tarball} sha256 {file_sha256(tarball)}")
    return 0 if run1["exit"] == 0 else 1


def write_tarball(package: Path, tarball: Path, mtime: int) -> None:
    """Sorted entries, uid/gid 0, empty names, fixed mtime, gzip without name or timestamp."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(package.rglob("*"), key=lambda p: p.relative_to(package).as_posix()):
            info = tar.gettarinfo(path, arcname=f"{PACKAGE_NAME}/{path.relative_to(package).as_posix()}")
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = mtime
            info.mode = 0o755 if path.is_dir() else 0o644
            if path.is_file():
                with open(path, "rb") as handle:
                    tar.addfile(info, handle)
            else:
                tar.addfile(info)
    with open(tarball, "wb") as handle, gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as gz:
        gz.write(buffer.getvalue())


# --- pages ---------------------------------------------------------------------------------

OPENING = ("This report checks specified artifact signatures, commitments and conformance rules under the supplied "
           "trust, history and evaluation-time inputs. It does not establish source truth, complete activity, camera "
           "capture time, custody or admissibility. Demo-generated narrative fields are identified below.")

LIMIT_GLOSS = {
    "custody_continuity": "receipt signatures, anchors and countersignatures do not establish custody continuity (CONFORMANCE.md:1106-1109)",
    "legal_admissibility": "the verifier establishes nothing about admissibility in any forum",
    "source_authenticity": "no sensor, device or capture truth is established",
    "technical_integrity": "structural, cryptographic, graph, policy, freshness and coverage checks under the exact inputs named",
    "discovery_completeness": "producer-declared completeness relative to signed manifest indexes, nothing more",
    "control_path_completeness": "an action dispatched around the enforcement point produces no receipt; nothing shows none occurred (D-84)",
    "input_origin_ancestry": "origin labels are relayed, not checked against prompt, retrieval or tool manifest bytes (D-78)",
    "retained_manifest_membership": "no retained epochs were supplied by a relying party for this run",
    "maximum_time_class": "receipt time evidence class; `asserted` is the producer host's own clock",
    "maximum_provenance_class": "inference provenance class; `self_asserted` is the producer's own declaration",
    "maximum_outcome_level": "`device_acknowledged` is the device's response as the producer recorded it, not an independent sensing",
    "requested_profile": "the profile the producer claimed",
    "evaluated_profile": "the profile the verifier evaluated the bundle against",
}


def page_00(facts, pick, run1, pinned, decoded, bundle, receipts, trust_policy, still_digest) -> str:
    verdict = decoded["verdict"] if decoded else None
    lines = ["# 00 — READ FIRST", "", OPENING, "", f"Specimen: `{pick['dir']}` — {facts['specimen_kind']}", ""]
    lines += ["## 1. Limits", ""]
    if verdict is None:
        lines.append(f"The verifier produced no verdict (exit {run1['exit']}); see 02-verify/run1.stderr.txt.")
    else:
        limits = verdict["limits"]
        order = [*LIMITS_FIRST, *(key for key in limits if key not in LIMITS_FIRST)]
        lines += [f"- `{key}` = `{limits[key]}` — {LIMIT_GLOSS.get(key, '')}" for key in order]
    selector = bundle["selector"]
    lines += ["", "## 2. Coverage and completeness", "",
              f"- Selector scope: tenant `{selector['tenant_id'].hex()}`, site `{selector['site_id'].hex()}`, "
              f"committed {selector['committed_from']}..{selector['committed_until']}, kinds {selector['receipt_kinds']}, "
              f"subject ids {[s.hex() for s in selector.get('subject_ids', [])]}, correlation ids "
              f"{[c.hex() for c in selector.get('correlation_ids', [])]}.",
              f"- Matching receipt count: {pinned['selector_matching_receipts']} (carried receipts: {len(receipts)}).",
              f"- Requested profile `{verdict['limits']['requested_profile'] if verdict else 'n/a'}`, evaluated profile "
              f"`{verdict['limits']['evaluated_profile'] if verdict else 'n/a'}`.",
              "- Observations emitted: " + (", ".join(f"`{o['name']}` ({'signed' if o['signed'] else 'report layer, not signed'})"
                                                   for o in pinned["observations"]) or "none") + ".",
              f"- Coverage `{bundle['coverage']}`: " + (f"{facts['coverage_sentence']}; `discovery_completeness = "
              f"{verdict['limits']['discovery_completeness']}`; ingress completeness and control-path completeness not "
              "established (CONFORMANCE.md:944)." if bundle["coverage"] == "complete" and verdict else
              "not `complete`; the coverage sentence for a complete specimen does not apply.")]
    hazard = any(r.get("body", {}).get("action", {}).get("hazard_class") == "life_safety" for r in receipts if isinstance(r.get("body", {}).get("action"), dict))
    lines += ["", "## 3. The D-66 exception", "", facts["d66_sentence"],
              f"This specimen carries `hazard_class: \"life_safety\"`: {'yes' if hazard else 'no'}. "
              f"The pinned trust policy carries a `life_safety_action_names` entry: "
              f"{'yes' if 'life_safety_action_names' in trust_policy else 'no'} (aar-core.cddl:493,1190).",
              "", "## 4. Specimen facts", ""]
    lines += [f"- **{fact['label']}** — {fact['text']} ({fact['ref']})" for fact in facts["facts"]]
    dispatch, observed = media_digests(bundle)
    lines += ["", "## 5. Media", "",
              f"Still `01-copy/{pick['still']}`, SHA-256 `{still_digest}`. Committed digests: dispatch "
              f"`target_response_body_digest` {sorted(d.hex() for d in dispatch)}; outcome-observation "
              f"`observation_commitment` {sorted(o.hex() for o in observed)}. "
              f"Equal to the still: {'yes' if dispatch | observed == {bytes.fromhex(still_digest)} else 'NO'}. "
              "Receipts carrying them: " + ", ".join(f"`{r['receipt_id'].hex()}` ({r['kind']})" for r in receipts
                                                      if r.get("kind") in ("dispatch", "outcome_observation")) + ".",
              "A recompressed derivative fails this identity test; no similarity threshold exists or will be added.",
              "", "## 6. Result", ""]
    if verdict is None:
        lines += [f"- Verifier exit `{run1['exit']}`; Result `{run1['result']}`; stderr: `{run1['stderr'].strip()}`"]
    else:
        lines += [f"- Result: `{run1['result']}` (verifier exit `{run1['exit']}`)",
                  f"- verdict_id: `{run1['verdict_id']}`",
                  f"- bundle_digest: `{run1['bundle_digest']}`",
                  f"- Evaluation time: `{pinned['evaluated_at']}`, from `01-copy/meta.json`, a producer file; the verifier "
                  "never reads a clock.",
                  "- Verifier identity for this run: the published corpus test key (`kid` "
                  f"`{pinned['verdict_kid']}`), not an operational identity. Run 3 in `02-verify/README.md` is the "
                  "examiner's own-key run."]
    lines += ["", "Prohibited claims: `appendix/prohibited-claims.md` (admissibility crosswalk section 5).",
              "", "Reading order: `01-copy/` → `02-verify/` → `03-source-and-run.md` → `04-operator-records/` → "
              "`05-text-fields.md` → `06-worksheet-902-14.md` → `07-questions.md` → `appendix/`.", ""]
    return "\n".join(lines)


def page_02(pinned, at) -> str:
    cmd = " ".join(pinned["command"])
    return f"""# 02 — verify

Producer-supplied pins and history remain producer-supplied when passed through CLI options:
`01-copy/trust-policy.json`, `01-copy/prior-state.json` and the `--at` value from `01-copy/meta.json`
are the producer's files. The verifier (pyref, Python 3.11+, standard library only) is run as a
subprocess by the packager; the packager is not part of the verifier.

## Run 1 — pinned

From the package root, with `PYTHONPATH` set to the aar checkout at the commit in
`03-source-and-run.md` (bootstrap: `git clone https://github.com/oneshot2001/aar && cd aar && git checkout <commit>`):

```
{cmd}
```

| pinned | value |
|---|---|
| exit code | `{pinned['exit']}` |
| Result | `{pinned['result']}` |
| verdict_id | `{pinned['verdict_id']}` |
| bundle_digest | `{pinned['bundle_digest']}` |
| verdict kid (corpus test key) | `{pinned.get('verdict_kid')}` |
| raw envelope | `run1.verdict.cbor` (SHA-256 `{pinned.get('verdict_cbor_sha256')}`) |
| stdout / stderr | `run1.stdout.txt` / `run1.stderr.txt` |

`run1.json` holds the same values as data.

## Run 3 — the examiner's own key

The examiner mints a chain and runs the same verifier under `--policy` and `--signing-key`.
A self-issued chain establishes key control, not the examiner's identity or the verifier's
correctness. Private keys never enter the package.

Mint (from the aar checkout; stdlib `secrets` for the scalars):

```
python3 -B -m pyref.examiner_package.mint_examiner_chain --out KEYS --at {at} \\
    --trust-policy 01-copy/trust-policy.json
```

What it does, in full: draws two P-256 scalars `1 <= d < n` with `secrets.randbelow`; writes
`KEYS/examiner-root.key` and `KEYS/examiner.key` (64 lowercase hex characters then LF, mode 0600,
created exclusively); derives each SPKI (DER, 91 bytes) and `kid = SHA-256(SPKI)`; builds a
self-signed root credential (`key_usage credential_issuing`, `principal_role authority_source`,
empty `path`) and a leaf (`key_usage verifier_signing`, `principal_role verifier`, `path =
[root credential_id]`), both `principal_type service`, `tenant_id` and `site_id` sixteen zero
bytes, `trust_anchor_id = SHA-256("AAR-EXAMINER-TRUST-ANCHOR-v1" || root kid)`,
`valid_from = {at} - 86400`, `valid_until = {at} + 30*86400` (chosen to cover the historical
`--at`; the examiner states this choice), `profile_limits` AAR-1 constants; `credential_id =
SHA-256(deterministic-CBOR(["AAR-CREDENTIAL-ID-v1", fields without credential_id]))`; signs each
with COSE_Sign1 (protected `{{1: -7, 3: "application/aar-credential+cbor;v=0.2", 4: issuer kid}}`,
detached payload, RFC 6979 ES256, low-S, P1363 r||s); orders `verifier_credentials` by
`credential_id` and `artifact_roots` by `root_kid`; writes `KEYS/examiner-policy.json` with
`v: 1`, `artifact_roots` copied from the producer's pinned `trust_store.roots` (a policy narrows
trust and never widens it: the carried credentials must still chain to a listed root),
`verifier_root_kid` and the two credential envelopes as hex; prints both kids and the policy digest
`SHA-256(deterministic-CBOR(["AAR-RP-POLICY-v1", policy]))`.

Run:

```
{cmd} --policy KEYS/examiner-policy.json --signing-key KEYS/examiner.key > run3.stdout.txt
python3 -B -m pyref.examiner_package.check_run3 --stdout run3.stdout.txt --policy KEYS/examiner-policy.json --run1 run1.json
```

The five acceptance checks (`check_run3` prints each as PASS or FAIL):

1. the verdict signature verifies under the examiner's leaf public key;
2. the leaf `kid` is the `kid` in the verdict's protected header;
3. `relying_party_policy_digest` equals the policy digest recomputed from `examiner-policy.json`;
4. `bundle_digest` equals run 1's;
5. `Result` equals run 1's.

The verdict id is not pinned: a fresh kid changes the preimage (`pyref/verdict.py:128-131`).
Independent signature check with a second tool: `check_run3` writes `run3.sig_structure.bin`,
`run3.leaf-spki.der` and `run3.signature.der` beside the stdout file; then
`openssl pkey -pubin -inform DER -in run3.leaf-spki.der -out leaf.pem && openssl dgst -sha256 -verify leaf.pem -signature run3.signature.der run3.sig_structure.bin`.

Known limit: the relying-party chain has no revocation (D-83 part 10); a compromised examiner key
can sign verdicts asserting any evaluation time inside its window.

## Run 2 — optional, harness

Stateless experiment, no history or pin inputs (`harness/verify.ts:14` accepts neither
`--prior-state` nor `--trust-policy`). It is a second implementation, never corroboration of run 1:

```
bun install --frozen-lockfile && bun run harness/verify.ts 01-copy/bundle.cbor --at {at}
```
"""


def page_03(run1, pinned, files, still_digest) -> str:
    head = git("rev-parse", "HEAD")
    tag_object = git("rev-parse", "v0.4.0")
    tag_target = git("rev-parse", "v0.4.0^{}")
    head_tree = git("rev-parse", "HEAD:pyref")
    tag_tree = git("rev-parse", "v0.4.0^{}:pyref")
    status = git("status", "--porcelain")
    executable = Path(sys.executable).resolve()
    rows = source_inventory()
    lines = ["# 03 — source and run", "",
             "This section identifies the source that was supplied and records the claimed conditions under which it ran. "
             "It does not prove which code executed.", "",
             "## Source identifiers (labels from the build host's git)", "",
             f"- commit at package time (the declared bootstrap target): `{head}`",
             f"- tag `v0.4.0`: tag object `{tag_object}` → commit `{tag_target}`; Git object format `{git('rev-parse', '--show-object-format')}`",
             f"- `pyref/` tree at package time `{head_tree}`; at `v0.4.0` `{tag_tree}`; equal: {'yes' if head_tree == tag_tree else 'no'}"
             " (`git rev-parse COMMIT:pyref` names the stored tree, not working files; working files are hashed below).",
             f"- working tree status (`git status --porcelain`): " + (f"\n```\n{status}\n```" if status else "clean, no untracked files"),
             "- builder label: the collector named in `01-copy/acquisition.json`; verifier identity for run 1: the published "
             "corpus test key (unauthenticated labels, both).",
             "", "## Interpreter and platform", "",
             f"- `sys.executable`: `{sys.executable}` → `{executable}`, SHA-256 `{file_sha256(executable)}`",
             f"- Python `{platform.python_version()}` ({sys.version.split()[0]}, {platform.python_implementation()})",
             f"- platform: `{platform.platform()}`, machine `{platform.machine()}`",
             "", "## Exact command and inputs", "",
             f"- cwd: the package root; `PYTHONPATH`: the aar checkout at `{head}`",
             f"- `{' '.join(pinned['command'])}`",
             f"- inputs: " + "; ".join(f"`01-copy/{f['name']}` {f['byte_length']} bytes SHA-256 `{f['destination_sha256']}`" for f in files),
             f"- exit `{run1['exit']}`; stdout `02-verify/run1.stdout.txt` (SHA-256 `{sha256_hex(run1['stdout'].encode())}`); "
             f"stderr `02-verify/run1.stderr.txt` (SHA-256 `{sha256_hex(run1['stderr'].encode())}`); raw verdict envelope "
             f"`02-verify/run1.verdict.cbor` (SHA-256 `{pinned.get('verdict_cbor_sha256')}`)",
             "", "## Source inventory (working files, hashed at package time)", "",
             "| path | mode | bytes | sha256 | blob at package commit | vs v0.4.0 |", "|---|---|---|---|---|---|"]
    lines += [f"| `{r['path']}` | {r['mode']} | {r['bytes']} | `{r['sha256']}` | `{r['blob']}` | {r['vs_v0_4_0']} |" for r in rows]
    lines += ["", "## Offline tag check", "",
              "`git tag -v v0.4.0` needs the tag and its object closure, the tagger's SSH public key, an `allowed_signers` "
              "file naming it, and a fingerprint obtained independently of this package. It proves the tag's assertions "
              "(which commit the tagger signed) and nothing about CI execution.",
              "", "## Absent, in writing", "",
              "No release assets, no SBOM, no provenance attestation, no reproducible build (threat model R-37). "
              "Fuzz-run reports and CI history are not cited as evidence of which code ran.", ""]
    return "\n".join(lines)


def legal_maps(receipts) -> str:
    lines = ["# Receipt `legal` maps", "",
             "Each carried receipt's `legal` map, decoded. These are demo constants written by the producer; `legal_hold` "
             "is a boolean, not a hold identifier; no retention or hold record exists for this specimen.", "",
             "| receipt_id | kind | purpose_id | jurisdiction_id | data_classification_id | retention_class_id | legal_hold |",
             "|---|---|---|---|---|---|---|"]
    for r in receipts:
        legal = r.get("legal", {})
        lines.append(f"| `{r['receipt_id'].hex()}` | {r.get('kind')} | {visible(str(legal.get('purpose_id')))} | "
                     f"{visible(str(legal.get('jurisdiction_id')))} | {visible(str(legal.get('data_classification_id')))} | "
                     f"{visible(str(legal.get('retention_class_id')))} | {legal.get('legal_hold')} |")
    return "\n".join(lines) + "\n"


def page_05(texts, payloads, body: bool) -> str:
    nonzero = [t for t in texts if t["invisible"]]
    zero = [t for t in texts if not t["invisible"]]
    not_decoded = [p for p in payloads if not p["decoded"]]
    ranges = ", ".join(f"U+{lo:04X}" + (f"–U+{hi:04X}" if hi != lo else "") for lo, hi in INVISIBLE_RANGES)
    header = [
        "# 05 — text fields" if body else "# Appendix — text fields with zero findings", "",
        f"Contract. Traversal of the decoded bundle (`01-copy/bundle.cbor`), not a schema whitelist: every text key and "
        "value, with envelope payloads, COSE structures and protected headers decoded, and the byte strings "
        "`parameters_cbor`, `canonical_command`, `canonical_cbor` and `canonical_bytes` decoded where they decode as "
        "deterministic CBOR. Unicode data version `" + unicodedata.unidata_version + f"` (Python {platform.python_version()}). "
        f"Counted set, by inclusive range: {ranges}. Positions are zero-based code-point indexes. Escaped form: every code "
        "point outside printable ASCII as `\\uXXXX`, supplementary-plane as `\\u{XXXXX}`, backslash as `\\\\`. Visible "
        "column: counted and C0/C1/DEL control code points replaced by their escape, Markdown-active ASCII backslash-escaped, "
        "so no active control reaches the reader. Nothing is normalized or stripped; raw bytes stay in `01-copy/bundle.cbor`.", ""]
    table = ["| path | visible | invisible count | positions | escaped |", "|---|---|---|---|---|"]
    rows = nonzero if body else zero
    for t in rows:
        positions = ", ".join(f"{i}:{escape_code(c)}" for i, c in t["invisible"]) or "—"
        table.append(f"| `{t['path']}` | {visible(t['text'])} | {len(t['invisible'])} | {positions} | `{escaped(t['text'])}` |")
    if not rows:
        table = ["(none)"]
    if not body:
        return "\n".join(header + [f"{len(zero)} rows, zero invisible code points each.", "", *table]) + "\n"
    lines = header + [f"Text rows: {len(texts)}; rows with invisible code points: {len(nonzero)} (below); rows with zero "
                      f"findings: {len(zero)} (`appendix/text-fields-zero.md`); embedded payloads decoded: "
                      f"{len(payloads) - len(not_decoded)}; not decoded: {len(not_decoded)}.", "",
                      "## Rows with invisible code points", "", *table, "",
                      "## Not decoded (opaque payloads, listed separately from decoded-with-zero-findings)", ""]
    lines += [f"- `{p['path']}`: {len(p['bytes'])} bytes, SHA-256 `{sha256_hex(p['bytes'])}`, {p['error']}"
              + (f", extracted to `{p['file']}`" if p.get("file") else "") for p in not_decoded] or ["(none)"]
    lines += ["", "## Extracted payloads (for access; the escrow is `01-copy/bundle.cbor`)", ""]
    lines += [f"- `{p['file']}` ← `{p['path']}`, {len(p['bytes'])} bytes, SHA-256 `{sha256_hex(p['bytes'])}`, "
              f"{'decoded' if p['decoded'] else 'not decoded'}" for p in payloads if p.get("file")]
    lines += ["", "## Schema evidence", "",
              "No CDDL schema check was run on this specimen. The release oracle (D-74, `spec/DECISIONS.md`) covers the "
              "fixtures and the demo bundles, not this bundle; the verifier's runtime checks are the only schema evidence "
              "here and they are what run 1 reports.", ""]
    return "\n".join(lines)


def page_06(pinned, decoded, acquisition, files, still_digest) -> str:
    limits = decoded["verdict"]["limits"] if decoded else {}
    hashes = "; ".join(f"`{f['name']}` `{f['destination_sha256']}`" for f in files)
    return f"""# 06 — worksheet, FRE 902(14)

DRAFT. Not reviewed by counsel. A verifier report is not a 902(13)/(14) certification. Federal 902(14)
needs a qualified person's certification and notice and inspection; a Pennsylvania state court applies
Frye to the expert method under Pa.R.E. 702. These are separate questions.

| field | software-filled (from the signed record and the acquisition record) | sworn (left blank) |
|---|---|---|
| hash set | {hashes}; still `{still_digest}`; verdict `bundle_digest` `{pinned['bundle_digest']}`; full list `01-copy/inventory.json` | |
| copy process | {acquisition.get('copy_method')}; collection time `{acquisition.get('collection_time_utc')}` (build host clock, a label); source `{acquisition.get('source', {}).get('repo_path')}` | |
| tool versions | {json.dumps(acquisition.get('tool_versions'), sort_keys=True)}; platform `{acquisition.get('platform')}` | |
| verifier identity | run 1: published corpus test key, kid `{pinned.get('verdict_kid')}`; run 3: the examiner's own leaf (not pinned here) | |
| time evidence class | `maximum_time_class = {limits.get('maximum_time_class')}`; evaluation time `{pinned['evaluated_at']}` from a producer file | |
| spec version | wire `application/aar-receipt+cbor;v=0.2`, verdict `application/aar-verdict+cbor;v=0.4` (v 6), verifier pyref `v0.4.0` | |
| who can certify collection | the collector label is "{acquisition.get('source', {}).get('collector_label')}" (a label, not a certification) | name: |
| who can explain verification | — | name: |
| qualified person's statement | — | |
| notice given / inspection offered | — | date: |
"""


def page_07(pick, decoded) -> str:
    time_class = decoded["verdict"]["limits"]["maximum_time_class"] if decoded else "n/a"
    return f"""# 07 — the nine questions (2026-10-20)

Each item of evidence an answer relies on is marked **supplied** (with its package path), **unavailable**
(it does not exist for this specimen) or **not collected** (it may exist but is not in this package).

1. **Keep the yes or no with the hash.** Signature and digest checks — supplied: `02-verify/run1.*`, `01-copy/inventory.json`. No similarity score is used anywhere; the still match is an exact SHA-256 identity (`00-READ-FIRST.md` section 5).
2. **Matching stills to frames.** Exact still digest equal to both committed digests — supplied: `01-copy/{pick['still']}`, `00-READ-FIRST.md` section 5. Frame-correspondence evidence — unavailable (this still is a single-JPEG fetch; no video exists for it). A recompressed derivative fails the identity test; there is no threshold.
3. **The footage.** The file is unchanged since the producer committed its digest — supplied (`02-verify`). Camera clock correctness, aim, and what the scene shows — unavailable; `source_authenticity: not_established` is signed on the verdict.
4. **The timestamp.** Receipt times come from the producer host's clock (`maximum_time_class = {time_class}`) — supplied as that label. Independent time evidence — unavailable.
5. **Context.** Camera model and firmware as the producer recorded them — supplied (`05-text-fields.md`, `source_device`/`observer`). Camera settings, position, a second camera, or any context from a source the producer does not control — not collected.
6. **The agent log.** Operator records — supplied: `04-operator-records/` (same administrative domain as the producer, not AAR custody). Explicit refusals are wire-emitted when they occur, but refusals do not enumerate unattempted actions; off-ontology tool calls are in other logs (onvif-mcp `docs/aar-alignment.md:91`) — not collected.
7. **The AI's instructions.** The inference receipt's prompt, retrieval and transcript manifests are producer-generated placeholders (`00-READ-FIRST.md` section 4, `05-payloads/`) — supplied as placeholders. The AI's actual instructions and conversation — not collected.
8. **The keys and the checker.** Key holders: per-agent key directories under one administration (`00-READ-FIRST.md` section 4) — supplied as a label. The checker: run 3 lets the examiner sign under their own key (`02-verify/README.md`); which verifier code ran is identified, not proven (`03-source-and-run.md`). Independent testing of the verifier by a party other than its author — unavailable.
9. **Admissibility.** `legal_admissibility: not_established` is signed on every verdict. The 902(14) worksheet is a draft with sworn fields blank (`06-worksheet-902-14.md`). Frye/Daubert material (error rate, general acceptance, peer review) — unavailable.
"""


def prohibited_claims() -> str:
    text = (REPO / "docs" / "admissibility-crosswalk-v0.1.md").read_text(encoding="utf-8")
    start = text.index("## 5. Prohibited claims")
    end = text.index("\n## ", start + 1)
    return ("# Appendix — prohibited claims\n\nCopied from `docs/admissibility-crosswalk-v0.1.md` section 5 at the commit "
            "named in `03-source-and-run.md`.\n\n" + text[start:end].strip() + "\n")
