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
import io
import platform
import re
import shutil
import tarfile
from pathlib import Path
from typing import Any

from ..cbor import loads
from .core import (LOG_NAMES, PACKAGE_NAME, REPO, SIDECARS, PackageError, decode_verdict, file_sha256, git,  # noqa: F401
                   json_text, media_digests, parse_report, read_json, receipt_payloads, run_verifier, select_specimen,
                   sha256_hex, sweep, window)
from .pages import OPENING, legal_maps, page_00, page_02, page_03  # noqa: F401
from .pages_tail import page_05, page_06, page_07, prohibited_claims
from .text import (EMBEDDED_KEYS, ENVELOPE_KEYS, INVISIBLE_RANGES, LOG_RULES, escape_code, escaped, find_log,  # noqa: F401
                   is_invisible, select_lines, text_rows, visible)


def source_inventory() -> list[dict[str, Any]]:
    """Every tracked file under pyref/ plus the two spec files: working-file hash, blob at HEAD, status vs v0.4.0."""
    paths = ("pyref", "spec/CONFORMANCE.md", "spec/aar-core.cddl")
    head_blobs = dict(line.split()[2:4][::-1] for line in git("ls-tree", "-r", "HEAD", *paths).splitlines())
    tag_blobs = dict(line.split()[2:4][::-1] for line in git("ls-tree", "-r", "v0.4.0", *paths).splitlines())
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
    keys = ("name", "byte_length", "source_sha256", "destination_sha256")
    if [{k: row[k] for k in keys} for row in files] != [{k: row.get(k) for k in keys} for row in record.get("files", [])]:
        raise PackageError("acquisition.json files do not match this copy; refresh the input from a fresh first build")
    return record


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
    files = copy_specimen(candidates / pick["dir"], stills / pick["still"], package / "01-copy")
    acquisition = fill_acquisition(acquisition_input, files, pick["dir"])
    (package / "01-copy" / "acquisition.json").write_text(json_text(acquisition))
    meta = read_json(package / "01-copy" / "meta.json", "meta.json")
    trust_policy = read_json(package / "01-copy" / "trust-policy.json", "trust-policy.json")
    bundle = loads((package / "01-copy" / "bundle.cbor").read_bytes())
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
    (package / "03-source-and-run.md").write_text(page_03(run1, pinned, files, source_inventory()))

    # 04
    records = package / "04-operator-records"
    records.mkdir()
    selector_window = window(bundle)
    invocation_ids = {r["freshness"]["invocation_id"].hex() for r in receipts if isinstance(r.get("freshness", {}).get("invocation_id"), bytes)}
    receipt_ids = {r["receipt_id"].hex() for r in receipts}
    for name in LOG_NAMES:
        source = find_log(logs, name)
        companion = [f"# {name} — companion", "",
                     "Operator record, same administrative domain as the producer, not AAR custody "
                     "(`custody_continuity: not_established` is signed on every verdict).", "",
                     f"Selection rule: {LOG_RULES[name]}. Selector window: {selector_window[0]}..{selector_window[1]} (producer host clock)."]
        if name == "journal.jsonl":
            companion.append(f"Journal keys for this specimen: invocation ids {sorted(invocation_ids)}; receipt ids {sorted(receipt_ids)}.")
        companion.append("")
        if source is None:
            companion += [f"Missing-file behaviour: `{name}` was not found under the logs path (checked `{name}` and `aar/{name}`). "
                          "Nothing was copied and nothing was fabricated; this companion is the only output for this log."]
        else:
            raw_log = source.read_bytes()
            kept = select_lines(name, raw_log, selector_window, invocation_ids, receipt_ids)
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
    (package / "05-payloads").mkdir()
    for index, row in enumerate(payloads):
        if row["path"].split(".")[-1].split("[")[0] in EMBEDDED_KEYS:
            row["file"] = f"05-payloads/{index:03d}-{re.sub(r'[^A-Za-z0-9_]+', '-', row['path'])[-80:]}.bin"
            (package / row["file"]).write_bytes(row["bytes"])
    (package / "05-text-fields.md").write_text(page_05(texts, payloads, body=True))
    (package / "appendix" / "text-fields-zero.md").write_text(page_05(texts, payloads, body=False))

    # 06, 07, appendix, 00
    (package / "06-worksheet-902-14.md").write_text(page_06(pinned, decoded, acquisition, files, still_digest))
    (package / "07-questions.md").write_text(page_07(pick, decoded))
    (package / "appendix" / "prohibited-claims.md").write_text(prohibited_claims())
    (package / "00-READ-FIRST.md").write_text(
        page_00(facts, pick, run1, pinned, decoded, bundle, receipts, trust_policy, still_digest))

    # inventory last, then the tarball
    inventory = [{"path": file.relative_to(package).as_posix(), "byte_length": file.stat().st_size, "sha256": file_sha256(file)}
                 for file in sorted(p for p in package.rglob("*") if p.is_file())]
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
