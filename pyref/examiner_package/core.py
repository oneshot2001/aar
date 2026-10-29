"""Core of the examiner package builder: constants, hashing, the verifier subprocess, bundle
access and the specimen rule (spec section 2). Never evaluates a bundle itself."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..cbor import loads

REPO = Path(__file__).resolve().parents[2]
SIDECARS = ("meta.json", "trust-policy.json", "prior-state.json")
LOG_NAMES = ("journal.jsonl", "anchor.jsonl", "chain.jsonl")
PACKAGE_NAME = "examiner-package-v0.1"


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


def git(*args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else ""


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


def window(bundle: dict[str, Any]) -> tuple[int, int]:
    selector = bundle["selector"]
    return selector["committed_from"], selector["committed_until"]


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
