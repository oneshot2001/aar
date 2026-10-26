"""Differential-fuzz batch transport (Packet D). stdlib only.

``python3 -B -m pyref.batch [--premises]``: one handshake line, then one NDJSON
request per stdin line and exactly one response per request, in order, then
``{"done": N}``. With ``--premises`` every ``verifier._fail`` call and every
``CBORError`` construction is recorded by wrapping those two callables at
runtime from here; nothing inside the wrapped modules changes.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from pathlib import Path
from typing import Any

from . import cbor, verifier
from .cli import _trust_policy
from .relying_party import load_configuration

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ("pyref/verifier.py", "pyref/cbor.py", "pyref/relying_party.py", "pyref/emission_identity.py", "pyref/verdict.py", "pyref/batch.py")
IDENTITY_FIELDS = ("product", "version", "build_digest", "config_digest")

_sites: list[list[Any]] = []


def _relative(filename: str) -> str:
    try:
        return str(Path(filename).resolve().relative_to(ROOT))
    except ValueError:
        return filename


def _install_recorder() -> None:
    original_fail = verifier._fail
    original_init = cbor.CBORError.__init__

    def fail(code: str, step: int, *, indeterminate: bool = False) -> None:
        frame = sys._getframe(1)
        _sites.append([_relative(frame.f_code.co_filename), frame.f_lineno, code, step])
        original_fail(code, step, indeterminate=indeterminate)

    def init(self: cbor.CBORError, message: str, code: str = "cbor/malformed") -> None:
        frame = sys._getframe(1)
        _sites.append([_relative(frame.f_code.co_filename), frame.f_lineno, code, None])
        original_init(self, message, code)

    verifier._fail = fail  # relying_party calls verifier._fail by attribute, so it is covered too
    cbor.CBORError.__init__ = init  # type: ignore[method-assign]


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _identity() -> dict[str, str]:
    """The verifier identity pyref signs with, read off a verdict rather than retyped."""
    fields = verifier.evaluate(b"", evaluated_at=0).verdict["verifier"]
    _sites.clear()
    return {name: fields[name].hex() if isinstance(fields[name], bytes) else fields[name] for name in IDENTITY_FIELDS}


def _arguments(inputs: dict[str, Any]) -> dict[str, Any]:
    at = inputs["evaluated_at"]
    policy, key, pin = inputs["policy"], inputs["signing_key"], inputs["trust_policy"]
    return {
        "evaluated_at": at,
        "prior_state": inputs["prior_state"], "replay_state": inputs["replay_state"],
        "configuration": load_configuration(Path(policy), Path(key), at) if policy is not None else None,
        "configured_trust_policy": None if pin is None else _trust_policy(Path(pin)),
    }


def _respond(request: dict[str, Any], identity: dict[str, str], premises: bool) -> dict[str, Any]:
    request_id = request["id"]
    bundle_hex, context_hex = request["bundle_hex"], request["context_hex"]
    if request["identity"] != identity:
        return {"id": request_id, "protocol_error": "identity differs from this pyref's own"}
    raw = None if bundle_hex is None else bytes.fromhex(bundle_hex)
    context = None if context_hex is None else bytes.fromhex(context_hex)
    arguments = _arguments(request["inputs"])
    response: dict[str, Any] = {"id": request_id, "input_sha256": hashlib.sha256(raw or b"").hexdigest()}
    _sites.clear()
    try:
        evaluation = verifier.evaluate(raw, context_bundle_raw=context, **arguments)  # type: ignore[arg-type]
        response.update(result=evaluation.result, reason=evaluation.reason,
                        step=evaluation.report["first_failure_step"], verdict_hex=evaluation.verdict_bytes.hex())
    except Exception as exc:  # an exception escaping evaluate() on a well-formed request is the crash channel
        response["crash"] = {"type": type(exc).__name__, "message": str(exc)}
    if premises:
        response["sites"] = list(_sites)
    return response


def main(argv: list[str] | None = None) -> int:
    premises = "--premises" in (argv if argv is not None else sys.argv[1:])
    if premises:
        _install_recorder()
    identity = _identity()
    _emit({
        "hello": 1, "python": platform.python_version(), "checkout": str(ROOT / "pyref"),
        "hash_seed": os.environ.get("PYTHONHASHSEED"),
        "sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES},
        "identity": identity,
    })
    count = 0
    for line in sys.stdin:
        if not line.strip():
            continue
        request: Any = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise TypeError("request is not an object")
            response = _respond(request, identity, premises)
        except Exception as exc:  # malformed request line: the adapter channel's business
            response = {"protocol_error": f"{type(exc).__name__}: {exc}"}
            if isinstance(request, dict) and isinstance(request.get("id"), str):
                response["id"] = request["id"]
        _emit(response)
        count += 1
    _emit({"done": count})
    return 0


if __name__ == "__main__":
    sys.exit(main())
