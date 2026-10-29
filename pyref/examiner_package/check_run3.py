"""Run-3 acceptance as a controlled invocation (spec amendments a, i, k).

    python3 -B -m pyref.examiner_package.check_run3 --keys DIR --run1 02-verify/run1.json [--stdout FILE]

Default: this program runs the verifier itself — ``python3 -B -m pyref verify 01-copy/bundle.cbor
--at <01-copy/meta.json> --trust-policy 01-copy/trust-policy.json --prior-state 01-copy/prior-state.json
--policy KEYS/examiner-policy.json --signing-key KEYS/examiner.key`` from the package root — captures
the complete stdout (written to ``KEYS/run3.stdout.txt``) and checks what it captured. With
``--stdout FILE`` a pasted transcript is checked instead and the output is headed UNVERIFIED
TRANSCRIPT: the inputs used for that run are not established by this check.

Lines: (1) policy and key pass ``pyref.relying_party.load_configuration``; (2) signature under the
examiner's leaf; (3) leaf kid in the protected header; (4) policy digest; (5) evaluated_at,
(6) bundle_digest, (7) result, (8) signed trust values (except relying_party_policy_digest),
(9) limits, (10) observations equal run 1's verdict; (11) no report-layer marker in the stdout.
Exports (``run3.sig_structure.bin``, ``run3.leaf-spki.der``, ``run3.signature.der``) are written
beside the keys, never inside the package. Exit codes: 0 every line passed in controlled mode; 1 a
line failed; 2 usage error (bad or missing input); 3 transcript mode (``--stdout``), whatever the
lines say; a usage error still exits 2.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import relying_party
from ..cbor import dumps, loads
from ..crypto import public_spki, verify_es256
from .core import REPORT_LAYER_MARKERS, PackageError, decode_verdict, parse_report, read_json, run_verifier

UNVERIFIED = "UNVERIFIED TRANSCRIPT: the inputs used for this run are not established by this check"


def der_signature(signature: bytes) -> bytes:
    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\x00") or b"\x00"
        if value[0] & 0x80:
            value = b"\x00" + value
        return b"\x02" + bytes([len(value)]) + value
    body = integer(signature[:32]) + integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def controlled_run(keys: Path, package: Path) -> dict:
    """Invoke the verifier with the package sidecars and the examiner's key; keep the raw stdout."""
    at = read_json(package / "01-copy" / "meta.json", "meta.json")["evaluated_at"]
    run = run_verifier(package, "01-copy/bundle.cbor", at, "01-copy/trust-policy.json", "01-copy/prior-state.json",
                       str((keys / "examiner-policy.json").resolve()), str((keys / "examiner.key").resolve()))
    (keys / "run3.stdout.txt").write_text(run["stdout"], encoding="utf-8", newline="\n")
    (keys / "run3.stderr.txt").write_text(run["stderr"], encoding="utf-8", newline="\n")
    return run


def check(keys: Path, run1_path: Path, stdout_path: Path | None = None) -> list[tuple[str, bool, str]]:
    package = run1_path.resolve().parent.parent
    run1_verdict = loads(loads((run1_path.parent / "run1.verdict.cbor").read_bytes())[0])
    if stdout_path is None:
        run = controlled_run(keys, package)
        results = [("0 controlled invocation", run["exit"] == 0,
                    f"exit {run['exit']}; " + " ".join(run["command"]) + f" (cwd: package root; stdout: {keys / 'run3.stdout.txt'})")]
        report = {key: run[key] for key in ("result", "verdict_cbor_hex", "report_layer_markers")}
    else:
        results = []
        report = parse_report(stdout_path.read_text(encoding="utf-8"))
    at = run1_verdict["evaluated_at"]
    try:
        configuration = relying_party.load_configuration(keys / "examiner-policy.json", keys / "examiner.key", at)
        results.append(("1 policy and key pass the verifier's chain logic (load_configuration)", True, f"leaf kid {configuration.kid.hex()}"))
    except relying_party.UsageError as exc:
        return results + [("1 policy and key pass the verifier's chain logic (load_configuration)", False, str(exc))]
    if not report["verdict_cbor_hex"]:
        return results + [("2 verdict present in the run-3 stdout", False, "no `CBOR hex:` line")]
    decoded = decode_verdict(report["verdict_cbor_hex"])
    verdict, protected = decoded["verdict"], decoded["protected"]
    leaf_spki = public_spki(configuration.scalar)
    sig_structure = dumps(["Signature1", decoded["protected_bytes"], b"", decoded["payload_bytes"]])
    trust_keys = sorted(set(run1_verdict["trust_policy"]) | set(verdict["trust_policy"]))
    trust_diff = [key for key in trust_keys if key != "relying_party_policy_digest"
                  and run1_verdict["trust_policy"].get(key) != verdict["trust_policy"].get(key)]
    results += [
        ("2 signature verifies under the examiner's leaf public key", verify_es256(leaf_spki, sig_structure, decoded["signature"]),
         f"SPKI sha256 = kid {configuration.kid.hex()}"),
        ("3 leaf kid is the verdict's protected kid", protected.get(4) == configuration.kid, f"protected kid {protected.get(4, b'').hex()}"),
        ("4 relying_party_policy_digest equals the recomputed policy digest",
         verdict["trust_policy"]["relying_party_policy_digest"] == configuration.policy_digest, f"policy digest {configuration.policy_digest.hex()}"),
        ("5 evaluated_at equals run 1", verdict["evaluated_at"] == run1_verdict["evaluated_at"], f"evaluated_at {verdict['evaluated_at']}"),
        ("6 bundle_digest equals run 1", verdict["bundle_digest"] == run1_verdict["bundle_digest"], f"bundle_digest {verdict['bundle_digest'].hex()}"),
        ("7 result equals run 1", verdict["result"] == run1_verdict["result"] == report["result"], f"Result {verdict['result']}"),
        ("8 signed trust values equal run 1 (the use of the pin file is established by the controlled invocation, not by this equality)",
         not trust_diff, "differs: " + ", ".join(trust_diff) if trust_diff else ", ".join(key for key in trust_keys if key != "relying_party_policy_digest")),
        ("9 limits equal run 1", verdict["limits"] == run1_verdict["limits"], json.dumps(verdict["limits"], sort_keys=True)),
        ("10 observations equal run 1", verdict["observations"] == run1_verdict["observations"], str(verdict["observations"])),
        ("11 no report-layer marker in the run-3 stdout", not report["report_layer_markers"],
         "found " + ", ".join(report["report_layer_markers"]) if report["report_layer_markers"] else f"none of {list(REPORT_LAYER_MARKERS)}"),
        ("verdict_id (not pinned)", True, verdict["verdict_id"].hex()),
    ]
    (keys / "run3.verdict.cbor").write_bytes(bytes.fromhex(report["verdict_cbor_hex"]))
    (keys / "run3.sig_structure.bin").write_bytes(sig_structure)
    (keys / "run3.leaf-spki.der").write_bytes(leaf_spki)
    (keys / "run3.signature.der").write_bytes(der_signature(decoded["signature"]))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pyref.examiner_package.check_run3", description=__doc__.splitlines()[0])
    parser.add_argument("--keys", required=True, type=Path, metavar="DIR", help="directory holding examiner-policy.json and examiner.key; outputs go here")
    parser.add_argument("--run1", required=True, type=Path, metavar="FILE", help="02-verify/run1.json (run1.verdict.cbor beside it; the package root is its grandparent)")
    parser.add_argument("--stdout", type=Path, metavar="FILE", help="check a pasted transcript instead of running the verifier (marked UNVERIFIED)")
    args = parser.parse_args(argv)
    if args.stdout is not None:
        print(UNVERIFIED)
    try:
        results = check(args.keys, args.run1, args.stdout)
    except (PackageError, OSError, ValueError, KeyError) as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2
    for name, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name}: {detail}")
    # Exit codes: 0 every line passed in controlled mode; 1 a line failed; 2 usage error;
    # 3 transcript mode (--stdout), whatever the lines say.
    if args.stdout is not None:
        return 3
    return 0 if all(passed for _, passed, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
