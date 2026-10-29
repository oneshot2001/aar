"""Run-3 acceptance (spec amendment a): the examiner policy and key pass the verifier's own chain
logic (``pyref.relying_party.load_configuration``, the path ``pyref verify --policy`` takes); the
run-3 verdict equals run 1 on evaluated_at, bundle_digest, result, every trust_policy entry except
relying_party_policy_digest, limits and observations; no report-layer marker in run-3 stdout;
signature under the examiner's leaf, leaf kid in the protected header, policy digest recomputed.

    python3 -B -m pyref.examiner_package.check_run3 --stdout FILE --keys DIR --run1 02-verify/run1.json

Writes ``<stem>.sig_structure.bin``, ``<stem>.leaf-spki.der`` and ``<stem>.signature.der`` beside
the stdout file so a second tool (OpenSSL) can verify the same signature. Exit 0 only when every
line passes.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import relying_party
from ..cbor import dumps, loads
from ..crypto import public_spki, verify_es256
from .core import REPORT_LAYER_MARKERS, decode_verdict, parse_report


def der_signature(signature: bytes) -> bytes:
    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\x00") or b"\x00"
        if value[0] & 0x80:
            value = b"\x00" + value
        return b"\x02" + bytes([len(value)]) + value
    body = integer(signature[:32]) + integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def check(stdout_path: Path, keys: Path, run1_path: Path) -> list[tuple[str, bool, str]]:
    stdout = stdout_path.read_text(encoding="utf-8")
    report = parse_report(stdout)
    run1 = json.loads(run1_path.read_text(encoding="utf-8"))
    run1_verdict = loads(loads((run1_path.parent / "run1.verdict.cbor").read_bytes())[0])
    at = run1["evaluated_at"]
    results: list[tuple[str, bool, str]] = []
    try:
        configuration = relying_party.load_configuration(keys / "examiner-policy.json", keys / "examiner.key", at)
        results.append(("1 policy and key pass the verifier's chain logic (load_configuration)", True,
                        f"leaf kid {configuration.kid.hex()}"))
    except relying_party.UsageError as exc:
        return [("1 policy and key pass the verifier's chain logic (load_configuration)", False, str(exc))]
    if not report["verdict_cbor_hex"]:
        return results + [("2 verdict present in run-3 stdout", False, "no `CBOR hex:` line")]
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
        ("8 trust_policy equals run 1 except relying_party_policy_digest", not trust_diff,
         "differs: " + ", ".join(trust_diff) if trust_diff else ", ".join(key for key in trust_keys if key != "relying_party_policy_digest")),
        ("9 limits equal run 1", verdict["limits"] == run1_verdict["limits"], json.dumps(verdict["limits"], sort_keys=True)),
        ("10 observations equal run 1", verdict["observations"] == run1_verdict["observations"], str(verdict["observations"])),
        ("11 no report-layer marker in run-3 stdout", not report["report_layer_markers"],
         "found " + ", ".join(report["report_layer_markers"]) if report["report_layer_markers"] else f"none of {list(REPORT_LAYER_MARKERS)}"),
        ("verdict_id (not pinned)", True, verdict["verdict_id"].hex()),
    ]
    stem = stdout_path.name.removesuffix(".txt").removesuffix(".stdout")
    (stdout_path.parent / f"{stem}.sig_structure.bin").write_bytes(sig_structure)
    (stdout_path.parent / f"{stem}.leaf-spki.der").write_bytes(leaf_spki)
    (stdout_path.parent / f"{stem}.signature.der").write_bytes(der_signature(decoded["signature"]))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pyref.examiner_package.check_run3", description=__doc__.splitlines()[0])
    parser.add_argument("--stdout", required=True, type=Path, metavar="FILE", help="run 3 stdout, as printed by the verifier")
    parser.add_argument("--keys", required=True, type=Path, metavar="DIR", help="directory holding examiner-policy.json and examiner.key")
    parser.add_argument("--run1", required=True, type=Path, metavar="FILE", help="02-verify/run1.json (run1.verdict.cbor beside it)")
    args = parser.parse_args(argv)
    try:
        results = check(args.stdout, args.keys, args.run1)
    except (OSError, ValueError, KeyError) as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2
    for name, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name}: {detail}")
    return 0 if all(passed for _, passed, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
