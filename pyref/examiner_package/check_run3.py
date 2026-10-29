"""The five run-3 acceptance checks (spec 02): signature under the examiner's leaf, leaf kid in the
protected header, policy digest recomputed, bundle_digest and Result equal to run 1.

    python3 -B -m pyref.examiner_package.check_run3 --stdout run3.stdout.txt --policy POLICY.json --run1 run1.json

Writes ``run3.sig_structure.bin``, ``run3.leaf-spki.der`` and ``run3.signature.der`` beside the stdout
file so a second tool (OpenSSL) can verify the same signature. Exit 0 only when all five pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import hashes, relying_party
from ..cbor import dumps, loads
from ..crypto import verify_es256
from . import decode_verdict, parse_report


def der_signature(signature: bytes) -> bytes:
    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\x00") or b"\x00"
        if value[0] & 0x80:
            value = b"\x00" + value
        return b"\x02" + bytes([len(value)]) + value
    body = integer(signature[:32]) + integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def check(stdout_path: Path, policy_path: Path, run1_path: Path) -> list[tuple[str, bool, str]]:
    report = parse_report(stdout_path.read_text(encoding="utf-8"))
    run1 = json.loads(run1_path.read_text(encoding="utf-8"))
    policy = relying_party.load_policy(policy_path)
    if not report["verdict_cbor_hex"]:
        return [("verdict present in stdout", False, "no `CBOR hex:` line")]
    decoded = decode_verdict(report["verdict_cbor_hex"])
    verdict, protected = decoded["verdict"], decoded["protected"]
    leaf = next((loads(env[0]) for env in policy["verifier_credentials"]
                 if loads(env[0]).get("key_usage") == "verifier_signing"), None)
    sig_structure = dumps(["Signature1", decoded["protected_bytes"], b"", decoded["payload_bytes"]])
    policy_digest = hashes.domain_hash(relying_party.POLICY_DOMAIN, policy)
    results = [
        ("1 signature verifies under the examiner's leaf", leaf is not None and verify_es256(leaf["public_key"], sig_structure, decoded["signature"]),
         f"leaf subject_kid {leaf['subject_kid'].hex() if leaf else 'none'}"),
        ("2 leaf kid is the verdict's protected kid", leaf is not None and protected.get(4) == leaf["subject_kid"], f"protected kid {protected.get(4, b'').hex()}"),
        ("3 relying_party_policy_digest equals the recomputed policy digest", verdict["trust_policy"]["relying_party_policy_digest"] == policy_digest,
         f"policy digest {policy_digest.hex()}"),
        ("4 bundle_digest equals run 1", verdict["bundle_digest"].hex() == run1["bundle_digest"], f"bundle_digest {verdict['bundle_digest'].hex()}"),
        ("5 Result equals run 1", verdict["result"] == run1["result"] == report["result"], f"Result {verdict['result']}"),
    ]
    stem = stdout_path.with_suffix("")
    stem.with_name(stem.name.replace(".stdout", "") + ".sig_structure.bin").write_bytes(sig_structure)
    if leaf is not None:
        stem.with_name(stem.name.replace(".stdout", "") + ".leaf-spki.der").write_bytes(leaf["public_key"])
    stem.with_name(stem.name.replace(".stdout", "") + ".signature.der").write_bytes(der_signature(decoded["signature"]))
    results.append(("verdict_id (not pinned)", True, verdict["verdict_id"].hex()))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pyref.examiner_package.check_run3", description=__doc__.splitlines()[0])
    parser.add_argument("--stdout", required=True, type=Path, metavar="FILE", help="run 3 stdout, as printed by the verifier")
    parser.add_argument("--policy", required=True, type=Path, metavar="FILE", help="the examiner's policy JSON")
    parser.add_argument("--run1", required=True, type=Path, metavar="FILE", help="02-verify/run1.json from the package")
    args = parser.parse_args(argv)
    try:
        results = check(args.stdout, args.policy, args.run1)
    except (OSError, ValueError, KeyError) as exc:
        print(f"{parser.prog}: error: {exc}", file=sys.stderr)
        return 2
    for name, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name}: {detail}")
    return 0 if all(passed for _, passed, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
