"""Mint an examiner's relying-party chain (D-83): two fresh P-256 keys, a self-signed root and a
verifier leaf, written as a policy JSON valid for ``--policy`` plus 0600 key files for ``--signing-key``.

    python3 -B -m pyref.examiner_package.mint_examiner_chain --keys DIR --at UNIX_SECONDS --trust-policy FILE

``artifact_roots`` is copied from the producer's pinned trust-policy roots so the carried credentials
still chain to a listed root; a policy narrows trust and never widens it. A self-issued chain
establishes key control, not the examiner's identity or the verifier's correctness.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from .. import hashes, relying_party
from ..cbor import dumps
from ..crypto import N, key_id, public_spki, sign_es256

CREDENTIAL = "application/aar-credential+cbor;v=0.2"
AAR1_LIMITS = {"profile": "AAR-1", "status_max_age_s": 86400, "lease_max_s": 86400, "anchor_max_cadence_s": 86400}


def credential(subject: int, issuer: int, path: list[bytes], at: int, leaf: bool) -> tuple[bytes, list[bytes]]:
    """Return (credential_id, envelope) signed by ``issuer``'s scalar."""
    fields: dict[str, Any] = {
        "v": 2, "subject_kid": key_id(subject), "public_key": public_spki(subject), "issuer_kid": key_id(issuer),
        "principal_type": "service", "principal_role": "verifier" if leaf else "authority_source",
        "tenant_id": bytes(16), "site_id": bytes(16), "valid_from": at - 86400, "valid_until": at + 30 * 86400,
        "cose_alg": -7, "curve": "P-256", "key_usage": "verifier_signing" if leaf else "credential_issuing",
        "trust_anchor_id": hashes.sha256(b"AAR-EXAMINER-TRUST-ANCHOR-v1" + key_id(issuer)),  # issuer == root in both
        "path": path, "profile_limits": AAR1_LIMITS,
    }
    credential_id = hashes.domain_hash("AAR-CREDENTIAL-ID-v1", fields)
    payload_bytes = dumps({"credential_id": credential_id, **fields})
    protected = dumps({1: -7, 3: CREDENTIAL, 4: key_id(issuer)})
    signature = sign_es256(issuer, dumps(["Signature1", protected, b"", payload_bytes]))
    return credential_id, [payload_bytes, dumps([protected, {}, None, signature])]


def write_key(path: Path, scalar: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(f"{scalar:064x}\n")


def mint(keys: Path, at: int, trust_policy: Path) -> dict[str, str]:
    keys.mkdir(parents=True, exist_ok=True)
    root_scalar = secrets.randbelow(N - 1) + 1
    leaf_scalar = secrets.randbelow(N - 1) + 1
    write_key(keys / "examiner-root.key", root_scalar)
    write_key(keys / "examiner.key", leaf_scalar)
    root_id, root_envelope = credential(root_scalar, root_scalar, [], at, leaf=False)
    leaf_id, leaf_envelope = credential(leaf_scalar, root_scalar, [root_id], at, leaf=True)
    envelopes = [env for _, env in sorted(((root_id, root_envelope), (leaf_id, leaf_envelope)))]
    roots = json.loads(trust_policy.read_text(encoding="utf-8"))["trust_store"]["roots"]
    policy = {
        "v": 1,
        "artifact_roots": sorted(({"root_kid": r["root_kid"], "tenant_id": r["tenant_id"], "allowed_sites": r["allowed_sites"],
                                   "allowed_key_usages": r["allowed_key_usages"]} for r in roots), key=lambda r: r["root_kid"]),
        "verifier_root_kid": key_id(root_scalar).hex(),
        "verifier_credentials": [dumps(env).hex() for env in envelopes],
    }
    (keys / "examiner-policy.json").write_text(json.dumps(policy, indent=2) + "\n")
    # The verifier's own chain logic validates what was just written (amendment a).
    configuration = relying_party.load_configuration(keys / "examiner-policy.json", keys / "examiner.key", at)
    return {"root_kid": key_id(root_scalar).hex(), "leaf_kid": configuration.kid.hex(),
            "policy_digest": configuration.policy_digest.hex()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pyref.examiner_package.mint_examiner_chain", description=__doc__.splitlines()[0])
    parser.add_argument("--keys", required=True, type=Path, metavar="DIR", help="where the key files and policy go (outside the package)")
    parser.add_argument("--at", required=True, type=int, metavar="UNIX_SECONDS", help="the run's --at; validity covers it")
    parser.add_argument("--trust-policy", required=True, type=Path, metavar="FILE", help="producer's pinned trust-policy.json (roots copied)")
    args = parser.parse_args(argv)
    for name, value in mint(args.keys, args.at, args.trust_policy).items():
        print(f"{name}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
