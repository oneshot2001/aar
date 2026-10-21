"""Relying-party policy: configuration and the step-8 root-acceptance loop (D-83).

``load_configuration`` validates the policy JSON mirror and the signing key in
the CONFORMANCE section 6 order before any bundle byte is read; every failure
is a ``UsageError`` (exit 2, no verdict). The credential checks reuse the
verifier's own step-6 envelope validation over the configured chain.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import hashes, verifier
from .cbor import CBORError, dumps, loads
from .crypto import N, key_id, parse_p256_spki

POLICY_DOMAIN = "AAR-RP-POLICY-v1"
ZERO16 = bytes(16)

# D-83 part 9: the kids of the thirteen v0.2.5 fixture scalars, enumerated by
# kid. A policy chain that reaches one is a usage error. The rp_* fixture pair
# is deliberately absent so the rp-* corpus stays reproducible.
LEGACY_FIXTURE_KIDS = frozenset(bytes.fromhex(kid) for kid in (
    "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3",  # agent_signing
    "dc0ce633dbcc913dafafa4b89ac44d8ce683fdfc3f60c8bdf21213b9f2b534ba",  # ep_signing
    "2b985badf1bac8293f6b92e8c0acc1139bc5a5ecbbf97a6271dcf0d4f6c68af6",  # authority_signing
    "3eab3fba5026b61d007cbf411b90f3c88ff89cf0a8088cbbfc3eaaca867dd663",  # approver_signing
    "dafc418eb082e83c76a48f0c526fe45e9ca4d4ecfa82366de3fccd37099fca01",  # outcome_signing
    "e26630d1233ed92d8ac231a4bf230fddb2d924d6eace7489946e1e82e9523a70",  # anchor_signing
    "11086649cd3e5d1892200a4200b165bbea5c9f9b47ca83792d4f9a1ef0dc8921",  # verifier_signing
    "8449111985c4e015d12e2c0b4847278c9d9e5f84a383fd4056a6d89bab795c5d",  # credential_issuing
    "e3615fff37474c561c068d1f56f5ec3751cd7eb2ea7046c016a142c932865496",  # status_signing
    "f0f6a0003fd9e94ffb16e2206cfdf272ef2e8860d73f32704b5f365b45505138",  # agent_signing_successor
    "21af110aa3ea3b9705cc6374830ce5bda521d901c5215f88604cc78385845dc0",  # mediator_outcome_signing
    "06bd70e0b4fcc9277de14317373dcf86f8fbeb48d8a52513f726059488c1d768",  # d77_outsider
    "c379f258d6ad972fdc80a8574dad37651dd58620a0ccd0808113be2ff6b37de9",  # d77_leaf
))


class UsageError(ValueError):
    """A local CLI input is missing or malformed."""


@dataclass(frozen=True)
class Configuration:
    scalar: int
    kid: bytes
    policy_digest: bytes
    verifier_kids: frozenset[bytes]
    roots: dict[bytes, dict[str, Any]]


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise UsageError(f"{label} must be a JSON object with exactly {', '.join(sorted(keys))}")
    return value


def _hex(value: Any, size: int | None, label: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value):
        raise UsageError(f"{label} must be a hex string")
    decoded = bytes.fromhex(value)
    if size is not None and len(decoded) != size:
        raise UsageError(f"{label} must decode to exactly {size} bytes")
    return decoded


def load_policy(path: Path) -> dict[str, Any]:
    """Read the JSON mirror and return the ``relying-party-policy`` CBOR map."""
    try:
        source = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"cannot read policy file {path}: {exc}") from exc
    _closed(source, {"v", "artifact_roots", "verifier_root_kid", "verifier_credentials"}, "policy")
    if source["v"] != 1:
        raise UsageError("policy.v must be 1")
    roots_source = source["artifact_roots"]
    if not isinstance(roots_source, list) or not 1 <= len(roots_source) <= 64:
        raise UsageError("policy.artifact_roots must contain 1 to 64 entries")
    roots = []
    for index, item in enumerate(roots_source):
        label = f"policy.artifact_roots[{index}]"
        _closed(item, {"root_kid", "tenant_id", "allowed_sites", "allowed_key_usages"}, label)
        sites = item["allowed_sites"]
        if not isinstance(sites, list) or not 1 <= len(sites) <= 256:
            raise UsageError(f"{label}.allowed_sites must contain 1 to 256 entries")
        usages = item["allowed_key_usages"]
        if not isinstance(usages, list) or not 1 <= len(usages) <= 8 or len(set(usages)) != len(usages) \
                or any(usage not in verifier.KEY_USAGES for usage in usages):
            raise UsageError(f"{label}.allowed_key_usages must be 1 to 8 distinct key usages")
        roots.append({
            "root_kid": _hex(item["root_kid"], 32, f"{label}.root_kid"),
            "tenant_id": _hex(item["tenant_id"], 16, f"{label}.tenant_id"),
            "allowed_sites": [_hex(site, 16, f"{label}.allowed_sites[{i}]") for i, site in enumerate(sites)],
            "allowed_key_usages": usages,
        })
    kids = [root["root_kid"] for root in roots]
    if kids != sorted(set(kids)):
        raise UsageError("policy.artifact_roots must be strictly sorted and unique by root_kid")
    credentials_source = source["verifier_credentials"]
    if not isinstance(credentials_source, list) or not 1 <= len(credentials_source) <= 9:
        raise UsageError("policy.verifier_credentials must contain 1 to 9 entries")
    credentials = []
    for index, item in enumerate(credentials_source):
        label = f"policy.verifier_credentials[{index}]"
        raw = _hex(item, None, label)
        try:
            credentials.append(loads(raw))
        except CBORError as exc:
            raise UsageError(f"{label}: {exc}") from exc
    return {
        "v": 1, "artifact_roots": roots,
        "verifier_root_kid": _hex(source["verifier_root_kid"], 32, "policy.verifier_root_kid"),
        "verifier_credentials": credentials,
    }


def _scalar(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8").rstrip()
    except (OSError, UnicodeError) as exc:
        raise UsageError(f"cannot read signing key file {path}: {exc}") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise UsageError("signing key file must hold exactly 64 lowercase hexadecimal characters")
    scalar = int(text, 16)
    if not 1 <= scalar < N:
        raise UsageError("signing key scalar must satisfy 1 <= d < n")
    return scalar


def _chain(policy: dict[str, Any], kid: bytes, evaluated_at: int) -> list[dict[str, Any]]:
    """CONFORMANCE section 6 chain algorithm; returns leaf-first members."""
    envelopes = policy["verifier_credentials"]
    state = verifier.State(raw=b"", evaluated_at=evaluated_at, prior_state=None, replay_state=None,
                           bundle={"artifacts": {"credentials": envelopes}})
    verifier._preparse_payloads(state)
    state.bundle = None
    try:
        members = [verifier._validate_envelope(state, "credentials", index, value).payload
                   for index, value in enumerate(envelopes)]
    except verifier.ValidationError as exc:
        raise UsageError(f"policy.verifier_credentials: {exc.code}") from exc
    ids = [member["credential_id"] for member in members]
    if ids != sorted(set(ids)):
        raise UsageError("policy.verifier_credentials must be strictly sorted and unique by credential_id")
    leaves = [member for member in members if member["subject_kid"] == kid]
    if len(leaves) != 1:
        raise UsageError("signing key matches no single policy.verifier_credentials entry")
    for member in members:
        if hashes.artifact_id(member, "credential_id") != member["credential_id"]:
            raise UsageError("policy.verifier_credentials: credential_id does not recompute")
        try:
            parse_p256_spki(member["public_key"])
        except ValueError as exc:
            raise UsageError(f"policy.verifier_credentials: {exc}") from exc
        if hashes.sha256(member["public_key"]) != member["subject_kid"]:
            raise UsageError("policy.verifier_credentials: public_key does not hash to subject_kid")
        if member["tenant_id"] != ZERO16 or member["site_id"] != ZERO16:
            raise UsageError("policy.verifier_credentials: tenant_id and site_id must be all-zero")
        if not member["valid_from"] <= evaluated_at < member["valid_until"]:
            raise UsageError("policy.verifier_credentials: a member is not valid at the evaluation time")
    leaf = leaves[0]
    if leaf["key_usage"] != "verifier_signing" or leaf["principal_role"] != "verifier" or not leaf["path"]:
        raise UsageError("the leaf must have key_usage verifier_signing, principal_role verifier and a non-empty path")
    by_id = {member["credential_id"]: member for member in members}
    chain = [leaf]
    for depth, credential_id in enumerate(leaf["path"]):
        parent = by_id.get(credential_id)
        if parent is None or parent["subject_kid"] != chain[-1]["issuer_kid"] or parent["path"] != leaf["path"][depth + 1:]:
            raise UsageError("policy.verifier_credentials: the leaf path does not resolve")
        chain.append(parent)
    if len({member["subject_kid"] for member in chain}) != len(chain):
        raise UsageError("policy.verifier_credentials: a subject_kid repeats in the chain")
    if any(member["key_usage"] != "credential_issuing" for member in chain[1:]):
        raise UsageError("every chain member except the leaf must have key_usage credential_issuing")
    root = chain[-1]
    if not root["subject_kid"] == root["issuer_kid"] == policy["verifier_root_kid"]:
        raise UsageError("the terminal credential must be self-signed by verifier_root_kid")
    if len(chain) != len(members):
        raise UsageError("policy.verifier_credentials must be exactly the leaf plus the credentials its path names")
    return chain


def load_configuration(policy_path: Path | None, key_path: Path | None, evaluated_at: int) -> Configuration | None:
    """Validate policy and key together, before the bundle; ``None`` when neither is supplied."""
    if (policy_path is None) != (key_path is None):
        raise UsageError("--policy and --signing-key must be supplied together")
    if policy_path is None:
        return None
    policy = load_policy(policy_path)
    scalar = _scalar(key_path)
    kid = key_id(scalar)
    chain = _chain(policy, kid, evaluated_at)
    verifier_kids = frozenset({policy["verifier_root_kid"], *(member["subject_kid"] for member in chain)})
    if verifier_kids & LEGACY_FIXTURE_KIDS:
        raise UsageError("policy chain contains a published fixture key")
    return Configuration(
        scalar, kid, hashes.domain_hash(POLICY_DOMAIN, policy), verifier_kids,
        {root["root_kid"]: root for root in policy["artifact_roots"]},
    )


def _accepts(root: dict[str, Any] | None, credential: dict[str, Any], used: bool) -> bool:
    return root is not None and root["tenant_id"] == credential["tenant_id"] \
        and credential["site_id"] in root["allowed_sites"] \
        and (not used or credential["key_usage"] in root["allowed_key_usages"])


def accept_roots(configuration: Configuration | None, credentials: list[verifier.Envelope],
                 terminals: dict[bytes, dict[str, Any]], roots: dict[bytes, dict[str, Any]],
                 used_kids: set[bytes], mediator_kids: set[bytes]) -> None:
    """Step 8 per carried credential: separation, producer acceptance, policy acceptance (D-83 part 4)."""
    for envelope in credentials:
        credential = envelope.payload
        code = "countersign/credential-invalid" if credential["subject_kid"] in mediator_kids else "credential/root-not-accepted"
        terminal_kid = terminals[credential["credential_id"]]["subject_kid"]
        used = credential["subject_kid"] in used_kids
        if configuration is not None and credential["subject_kid"] in configuration.verifier_kids:
            verifier._fail(code, 8)
        # The wire carries both a credential trust_anchor_id and a trust-store
        # root_id, but the normative path rule says acceptance terminates by
        # root key/tenant/site; it defines no equality between those two IDs.
        if not _accepts(roots.get(terminal_kid), credential, used):
            verifier._fail(code, 8)
        if configuration is not None and not _accepts(configuration.roots.get(terminal_kid), credential, used):
            verifier._fail(code, 8)
