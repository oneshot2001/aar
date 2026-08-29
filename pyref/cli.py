"""Offline command-line packaging for the clean-room AAR verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .cbor import CBORError, dumps, loads
from .verifier import KEY_USAGES, LIMITS, MAX_U53, Evaluation, evaluate


EXIT_CONFORMANT = 0
EXIT_NONCONFORMANT = 1
EXIT_USAGE = 2
EXIT_INDETERMINATE = 3
EXIT_INTERNAL = 70


class UsageError(ValueError):
    """A local CLI input is missing or malformed."""


def _timestamp(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be decimal Unix seconds") from exc
    if not 0 <= parsed <= MAX_U53:
        raise argparse.ArgumentTypeError("must be between 0 and 9007199254740991")
    return parsed


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"cannot read {label} file {path}: {exc.strerror or exc}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"invalid JSON in {label} file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise UsageError(f"{label} file must contain one JSON object")
    return value


def _closed(
    value: Any, keys: set[str], label: str, optional: set[str] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UsageError(f"{label} must be a JSON object")
    optional = optional or set()
    actual = set(value)
    if not keys <= actual or not actual <= keys | optional:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys - optional)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unknown {', '.join(extra)}")
        raise UsageError(f"{label}: {'; '.join(details)}")
    return value


def _hex_bytes(value: Any, size: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise UsageError(f"{label} must be a {size}-byte lowercase or uppercase hex string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise UsageError(f"{label} is not valid hex") from exc
    if len(decoded) != size:
        raise UsageError(f"{label} must decode to exactly {size} bytes")
    return decoded


def _uint(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_U53:
        raise UsageError(f"{label} must be an unsigned integer <= 9007199254740991")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        raise UsageError(f"{label} must be a nonempty array of strings")
    return value


def _trust_policy(path: Path) -> dict[str, Any]:
    source = _closed(
        _read_json(path, "trust-policy"),
        {"trust_store", "expected_anchor_heads", "verifier_policy_digest"},
        "trust-policy",
        {"life_safety_action_names"},
    )
    store_source = _closed(
        source["trust_store"], {"digest", "snapshot_id", "created_at", "roots"},
        "trust-policy.trust_store",
    )
    roots_source = store_source["roots"]
    if not isinstance(roots_source, list) or not 1 <= len(roots_source) <= 64:
        raise UsageError("trust-policy.trust_store.roots must contain 1 to 64 entries")
    roots = []
    for index, item in enumerate(roots_source):
        label = f"trust-policy.trust_store.roots[{index}]"
        item = _closed(
            item,
            {"root_id", "root_kid", "tenant_id", "allowed_sites", "allowed_key_usages"},
            label,
        )
        sites = item["allowed_sites"]
        if not isinstance(sites, list) or not 1 <= len(sites) <= 256:
            raise UsageError(f"{label}.allowed_sites must contain 1 to 256 entries")
        usages = _string_list(item["allowed_key_usages"], f"{label}.allowed_key_usages")
        if len(usages) > 8 or len(set(usages)) != len(usages) or any(
            usage not in KEY_USAGES for usage in usages
        ):
            raise UsageError(f"{label}.allowed_key_usages contains an invalid or duplicate usage")
        roots.append({
            "root_id": _hex_bytes(item["root_id"], 32, f"{label}.root_id"),
            "root_kid": _hex_bytes(item["root_kid"], 32, f"{label}.root_kid"),
            "tenant_id": _hex_bytes(item["tenant_id"], 16, f"{label}.tenant_id"),
            "allowed_sites": [
                _hex_bytes(site, 16, f"{label}.allowed_sites[{site_index}]")
                for site_index, site in enumerate(sites)
            ],
            "allowed_key_usages": usages,
        })

    heads_source = source["expected_anchor_heads"]
    if not isinstance(heads_source, list) or not 1 <= len(heads_source) <= 32:
        raise UsageError("trust-policy.expected_anchor_heads must contain 1 to 32 entries")
    heads = []
    for index, item in enumerate(heads_source):
        label = f"trust-policy.expected_anchor_heads[{index}]"
        item = _closed(item, {"target_id", "observed_at", "tree_size", "root"}, label)
        heads.append({
            "target_id": _hex_bytes(item["target_id"], 16, f"{label}.target_id"),
            "observed_at": _uint(item["observed_at"], f"{label}.observed_at"),
            "tree_size": _uint(item["tree_size"], f"{label}.tree_size"),
            "root": _hex_bytes(item["root"], 32, f"{label}.root"),
        })
        if not 1 <= heads[-1]["tree_size"] <= 4_294_967_295:
            raise UsageError(f"{label}.tree_size must be between 1 and 4294967295")

    life_safety_action_names = source.get("life_safety_action_names")
    if life_safety_action_names is not None:
        if not isinstance(life_safety_action_names, list) or len(life_safety_action_names) > 64:
            raise UsageError("trust-policy.life_safety_action_names must contain 0 to 64 strings")
        for index, name in enumerate(life_safety_action_names):
            if not isinstance(name, str) or not 1 <= len(name.encode("utf-8")) <= 128:
                raise UsageError(
                    f"trust-policy.life_safety_action_names[{index}] must be 1 to 128 UTF-8 bytes"
                )

    return {
        "trust_store": {
            "digest": _hex_bytes(store_source["digest"], 32, "trust-policy.trust_store.digest"),
            "snapshot_id": _hex_bytes(
                store_source["snapshot_id"], 32, "trust-policy.trust_store.snapshot_id"
            ),
            "created_at": _uint(store_source["created_at"], "trust-policy.trust_store.created_at"),
            "roots": roots,
        },
        "expected_anchor_heads": heads,
        "verifier_policy_digest": _hex_bytes(
            source["verifier_policy_digest"], 32, "trust-policy.verifier_policy_digest"
        ),
        **({"life_safety_action_names": life_safety_action_names}
           if life_safety_action_names is not None else {}),
    }


def _prior_state(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    source = _read_json(path, "prior-state")
    unknown = set(source) - {"prior_emissions", "entries"}
    if unknown:
        raise UsageError(f"prior-state: unknown {', '.join(sorted(unknown))}")
    emissions_source = source.get("prior_emissions", [])
    entries_source = source.get("entries", [])
    if not isinstance(emissions_source, list) or not isinstance(entries_source, list):
        raise UsageError("prior-state.prior_emissions and prior-state.entries must be arrays")

    emissions = []
    emission_keys = {
        "issuer_kid", "issuer_seq", "epoch_owner_kid", "epoch_id", "epoch_seq",
        "receipt_id", "envelope_digest",
    }
    for index, item in enumerate(emissions_source):
        label = f"prior-state.prior_emissions[{index}]"
        item = _closed(item, emission_keys, label)
        emissions.append({
            "issuer_kid": _hex_bytes(item["issuer_kid"], 32, f"{label}.issuer_kid").hex(),
            "issuer_seq": _uint(item["issuer_seq"], f"{label}.issuer_seq"),
            "epoch_owner_kid": _hex_bytes(
                item["epoch_owner_kid"], 32, f"{label}.epoch_owner_kid"
            ).hex(),
            "epoch_id": _uint(item["epoch_id"], f"{label}.epoch_id"),
            "epoch_seq": _uint(item["epoch_seq"], f"{label}.epoch_seq"),
            "receipt_id": _hex_bytes(item["receipt_id"], 32, f"{label}.receipt_id").hex(),
            "envelope_digest": _hex_bytes(
                item["envelope_digest"], 32, f"{label}.envelope_digest"
            ).hex(),
        })

    entries = []
    for index, item in enumerate(entries_source):
        label = f"prior-state.entries[{index}]"
        item = _closed(item, {"replay_domain", "invocation_id", "content_digest"}, label)
        entries.append({
            "replay_domain": _hex_bytes(item["replay_domain"], 32, f"{label}.replay_domain"),
            "invocation_id": _hex_bytes(item["invocation_id"], 16, f"{label}.invocation_id"),
            "content_digest": _hex_bytes(item["content_digest"], 32, f"{label}.content_digest"),
        })
    entry_keys = [
        dumps([entry["replay_domain"], entry["invocation_id"], entry["content_digest"]])
        for entry in entries
    ]
    if any(previous >= current for previous, current in zip(entry_keys, entry_keys[1:])):
        raise UsageError("prior-state.entries must be strictly sorted and unique")
    return {"prior_emissions": emissions}, {"entries": entries}


def _check_policy_pin(raw: bytes, policy: dict[str, Any]) -> None:
    if len(raw) > LIMITS["exact_encoded_bundle_bytes"]:
        return
    try:
        bundle = loads(raw)
    except CBORError:
        return
    if not isinstance(bundle, dict) or not isinstance(bundle.get("trust_inputs"), dict):
        return
    carried = dict(bundle["trust_inputs"])
    carried.pop("evaluation_time", None)
    if carried != policy:
        raise UsageError(
            "trust-policy does not exactly match the bundle trust_inputs "
            "(evaluation_time is supplied separately by --at)"
        )


def _print_evaluation(bundle_path: Path, at: int, evaluation: Evaluation, policy_pinned: bool) -> None:
    print("AAR offline verification report")
    print(f"Bundle: {bundle_path}")
    print(f"Evaluation time: {at}")
    print("Network: not used (all inputs are local)")
    print(f"Trust policy: {'externally pinned' if policy_pinned else 'producer-declared only'}")
    print(f"Result: {evaluation.result}")
    print("Steps:")
    for item in evaluation.report["steps"]:
        status = item["status"].upper().replace("_", " ")
        print(f"  {item['step']:02d} {status:<13} {item['name']}")
    if evaluation.report["first_failure_step"] is not None:
        print(
            f"First failure: step {evaluation.report['first_failure_step']} "
            f"({evaluation.report['first_failure_reason']})"
        )
    else:
        print("First failure: none")

    matching_receipts = evaluation.report["selector_matching_receipts"]
    print(
        "Selector-matching receipts: "
        f"{matching_receipts if matching_receipts is not None else 'not evaluated'}"
    )
    print("Observations:")
    report_only = set(evaluation.report["report_layer_observations"])
    if not evaluation.report["observations"]:
        print("  (none)")
    for observation in evaluation.report["observations"]:
        suffix = " [report layer; not signed]" if observation in report_only else " [signed]"
        print(f"  - {observation}{suffix}")

    verdict = evaluation.verdict
    limits = verdict["limits"]
    scope = verdict["scope"]
    print("Signed verdict:")
    print(f"  CBOR hex: {evaluation.verdict_bytes.hex()}")
    print("  Decoded summary:")
    print(f"    verdict_id: {verdict['verdict_id'].hex()}")
    print(f"    result: {verdict['result']}")
    if evaluation.reason is not None:
        print(f"    reason: {evaluation.reason}")
    print(f"    evaluated_at: {verdict['evaluated_at']}")
    print(f"    bundle_digest: {verdict['bundle_digest'].hex()}")
    print(f"    requested_profile: {limits['requested_profile']}")
    print(f"    evaluated_profile: {limits['evaluated_profile']}")
    print(f"    coverage: {scope['coverage']}")
    signed_observations = verdict["observations"]
    print(f"    signed_observations: {', '.join(signed_observations) if signed_observations else '(none)'}")


def _verify(args: argparse.Namespace) -> int:
    try:
        raw = args.bundle.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read bundle file {args.bundle}: {exc.strerror or exc}") from exc

    policy = _trust_policy(args.trust_policy) if args.trust_policy else None
    if args.prior_state:
        prior, replay = _prior_state(args.prior_state)
    else:
        prior = replay = None

    evaluation = evaluate(
        raw,
        evaluated_at=args.at,
        prior_state=prior,
        replay_state=replay,
        configured_trust_policy=policy,
    )
    if policy is not None and (evaluation.result == "conformant" or evaluation.step > 5):
        _check_policy_pin(raw, policy)
    _print_evaluation(args.bundle, args.at, evaluation, policy is not None)
    return {
        "conformant": EXIT_CONFORMANT,
        "nonconformant": EXIT_NONCONFORMANT,
        "indeterminate": EXIT_INDETERMINATE,
    }[evaluation.result]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pyref",
        description="AAR v0.2 clean-room offline verifier (stdlib only; no network access).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser(
        "verify",
        help="verify one deterministic-CBOR AAR bundle and emit a signed verdict",
        description="Verify one AAR bundle entirely offline and emit a 20-step report plus signed verdict.",
        epilog=(
            "File formats (closed JSON objects; all byte strings are hex):\n"
            "  POLICY.json = {trust_store:{digest,snapshot_id,created_at,roots:[\n"
            "    {root_id,root_kid,tenant_id,allowed_sites,allowed_key_usages}]},\n"
            "    expected_anchor_heads:[{target_id,observed_at,tree_size,root}],\n"
            "    verifier_policy_digest}\n"
            "  PRIOR.json = {prior_emissions:[{issuer_kid,issuer_seq,epoch_owner_kid,\n"
            "    epoch_id,epoch_seq,receipt_id,envelope_digest}], entries:[\n"
            "    {replay_domain,invocation_id,content_digest}]}\n"
            "evaluation_time is never read from either file; it comes only from --at.\n"
            "See pyref/README.md for byte sizes and semantics."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verify.add_argument("bundle", type=Path, metavar="BUNDLE.cbor")
    verify.add_argument(
        "--trust-policy", type=Path, metavar="FILE",
        help="JSON policy pin; must exactly match the bundle-carried trust inputs",
    )
    verify.add_argument(
        "--prior-state", type=Path, metavar="FILE",
        help="JSON prior emissions and one-time replay state",
    )
    verify.add_argument(
        "--at", required=True, type=_timestamp, metavar="TIMESTAMP",
        help="explicit evaluation time as decimal Unix seconds; the wall clock is never read",
    )
    verify.set_defaults(handler=_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except UsageError as exc:
        print(f"{parser.prog} {args.command}: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:
        print(f"{parser.prog} {args.command}: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
