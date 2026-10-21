"""The kats/relying-party row protocol (D-83 part 11): one *.inputs.json sidecar per row."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
RELYING_PARTY_DIRECTORY = ROOT / "kats" / "relying-party"


def _rp_fixture_paths() -> list[Path]:
    """One row per inputs sidecar; the row path is the virtual <name>.cbor beside it."""
    return [path.with_name(path.name.removesuffix(".inputs.json") + ".cbor") for path in RELYING_PARTY_DIRECTORY.glob("*.inputs.json")]


def _inputs_path(path: Path) -> Path | None:
    candidate = path.with_name(path.name.removesuffix(".cbor") + ".inputs.json")
    return candidate if candidate.exists() else None


def _bundle_path(path: Path) -> Path:
    """The bundle bytes a row evaluates: the sidecar's `bundle` (relative to it) or <name>.cbor."""
    inputs_path = _inputs_path(path)
    bundle = json.loads(inputs_path.read_text(encoding="utf-8")).get("bundle") if inputs_path else None
    return path.parent / bundle if bundle else path


def _rp_inputs(path: Path) -> dict[str, Any] | None:
    """The evaluate() keyword arguments named by a row's inputs sidecar; null = not supplied."""
    inputs_path = _inputs_path(path)
    if inputs_path is None:
        return None
    from .cli import _trust_policy
    from .relying_party import load_configuration
    inputs = json.loads(inputs_path.read_text(encoding="utf-8"))
    sibling = lambda name: None if name is None else path.with_name(name)  # noqa: E731
    state = lambda name: None if name is None else json.loads(sibling(name).read_text(encoding="utf-8"))  # noqa: E731
    return {
        "evaluated_at": inputs["at"],
        "configuration": load_configuration(sibling(inputs["policy"]), sibling(inputs["signing_key"]), inputs["at"]),
        "configured_trust_policy": None if inputs["trust_policy"] is None else _trust_policy(sibling(inputs["trust_policy"])),
        "prior_state": state(inputs["prior_state"]), "replay_state": state(inputs["replay_state"]),
    }


def _sidecar_path(path: Path) -> Path:
    if path.name.endswith(".bundle.cbor"):
        return path.with_name(path.name.removesuffix(".bundle.cbor") + ".json")
    return path.with_suffix(".json")


def _prior_path(path: Path) -> Path | None:
    if not path.name.endswith(".bundle.cbor"):
        return None
    candidate = path.with_name(path.name.removesuffix(".bundle.cbor") + ".prior.json")
    return candidate if candidate.exists() else None
