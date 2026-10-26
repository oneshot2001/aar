"""Rejection-site inventory (Packet D): every ``_fail(`` call in verifier.py,
relying_party.py and emission_identity.py, and every ``CBORError(``
construction in cbor.py, by AST.
Decoder checks the source documents as unreachable are listed under EXCLUDED
with that comment as the reason. ``python3 -B -m pyref.premises`` prints JSON.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
FAIL_FILES = ("pyref/verifier.py", "pyref/relying_party.py", "pyref/emission_identity.py")
CBOR_FILE = "pyref/cbor.py"
UNREACHABLE_MARK = "unreachable"


def _calls(tree: ast.AST, matches: Any) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call) and matches(node.func)]


def _literal(node: ast.expr | None, kind: type) -> Any:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, kind) else "dynamic"


def inventory() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sites: list[dict[str, Any]] = []
    for name in FAIL_FILES:
        tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
        is_fail = lambda f: (isinstance(f, ast.Name) and f.id == "_fail") or (isinstance(f, ast.Attribute) and f.attr == "_fail")  # noqa: E731
        for call in _calls(tree, is_fail):
            code = _literal(call.args[0] if call.args else None, str)
            sites.append({"file": name, "line": call.lineno, "code": code,
                          "step": _literal(call.args[1] if len(call.args) > 1 else None, int),
                          **({"code_expr": ast.unparse(call.args[0])} if code == "dynamic" else {})})
    lines = (ROOT / CBOR_FILE).read_text(encoding="utf-8").split("\n")
    excluded: list[dict[str, Any]] = []
    for call in _calls(ast.parse("\n".join(lines)), lambda f: isinstance(f, ast.Name) and f.id == "CBORError"):
        code = _literal(call.args[1], str) if len(call.args) > 1 else "cbor/malformed"
        site = {"file": CBOR_FILE, "line": call.lineno, "code": code, "step": "dynamic"}
        text = lines[call.lineno - 1]
        comment = text[text.index("#"):].strip() if "#" in text else ""
        if UNREACHABLE_MARK in comment:
            excluded.append({**site, "reason": comment})
        else:
            sites.append(site)
    return sorted(sites, key=lambda s: (s["file"], s["line"])), excluded


def main() -> int:
    sites, excluded = inventory()
    counts = {name: sum(site["file"] == name for site in sites) for name in (*FAIL_FILES, CBOR_FILE)}
    json.dump({"inventory": sites, "excluded": excluded, "counts": {**counts, "excluded": len(excluded)}}, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
