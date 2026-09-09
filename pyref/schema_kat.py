"""D5 CDDL schema oracle (release gate).

Validates exact fixture, demo, and verdict bytes against the normative CDDL
with an external pinned engine; runtime verifiers are not involved. pyref stays
stdlib-only: the engine is a dev tool reached over subprocess. Fails closed.

    gem install --user-install json_pure -v 2.7.6   # system Ruby 2.6 only
    gem install --user-install cddl -v 0.12.14
    python3 -B -m pyref.schema_kat
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .cbor import dumps, loads
from .kat import KAT_DIRECTORIES, ROOT
from .verifier import evaluate

ENGINE_VERSION = "0.12.14"  # Ruby `cddl` gem (Bormann reference implementation)
AT = 1_735_689_800
CORE = (ROOT / "spec" / "aar-core.cddl").read_text()
VERDICT = re.search(r"```cddl\n(verdict-envelope = \[.*?)```", (ROOT / "spec" / "CONFORMANCE.md").read_text(), re.S).group(1)
ARTIFACT_ROOTS = dict(re.findall(r"(\w+): \[ \d+\*\d+ ([\w-]+) \]", CORE.split("bundle-artifacts = {")[1].split("}")[0]))
POSITIVE = ROOT / "kats" / "positive"


def engine() -> str:
    exe = shutil.which("cddl")
    try:
        if exe is None:
            gem_dir = subprocess.run(["ruby", "-e", "print Gem.user_dir"], capture_output=True, text=True).stdout
            exe = str(Path(gem_dir) / "bin" / "cddl")
        banner = subprocess.run([exe], capture_output=True, text=True).stderr
    except OSError:
        sys.exit(f"engine unsupported: ruby or {exe} not found; gem install --user-install cddl -v {ENGINE_VERSION}")
    found = re.search(r"cddl tool version (\S+)", banner)
    if found is None or found.group(1) != ENGINE_VERSION:
        sys.exit(f"engine unsupported: expected cddl gem {ENGINE_VERSION}, found {found and found.group(1)}")
    return exe


def accepts(exe: str, schema: str, root: str, blob: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        spec = Path(tmp, "spec.cddl")
        spec.write_text(f"oracle-root = {root}\n\n{schema}")
        file = Path(tmp, "0.cbor")
        file.write_bytes(blob)
        run = subprocess.run([exe, str(spec), "validate", str(file)], capture_output=True, text=True)
    # 1 + failed-subtree dump on stdout = validation failure; 1 with empty stdout = gem crash; anything else = engine/schema error
    if run.returncode not in (0, 1) or (run.returncode == 1 and not run.stdout):
        sys.exit(f"engine unsupported: cddl exit {run.returncode} for {root}: {run.stderr.strip()[:400]}")
    return run.returncode == 0


def narrow(exe: str, blob: bytes) -> str:
    """Name the first artifact that fails its own production inside a bundle."""
    value = loads(blob)
    if isinstance(value, dict) and isinstance(value.get("artifacts"), dict):
        for key, entries in value["artifacts"].items():
            for index, entry in enumerate(entries):
                if not accepts(exe, CORE, ARTIFACT_ROOTS[key], dumps(entry)):
                    return f"$.artifacts.{key}[{index}]"
        for index, entry in enumerate(value.get("ranges", [])):
            if not accepts(exe, CORE, "manifest-range-proof", dumps(entry)):
                return f"$.ranges[{index}]"
    return "$"


def mutate(blob: bytes, path: str, value) -> bytes:
    envelope = loads(blob)
    payload = loads(envelope[0])
    target = payload
    *keys, last = path.split(".")
    for key in keys:
        target = target[key]
    target[last] = value
    return dumps([dumps(payload), envelope[1]])


def verdict(blob: bytes) -> bytes:
    return evaluate(blob, evaluated_at=AT, replay_state={"entries": []}).verdict_bytes


def corpus() -> list[tuple[str, str, str, bytes]]:
    """(label, schema, root, bytes) for every conformant fixture, demo bundle, and their verdicts."""
    items: list[tuple[str, str, str, bytes]] = []
    for path in sorted(path for directory in KAT_DIRECTORIES for path in directory.glob("*.json")):
        descriptor = json.loads(path.read_text())
        if descriptor.get("expectation", "conformant") != "conformant":
            continue
        kind = descriptor.get("object_type", "bundle")
        root = "aar-wire-object" if kind == "bundle" or kind.endswith("-envelope") else kind
        items.append((str(path.relative_to(ROOT)), CORE, root, path.with_suffix(".cbor").read_bytes()))
    with tempfile.TemporaryDirectory() as tmp:
        try:
            if subprocess.run(["bun", "run", str(ROOT / "demo" / "ep" / "golden.ts"), tmp]).returncode != 0:
                sys.exit("demo bundles: `bun run demo/ep/golden.ts` failed")
        except OSError:
            sys.exit("engine unsupported: bun not found (demo bundles come from `bun run demo/ep/golden.ts`)")
        items += [(f"demo golden {p.stem}", CORE, "aar-wire-object", p.read_bytes()) for p in sorted(Path(tmp).glob("*.cbor"))]
    items += [(f"{label} verdict", VERDICT, "verdict-envelope", verdict(blob)) for label, _, root, blob in list(items) if root == "aar-wire-object" and loads(blob).__class__ is dict]
    return items


def probes() -> list[tuple[str, str, str, bytes, bool, bool]]:
    """(label, schema, root, bytes, expect_accept, engine_self_test)."""
    credential = (POSITIVE / "credential-ep-signing-aar-2a.cbor").read_bytes()
    observation = (POSITIVE / "receipt-observation-agent-root.cbor").read_bytes()
    attempt = (POSITIVE / "receipt-action-attempt.cbor").read_bytes()
    manifest = (POSITIVE / "epoch-manifest-populated.cbor").read_bytes()
    signed_verdict = verdict((POSITIVE / "bundle-valid-subset.cbor").read_bytes())
    item = loads(loads(observation)[0])["body"]["consumption"]["items"][0]
    target = loads(loads(manifest)[0])["anchor_plan"]["targets"][0]
    consumption = lambda count: mutate(observation, "body.consumption.items", [item] * count)  # noqa: E731
    credential_payload = loads(loads(credential)[0])
    return [
        ("self-test .cbor inner not a credential", CORE, "credential-envelope", dumps([dumps({"v": 2}), loads(credential)[1]]), False, True),
        ("self-test .cbor twin", CORE, "credential-envelope", credential, True, True),
        ("self-test closed map extra key", CORE, "credential-envelope", mutate(credential, "extra", 1), False, True),
        ("self-test closed map twin", CORE, "credential-envelope", dumps([dumps(credential_payload), loads(credential)[1]]), True, True),
        ("D1 principal_type authority_source", CORE, "credential-envelope", mutate(credential, "principal_type", "authority_source"), False, True),
        ("D1 principal_type service twin", CORE, "credential-envelope", mutate(credential, "principal_type", "service"), True, True),
        ("self-test id16 given 32 bytes", CORE, "credential-envelope", mutate(credential, "tenant_id", bytes(32)), False, True),
        ("self-test id16 given 15 bytes", CORE, "credential-envelope", mutate(credential, "tenant_id", bytes(15)), False, True),
        ("self-test id16 twin", CORE, "credential-envelope", mutate(credential, "tenant_id", bytes(16)), True, True),
        ("D2 consumption empty", CORE, "receipt-envelope", consumption(0), False, True),
        ("D2 consumption 4097", CORE, "receipt-envelope", consumption(4097), False, True),
        ("D2 consumption 1", CORE, "receipt-envelope", consumption(1), True, True),
        ("D2 consumption 4096", CORE, "receipt-envelope", consumption(4096), True, True),
        ("D2 exclusion unknown reason", CORE, "receipt-envelope", mutate(attempt, "body.command.excluded_fields", [{"name": "x", "reason": "bogus", "value_commitment": bytes(32)}]), False, False),
        ("D2 exclusion without value_commitment", CORE, "receipt-envelope", mutate(attempt, "body.command.excluded_fields", [{"name": "x", "reason": "secret"}]), False, False),
        ("D2 zero exclusions", CORE, "receipt-envelope", mutate(attempt, "body.command.excluded_fields", []), True, False),
        ("D2 basis unknown", CORE, "epoch-manifest-envelope", mutate(manifest, "anchor_plan.independence.basis", "independent"), False, False),
        ("D2 one anchor target", CORE, "epoch-manifest-envelope", mutate(manifest, "anchor_plan.targets", [target]), True, False),
        ("D4 custody partially_evidenced", VERDICT, "verdict-envelope", mutate(signed_verdict, "limits.custody_continuity", "partially_evidenced"), False, False),
        ("D4 custody not_established twin", VERDICT, "verdict-envelope", signed_verdict, True, False),
    ]


def main() -> int:
    exe = engine()
    for label, schema, root, blob, expect_accept, self_test in probes():
        if accepts(exe, schema, root, blob) != expect_accept:
            print(f"FAIL {'engine unsupported: ' if self_test else ''}{label}: production={root} expected={'accept' if expect_accept else 'reject'}")
            return 1
    items = corpus()
    failures = [(label, root, blob) for label, schema, root, blob in items if not accepts(exe, schema, root, blob)]
    for label, root, blob in failures:
        print(f"FAIL {label}: production={root} expected=accept path={narrow(exe, blob)}")
    if failures:
        return 1
    print(f"schema oracle: cddl gem {ENGINE_VERSION}; {len(items)} corpus objects accepted, 20 probes matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
