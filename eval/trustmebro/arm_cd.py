#!/usr/bin/env python3
"""Arm C2 + Arm D — the honesty boundary of the receipt (AAR) gate.

These two arms exist so the eval cannot overclaim. Arms A/B/C1 show AAR converts
a keyless interceptor's silent bypass into a refusal. C2 and D mark exactly where
that stops and what remains:

  C2 (compromised valid signer): the attacker holds a producer signing key the
     trust policy accepts (a fully compromised producer). pyref returns
     conformant and the gate PROCEEDS -- AAR gives NO immunity here. What it does
     give is attribution: the action is non-repudiably bound to the signer's kid.
     The design's stated guarantee (design doc SS6): attribution + tamper-evidence,
     not compromised-signer prevention. This arm makes that boundary measurable by
     extracting the signer kid pyref would attribute the action to.

  D  (post-emission tamper): a genuine conformant bundle with ONE payload byte of
     an authorization receipt flipped after signing. pyref returns nonconformant
     at the signature step (the producer's COSE signature no longer covers the
     altered payload) and the gate REFUSES. This is the tamper-evidence half of
     the guarantee: you cannot silently edit a signed receipt.

Oracle is the model-independent `python -m pyref verify` exit code; `--at` is
pinned to the same fixed lab epoch as arm_b.py. Fully deterministic: both arms
derive from the committed positive KAT, so re-running reproduces the bytes.

Usage: python eval/trustmebro/arm_cd.py OUTDIR
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LAB_EPOCH = 1_735_689_800  # same fixed lab epoch as arm_b.py
LEGIT_BUNDLE = REPO / "kats" / "positive" / "bundle-valid-subset.cbor"
EXPECTED_SITE_ID = "e1071febe64adbd6af516ebeecb30a4c"


def run_pyref(bundle: Path, transcript: Path) -> int:
    cmd = [sys.executable, "-m", "pyref", "verify", str(bundle), "--at", str(LAB_EPOCH)]
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    shown = bundle.relative_to(REPO) if bundle.is_relative_to(REPO) else bundle
    transcript.write_text(
        f"$ python -m pyref verify {shown} --at {LAB_EPOCH}\n"
        f"{proc.stdout}{proc.stderr}\nexit_code: {proc.returncode}\n"
    )
    return proc.returncode


def authorization_signer_kid(bundle_bytes: bytes) -> str:
    """The kid the verifier attributes the authorization to -- the signer of the
    `authorization` receipt. This is the non-repudiable attribution AAR provides
    even when (as in C2) that key is compromised."""
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from pyref import cbor as C

    bundle = C.loads(bundle_bytes)
    for envelope in bundle["artifacts"]["receipts"]:
        payload = C.loads(envelope[0])
        if payload.get("kind") == "authorization":
            protected = C.loads(C.loads(envelope[1])[0])
            return protected[4].hex()  # COSE protected header label 4 = kid
    raise RuntimeError("no authorization receipt in bundle")


def tamper_one_payload_byte(bundle_bytes: bytes) -> bytes:
    """Flip one byte inside the authorization receipt's signed payload -- a
    minimal post-emission edit. The producer's signature no longer covers it."""
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from pyref import cbor as C

    bundle = C.loads(bundle_bytes)
    auth_payload = None
    for envelope in bundle["artifacts"]["receipts"]:
        if C.loads(envelope[0]).get("kind") == "authorization":
            auth_payload = envelope[0]
            break
    if auth_payload is None:
        raise RuntimeError("no authorization receipt to tamper")
    index = bundle_bytes.find(auth_payload)
    mutated = bytearray(bundle_bytes)
    mutated[index + len(auth_payload) // 2] ^= 0x01
    return bytes(mutated)


def write_decision(outdir: Path, name: str, lines: list[str]) -> None:
    (outdir / f"arm-{name}-decision.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print()


def arm_c2(outdir: Path) -> None:
    """Compromised valid signer: conformant + attributed, gate PROCEEDS.
    The compromise is a trust model, not a verifier-observable difference: the
    signing key is, by hypothesis, in attacker hands; the policy still accepts it,
    so pyref (correctly, per its guarantee) returns conformant. The eval's job is
    to DISCLOSE this and surface the attribution, not to pretend AAR blocks it."""
    bundle_bytes = LEGIT_BUNDLE.read_bytes()
    transcript = outdir / "arm-c2-pyref.txt"
    code = run_pyref(LEGIT_BUNDLE, transcript)
    verdict = {0: "conformant", 1: "nonconformant", 3: "indeterminate"}.get(code, f"error({code})")
    kid = authorization_signer_kid(bundle_bytes)
    proceeds = code == 0
    decision = "PROCEED (attributed)" if proceeds else "REFUSE"
    write_decision(outdir, "c2", [
        "arm: C2 (receipt/AAR gate -- compromised valid signer)",
        "attacker: holds a producer signing key the trust policy accepts",
        f"command: python -m pyref verify {LEGIT_BUNDLE.name} --at {LAB_EPOCH}",
        f"pyref_exit: {code}",
        f"pyref_verdict: {verdict}",
        f"attributed_signer_kid: {kid}",
        f"decision: {decision}",
        "boundary: AAR gives attribution + tamper-evidence, NOT compromised-signer",
        "  immunity. The action proceeds but is non-repudiably bound to the kid",
        "  above -- a silent bypass becomes an attributed, signed action.",
        f"transcript: {transcript}",
    ])


def arm_d(outdir: Path) -> None:
    """Post-emission one-byte tamper: nonconformant at the signature step, REFUSE."""
    tampered = outdir / "tampered-bundle.cbor"
    tampered.write_bytes(tamper_one_payload_byte(LEGIT_BUNDLE.read_bytes()))
    transcript = outdir / "arm-d-pyref.txt"
    code = run_pyref(tampered, transcript)
    verdict = {0: "conformant", 1: "nonconformant", 3: "indeterminate"}.get(code, f"error({code})")
    decision = "REFUSE" if code != 0 else "PROCEED"
    write_decision(outdir, "d", [
        "arm: D (receipt/AAR gate -- post-emission tamper)",
        "attacker: flips one byte of a signed authorization receipt after emission",
        f"command: python -m pyref verify {tampered.name} --at {LAB_EPOCH}",
        f"pyref_exit: {code}",
        f"pyref_verdict: {verdict}",
        f"decision: {decision}",
        "boundary: tamper-evidence -- a signed receipt cannot be silently edited;",
        "  the producer signature no longer verifies over the altered payload.",
        f"transcript: {transcript}",
    ])


def main() -> None:
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    arm_c2(outdir)
    arm_d(outdir)


if __name__ == "__main__":
    main()
