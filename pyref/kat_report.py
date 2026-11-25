"""Divergence report writing for the Gate 4 KAT runner (``pyref/DIVERGENCES.md``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DIVERGENCES_PATH = Path(__file__).resolve().parent / "DIVERGENCES.md"


def _stateful(evaluation: Any, arguments: dict[str, Any]) -> str:
    if arguments["prior_state"] is None:
        return "not_evaluated"
    if evaluation is None:
        return "evaluation_failed"
    value = evaluation.report["stateful_properties"]
    return "skipped" if value == "not_evaluated" else value


def _divergence(
    fixture: Path,
    check: str,
    mismatch: dict[str, Any],
    spec: str,
    hypothesis: str,
) -> dict[str, Any]:
    return {
        "fixture": str(fixture.relative_to(ROOT)),
        "check": check,
        "expected": mismatch.get("expected"),
        "produced": mismatch.get("produced"),
        "location": mismatch.get("path"),
        "spec_sentences": [spec],
        "ambiguity_hypothesis": hypothesis,
    }


def _replace_section(heading: str, lines: list[str]) -> None:
    try:
        report = DIVERGENCES_PATH.read_bytes().splitlines(keepends=True)
    except FileNotFoundError:
        raise ValueError(f"{DIVERGENCES_PATH}: missing heading {heading}") from None
    for index, line in enumerate(report):
        if line.rstrip(b"\r\n") == heading.encode("utf-8"):
            start = index + 1
            break
    else:
        raise ValueError(f"{DIVERGENCES_PATH}: missing heading {heading}")
    end = start
    while end < len(report) and not report[end].startswith(b"## "):
        end += 1
    body = "\n".join(lines).encode("utf-8")
    if not report[start - 1].endswith((b"\r", b"\n")):
        body = b"\n" + body
    if end < len(report):
        body += b"\n"
    DIVERGENCES_PATH.write_bytes(b"".join(report[:start]) + body + b"".join(report[end:]))


def _report_text(value: Any) -> str:
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def _write_divergences(divergences: list[dict[str, Any]]) -> None:
    lines = [""]
    if not divergences:
        lines.extend(["No C1 divergences recorded.", ""])
    for index, item in enumerate(divergences, 1):
        lines.extend(
            [
                f"### {index}. `{_report_text(item['fixture'])}` — {_report_text(item['check'])}",
                "",
                f"- Location: `{_report_text(item['location'])}`",
                f"- Expected: `{json.dumps(item['expected'], sort_keys=True)}`",
                f"- Produced: `{json.dumps(item['produced'], sort_keys=True)}`",
                "- Spec sentence(s) relied on:",
                "",
                f"  > {_report_text(item['spec_sentences'][0])}",
                "",
                f"- Ambiguity hypothesis: {_report_text(item['ambiguity_hypothesis'])}",
                "",
            ]
        )
    _replace_section("## C1", lines)


def _write_c2_divergences(divergences: list[dict[str, Any]]) -> None:
    lines = [""]
    if not divergences:
        lines.extend(["No verdict, reason-code, class, or determinism divergences recorded.", ""])
    for index, item in enumerate(divergences, 1):
        lines.extend([
            f"### {index}. `{_report_text(item['fixture'])}`",
            "",
            f"- Expected: `{json.dumps(item['expected'], sort_keys=True)}`",
            f"- Produced: `{json.dumps(item['produced'], sort_keys=True)}`",
            "- Spec sentence(s) relied on:",
            "",
            "  > First failure wins. No verifier may continue to a later step and substitute its reason for an earlier failure.",
            "",
            f"  > {_report_text(item['spec_sentence'])}",
            "",
            f"- Ambiguity hypothesis: {_report_text(item['ambiguity_hypothesis'])}",
            "",
        ])
    _replace_section("## C2 verdict/reason divergences", lines)


def _divergence_hypothesis(fixture: dict[str, Any]) -> str:
    expected = fixture.get("expected_code")
    produced = fixture.get("produced_code")
    if fixture.get("expected_class") is not None:
        return (
            "The verdict result/reason agrees, but the C2 reporter selected the class dimension from the boundary's "
            "left-hand label (for example `proxy_captured_to_provider_attested`) and therefore reported the outcome "
            "dimension as `not_evaluated`. This is likely a pyref boundary-reporting bug, not a wire-verdict disagreement."
        )
    if produced == "credential/status-missing":
        return (
            "Changing and re-identifying the stapled snapshot leaves the clean-room reading of the decision's exact "
            "status_snapshot_id reference unresolved, making status-missing earlier than the intended status/lease defect. "
            "The fixture may intend the mutated snapshot to replace that reference implicitly, which the spec does not state."
        )
    if expected and expected.startswith("delegation/") and produced is None:
        return (
            "The mutated top-level delegation artifact is not the byte-identical delegation embedded in the carried "
            "authorization. Pyref applies attempt-time delegation checks to the embedded dominating delegation and treats "
            "the unreferenced top-level artifact as validly signed content; the fixture appears to require lifecycle/scope "
            "evaluation of every carried delegation even when it is not selected by an authorization path."
        )
    if expected == "epoch/late-insertion":
        return (
            "Pyref checked the close event's declared anchor deadline before comparing receipt commit time with the changed "
            "manifest close. Step 14 lists late-arrival routing before anchor deadline, so this is likely a pyref intra-step "
            "ordering bug exposed by a fixture carrying both consequences of the close-time mutation."
        )
    if expected and expected.startswith("manifest/index-") and produced == "manifest/index-root-mismatch":
        return (
            "The changed signed index entry bytes no longer recompute to the carried root. Pyref follows step 15's literal "
            "order, 'Recompute entry leaves and root, then require sort order, contiguous leaf indices, unique ...', so it "
            "reports root mismatch before the fixture's intended later index defect."
        )
    if expected == "bundle/artifact-out-of-scope" and produced == "bundle/range-boundary":
        return (
            "Pyref compares each carried range against every objective manifest entry in the half-open temporal slice before "
            "checking extra carried artifacts. The fixture appears to treat that range as boundary-complete under a narrower "
            "selector reading, while D-19 says ranges carry nonmatching kinds/subjects as well."
        )
    return (
        "The clean-room implementation and fixture expectation differ on the first applicable validation step or exact "
        "semantic trigger. No fixture-specific verifier tuning was applied after the formal corpus run."
    )
