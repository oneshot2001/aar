"""Section preservation regressions for the KAT divergence report writers."""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyref import kat_report
from pyref.kat import Audit, _audit_nested_maps


class SectionAwareDivergences(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = subprocess.check_output(
            ["git", "show", "HEAD:pyref/DIVERGENCES.md"],
            cwd=Path(__file__).resolve().parents[1],
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "DIVERGENCES.md"
        self.path.write_bytes(self.original)
        patcher = patch.object(kat_report, "DIVERGENCES_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.c1 = {
            "fixture": "kats/c1-example.cbor",
            "check": "digest",
            "location": "$.payload.digest",
            "expected": "expected C1 digest",
            "produced": "produced C1 digest",
            "spec_sentences": ["Recompute the digest."],
            "ambiguity_hypothesis": "C1 example hypothesis.",
        }
        self.c2 = {
            "fixture": "kats/c2-example.cbor",
            "expected": {"result": "conformant"},
            "produced": {"result": "nonconformant"},
            "spec_sentence": "The first failure determines the verdict.",
            "ambiguity_hypothesis": "C2 example hypothesis.",
        }

    def section(self, report, heading):
        match = re.search(rb"(?m)^" + re.escape(heading.encode()) + rb"\r?\n", report)
        self.assertIsNotNone(match, heading)
        start = match.end()
        following = re.search(rb"(?m)^## ", report[start:])
        end = start + following.start() if following else len(report)
        return report[:start], report[start:end], report[end:]

    def assert_outside_unchanged(self, before, after, heading):
        prefix, _, suffix = self.section(before, heading)
        new_prefix, body, new_suffix = self.section(after, heading)
        self.assertEqual((new_prefix, new_suffix), (prefix, suffix))
        self.assertTrue(body.startswith(b"\n"))
        self.assertFalse(body.startswith(b"\n\n"))
        self.assertTrue(body.endswith(b"\n\n" if suffix else b"\n"))
        self.assertFalse(body.endswith(b"\n\n\n" if suffix else b"\n\n"))
        return body

    def test_empty_c1_run_leaves_the_committed_report_byte_identical(self):
        kat_report._write_divergences([])
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_empty_c2_run_leaves_the_committed_report_byte_identical(self):
        kat_report._write_c2_divergences([])
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_populated_c1_then_empty_c1_clears_the_resolved_finding(self):
        kat_report._write_divergences([self.c1])
        body = self.assert_outside_unchanged(self.original, self.path.read_bytes(), "## C1")
        self.assertIn(b"### 1. `kats/c1-example.cbor`", body)
        self.assertIn(b"- Location: `$.payload.digest`", body)
        self.assertNotIn(b"No C1 divergences recorded.", body)
        kat_report._write_divergences([])
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_c2_update_keeps_a_populated_c1_section(self):
        kat_report._write_divergences([self.c1])
        after_c1 = self.path.read_bytes()
        c1_body = self.section(after_c1, "## C1")[1]
        kat_report._write_c2_divergences([self.c2])
        populated = self.path.read_bytes()
        body = self.assert_outside_unchanged(after_c1, populated, "## C2 verdict/reason divergences")
        self.assertIn(b"### 1. `kats/c2-example.cbor`", body)
        self.assertNotIn(b"No verdict, reason-code, class, or determinism divergences recorded.", body)
        self.assertEqual(self.section(populated, "## C1")[1], c1_body)
        kat_report._write_c2_divergences([])
        self.assertEqual(self.section(self.path.read_bytes(), "## C1")[1], c1_body)
        self.assertEqual(self.path.read_bytes(), after_c1)
        self.assertNotIn(b"kats/c2-example.cbor", self.path.read_bytes())

    def test_c1_update_keeps_c2_findings_and_adjudication_history(self):
        kat_report._write_c2_divergences([self.c2])
        after_c2 = self.path.read_bytes()
        kat_report._write_divergences([self.c1])
        self.assert_outside_unchanged(after_c2, self.path.read_bytes(), "## C1")
        kat_report._write_divergences([])
        self.assertEqual(self.path.read_bytes(), after_c2)
        self.assertIn(b"## Adjudication history\n", self.path.read_bytes())

    def test_report_without_the_section_is_refused_and_left_unchanged(self):
        for writer, heading in (
            (kat_report._write_divergences, "## C1"),
            (kat_report._write_c2_divergences, "## C2 verdict/reason divergences"),
        ):
            for label, report in (
                ("old format", b"# C1 divergences\n\nNo divergences recorded.\n"),
                ("missing file", None),
                ("missing heading", self.original.replace(heading.encode() + b"\n", b"")),
                ("inexact heading", self.original.replace(heading.encode() + b"\n", heading.encode() + b" extra\n")),
            ):
                with self.subTest(writer=writer.__name__, report=label):
                    if report is None:
                        self.path.unlink()
                    else:
                        self.path.write_bytes(report)
                    with self.assertRaises(ValueError) as raised:
                        writer([])
                    self.assertIn(str(self.path), str(raised.exception))
                    self.assertIn(heading, str(raised.exception))
                    if report is None:
                        self.assertFalse(self.path.exists())
                    else:
                        self.assertEqual(self.path.read_bytes(), report)

    def test_newline_bearing_fields_cannot_end_a_section(self):
        injection = "\n## injected\r## injected"
        audit = Audit()
        _audit_nested_maps(
            {"key" + injection: {"canonical_bytes": b"example", "digest": bytes(32), "media_type": "text/plain"}},
            "$", audit,
        )
        self.assertIsNotNone(audit.mismatch)
        location = audit.mismatch["path"]
        self.assertIn(injection, location)
        self.c1["location"] = location
        self.c1["check"] += injection
        self.c1["spec_sentences"][0] += injection
        self.c2["spec_sentence"] += injection
        for writer, heading, finding in (
            (kat_report._write_divergences, "## C1", self.c1),
            (kat_report._write_c2_divergences, "## C2 verdict/reason divergences", self.c2),
        ):
            with self.subTest(writer=writer.__name__):
                finding["fixture"] += injection
                finding["ambiguity_hypothesis"] += injection
                finding["expected"] = "expected" + injection
                finding["produced"] = "produced" + injection
                writer([finding])
                body = self.assert_outside_unchanged(self.original, self.path.read_bytes(), heading)
                fields = [finding["fixture"], finding["ambiguity_hypothesis"], finding["expected"], finding["produced"]]
                fields += ([finding["check"], location, finding["spec_sentences"][0]]
                           if heading == "## C1" else [finding["spec_sentence"]])
                for field in fields:
                    self.assertIn(field.replace("\r", "\\r").replace("\n", "\\n").encode(), body)
                self.assertNotIn(b"\r", body)
                self.assertIsNone(re.search(rb"(?m)^## ", body))
                writer([])
                self.assertEqual(self.path.read_bytes(), self.original)

    def test_bytes_outside_the_section_are_preserved(self):
        edited = self.original
        for old, new in (
            (b"# Gate 4 clean-room divergences", b"# Edited report title"),
            (b"Generated by `python -m pyref.kat --slice c2`.", b"Generated by a different command."),
            (b"The standalone", b"Edited entry-point text. The standalone"),
            (b"The 20 Run A", b"Edited adjudication history. The 20 Run A"),
            (b"No open divergences remain.", b"Edited D-73 text; keep this adjudication."),
        ):
            self.assertIn(old, edited)
            edited = edited.replace(old, new)
        edited += b"\n## Later section\n\nKeep this later section.\n"
        # Mix LF and CRLF, including heading lines, to detect newline normalization.
        edited = b"".join(line + (b"\r\n" if index % 2 else b"\n")
                          for index, line in enumerate(edited.splitlines()))
        for writer, heading, finding in (
            (kat_report._write_divergences, "## C1", self.c1),
            (kat_report._write_c2_divergences, "## C2 verdict/reason divergences", self.c2),
        ):
            with self.subTest(writer=writer.__name__):
                self.path.write_bytes(edited)
                writer([finding])
                self.assert_outside_unchanged(edited, self.path.read_bytes(), heading)
                writer([])
                self.assert_outside_unchanged(edited, self.path.read_bytes(), heading)


if __name__ == "__main__":
    unittest.main()
