"""python3 -B -m unittest pyref.examiner_package_test

Synthetic candidates come from the KAT corpus under a temp dir; the onvif-mcp corpus tests
(here and in ``examiner_package_test_build``, collected through the import below) run only when
~/Projects/onvif-mcp/receipts exists and are skipped, not failed, elsewhere.
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

from pyref import examiner_package as ep
from pyref.cbor import dumps, loads
from pyref.examiner_package_test_build import ACQUISITION, CORPUS, FACTS, FullBuild  # noqa: F401

REPO = Path(__file__).resolve().parents[1]
KAT = REPO / "kats" / "positive" / "bundle-valid-subset.cbor"
KNOWN_PICK = "1792172898-camera-stream-view-q6358-78f38116"
KNOWN_STILL = "snap-q6358-1792172897320.jpg"


def _hexify(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: _hexify(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_hexify(item) for item in value]
    return value


def kat_candidate(root: Path, name: str, prior: dict, sidecars=("meta.json", "trust-policy.json", "prior-state.json")) -> Path:
    directory = root / name
    directory.mkdir()
    shutil.copyfile(KAT, directory / "bundle.cbor")
    trust = loads(KAT.read_bytes())["trust_inputs"]
    files = {"meta.json": {"evaluated_at": trust["evaluation_time"], "camera": "kat", "tool_action": "kat"},
             "trust-policy.json": _hexify({key: value for key, value in trust.items() if key != "evaluation_time"}),
             "prior-state.json": prior}
    for sidecar in sidecars:
        (directory / sidecar).write_text(json.dumps(files[sidecar]))
    return directory


def synthetic_inputs(root: Path) -> Path:
    inputs = root / "inputs"
    inputs.mkdir()
    (inputs / "specimen-facts.json").write_text(json.dumps(FACTS))
    (inputs / "acquisition.json").write_text(json.dumps(ACQUISITION))
    for name in ("c", "s", "l"):
        (root / name).mkdir()
    return inputs


class SpecimenRule(unittest.TestCase):
    def test_synthetic_sweep_reasons(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "stills").mkdir()
            kat_candidate(root, "a-conformant", {})
            entry = {"issuer_kid": "00" * 32, "issuer_seq": 1, "epoch_owner_kid": "00" * 32, "epoch_id": 1, "epoch_seq": 1,
                     "receipt_id": "00" * 32, "envelope_digest": "00" * 32}
            kat_candidate(root, "b-refused", {"prior_emissions": [entry, entry]})
            kat_candidate(root, "c-missing", {}, sidecars=("trust-policy.json", "prior-state.json"))
            (root / "d-no-bundle").mkdir()
            rows = {row["dir"]: row for row in ep.sweep(root, root / "stills")}
            self.assertEqual(set(rows), {"a-conformant", "b-refused", "c-missing"})
            self.assertEqual(rows["a-conformant"]["exit"], 0)
            self.assertIn(rows["a-conformant"]["reason"], ("no-exact-still-match", "commitments-missing", "commitments-differ"))
            self.assertEqual(rows["b-refused"]["exit"], 2)
            self.assertIn("prior-state.prior_emissions must be strictly sorted and unique", rows["b-refused"]["reason"])
            self.assertEqual(rows["c-missing"]["reason"], "missing sidecar: meta.json")
            self.assertEqual((root / "b-refused" / "prior-state.json").read_text(), json.dumps({"prior_emissions": [entry, entry]}))
            with self.assertRaises(ep.PackageError):
                ep.select_specimen(root, root / "stills", "kat")

    def test_classify_reasons(self):
        d = b"\x01" * 32
        self.assertEqual(ep.classify_still(set(), {d}, {d.hex(): ["a"]}), (None, "commitments-missing"))
        self.assertEqual(ep.classify_still({d}, {b"\x02" * 32}, {d.hex(): ["a"]}), (None, "commitments-differ"))
        self.assertEqual(ep.classify_still({d}, {d}, {d.hex(): ["a", "b"]}), (None, "still-ambiguous"))
        self.assertEqual(ep.classify_still({d}, {d}, {}), (None, "no-exact-still-match"))
        self.assertEqual(ep.classify_still({d}, {d}, {d.hex(): ["a"]}), ("a", "conformant, exact still match"))

    def test_asserts_binding(self):
        rows = [{"exit": 0, "tool_action": "camera.ptz.preset"}, {"exit": 0, "tool_action": "camera.stream.view"}]
        pick = {"dir": "x", "bundle_digest": "ab"}
        facts = {"asserts": {"no_conformant_tool_action_other_than": ["camera.stream.view"]}, "verified_against": {"bundle_digest": "ab"}}
        with self.assertRaisesRegex(ep.PackageError, "no_conformant_tool_action_other_than.*camera.ptz.preset"):
            ep.check_asserts(facts, pick, rows)
        ep.check_asserts(facts, pick, rows[1:])
        with self.assertRaisesRegex(ep.PackageError, "verified_against.bundle_digest"):
            ep.check_asserts({**facts, "verified_against": {"bundle_digest": "cd"}}, pick, rows[1:])

    def test_asserts_are_closed(self):
        # Codex NEW-2: the typo must be an error, not a silent pass, even with a PTZ row present.
        rows = [{"exit": 0, "tool_action": "camera.ptz.preset"}]
        pick = {"dir": "x", "bundle_digest": "ab"}
        typo = {"asserts": {"no_conformant_tool_actions_other_than": ["camera.stream.view"]}, "verified_against": {"bundle_digest": "ab"}}
        with self.assertRaisesRegex(ep.PackageError, "unknown key 'no_conformant_tool_actions_other_than'"):
            ep.check_asserts(typo, pick, rows)
        for bad in ("camera.stream.view", [1], None):
            with self.assertRaisesRegex(ep.PackageError, "must be a list of str"):
                ep.validate_asserts({"asserts": {"no_conformant_tool_action_other_than": bad}})
        with self.assertRaisesRegex(ep.PackageError, "must be a JSON object"):
            ep.validate_asserts({"asserts": []})

    def test_out_as_file_is_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = synthetic_inputs(root)
            (root / "out").write_text("")
            with self.assertRaisesRegex(ep.PackageError, "--out"):
                ep.build(root / "c", root / "s", root / "l", inputs, root / "out", "q6358")
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["c", "inputs", "l", "out", "s"])

    def test_relative_or_short_root_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = synthetic_inputs(root)
            for logs, message in ((Path("."), "must be an absolute path"), (Path("receipts"), "must be an absolute path"),
                                  (Path("/"), "fewer than two path components"), (Path("/usr"), "fewer than two path components")):
                with self.assertRaisesRegex(ep.PackageError, message):
                    ep.build(root / "c", root / "s", logs, inputs, root / "out", "q6358")
            self.assertFalse((root / "out").exists())

    @unittest.skipUnless(CORPUS.is_dir(), "onvif-mcp corpus not present")
    def test_real_corpus_pick(self):
        pick, rows = ep.select_specimen(CORPUS / "aar", CORPUS, "q6358")
        eligible = sorted((row for row in rows if row["still"]), key=lambda row: row["rank"])
        newest_q6358 = max((row for row in eligible if row["camera"] == "q6358"), key=lambda row: row["evaluated_at"])
        self.assertIs(pick, newest_q6358)
        self.assertTrue(pick["selected"] and pick["dir"].startswith(str(pick["evaluated_at"])))
        self.assertEqual([row["evaluated_at"] for row in eligible], sorted((row["evaluated_at"] for row in eligible), reverse=True))
        known = next(row for row in rows if row["dir"] == KNOWN_PICK)
        self.assertEqual((known["exit"], known["still"]), (0, KNOWN_STILL))
        refused = [row for row in rows if row["exit"] == 2]
        self.assertTrue(refused and all("prior_emissions must be strictly sorted" in row["reason"] for row in refused))
        self.assertTrue(all(row["reason"] for row in rows))

    @unittest.skipUnless(CORPUS.is_dir(), "onvif-mcp corpus not present")
    def test_real_candidate_without_still_or_with_two_stills(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(CORPUS / "aar" / KNOWN_PICK, root / KNOWN_PICK)
            (root / "none").mkdir()
            [row] = ep.sweep(root, root / "none")
            self.assertEqual((row["exit"], row["reason"], row["still"]), (0, "no-exact-still-match", None))
            (root / "two").mkdir()
            for name in (KNOWN_STILL, "snap-q6358-copy.jpg"):
                shutil.copyfile(CORPUS / KNOWN_STILL, root / "two" / name)
            [row] = ep.sweep(root, root / "two")
            self.assertEqual((row["reason"], row["still"]), ("still-ambiguous", None))


class TextFields(unittest.TestCase):
    def test_contract(self):
        sample = "a​b|‮\x07\U000E0100 "
        self.assertEqual(ep.visible(sample), "a\\u200Bb\\|\\u202E\\u0007\\u{E0100}\\u2028")
        self.assertEqual(ep.escaped(sample), "a\\u200Bb\\|\\u202E\\u0007\\u{E0100}\\u2028")
        self.assertTrue(all(ep.is_invisible(c) for c in (0x200B, 0x202E, 0xFEFF, 0xFE0F, 0xE0100, 0x2060)))
        self.assertFalse(ep.is_invisible(ord("a")) or ep.is_invisible(0x2028))

    def test_traversal_decodes_embedded_and_inventories_bytes(self):
        cose = dumps([dumps({1: -7}), {}, None, b"\x00" * 64])
        bundle = {"artifacts": {"receipts": [[dumps({"a": "x​y"}), cose]]},
                  "parameters_cbor": dumps({"k": "v"}), "canonical_bytes": b"\xff\xff",
                  "siblings": [b"\x01" * 32, b"\x02" * 16], "blob": b"\x03" * 5, "name": "plain"}
        texts, payloads = ep.text_rows(bundle)
        by_path = {row["path"]: row for row in texts}
        self.assertEqual(by_path["bundle.artifacts.receipts[0][0]{payload}.a"]["invisible"], [(1, 0x200B)])
        self.assertEqual(by_path["bundle.parameters_cbor{cbor}.k"]["text"], "v")
        self.assertIn("bundle.<key:name>", by_path)
        kinds = {row["path"]: row["kind"] for row in payloads}
        self.assertEqual(kinds, {"bundle.artifacts.receipts[0][0]": "decoded", "bundle.artifacts.receipts[0][1]": "decoded",
                                 "bundle.artifacts.receipts[0][1]{cose}[0]": "decoded", "bundle.artifacts.receipts[0][1]{cose}[3]": "opaque",
                                 "bundle.parameters_cbor": "decoded", "bundle.canonical_bytes": "not-decoded",
                                 "bundle.siblings[0]": "identifier", "bundle.siblings[1]": "identifier", "bundle.blob": "opaque"})

    def test_nested_envelope_is_inventoried_not_hidden(self):
        # Codex P2-8 reproduction: an envelope-shaped pair under an unknown key inside canonical_bytes.
        cose = dumps([dumps({1: -7}), {}, None, b"\x00" * 64])
        bundle = {"canonical_bytes": dumps({"nested_envelope": [dumps({"text": "hidden‮"}), cose]})}
        texts, payloads = ep.text_rows(bundle)
        page = ep.page_05(texts, payloads, body=True)
        appendix = ep.page_05(texts, payloads, body=False)
        kinds = {p["path"]: p["kind"] for p in payloads if "nested_envelope" in p["path"]}
        # The 16-byte payload is identifier-sized by the R6 rule (appendix); the COSE bytes are opaque (body).
        self.assertEqual(kinds, {"bundle.canonical_bytes{cbor}.nested_envelope[0]": "identifier",
                                 "bundle.canonical_bytes{cbor}.nested_envelope[1]": "opaque"})
        self.assertIn("nested\\_envelope\\[0\\]", appendix)
        self.assertIn("nested\\_envelope\\[1\\]", page)
        self.assertNotIn("‮", page + appendix)
        self.assertFalse(any("hidden" in t["text"] for t in texts))

    def test_path_column_is_escaped(self):
        # Codex P2-7 reproduction: a bidi control in a key reaches the path column.
        texts, payloads = ep.text_rows({"parameters_cbor": dumps({"evil‮key": "normal", "a|b`c": "d"})})
        for body in (True, False):
            page = ep.page_05(texts, payloads, body=body)
            self.assertNotIn("‮", page)
        appendix = ep.page_05(texts, payloads, body=False)
        self.assertIn("evil\\u202Ekey", appendix)
        self.assertIn("a\\|b\\`c", appendix)


class OperatorRecords(unittest.TestCase):
    def test_select_lines(self):
        journal = b'{"event":"x","invocation_id":"aa"}\n{"event":"y","receipt_id":"bb"}\n{"event":"z"}\nnot json\n'
        anchor = b'{"appended_at":5}\n{"appended_at":10}\n{"appended_at":11}\n'
        chain = b'{"ts":"2026-10-16T17:48:18.766Z"}\n{"ts":"2026-10-16T17:49:00Z"}\n[1]\n'
        self.assertEqual([n for n, _ in ep.select_lines("journal.jsonl", journal, (0, 0), {"aa"}, {"bb"})[0]], [1, 2])
        self.assertEqual([n for n, _ in ep.select_lines("anchor.jsonl", anchor, (6, 10), set(), set())[0]], [2])
        kept, undated = ep.select_lines("chain.jsonl", chain, (1792172838, 1792172899), set(), set())
        self.assertEqual((kept, undated), ([(1, b'{"ts":"2026-10-16T17:48:18.766Z"}\n')], []))

    def test_offset_free_timestamp_never_interpreted(self):
        # Codex P2-10 reproduction under two TZ values: the naive line is undated and never selected.
        line = b'{"ts":"2026-10-16T17:48:18"}\n'
        original = os.environ.get("TZ")
        try:
            for zone in ("UTC", "America/Denver"):
                os.environ["TZ"] = zone
                time.tzset()
                kept, undated = ep.select_lines("chain.jsonl", line, (1792172838, 1792172899), set(), set())
                self.assertEqual(kept, [])
                self.assertEqual(undated, [(1, ep.sha256_hex(line))])
                self.assertIsNone(ep.iso_seconds("2026-10-16T17:48:18"))
                self.assertEqual(ep.iso_seconds("2026-10-16T17:48:18Z"), 1792172898)
        finally:
            if original is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = original
            time.tzset()

    def test_localize_whole_segments_only(self):
        roots = [Path("/x/receipts"), Path("/x/receipts/aar")]
        self.assertEqual(ep.localize(b'{"detail":"saved /x/receipts/a.jpg"}\n', roots), b'{"detail":"saved <local>/a.jpg"}\n')
        self.assertEqual(ep.localize(b'{"p":"/x/receipts"}', roots), b'{"p":"<local>"}')
        self.assertEqual(ep.localize(b'/x/receipts/aar/j.jsonl', roots), b'<local>/j.jsonl')
        self.assertEqual(ep.localize(b'{"p":"/x/receipts2/a.jpg"}', roots), b'{"p":"/x/receipts2/a.jpg"}')
        self.assertEqual(ep.localize(b'{"x":"a.b"}', roots), b'{"x":"a.b"}')  # Codex-style line, untouched
        self.assertEqual(ep.localize(b'{"x":"a.b"}', [Path("/a")]), b'{"x":"a.b"}')


class Tarball(unittest.TestCase):
    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg" / "sub").mkdir(parents=True)
            (root / "pkg" / "b.txt").write_text("b")
            (root / "pkg" / "sub" / "a.txt").write_text("a")
            digest = ep.write_tarball(root / "pkg", root / "one.tar.gz", mtime=1792172898)
            (root / "pkg" / "b.txt").touch()
            ep.write_tarball(root / "pkg", root / "two.tar.gz", mtime=1792172898)
            one = (root / "one.tar.gz").read_bytes()
            self.assertEqual(one, (root / "two.tar.gz").read_bytes())
            self.assertEqual(one[3:8], b"\x00" * 5)  # gzip FLG 0 (no name), MTIME 0
            self.assertEqual(one[8], 2)  # XFL: maximum compression (level 9)
            self.assertEqual(ep.sha256_hex(gzip.decompress(one)), digest)
            with tarfile.open(root / "one.tar.gz") as tar:
                members = tar.getmembers()
            self.assertEqual({(m.uid, m.gid, m.mtime, m.uname) for m in members}, {(0, 0, 1792172898, "")})
            self.assertEqual([m.name for m in members], [f"{ep.PACKAGE_NAME}/b.txt", f"{ep.PACKAGE_NAME}/sub", f"{ep.PACKAGE_NAME}/sub/a.txt"])


if __name__ == "__main__":
    unittest.main()
