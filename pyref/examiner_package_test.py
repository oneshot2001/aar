"""python3 -B -m unittest pyref.examiner_package_test

Synthetic candidates come from the KAT corpus under a temp dir; the onvif-mcp corpus tests run only
when ~/Projects/onvif-mcp/receipts exists (they are skipped, not failed, elsewhere).
"""

from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from pyref import examiner_package as ep
from pyref.cbor import dumps, loads
from pyref.examiner_package import check_run3, mint_examiner_chain

REPO = Path(__file__).resolve().parents[1]
KAT = REPO / "kats" / "positive" / "bundle-valid-subset.cbor"
CORPUS = Path.home() / "Projects" / "onvif-mcp" / "receipts"
EXPECTED_PICK = "1792172898-camera-stream-view-q6358-78f38116"
EXPECTED_STILL = "snap-q6358-1792172897320.jpg"
FACTS = {"specimen_kind": "test specimen", "coverage_sentence": "complete relative to the selected producer-declared indexes",
         "d66_sentence": "D-66 sentence.", "facts": [{"label": "one", "text": "A fact.", "ref": "ref"}]}
ACQUISITION = {"source": {"repo_path": "x/<specimen-dir>/", "collector_label": "test"}, "files": [], "copy_method": "",
               "tool_versions": {}, "collection_time_utc": None, "platform": None, "errors": [], "transformations": []}


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
            self.assertEqual((rows["a-conformant"]["exit"], rows["a-conformant"]["reason"]), (0, "no-exact-still-match"))
            self.assertEqual(rows["b-refused"]["exit"], 2)
            self.assertIn("prior-state.prior_emissions must be strictly sorted and unique", rows["b-refused"]["reason"])
            self.assertEqual(rows["c-missing"]["reason"], "missing sidecar: meta.json")
            self.assertEqual((root / "b-refused" / "prior-state.json").read_text(), json.dumps({"prior_emissions": [entry, entry]}))
            with self.assertRaises(ep.PackageError):
                ep.select_specimen(root, root / "stills", "kat")

    @unittest.skipUnless(CORPUS.is_dir(), "onvif-mcp corpus not present")
    def test_real_corpus_pick(self):
        pick, rows = ep.select_specimen(CORPUS / "aar", CORPUS, "q6358")
        eligible = sorted((row for row in rows if row["still"]), key=lambda row: row["rank"])
        newest_q6358 = max((row for row in eligible if row["camera"] == "q6358"), key=lambda row: row["evaluated_at"])
        self.assertIs(pick, newest_q6358)
        self.assertTrue(pick["selected"] and pick["dir"].startswith(str(pick["evaluated_at"])))
        # The 2026-10-29 lock-time specimen stays conformant and still-matched; a newer capture outranks it by rule.
        known = next(row for row in rows if row["dir"] == EXPECTED_PICK)
        self.assertEqual((known["exit"], known["still"]), (0, EXPECTED_STILL))
        self.assertEqual([row["evaluated_at"] for row in eligible], sorted((row["evaluated_at"] for row in eligible), reverse=True))
        refused = [row for row in rows if row["exit"] == 2]
        self.assertTrue(refused and all("prior_emissions must be strictly sorted" in row["reason"] for row in refused))
        self.assertTrue(all(row["reason"] for row in rows))

    @unittest.skipUnless(CORPUS.is_dir(), "onvif-mcp corpus not present")
    def test_real_candidate_without_still_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(CORPUS / "aar" / EXPECTED_PICK, root / EXPECTED_PICK)
            (root / "stills").mkdir()
            [row] = ep.sweep(root, root / "stills")
            self.assertEqual((row["exit"], row["reason"], row["still"]), (0, "no-exact-still-match", None))


class TextFields(unittest.TestCase):
    def test_contract(self):
        sample = "a​b|‮\x07\U000E0100"
        self.assertEqual(ep.visible(sample), "a\\u200Bb\\|\\u202E\\u0007\\u{E0100}")
        self.assertEqual(ep.escaped(sample), "a\\u200Bb\\|\\u202E\\u0007\\u{E0100}")
        self.assertTrue(all(ep.is_invisible(c) for c in (0x200B, 0x202E, 0xFEFF, 0xFE0F, 0xE0100, 0x2060)))
        self.assertFalse(ep.is_invisible(ord("a")))

    def test_traversal_decodes_embedded_and_keeps_siblings_opaque(self):
        cose = dumps([dumps({1: -7}), {}, None, b"\x00" * 64])
        bundle = {"artifacts": {"receipts": [[dumps({"a": "x​y"}), cose]]},
                  "parameters_cbor": dumps({"k": "v"}), "canonical_bytes": b"\xff\xff",
                  "siblings": [b"\x01" * 32, b"\x02" * 32], "name": "plain"}
        texts, payloads = ep.text_rows(bundle)
        by_path = {row["path"]: row for row in texts}
        self.assertEqual(by_path["bundle.artifacts.receipts[0][0]{payload}.a"]["invisible"], [(1, 0x200B)])
        self.assertEqual(by_path["bundle.parameters_cbor{cbor}.k"]["text"], "v")
        self.assertIn("bundle.<key:name>", by_path)
        decoded = {row["path"]: row["decoded"] for row in payloads}
        self.assertEqual(decoded, {"bundle.artifacts.receipts[0][0]": True, "bundle.artifacts.receipts[0][1]": True,
                                   "bundle.artifacts.receipts[0][1]{cose}[0]": True, "bundle.parameters_cbor": True,
                                   "bundle.canonical_bytes": False})


class OperatorRecords(unittest.TestCase):
    def test_select_lines(self):
        journal = b'{"event":"x","invocation_id":"aa"}\n{"event":"y","receipt_id":"bb"}\n{"event":"z"}\nnot json\n'
        anchor = b'{"appended_at":5}\n{"appended_at":10}\n{"appended_at":11}\n'
        chain = b'{"ts":"2026-10-16T17:48:18.766Z"}\n{"ts":"2026-10-16T17:49:00Z"}\n[1]\n'
        self.assertEqual([n for n, _ in ep.select_lines("journal.jsonl", journal, (0, 0), {"aa"}, {"bb"})], [1, 2])
        self.assertEqual([n for n, _ in ep.select_lines("anchor.jsonl", anchor, (6, 10), set(), set())], [2])
        kept = ep.select_lines("chain.jsonl", chain, (1792172838, 1792172899), set(), set())
        self.assertEqual([(n, line) for n, line in kept], [(1, b'{"ts":"2026-10-16T17:48:18.766Z"}\n')])


class Tarball(unittest.TestCase):
    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg" / "sub").mkdir(parents=True)
            (root / "pkg" / "b.txt").write_text("b")
            (root / "pkg" / "sub" / "a.txt").write_text("a")
            ep.write_tarball(root / "pkg", root / "one.tar.gz", mtime=1792172898)
            (root / "pkg" / "b.txt").touch()
            ep.write_tarball(root / "pkg", root / "two.tar.gz", mtime=1792172898)
            self.assertEqual((root / "one.tar.gz").read_bytes(), (root / "two.tar.gz").read_bytes())
            self.assertEqual((root / "one.tar.gz").read_bytes()[3:9], b"\x00" * 6)  # gzip FLG 0 (no name), MTIME 0, XFL 0
            with tarfile.open(root / "one.tar.gz") as tar:
                members = tar.getmembers()
            self.assertEqual({(m.uid, m.gid, m.mtime, m.uname) for m in members}, {(0, 0, 1792172898, "")})
            self.assertEqual([m.name for m in members], [f"{ep.PACKAGE_NAME}/b.txt", f"{ep.PACKAGE_NAME}/sub", f"{ep.PACKAGE_NAME}/sub/a.txt"])


@unittest.skipUnless(CORPUS.is_dir(), "onvif-mcp corpus not present")
class FullBuild(unittest.TestCase):
    def test_build_twice_identical_and_run3_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = root / "inputs"
            inputs.mkdir()
            (inputs / "specimen-facts.json").write_text(json.dumps(FACTS))
            (inputs / "acquisition.json").write_text(json.dumps(ACQUISITION))
            self.assertEqual(ep.build(CORPUS / "aar", CORPUS, CORPUS, inputs, root / "first", "q6358"), 0)
            filled = json.loads((root / "first" / "package" / "01-copy" / "acquisition.json").read_text())
            self.assertTrue(filled["collection_time_utc"] and filled["files"] and filled["platform"])
            shutil.copyfile(root / "first" / "package" / "01-copy" / "acquisition.json", inputs / "acquisition.json")
            for name in ("second", "third"):
                self.assertEqual(ep.build(CORPUS / "aar", CORPUS, CORPUS, inputs, root / name, "q6358"), 0)
            second, third = root / "second", root / "third"
            for file in sorted(p for p in second.rglob("*") if p.is_file()):
                self.assertEqual(file.read_bytes(), (third / file.relative_to(second)).read_bytes(), str(file))
            package = second / "package"
            self.assertTrue((package / "00-READ-FIRST.md").read_text().startswith("# 00 — READ FIRST\n\n" + ep.OPENING))
            inventory = json.loads((package / "01-copy" / "inventory.json").read_text())
            self.assertNotIn("01-copy/inventory.json", {row["path"] for row in inventory["files"]})
            self.assertIn("01-copy/acquisition.json", {row["path"] for row in inventory["files"]})
            run1 = json.loads((package / "02-verify" / "run1.json").read_text())
            self.assertEqual((run1["exit"], run1["result"]), (0, "conformant"))
            self.assertIn("## Not decoded", (package / "05-text-fields.md").read_text())
            self.assertNotIn("inclusion.siblings", (package / "05-text-fields.md").read_text())
            keys = mint_examiner_chain.mint(root / "keys", run1["evaluated_at"], package / "01-copy" / "trust-policy.json")
            self.assertEqual((root / "keys" / "examiner.key").stat().st_mode & 0o777, 0o600)
            run3 = ep.run_verifier(package, "01-copy/bundle.cbor", run1["evaluated_at"], "01-copy/trust-policy.json",
                                   "01-copy/prior-state.json", "../../keys/examiner-policy.json", "../../keys/examiner.key")
            self.assertEqual(run3["exit"], 0, run3["stderr"])
            (root / "run3.stdout.txt").write_text(run3["stdout"])
            results = check_run3.check(root / "run3.stdout.txt", root / "keys" / "examiner-policy.json", package / "02-verify" / "run1.json")
            self.assertTrue(all(passed for _, passed, _ in results), results)
            self.assertIn(keys["leaf_kid"], results[1][2])


if __name__ == "__main__":
    unittest.main()
