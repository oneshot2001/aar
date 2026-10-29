"""End-to-end build tests on the onvif-mcp corpus (skipped when it is absent). Collected by
``python3 -B -m unittest pyref.examiner_package_test`` through that module's import."""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from pyref import examiner_package as ep
from pyref.cbor import dumps, loads
from pyref.crypto import public_spki
from pyref.examiner_package import check_run3, mint_examiner_chain

REPO = Path(__file__).resolve().parents[1]
CORPUS = Path.home() / "Projects" / "onvif-mcp" / "receipts"
FACTS = {"specimen_kind": "test specimen", "coverage_sentence": "complete relative to the selected producer-declared indexes",
         "d66_sentence": "D-66 sentence.", "asserts": {"no_conformant_tool_action_other_than": ["camera.stream.view"]},
         "verified_against": {"bundle_digest": None},
         "facts": [{"label": "anchor log", "text": "This bundle carries no anchor.", "ref": "ref"},
                   {"label": "bundle and exporter", "text": "The bundle file is unsigned (D-36).", "ref": "D-36", "generated_prefix": "artifact_inventory"}]}
ACQUISITION = {"source": {"repo_path": "x/<specimen-dir>/", "host_label": "Mac Studio (test)", "collector_label": "test"}, "files": [],
               "copy_method": "", "tool_versions": {}, "collection_time_utc": None, "platform": None, "errors": [], "transformations": []}


def tree_hashes(package: Path) -> dict[str, str]:
    return {p.relative_to(package).as_posix(): ep.file_sha256(p) for p in package.rglob("*") if p.is_file()}


@unittest.skipUnless(CORPUS.is_dir(), "onvif-mcp corpus not present")
class FullBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = cls.root = Path(cls.tmp.name)
        pick, _ = ep.select_specimen(CORPUS / "aar", CORPUS, "q6358")
        inputs = cls.inputs = root / "inputs"
        inputs.mkdir()
        facts = {**FACTS, "verified_against": {"bundle_digest": pick["bundle_digest"]}}
        (inputs / "specimen-facts.json").write_text(json.dumps(facts))
        (inputs / "acquisition.json").write_text(json.dumps(ACQUISITION))
        assert ep.build(CORPUS / "aar", CORPUS, CORPUS, inputs, root / "first", "q6358") == 0
        shutil.copyfile(root / "first" / "acquisition-full.json", inputs / "acquisition.json")
        for name in ("second", "third"):
            assert ep.build(CORPUS / "aar", CORPUS, CORPUS, inputs, root / name, "q6358") == 0
        cls.package = root / "second" / "package"
        cls.run1 = cls.package / "02-verify" / "run1.json"
        cls.keys = root / "keys"
        cls.minted = mint_examiner_chain.mint(cls.keys, json.loads(cls.run1.read_text())["evaluated_at"], cls.package / "01-copy" / "trust-policy.json")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_builds_identical_and_inventory(self):
        second, third = self.root / "second", self.root / "third"
        for file in sorted(p for p in second.rglob("*") if p.is_file()):
            self.assertEqual(file.read_bytes(), (third / file.relative_to(second)).read_bytes(), str(file))
        self.assertEqual((second / "examiner-package-v0.1.tar.sha256").read_text(),
                         ep.sha256_hex(gzip.decompress((second / "examiner-package-v0.1.tar.gz").read_bytes())) + "  examiner-package-v0.1.tar\n")
        page = (self.package / "00-READ-FIRST.md").read_text()
        self.assertTrue(page.startswith("# 00 — READ FIRST\n\n" + ep.OPENING))
        self.assertIn("Artifacts carried in this bundle, from the decoded bytes: ", page)
        self.assertIn("anchors (signed) 0", page)
        inventory = json.loads((self.package / "01-copy" / "inventory.json").read_text())
        self.assertNotIn("01-copy/inventory.json", {row["path"] for row in inventory["files"]})
        self.assertIn("01-copy/acquisition.json", {row["path"] for row in inventory["files"]})
        run1 = json.loads(self.run1.read_text())
        self.assertEqual((run1["exit"], run1["result"]), (0, "conformant"))
        self.assertNotIn("interpreter", run1)
        self.assertIn("sys.executable", (self.package / "03-source-and-run.md").read_text())
        self.assertIn("## Not decoded", (self.package / "05-text-fields.md").read_text())
        self.assertNotIn("inclusion.siblings", (self.package / "05-text-fields.md").read_text())
        self.assertIn("Identifier-sized byte strings", (self.package / "appendix" / "text-fields-zero.md").read_text())
        self.assertIn("This bundle carries no anchor.", (self.package / "04-operator-records" / "anchor.jsonl.md").read_text())

    def test_reproducible_set_excludes_only_03_and_inventory(self):
        # Amendment (j): a different interpreter path changes 03 and inventory.json and nothing else.
        alt = self.root / "alt-python"
        os.symlink(sys.executable, alt)
        original = sys.executable
        sys.executable = str(alt)
        try:
            self.assertEqual(ep.build(CORPUS / "aar", CORPUS, CORPUS, self.inputs, self.root / "fourth", "q6358"), 0)
        finally:
            sys.executable = original
        base, other = tree_hashes(self.package), tree_hashes(self.root / "fourth" / "package")
        self.assertEqual(set(base), set(other))
        differing = {path for path in base if base[path] != other[path]}
        self.assertEqual(differing, set(ep.OUTSIDE_REPRODUCIBLE_SET))
        self.assertIn(str(alt), (self.root / "fourth" / "package" / "03-source-and-run.md").read_text())

    def test_tarball_carries_no_absolute_path_or_host(self):
        with tarfile.open(self.root / "second" / "examiner-package-v0.1.tar.gz") as tar:
            members = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
        for name, data in members.items():
            self.assertNotIn(b"/Users/", data, name)
            self.assertNotIn(b"Agents-MacBook", data, name)
            if not name.endswith("01-copy/acquisition.json"):
                self.assertNotIn(b"Mac Studio", data, name)
        self.assertIn(b"Mac Studio (test)", members[f"{ep.PACKAGE_NAME}/01-copy/acquisition.json"])
        self.assertIn(b"<local>", members[f"{ep.PACKAGE_NAME}/04-operator-records/chain.jsonl"])
        self.assertIn("identified derivative", (self.package / "04-operator-records" / "chain.jsonl.md").read_text())
        self.assertIn("/Users/", (self.root / "first" / "acquisition-full.json").read_text())

    def test_run3_controlled_and_transcript_modes(self):
        self.assertEqual((self.keys / "examiner.key").stat().st_mode & 0o777, 0o600)
        before = tree_hashes(self.package)
        results = check_run3.check(self.keys, self.run1)
        self.assertEqual([name.split()[0] for name, _, _ in results][:12], [str(i) for i in range(12)])
        self.assertTrue(all(passed for _, passed, _ in results), results)
        self.assertIn("--trust-policy 01-copy/trust-policy.json --prior-state 01-copy/prior-state.json --policy", results[0][2])
        self.assertIn(self.minted["leaf_kid"], results[1][2])
        self.assertEqual(tree_hashes(self.package), before)  # nothing written inside the package (R5)
        for name in ("run3.stdout.txt", "run3.verdict.cbor", "run3.sig_structure.bin", "run3.leaf-spki.der", "run3.signature.der"):
            self.assertTrue((self.keys / name).is_file(), name)
        good = self.keys / "run3.stdout.txt"
        # Codex P1-2 residual: a transcript from a run WITHOUT --trust-policy, edited down to Result + CBOR hex,
        # passes lines 1-10 under --stdout and is therefore headed UNVERIFIED; the controlled mode has no stdout to edit.
        at = json.loads(self.run1.read_text())["evaluated_at"]
        run = ep.run_verifier(self.package, "01-copy/bundle.cbor", at, None, "01-copy/prior-state.json",
                              str(self.keys / "examiner-policy.json"), str(self.keys / "examiner.key"))
        self.assertEqual(run["exit"], 0, run["stderr"])
        edited = self.root / "edited.stdout.txt"
        edited.write_text("\n".join(l for l in run["stdout"].splitlines() if l.startswith(("Result:", "  CBOR hex:"))) + "\n")
        results = check_run3.check(self.keys, self.run1, edited)
        self.assertTrue(all(passed for name, passed, _ in results if name.split()[0] in {str(i) for i in range(1, 11)}), results)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            check_run3.main(["--keys", str(self.keys), "--run1", str(self.run1), "--stdout", str(edited)])
        self.assertTrue(out.getvalue().startswith(check_run3.UNVERIFIED))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(check_run3.main(["--keys", str(self.keys), "--run1", str(self.run1)]), 0)
        self.assertNotIn("UNVERIFIED", out.getvalue())
        self.assertTrue(out.getvalue().startswith("PASS  0 controlled invocation"))
        # (i) Codex P1-1: substituted leaf SPKI, original kid and credential signature kept.
        bad = self.root / "bad-spki"
        shutil.copytree(self.keys, bad)
        policy = json.loads((bad / "examiner-policy.json").read_text())
        credentials = []
        for item in policy["verifier_credentials"]:
            envelope = loads(bytes.fromhex(item))
            payload = loads(envelope[0])
            if payload["key_usage"] == "verifier_signing":
                payload["public_key"] = public_spki(789)
                envelope = [dumps(payload), envelope[1]]
            credentials.append(dumps(envelope).hex())
        policy["verifier_credentials"] = credentials
        (bad / "examiner-policy.json").write_text(json.dumps(policy))
        results = check_run3.check(bad, self.run1, good)
        self.assertFalse(results[0][1], results)
        # (ii) a second chain's policy and key against chain A's verdict.
        other = self.root / "other"
        mint_examiner_chain.mint(other, at, self.package / "01-copy" / "trust-policy.json")
        failed = {name.split()[0] for name, passed, _ in check_run3.check(other, self.run1, good) if not passed}
        self.assertTrue(failed & {"2", "3", "4"}, failed)
        # (iii) run-1 stdout fed as a transcript.
        results = check_run3.check(self.keys, self.run1, self.package / "02-verify" / "run1.stdout.txt")
        self.assertFalse(all(passed for _, passed, _ in results), results)

    @unittest.skipUnless(shutil.which("openssl") and shutil.which("bash"), "openssl and bash needed")
    def test_printed_commands_run_verbatim_from_a_fresh_extraction(self):
        extract = self.root / "extract"
        extract.mkdir()
        with tarfile.open(self.root / "second" / "examiner-package-v0.1.tar.gz") as tar:
            tar.extractall(extract, filter="data")
        package = extract / ep.PACKAGE_NAME
        readme = (package / "02-verify" / "README.md").read_text()
        blocks = re.findall(r"```\n(.*?)```", readme.split("## Run 2")[0], re.DOTALL)
        script = "set -euo pipefail\n" + "\n".join(blocks)
        proc = subprocess.run(["bash", "-c", script], cwd=package, capture_output=True, text=True,
                              env={**os.environ, "AAR": str(REPO)})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Verified OK", proc.stdout + proc.stderr)
        self.assertIn("PASS  0 controlled invocation", proc.stdout)
        self.assertEqual(proc.stdout.count("FAIL"), 0, proc.stdout)
        self.assertNotIn("UNVERIFIED", proc.stdout)
        self.assertTrue((extract / "examiner-keys" / "run3.stdout.txt").exists())
        # R5: the extracted package tree still equals inventory.json after the run.
        inventory = {row["path"]: row["sha256"] for row in json.loads((package / "01-copy" / "inventory.json").read_text())["files"]}
        actual = tree_hashes(package)
        self.assertEqual(set(actual), set(inventory) | {"01-copy/inventory.json"})
        self.assertEqual({path: actual[path] for path in inventory}, inventory)
