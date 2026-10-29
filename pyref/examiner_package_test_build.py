"""End-to-end build tests on the onvif-mcp corpus (skipped when it is absent). Collected by
``python3 -B -m unittest pyref.examiner_package_test`` through that module's import."""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
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


@unittest.skipUnless(CORPUS.is_dir(), "onvif-mcp corpus not present")
class FullBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = cls.root = Path(cls.tmp.name)
        pick, _ = ep.select_specimen(CORPUS / "aar", CORPUS, "q6358")
        inputs = root / "inputs"
        inputs.mkdir()
        facts = {**FACTS, "verified_against": {"bundle_digest": pick["bundle_digest"]}}
        (inputs / "specimen-facts.json").write_text(json.dumps(facts))
        (inputs / "acquisition.json").write_text(json.dumps(ACQUISITION))
        assert ep.build(CORPUS / "aar", CORPUS, CORPUS, inputs, root / "first", "q6358") == 0
        shutil.copyfile(root / "first" / "acquisition-full.json", inputs / "acquisition.json")
        for name in ("second", "third"):
            assert ep.build(CORPUS / "aar", CORPUS, CORPUS, inputs, root / name, "q6358") == 0
        cls.package = root / "second" / "package"
        cls.run1 = json.loads((cls.package / "02-verify" / "run1.json").read_text())
        cls.keys = root / "keys"
        cls.minted = mint_examiner_chain.mint(cls.keys, cls.run1["evaluated_at"], cls.package / "01-copy" / "trust-policy.json")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run3(self, keys: Path, name: str, trust="01-copy/trust-policy.json", prior="01-copy/prior-state.json") -> Path:
        run = ep.run_verifier(self.package, "01-copy/bundle.cbor", self.run1["evaluated_at"], trust, prior,
                              os.path.relpath(keys / "examiner-policy.json", self.package), os.path.relpath(keys / "examiner.key", self.package))
        self.assertEqual(run["exit"], 0, run["stderr"])
        path = self.root / f"{name}.stdout.txt"
        path.write_text(run["stdout"])
        return path

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
        self.assertEqual((self.run1["exit"], self.run1["result"]), (0, "conformant"))
        self.assertIn("## Not decoded", (self.package / "05-text-fields.md").read_text())
        self.assertNotIn("inclusion.siblings", (self.package / "05-text-fields.md").read_text())
        self.assertIn("Identifier-sized byte strings", (self.package / "appendix" / "text-fields-zero.md").read_text())
        self.assertIn("This bundle carries no anchor.", (self.package / "04-operator-records" / "anchor.jsonl.md").read_text())

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

    def test_run3_positive_and_negatives(self):
        self.assertEqual((self.keys / "examiner.key").stat().st_mode & 0o777, 0o600)
        results = check_run3.check(self.run3(self.keys, "run3"), self.keys, self.package / "02-verify" / "run1.json")
        self.assertEqual([name[:2].strip() for name, _, _ in results][:11], [str(i) for i in range(1, 12)])
        self.assertTrue(all(passed for _, passed, _ in results), results)
        self.assertIn(self.minted["leaf_kid"], results[0][2])
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
        results = check_run3.check(self.root / "run3.stdout.txt", bad, self.package / "02-verify" / "run1.json")
        self.assertFalse(results[0][1], results)
        # (ii) a second chain's policy and key against chain A's verdict.
        other = self.root / "other"
        mint_examiner_chain.mint(other, self.run1["evaluated_at"], self.package / "01-copy" / "trust-policy.json")
        results = check_run3.check(self.root / "run3.stdout.txt", other, self.package / "02-verify" / "run1.json")
        failed = {name for name, passed, _ in results if not passed}
        self.assertTrue(any(name.startswith(("2 ", "3 ", "4 ")) for name in failed), results)
        # (iii) Codex P1-2: run 3 without --trust-policy / --prior-state.
        results = check_run3.check(self.run3(self.keys, "run3-nopins", trust=None, prior=None), self.keys, self.package / "02-verify" / "run1.json")
        failed = {name for name, passed, _ in results if not passed}
        self.assertTrue(any(name.startswith("8 ") for name in failed) and any(name.startswith("11 ") for name in failed), results)
        # (iv) run-1 stdout fed as run 3.
        results = check_run3.check(self.package / "02-verify" / "run1.stdout.txt", self.keys, self.package / "02-verify" / "run1.json")
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
        self.assertEqual(proc.stdout.count("FAIL"), 0, proc.stdout)
        self.assertTrue((extract / "examiner-keys" / "examiner.key").exists())
        self.assertFalse(any(p.name.startswith("run3") for p in (package / "02-verify").iterdir()))
