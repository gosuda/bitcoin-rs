"""Offline regressions for the corpus seed-content invariant.

scripts/validate-corpus-seeds.sh owns the rule shared by the fuzz campaign
worker and the corpus publication job: every entry (including dotfiles and
nested paths, which shell globs miss but rsync copies) must be a
non-symlink regular file named by its own SHA-1, within FUZZ_MAX_SEED_BYTES,
with a positive count inside the sanity budget. Modes normalize to 0644.
"""

import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "validate-corpus-seeds.sh"
POLICY = SCRIPT.with_name("fuzz-policy.sh")
_budget = re.search(
    r"^readonly FUZZ_MAX_SEED_BYTES=([0-9]+)\s*(?:#.*)?$",
    POLICY.read_text(),
    re.M,
)
if _budget is None or int(_budget.group(1)) < 1:
    raise RuntimeError("Cannot read the positive FUZZ_MAX_SEED_BYTES policy")
BUDGET = int(_budget.group(1))


def run_validator(*args):
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )

class ValidateCorpusSeedsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.corpus = Path(self.tmp.name) / "corpus"
        self.corpus.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def add_seed(self, content: bytes, name: str | None = None):
        digest = hashlib.sha1(content).hexdigest()
        path = self.corpus / (name if name is not None else digest)
        path.write_bytes(content)
        return path

    def test_valid_corpus_passes(self):
        # The publish job invokes the validator by path, so the exec bit is
        # part of the contract (subprocess "bash script" calls would not
        # catch a missing one).
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        self.add_seed(b"good-seed")
        self.add_seed(b"another-seed")
        proc = run_validator(str(self.corpus), "t")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for entry in self.corpus.iterdir():
            self.assertEqual(oct(entry.stat().st_mode & 0o777), "0o644")

    def test_misnamed_seed_fails(self):
        self.add_seed(b"tampered", name="0" * 40)
        proc = run_validator(str(self.corpus), "t")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not named by its sha1", proc.stderr)

    def test_dotfile_payload_fails(self):
        self.add_seed(b"good-seed")
        self.add_seed(b"hidden", name=".payload")
        proc = run_validator(str(self.corpus), "t")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(".payload", proc.stderr)

    def test_nested_path_fails(self):
        self.add_seed(b"good-seed")
        nested = self.corpus / "sub"
        nested.mkdir()
        content = b"nested"
        (nested / hashlib.sha1(content).hexdigest()).write_bytes(content)
        proc = run_validator(str(self.corpus), "t")
        self.assertNotEqual(proc.returncode, 0)

    def test_symlink_fails(self):
        target = self.add_seed(b"good-seed")
        digest = hashlib.sha1(b"link-target").hexdigest()
        os.symlink(target, self.corpus / digest)
        proc = run_validator(str(self.corpus), "t")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("non-regular", proc.stderr)

    def test_oversized_seed_fails(self):
        self.add_seed(b"x" * (BUDGET + 1))
        proc = run_validator(str(self.corpus), "t")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("oversized", proc.stderr)

    def test_empty_corpus_fails(self):
        proc = run_validator(str(self.corpus), "t")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing empty corpus", proc.stderr)

    def test_budget_flags_reject_flood(self):
        self.add_seed(b"one")
        self.add_seed(b"two")
        proc = run_validator(
            "-n", "1", "-b", "268435456",
            str(self.corpus), "t",
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("over budget", proc.stderr)

    def test_budget_flags_accept_within_cap(self):
        self.add_seed(b"one")
        proc = run_validator(
            "-n", "65536", "-b", "268435456",
            str(self.corpus), "t",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

if __name__ == "__main__":
    unittest.main()
