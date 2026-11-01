"""Regressions for worker-side corpus publication.

scripts/run-fuzz-campaign.sh publishes the minimized corpus with rsync.
The corpus seed-content invariant (non-symlink regular file named by its
SHA-1, within FUZZ_MAX_SEED_BYTES, no dotfile or nested path) must be
enforced on the worker bytes before rsync, so the campaign output never
carries a seed that the publish job would refuse.

The script runs against stub rustc, cargo, and jq tools in PATH, so no
fuzzing happens and no metadata is required. The corpus and output live
under fuzz/ so the script's same-filesystem guard holds.
"""

import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "run-fuzz-campaign.sh"
POLICY = REPO_ROOT / "scripts" / "fuzz-policy.sh"
TARGET = "script_publish_probe"

_budget = re.search(
    r"^readonly FUZZ_MAX_SEED_BYTES=([0-9]+)\s*(?:#.*)?$",
    POLICY.read_text(),
    re.M,
)
if _budget is None or int(_budget.group(1)) < 1:
    raise RuntimeError("Cannot read the positive FUZZ_MAX_SEED_BYTES policy")
BUDGET = int(_budget.group(1))

RUSTC_STUB = """#!/bin/sh
for argument in "$@"; do
    if [ "$argument" = "--print" ]; then
        printf '%s\\n' "${STUB_SYSROOT}"
        exit 0
    fi
done
printf 'rustc 1.99.0-nightly (0000000 2026-01-01)\\nhost: x86_64-unknown-linux-gnu\\n'
"""

CARGO_STUB = """#!/bin/sh
if [ "$1" = "+nightly" ]; then
    shift
fi
if [ "$1" = "fuzz" ] && [ "$2" = "list" ]; then
    printf '%s\\n' "${STUB_TARGET}"
fi
exit 0
"""

JQ_STUB = """#!/bin/sh
exit 0
"""


class RunFuzzCampaignPublishTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(
            prefix=".run-fuzz-campaign-test-", dir=REPO_ROOT / "fuzz"
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stubs = self.root / "stubs"
        self.stubs.mkdir()
        self._stub("rustc", RUSTC_STUB)
        self._stub("cargo", CARGO_STUB)
        self._stub("jq", JQ_STUB)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.output = self.root / "output"

    def _stub(self, name, script):
        path = self.stubs / name
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)

    def _add_seed(self, content, name=None, directory=None):
        parent = self.corpus if directory is None else directory
        parent.mkdir(parents=True, exist_ok=True)
        path = parent / (name if name is not None else hashlib.sha1(content).hexdigest())
        path.write_bytes(content)
        return path

    def _published_entries(self):
        published = self.output / "corpus" / TARGET
        if not published.exists():
            return []
        return sorted(str(path.relative_to(published)) for path in published.rglob("*"))

    def _run_campaign(self):
        environment = os.environ.copy()
        environment["PATH"] = f"{self.stubs}{os.pathsep}{environment['PATH']}"
        environment["STUB_SYSROOT"] = str(self.root / "sysroot")
        environment["STUB_TARGET"] = TARGET
        environment["FUZZ_COVERAGE"] = "0"
        environment["FUZZ_CORPUS_DIR"] = ""
        for key in (
            "GITHUB_SHA",
            "GITHUB_REPOSITORY",
            "GITHUB_RUN_ID",
            "GITHUB_STEP_SUMMARY",
        ):
            environment.pop(key, None)
        return subprocess.run(
            ["bash", str(SCRIPT), TARGET, "1", str(self.corpus), str(self.output)],
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _assert_refused(self, expected):
        completed = self._run_campaign()
        self.assertNotEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn(expected, completed.stderr)
        self.assertEqual(self._published_entries(), [])

    def test_valid_corpus_is_published(self):
        content = b"valid-seed"
        self._add_seed(content)
        completed = self._run_campaign()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        published = self.output / "corpus" / TARGET
        digest = hashlib.sha1(content).hexdigest()
        self.assertEqual((published / digest).read_bytes(), content)

    def test_oversized_seed_is_not_published(self):
        self._add_seed(b"x" * (BUDGET + 1))
        self._assert_refused("oversized")

    def test_dotfile_seed_is_not_published(self):
        self._add_seed(b"dotfile", name=".payload")
        self._assert_refused("not named by its sha1")

    def test_nested_seed_is_not_published(self):
        self._add_seed(b"nested", directory=self.corpus / "nested")
        self._assert_refused("non-regular")

    def test_symlink_seed_is_not_published(self):
        content = b"linked-seed"
        real = self.root / "real-seed"
        real.write_bytes(content)
        (self.corpus / hashlib.sha1(content).hexdigest()).symlink_to(real)
        self._assert_refused("non-regular")


if __name__ == "__main__":
    unittest.main()
