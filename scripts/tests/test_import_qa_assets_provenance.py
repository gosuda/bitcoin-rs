"""End-to-end importer contract regressions.

Contract: ``CONSTRAINTS.md`` § QA corpus importer setup contract.
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "import-qa-assets.sh"
MAPPER = SCRIPT.with_name("import_qa_assets.py")

# Statuses specified by CONSTRAINTS.md § QA corpus importer setup contract.
STATUS = {
    "commit_probe": 29,
    "size_probe": 31,
    "timestamp": 47,
    "minimization": 43,
    "provenance_write": 51,
    "provenance_publish": 53,
    "termination": 143,
}


class ImportFlowTests(unittest.TestCase):
    """Run the real shell and mapper, replacing only external acquisition/tools."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / MAPPER.name).write_bytes(MAPPER.read_bytes())
        inventory = self.root / "crates/p2p/src/compat.rs"
        inventory.parent.mkdir(parents=True)
        inventory.write_text('pub const COMMANDS: &[Command] = &[Command { name: "ping" }];\n')
        harness = self.root / "fuzz/fuzz_targets/script_eval.rs"
        harness.parent.mkdir(parents=True)
        harness.write_text("const ELEMENT_LEN_MAX: usize = 1_024;\n")
        self.provenance = self.root / "fuzz/CORPUS_PROVENANCE.md"
        self.provenance.write_text("previous provenance\n")
        self.source = self.root / "upstream"
        self.corpora = self.source / "fuzz_corpora"
        for name in ("p2p_deserialize_raw_net_msg", "bitcoin_deserialize_script",
                     "bitcoin_script_bytes_to_asm_fmt", "bitcoin_deserialize_block",
                     "bitcoin_deserialize_transaction"):
            (self.corpora / name).mkdir(parents=True)
        message = b"\0" * 4 + b"ping".ljust(12, b"\0") + b"\0" * 8 + b"payload"
        (self.corpora / "p2p_deserialize_raw_net_msg/seed").write_bytes(message)
        for name in ("bitcoin_deserialize_script", "bitcoin_deserialize_block",
                     "bitcoin_deserialize_transaction"):
            (self.corpora / name / "seed").write_bytes(b"Q")
        pin = re.search(r'^readonly QA_ASSETS_PIN="([0-9a-f]{40})"$', SCRIPT.read_text(), re.M)
        self.assertIsNotNone(pin)
        self.pin = pin.group(1)
        stubs = {
            "git": r'''
if [[ "$1" == rev-parse ]]; then printf '%s\n' "$TEST_ROOT"; exit; fi
if [[ "$1" == init ]]; then mkdir -p "${!#}"; exit; fi
[[ "$1" == -C ]] || exit 99
case "$3" in
    remote|fetch) ;;
    checkout) cp -a "$SOURCE_FIXTURE/." "$2/" ;;
    rev-parse)
        printf '%s\n' "$EXPECTED_PIN"
        [[ "${FAIL_STAGE:-}" != git_head ]] || exit 29
        ;;
    *) exit 99 ;;
esac
''',
            "rustc": "printf 'host: x86_64-unknown-linux-gnu\\n'",
            "df": "printf 'Filesystem Blocks Used Available Capacity Mounted\\n'\n"
                  "printf 'test 100000 0 100000 0%% /\\n'",
            "du": "printf '1\\tclone\\n'\n[[ \"${FAIL_STAGE:-}\" != du ]] || exit 31",
            "date": "[[ \"${FAIL_STAGE:-}\" != date ]] || exit 47\n"
                    "printf '2000-01-01T00:00:00Z\\n'",
            "cat": "if [[ \"${FAIL_STAGE:-}\" == term ]]; then kill -TERM \"$PPID\"; exit 0; fi\n"
                   "if [[ \"${FAIL_STAGE:-}\" == provenance_write ]]; then printf partial; exit 51; fi\n"
                   "exec /usr/bin/cat \"$@\"",
            "mv": "[[ \"${FAIL_STAGE:-}\" != provenance_publish ]] || exit 53\n"
                  "exec /usr/bin/mv \"$@\"",
            "cargo": r'''
[[ "${RUSTUP_TOOLCHAIN:-}" == nightly ]] || exit 98
[[ ! -v RUSTC_WRAPPER && ! -v CARGO_BUILD_BUILD_DIR ]] || exit 97
printf '%s\n' "${!#}" >> "$TEST_ROOT/cmin.log"
[[ "${FAIL_STAGE:-}" != cmin ]] || exit 43
''',
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body + "\n")
            path.chmod(0o755)

    def run_import(self, fail=""):
        environment = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                           TEST_ROOT=str(self.root), SOURCE_FIXTURE=str(self.source),
                           EXPECTED_PIN=self.pin, TMPDIR=str(self.tmp), FAIL_STAGE=fail,
                           RUSTC_WRAPPER="must-be-unset", CARGO_BUILD_BUILD_DIR="must-be-unset")
        result = subprocess.run(["bash", str(SCRIPT)], cwd=self.root, env=environment,
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(list(self.tmp.iterdir()), [], "clone leaked after importer exit")
        self.assertEqual(list((self.root / "fuzz").glob(".corpus-provenance.*")), [],
                         "provenance staging leaked after importer exit")
        return result

    def test_success_maps_then_minimizes_and_records_provenance(self):
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.provenance.stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.root / "cmin.log").read_text().splitlines(),
                         ["p2p_message", "block_decode", "tx_decode", "script_eval"])
        self.assertIn(self.pin, self.provenance.read_text())
        self.assertIn("2000-01-01T00:00:00Z", self.provenance.read_text())
        for target in ("block_decode", "tx_decode"):
            self.assertEqual((self.root / "fuzz/corpus" / target / "seed").read_bytes(), b"Q")

    def test_missing_source_stops_before_minimization_or_provenance(self):
        (self.corpora / "bitcoin_script_bytes_to_asm_fmt").rmdir()
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertFalse((self.root / "fuzz/corpus").exists())
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")

    def test_failed_minimization_preserves_provenance(self):
        result = self.run_import("cmin")
        self.assertEqual(result.returncode, STATUS["minimization"], result.stderr)
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")
        self.assertEqual((self.root / "cmin.log").read_text().splitlines(), ["p2p_message"])

    def test_failed_commit_probe_is_not_hidden_by_valid_output(self):
        result = self.run_import("git_head")
        self.assertEqual(result.returncode, STATUS["commit_probe"], result.stderr)
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")

    def test_failed_size_probe_stops_before_mapping(self):
        result = self.run_import("du")
        self.assertEqual(result.returncode, STATUS["size_probe"], result.stderr)
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertFalse((self.root / "fuzz/corpus").exists())
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")

    def test_failed_timestamp_preserves_provenance(self):
        result = self.run_import("date")
        self.assertEqual(result.returncode, STATUS["timestamp"], result.stderr)
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")

    def test_failed_provenance_write_preserves_previous_file(self):
        result = self.run_import("provenance_write")
        self.assertEqual(result.returncode, STATUS["provenance_write"], result.stderr)
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")

    def test_failed_provenance_publish_preserves_previous_file(self):
        result = self.run_import("provenance_publish")
        self.assertEqual(result.returncode, STATUS["provenance_publish"], result.stderr)
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")

    def test_provenance_symlink_is_replaced_without_following_it(self):
        outside = self.root / "outside.md"
        outside.write_text("unrelated data\n")
        self.provenance.unlink()
        self.provenance.symlink_to(outside)
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside.read_text(), "unrelated data\n")
        self.assertFalse(self.provenance.is_symlink())
        self.assertIn(self.pin, self.provenance.read_text())

    def test_provenance_directory_is_not_used_as_a_container(self):
        self.provenance.unlink()
        self.provenance.mkdir()
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.provenance.iterdir()), [])

    def test_termination_cleans_staging_and_preserves_provenance(self):
        result = self.run_import("term")
        self.assertEqual(result.returncode, STATUS["termination"], result.stderr)
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")


if __name__ == "__main__":
    unittest.main()
