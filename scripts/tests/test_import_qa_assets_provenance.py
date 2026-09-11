"""End-to-end failure and provenance-publication tests for the QA corpus importer.

Contract: docs/contracts/qa-corpus.md#qac-03-importer-acquisition-and-provenance-publication.
Injected nonzero statuses below are test sentinels proving pass-through; the contract owns
that failures are propagated, not the sentinel numbers themselves.
"""

import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve().parents[1] / "import-qa-assets.sh"
MAPPER = SCRIPT.with_name("import_qa_assets.py")
OWNER_HARNESS = REPO_ROOT / "fuzz/fuzz_targets/script_eval.rs"

GIT_HEAD_STATUS = 29
SIZE_STATUS = 31
CMIN_STATUS = 43
DATE_STATUS = 47
PROVENANCE_WRITE_STATUS = 51
PROVENANCE_CHMOD_STATUS = 52
PROVENANCE_PUBLISH_STATUS = 53
TERM_STATUS = 128 + 15


class ImportFlowTests(unittest.TestCase):
    """Exercise QAC-03 through the real shell and mapper with external tools stubbed."""

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
        harness.write_bytes(OWNER_HARNESS.read_bytes())
        self.provenance = self.root / "fuzz/CORPUS_PROVENANCE.md"
        self.provenance.write_text((REPO_ROOT / "fuzz" / "CORPUS_PROVENANCE.md").read_text())
        self.previous_provenance = self.provenance.read_text()
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
            "git": f'''
if [[ "$1" == rev-parse ]]; then printf '%s\\n' "$TEST_ROOT"; exit; fi
if [[ "$1" == init ]]; then mkdir -p "${{!#}}"; exit; fi
[[ "$1" == -C ]] || exit 99
case "$3" in
    remote|fetch) ;;
    checkout) cp -a "$SOURCE_FIXTURE/." "$2/" ;;
    rev-parse)
        printf '%s\\n' "$EXPECTED_PIN"
        [[ "${{FAIL_STAGE:-}}" != git_head ]] || exit {GIT_HEAD_STATUS}
        ;;
    *) exit 99 ;;
esac
''',
            "rustc": "printf 'host: x86_64-unknown-linux-gnu\\n'",
            "df": "printf 'Filesystem Blocks Used Available Capacity Mounted\\n'\n"
                  "printf 'test 100000 0 100000 0%% /\\n'",
            "du": f"printf '1\\tclone\\n'\n[[ \"${{FAIL_STAGE:-}}\" != du ]] || exit {SIZE_STATUS}",
            "date": f"[[ \"${{FAIL_STAGE:-}}\" != date ]] || exit {DATE_STATUS}\n"
                    "printf '2000-01-01T00:00:00Z\\n'",
            "cat": f"if [[ \"${{FAIL_STAGE:-}}\" == term ]]; then kill -TERM \"$PPID\"; exit 0; fi\n"
                   f"if [[ \"${{FAIL_STAGE:-}}\" == provenance_write ]]; then printf partial; exit {PROVENANCE_WRITE_STATUS}; fi\n"
                   "exec /usr/bin/cat \"$@\"",
            "chmod": f"[[ \"${{FAIL_STAGE:-}}\" != provenance_chmod ]] || exit {PROVENANCE_CHMOD_STATUS}\n"
                     "exec /usr/bin/chmod \"$@\"",
            "mv": f"[[ \"${{FAIL_STAGE:-}}\" != provenance_publish ]] || exit {PROVENANCE_PUBLISH_STATUS}\n"
                  "exec /usr/bin/mv \"$@\"",
            "cargo": f'''
[[ "${{RUSTUP_TOOLCHAIN:-}}" == nightly ]] || exit 98
[[ ! -v RUSTC_WRAPPER && ! -v CARGO_BUILD_BUILD_DIR ]] || exit 97
printf '%s\\n' "${{!#}}" >> "$TEST_ROOT/cmin.log"
[[ "${{FAIL_STAGE:-}}" != cmin ]] || exit {CMIN_STATUS}
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
        self.assertEqual((self.root / "cmin.log").read_text().splitlines(),
                         ["p2p_message", "block_validate", "tx_validate", "script_eval"])
        self.assertIn(self.pin, self.provenance.read_text())
        self.assertIn("2000-01-01T00:00:00Z", self.provenance.read_text())
        self.assertEqual(stat.S_IMODE(self.provenance.stat().st_mode), 0o644)
        for target in ("block_validate", "tx_validate"):
            self.assertEqual((self.root / "fuzz/corpus" / target / "seed").read_bytes(), b"Q")

    def test_missing_source_stops_before_minimization_or_provenance(self):
        (self.corpora / "bitcoin_script_bytes_to_asm_fmt").rmdir()
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertFalse((self.root / "fuzz/corpus").exists())
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_minimization_preserves_provenance(self):
        result = self.run_import("cmin")
        self.assertEqual(result.returncode, CMIN_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)
        self.assertEqual((self.root / "cmin.log").read_text().splitlines(), ["p2p_message"])

    def test_failed_commit_probe_is_not_hidden_by_valid_output(self):
        result = self.run_import("git_head")
        self.assertEqual(result.returncode, GIT_HEAD_STATUS, result.stderr)
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_size_probe_stops_before_mapping(self):
        result = self.run_import("du")
        self.assertEqual(result.returncode, SIZE_STATUS, result.stderr)
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertFalse((self.root / "fuzz/corpus").exists())
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_timestamp_preserves_provenance(self):
        result = self.run_import("date")
        self.assertEqual(result.returncode, DATE_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_provenance_write_preserves_previous_file(self):
        result = self.run_import("provenance_write")
        self.assertEqual(result.returncode, PROVENANCE_WRITE_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_provenance_chmod_preserves_previous_file(self):
        result = self.run_import("provenance_chmod")
        self.assertEqual(result.returncode, PROVENANCE_CHMOD_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_provenance_publish_preserves_previous_file(self):
        result = self.run_import("provenance_publish")
        self.assertEqual(result.returncode, PROVENANCE_PUBLISH_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_provenance_symlink_is_replaced_without_following_it(self):
        outside = self.root / "outside.md"
        outside.write_text(self.previous_provenance)
        self.provenance.unlink()
        self.provenance.symlink_to(outside)
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside.read_text(), self.previous_provenance)
        self.assertFalse(self.provenance.is_symlink())
        self.assertIn(self.pin, self.provenance.read_text())
        self.assertEqual(stat.S_IMODE(self.provenance.stat().st_mode), 0o644)

    def test_provenance_directory_is_not_used_as_a_container(self):
        self.provenance.unlink()
        self.provenance.mkdir()
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.provenance.iterdir()), [])

    def test_termination_cleans_staging_and_preserves_provenance(self):
        result = self.run_import("term")
        self.assertEqual(result.returncode, TERM_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_nonnumeric_disk_probe_cannot_authorize_an_import(self):
        probe = self.bin / "df"
        probe.write_text("#!/usr/bin/env bash\nprintf 'Filesystem Blocks Used Available Capacity Mounted\\n'\n"
                         "printf 'test 100000 0 unknown 0%% /\\n'\n")
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.root / "fuzz/corpus").exists())
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_overflowing_disk_probe_cannot_authorize_an_import(self):
        probe = self.bin / "df"
        probe.write_text("#!/usr/bin/env bash\nprintf 'Filesystem Blocks Used Available Capacity Mounted\\n'\n"
                         "printf 'test 100000 0 999999999999999999999999999999999999 0%% /\\n'\n")
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.root / "fuzz/corpus").exists())
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_provenance_does_not_claim_fixed_selectors_after_owner_reordering(self):
        harness = self.root / "fuzz/fuzz_targets/script_eval.rs"
        text = harness.read_text()
        text = text.replace("    VerifyFlags::NONE,", "    SWAP_NONE,")
        text = text.replace("    VerifyFlags::TAPROOT,", "    VerifyFlags::NONE,")
        text = text.replace("    SWAP_NONE,", "    VerifyFlags::TAPROOT,")
        harness.write_text(text)
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = self.provenance.read_text()
        self.assertNotIn("selector 0x00", record)
        self.assertNotIn("selector 0x03", record)
        self.assertIn("NONE", record)
        self.assertIn("TAPROOT", record)
        self.assertIn("FLAGS", record)

        documentation = OWNER_HARNESS.read_text()
        self.assertNotIn("`0x00`", documentation)
        self.assertNotIn("`0x03`", documentation)



if __name__ == "__main__":
    unittest.main()
