"""End-to-end failure and provenance-publication tests for the reference importer.

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
SCRIPT = Path(__file__).resolve().parents[1] / "import-reference-corpora.sh"

CMIN_STATUS = 43
DATE_STATUS = 47
PROVENANCE_PUBLISH_STATUS = 53


class ImportFlowTests(unittest.TestCase):
    """Exercise QAC-03 through the real shell with external tools stubbed."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        scripts = self.root / "scripts"
        scripts.mkdir()
        # Stand-in for the gosuda/bitcoin-rs-fuzz-corpus checkout the
        # importer now writes into (FUZZ_CORPUS_DIR points at its corpus/).
        self.corpus_dir = self.root / "fuzz-corpus/corpus"
        self.corpus_dir.mkdir(parents=True)
        self.provenance = self.root / "fuzz/CORPUS_PROVENANCE.md"
        self.provenance.parent.mkdir(parents=True)
        self.provenance.write_text(
            (REPO_ROOT / "fuzz" / "CORPUS_PROVENANCE.md").read_text()
        )
        self.previous_provenance = self.provenance.read_text()
        # Fake sparse clones: only the directories the importer reads.
        for name in ("bitcoin", "btcd"):
            source = self.root / f"source-{name}"
            for sub in ("src/test/data", "txscript/data", "blockchain/testdata", "wire"):
                (source / sub).mkdir(parents=True, exist_ok=True)
        pins = re.findall(
            r'^readonly (BITCOIN_PIN|BTCD_PIN)="([0-9a-f]{40})"$',
            SCRIPT.read_text(), re.M,
        )
        self.assertEqual(len(pins), 2)
        self.pins = dict(pins)
        stubs = {
            "git": '''
if [[ "$1" == rev-parse && "$2" == --show-toplevel ]]; then printf '%s\\n' "$TEST_ROOT"; exit; fi
if [[ "$1" == init ]]; then mkdir -p "${!#}"; exit; fi
[[ "$1" == -C ]] || exit 99
dir="$2"; sub="$3"
case "${sub%% *}" in
    remote) ;;
    sparse-checkout) ;;
    # The fetched ref is what checkout pins as HEAD, so a driver that fetches
    # or verifies the wrong commit fails the pin check instead of passing.
    fetch)
        printf '%s' "${!#}" > "$dir/.fetched_ref"
        printf '%s %s\n' "$(basename "$dir")" "${!#}" >> "$TEST_ROOT/fetch.log" ;;
    checkout)
        cp -a "$TEST_ROOT/source-$(basename "$dir")/." "$dir/"
        cp "$dir/.fetched_ref" "$dir/.head" ;;
    rev-parse) cat "$dir/.head" ;;
    *) exit 99 ;;
esac
''',
            "rustc": "printf 'host: x86_64-unknown-linux-gnu\\n'",
            "df": "printf 'Filesystem Blocks Used Available Capacity Mounted\\n'\n"
                  "printf 'test 100000 0 100000 0%% /\\n'",
            "du": "printf '1\\tclone\\n'",
            "date": f"[[ \"${{FAIL_STAGE:-}}\" != date ]] || exit {DATE_STATUS}\n"
                    "printf '2000-01-01T00:00:00Z\\n'",
            # The mapper call carries --out-base; the provenance fill runs a
            # heredoc program on stdin (`python3 -`) that needs the real tool.
            "python3": "if [[ \"$1\" == - ]]; then exec /usr/bin/python3 \"$@\"; fi\n"
                       "out=\"\"; prev=\"\"\n"
                       "for arg in \"$@\"; do if [[ \"$prev\" == --out-base ]]; then out=\"$arg\"; fi; prev=\"$arg\"; done\n"
                       "for t in p2p_message block_validate tx_validate script_eval utxo_snapshot; do\n"
                       "    mkdir -p \"$out/$t\"; printf 's' > \"$out/$t/seed\"\n"
                       "done",
            "cargo": '''
[[ "${RUSTUP_TOOLCHAIN:-}" == nightly ]] || exit 98
[[ ! -v RUSTC_WRAPPER && ! -v CARGO_BUILD_BUILD_DIR ]] || exit 97
# Preflight runs `cargo fuzz --version`; only cmin invocations are logged.
[[ "$1" == fuzz && "$2" == cmin ]] || exit 0
printf '%s\\n' "${!#}" >> "$TEST_ROOT/cmin.log"
[[ "${FAIL_STAGE:-}" != cmin ]] || exit ''' + str(CMIN_STATUS),
            "mv": f"[[ \"${{FAIL_STAGE:-}}\" != provenance_publish ]] || exit {PROVENANCE_PUBLISH_STATUS}\n"
                  "exec /usr/bin/mv \"$@\"",
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body + "\n")
            path.chmod(0o755)

    def run_import(self, fail=""):
        environment = dict(
            os.environ,
            PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            # The driver prepends $HOME/.cargo/bin so rustup shims win on a
            # developer box; a fake HOME keeps the stub toolchain in charge.
            HOME=str(self.home),
            TEST_ROOT=str(self.root), TMPDIR=str(self.tmp), FAIL_STAGE=fail,
            BITCOIN_PIN=self.pins["BITCOIN_PIN"], BTCD_PIN=self.pins["BTCD_PIN"],
            FUZZ_CORPUS_DIR=str(self.corpus_dir),
            RUSTC_WRAPPER="must-be-unset", CARGO_BUILD_BUILD_DIR="must-be-unset",
        )
        result = subprocess.run(["bash", str(SCRIPT)], cwd=self.root, env=environment,
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(list(self.tmp.iterdir()), [], "clone leaked after importer exit")
        self.assertEqual(list((self.root / "fuzz").glob(".corpus-provenance.*")), [],
                         "provenance staging leaked after importer exit")
        self.assertEqual(
            [p for p in (self.root / "fuzz/corpus").rglob("*")],
            [], "nothing may remain under the in-repo fuzz/corpus staging")
        return result

    def test_success_maps_minimizes_and_records_reference_provenance(self):
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.root / "cmin.log").read_text().splitlines(),
            ["p2p_message", "block_validate", "tx_validate", "script_eval", "utxo_snapshot"],
        )
        self.assertEqual(
            sorted((self.root / "fetch.log").read_text().splitlines()),
            sorted([
                f"bitcoin {self.pins['BITCOIN_PIN']}",
                f"btcd {self.pins['BTCD_PIN']}",
            ]),
        )
        record = self.provenance.read_text()
        self.assertIn(self.pins["BITCOIN_PIN"], record)
        self.assertIn(self.pins["BTCD_PIN"], record)
        self.assertIn("2000-01-01T00:00:00Z", record)
        self.assertEqual(stat.S_IMODE(self.provenance.stat().st_mode), 0o644)
        # The authored head (everything above the generated section) is preserved.
        head = self.previous_provenance.split("## Reference corpora", 1)[0]
        self.assertTrue(record.startswith(head))
        for target in ("block_validate", "tx_validate"):
            self.assertTrue((self.corpus_dir / target / "seed").is_file())

    def test_missing_reference_section_refuses_to_overwrite_provenance(self):
        head = self.previous_provenance.split("## Reference corpora", 1)[0]
        self.provenance.write_text(head)
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.provenance.read_text(), head)

    def test_missing_corpus_checkout_stops_before_any_staging(self):
        self.corpus_dir.rmdir()
        self.corpus_dir.parent.rmdir()
        result = self.run_import()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "cmin.log").exists())
        self.assertFalse((self.root / "fetch.log").exists())
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_minimization_preserves_provenance(self):
        result = self.run_import("cmin")
        self.assertEqual(result.returncode, CMIN_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)
        self.assertEqual(
            (self.root / "cmin.log").read_text().splitlines(), ["p2p_message"]
        )

    def test_failed_timestamp_preserves_provenance(self):
        result = self.run_import("date")
        self.assertEqual(result.returncode, DATE_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)

    def test_failed_provenance_publish_preserves_previous_file(self):
        result = self.run_import("provenance_publish")
        self.assertEqual(result.returncode, PROVENANCE_PUBLISH_STATUS, result.stderr)
        self.assertEqual(self.provenance.read_text(), self.previous_provenance)


if __name__ == "__main__":
    unittest.main()
