"""Offline, subprocess-level regression tests for fetch-golden.sh.

The acquisition contract and failure cases are recorded in PR #740:
https://github.com/gosuda/bitcoin-rs/pull/740
The baseline script (Git blob 6073db3294ec4ce88571ca55a9dad7e18b2cd7b5)
owns fixture paths and cache reuse; PR #740 adds failure-atomic publication
and offline reuse. Heights come from the script, not a second inventory.
Response bytes are synthetic transport fixtures, not Bitcoin validity vectors:
expected file contents are the stub's input bytes, never downloader output.

Run from the repository root: python3 -m unittest discover -s scripts/tests -v
"""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "fetch-golden.sh"
_height_array = re.search(r"^heights=\((\d+(?:\s+\d+)*)\)$", SCRIPT.read_text(), re.M)
if _height_array is None:
    raise RuntimeError("Cannot read the downloader's fixture-height inventory")
HEIGHTS = tuple(int(height) for height in _height_array.group(1).split())
TXID = "ab" * 32
CURL_STUB = r'''#!/usr/bin/env bash
set -eu
url="${!#}"
printf '%s\n' "$url" >> "$REQUEST_LOG"
mode="${CURL_MODE:-ok}"
[[ "$mode" != offline ]] || exit 7
case "$url" in
    */block-height/*)
        if [[ "$mode" == invalid_hash ]]; then
            printf 'not-a-block-hash\n'
        else
            printf '%064x\n' "${url##*/}"
        fi
        ;;
    */raw)
        [[ "$mode" == empty_raw ]] || printf 'block bytes'
        [[ "$mode" != partial_raw ]] || exit 18
        ;;
    */txids)
        txid="abababababababababababababababababababababababababababababababab"
        case "$mode" in
            invalid_json) printf '[\n' ;;
            invalid_txid) printf '["not-a-txid"]\n' ;;
            wrong_shape) printf '{"%s":true}\n' "$txid" ;;
            empty_txids) printf '[]\n' ;;
            *) printf '["%s"]\n' "$txid" ;;
        esac
        [[ "$mode" != failed_txids ]] || exit 18
        ;;
    *) exit 99 ;;
esac
'''


class FetchGoldenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "crates/primitives/tests/testdata"
        self.output.mkdir(parents=True)
        self.block_path = self.output / f"{HEIGHTS[0]}.bin"
        self.txids_path = self.output / f"{HEIGHTS[0]}.txids.txt"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        stub = self.bin / "curl"
        stub.write_text(CURL_STUB, encoding="utf-8")
        stub.chmod(0o755)
        self.log = self.root / "requests.log"
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                        REQUEST_LOG=str(self.log))

    def run_fetch(self, mode="ok"):
        result = subprocess.run(
            ["bash", str(SCRIPT)], cwd=self.root,
            env=dict(self.env, CURL_MODE=mode), capture_output=True,
            text=True, timeout=30, check=False,
        )
        self.assertEqual(list(self.output.glob(".fetch-golden.*")), [],
                         "temporary files must be cleaned on success or failure")
        return result

    def requests(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def seed_cache(self):
        for height in HEIGHTS:
            (self.output / f"{height}.bin").write_bytes(b"existing block")
            (self.output / f"{height}.txids.txt").write_text(TXID + "\n", encoding="utf-8")

    def test_success_publishes_complete_fixtures(self):
        result = self.run_fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.requests()), 3 * len(HEIGHTS))
        for height in HEIGHTS:
            self.assertEqual((self.output / f"{height}.bin").read_bytes(), b"block bytes")
            self.assertEqual((self.output / f"{height}.txids.txt").read_text(), TXID + "\n")

    def test_complete_cache_needs_no_network(self):
        self.seed_cache()
        result = self.run_fetch("offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.requests(), [])
        self.assertEqual(self.block_path.read_bytes(), b"existing block")

    def test_nonregular_cache_entries_fail_before_network(self):
        self.seed_cache()
        for path in (self.block_path, self.txids_path):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.unlink()
                path.mkdir()
                result = self.run_fetch("offline")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(path.name, result.stderr)
                self.assertEqual(self.requests(), [])
                self.assertEqual(list(path.iterdir()), [])
                path.rmdir()
                path.write_bytes(original)

    def test_complete_cache_needs_no_staging_directory(self):
        self.seed_cache()
        mktemp = self.bin / "mktemp"
        mktemp.write_text("#!/usr/bin/env bash\nexit 97\n", encoding="utf-8")
        mktemp.chmod(0o755)
        result = self.run_fetch("offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.requests(), [])

    def test_failed_raw_is_not_published_and_retry_succeeds(self):
        result = self.run_fetch("partial_raw")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.block_path.exists())
        self.assertFalse(self.txids_path.exists())
        retry = self.run_fetch()
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual(self.block_path.read_bytes(), b"block bytes")

    def test_invalid_raw_and_hash_are_not_published(self):
        for mode in ("empty_raw", "invalid_hash"):
            with self.subTest(mode=mode):
                result = self.run_fetch(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.block_path.exists())
                self.assertFalse(self.txids_path.exists())

    def test_invalid_txids_are_not_published(self):
        for mode in ("invalid_json", "invalid_txid", "wrong_shape", "empty_txids", "failed_txids"):
            with self.subTest(mode=mode):
                result = self.run_fetch(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.txids_path.exists())
                self.assertEqual(self.block_path.read_bytes(), b"block bytes")

    def test_empty_cache_entries_are_replaced(self):
        self.seed_cache()
        self.block_path.write_bytes(b"")
        self.txids_path.write_bytes(b"")
        result = self.run_fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.block_path.read_bytes(), b"block bytes")
        self.assertEqual(self.txids_path.read_text(), TXID + "\n")
        self.assertEqual(len(self.requests()), 3)

    def test_partial_cache_preserves_existing_files(self):
        self.seed_cache()
        self.txids_path.unlink()
        result = self.run_fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.block_path.read_bytes(), b"existing block")
        self.assertEqual(len(self.requests()), 2)


if __name__ == "__main__":
    unittest.main()
