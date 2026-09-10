"""Offline tests for the QAC-01 import boundary and its actual mapper bodies.

QAC-01 is owned by docs/contracts/qa-corpus.md. PR #747 records the reproduced
metadata, framing, and setup failures against original importer Git blob
22a14e444732dd71913bc5043feed231f4a53d03. Fixtures here are synthetic transport
and framing inputs, not Bitcoin validity vectors; expected bytes are assembled
independently from the documented harness framing, never mapper output.
The live seed budget is read from the importer, not duplicated in this suite.
"""

from contextlib import redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "import-qa-assets.sh"
_SCRIPT_TEXT = SCRIPT.read_text()
_budget_match = re.search(r"^readonly MAX_SEED_BYTES=([0-9]+)\s+#", _SCRIPT_TEXT, re.M)
if _budget_match is None:
    raise RuntimeError("importer MAX_SEED_BYTES definition is missing")
BUDGET = int(_budget_match.group(1))
if BUDGET <= 0:
    raise RuntimeError("importer MAX_SEED_BYTES must be positive")


def mapper_function(name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^PYEOF\n\}}", SCRIPT.read_text(), re.M | re.S)
    if match is None:
        raise AssertionError(f"Missing mapper function: {name}")
    return match.group(0)


def mapper_body(name):
    return mapper_function(name).split("<<'PYEOF'\n", 1)[1].rsplit("\nPYEOF", 1)[0]


class MapperTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.corpora = self.root / "qa/fuzz_corpora"
        self.p2p = self.corpora / "p2p_deserialize_raw_net_msg"
        self.scripts = self.corpora / "bitcoin_deserialize_script"
        self.asm = self.corpora / "bitcoin_script_bytes_to_asm_fmt"
        self.fuzz = self.root / "fuzz"
        self.output = self.fuzz / "corpus"
        self.inventory = self.root / "crates/p2p/src/compat.rs"
        self.script_target = self.fuzz / "fuzz_targets/script_eval.rs"
        for path in (self.p2p, self.scripts, self.asm, self.inventory.parent, self.script_target.parent):
            path.mkdir(parents=True, exist_ok=True)
        self.inventory.write_text('''// COMMANDS documentation mentions "decoy".
pub const COMMANDS: &[Command] = &[
    Command { name: "ping", status: CommandStatus::Served },
    Command { name: "pong", status: CommandStatus::Ignored },
];
pub const CORE_UNTYPED_COMMANDS: &[&str] = &["outside"];
''')
        self.script_target.write_text("const ELEMENT_LEN_MAX: usize = 1_024;\n")

    def run_mapper(self, name, budget=BUDGET):
        if name == "map_p2p":
            args = [self.p2p, self.inventory, self.output / "p2p_message", budget]
        else:
            args = [self.scripts, self.asm, self.script_target, self.output / "script_eval", budget]
        with patch.object(sys, "argv", ["-"] + [str(arg) for arg in args]), redirect_stdout(io.StringIO()):
            exec(compile(mapper_body(name), f"{SCRIPT}:{name}", "exec"), {"__name__": "__main__"})

    def assert_seed(self, target, expected):
        path = self.output / target / hashlib.sha256(expected).hexdigest()[:32]
        self.assertEqual(path.read_bytes(), expected)
        self.assertLessEqual(len(expected), BUDGET)

    def write_message(self, command, payload):
        path = self.p2p / command
        path.write_bytes(b"\0" * 4 + command.encode().ljust(12, b"\0") + b"\0" * 8 + payload)
        return path

    def test_inventory_order_and_non_inventory_strings(self):
        self.write_message("pong", b"payload")
        self.run_mapper("map_p2p")
        self.assert_seed("p2p_message", b"\x01payload")

    def test_missing_or_ambiguous_inventory_fails_closed(self):
        for inventory in ("let x = bitcoin_rs_p2p::COMMANDS;", "pub const COMMANDS: &[Command] = &[];",
                          'pub const COMMANDS: &[Command] = &[Command { name: "ping" }, Command { name: "ping" }];'):
            with self.subTest(inventory=inventory):
                self.inventory.write_text(inventory)
                with self.assertRaises(SystemExit):
                    self.run_mapper("map_p2p")
        self.assertFalse((self.output / "p2p_message").exists())

    def test_short_and_unknown_messages_are_skipped(self):
        (self.p2p / "short").write_bytes(b"\0" * 24)
        self.write_message("unknown", b"payload")
        self.run_mapper("map_p2p")
        self.assertEqual(list((self.output / "p2p_message").iterdir()), [])

    def test_p2p_budget_includes_selector(self):
        self.write_message("ping", b"P" * BUDGET)
        self.run_mapper("map_p2p")
        self.assert_seed("p2p_message", b"\0" + b"P" * (BUDGET - 1))

    def test_65536_byte_script_frames_match_the_harness(self):
        script = b"Q" * (1 << 16)  # Historical u16 overflow, independent of today's cap.
        (self.scripts / "boundary").write_bytes(script)
        self.run_mapper("map_script")
        raw = b"\0\0\0" + (1024).to_bytes(2, "little") + script[:1024] + b"\0"
        taproot = b"\x03\0\0\x22\0\x51\x20" + script[:32] + b"\x01" + (992).to_bytes(2, "little") + script[32:1024]
        self.assert_seed("script_eval", raw)
        self.assert_seed("script_eval", taproot)
        self.assertEqual(len(list((self.output / "script_eval").iterdir())), 2)

    def test_script_limit_follows_the_owner_constant(self):
        self.script_target.write_text("const ELEMENT_LEN_MAX: usize = 512;\n")
        (self.scripts / "script").write_bytes(b"Q" * 1024)
        self.run_mapper("map_script")
        self.assert_seed("script_eval", b"\0\0\0\0\x02" + b"Q" * 512 + b"\0")

    def test_missing_script_limit_fails_closed(self):
        self.script_target.write_text("// no element limit\n")
        with self.assertRaises(SystemExit):
            self.run_mapper("map_script")
        self.assertFalse((self.output / "script_eval").exists())

    def test_short_and_empty_scripts_preserve_bytes(self):
        for name, script in (("empty", b""), ("short", b"Q" * 31)):
            (self.scripts / name).write_bytes(script)
        self.run_mapper("map_script")
        self.assert_seed("script_eval", b"\0" * 6)
        self.assert_seed("script_eval", b"\0\0\0\x1f\0" + b"Q" * 31 + b"\0")

    def test_complete_script_frames_fit_a_smaller_budget(self):
        (self.scripts / "script").write_bytes(b"Q" * 1024)
        self.run_mapper("map_script", budget=64)
        for path in (self.output / "script_eval").iterdir():
            self.assertLessEqual(path.stat().st_size, 64)

    def test_corpus_reads_are_bounded_before_allocation(self):
        p2p = self.write_message("ping", b"payload")
        script = self.scripts / "large"
        script.touch()
        for path in (p2p, script):
            with path.open("r+b") as stream:
                stream.truncate(8 * 1024 * 1024)
        limits = {p2p: 24 + BUDGET - 1, script: 1024}
        reads = {}
        original_open = Path.open
        test = self

        class GuardedReader:
            def __init__(self, stream, path):
                self.stream, self.path = stream, path

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def read(self, size=-1):
                test.assertGreaterEqual(size, 0, "unbounded read")
                test.assertLessEqual(size, limits[self.path])
                reads[self.path] = size
                return self.stream.read(size)

        def guarded_open(path, mode="r", *args, **kwargs):
            stream = original_open(path, mode, *args, **kwargs)
            return GuardedReader(stream, path) if path in limits and mode == "rb" else stream

        with patch.object(Path, "open", guarded_open):
            self.run_mapper("map_p2p")
            self.run_mapper("map_script")
        self.assertEqual(reads, limits)

    def test_shell_functions_pass_the_owner_paths(self):
        self.write_message("pong", b"payload")
        (self.scripts / "script").write_bytes(b"Q")
        command = '''set -euo pipefail
CARGO_ENV=(env)
REPO_ROOT="$1"
CORPORA="$2"
FUZZ_DIR="$3"
OUT_BASE="$4"
MAX_SEED_BYTES="$5"
'''
        command += mapper_function("map_p2p") + "\n" + mapper_function("map_script") + "\nmap_p2p\nmap_script\n"
        result = subprocess.run(["bash", "-c", command, "mapper-tests", str(self.root), str(self.corpora),
                                 str(self.fuzz), str(self.output), str(BUDGET)], capture_output=True, text=True,
                                timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_seed("p2p_message", b"\x01payload")
        self.assert_seed("script_eval", b"\0\0\0\x01\0Q\0")


class DirectMapperTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "input seeds"
        self.output = self.root / "output seeds"
        self.source.mkdir()

    def run_direct(self):
        match = re.search(r"^map_direct\(\) \{\n.*?^\}", SCRIPT.read_text(), re.M | re.S)
        self.assertIsNotNone(match, "missing direct mapper")
        command = """set -euo pipefail
CARGO_ENV=(env)
MAX_SEED_BYTES="$3"
log() { printf '%s\\n' "$*"; }
""" + match.group(0) + '\nmap_direct "$1" "$2" tx_decode\n'
        return subprocess.run(["bash", "-c", command, "direct-tests", str(self.source),
                               str(self.output), str(BUDGET)], capture_output=True, text=True,
                              timeout=30, check=False)

    def test_missing_source_fails_instead_of_reporting_empty_success(self):
        self.source.rmdir()
        result = self.run_direct()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("imported=0", result.stdout)

    def test_direct_bytes_and_unusual_names_are_preserved(self):
        files = {"empty": b"", "with space": b"seed", "line\nbreak": bytes(range(256)),
                 "-option": b"not a flag", "high-byte": b"\xff\x00"}
        for name, data in files.items():
            (self.source / name).write_bytes(data)
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, files)
        self.assertIn(f"imported={len(files)} skipped_oversize=0", result.stdout)

    def test_size_boundary_is_exclusive(self):
        (self.source / "below").write_bytes(b"Q" * (BUDGET - 1))
        (self.source / "equal").write_bytes(b"Q" * BUDGET)
        with (self.source / "sparse").open("wb") as stream:
            stream.truncate(8 * 1024 * 1024)
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([p.name for p in self.output.iterdir()], ["below"])
        self.assertEqual((self.output / "below").read_bytes(), b"Q" * (BUDGET - 1))
        self.assertIn("imported=1 skipped_oversize=2", result.stdout)

    def test_non_regular_entries_are_not_followed(self):
        (self.source / "seed").write_bytes(b"payload")
        (self.source / "directory").mkdir()
        (self.source / "link").symlink_to(self.source / "seed")
        (self.source / "broken").symlink_to(self.source / "absent")
        os.mkfifo(self.source / "fifo")
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([p.name for p in self.output.iterdir()], ["seed"])

    def test_growing_direct_read_is_bounded_before_allocation(self):
        path = self.source / "growing"
        path.write_bytes(b"Q")
        requests = []
        original_open = open

        class GuardedReader:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def read(self, size=-1):
                requests.append(size)
                if not 0 <= size <= BUDGET:
                    raise AssertionError(f"unbounded direct read: {size}")
                return self.stream.read(size)

        def guarded_open(name, *args, **kwargs):
            # Grow after the metadata guard but before its bounded read.
            with original_open(name, "r+b") as stream:
                stream.truncate(8 * 1024 * 1024)
            return GuardedReader(original_open(name, *args, **kwargs))

        args = ["-", str(self.source), str(self.output), "tx_decode", str(BUDGET)]
        with patch.object(sys, "argv", args), patch("builtins.open", guarded_open), redirect_stdout(io.StringIO()):
            exec(compile(mapper_body("map_direct"), str(SCRIPT), "exec"), {"__name__": "__main__"})
        self.assertEqual(requests, [BUDGET])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_known_oversized_files_need_no_payload_read(self):
        with (self.source / "large").open("wb") as stream:
            stream.truncate(8 * 1024 * 1024)
        args = ["-", str(self.source), str(self.output), "tx_decode", str(BUDGET)]
        with patch.object(sys, "argv", args), patch("builtins.open", side_effect=AssertionError("payload opened")), redirect_stdout(io.StringIO()):
            exec(compile(mapper_body("map_direct"), str(SCRIPT), "exec"), {"__name__": "__main__"})
        self.assertEqual(list(self.output.iterdir()), [])

    def test_output_failure_is_not_reported_as_success(self):
        self.output.write_bytes(b"existing non-directory")
        (self.source / "seed").write_bytes(b"payload")
        result = self.run_direct()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), b"existing non-directory")


class SetupFailureTests(unittest.TestCase):
    """Regression coverage for CONSTRAINTS.md#qa-corpus-importer-setup-contract."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        stubs = {
            "git": '''[[ "${FAIL_SETUP:-}" != git ]] || exit 19
[[ "$1" == rev-parse ]] || { touch "$TEST_ROOT/clone-attempted"; exit 98; }
printf '%s\\n' "$TEST_ROOT"''',
            "rustc": '''[[ "${FAIL_SETUP:-}" != rustc ]] || exit 17
printf 'host: x86_64-unknown-linux-gnu\\n' ''',
            "mktemp": '''[[ "${FAIL_SETUP:-}" != mktemp ]] || exit 23
mkdir "$TEST_ROOT/staging"
printf '%s\\n' "$TEST_ROOT/staging"''',
            "df": '''[[ "${FAIL_SETUP:-}" != df ]] || exit 7
printf 'Filesystem 1048576-blocks Used Available Capacity Mounted\\n'
printf 'test 100 100 0 100%% /\\n' ''',
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\nset -eu\n" + body + "\n")
            path.chmod(0o755)

    def check_failure(self, failure, status):
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                   TEST_ROOT=str(self.root), FAIL_SETUP=failure)
        result = subprocess.run(["bash", str(SCRIPT)], env=env, cwd=self.root,
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertFalse((self.root / "staging").exists(), "failed setup leaked its working directory")
        self.assertFalse((self.root / "clone-attempted").exists())

    def test_insufficient_disk_cleans_staging(self):
        self.check_failure("", 1)

    def test_git_failure_stops_before_allocating(self):
        self.check_failure("git", 19)

    def test_rustc_failure_stops_before_allocating(self):
        self.check_failure("rustc", 17)

    def test_mktemp_failure_is_not_masked(self):
        self.check_failure("mktemp", 23)

    def test_disk_probe_failure_cleans_staging(self):
        self.check_failure("df", 7)


class MetadataFailureTests(unittest.TestCase):
    def test_metadata_commands_preserve_failure_status(self):
        # Exercise the actual declarations under the script's shell flags;
        # readonly must not turn a failed provenance probe into success.
        for variable, command, status in (("UPSTREAM_COMMIT", "git", 17),
                                          ("UPSTREAM_SIZE_MB", "du", 19),
                                          ("IMPORT_DATE", "date", 23)):
            with self.subTest(variable=variable), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                stub = root / command
                stub.write_text(f"#!/bin/bash\nexit {status}\n")
                stub.chmod(0o755)
                declaration = re.search(rf"^(?:readonly )?{variable}=.*$(?:\nreadonly {variable}$)?",
                                        SCRIPT.read_text(), re.M)
                self.assertIsNotNone(declaration)
                result = subprocess.run(["bash", "-c", 'set -euo pipefail\nWORKDIR="$1"\n'
                                         + declaration.group(0) + "\nprintf continued\n",
                                         "metadata-tests", str(root)],
                                        env=dict(os.environ, PATH=f"{root}{os.pathsep}{os.environ['PATH']}"),
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertNotIn("continued", result.stdout)


if __name__ == "__main__":
    unittest.main()
