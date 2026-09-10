"""Offline tests of the importer's actual mappers and setup failures.

Contract: docs/contracts/qa-corpus.md QAC-01 and fuzz/CORPUS_PROVENANCE.md
own the corpus mapping and successful-import provenance. The P2P harness
accepts a selector with an empty payload. Seed budgets come from the importer.
Fixture metadata and byte strings below are independent synthetic inputs,
not consensus vectors or candidate-derived expected outputs.

Setup failures must abort before cloning and clean acquired staging storage.
The injected command statuses (for example, 7, 17, 19, 23) are test sentinels, not a public
exit-code inventory. Bash assignment/errexit behavior is the external reference:
https://www.gnu.org/software/bash/manual/html_node/Exit-Status.html
Regression context: https://github.com/gosuda/bitcoin-rs/pull/747
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
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", SCRIPT.read_text(), re.M | re.S)
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

    def test_header_only_known_message_preserves_empty_payload(self):
        self.inventory.write_text('pub const COMMANDS: &[Command] = &[Command { name: "verack" }];')
        self.write_message("verack", b"")
        self.run_mapper("map_p2p")
        self.assert_seed("p2p_message", b"\0")

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
        script = b"Q" * (1 << 16)  # u16 framing boundary, independent of the seed budget
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
[[ "${FAIL_SETUP:-}" != missing_host ]] || exit 0
printf 'host: x86_64-unknown-linux-gnu\\n' ''',
            "mktemp": '''touch "$TEST_ROOT/mktemp-called"
[[ "${FAIL_SETUP:-}" != mktemp ]] || exit 23
mkdir "$TEST_ROOT/staging"
printf '%s\\n' "$TEST_ROOT/staging"''',
            "df": '''[[ "${FAIL_SETUP:-}" != df ]] || exit 7
printf 'Filesystem 1048576-blocks Used Available Capacity Mounted\\n'
if [[ "${FAIL_SETUP:-}" == invalid_disk ]]; then
    printf 'test 100 0 invalid 0%% /\\n'
else
    printf 'test 100 100 0 100%% /\\n'
fi ''',
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
        if failure in ("git", "rustc", "missing_host"):
            self.assertFalse((self.root / "mktemp-called").exists())

    def test_insufficient_disk_cleans_staging(self):
        self.check_failure("", 1)

    def test_git_failure_stops_before_allocating(self):
        self.check_failure("git", 19)

    def test_rustc_failure_stops_before_allocating(self):
        self.check_failure("rustc", 17)

    def test_mktemp_failure_is_not_masked(self):
        self.check_failure("mktemp", 23)

    def test_missing_host_stops_before_allocating(self):
        self.check_failure("missing_host", 1)

    def test_malformed_disk_probe_fails_closed(self):
        self.check_failure("invalid_disk", 1)

    def test_disk_probe_failure_cleans_staging(self):
        self.check_failure("df", 7)

    def test_external_failure_statuses_are_not_remapped(self):
        for command, old_status, status in (("git", 19, 61), ("rustc", 17, 62),
                                             ("mktemp", 23, 63), ("df", 7, 64)):
            with self.subTest(command=command):
                stub = self.bin / command
                stub.write_text(stub.read_text().replace(f"exit {old_status}", f"exit {status}"))
                self.check_failure(command, status)


class DirectMappingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "output"

    def run_direct(self):
        command = """set -euo pipefail
CARGO_ENV=(env)
MAX_SEED_BYTES="$3"
log() { printf '[import-qa-assets] %s\\n' "$*"; }
"""
        command += mapper_function("map_direct") + '\nmap_direct "$1" "$2" block_decode\n'
        return subprocess.run(
            ["bash", "-c", command, "direct-tests", str(self.source), str(self.output), str(BUDGET)],
            capture_output=True, text=True, timeout=30, check=False,
        )

    def test_missing_source_cannot_report_success(self):
        self.source.rmdir()
        result = self.run_direct()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("imported=", result.stdout)

    def test_exact_byte_mapping_and_size_boundary(self):
        (self.source / "empty").touch()
        retained = bytes(range(256)) * ((BUDGET - 1) // 256) + b"x" * ((BUDGET - 1) % 256)
        (self.source / "last accepted").write_bytes(retained)
        for name, size in (("at-limit", BUDGET), ("over-limit", BUDGET + 1)):
            with (self.source / name).open("wb") as output:
                output.truncate(size)
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in self.output.iterdir()}, {"empty", "last accepted"})
        self.assertEqual((self.output / "last accepted").read_bytes(), retained)
        self.assertEqual((self.output / "empty").read_bytes(), b"")
        self.assertIn("imported=2 skipped_oversize=2", result.stdout)

    def test_nested_directories_and_symlinks_are_not_imported(self):
        nested = self.source / "nested"
        nested.mkdir()
        (nested / "seed").write_bytes(b"nested bytes")
        (self.source / "link").symlink_to(nested / "seed")
        (self.source / "broken").symlink_to(self.source / "absent")
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertIn("imported=0 skipped_oversize=0", result.stdout)

    def test_filenames_are_not_interpreted_as_shell_syntax(self):
        names = ("line\nbreak", "-option", "white space", "semi;colon", "$(touch injected)")
        for name in names:
            (self.source / name).write_bytes(name.encode())
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in self.output.iterdir()}, set(names))
        for name in names:
            self.assertEqual((self.output / name).read_bytes(), name.encode())


class ImportFlowTests(unittest.TestCase):
    """Execute the entry point, replacing only Git/Rust and failure probes.

    QAC-01 provenance is a success record: failed acquisition, measurement,
    or minimization must not replace the previous provenance document.
    The four target names below come from that contract's explicit scope.
    """

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="qa import flow ")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.upstream = self.root / "upstream"
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.provenance = self.root / "fuzz/CORPUS_PROVENANCE.md"
        self.provenance.parent.mkdir()
        self.provenance.write_text("previous provenance\n")
        self.log = self.root / "minimize.log"
        self.pin = re.search(r'^readonly QA_ASSETS_PIN="([0-9a-f]{40})"', SCRIPT.read_text(), re.M).group(1)
        for corpus in ("p2p_deserialize_raw_net_msg", "bitcoin_deserialize_script",
                       "bitcoin_script_bytes_to_asm_fmt", "bitcoin_deserialize_block",
                       "bitcoin_deserialize_transaction"):
            (self.upstream / "fuzz_corpora" / corpus).mkdir(parents=True)
        (self.upstream / "fuzz_corpora/p2p_deserialize_raw_net_msg/verack").write_bytes(
            b"\0" * 4 + b"verack" + b"\0" * 14)
        (self.upstream / "fuzz_corpora/bitcoin_deserialize_script/script").write_bytes(b"Q" * 32)
        (self.upstream / "fuzz_corpora/bitcoin_deserialize_block/block").write_bytes(b"block bytes")
        (self.upstream / "fuzz_corpora/bitcoin_deserialize_transaction/tx").write_bytes(b"tx bytes")
        inventory = self.root / "crates/p2p/src/compat.rs"
        inventory.parent.mkdir(parents=True)
        inventory.write_text('pub const COMMANDS: &[Command] = &[Command { name: "verack" }];')
        harness = self.root / "fuzz/fuzz_targets/script_eval.rs"
        harness.parent.mkdir()
        harness.write_text("const ELEMENT_LEN_MAX: usize = 1024;\n")
        stubs = {
            "git": r"""case "$1" in
rev-parse) printf '%s\n' "$TEST_ROOT" ;;
init) mkdir -p "$3"; cp -R "$UPSTREAM/." "$3/" ;;
-C)
    case "$3" in
        remote|checkout) : ;;
        fetch) [[ "$FAIL_FLOW" != fetch ]] || exit 31 ;;
        rev-parse) [[ "$FAIL_FLOW" != identity ]] || exit 44; printf '%s\n' "$PIN" ;;
        *) exit 99 ;;
    esac ;;
*) exit 99 ;;
esac""",
            "rustc": "printf 'host: x86_64-unknown-linux-gnu\\n'",
            "df": "printf 'Filesystem 1048576-blocks Used Available Capacity Mounted\\ntest 9999 0 9999 0%% /\\n'",
            "du": '[[ "$FAIL_FLOW" != size ]] || exit 42\nexec /usr/bin/du "$@"',
            "date": '[[ "$FAIL_FLOW" != date ]] || exit 43\nexec /usr/bin/date "$@"',
            "cargo": r"""printf '%s\n' "$*" >> "$MINIMIZE_LOG"
[[ "$FAIL_FLOW" != minimize || "${!#}" != tx_decode ]] || exit 37
if [[ "$FAIL_FLOW" == terminate ]]; then kill -TERM "$PPID"; fi""",
        }
        for name, body in stubs.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\nset -eu\n" + body + "\n")
            path.chmod(0o755)

    def run_import(self, failure=""):
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                   TEST_ROOT=str(self.root), UPSTREAM=str(self.upstream), TMPDIR=str(self.tmp),
                   PIN=self.pin, MINIMIZE_LOG=str(self.log), FAIL_FLOW=failure)
        result = subprocess.run(["bash", str(SCRIPT)], cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(list(self.tmp.iterdir()), [], "import leaked its clone")
        return result

    def assert_failure(self, failure, status):
        result = self.run_import(failure)
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertEqual(self.provenance.read_text(), "previous provenance\n")
        self.assertNotIn("import complete", result.stdout)

    def test_success_minimizes_all_targets_before_provenance(self):
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.log.read_text().splitlines(), [
            f"fuzz cmin --target x86_64-unknown-linux-gnu {target}"
            for target in ("p2p_message", "block_decode", "tx_decode", "script_eval")])
        self.assertIn(self.pin, self.provenance.read_text())
        self.assertEqual((self.root / "fuzz/corpus/block_decode/block").read_bytes(), b"block bytes")
        self.assertEqual((self.root / "fuzz/corpus/tx_decode/tx").read_bytes(), b"tx bytes")
        self.assertEqual([p.read_bytes() for p in (self.root / "fuzz/corpus/p2p_message").iterdir()], [b"\0"])

    def test_missing_direct_corpus_cannot_publish_provenance(self):
        directory = self.upstream / "fuzz_corpora/bitcoin_deserialize_block"
        (directory / "block").unlink()
        directory.rmdir()
        self.assert_failure("", 1)
        self.assertFalse(self.log.exists())

    def test_fetch_failure_preserves_status_and_provenance(self):
        self.assert_failure("fetch", 31)

    def test_identity_failure_preserves_status_and_provenance(self):
        self.assert_failure("identity", 44)

    def test_size_probe_failure_preserves_status_and_provenance(self):
        self.assert_failure("size", 42)

    def test_date_failure_preserves_status_and_provenance(self):
        self.assert_failure("date", 43)

    def test_minimizer_failure_preserves_status_and_provenance(self):
        self.assert_failure("minimize", 37)
        self.assertEqual(len(self.log.read_text().splitlines()), 3)

    def test_termination_cleans_clone_and_preserves_provenance(self):
        self.assert_failure("terminate", 143)


if __name__ == "__main__":
    unittest.main()
