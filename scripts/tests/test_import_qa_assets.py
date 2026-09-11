"""Offline QA import regressions for QAC-01 and the harness input contracts.

See docs/contracts/qa-corpus.md, fuzz/CORPUS_PROVENANCE.md, and the framing
comments in fuzz/fuzz_targets/{p2p_message,script_eval}.rs. Fixtures here are
synthetic wire bytes with hand-written expected frames, not Bitcoin validity
vectors. The importer owns MAX_SEED_BYTES; Rust owners supply the inventories
and element limits. Failure publication cases are documented in PR #747.
"""

from contextlib import contextmanager, redirect_stdout
import importlib.util
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
_budget = re.search(r"^readonly MAX_SEED_BYTES=([0-9]+)\s*(?:#.*)?$", SCRIPT.read_text(), re.M)
if _budget is None or int(_budget.group(1)) < 1:
    raise RuntimeError("Cannot read the importer's positive MAX_SEED_BYTES limit")
BUDGET = int(_budget.group(1))


MAPPER = SCRIPT.with_name("import_qa_assets.py")
_spec = importlib.util.spec_from_file_location("qa_assets_mapper", MAPPER)
mapper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mapper)


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
        self.script_target.write_text(
            "const FLAGS: [VerifyFlags; 4] = [\n"
            "    VerifyFlags::NONE,\n"
            "    VerifyFlags::MANDATORY,\n"
            "    VerifyFlags::STANDARD,\n"
            "    VerifyFlags::TAPROOT,\n"
            "];\n"
            "const ELEMENT_LEN_MAX: usize = 1_024;\n"
        )

    def run_mapper(self, name, budget=BUDGET):
        with redirect_stdout(io.StringIO()):
            if name == "map_p2p":
                mapper.map_p2p(self.p2p, self.inventory, self.output / "p2p_message", budget)
            else:
                mapper.map_script([self.scripts, self.asm], self.script_target,
                                  self.output / "script_eval", budget)

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
                with self.assertRaises(ValueError):
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
        script = b"Q" * (1 << 16)
        (self.scripts / "boundary").write_bytes(script)
        self.run_mapper("map_script")
        raw = b"\0\0\0" + (1024).to_bytes(2, "little") + script[:1024] + b"\0"
        taproot = b"\x03\0\0\x22\0\x51\x20" + script[:32] + b"\x01" + (992).to_bytes(2, "little") + script[32:1024]
        self.assert_seed("script_eval", raw)
        self.assert_seed("script_eval", taproot)
        self.assertEqual(len(list((self.output / "script_eval").iterdir())), 2)

    def test_script_limit_follows_the_owner_constant(self):
        self.script_target.write_text(
            self.script_target.read_text().replace("1_024", "512")
        )
        (self.scripts / "script").write_bytes(b"Q" * 1024)
        self.run_mapper("map_script")
        self.assert_seed("script_eval", b"\0\0\0\0\x02" + b"Q" * 512 + b"\0")

    def test_missing_script_limit_fails_closed(self):
        self.script_target.write_text(
            self.script_target.read_text().replace("const ELEMENT_LEN_MAX: usize = 1_024;\n", "")
        )
        with self.assertRaises(ValueError):
            self.run_mapper("map_script")
        self.assertFalse((self.output / "script_eval").exists())


    def test_script_selectors_follow_the_owner_inventory_order(self):
        self.script_target.write_text(
            "const FLAGS: [VerifyFlags; 4] = [\n"
            "    VerifyFlags::TAPROOT,\n"
            "    VerifyFlags::MANDATORY,\n"
            "    VerifyFlags::NONE,\n"
            "    VerifyFlags::STANDARD,\n"
            "];\n"
            "const ELEMENT_LEN_MAX: usize = 1_024;\n"
        )
        script = b"Q" * 64
        (self.scripts / "script").write_bytes(script)
        self.run_mapper("map_script")
        raw = b"\x02\0\0\x40\0" + script + b"\0"
        taproot = b"\x00\0\0\x22\0\x51\x20" + script[:32] + b"\x01\x20\0" + script[32:]
        self.assert_seed("script_eval", raw)
        self.assert_seed("script_eval", taproot)

    def test_missing_script_flags_fail_closed(self):
        self.script_target.write_text("const ELEMENT_LEN_MAX: usize = 1_024;\n")
        with self.assertRaisesRegex(ValueError, "FLAGS"):
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
        original_open = open
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

        with patch.object(mapper, "open", guarded_open, create=True):
            self.run_mapper("map_p2p")
            self.run_mapper("map_script")
        self.assertEqual(reads, limits)

    def test_cli_maps_all_targets_using_the_owner_paths(self):
        self.write_message("pong", b"payload")
        (self.scripts / "script").write_bytes(b"Q")
        for source in ("bitcoin_deserialize_block", "bitcoin_deserialize_transaction"):
            (self.corpora / source).mkdir()
            (self.corpora / source / "seed").write_bytes(b"direct")
        result = subprocess.run(
            [sys.executable, str(MAPPER), "--corpora", str(self.corpora),
             "--repo-root", str(self.root), "--out-base", str(self.output),
             "--max-seed-bytes", str(BUDGET)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_seed("p2p_message", b"\x01payload")
        self.assert_seed("script_eval", b"\0\0\0\x01\0Q\0")
        for target in ("block_decode", "tx_decode"):
            self.assertEqual((self.output / target / "seed").read_bytes(), b"direct")


    def test_directory_order_does_not_change_seed_names_or_bytes(self):
        self.write_message("ping", b"A")
        self.write_message("pong", b"B")
        for directory in (self.scripts, self.asm):
            (directory / "one").write_bytes(b"Q" * 64)
            (directory / "two").write_bytes(b"R")
        self.run_mapper("map_p2p")
        self.run_mapper("map_script")
        expected = {str(path.relative_to(self.output)): path.read_bytes()
                    for path in self.output.rglob("*") if path.is_file()}
        self.output = self.root / "reversed"
        original_paths = mapper._seed_paths

        def reversed_paths(source):
            return iter(reversed(list(original_paths(source))))

        with patch.object(mapper, "_seed_paths", reversed_paths):
            self.run_mapper("map_p2p")
            self.run_mapper("map_script")
        actual = {str(path.relative_to(self.output)): path.read_bytes()
                  for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(actual, expected)


class SetupFailureTests(unittest.TestCase):
    """Regression coverage for CONSTRAINTS.md#qa-corpus-importer-setup-contract.

    QAC-01 names the corpus/provenance owner; the setup section in
    CONSTRAINTS.md owns the exit-status and cleanup behavior asserted below.
    """

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


class DirectMappingTests(unittest.TestCase):
    """Direct mappings preserve exact bytes/names and never report a failed scan as success."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "output"
        self.output.mkdir()

    def run_direct(self, source=None, env=None):
        return subprocess.run(
            [sys.executable, "-c",
             "from pathlib import Path; import sys; from import_qa_assets import map_direct; "
             "map_direct(Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3]), 'test-direct')",
             str(source or self.source), str(self.output), str(BUDGET)],
            cwd=MAPPER.parent, env=env, capture_output=True,
            text=True, timeout=10, check=False,
        )

    def test_exact_bytes_and_unusual_names_are_preserved(self):
        seeds = {"empty": b"", "space and\nnewline": b"\x00\xff\n", "-option": b"abc"}
        for name, data in seeds.items():
            (self.source / name).write_bytes(data)
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, seeds)

    def test_limit_is_exclusive(self):
        for name, length in (("under", BUDGET - 1), ("equal", BUDGET), ("over", BUDGET + 1)):
            (self.source / name).write_bytes(b"x" * length)
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([p.name for p in self.output.iterdir()], ["under"])
        self.assertEqual((self.output / "under").read_bytes(), b"x" * (BUDGET - 1))
        self.assertIn("skipped_oversize=2", result.stdout)

    def test_missing_source_is_an_error(self):
        result = self.run_direct(self.root / "missing")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_non_directory_source_is_an_error(self):
        source = self.root / "not-a-directory"
        source.write_bytes(b"seed")
        result = self.run_direct(source)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_non_regular_entries_are_not_followed(self):
        (self.source / "directory").mkdir()
        (self.source / "link").symlink_to(self.root / "external")
        (self.root / "external").write_bytes(b"external")
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_conflicting_output_directory_is_not_a_copy_destination(self):
        (self.source / "seed").write_bytes(b"new")
        (self.output / "seed").mkdir()
        result = self.run_direct()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(list((self.output / "seed").iterdir()), [])

    def test_existing_output_symlink_does_not_overwrite_its_target(self):
        external = self.root / "external"
        external.write_bytes(b"preserve")
        (self.output / "seed").symlink_to(external)
        (self.source / "seed").write_bytes(b"new")
        result = self.run_direct()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(external.read_bytes(), b"preserve")
        self.assertFalse((self.output / "seed").is_symlink())
        self.assertEqual((self.output / "seed").read_bytes(), b"new")


class PublicationTests(unittest.TestCase):
    """Failed publication preserves old bytes and cleans temporary files."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name)
        self.destination = self.output / "seed"
        self.destination.write_bytes(b"old")

    def assert_preserved(self):
        self.assertEqual(self.destination.read_bytes(), b"old")
        self.assertEqual(list(self.output.iterdir()), [self.destination])

    def test_replace_failure_preserves_old_file(self):
        with patch.object(mapper.os, "replace", side_effect=OSError("injected rename failure")):
            with self.assertRaisesRegex(OSError, "rename failure"):
                mapper._publish(self.output, "seed", b"new")
        self.assert_preserved()

    def test_partial_write_failure_preserves_old_file(self):
        real_temporary = mapper.tempfile.NamedTemporaryFile

        def failing_temporary(*args, **kwargs):
            temporary = real_temporary(*args, **kwargs)
            write = temporary.write

            def fail_after_prefix(data):
                write(data[:2])
                raise OSError("injected partial write")

            temporary.write = fail_after_prefix
            return temporary

        with patch.object(mapper.tempfile, "NamedTemporaryFile", failing_temporary):
            with self.assertRaisesRegex(OSError, "partial write"):
                mapper._publish(self.output, "seed", b"new")
        self.assert_preserved()

    def test_staging_failure_preserves_old_file(self):
        with patch.object(mapper.tempfile, "NamedTemporaryFile", side_effect=OSError("no space")):
            with self.assertRaisesRegex(OSError, "no space"):
                mapper._publish(self.output, "seed", b"new")
        self.assert_preserved()

    def test_old_file_remains_visible_until_replace(self):
        replace = mapper.os.replace
        observations = []

        def observe(staged, destination):
            observations.append((self.destination.read_bytes(), Path(staged).read_bytes()))
            replace(staged, destination)

        with patch.object(mapper.os, "replace", observe):
            mapper._publish(self.output, "seed", b"complete new bytes")
        self.assertEqual(observations, [(b"old", b"complete new bytes")])
        self.assertEqual(self.destination.read_bytes(), b"complete new bytes")
        self.assertEqual(list(self.output.iterdir()), [self.destination])

    def test_directory_scan_is_lazy_and_closes(self):
        class Entry:
            path = "synthetic/seed"

            def is_file(self, *, follow_symlinks):
                self.follow_symlinks = follow_symlinks
                return True

        entry = Entry()
        requested = []
        closed = []

        @contextmanager
        def entries(_source):
            def iterator():
                requested.append(1)
                yield entry
                raise AssertionError("directory was eagerly consumed")
            try:
                yield iterator()
            finally:
                closed.append(True)

        with patch.object(mapper.os, "scandir", entries):
            paths = mapper._seed_paths(Path("synthetic"))
            self.assertEqual(next(paths), Path(entry.path))
            self.assertEqual(requested, [1])
            self.assertFalse(entry.follow_symlinks)
            paths.close()
        self.assertEqual(closed, [True])

    def test_scanning_failure_is_not_swallowed(self):
        with patch.object(mapper.os, "scandir", side_effect=OSError("scan failed")):
            with self.assertRaisesRegex(OSError, "scan failed"):
                list(mapper._seed_paths(self.output))

    def test_direct_reads_stop_at_the_budget_without_trusting_metadata(self):
        source = self.output / "source"
        source.mkdir()
        seed = source / "large"
        with seed.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024)
        destination = self.output / "mapped"
        real_open = open
        requested = []

        @contextmanager
        def bounded_open(path, mode="r", *args, **kwargs):
            with real_open(path, mode, *args, **kwargs) as stream:
                if path != seed or mode != "rb":
                    yield stream
                    return

                class Bounded:
                    def read(self, size=-1):
                        requested.append(size)
                        if not 0 <= size <= BUDGET:
                            raise AssertionError("unbounded corpus read")
                        return stream.read(size)

                yield Bounded()

        with patch.object(mapper, "open", bounded_open, create=True), redirect_stdout(io.StringIO()):
            mapper.map_direct(source, destination, BUDGET, "direct")
        self.assertEqual(requested, [BUDGET])
        self.assertEqual(list(destination.iterdir()), [])

    def test_invalid_budgets_fail_before_reads_or_publication(self):
        with patch.object(mapper, "_read_seed", side_effect=AssertionError("read too early")):
            for budget in (0, -1):
                with self.subTest(budget=budget):
                    with self.assertRaises(ValueError):
                        mapper.map_direct(self.output, self.output, budget, "direct")
                    with self.assertRaises(ValueError):
                        mapper.map_p2p(self.output, self.output, self.output, budget)


if __name__ == "__main__":
    unittest.main()
