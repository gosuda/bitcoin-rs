"""QAC-01 boundary regressions for seed ingress and publication.

`docs/contracts/qa-corpus.md` QAC-01 and QAC-04 and the framing in
`fuzz/fuzz_targets/p2p_message.rs` require a selector followed by the payload,
which may be empty. `crates/p2p/src/compat.rs` owns selector order; comments
are not inventory entries. AGENTS.md's data-preservation rule applies to
publication, and CONSTRAINTS.md CL-14 requires bounded ingress. File races
below are injected in disposable directories, not an operator checkout.
"""

from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_import_qa_assets import BUDGET, MAPPER, mapper


class SeedBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "output"
        self.inventory = self.root / "compat.rs"

    def map_p2p(self, budget=BUDGET):
        with redirect_stdout(io.StringIO()):
            mapper.map_p2p(self.source, self.inventory, self.output, budget)

    def write_message(self, name, payload=b""):
        self.assertLessEqual(len(name), 12)
        message = b"\0" * 4 + name.encode().ljust(12, b"\0") + b"\0" * 8 + payload
        (self.source / name).write_bytes(message)

    def test_commented_commands_do_not_shift_decoder_selection(self):
        self.inventory.write_text('''pub const COMMANDS: &[Command] = &[
    // Command { name: "ghost" },
    Command { name: "verack" },
    /* nested /* Command { name: "phantom" }, */ ]; still a comment */
    Command { name: "ping" },
];
''')
        self.write_message("ping", b"payload")
        self.map_p2p()
        # Only two live entries exist; ping is independently the second entry.
        self.assertEqual([path.read_bytes() for path in self.output.iterdir()],
                         [b"\x01payload"])

    def test_raw_strings_before_commands_do_not_stop_inventory_scan(self):
        self.inventory.write_text('''const NOTE: &str = r#""/*"#;
    pub const COMMANDS: &[Command] = &[Command { name: "ping" }];
''')
        self.write_message("ping", b"payload")
        self.map_p2p()
        self.assertEqual([path.read_bytes() for path in self.output.iterdir()], [b"\0payload"])

    def test_raw_string_delimiters_preserve_live_command_selection(self):
        # Rust Reference raw-string grammar (matching hash-delimited terminators):
        # https://doc.rust-lang.org/reference/tokens.html#raw-string-literals
        # Strings before COMMANDS are fixture data, not inventory or comments.
        table = ('pub const COMMANDS: &[Command] = &['
                 'Command { name: "ping" }, Command { name: "verack" }];')
        self.write_message("verack")
        for prefix in ("r", "br", "cr"):
            for count in (0, 1, 2, 3, 255):
                with self.subTest(prefix=prefix, hashes=count):
                    hashes = "#" * count
                    body = '/* // backslash \\'
                    if count:
                        body += ' embedded " /* quote'
                    if count > 1:
                        body += ' "' + "#" * (count - 1) + ' not the terminator'
                    literal = prefix + hashes + '"' + body + '"' + hashes
                    kind = {'r': '&str', 'br': '&[u8]', 'cr': '&core::ffi::CStr'}[prefix]
                    text = 'const EXAMPLE: ' + kind + ' = ' + literal + ';\n' + table
                    self.inventory.write_text(text)
                    self.assertIn(literal, mapper._strip_rust_comments(text))
                    self.map_p2p()
                    self.assertEqual([path.read_bytes() for path in self.output.iterdir()],
                                     [b"\x01"])

    def test_unterminated_raw_literal_is_rejected(self):
        self.inventory.write_text('const BAD: &str = r##"not terminated;\n'
                                  'pub const COMMANDS: &[Command] = &['
                                  'Command { name: "verack" }];')
        with self.assertRaisesRegex(ValueError, "raw string"):
            self.map_p2p()
        self.assertFalse(self.output.exists())

    def test_header_only_command_becomes_a_selector_only_seed(self):
        self.inventory.write_text('pub const COMMANDS: &[Command] = &[Command { name: "verack" }];')
        self.write_message("verack")
        self.map_p2p()
        self.assertEqual([path.read_bytes() for path in self.output.iterdir()], [b"\0"])

    def test_one_byte_budget_supports_a_selector_only_seed(self):
        self.inventory.write_text('pub const COMMANDS: &[Command] = &[Command { name: "verack" }];')
        self.write_message("verack")
        self.map_p2p(budget=1)
        self.assertEqual([path.read_bytes() for path in self.output.iterdir()], [b"\0"])

    def test_truncated_envelopes_never_become_selector_only_seeds(self):
        self.inventory.write_text('pub const COMMANDS: &[Command] = &[Command { name: "verack" }];')
        message = b"\0" * 4 + b"verack".ljust(12, b"\0") + b"\0" * 8
        for length in range(len(message)):
            (self.source / str(length)).write_bytes(message[:length])
        self.map_p2p()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_source_changed_to_symlink_after_scan_is_rejected(self):
        seed = self.source / "seed"
        seed.write_bytes(b"expected")
        unrelated = self.root / "unrelated"
        unrelated.write_bytes(b"must not enter corpus")
        original_paths = mapper._seed_paths

        def raced_paths(source):
            for path in original_paths(source):
                path.unlink()
                path.symlink_to(unrelated)
                yield path

        with patch.object(mapper, "_seed_paths", raced_paths), redirect_stdout(io.StringIO()):
            with self.assertRaises(OSError):
                mapper.map_direct(self.source, self.output, BUDGET, "test")
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(unrelated.read_bytes(), b"must not enter corpus")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_fifo_read_is_rejected_without_waiting_for_a_writer(self):
        fifo = self.source / "fifo"
        os.mkfifo(fifo)
        command = [sys.executable, "-c",
                   "from pathlib import Path; import sys; "
                   "from import_qa_assets import _read_seed; "
                   "_read_seed(Path(sys.argv[1]), int(sys.argv[2]))",
                   str(fifo), str(BUDGET)]
        try:
            result = subprocess.run(command, cwd=MAPPER.parent, capture_output=True,
                                    text=True, timeout=2, check=False)
        except subprocess.TimeoutExpired:
            self.fail("seed ingress blocked on a FIFO despite its byte budget")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular", result.stderr)

    def test_failed_descriptor_validation_closes_the_descriptor(self):
        seed = self.source / "seed"
        seed.write_bytes(b"data")
        opened = []
        real_open = os.open

        def observe_open(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with patch.object(mapper.os, "open", observe_open):
            with patch.object(mapper.os, "fstat", side_effect=OSError("injected fstat failure")):
                with self.assertRaisesRegex(OSError, "fstat failure"):
                    mapper._read_seed(seed, BUDGET)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_published_seed_remains_readable_in_a_shared_checkout(self):
        self.output.mkdir()
        previous_umask = os.umask(0o022)
        try:
            mapper._publish(self.output, "seed", b"public corpus bytes")
        finally:
            os.umask(previous_umask)
        # QAC-04 requires repository-readable mode for published corpus seeds.
        self.assertEqual(stat.S_IMODE((self.output / "seed").stat().st_mode), 0o644)

    def test_failed_seed_mode_change_preserves_previous_bytes(self):
        self.output.mkdir()
        destination = self.output / "seed"
        destination.write_bytes(b"old")
        with patch.object(mapper.os, "fchmod", side_effect=OSError("injected chmod failure")):
            with self.assertRaisesRegex(OSError, "chmod failure"):
                mapper._publish(self.output, "seed", b"new")
        self.assertEqual(destination.read_bytes(), b"old")
        self.assertEqual(list(self.output.iterdir()), [destination])


if __name__ == "__main__":
    unittest.main()
