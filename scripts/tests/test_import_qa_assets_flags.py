"""Regression for Rust comments in the script_eval FLAGS owner inventory.

Contract: `fuzz/fuzz_targets/script_eval.rs` owns the selector-indexed input framing
and `FLAGS` order; `docs/contracts/qa-corpus.md` QAC-01 requires imported script
seeds to feed that harness. This test mutates only owner syntax (order/comments),
then derives selector indices from the parsed owner contract before independently
constructing the documented byte frame.
"""

import importlib.util
from pathlib import Path
import tempfile
import unittest


MAPPER = Path(__file__).resolve().parents[1] / "import_qa_assets.py"
_SPEC = importlib.util.spec_from_file_location("qa_flags_mapper", MAPPER)
mapper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mapper)


class FlagCommentTests(unittest.TestCase):
    def test_comments_with_commas_do_not_change_owned_selectors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            output = root / "output"
            source.mkdir()
            script = b"Q" * 64
            (source / "script").write_bytes(script)
            harness = root / "script_eval.rs"
            harness.write_text(
                "const FLAGS: [VerifyFlags; 4] = [\n"
                "    VerifyFlags::TAPROOT, // taproot, selector owner\n"
                "    /* mandatory, nested /* comment, comma */ still comment */\n"
                "    VerifyFlags::MANDATORY,\n"
                "    VerifyFlags::NONE, // none, selector owner\n"
                "    VerifyFlags::STANDARD,\n"
                "];\n"
                "const ELEMENT_LEN_MAX: usize = 1_024;\n"
            )
            _, none_selector, taproot_selector = mapper._script_contract(harness)
            mapper.map_script([source], harness, output, 65_536)
            seeds = {path.read_bytes() for path in output.iterdir()}
            raw = bytes([none_selector]) + b"\0\0\x40\0" + script + b"\0"
            taproot = (bytes([taproot_selector]) + b"\0\0\x22\0\x51\x20" + script[:32]
                       + b"\x01\x20\0" + script[32:])
            self.assertEqual(seeds, {raw, taproot})


if __name__ == "__main__":
    unittest.main()
