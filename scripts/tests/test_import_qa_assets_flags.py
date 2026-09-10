"""Regression for Rust comments in the script_eval FLAGS owner inventory."""

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
            mapper.map_script([source], harness, output, 65_536)
            seeds = {path.read_bytes() for path in output.iterdir()}
            raw = b"\x02\0\0\x40\0" + script + b"\0"
            taproot = b"\x00\0\0\x22\0\x51\x20" + script[:32] + b"\x01\x20\0" + script[32:]
            self.assertEqual(seeds, {raw, taproot})


if __name__ == "__main__":
    unittest.main()
