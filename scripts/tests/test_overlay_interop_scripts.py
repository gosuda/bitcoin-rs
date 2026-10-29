"""Offline regressions for the P2P overlay interop scripts.

No live daemon is launched: the recorder is checked statically against the
Python 3.11 grammar it must run under, and the interop driver is checked
for its tor-gencert digest pin and its evidence-preserving cleanup.
"""

import ast
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
RECORDER = REPO / "scripts/overlay_recorder.py"
DRIVER = REPO / "scripts/run-p2p-overlay-interop.sh"


class OverlayRecorderTest(unittest.TestCase):
    def test_parses_on_python_311_grammar(self):
        source = RECORDER.read_text()
        ast.parse(source, feature_version=(3, 11))

    def test_no_pep695_syntax(self):
        tree = ast.parse(RECORDER.read_text())
        type_aliases = [node for node in ast.walk(tree) if type(node).__name__ == "TypeAlias"]
        self.assertEqual([], type_aliases, "PEP 695 `type` aliases need Python 3.12")
        with_params = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and getattr(node, "type_params", [])
        ]
        self.assertEqual([], with_params, "PEP 695 generics need Python 3.12")

    def test_bounded_is_plain_def_over_typevar(self):
        source = RECORDER.read_text()
        self.assertIn('T = TypeVar("T")', source)
        self.assertIn("async def bounded(awaitable: Awaitable[T],", source)
        self.assertNotIn("async def bounded[", source)


class OverlayInteropDriverTest(unittest.TestCase):
    def test_tor_gencert_digest_pin_enforced(self):
        source = DRIVER.read_text()
        self.assertIn("--tor-gencert-sha256", source)
        self.assertIn('sha256sum "${TOR_GENCERT_BIN}"', source)
        self.assertIn("tor-gencert pin mismatch", source)
        # tor-gencert has no --version flag (-v is verbose); probing it
        # would fail every real run at the pin.
        self.assertNotIn('"${TOR_GENCERT_CMD[@]}" --version', source)

    def test_evidence_inside_workdir_is_kept_on_success(self):
        source = DRIVER.read_text()
        self.assertIn("evidence_in_workdir", source)
        self.assertIn('EVIDENCE="${WORKDIR}/evidence.json"', source)
        self.assertIn("((evidence_in_workdir == 0))", source)


if __name__ == "__main__":
    unittest.main()
