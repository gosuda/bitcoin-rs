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
