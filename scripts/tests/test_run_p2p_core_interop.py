"""Offline checks for the Core differential driver's workdir handling.

A kept --workdir (KEEP=1, the CI cache shape under target/) can restore
stale node datadirs across runs; a restored datadir with an obsolete
schema epoch makes bitcoin-rs refuse to open it. The driver must reset
both datadirs before launching either node. `true` stands in for
bitcoind: it exits 0 immediately, so the run aborts at the cookie check
with the reset already executed — no real node required.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/run-p2p-core-interop.sh"


class RunP2pCoreInteropTest(unittest.TestCase):
    def test_kept_workdir_datadirs_are_reset_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            stale_files = []
            for node_dir in ("core", "rs"):
                stale = workdir / node_dir / "stale-epoch-state"
                stale.parent.mkdir(parents=True)
                stale.write_text("restored by rust-cache\n")
                stale_files.append(stale)

            result = subprocess.run(
                [
                    "bash",
                    str(SCRIPT),
                    "--bitcoind-command",
                    "true",
                    "--workdir",
                    str(workdir),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # The stand-in bitcoind exits before producing a cookie, so the
            # driver must fail after the reset; reaching that failure proves
            # the reset ran.
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("starting bitcoind", result.stdout)
            for stale in stale_files:
                self.assertFalse(stale.exists(), f"stale file survived reset: {stale}")
            self.assertEqual([], list((workdir / "core").iterdir()))
            self.assertEqual([], list((workdir / "rs").iterdir()))


if __name__ == "__main__":
    unittest.main()
