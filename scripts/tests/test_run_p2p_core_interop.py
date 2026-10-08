"""Offline checks for the Core differential driver's workdir handling.

A kept --workdir (KEEP=1, the CI cache shape under target/) can restore
stale node datadirs across runs; a restored datadir with an obsolete
schema epoch makes bitcoin-rs refuse to open it. The driver must reset
both datadirs before launching either node — not merely by exit time —
so the stand-in bitcoind below inspects the datadirs at its own
invocation and records a verdict. It exits 0 after the check, so the
driver aborts at the cookie probe with the ordering already proven.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/run-p2p-core-interop.sh"

# Runs in place of bitcoind: reads -datadir=<dir> from its arguments and
# writes "clean" to <workdir>/verdict only when both node datadirs are
# empty at launch. Exits 0 either way so the driver keeps going.
STUB_BITCOIND = """\
#!/bin/sh
datadir=""
for arg in "$@"; do
  case "${arg}" in
    -datadir=*) datadir="${arg#-datadir=}" ;;
  esac
done
workdir=$(dirname "${datadir}")
if [ -n "$(ls -A "${workdir}/core" 2>/dev/null)" ] || [ -n "$(ls -A "${workdir}/rs" 2>/dev/null)" ]; then
  printf 'stale\\n' > "${workdir}/verdict"
else
  printf 'clean\\n' > "${workdir}/verdict"
fi
exit 0
"""


class RunP2pCoreInteropTest(unittest.TestCase):
    def test_datadirs_are_empty_when_core_launches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workdir = root / "workdir"
            stub = root / "stub-bitcoind"
            stub.write_text(STUB_BITCOIND)
            stub.chmod(0o755)
            for node_dir in ("core", "rs"):
                stale = workdir / node_dir / "stale-epoch-state"
                stale.parent.mkdir(parents=True)
                stale.write_text("restored by rust-cache\n")

            result = subprocess.run(
                [
                    "bash",
                    str(SCRIPT),
                    "--bitcoind-command",
                    str(stub),
                    "--workdir",
                    str(workdir),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # The stand-in exits before producing a cookie, so the driver
            # must fail after launching it; reaching that failure proves the
            # verdict was written.
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("starting bitcoind", result.stdout)
            verdict = (workdir / "verdict").read_text().strip()
            self.assertEqual(
                "clean",
                verdict,
                "node datadirs were not reset before bitcoind launched",
            )


if __name__ == "__main__":
    unittest.main()
