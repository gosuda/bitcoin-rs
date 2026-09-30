"""Offline checks for accepting or replacing a pinned Core installation cache."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "install-bitcoind.sh"
PIN = re.search(r'^readonly TARBALL_SHA256="([0-9a-f]{64})"$', SCRIPT.read_text(), re.M)
if PIN is None:
    raise RuntimeError("Installer must declare its pinned archive digest")


class InstallBitcoindTest(unittest.TestCase):
    def test_cache_requires_successful_version_probe(self):
        for version_exit in (0, 42):
            with self.subTest(version_exit=version_exit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                prefix = root / "core"
                (prefix / "bin").mkdir(parents=True)
                binary = prefix / "bin" / "bitcoind"
                binary.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' 'Bitcoin Core daemon version v31.1.0 bitcoind'\n"
                    # More than a pipe buffer: early head termination must not
                    # make a successful version process look like a failed one.
                    "i=0\nwhile [ \"$i\" -lt 4096 ]; do\n"
                    "  printf '%s\\n' 'additional version and license information'\n"
                    "  i=$((i + 1))\ndone\n"
                    f"exit {version_exit}\n"
                )
                binary.chmod(0o755)
                (prefix / ".bitcoin-rs-core-tarball-sha256").write_text(PIN.group(1) + "\n")
                shims = root / "bin"
                shims.mkdir()
                curl = shims / "curl"
                curl.write_text('#!/bin/sh\n: > "$DOWNLOAD_SENTINEL"\nexit 97\n')
                curl.chmod(0o755)
                sentinel = root / "download"
                result = subprocess.run(
                    ["bash", str(SCRIPT), "--print-path"],
                    env={
                        **os.environ,
                        "BITCOIND_PREFIX": str(prefix),
                        "DOWNLOAD_SENTINEL": str(sentinel),
                        "PATH": str(shims) + os.pathsep + os.environ["PATH"],
                    },
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                if version_exit == 0:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), str(binary))
                    self.assertFalse(sentinel.exists())
                else:
                    self.assertEqual(result.returncode, 97, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertTrue(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
