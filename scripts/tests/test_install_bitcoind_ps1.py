"""Offline checks for accepting or replacing a pinned Core installation cache
on the native-PowerShell lane.

Mirrors test_install_bitcoind.py's cache contract: a working pinned binary
with a matching stamp must be reused without a fetch, and a binary whose
-version probe fails (or cannot launch at all) must be rejected and replaced —
a throw from the probe must not abort the installer. The fetch is intercepted
by a PATH-shimmed curl.exe exactly like the bash lane shims curl. Requires
Windows (sys.platform == "win32") and a powershell.exe on PATH; skipped
elsewhere.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/install-bitcoind.ps1"
PIN = subprocess.check_output(
    [
        sys.executable,
        str(REPO / "scripts/resolve_reference_identity.py"),
        "core",
        str(REPO),
    ],
    text=True,
).splitlines()[2]
POWERSHELL = (
    shutil.which("powershell.exe")
    or shutil.which("powershell")
    or shutil.which("pwsh")
    or shutil.which("pwsh.exe")
)

# The stubs are compiled per test run so `-version` and `curl.exe` are real
# launches — the corrupt-cache case cannot exist with a text-file stand-in
# (PowerShell refusing to exec it is exactly the throw path under test).
# Add-Type is the toolchain-free compiler .NET ships on Windows.
STUB_CS_TEMPLATE = (
    "public class P { public static int Main(string[] a) {"
    " BODY"
    " return EXITCODE; } }"
)
BITCOIND_BODY = (
    "System.Console.WriteLine(\"Bitcoin Core daemon version v31.1.0 bitcoind\");"
)
CURL_BODY = (
    "System.IO.File.WriteAllBytes("
    "System.Environment.GetEnvironmentVariable(\"DOWNLOAD_SENTINEL\"),"
    "new byte[0]);"
)


def compile_stub(destination: Path, body: str, exit_code: int) -> None:
    """Build a stub console exe running `body` and exiting `exit_code`."""
    source = destination.parent / (destination.stem + ".cs")
    source.write_text(STUB_CS_TEMPLATE.replace("BODY", body).replace("EXITCODE", str(exit_code)))
    subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-Command",
            f"Add-Type -Path '{source}' -OutputAssembly '{destination}' "
            "-OutputType ConsoleApplication",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )


def fake_curl(shims: Path) -> None:
    """A curl.exe shim: any fetch attempt writes the sentinel and exits 97."""
    compile_stub(shims / "curl.exe", CURL_BODY, 97)


@unittest.skipUnless(sys.platform == "win32" and POWERSHELL, "native Windows only")
class InstallBitcoindPs1Test(unittest.TestCase):
    def _run(self, prefix: Path, shims: Path, sentinel: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["BITCOIND_PREFIX"] = str(prefix)
        env["DOWNLOAD_SENTINEL"] = str(sentinel)
        env["PATH"] = str(shims) + os.pathsep + env["PATH"]
        return subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT),
                "-PrintPath",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
        )

    def _workspace(self, root: Path) -> tuple[Path, Path, Path]:
        prefix = root / "core"
        (prefix / "bin").mkdir(parents=True)
        (prefix / ".bitcoin-rs-core-tarball-sha256").write_text(PIN + "\n")
        shims = root / "shims"
        shims.mkdir()
        fake_curl(shims)
        return prefix, shims, root / "download"

    def test_cache_hit_requires_successful_version_probe(self):
        for version_exit in (0, 42):
            with self.subTest(version_exit=version_exit), tempfile.TemporaryDirectory() as temporary:
                prefix, shims, sentinel = self._workspace(Path(temporary))
                binary = prefix / "bin" / "bitcoind.exe"
                compile_stub(binary, BITCOIND_BODY, version_exit)
                result = self._run(prefix, shims, sentinel)
                if version_exit == 0:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), str(binary))
                    self.assertFalse(sentinel.exists())
                    self.assertNotIn("downloading", result.stderr)
                else:
                    self.assertEqual(result.returncode, 97, result.stderr)
                    self.assertTrue(sentinel.exists())

    def test_empty_stamp_rejects_cache(self):
        """A zero-byte stamp is a cache miss, not a crash."""
        with tempfile.TemporaryDirectory() as temporary:
            prefix, shims, sentinel = self._workspace(Path(temporary))
            (prefix / ".bitcoin-rs-core-tarball-sha256").write_text("")
            binary = prefix / "bin" / "bitcoind.exe"
            compile_stub(binary, BITCOIND_BODY, 0)
            result = self._run(prefix, shims, sentinel)
            self.assertEqual(result.returncode, 97, result.stderr)
            self.assertTrue(sentinel.exists())

    def test_unlaunchable_cached_binary_rejects_cache(self):
        """A stamped bitcoind.exe that cannot exec must be replaced, not fatal."""
        with tempfile.TemporaryDirectory() as temporary:
            prefix, shims, sentinel = self._workspace(Path(temporary))
            binary = prefix / "bin" / "bitcoind.exe"
            binary.write_text("not a PE image")
            result = self._run(prefix, shims, sentinel)
            # The curl shim fails the fetch with 97 — proving the installer
            # rejected the cache and reached the download instead of aborting.
            self.assertEqual(result.returncode, 97, result.stderr)
            self.assertTrue(sentinel.exists())
            self.assertIn("reinstalling", result.stderr)


if __name__ == "__main__":
    unittest.main()
