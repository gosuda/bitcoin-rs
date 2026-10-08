"""The feature gate must select its root workspace from any in-repo directory."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-feature-matrix.sh"


class FeatureMatrixTest(unittest.TestCase):
    def test_nested_workspace_does_not_replace_matrix_workspace(self):
        cargo = shutil.which("cargo")
        self.assertIsNotNone(cargo, "Cargo is required to resolve real workspaces")
        with tempfile.TemporaryDirectory(prefix="feature matrix ") as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = []\n')
            nested = root / "fuzz"
            nested.mkdir()
            (nested / "Cargo.toml").write_text('[workspace]\nmembers = []\n')
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copy2(SCRIPT, scripts / SCRIPT.name)
            (scripts / "feature-matrix.tsv").write_text(
                "root\troot-package\tpure\t--no-default-features\n"
            )
            shims = root / "bin"
            shims.mkdir()
            # Run Cargo's actual workspace resolver, not a fake cwd assertion.
            # No compilation or dependency resolution is needed for this boundary.
            shim = shims / "cargo"
            shim.write_text(
                f"#!{sys.executable}\n"
                "import os, subprocess, sys\n"
                "result = subprocess.run([os.environ['REAL_CARGO'], 'locate-project', "
                "'--workspace', '--message-format', 'plain'], capture_output=True, text=True)\n"
                "sys.stdout.write(result.stdout)\n"
                "sys.stderr.write(result.stderr)\n"
                "sys.exit(result.returncode or "
                "(0 if result.stdout.strip() == os.environ['EXPECTED_MANIFEST'] else 86))\n"
            )
            shim.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": str(shims) + os.pathsep + os.environ["PATH"],
                "REAL_CARGO": cargo,
                "EXPECTED_MANIFEST": str((root / "Cargo.toml").resolve()),
            }
            for cwd in (root, nested):
                with self.subTest(cwd=cwd.name):
                    result = subprocess.run(
                        ["bash", str(scripts / SCRIPT.name), "pure"],
                        cwd=cwd,
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=20,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
