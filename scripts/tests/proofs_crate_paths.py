"""Manual real-tool regression: python3 scripts/tests/proofs_crate_paths.py --verbose."""

import os
import re
import shutil
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
TIMEOUT_SECONDS = 300


def run_proofs(root: Path, environment: dict[str, str]) -> tuple[int, str]:
    process = subprocess.Popen(
        ["bash", "scripts/ci-pr.sh", "proofs"],
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        return -signal.SIGKILL, f"proofs exceeded {TIMEOUT_SECONDS}s\n{output}"
    return process.returncode, output


class ProofsCratePathsTest(unittest.TestCase):
    def test_storage_directory_spellings(self) -> None:
        for tool in ("bash", "cargo", "cargo-kani", "lake", "rg"):
            self.assertIsNotNone(
                shutil.which(tool), f"Required real tool missing: {tool}"
            )
        environment = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME", "ELAN_HOME")
            if key in os.environ
        }
        environment.update(
            CARGO_NET_OFFLINE="true",
            CARGO_TERM_COLOR="never",
            PROOFS_JOBS="1",
            PROOFS_VERBOSE="1",
            PROOFS_EXTRACT_LEAN_CMD="/usr/bin/true",
        )
        with tempfile.TemporaryDirectory(prefix="proofs-crate-paths-") as temporary:
            root = Path(temporary)
            files = {
                "Cargo.toml": '[workspace]\nmembers = ["crates/storage"]\nresolver = "2"\n',
                "crates/storage/Cargo.toml": (
                    '[package]\nname = "bitcoin-rs-storage"\nversion = "0.0.0"\n'
                    'edition = "2021"\nautotests = false\n'
                    "[features]\ndefault = []\nmdbx = []\n"
                    '[[test]]\nname = "mdbx_bounded_read_allocation"\n'
                    'path = "tests/mdbx_bounded_read_allocation.rs"\n'
                    'required-features = ["mdbx"]\n'
                ),
                "crates/storage/src/lib.rs": (
                    "pub fn bounded_read(requested: u8, available: u8) -> u8 {\n"
                    "    requested.min(available)\n}\n"
                    "#[cfg(kani)]\nmod proofs {\n"
                    "    #[kani::proof]\n    fn read_never_exceeds_available() {\n"
                    "        let requested: u8 = kani::any();\n"
                    "        let available: u8 = kani::any();\n"
                    "        assert!(super::bounded_read(requested, available) <= available);\n"
                    "    }\n}\n"
                ),
                "crates/storage/tests/mdbx_bounded_read_allocation.rs": (
                    "#[cfg(kani)]\n#[kani::proof]\n"
                    "fn read_never_exceeds_request() {\n"
                    "    let requested: u8 = kani::any();\n"
                    "    let available: u8 = kani::any();\n"
                    "    assert!(bitcoin_rs_storage::bounded_read(requested, available) <= requested);\n"
                    "}\n"
                ),
                "docs/lean/lakefile.toml": (
                    'name = "path_probe"\ndefaultTargets = ["Probe"]\n'
                    '[[lean_lib]]\nname = "Probe"\n'
                ),
                "docs/lean/Probe.lean": "theorem probe_identity (n : Nat) : n = n := rfl\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            (root / "scripts").mkdir()
            for name in ("ci-pr.sh", "extract_lean.sh"):
                shutil.copy2(SCRIPTS / name, root / "scripts" / name)
            shutil.copy2(
                SCRIPTS.parent / "docs/lean/lean-toolchain",
                root / "docs/lean/lean-toolchain",
            )
            storage = root / "crates/storage"
            (root / "storage-link").symlink_to(storage, target_is_directory=True)
            spellings = (
                "crates/storage",
                "./crates/storage",
                "crates/storage/",
                "crates/../crates/storage",
                str(storage),
                "storage-link",
            )
            for spelling in spellings:
                with self.subTest(crate=spelling):
                    environment["PROOFS_CRATES"] = spelling
                    shutil.rmtree(root / "target/proofs-logs", ignore_errors=True)
                    status, output = run_proofs(root, environment)
                    logs = "\n".join(
                        f"--- {path.name} ---\n{path.read_text(encoding='utf-8')}"
                        for path in sorted((root / "target/proofs-logs").glob("*.log"))
                    )
                    diagnostics = (
                        f"PROOFS_CRATES={spelling!r}; exit={status}\n{output}\n{logs}"
                    )
                    print(f"\n=== {diagnostics}", flush=True)
                    self.assertEqual(status, 0, diagnostics)
                    counts = re.findall(
                        r"Complete - (\d+) successfully verified harnesses", output
                    )
                    self.assertGreaterEqual(
                        sum(map(int, counts)),
                        2,
                        "Both library and feature-required integration harnesses must verify\n"
                        + diagnostics,
                    )

            environment["PROOFS_CRATES"] = "crates/storage crates/nested/gone"
            shutil.rmtree(root / "target/proofs-logs", ignore_errors=True)
            status, output = run_proofs(root, environment)
            logs = "\n".join(
                f"--- {path.name} ---\n{path.read_text(encoding='utf-8')}"
                for path in sorted((root / "target/proofs-logs").glob("*.log"))
            )
            diagnostics = (
                f"PROOFS_CRATES={environment['PROOFS_CRATES']!r}; exit={status}\n"
                f"{output}\n{logs}"
            )
            print(f"\n=== {diagnostics}", flush=True)
            self.assertNotEqual(status, 0, diagnostics)
            self.assertIn("==> FAILED: kani: crates/nested/gone", output)
            self.assertIn("==> ok: kani: crates/storage", output)
            self.assertIn("==> ok: lean: pipeline", output)


if __name__ == "__main__":
    unittest.main()
