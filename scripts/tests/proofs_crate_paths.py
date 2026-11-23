"""Manual proofs-stage regression: uv run scripts/tests/proofs_crate_paths.py --verbose."""

import os
import re
import shutil
import signal
import subprocess
import sys
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
            for key in ("PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME", "ELAN_HOME", "KANI_HOME")
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
                    'edition = "2024"\nautotests = false\n'
                    "[features]\ndefault = []\nmdbx = []\n"
                    '[[test]]\nname = "mdbx_bounded_read_allocation"\n'
                    'path = "mdbx_bounded_read_allocation_tests.rs"\n'
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
                "crates/storage/mdbx_bounded_read_allocation_tests.rs": (
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


WORKER_PROBE = r"""import argparse
import os
import sys
import time
from pathlib import Path

root = Path(os.environ["PROOFS_PROBE_ROOT"])
release = root / "release"


def run_kani() -> None:
    (root / "started" / Path.cwd().name).touch()
    deadline = time.monotonic() + 20
    while not release.exists():
        if time.monotonic() >= deadline:
            raise SystemExit("model worker probe did not release Kani")
        time.sleep(0.01)


class Arguments:
    jobs: str = ""


def run_models() -> None:
    try:
        (root / "model-arguments").write_text(
            "\n".join(sys.argv[1:]), encoding="utf-8"
        )
        parser = argparse.ArgumentParser()
        parser.add_argument("--jobs", required=True)
        arguments = Arguments()
        parser.parse_args(namespace=arguments)
        expected = os.environ["PROOFS_PROBE_JOBS"]
        if arguments.jobs != expected:
            raise SystemExit(
                f"model jobs must be canonical decimal {expected}, got {arguments.jobs}"
            )
        width = int(os.environ["PROOFS_PROBE_WIDTH"])
        deadline = time.monotonic() + 10
        while len(tuple((root / "started").iterdir())) < width:
            if time.monotonic() >= deadline:
                raise SystemExit("Kani scheduler did not reach the model worker limit")
            time.sleep(0.01)
        time.sleep(0.2)
        observed = len(tuple((root / "started").iterdir()))
        (root / "first-cohort").write_text(str(observed), encoding="utf-8")
        if observed != width:
            raise SystemExit(
                f"Kani scheduler started {observed} workers for model limit {width}"
            )
    finally:
        release.touch()


if len(sys.argv) > 1 and sys.argv[1] == "kani":
    run_kani()
else:
    run_models()
"""

class ProofsJobLimitsTest(unittest.TestCase):
    def fixture(
        self, root: Path, jobs: str, expected: int, crate_count: int
    ) -> dict[str, str]:
        for tool in ("bash", "lake", "rg"):
            self.assertIsNotNone(shutil.which(tool), f"Required real tool missing: {tool}")
        scripts = root / "scripts"
        scripts.mkdir()
        for name in ("ci-pr.sh", "extract_lean.sh"):
            shutil.copy2(SCRIPTS / name, scripts / name)
        (scripts / "check_models.py").write_text(WORKER_PROBE, encoding="utf-8")
        lean = root / "docs/lean"
        lean.mkdir(parents=True)
        (lean / "lakefile.toml").write_text(
            'name = "worker_probe"\ndefaultTargets = ["Probe"]\n'
            '[[lean_lib]]\nname = "Probe"\n',
            encoding="utf-8",
        )
        (lean / "Probe.lean").write_text(
            "theorem probe_identity (n : Nat) : n = n := rfl\n", encoding="utf-8"
        )
        shutil.copy2(SCRIPTS.parent / "docs/lean/lean-toolchain", lean / "lean-toolchain")
        probe = root / "probe"
        (probe / "started").mkdir(parents=True)
        crates = tuple(f"crates/probe-{index:02}" for index in range(crate_count))
        for crate in crates:
            (root / crate).mkdir(parents=True)
        environment = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME", "ELAN_HOME", "KANI_HOME")
            if key in os.environ
        }
        environment.update(
            CARGO_TERM_COLOR="never",
            PROOFS_JOBS=jobs,
            PROOFS_CRATES=" ".join(crates),
            PROOFS_VERBOSE="1",
            PROOFS_EXTRACT_LEAN_CMD="/usr/bin/true",
            PROOFS_KANI_CMD=f"{sys.executable} {scripts / 'check_models.py'} kani",
            PROOFS_PROBE_ROOT=str(probe),
            PROOFS_PROBE_JOBS=str(expected),
            PROOFS_PROBE_WIDTH=str(min(expected, crate_count)),
        )
        return environment

    def test_decimal_limit_reaches_both_schedulers(self) -> None:
        cases = (
            ("1", 1, 2),
            ("0002", 2, 3),
            ("08", 8, 9),
            ("010", 10, 11),
            ("9223372036854775807", 9223372036854775807, 2),
            ("00009223372036854775807", 9223372036854775807, 2),
        )
        for jobs, expected, crate_count in cases:
            with self.subTest(jobs=jobs), tempfile.TemporaryDirectory(
                prefix="proofs-job-limits-"
            ) as temporary:
                root = Path(temporary)
                environment = self.fixture(root, jobs, expected, crate_count)
                status, output = run_proofs(root, environment)
                self.assertEqual(status, 0, output)
                self.assertEqual(
                    (root / "probe/model-arguments").read_text(encoding="utf-8").splitlines(),
                    ["--jobs", str(expected)],
                )
                self.assertEqual(
                    int((root / "probe/first-cohort").read_text(encoding="utf-8")),
                    min(expected, crate_count),
                )
                self.assertEqual(len(tuple((root / "probe/started").iterdir())), crate_count)
                self.assertIn("==> ok: models: check_models", output)

    def test_invalid_limit_refuses_before_launching_proof_jobs(self) -> None:
        for jobs in (
            "",
            "0",
            "000",
            "-1",
            "+1",
            " 2",
            "2 ",
            "1.5",
            "08x",
            "1+1",
            "9223372036854775808",
            "18446744073709551616",
            "9" * 100,
        ):
            with self.subTest(jobs=jobs), tempfile.TemporaryDirectory(
                prefix="proofs-invalid-job-limit-"
            ) as temporary:
                root = Path(temporary)
                environment = self.fixture(root, jobs, 1, 2)
                status, output = run_proofs(root, environment)
                self.assertEqual(status, 2, output)
                self.assertIn("PROOFS_JOBS must be a decimal integer", output)
                self.assertEqual(tuple((root / "probe/started").iterdir()), ())
                self.assertFalse((root / "probe/model-arguments").exists())
                self.assertFalse((root / "docs/lean/.lake").exists())



if __name__ == "__main__":
    unittest.main()
