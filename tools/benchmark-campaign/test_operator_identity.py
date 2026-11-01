# pyright: strict
"""Contract tests for the operator identity bundle collector."""

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import evidence
import filesystem
import operator_identity

BINARY_BYTES = b"fake-bitcoin-rs-benchmark-binary\n"
NODE_CONFIG_BYTES = b'<node-config validation="native"/>\n'

FAKE_CPUINFO = """processor\t: 0
vendor_id\t: GenuineTest
model name\t: Test CPU Model A
cpu MHz\t\t: 3000.000

processor\t: 1
vendor_id\t: GenuineTest
model name\t: Test CPU Model B
cpu MHz\t\t: 3000.000
"""

FAKE_MEMINFO = """MemTotal:       16051764 kB
MemFree:         1000000 kB
"""

FAKE_RUSTC_OUTPUT = """rustc 9.9.0-fake (0000000 2026-01-01)
binary: rustc
commit-hash: 0000000000000000000000000000000000000000
commit-date: 2026-01-01
host: x86_64-unknown-linux-gnu
"""

RUSTC_ON_PATH = shutil.which("rustc") is not None

REQUIRED_FLAGS = (
    ("--commit", "source_commit"),
    ("--features", "features"),
    ("--allocator", "allocator"),
    ("--validation-mode", "validation_mode"),
    ("--backend", "backend"),
    ("--batch-mode", "batch_mode"),
    ("--flush-posture", "flush_posture"),
    ("--sync-posture", "sync_posture"),
)


def _write_bytes(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    return path


def _write_text(path: Path, payload: str) -> Path:
    path.write_text(payload, encoding="utf-8")
    return path


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"expected a JSON object, got {type(value).__name__}")
    return value




def _first_cpu_model(cpuinfo_text: str) -> str:
    match = re.search(r"^model name\s*:\s+(.+)$", cpuinfo_text, re.MULTILINE)
    if match is None:
        raise RuntimeError("no model name in cpuinfo text")
    return match.group(1).strip()


def _cpu_models(cpuinfo_text: str) -> list[str]:
    found = re.findall(r"^model name\s*:\s+(.+)$", cpuinfo_text, re.MULTILINE)
    return sorted({model.strip() for model in found})


def _online_cpus(cpuinfo_text: str) -> list[int]:
    found = re.findall(r"^processor\s*:\s+(\d+)$", cpuinfo_text, re.MULTILINE)
    return sorted({int(cpu) for cpu in found})


def _mem_total_bytes(meminfo_text: str) -> int:
    match = re.search(r"^MemTotal:\s+(\d+)\s*kB", meminfo_text, re.MULTILINE)
    if match is None:
        raise RuntimeError("no MemTotal in meminfo text")
    return int(match.group(1)) * 1024


def _kernel_identity() -> dict[str, object]:
    name = os.uname()
    return {
        "sysname": name.sysname,
        "release": name.release,
        "version": name.version,
        "machine": name.machine,
    }


class HostFixture:
    """Temp-dir stand-in for /proc, /sys, rustc, and the campaign run dir."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.run_dir = root / "run"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.binary = _write_bytes(root / "binary", BINARY_BYTES)
        self.cpuinfo = _write_text(root / "cpuinfo", FAKE_CPUINFO)
        self.meminfo = _write_text(root / "meminfo", FAKE_MEMINFO)
        self.sys_base = root / "sys"
        governor = self.sys_base / "cpu0" / "cpufreq" / "scaling_governor"
        governor.parent.mkdir(parents=True, exist_ok=True)
        governor.write_text("performance\n", encoding="utf-8")
        self.broken_rustc = self._rustc_stub("broken-rustc", "#!/bin/sh\nexit 3\n")
        output = FAKE_RUSTC_OUTPUT.replace("\n", "\\n")
        self.rustc = self._rustc_stub(
            "fake-rustc", f"#!/bin/sh\nprintf '%b' '{output}'\n"
        )

    def _rustc_stub(self, name: str, script: str) -> Path:
        path = _write_text(self.root / name, script)
        path.chmod(0o755)
        return path

    def base_request(self) -> operator_identity.CaptureRequest:
        return operator_identity.CaptureRequest(
            run_dir=self.run_dir,
            binary=self.binary,
            commit="8b30c506a",
            features="native-validation",
            allocator="mimalloc",
            validation_mode="native",
            backend="fjall",
            batch_mode="write_durable",
            flush_posture="per_block",
            sync_posture="fsync_on_commit",
        )

    def capture(
        self,
        request: operator_identity.CaptureRequest | None = None,
        *,
        cpuinfo_path: Path | None = None,
        meminfo_path: Path | None = None,
        rustc_command: str | None = None,
    ) -> evidence.JsonObject:
        return operator_identity.capture_bundle(
            request if request is not None else self.base_request(),
            cpuinfo_path=cpuinfo_path if cpuinfo_path is not None else self.cpuinfo,
            meminfo_path=meminfo_path if meminfo_path is not None else self.meminfo,
            sys_base=self.sys_base,
            rustc_command=(
                rustc_command if rustc_command is not None else str(self.rustc)
            ),
        )


def _capture_argv(tmp: Path, output: Path) -> list[str]:
    run_dir = tmp / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    binary = _write_bytes(tmp / "binary", BINARY_BYTES)
    return [
        "capture",
        "--run-dir",
        str(run_dir),
        "--binary",
        str(binary),
        "--output",
        str(output),
        "--commit",
        "8b30c506a",
        "--features",
        "native-validation",
        "--allocator",
        "mimalloc",
        "--validation-mode",
        "native",
        "--backend",
        "fjall",
        "--batch-mode",
        "write_durable",
        "--flush-posture",
        "per_block",
        "--sync-posture",
        "fsync_on_commit",
    ]


def _run_main(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = operator_identity.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class CaptureBundleTests(unittest.TestCase):
    def test_bundle_records_supplied_values_and_host_sources(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            node_config = _write_bytes(host.root / "node-config", NODE_CONFIG_BYTES)
            request = dataclasses.replace(host.base_request(), node_config=node_config)
            bundle = host.capture(request)
            expected_storage = filesystem.identify_scope(host.run_dir)[1]
            expected_binary_path = str(host.binary.resolve())

        self.assertEqual(bundle["schema"], operator_identity.SCHEMA)
        artifact = _mapping(bundle["artifact"])
        self.assertEqual(
            artifact["binary_sha256"], hashlib.sha256(BINARY_BYTES).hexdigest()
        )
        self.assertEqual(artifact["binary_size_bytes"], len(BINARY_BYTES))
        self.assertEqual(artifact["binary_path"], expected_binary_path)
        self.assertEqual(artifact["source_commit"], "8b30c506a")
        self.assertEqual(
            _mapping(bundle["configuration"]),
            {
                "features": "native-validation",
                "allocator": "mimalloc",
                "validation_mode": "native",
                "node_config_path": str(node_config.resolve()),
                "node_config_sha256": hashlib.sha256(NODE_CONFIG_BYTES).hexdigest(),
            },
        )
        self.assertEqual(
            _mapping(bundle["durability"]),
            {
                "backend": "fjall",
                "batch_mode": "write_durable",
                "flush_posture": "per_block",
                "sync_posture": "fsync_on_commit",
            },
        )
        self.assertEqual(
            _mapping(bundle["toolchain"]),
            {"rustc_version_verbose": FAKE_RUSTC_OUTPUT.rstrip("\n")},
        )
        hardware = _mapping(bundle["hardware"])
        self.assertEqual(hardware["cpu_model"], "Test CPU Model A")
        self.assertEqual(
            hardware["cpu_models"], ["Test CPU Model A", "Test CPU Model B"]
        )
        self.assertEqual(hardware["cpus_online"], [0, 1])
        self.assertEqual(hardware["memory_total_bytes"], 16051764 * 1024)
        self.assertEqual(hardware["kernel"], _kernel_identity())
        pinned = sorted(os.sched_getaffinity(0))
        self.assertEqual(hardware["cpus_pinned"], pinned)
        self.assertEqual(
            hardware["cpufreq_governors"],
            {"cpu0": "performance"} if 0 in pinned else {},
        )
        self.assertEqual(bundle["storage"], expected_storage)

    def test_bundle_digest_covers_the_payload(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            bundle = host.capture()
        payload = {
            key: value for key, value in bundle.items() if key != "bundle_sha256"
        }
        self.assertEqual(bundle["bundle_sha256"], evidence.canonical_sha256(payload))

    def test_node_config_is_absent_when_not_given(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            bundle = host.capture()
        self.assertEqual(
            set(_mapping(bundle["configuration"])),
            {"features", "allocator", "validation_mode"},
        )

    def test_each_missing_required_value_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            base = host.base_request()
            cases = (
                ("source_commit", dataclasses.replace(base, commit=None)),
                ("features", dataclasses.replace(base, features=None)),
                ("allocator", dataclasses.replace(base, allocator=None)),
                ("validation_mode", dataclasses.replace(base, validation_mode=None)),
                ("backend", dataclasses.replace(base, backend=None)),
                ("batch_mode", dataclasses.replace(base, batch_mode=None)),
                ("flush_posture", dataclasses.replace(base, flush_posture=None)),
                ("sync_posture", dataclasses.replace(base, sync_posture=None)),
            )
            for identity, request in cases:
                with self.subTest(identity=identity):
                    try:
                        host.capture(request)
                    except operator_identity.BlockedIdentity as error:
                        self.assertEqual(
                            [name for name, _ in error.blocked], [identity]
                        )
                        self.assertIsNone(error.blocked[0][1])
                    else:
                        self.fail(f"capture accepted a missing {identity}")

    def test_refused_commit_values_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            base = host.base_request()
            for commit in ("8b30c506a-dirty", "ABC1234", "8b30c5", "z1234567", ""):
                with self.subTest(commit=commit):
                    request = dataclasses.replace(base, commit=commit)
                    try:
                        host.capture(request)
                    except operator_identity.BlockedIdentity as error:
                        self.assertEqual(
                            [name for name, _ in error.blocked], ["source_commit"]
                        )
                    else:
                        self.fail(f"capture accepted commit {commit!r}")

    def test_refused_batch_mode_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            request = dataclasses.replace(host.base_request(), batch_mode="write_back")
            try:
                host.capture(request)
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["batch_mode"])
                reason = error.blocked[0][1]
                self.assertIsNotNone(reason)
                self.assertIn("write_deferred", reason if reason is not None else "")
            else:
                self.fail("capture accepted an unknown batch mode")

    def test_unreadable_binary_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            request = dataclasses.replace(host.base_request(), binary=host.root / "gone")
            try:
                host.capture(request)
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["binary"])
                self.assertIn(
                    "cannot stat",
                    error.blocked[0][1] if error.blocked[0][1] is not None else "",
                )
            else:
                self.fail("capture accepted a missing binary")

    def test_unreadable_node_config_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            request = dataclasses.replace(
                host.base_request(), node_config=host.root / "gone-config"
            )
            try:
                host.capture(request)
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["node_config"])
            else:
                self.fail("capture accepted a missing NodeConfig")

    def test_missing_cpuinfo_blocks_hardware(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            try:
                host.capture(cpuinfo_path=host.root / "gone-cpuinfo")
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["hardware"])
                self.assertIn(
                    "cannot read",
                    error.blocked[0][1] if error.blocked[0][1] is not None else "",
                )
            else:
                self.fail("capture accepted a missing cpuinfo source")

    def test_cpuinfo_without_model_name_blocks_hardware(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            cpuinfo = _write_text(
                host.root / "cpuinfo-no-model",
                "processor\t: 0\nvendor_id\t: GenuineTest\n",
            )
            try:
                host.capture(cpuinfo_path=cpuinfo)
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["hardware"])
                self.assertIn(
                    "no processor model name",
                    error.blocked[0][1] if error.blocked[0][1] is not None else "",
                )
            else:
                self.fail("capture accepted cpuinfo without a model name")

    def test_meminfo_without_total_blocks_hardware(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            meminfo = _write_text(host.root / "meminfo-no-total", "MemFree: 1 kB\n")
            try:
                host.capture(meminfo_path=meminfo)
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["hardware"])
                self.assertIn(
                    "MemTotal",
                    error.blocked[0][1] if error.blocked[0][1] is not None else "",
                )
            else:
                self.fail("capture accepted meminfo without MemTotal")

    def test_missing_rustc_blocks_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            try:
                host.capture(rustc_command=str(host.root / "no-such-rustc"))
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["toolchain"])
                self.assertIn(
                    "no-such-rustc",
                    error.blocked[0][1] if error.blocked[0][1] is not None else "",
                )
            else:
                self.fail("capture accepted a missing rustc")

    def test_failing_rustc_blocks_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            host = HostFixture(Path(raw))
            try:
                host.capture(rustc_command=str(host.broken_rustc))
            except operator_identity.BlockedIdentity as error:
                self.assertEqual([name for name, _ in error.blocked], ["toolchain"])
                self.assertIn(
                    "exit 3",
                    error.blocked[0][1] if error.blocked[0][1] is not None else "",
                )
            else:
                self.fail("capture accepted a failing rustc")


class CaptureCliTests(unittest.TestCase):
    @unittest.skipIf(not RUSTC_ON_PATH, "rustc is not on PATH")
    def test_capture_writes_bundle_with_live_host_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            output = tmp / "operator-identity.json"
            argv = _capture_argv(tmp, output)
            code, stdout, stderr = _run_main(argv)
            self.assertEqual(code, 0, stderr)
            self.assertIn("bundle_sha256=", stdout)
            bundle = _mapping(json.loads(output.read_text(encoding="utf-8")))
            run_dir = tmp / "run"

            self.assertEqual(
                bundle["bundle_sha256"],
                evidence.canonical_sha256(
                    {
                        key: value
                        for key, value in bundle.items()
                        if key != "bundle_sha256"
                    }
                ),
            )
            artifact = _mapping(bundle["artifact"])
            self.assertEqual(
                artifact["binary_sha256"], hashlib.sha256(BINARY_BYTES).hexdigest()
            )
            cpuinfo_text = Path("/proc/cpuinfo").read_text(encoding="utf-8")
            hardware = _mapping(bundle["hardware"])
            self.assertEqual(hardware["cpu_model"], _first_cpu_model(cpuinfo_text))
            self.assertEqual(hardware["cpu_models"], _cpu_models(cpuinfo_text))
            self.assertEqual(hardware["cpus_online"], _online_cpus(cpuinfo_text))
            self.assertEqual(
                hardware["cpus_pinned"], sorted(os.sched_getaffinity(0))
            )
            self.assertEqual(
                hardware["memory_total_bytes"],
                _mem_total_bytes(Path("/proc/meminfo").read_text(encoding="utf-8")),
            )
            self.assertEqual(hardware["kernel"], _kernel_identity())
            self.assertEqual(
                bundle["storage"], filesystem.identify_scope(run_dir)[1]
            )
            expected_rustc = subprocess.run(
                ["rustc", "--version", "--verbose"],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            ).stdout.strip()
            self.assertEqual(
                _mapping(bundle["toolchain"]),
                {"rustc_version_verbose": expected_rustc},
            )

    def test_each_missing_flag_is_blocked_and_writes_nothing(self) -> None:
        for flag, identity in REQUIRED_FLAGS:
            with self.subTest(flag=flag):
                with tempfile.TemporaryDirectory() as raw:
                    tmp = Path(raw)
                    output = tmp / "operator-identity.json"
                    argv = _capture_argv(tmp, output)
                    position = argv.index(flag)
                    del argv[position : position + 2]
                    code, _, stderr = _run_main(argv)
                    self.assertEqual(code, 2)
                    self.assertIn(f"BLOCKED: {identity}", stderr)
                    self.assertFalse(output.exists())

    def test_dirty_commit_is_blocked_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            output = tmp / "operator-identity.json"
            argv = _capture_argv(tmp, output)
            commit = argv.index("--commit")
            argv[commit + 1] = "8b30c506a-dirty"
            code, _, stderr = _run_main(argv)
            self.assertEqual(code, 2)
            self.assertIn("BLOCKED: source_commit:", stderr)
            self.assertFalse(output.exists())

    def test_missing_binary_is_blocked_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            output = tmp / "operator-identity.json"
            argv = _capture_argv(tmp, output)
            binary = argv.index("--binary")
            argv[binary + 1] = str(tmp / "no-binary")
            code, _, stderr = _run_main(argv)
            self.assertEqual(code, 2)
            self.assertIn("BLOCKED: binary", stderr)
            self.assertFalse(output.exists())

    def test_missing_node_config_is_blocked_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            output = tmp / "operator-identity.json"
            argv = _capture_argv(tmp, output)
            argv.extend(["--node-config", str(tmp / "no-config")])
            code, _, stderr = _run_main(argv)
            self.assertEqual(code, 2)
            self.assertIn("BLOCKED: node_config", stderr)
            self.assertFalse(output.exists())

    @unittest.skipIf(not RUSTC_ON_PATH, "rustc is not on PATH")
    def test_existing_output_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            output = tmp / "operator-identity.json"
            argv = _capture_argv(tmp, output)
            first, _, first_stderr = _run_main(argv)
            self.assertEqual(first, 0, first_stderr)
            published = output.read_bytes()
            second, _, second_stderr = _run_main(argv)
            self.assertEqual(second, 1)
            self.assertIn("already exists", second_stderr)
            self.assertEqual(output.read_bytes(), published)

    def test_invalid_batch_mode_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            output = tmp / "operator-identity.json"
            argv = _capture_argv(tmp, output)
            batch = argv.index("--batch-mode")
            argv[batch + 1] = "write_back"
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    operator_identity.main(argv)
            except SystemExit as error:
                self.assertEqual(error.code, 2)
            else:
                self.fail("invalid batch mode was accepted")
            self.assertFalse(output.exists())


class VerifyTests(unittest.TestCase):
    def _publish(self, root: Path) -> tuple[Path, Path]:
        host = HostFixture(root)
        bundle = host.capture()
        path = root / "operator-identity.json"
        evidence._publish_result(bundle, path)
        return path, host.binary

    def test_verify_accepts_matching_bundle_and_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle_path, binary = self._publish(Path(raw))
            code, stdout, stderr = _run_main(
                ["verify", "--bundle", str(bundle_path), "--binary", str(binary)]
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(stdout.startswith("VALID bundle_sha256="))

    def test_verify_rejects_a_mutated_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle_path, binary = self._publish(Path(raw))
            _write_bytes(binary, b"replaced-after-capture\n")
            code, _, stderr = _run_main(
                ["verify", "--bundle", str(bundle_path), "--binary", str(binary)]
            )
            self.assertEqual(code, 1)
            self.assertIn("binary hash mismatch", stderr)

    def test_verify_rejects_tampered_payload(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle_path, binary = self._publish(Path(raw))
            bundle = _mapping(json.loads(bundle_path.read_text(encoding="utf-8")))
            _mapping(bundle["configuration"])["allocator"] = "system"
            _write_text(bundle_path, json.dumps(bundle))
            code, _, stderr = _run_main(
                ["verify", "--bundle", str(bundle_path), "--binary", str(binary)]
            )
            self.assertEqual(code, 1)
            self.assertIn("bundle digest mismatch", stderr)

    def test_verify_rejects_a_wrong_schema_even_with_a_matching_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle_path, binary = self._publish(Path(raw))
            bundle = _mapping(json.loads(bundle_path.read_text(encoding="utf-8")))
            bundle["schema"] = "other-schema-v9"
            payload = {
                key: value for key, value in bundle.items() if key != "bundle_sha256"
            }
            bundle["bundle_sha256"] = evidence.canonical_sha256(payload)
            _write_text(bundle_path, json.dumps(bundle))
            code, _, stderr = _run_main(
                ["verify", "--bundle", str(bundle_path), "--binary", str(binary)]
            )
            self.assertEqual(code, 1)
            self.assertIn("bundle schema must be", stderr)

    def test_verify_rejects_a_corrupt_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            bundle_path = _write_text(root / "operator-identity.json", "not-json\n")
            binary = _write_bytes(root / "binary", BINARY_BYTES)
            code, _, stderr = _run_main(
                ["verify", "--bundle", str(bundle_path), "--binary", str(binary)]
            )
            self.assertEqual(code, 1)
            self.assertIn("cannot read bundle", stderr)

    def test_verify_rejects_a_missing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle_path, _ = self._publish(Path(raw))
            code, _, stderr = _run_main(
                [
                    "verify",
                    "--bundle",
                    str(bundle_path),
                    "--binary",
                    str(Path(raw) / "no-binary"),
                ]
            )
            self.assertEqual(code, 1)
            self.assertIn("cannot hash binary", stderr)


if __name__ == "__main__":
    unittest.main()
