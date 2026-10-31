"""Offline tests of formal evidence custody, bounds and failure handling, not model proofs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_models

MODULES = (("PeerLeases", "Session"), ("ChainAdmission", "Commit"))


class ModelEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        rows: list[str] = []
        for owner, machine in MODULES:
            directory = self.root / "docs/models" / owner
            directory.mkdir(parents=True, exist_ok=True)
            tla = directory / f"{machine}.tla"
            tla.write_text("fixture\n", encoding="utf-8")
            cfg = directory / f"{machine}.cfg"
            cfg.write_text("CONSTANTS\nN = 1\nINIT Init\nNEXT Next\n", encoding="utf-8")
            rows.append(
                f"| {owner}/{machine} | {hashlib.sha256(tla.read_bytes()).hexdigest()} "
                f"| {hashlib.sha256(cfg.read_bytes()).hexdigest()} | N=1 | 128 | BLOCKED | - | - |"
            )
        contract = self.root / check_models.FORMAL_CONTRACT
        contract.parent.mkdir(parents=True, exist_ok=True)
        contract.write_text("\n".join(rows), encoding="utf-8")
        self.home = self.root / "tool"
        (self.home / "bin").mkdir(parents=True)
        (self.home / "lib").mkdir()
        jar = self.home / "lib/apalache.jar"
        jar.write_bytes(b"synthetic tool, not a prover")
        archive = self.home / "apalache-0.62.4.zip"
        archive.write_bytes(b"synthetic archive, not the prover")
        api = self.root / "crates/rpc"
        api.mkdir(parents=True)
        (api / "core-compat.toml").write_text(
            '[reference.formal_tool]\nname = "apalache-mc"\nversion = "0.62.4"\n'
            f'archive_sha256 = "{hashlib.sha256(archive.read_bytes()).hexdigest()}"\n'
            f'jar_sha256 = "{hashlib.sha256(jar.read_bytes()).hexdigest()}"\n',
            encoding="utf-8",
        )
        self.executable = self.home / "bin/apalache-mc"
        self.write_tool('print("The outcome is: NoError\\nEXITCODE: OK")')

    def write_tool(self, body: str, version: str = "0.62.4") -> None:
        self.executable.write_text(
            f"#!{sys.executable}\nimport sys, time\n"
            f"if sys.argv[1] == 'version':\n    print({version!r})\n    sys.exit(0)\n{body}\n",
            encoding="utf-8",
        )
        self.executable.chmod(0o755)

    def module(self, index: int = 0) -> check_models.Module:
        return check_models.modules(self.root)[index]

    def run_check(self, timeout: int = 5) -> dict:
        return check_models.run_module(
            self.root, self.executable, self.module(), check_models.PROPERTIES[0], timeout
        )

    def results(self) -> list[dict]:
        return [
            json.loads(path.read_text())
            for path in sorted(self.root.glob("target/apalache/**/result.json"))
        ]

    def newest_result(self) -> dict:
        results = sorted(self.root.glob("target/apalache/**/result.json"),
                         key=lambda path: path.stat().st_mtime)
        self.assertTrue(results, "no result.json recorded")
        return json.loads(results[-1].read_text())

    def test_inventory_keys_on_owner_and_machine(self) -> None:
        inventory = check_models.modules(self.root)
        self.assertEqual([module.name for module in inventory],
                         ["ChainAdmission/Commit", "PeerLeases/Session"])
        self.assertEqual(self.module(1).source(self.root).name, "Session.tla")

    def test_input_custody_rejects_changed_missing_and_extra_models(self) -> None:
        (self.root / "docs/models/PeerLeases/Session.tla").write_text("changed", encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.modules(self.root)
        self.assertEqual(error.exception.code, 15)
        (self.root / "docs/models/PeerLeases/Session.tla").unlink()
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.modules(self.root)
        self.assertEqual(error.exception.code, 15)
        (self.root / "docs/models/PeerLeases/Session.tla").write_text("fixture\n", encoding="utf-8")
        (self.root / "docs/models/PeerLeases/Lease.tla").write_text("extra\n", encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.modules(self.root)
        self.assertEqual(error.exception.code, 15)
        self.assertEqual(str(error.exception).startswith("module inventory differs"), True)

    def test_tool_custody_rejects_wrong_version_and_jar(self) -> None:
        with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
            self.assertEqual(check_models.tool(self.root), self.executable)
            self.write_tool("", version="0.62.40")
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
            self.assertEqual(error.exception.code, 11)
            self.write_tool("")
            (self.home / "apalache-0.62.4.zip").write_bytes(b"different")
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
            self.assertEqual(error.exception.code, 11)
            self.assertEqual("archive" in str(error.exception), True)
            (self.home / "apalache-0.62.4.zip").write_bytes(b"synthetic archive, not the prover")
            (self.home / "lib/apalache.jar").write_bytes(b"different")
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
            self.assertEqual(error.exception.code, 11)
            self.assertEqual("JAR" in str(error.exception), True)

    def test_provisioned_download_archive_satisfies_custody(self) -> None:
        # The CI provisioner keeps the archive under target/ci-reference-downloads
        # and extracts it into the install root, so the archive check reads both.
        (self.home / "apalache-0.62.4.zip").unlink()
        downloads = self.root / "target/ci-reference-downloads"
        downloads.mkdir(parents=True)
        (downloads / "apalache-0.62.4.zip").write_bytes(b"synthetic archive, not the prover")
        with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
            self.assertEqual(check_models.tool(self.root), self.executable)

    def test_empty_apalache_home_uses_default_location(self) -> None:
        default = (self.root / "target/tools" / "apalache-0.62.4" / "bin"
                   / "apalache-mc").resolve()
        with patch.dict(os.environ, {"APALACHE_HOME": ""}):
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
        self.assertEqual(error.exception.code, 11)
        self.assertEqual(str(error.exception), f"missing executable: {default}")

    def test_missing_model_file_is_a_model_identity_failure(self) -> None:
        (self.root / "docs/models/PeerLeases/Session.tla").unlink()
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 15)

    def test_missing_jar_is_a_tool_identity_failure(self) -> None:
        (self.home / "lib/apalache.jar").unlink()
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 11)

    def test_malformed_tool_pin_missing_version_is_a_tool_identity_failure(self) -> None:
        pin = self.root / "crates/rpc/core-compat.toml"
        text = pin.read_text(encoding="utf-8")
        pin.write_text(text.replace('version = "0.62.4"\n', ""), encoding="utf-8")
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 11)

    def test_deleted_contract_is_an_inventory_identity_failure(self) -> None:
        (self.root / check_models.FORMAL_CONTRACT).unlink()
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 15)

    def test_check_only_confirms_identity_without_running_properties(self) -> None:
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 0)
        self.assertEqual(self.results(), [])

    def test_unknown_module_name_is_a_model_identity_failure(self) -> None:
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only",
                                            "--module", "PeerLeases/Lease"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 15)

    def test_module_filter_runs_only_the_named_module(self) -> None:
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--k-start", "4",
                                            "--module", "PeerLeases/Session"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 0)
        summary = json.loads((self.root / "target/apalache/summary.json").read_text())
        self.assertEqual(set(summary), {"PeerLeases/Session"})

    def test_temporal_lane_writes_under_temporal_directory(self) -> None:
        module = self.module()
        check_models.run_module(
            self.root, self.executable, module, check_models.PROPERTIES[1], 5
        )
        results = list(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(len(results), 1)
        record = json.loads(results[0].read_text())
        self.assertEqual(record, {"k": 128, "native_rc": 0, "evidence_rc": 0})
        self.assertTrue(results[0].with_name("identity.json").is_file())
        temporal = (self.root / "target/apalache" / module.owner / module.machine
                    / "temporal" / "k128")
        self.assertEqual(results[0].parent.parent, temporal)

    def test_inherited_smt_solver_cannot_override_the_pinned_prover(self) -> None:
        with patch.dict(os.environ, {"SMT_SOLVER": "boo"}):
            self.run_check()
        identity = json.loads(self.newest_result_file().with_name("identity.json").read_text())
        self.assertEqual(identity["solver"], "z3")

    def newest_result_file(self) -> Path:
        path = next(self.root.glob("target/apalache/**/result.json"))
        return path

    def test_complete_success_retains_identity_and_outcome(self) -> None:
        record = self.run_check()
        self.assertEqual(record["k"], 128)
        self.assertEqual(record["evidence_rc"], 0)
        results = self.results()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], {"k": 128, "native_rc": 0, "evidence_rc": 0})
        identity = json.loads(self.newest_result_file().with_name("identity.json").read_text())
        self.assertIn("--length=128", identity["argv"])
        self.assertIn("--inv=TypeOK", identity["argv"])
        self.assertEqual(identity["constants"], "N = 1")
        self.assertEqual(identity["k"], 128)

    def test_native_failures_keep_their_meaning(self) -> None:
        for native, expected in ((150, 12), (120, 12), (12, 13), (255, 14)):
            with self.subTest(native=native):
                self.write_tool(f"sys.exit({native})")
                record = self.run_check()
                self.assertEqual(record["evidence_rc"], expected)
                self.assertEqual(record["native_rc"], native)
                result = self.newest_result()
                self.assertEqual(result["native_rc"], native)
                self.assertEqual(result["evidence_rc"], expected)

    def test_zero_exit_without_complete_outcome_is_not_a_proof(self) -> None:
        for text in ("", "The outcome is: NoError", "EXITCODE: OK"):
            with self.subTest(text=text):
                self.write_tool(f"print({text!r})")
                record = self.run_check()
                self.assertEqual(record["evidence_rc"], 14)
                self.assertEqual(self.newest_result()["evidence_rc"], 14)

    def test_resource_exhaustion_halves_the_bound_and_records_the_largest_completed(self) -> None:
        body = (
            "import sys\n"
            "length = [arg for arg in sys.argv if arg.startswith('--length=')][0]\n"
            "bound = int(length.split('=')[1])\n"
            "if bound > 16:\n    sys.exit(255)\n"
            "print('The outcome is: NoError\\nEXITCODE: OK')\n"
        )
        self.write_tool(body)
        record = self.run_check()
        self.assertEqual(record["k"], 16)
        self.assertEqual(record["evidence_rc"], 0)
        bounds = sorted(result["k"] for result in self.results())
        self.assertEqual(bounds, [16, 32, 64, 128])

    def test_halving_stops_at_one_and_reports_the_resource_code(self) -> None:
        self.write_tool("sys.exit(255)")
        record = check_models.run_module(
            self.root, self.executable, self.module(), check_models.PROPERTIES[0], 5
        )
        self.assertEqual(record["k"], 1)
        self.assertEqual(record["evidence_rc"], 14)

    def test_summary_records_bound_and_return_codes(self) -> None:
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--k-start", "8"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 0)
        summary = json.loads((self.root / "target/apalache/summary.json").read_text())
        self.assertEqual(set(summary), {"ChainAdmission/Commit", "PeerLeases/Session"})
        for lanes in summary.values():
            for kind in ("safety", "temporal"):
                self.assertEqual(lanes[kind]["k"], 8)
                self.assertEqual(lanes[kind]["evidence_rc"], 0)

    def test_timeout_kills_the_whole_tool_session(self) -> None:
        body = (
            "import os, subprocess, sys\n"
            "if sys.argv[1] == 'check':\n"
            "    child = subprocess.Popen(['sleep', '300'], start_new_session=False)\n"
            "    with open('descendant.pid', 'w') as sink:\n"
            "        sink.write(str(child.pid))\n"
            "    os.wait()\n"
        )
        self.write_tool(body)
        record = self.run_check(timeout=1)
        self.assertEqual(record["evidence_rc"], 14)
        pid_file = next(self.root.glob("target/apalache/**/descendant.pid"))
        descendant = int(pid_file.read_text())
        try:
            stat = Path(f"/proc/{descendant}/stat").read_text(encoding="ascii")
        except (ProcessLookupError, FileNotFoundError):
            stat = None
        if stat is not None:
            state = stat[stat.rfind(")") + 1:].split(maxsplit=1)[0]
            self.assertEqual(state, "Z")
        result = next(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(json.loads(result.read_text()),
                         {"k": 128, "native_rc": None, "evidence_rc": 14})

    def test_parallel_execution_preserves_summary_order_and_worst_code_selection(self) -> None:
        expected_summary = {
            "ChainAdmission/Commit": {
                "safety": {"k": 8, "native_rc": 0, "evidence_rc": 0, "run": "run-1"},
                "temporal": {"k": 8, "native_rc": 150, "evidence_rc": 12, "run": "run-2"},
            },
            "PeerLeases/Session": {
                "safety": {"k": 8, "native_rc": 0, "evidence_rc": 0, "run": "run-3"},
                "temporal": {"k": 8, "native_rc": 0, "evidence_rc": 0, "run": "run-4"},
            },
        }

        def fake_run_module(root, executable, module, property_arg, *args, **kwargs):
            import time
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            if module.name == "ChainAdmission/Commit" and kind == "safety":
                time.sleep(0.04)
            elif module.name == "PeerLeases/Session" and kind == "temporal":
                time.sleep(0.01)
            return dict(expected_summary[module.name][kind])

        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=fake_run_module),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "4", "--k-start", "8"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            rc = check_models.main()
        self.assertEqual(rc, 12)
        summary_path = self.root / "target/apalache/summary.json"
        summary_raw = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary_raw, expected_summary)
        self.assertEqual(list(summary_raw.keys()), ["ChainAdmission/Commit", "PeerLeases/Session"])
        self.assertEqual(list(summary_raw["ChainAdmission/Commit"].keys()), ["safety", "temporal"])
        self.assertEqual(list(summary_raw["PeerLeases/Session"].keys()), ["safety", "temporal"])

    def test_k_memo_used_only_when_hash_and_version_match(self) -> None:
        memo_path = self.root / "target/apalache/k-memo.json"
        memo_path.parent.mkdir(parents=True, exist_ok=True)
        commit_module = self.module(0)
        started_k: dict[str, int] = {}

        def recording_runner(root, executable, module, property_arg, timeout=3600, *args, **kwargs):
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            start = args[0] if args else kwargs.get("start", 128)
            started_k[f"{module.name}:{kind}"] = start
            return {"k": start, "native_rc": 0, "evidence_rc": 0, "run": "test"}

        memo_path.write_text(
            json.dumps({
                f"{commit_module.name}:safety": {
                    "tla_sha256": commit_module.tla_sha256,
                    "tool_version": "0.62.4",
                    "k": 16,
                }
            }) + "\n",
            encoding="utf-8",
        )
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=recording_runner),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "1"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 0)
        self.assertEqual(started_k[f"{commit_module.name}:safety"], 16)
        self.assertEqual(started_k[f"{commit_module.name}:temporal"], 128)

        started_k.clear()
        memo_path.write_text(
            json.dumps({
                f"{commit_module.name}:safety": {
                    "tla_sha256": "0" * 64,
                    "tool_version": "0.62.4",
                    "k": 16,
                }
            }) + "\n",
            encoding="utf-8",
        )
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=recording_runner),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "1"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 0)
        self.assertEqual(started_k[f"{commit_module.name}:safety"], 128)

        started_k.clear()
        memo_path.write_text(
            json.dumps({
                f"{commit_module.name}:safety": {
                    "tla_sha256": commit_module.tla_sha256,
                    "tool_version": "0.61.0",
                    "k": 16,
                }
            }) + "\n",
            encoding="utf-8",
        )
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=recording_runner),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "1"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 0)
        self.assertEqual(started_k[f"{commit_module.name}:safety"], 128)

        started_k.clear()
        memo_path.write_text(
            json.dumps({
                f"{commit_module.name}:safety": {
                    "tla_sha256": commit_module.tla_sha256,
                    "tool_version": "0.62.4",
                    "k": 16,
                }
            }) + "\n",
            encoding="utf-8",
        )
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=recording_runner),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "1", "--k-start", "32"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 0)
        self.assertEqual(started_k[f"{commit_module.name}:safety"], 32)

    def test_failing_lane_yields_nonzero_exit_when_others_pass(self) -> None:
        def mixed_runner(root, executable, module, property_arg, timeout=3600, *args, **kwargs):
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            start = args[0] if args else kwargs.get("start", 128)
            if module.name == "ChainAdmission/Commit" and kind == "temporal":
                return {"k": start, "native_rc": 255, "evidence_rc": 14, "run": "err"}
            return {"k": start, "native_rc": 0, "evidence_rc": 0, "run": "ok"}
        memo_file = self.root / "target/apalache/k-memo.json"
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=mixed_runner),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "2"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            rc = check_models.main()
        summary = json.loads((self.root / "target/apalache/summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["ChainAdmission/Commit"]["temporal"]["evidence_rc"], 14)
        self.assertEqual(summary["ChainAdmission/Commit"]["safety"]["evidence_rc"], 0)
        if memo_file.is_file():
            memo = json.loads(memo_file.read_text(encoding="utf-8"))
            self.assertNotIn("ChainAdmission/Commit:temporal", memo)

if __name__ == "__main__":
    unittest.main()
