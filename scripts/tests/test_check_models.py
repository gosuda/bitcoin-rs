"""Offline tests of formal evidence custody, bounds and failure handling, not model proofs."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import signal
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_models

MODULES = (("PeerLeases", "Session", 128), ("ChainAdmission", "Commit", 16))


class ModelEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        rows: list[str] = []
        for owner, machine, floor in MODULES:
            directory = self.root / "docs/models" / owner
            directory.mkdir(parents=True, exist_ok=True)
            tla = directory / f"{machine}.tla"
            tla.write_text("fixture\n", encoding="utf-8")
            cfg = directory / f"{machine}.cfg"
            cfg.write_text("CONSTANTS\nN = 1\nINIT Init\nNEXT Next\n", encoding="utf-8")
            tla_sha = hashlib.sha256(tla.read_bytes()).hexdigest()
            cfg_sha = hashlib.sha256(cfg.read_bytes()).hexdigest()
            rows.append(
                f"| {owner}/{machine} | {tla_sha} | {cfg_sha} | N=1 | {floor} | BLOCKED | - | - | apalache |"
            )
        table_header = (
            "| module | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc | checker |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
        )
        contract = self.root / check_models.FORMAL_CONTRACT
        contract.parent.mkdir(parents=True, exist_ok=True)
        contract.write_text(f"{table_header}\n" + "\n".join(rows), encoding="utf-8")
        self.home = self.root / "tool"
        (self.home / "bin").mkdir(parents=True)
        (self.home / "lib").mkdir()
        jar = self.home / "lib/apalache.jar"
        jar.write_bytes(b"synthetic tool, not a prover")
        archive = self.home / "apalache-0.62.4.zip"
        archive.write_bytes(b"synthetic archive, not the prover")
        api = self.root / "crates/serving"
        api.mkdir(parents=True)
        (api / "core-compat.toml").write_text(
            '[reference.formal_tool]\nname = "apalache-mc"\nversion = "0.62.4"\n'
            f'archive_sha256 = "{hashlib.sha256(archive.read_bytes()).hexdigest()}"\n'
            f'jar_sha256 = "{hashlib.sha256(jar.read_bytes()).hexdigest()}"\n',
            encoding="utf-8",
        )
        self.executable = self.home / "bin/apalache-mc"
        self.toolchain = check_models.Toolchain(
            executable=self.executable,
            jar=jar,
            jar_sha256=hashlib.sha256(jar.read_bytes()).hexdigest(),
        )
        self.write_tool('print("The outcome is: NoError\\nEXITCODE: OK")')
    def write_tool(self, body: str, version: str = "0.62.4") -> None:
        self.executable.write_text(
            f"#!{sys.executable}\nimport sys, time\n"
            f"if sys.argv[1] == 'version':\n    print({version!r})\n    sys.exit(0)\n{body}\n",
            encoding="utf-8",
        )
        self.executable.chmod(0o755)
    def write_tlc_tool(self, body: str) -> Path:
        java_script = self.home / "bin/mock_java"
        java_script.write_text(
            f"#!{sys.executable}\nimport sys\n{body}\n",
            encoding="utf-8",
        )
        java_script.chmod(0o755)
        return java_script

    def module(self, index: int = 0) -> check_models.Module:
        return check_models.modules(self.root)[index]

    def run_check(self, timeout: int = 5) -> dict[str, int | str | None]:
        return check_models.run_module(
            self.root, self.toolchain, self.module(), check_models.PROPERTIES[0], timeout
        )

    def results(self) -> list[dict[str, int | str | None]]:
        return [
            json.loads(path.read_text())
            for path in sorted(self.root.glob("target/apalache/**/result.json"))
        ]

    def newest_result(self) -> dict[str, int | str | None]:
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
            self.assertEqual(check_models.tool(self.root).executable, self.executable)
            self.assertEqual(check_models.tool(self.root).jar, self.home / "lib/apalache.jar")
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
            self.assertEqual(check_models.tool(self.root).executable, self.executable)
            self.assertEqual(check_models.tool(self.root).jar, self.home / "lib/apalache.jar")

    def test_empty_apalache_home_uses_default_location(self) -> None:
        with patch.dict(os.environ, {"APALACHE_HOME": ""}), self.assertRaises(check_models.EvidenceError) as error:
            check_models.tool(self.root)
        self.assertEqual(error.exception.code, 11)

    def test_missing_model_file_is_a_model_identity_failure(self) -> None:
        (self.root / "docs/models/PeerLeases/Session.tla").unlink()
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--check-only"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 15)

    def test_missing_jar_is_a_tool_identity_failure(self) -> None:
        (self.home / "lib/apalache.jar").unlink()
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--check-only"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 11)

    def test_malformed_tool_pin_missing_version_is_a_tool_identity_failure(self) -> None:
        pin = self.root / "crates/serving/core-compat.toml"
        text = pin.read_text(encoding="utf-8")
        pin.write_text(text.replace('version = "0.62.4"\n', ""), encoding="utf-8")
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--check-only"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 11)

    def test_deleted_contract_is_an_inventory_identity_failure(self) -> None:
        (self.root / check_models.FORMAL_CONTRACT).unlink()
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--check-only"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 15)

    def test_check_only_confirms_identity_without_running_properties(self) -> None:
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--check-only"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 0)
        self.assertEqual(self.results(), [])

    def test_unknown_module_name_is_a_model_identity_failure(self) -> None:
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--check-only", "--module", "PeerLeases/Lease"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 15)

    def test_module_filter_runs_only_the_named_module(self) -> None:
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--k-start", "128", "--module", "PeerLeases/Session"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 0)
        summary = json.loads((self.root / "target/apalache/summary.json").read_text())
        self.assertEqual(set(summary), {"PeerLeases/Session"})

    def test_temporal_lane_writes_under_temporal_directory(self) -> None:
        module = self.module()
        check_models.run_module(
            self.root, self.toolchain, module, check_models.PROPERTIES[1], 5
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
        self.assertIn("--inv=TypeOK,Safety", identity["argv"])
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

    def test_resource_exhaustion_halves_the_bound_down_to_the_module_floor(self) -> None:
        body = (
            "import sys\n"
            "length = [arg for arg in sys.argv if arg.startswith('--length=')][0]\n"
            "bound = int(length.split('=')[1])\n"
            "if bound > 16:\n    sys.exit(137)\n"
            "print('The outcome is: NoError\\nEXITCODE: OK')\n"
        )
        self.write_tool(body)
        record = self.run_check()
        self.assertEqual(record["k"], 16)
        self.assertEqual(record["evidence_rc"], 0)
        bounds = sorted(result["k"] for result in self.results())
        self.assertEqual(bounds, [16, 32, 64, 128])

    def test_halving_stops_at_the_module_floor_and_reports_the_resource_code(self) -> None:
        self.write_tool("sys.exit(137)")
        record = check_models.run_module(
            self.root, self.toolchain, self.module(1), check_models.PROPERTIES[0], 5
        )
        self.assertEqual(record["k"], 128)
        self.assertEqual(record["evidence_rc"], 14)

    def test_spec_evaluation_error_does_not_halve_the_bound(self) -> None:
        self.write_tool("sys.exit(75)")
        record = self.run_check()
        self.assertEqual(record["k"], 128)
        self.assertEqual(record["evidence_rc"], 14)
        self.assertEqual(len(self.results()), 1)

    def test_pass_below_the_module_floor_is_unavailable_evidence(self) -> None:
        record = check_models.run_module(
            self.root, self.toolchain, self.module(1), check_models.PROPERTIES[0], 5,
            start=64,
        )
        self.assertEqual(record["k"], 64)
        self.assertEqual(record["evidence_rc"], check_models.BOUND_CODE)

    def test_summary_records_bound_and_return_codes(self) -> None:
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--k-start", "128"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 0)
        summary = json.loads((self.root / "target/apalache/summary.json").read_text())
        self.assertEqual(set(summary), {"ChainAdmission/Commit", "PeerLeases/Session"})
        for lanes in summary.values():
            for kind in ("safety", "temporal"):
                self.assertEqual(lanes[kind]["k"], 128)
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
        self.assertIsNone(record["native_rc"])
        self.assertEqual(record["evidence_rc"], 14)
        sessions = iter(sorted(self.root.glob("target/apalache/**/descendant.pid")))
        for pid_file in (next(sessions), *sessions):
            descendant = int(pid_file.read_text())
            result = json.loads((pid_file.parent / "result.json").read_text())
            self.assertEqual(
                result,
                {
                    "k": int(pid_file.parent.parent.name[1:]),
                    "native_rc": None,
                    "evidence_rc": 14,
                },
            )
            try:
                stat = Path(f"/proc/{descendant}/stat").read_text(encoding="ascii")
            except (ProcessLookupError, FileNotFoundError):
                stat = None
            if stat is not None:
                state = stat[stat.rfind(")") + 1:].split(maxsplit=1)[0]
                self.assertEqual(state, "Z")

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

    def test_default_starts_follow_the_documented_floor_even_with_a_stale_memo(self) -> None:
        directory = self.root / "docs/models/Deep"
        directory.mkdir(parents=True)
        tla = directory / "Scan.tla"
        tla.write_text("fixture\n", encoding="utf-8")
        cfg = directory / "Scan.cfg"
        cfg.write_text("CONSTANTS\nN = 1\nINIT Init\nNEXT Next\n", encoding="utf-8")
        shas = {}
        rows = []
        for owner, machine, floor in (
            ("ChainAdmission", "Commit", 16),
            ("PeerLeases", "Session", 128),
            ("Deep", "Scan", 256),
        ):
            path = self.root / "docs/models" / owner / f"{machine}.tla"
            cfg_path = self.root / "docs/models" / owner / f"{machine}.cfg"
            shas[f"{owner}/{machine}"] = (
                hashlib.sha256(path.read_bytes()).hexdigest(),
                hashlib.sha256(cfg_path.read_bytes()).hexdigest(),
            )
            rows.append(
                f"| {owner}/{machine} | {shas[f'{owner}/{machine}'][0]} "
                f"| {shas[f'{owner}/{machine}'][1]} | N=1 | {floor} | BLOCKED | - | - | apalache |"
            )
        table_header = (
            "| module | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc | checker |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
        )
        contract = self.root / check_models.FORMAL_CONTRACT
        contract.write_text(f"{table_header}\n" + "\n".join(rows), encoding="utf-8")
        memo_path = self.root / "target/apalache/k-memo.json"
        memo_path.parent.mkdir(parents=True, exist_ok=True)
        memo_path.write_text(
            json.dumps({
                "ChainAdmission/Commit:safety": {
                    "tla_sha256": shas["ChainAdmission/Commit"][0],
                    "cfg_sha256": shas["ChainAdmission/Commit"][1],
                    "tool_version": "0.62.4",
                    "k": 16,
                },
                "PeerLeases/Session:safety": {
                    "tla_sha256": shas["PeerLeases/Session"][0],
                    "cfg_sha256": shas["PeerLeases/Session"][1],
                    "tool_version": "0.62.4",
                    "k": 128,
                },
            }) + "\n",
            encoding="utf-8",
        )
        started: dict[str, int] = {}

        def recording_runner(root, executable, module, property_arg, timeout=3600, *args, **kwargs):
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            start = args[0] if args else kwargs.get("start", 128)
            started[f"{module.name}:{kind}"] = start
            return {"k": start, "native_rc": 0, "evidence_rc": 0, "run": "test"}

        def run_main(*extra: str) -> int:
            started.clear()
            with (
                patch.object(check_models, "ROOT", self.root),
                patch.object(check_models, "run_module", side_effect=recording_runner),
                patch.object(sys, "argv", ["check_models.py", "--jobs", "1", *extra]),
                patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
            ):
                return check_models.main()

        self.assertEqual(run_main(), 0)
        self.assertEqual(started["ChainAdmission/Commit:safety"], 128)
        self.assertEqual(started["ChainAdmission/Commit:temporal"], 128)
        self.assertEqual(started["PeerLeases/Session:safety"], 128)
        self.assertEqual(started["PeerLeases/Session:temporal"], 128)
        self.assertEqual(started["Deep/Scan:safety"], 256)
        self.assertEqual(started["Deep/Scan:temporal"], 256)

        self.assertEqual(run_main("--k-start", "32"), 0)
        self.assertEqual(started["ChainAdmission/Commit:safety"], 32)
        self.assertEqual(started["Deep/Scan:safety"], 32)

    def test_failing_lane_yields_nonzero_exit_when_others_pass(self) -> None:
        def mixed_runner(root, executable, module, property_arg, timeout=3600, *args, **kwargs):
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            start = args[0] if args else kwargs.get("start", 128)
            if module.name == "ChainAdmission/Commit" and kind == "temporal":
                return {"k": start, "native_rc": 255, "evidence_rc": 14, "run": "err"}
            return {"k": start, "native_rc": 0, "evidence_rc": 0, "run": "ok"}
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=mixed_runner),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "2"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            rc = check_models.main()
        self.assertEqual(rc, 14)
        summary = json.loads((self.root / "target/apalache/summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["ChainAdmission/Commit"]["temporal"]["evidence_rc"], 14)
        self.assertEqual(summary["ChainAdmission/Commit"]["safety"]["evidence_rc"], 0)

    def test_counterexample_outranks_unavailable_evidence(self) -> None:
        def diverging_runner(root, executable, module, property_arg, *args, **kwargs):
            kind = "safety" if property_arg.startswith("--inv=") else "temporal"
            if module.name == "ChainAdmission/Commit":
                evidence = 13 if kind == "safety" else 14
            else:
                evidence = 0
            return {"k": 128, "native_rc": 12, "evidence_rc": evidence, "run": "x"}
        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "run_module", side_effect=diverging_runner),
            patch.object(sys, "argv", ["check_models.py", "--jobs", "2"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 13)

    def test_unknown_and_missing_checker_in_registry_fails_closed(self) -> None:
        table_header = (
            "| module | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc | checker |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
        )
        contract = self.root / check_models.FORMAL_CONTRACT
        contract.write_text(
            f"{table_header}\n"
            "| Owner/Machine | " + "0" * 64 + " | " + "1" * 64 + " | N=1 | 16 | BLOCKED | - | - |\n",
            encoding="utf-8",
        )
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.modules(self.root)
        self.assertEqual(error.exception.code, 15)
        self.assertIn("malformed inventory row", str(error.exception))

        contract.write_text(
            f"{table_header}\n"
            "| Owner/Machine | " + "0" * 64 + " | " + "1" * 64 + " | N=1 | 16 | BLOCKED | - | - | spin |\n",
            encoding="utf-8",
        )
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.modules(self.root)
        self.assertEqual(error.exception.code, 15)
        self.assertIn("unknown or missing checker", str(error.exception))
    def test_pinned_cfg_with_restricting_sections_rejected(self) -> None:
        for section in (
            "CONSTRAINT Bound",
            "ACTION-CONSTRAINT StepConstraint",
            "FAIRNESS",
            "SYMMETRY Perms",
            "PROPERTY SomeProp",
            "INVARIANT SomeInv",
        ):
            with self.subTest(section=section):
                bad_cfg = f"INIT Init\nNEXT Next\n{section}\n"
                with self.assertRaises(check_models.EvidenceError) as error:
                    check_models.validate_tlc_cfg(bad_cfg, "Test/Module")
                self.assertEqual(error.exception.code, 12)

        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.validate_tlc_cfg("CONSTANTS N=1\nINIT Init\n", "Test/Module")
        self.assertEqual(error.exception.code, 12)

    def test_generated_tlc_cfg_preserves_constants_and_appends_required_properties(self) -> None:
        pinned = "CONSTANTS\nN = 1\nINIT Init\nNEXT Next\n"
        gen = check_models.generate_tlc_cfg(pinned)
        self.assertIn("CONSTANTS\nN = 1", gen)
        self.assertIn("INIT Init", gen)
        self.assertIn("NEXT Next", gen)
        self.assertIn("INVARIANT TypeOK", gen)
        self.assertIn("INVARIANT Safety", gen)
        self.assertIn("PROPERTY ConditionalProgress", gen)

    def test_tlc_complete_success_projects_both_lanes_with_honest_null_k(self) -> None:
        tlc_output = (
            'print("Model checking completed. No error has been found.\\n'
            'Checking 1 temporal properties for the complete state graph with 134 states.\\n'
            '134 states generated, 134 distinct states found, 0 states left on queue.")\n'
            "sys.exit(0)"
        )
        java_cmd = self.write_tlc_tool(tlc_output)
        module = dataclasses.replace(self.module(0), checker="tlc")
        with patch.dict(os.environ, {"JAVA": str(java_cmd)}):
            records = check_models.run_tlc_module(self.root, self.toolchain, module, 5)
        self.assertEqual(records["safety"]["k"], None)
        self.assertEqual(records["safety"]["native_rc"], 0)
        self.assertEqual(records["safety"]["evidence_rc"], 0)
        self.assertEqual(records["safety"]["distinct_states"], 134)
        self.assertEqual(records["temporal"]["k"], None)
        self.assertEqual(records["temporal"]["native_rc"], 0)
        self.assertEqual(records["temporal"]["evidence_rc"], 0)
        self.assertEqual(records["temporal"]["distinct_states"], 134)
        run_dir = Path(str(records["safety"]["run"]))
        identity = json.loads((run_dir / "identity.json").read_text(encoding="utf-8"))
        self.assertEqual(identity["checker"], "tlc")
        self.assertEqual(identity["distinct_states"], 134)
        self.assertIn("input_cfg_sha256", identity)
        self.assertIn("generated_cfg_sha256", identity)
        self.assertNotEqual(identity["input_cfg_sha256"], identity["generated_cfg_sha256"])
        result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["k"], None)
        self.assertEqual(result["native_rc"], 0)
        self.assertEqual(result["evidence_rc"], 0)

    def test_tlc_malformed_output_fails_closed(self) -> None:
        cases = (
            'print("Some output without marker")\nsys.exit(0)',
            'print("Model checking completed. No error has been found.\\nChecking temporal properties\\n10 states generated, 10 distinct states found, 5 states left on queue.")\nsys.exit(0)',
            'print("Model checking completed. No error has been found.\\nChecking temporal properties\\n0 states generated, 0 distinct states found, 0 states left on queue.")\nsys.exit(0)',
            'print("Model checking completed. No error has been found.\\nChecking temporal properties\\n10 states generated, 10 distinct states found, 0 states left on queue.\\nError: Invariant Safety is violated.")\nsys.exit(0)',
            'sys.exit(0)',
        )
        module = dataclasses.replace(self.module(0), checker="tlc")
        for body in cases:
            with self.subTest(body=body):
                java_cmd = self.write_tlc_tool(body)
                with patch.dict(os.environ, {"JAVA": str(java_cmd)}):
                    records = check_models.run_tlc_module(self.root, self.toolchain, module, 5)
                self.assertNotEqual(records["safety"]["evidence_rc"], 0)

    def test_tlc_property_omission_fails_closed(self) -> None:
        pinned = "INIT Init\nNEXT Next\n"
        gen = check_models.generate_tlc_cfg(pinned)
        self.assertIn("PROPERTY ConditionalProgress", gen)
        self.assertIn("INVARIANT TypeOK", gen)
        self.assertIn("INVARIANT Safety", gen)

        module = dataclasses.replace(self.module(0), checker="tlc")
        with patch.object(check_models, "generate_tlc_cfg", return_value="INIT Init\nNEXT Next\n"):
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.run_tlc_module(self.root, self.toolchain, module, 5)
            self.assertEqual(error.exception.code, 12)
            self.assertIn("missing PROPERTY ConditionalProgress", str(error.exception))

        with patch.object(check_models, "generate_tlc_cfg", return_value="INIT Init\nNEXT Next\nPROPERTY ConditionalProgress\n"):
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.run_tlc_module(self.root, self.toolchain, module, 5)
            self.assertEqual(error.exception.code, 12)
            self.assertIn("missing required invariants", str(error.exception))

    def test_tlc_native_return_codes_mapping(self) -> None:
        module = dataclasses.replace(self.module(0), checker="tlc")
        code_cases = (
            (11, 'print("Error: Deadlock reached.")\nsys.exit(11)', 13, 14),
            (12, 'print("Error: Invariant Safety is violated.")\nsys.exit(12)', 13, 14),
            (13, 'print("Error: Temporal property ConditionalProgress is violated.")\nsys.exit(13)', 14, 13),
            (10, 'print("Error: Assumption is violated.")\nsys.exit(10)', 13, 14),
            (14, 'print("Error: Assertion failed.")\nsys.exit(14)', 13, 14),
            (150, 'print("Error: Parse error in specification.")\nsys.exit(150)', 12, 12),
            (151, 'print("Error: Configuration parse error.")\nsys.exit(151)', 12, 12),
        )
        for native, script, exp_safety, exp_temporal in code_cases:
            with self.subTest(native=native):
                java_cmd = self.write_tlc_tool(script)
                with patch.dict(os.environ, {"JAVA": str(java_cmd)}):
                    records = check_models.run_tlc_module(self.root, self.toolchain, module, 5)
                self.assertEqual(records["safety"]["evidence_rc"], exp_safety)
                self.assertEqual(records["temporal"]["evidence_rc"], exp_temporal)
                self.assertEqual(records["safety"]["native_rc"], native)

    def test_session_cleanup_on_timeout_and_signal(self) -> None:
        body = (
            "import os, subprocess, sys, time\n"
            "child = subprocess.Popen(['sleep', '300'], start_new_session=False)\n"
            "with open('tlc_child.pid', 'w') as f:\n"
            "    f.write(str(child.pid))\n"
            "time.sleep(30)\n"
        )
        java_cmd = self.write_tlc_tool(body)
        module = dataclasses.replace(self.module(0), checker="tlc")
        with patch.dict(os.environ, {"JAVA": str(java_cmd)}):
            records = check_models.run_tlc_module(self.root, self.toolchain, module, 1)
        self.assertEqual(records["safety"]["evidence_rc"], 14)
        pid_file = next(self.root.glob("target/apalache/**/tlc_child.pid"))
        child_pid = int(pid_file.read_text())
        stat = None
        try:
            stat = Path(f"/proc/{child_pid}/stat").read_text(encoding="ascii")
        except (ProcessLookupError, FileNotFoundError):
            stat = None
        if stat is not None:
            state = stat[stat.rfind(")") + 1:].split(maxsplit=1)[0]
            self.assertEqual(state, "Z")

        check_models.register_session(999999)
        self.assertIn(999999, check_models.LIVE_SESSIONS)
        check_models.cleanup_all_sessions(signal.SIGKILL)
        self.assertEqual(len(check_models.LIVE_SESSIONS), 0)

    def test_checker_flag_overrides_configured_checker(self) -> None:
        rows = []
        for owner, machine, floor in MODULES:
            path = self.root / "docs/models" / owner / f"{machine}.tla"
            cfg_path = self.root / "docs/models" / owner / f"{machine}.cfg"
            tla_sha = hashlib.sha256(path.read_bytes()).hexdigest()
            cfg_sha = hashlib.sha256(cfg_path.read_bytes()).hexdigest()
            rows.append(
                f"| {owner}/{machine} | {tla_sha} | {cfg_sha} | N=1 | {floor} | BLOCKED | - | - | tlc |"
            )
        table_header = (
            "| module | .tla sha256 | .cfg sha256 | CONSTANT values | K | last recorded outcome | native rc | evidence rc | checker |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
        )
        contract = self.root / check_models.FORMAL_CONTRACT
        contract.write_text(f"{table_header}\n" + "\n".join(rows), encoding="utf-8")

        tlc_output = (
            'print("Model checking completed. No error has been found.\\n'
            'Checking 1 temporal properties for the complete state graph with 10 states.\\n'
            '10 states generated, 10 distinct states found, 0 states left on queue.")\n'
            "sys.exit(0)"
        )
        java_cmd = self.write_tlc_tool(tlc_output)

        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", ["check_models.py", "--module", "ChainAdmission/Commit"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home), "JAVA": str(java_cmd)}),
        ):
            rc = check_models.main()
        self.assertEqual(rc, 0)
        summary = json.loads((self.root / "target/apalache/summary.json").read_text())
        self.assertEqual(summary["ChainAdmission/Commit"]["safety"]["k"], None)

        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(sys, "argv", [
                "check_models.py", "--checker", "apalache", "--k-start", "16",
                "--module", "ChainAdmission/Commit"
            ]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            rc = check_models.main()
        self.assertEqual(rc, 0)
        summary = json.loads((self.root / "target/apalache/summary.json").read_text())
        self.assertEqual(summary["ChainAdmission/Commit"]["safety"]["k"], 16)

    def test_inventory_fails_on_missing_slash_or_malformed_row(self) -> None:
        contract = self.root / check_models.FORMAL_CONTRACT
        lines = contract.read_text(encoding="utf-8").splitlines()

        malformed_lines = [
            line.replace("ChainAdmission/Commit", "Commit")
            if "ChainAdmission/Commit" in line else line
            for line in lines
        ]
        contract.write_text("\n".join(malformed_lines), encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.modules(self.root)
        self.assertEqual(error.exception.code, 15)
        self.assertIn("missing owner/machine separator", str(error.exception))

        col_lines = [
            "| ChainAdmission/Commit | col2 |"
            if "ChainAdmission/Commit" in line else line
            for line in lines
        ]
        contract.write_text("\n".join(col_lines), encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.modules(self.root)
        self.assertEqual(error.exception.code, 15)
        self.assertIn("malformed inventory row", str(error.exception))

    def test_tlc_cfg_rejects_plural_restricting_keywords_view_and_specification(self) -> None:
        base_cfg = "CONSTANTS\nN = 1\nINIT Init\nNEXT Next\n"
        restricting = (
            "CONSTRAINTS Const1",
            "CONSTRAINT Const1",
            "ACTION-CONSTRAINTS Act1",
            "ACTION_CONSTRAINTS Act1",
            "ACTION-CONSTRAINT Act1",
            "ACTION_CONSTRAINT Act1",
            "VIEW View1",
            "SYMMETRY Symm1",
            "SPECIFICATION Spec",
            "FAIRNESS Fair1",
            "SIMULATION 100",
            "CHECK_DEADLOCK FALSE",
        )
        for section in restricting:
            with self.subTest(section=section):
                bad_cfg = f"{base_cfg}{section}\n"
                with self.assertRaises(check_models.EvidenceError) as error:
                    check_models.validate_tlc_cfg(bad_cfg, "Test/Module")
                self.assertEqual(error.exception.code, 12)
                self.assertIn("contains restricting section", str(error.exception))

        display_only = (
            "ALIAS MyAlias",
            "POSTCONDITION PostCheck",
            "POSTCONDITIONS PostCheck",
        )
        for section in display_only:
            with self.subTest(display_only=section):
                allowed_cfg = f"{base_cfg}{section}\n"
                check_models.validate_tlc_cfg(allowed_cfg, "Test/Module")

    def test_tlc_cfg_requires_exact_init_and_next_word_boundaries(self) -> None:
        missing_init = "CONSTANTS\nINITIAL_STATE = 0\nNEXT Next\n"
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.validate_tlc_cfg(missing_init, "Test/Module")
        self.assertEqual(error.exception.code, 12)
        self.assertIn("missing INIT or NEXT", str(error.exception))

        missing_next = "CONSTANTS\nNEXT_EPOCH = 1\nINIT Init\n"
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.validate_tlc_cfg(missing_next, "Test/Module")
        self.assertEqual(error.exception.code, 12)
        self.assertIn("missing INIT or NEXT", str(error.exception))

    def test_summary_fails_closed_on_omitted_lane(self) -> None:
        inventory = check_models.modules(self.root)
        mod = inventory[0]
        results = {
            (mod.name, "safety"): {
                "k": None,
                "native_rc": 0,
                "evidence_rc": 0,
                "run": "/tmp/test",
                "checker": "tlc",
            }
        }
        summary = check_models.build_summary(inventory, results)
        self.assertIn("temporal", summary[mod.name])
        self.assertEqual(summary[mod.name]["temporal"]["evidence_rc"], 14)

        with (
            patch.object(check_models, "ROOT", self.root),
            patch.object(check_models, "modules", return_value=(mod,)),
            patch.object(check_models, "execute_jobs", return_value=results),
            patch.object(check_models, "tool", return_value=self.toolchain),
            patch.object(sys, "argv", ["check_models.py"]),
            patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
        ):
            self.assertEqual(check_models.main(), 14)

    def test_signal_handling_reentrancy_and_sighup(self) -> None:
        self.assertIsInstance(check_models.LIVE_SESSIONS_LOCK, type(threading.RLock()))
        check_models.register_session(12345)
        with check_models.LIVE_SESSIONS_LOCK:
            check_models.cleanup_all_sessions(signal.SIGKILL)
        self.assertEqual(len(check_models.LIVE_SESSIONS), 0)

        if hasattr(signal, "SIGHUP"):
            old_handler = signal.getsignal(signal.SIGHUP)
            try:
                with (
                    patch.object(check_models, "ROOT", self.root),
                    patch.object(sys, "argv", ["check_models.py", "--check-only"]),
                    patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}),
                ):
                    check_models.main()
                self.assertIs(signal.getsignal(signal.SIGHUP), check_models.handle_termination_signal)
            finally:
                signal.signal(signal.SIGHUP, old_handler)

    def test_tool_custody_enforces_verified_toolchain(self) -> None:
        with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
            toolchain = check_models.tool(self.root)
            self.assertIsInstance(toolchain, check_models.Toolchain)
            self.assertEqual(toolchain.executable, self.executable)
            self.assertEqual(toolchain.jar, self.home / "lib/apalache.jar")
            self.assertEqual(toolchain.jar_sha256, check_models.sha256(toolchain.jar))


    def test_tlc_performance_guard_fails_when_state_budget_exceeded(self) -> None:
        log_text = "Model checking completed. No error has been found.\n"
        match_pass = re.search(
            r"(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue\.",
            "53 states generated, 26 distinct states found, 0 states left on queue.",
        )
        report_pass = check_models.TlcLogReport(
            log_text=log_text,
            state_match=match_pass,
            queue_left=0,
            distinct_states=26,
            states_gen=53,
        )
        self.assertEqual(check_models.map_tlc_return_codes(0, report_pass, state_budget=26), (0, 0))

        match_fail = re.search(
            r"(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue\.",
            "60 states generated, 27 distinct states found, 0 states left on queue.",
        )
        report_fail = check_models.TlcLogReport(
            log_text=log_text,
            state_match=match_fail,
            queue_left=0,
            distinct_states=27,
            states_gen=60,
        )
        self.assertEqual(check_models.map_tlc_return_codes(0, report_fail, state_budget=26), (14, 14))
if __name__ == "__main__":
    unittest.main()
