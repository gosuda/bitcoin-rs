"""Offline tests of formal evidence custody and failure handling, not model proofs."""

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


class ModelEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        directory = self.root / "docs/models"
        directory.mkdir(parents=True)
        rows: list[str] = []
        for name in check_models.MODELS:
            tla = (directory / f"{name}.tla")
            tla.write_text("fixture\n", encoding="utf-8")
            cfg = (directory / f"{name}.cfg")
            cfg.write_text("CONSTANTS\nN = 1\nINIT Init\nNEXT Next\n", encoding="utf-8")
            digest = hashlib.sha256(tla.read_bytes()).hexdigest()
            cfg_digest = hashlib.sha256(cfg.read_bytes()).hexdigest()
            rows.append(
                f"| {name} | {digest} | {cfg_digest} | N=1 | 128 | BLOCKED | - | - |"
            )
        (self.root / "CONSTRAINTS.md").write_text("\n".join(rows), encoding="utf-8")
        self.home = self.root / "tool"
        (self.home / "bin").mkdir(parents=True)
        (self.home / "lib").mkdir()
        jar = self.home / "lib/apalache.jar"
        jar.write_bytes(b"synthetic tool, not a prover")
        api = self.root / "crates/rpc"
        api.mkdir(parents=True)
        (api / "core-compat.toml").write_text(
            '[reference.formal_tool]\nname = "apalache-mc"\nversion = "0.62.2"\n'
            f'jar_sha256 = "{hashlib.sha256(jar.read_bytes()).hexdigest()}"\n',
            encoding="utf-8",
        )
        self.executable = self.home / "bin/apalache-mc"
        self.write_tool('print("The outcome is: NoError\\nEXITCODE: OK")')

    def write_tool(self, body: str, version: str = "0.62.2") -> None:
        self.executable.write_text(
            f"#!{sys.executable}\nimport sys, time\n"
            f"if sys.argv[1] == 'version':\n    print({version!r})\n    sys.exit(0)\n{body}\n",
            encoding="utf-8",
        )
        self.executable.chmod(0o755)

    def run_check(self, timeout: int = 5) -> None:
        model = check_models.models(self.root)[0]
        check_models.run_model(self.root, self.executable, model, check_models.PROPERTIES[0], timeout)

    def test_input_custody_rejects_changed_or_missing_models(self) -> None:
        self.assertEqual(len(check_models.models(self.root)), 3)
        (self.root / "docs/models/ChainAdmission.tla").write_text("changed", encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.models(self.root)
        self.assertEqual(error.exception.code, 15)
        (self.root / "CONSTRAINTS.md").write_text("", encoding="utf-8")
        with self.assertRaises(check_models.EvidenceError) as error:
            check_models.models(self.root)
        self.assertEqual(error.exception.code, 15)

    def test_tool_custody_rejects_wrong_version_and_jar(self) -> None:
        with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
            self.assertEqual(check_models.tool(self.root), self.executable)
            self.write_tool("", version="0.62.20")
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
            self.assertEqual(error.exception.code, 11)
            self.write_tool("")
            (self.home / "lib/apalache.jar").write_bytes(b"different")
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
            self.assertEqual(error.exception.code, 11)

    def test_empty_apalache_home_uses_default_location(self) -> None:
        default = (
            self.root / "target/tools" / "apalache-0.62.2" / "bin" / "apalache-mc"
        ).resolve()
        with patch.dict(os.environ, {"APALACHE_HOME": ""}):
            with self.assertRaises(check_models.EvidenceError) as error:
                check_models.tool(self.root)
        self.assertEqual(error.exception.code, 11)
        self.assertEqual(str(error.exception), f"missing executable: {default}")


    def test_missing_model_file_is_a_model_identity_failure(self) -> None:
        # A missing model file is a custody failure on the model lane, not an
        # unavailable run: main() must report the model-identity code, 15,
        # never the generic FileNotFoundError mapped to 14.
        (self.root / "docs/models/PeerLeases.tla").unlink()
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 15)

    def test_missing_jar_is_a_tool_identity_failure(self) -> None:
        # A missing JAR is a tool-lane custody failure: main() must report the
        # tool-identity code, 11, never the generic FileNotFoundError code 14.
        (self.home / "lib/apalache.jar").unlink()
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 11)

    def test_malformed_tool_pin_missing_version_is_a_tool_identity_failure(self) -> None:
        # A pin missing one of the name/version/jar_sha256 keys cannot name a
        # tool: main() must report the tool-identity code, 11, never the
        # generic KeyError code 14.
        pin = self.root / "crates/rpc/core-compat.toml"
        text = pin.read_text(encoding="utf-8")
        pin.write_text(text.replace('version = "0.62.2"\n', ""), encoding="utf-8")
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 11)

    def test_deleted_register_is_an_inventory_identity_failure(self) -> None:
        # A deleted custody register cannot settle model identity: main()
        # must report the inventory code, 15, never the generic
        # FileNotFoundError code 14.
        (self.root / "CONSTRAINTS.md").unlink()
        with patch.object(check_models, "ROOT", self.root):
            with patch.object(sys, "argv", ["check_models.py", "--check-only"]):
                with patch.dict(os.environ, {"APALACHE_HOME": str(self.home)}):
                    self.assertEqual(check_models.main(), 15)

    def test_temporal_lane_writes_under_temporal_directory(self) -> None:
        model = check_models.models(self.root)[0]
        check_models.run_model(
            self.root, self.executable, model, check_models.PROPERTIES[1], 5
        )
        results = list(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(len(results), 1)
        self.assertEqual(json.loads(results[0].read_text()), {"native_rc": 0, "evidence_rc": 0})
        # Identity is recorded inside the fresh run directory itself.
        self.assertTrue(results[0].with_name("identity.json").is_file())
        temporal = self.root / "target/apalache" / model.name / "temporal"
        self.assertEqual(results[0].parent.parent, temporal)

    def test_inherited_smt_solver_cannot_override_the_pinned_prover(self) -> None:
        # The solver is part of the recorded evidence identity; a variable
        # inherited from the caller's shell must not swap the pinned prover.
        with patch.dict(os.environ, {"SMT_SOLVER": "boo"}):
            self.run_check()
        results = list(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(len(results), 1)
        identity = json.loads(results[0].with_name("identity.json").read_text())
        self.assertEqual(identity["solver"], "z3")

    def test_complete_success_retains_identity_and_outcome(self) -> None:
        self.run_check()
        results = list(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(len(results), 1)
        self.assertEqual(json.loads(results[0].read_text()), {"native_rc": 0, "evidence_rc": 0})
        identity = json.loads(results[0].with_name("identity.json").read_text())
        self.assertIn("--length=128", identity["argv"])
        self.assertIn("--inv=TypeOK,Safety,TransitionSafety", identity["argv"])
        self.assertEqual(identity["constants"], "N = 1")

    def newest_result(self) -> dict[str, object]:
        # Each subtest spawns a fresh run directory, so the newest result.json
        # under the model's run tree records that subtest's verdict.
        results = sorted(self.root.glob("target/apalache/**/result.json"),
                         key=lambda path: path.stat().st_mtime)
        self.assertTrue(results, "no result.json recorded")
        return json.loads(results[-1].read_text())

    def test_native_failures_keep_their_meaning(self) -> None:
        for native, expected in ((150, 12), (120, 12), (12, 13), (255, 14)):
            with self.subTest(native=native):
                self.write_tool(f"sys.exit({native})")
                with self.assertRaises(check_models.EvidenceError) as error:
                    self.run_check()
                self.assertEqual(error.exception.code, expected)
                result = self.newest_result()
                self.assertEqual(result["native_rc"], native)
                self.assertEqual(result["evidence_rc"], expected)

    def test_zero_exit_without_complete_outcome_is_not_a_proof(self) -> None:
        for text in ("", "The outcome is: NoError", "EXITCODE: OK"):
            with self.subTest(text=text):
                self.write_tool(f"print({text!r})")
                with self.assertRaises(check_models.EvidenceError) as error:
                    self.run_check()
                self.assertEqual(error.exception.code, 14)
                self.assertEqual(self.newest_result()["evidence_rc"], 14)

    def test_timeout_kills_the_whole_tool_session(self) -> None:
        # The fake tool is a real process tree: the python child spawns a
        # `sleep 300` descendant, records its pid on disk, and waits for it.
        # A plain sleep would leave the os.killpg branch unproven, so after
        # run_model times out the test asserts the recorded descendant is
        # gone (the whole group died, not just the launcher).
        body = (
            "import os, subprocess, sys\n"
            "if sys.argv[1] == 'check':\n"
            "    child = subprocess.Popen(['sleep', '300'], start_new_session=False)\n"
            "    with open('descendant.pid', 'w') as sink:\n"
            "        sink.write(str(child.pid))\n"
            "    os.wait()\n"
        )
        self.write_tool(body)
        # cwd=run_dir for the tool, so the pid file lands beside output.log.
        with self.assertRaises(check_models.EvidenceError) as error:
            self.run_check(timeout=1)
        # Descendant state first: os.killpg must have reached the whole tool
        # session before any recorded outcome can be asserted.  A killed
        # descendant may remain as a zombie until its parent is reaped, so
        # os.kill(pid, 0) alone does not prove that it is no longer running.
        pid_file = next(self.root.glob("target/apalache/**/descendant.pid"))
        descendant = int(pid_file.read_text())
        try:
            stat = Path(f"/proc/{descendant}/stat").read_text(encoding="ascii")
        except (ProcessLookupError, FileNotFoundError):
            stat = None
        if stat is not None:
            state = stat[stat.rfind(")") + 1 :].split(maxsplit=1)[0]
            self.assertEqual(state, "Z")
        self.assertEqual(error.exception.code, 14)
        result = next(self.root.glob("target/apalache/**/result.json"))
        self.assertEqual(json.loads(result.read_text()), {"native_rc": None, "evidence_rc": 14})


if __name__ == "__main__":
    unittest.main()
