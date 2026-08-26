#!/usr/bin/env python3.14
# pyright: strict
"""Behavioral tests for the native exact-seven-pair campaign runner."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import TypeIs
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

import runner
from native_offline import AdapterKind, ContractError
from runner import (
    ALL_CELLS,
    PAIR_COUNT,
    Architecture,
    Verdict,
    classify_wall_performance,
    load_config,
    parse_config,
    run_cell,
    schedule_for,
    validate_result,
)

type JsonObject = dict[str, object]
TARGET = ALL_CELLS[0]
ZERO_HASH = "0" * 64
GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
STOP_HASH = "1" * 64
COMMIT = "2" * 40


def _is_object(value: object) -> TypeIs[JsonObject]:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in value)  # pyright: ignore[reportUnknownVariableType]


def _object(value: object) -> JsonObject:
    if not _is_object(value):
        raise TypeError("expected JSON object")
    return value


def _is_array(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _array(value: object) -> list[object]:
    if not _is_array(value):
        raise TypeError("expected JSON array")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _candidate_script(
    workspace: Path,
    *,
    witness: int = 1,
    stop_hash: str = STOP_HASH,
    malformed: bool = False,
    mutate_input: bool = False,
    restore_swap_input: bool = False,
    exit_code: int = 0,
    sleep_seconds: float = 0.06,
) -> Path:
    source = f"""#!{sys.executable}
import hashlib
import json
import os
import pathlib
import sys
import time

args = dict(zip(sys.argv[1::2], sys.argv[2::2], strict=True))
data_dir = pathlib.Path(args['--data-dir'])
corpus = pathlib.Path(args['--blocks-file'])
manifest = pathlib.Path(args['--corpus-manifest'])
(data_dir / 'executed.txt').write_text(sys.argv[0], encoding='utf-8')
(data_dir / 'environment.json').write_text(
    json.dumps(dict(os.environ), sort_keys=True), encoding='utf-8'
)
(data_dir / 'affinity.json').write_text(
    json.dumps(sorted(os.sched_getaffinity(0))), encoding='utf-8'
)
time.sleep({sleep_seconds!r})
if {exit_code}:
    raise SystemExit({exit_code})
if {mutate_input!r}:
    with open(corpus, 'ab') as stream:
        stream.write(b'mutated')
if {restore_swap_input!r}:
    original = pathlib.Path({str(workspace / "blocks.dat")!r})
    held = original.with_name('blocks.held')
    original.rename(held)
    original.write_bytes(b'substitute corpus')
    try:
        consumed = corpus.read_bytes()
    finally:
        original.unlink()
        held.rename(original)
    (data_dir / 'consumed.sha256').write_text(
        hashlib.sha256(consumed).hexdigest(), encoding='ascii'
    )
output = pathlib.Path(args['--output'])
if {malformed!r}:
    output.write_text('{{bad json', encoding='utf-8')
    raise SystemExit(0)
record = {{
    'schema': 'mainnet-prefix-replay-v3',
    'measurement_target': 'mainnet-prefix-replay',
    'git_head': '{COMMIT}',
    'network': 'mainnet',
    'network_magic': 'f9beb4d9',
    'genesis_hash': '{GENESIS}',
    'corpus_manifest': {{
        'schema': 'bitcoin-rs-corpus-manifest',
        'version': 1,
        'path': str(manifest),
        'bytes': manifest.stat().st_size,
        'sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
    }},
    'archive': {{
        'path': str(corpus),
        'bytes': corpus.stat().st_size,
        'sha256': hashlib.sha256(corpus.read_bytes()).hexdigest(),
    }},
    'start_height': 0,
    'start_hash': '{GENESIS}',
    'stop_height': 2,
    'stop_hash': '{stop_hash}',
    'assume_valid_height': 0,
    'window': 1024,
    'window_verify_success_total': {witness},
    'checkpoint_generation': 1,
    'storage_backend': 'fjall',
    'txindex': False,
    'block_count': 3,
    'tx_count': 3,
    'block_bytes': corpus.stat().st_size,
    'elapsed_seconds': 0.01,
    'blocks_per_second': 300.0,
    'fetch_seconds': 0.001,
    'decode_seconds': 0.001,
    'stage_seconds': [{{'stage': 'apply', 'count': 3, 'sum_seconds': 0.01}}],
    'rss_high_water_bytes': 1024,
    'block_source': 'file',
    'data_dir': str(data_dir),
    'txindex_worker_catchup_seconds': None,
    'txindex_total_elapsed_seconds': None,
}}
output.write_text(json.dumps(record), encoding='utf-8')
"""
    return _write_executable(workspace / "fake-candidate.py", source)


def _core_script(
    workspace: Path,
    *,
    full_validation: bool = True,
    gap: bool = False,
    final_hash: str = STOP_HASH,
    exit_code: int = 0,
    sleep_seconds: float = 0.06,
) -> Path:
    source = f"""#!{sys.executable}
import json
import os
import pathlib
import sys
import time

time.sleep({sleep_seconds!r})
if {exit_code}:
    raise SystemExit({exit_code})
args = dict(argument[1:].split('=', 1) for argument in sys.argv[1:])
log = pathlib.Path(args['debuglogfile'])
lines = ['2026-01-01T00:00:00Z Bitcoin Core version v31.1.0 (release build)']
for name, value in args.items():
    lines.append(f'2026-01-01T00:00:00Z Command-line arg: {{name}}="{{value}}"')
if {full_validation!r}:
    lines.append('2026-01-01T00:00:00Z Validating signatures for all blocks.')
heights = [0, 2] if {gap!r} else [0, 1, 2]
for height in heights:
    block_hash = '{final_hash}' if height == 2 else format(height + 3, '064x')
    lines.append(
        f'2026-01-01T00:00:00Z UpdateTip: new best={{block_hash}} height={{height}} version=0x1'
    )
lines.append('2026-01-01T00:00:01Z Shutdown done')
log.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')
data_dir = pathlib.Path(args['datadir'])
(data_dir / 'executed.txt').write_text(sys.argv[0], encoding='utf-8')
(data_dir / 'environment.json').write_text(
    json.dumps(dict(os.environ), sort_keys=True), encoding='utf-8'
)
(data_dir / 'affinity.json').write_text(
    json.dumps(sorted(os.sched_getaffinity(0))), encoding='utf-8'
)
"""
    return _write_executable(workspace / "fake-core.py", source)


def _program(
    binary: Path, adapter: AdapterKind, command: list[str], *, mimalloc: bool
) -> JsonObject:
    return {
        "adapter": adapter.value,
        "binary_path": str(binary),
        "binary_sha256": _sha256(binary),
        "commit": COMMIT,
        "build": "synthetic release",
        "features": ["synthetic"],
        "mimalloc": mimalloc,
        "command": command,
    }


def _state() -> JsonObject:
    return {
        "height": 2,
        "bestblock": STOP_HASH,
        "txouts": 3,
        "total_amount_sat": 5_000_000_000,
        "muhash": "3" * 64,
        "utxo_hash_serialized_3": "4" * 64,
    }


def _proof(
    corpus: Path,
    manifest: Path,
    candidate: JsonObject,
    core: JsonObject,
    *,
    affinity: tuple[int, ...] = (0,),
    candidate_identity: str | None = None,
) -> JsonObject:
    state = _state()
    return {
        "schema": "benchmark-campaign-cell-proof-v1",
        "scope": "role_cell_product",
        "cell": TARGET.key,
        "inputs": {
            "corpus_sha256": _sha256(corpus),
            "corpus_bytes": corpus.stat().st_size,
            "manifest_sha256": _sha256(manifest),
            "manifest_bytes": manifest.stat().st_size,
        },
        "affinity": list(affinity),
        "runtime_dispatch": "synthetic-scalar",
        "expected_state": state,
        "candidate": {
            "program_identity_sha256": candidate_identity
            if candidate_identity is not None
            else _canonical_sha256(candidate),
            "native_evidence_sha256": "5" * 64,
            "validation_sha256": "6" * 64,
            "durability_proof_sha256": "7" * 64,
            "proof_tool_identity_sha256": "8" * 64,
            "state": state,
            "durability_ok": True,
        },
        "core": {
            "program_identity_sha256": _canonical_sha256(core),
            "native_evidence_sha256": "9" * 64,
            "restart_log_sha256": "a" * 64,
            "gettxoutsetinfo_sha256": "b" * 64,
            "state": state,
            "restart_count": 1,
            "durability_ok": True,
        },
    }


class CampaignFixture:
    workspace: Path
    corpus: Path
    manifest: Path
    proof: Path
    config: Path
    candidate: Path
    core: Path

    def __init__(
        self,
        workspace: Path,
        *,
        candidate_witness: int = 1,
        candidate_hash: str = STOP_HASH,
        candidate_malformed: bool = False,
        mutate_input: bool = False,
        restore_swap_input: bool = False,
        candidate_exit: int = 0,
        core_full_validation: bool = True,
        core_gap: bool = False,
        core_hash: str = STOP_HASH,
        core_exit: int = 0,
        bad_proof_identity: bool = False,
        affinity: tuple[int, ...] = (0,),
    ) -> None:
        self.workspace = workspace
        self.corpus = workspace / "blocks.dat"
        self.manifest = workspace / "manifest.json"
        self.corpus.write_bytes(b"synthetic framed blocks")
        self.manifest.write_text('{"schema":"synthetic"}\n', encoding="utf-8")
        self.candidate = _candidate_script(
            workspace,
            witness=candidate_witness,
            stop_hash=candidate_hash,
            malformed=candidate_malformed,
            mutate_input=mutate_input,
            restore_swap_input=restore_swap_input,
            exit_code=candidate_exit,
        )
        self.core = _core_script(
            workspace,
            full_validation=core_full_validation,
            gap=core_gap,
            final_hash=core_hash,
            exit_code=core_exit,
        )
        candidate_program = _program(
            self.candidate,
            AdapterKind.BITCOIN_RS_REPLAY,
            [
                str(self.candidate),
                "--stop-height",
                "2",
                "--blocks-file",
                "{corpus_path}",
                "--corpus-manifest",
                "{manifest_path}",
                "--assume-valid-height",
                "0",
                "--storage-backend",
                "fjall",
                "--data-dir",
                "{data_dir}",
                "--output",
                "{result_path}",
            ],
            mimalloc=True,
        )
        core_program = _program(
            self.core,
            AdapterKind.BITCOIN_CORE_LOADBLOCK,
            [
                str(self.core),
                "-assumevalid=0",
                "-blocksxor=0",
                "-connect=0",
                "-datadir={data_dir}",
                "-debuglogfile={result_path}",
                "-disablewallet=1",
                "-dnsseed=0",
                "-fixedseeds=0",
                "-listen=0",
                "-loadblock={corpus_path}",
                "-server=1",
                "-stopatheight=2",
            ],
            mimalloc=False,
        )
        proof = _proof(
            self.corpus,
            self.manifest,
            candidate_program,
            core_program,
            affinity=affinity,
            candidate_identity="f" * 64 if bad_proof_identity else None,
        )
        self.proof = workspace / "cell-proof.json"
        self.proof.write_text(json.dumps(proof), encoding="utf-8")
        cells: list[object] = []
        for cell in ALL_CELLS:
            ready = cell == TARGET
            cells.append(
                {
                    "cell": {
                        "domain": cell.domain.value,
                        "corpus": cell.corpus.value,
                        "architecture": cell.architecture.value,
                        "backend": cell.backend.value,
                    },
                    "blocked_reason": None if ready else "not configured",
                    "candidate": candidate_program,
                    "core": core_program,
                    "corpus_path": str(self.corpus),
                    "corpus_sha256": _sha256(self.corpus),
                    "manifest_path": str(self.manifest),
                    "manifest_sha256": _sha256(self.manifest),
                    "proof_path": str(self.proof) if ready else None,
                    "proof_sha256": _sha256(self.proof) if ready else None,
                    "affinity": list(affinity),
                }
            )
        config: JsonObject = {
            "schema": "benchmark-campaign-config-v2",
            "schedule_seed": 42,
            "output_root": str(workspace / "out"),
            "cells": cells,
        }
        self.config = workspace / "config.json"
        self.config.write_text(json.dumps(config), encoding="utf-8")

    def run(self) -> tuple[runner.CellResult, Path]:
        return run_cell(load_config(self.config), TARGET)


class WorkspaceTestCase(unittest.TestCase):
    _temporary: tempfile.TemporaryDirectory[str]
    workspace: Path

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self._temporary.name).resolve()
        machine_patcher = patch.object(
            runner.platform, "machine", return_value="x86_64"
        )
        machine_patcher.start()
        self.addCleanup(machine_patcher.stop)

    def tearDown(self) -> None:
        self._temporary.cleanup()


class UniverseAndScheduleTests(unittest.TestCase):
    def test_exact_cell_universe(self) -> None:
        self.assertEqual(len(ALL_CELLS), 36)
        self.assertEqual(len(set(ALL_CELLS)), 36)

    def test_every_schedule_has_seven_balanced_pairs(self) -> None:
        for cell in ALL_CELLS:
            schedule = schedule_for(cell, 42)
            self.assertEqual(len(schedule), PAIR_COUNT)
            self.assertTrue(all(set(pair) == set(runner.Role) for pair in schedule))
            candidate_first = sum(pair[0] is runner.Role.CANDIDATE for pair in schedule)
            self.assertIn(candidate_first, (3, 4))

    def test_ratio_boundary_is_inclusive(self) -> None:
        candidate, core, ratio, verdict = classify_wall_performance(
            [10] * PAIR_COUNT, [20] * PAIR_COUNT
        )
        self.assertEqual((candidate, core, ratio, verdict), (10, 20, 2.0, Verdict.PASS))


class ConfigContractTests(WorkspaceTestCase):
    def test_unknown_adapter_is_rejected(self) -> None:
        fixture = CampaignFixture(self.workspace)
        raw = _object(json.loads(fixture.config.read_text(encoding="utf-8")))
        cells = _array(raw["cells"])
        first = _object(cells[0])
        candidate = _object(first["candidate"])
        candidate["adapter"] = "wrapper"
        with self.assertRaisesRegex(ContractError, "unsupported value"):
            parse_config(raw)

    def test_adapter_requires_every_exact_placeholder(self) -> None:
        fixture = CampaignFixture(self.workspace)
        raw = _object(json.loads(fixture.config.read_text(encoding="utf-8")))
        first = _object(_array(raw["cells"])[0])
        candidate = _object(first["candidate"])
        command = _array(candidate["command"])
        candidate["command"] = [
            value for value in command if value != "{manifest_path}"
        ]
        with self.assertRaisesRegex(ContractError, "must use exactly"):
            parse_config(raw)

    def test_timed_candidate_has_no_validation_output(self) -> None:
        fixture = CampaignFixture(self.workspace)
        campaign = load_config(fixture.config)
        self.assertNotIn("--validation-output", campaign.cells[0].candidate.command)

    def test_validation_output_is_rejected_before_timing(self) -> None:
        fixture = CampaignFixture(self.workspace)
        raw = _object(json.loads(fixture.config.read_text(encoding="utf-8")))
        first = _object(_array(raw["cells"])[0])
        candidate = _object(first["candidate"])
        command = _array(candidate["command"])
        candidate["command"] = [*command, "--validation-output", "/tmp/validation"]
        proof = _object(json.loads(fixture.proof.read_text(encoding="utf-8")))
        proof_candidate = _object(proof["candidate"])
        proof_candidate["program_identity_sha256"] = _canonical_sha256(candidate)
        fixture.proof.write_text(json.dumps(proof), encoding="utf-8")
        first["proof_sha256"] = _sha256(fixture.proof)
        fixture.config.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "must not include"):
            fixture.run()

    def test_ready_cell_requires_proof(self) -> None:
        fixture = CampaignFixture(self.workspace)
        raw = _object(json.loads(fixture.config.read_text(encoding="utf-8")))
        first = _object(_array(raw["cells"])[0])
        first["proof_path"] = None
        first["proof_sha256"] = None
        with self.assertRaisesRegex(ContractError, "requires a proof"):
            parse_config(raw)

    def test_proof_must_bind_exact_program_identity(self) -> None:
        fixture = CampaignFixture(self.workspace, bad_proof_identity=True)
        with self.assertRaisesRegex(ContractError, "candidate identity"):
            fixture.run()


class NativeExecutionTests(WorkspaceTestCase):
    def test_complete_seven_pair_run_and_round_trip(self) -> None:
        fixture = CampaignFixture(self.workspace)
        result, result_path = fixture.run()
        self.assertEqual(result.scheduled_pairs, PAIR_COUNT)
        self.assertEqual(result.valid_pairs, PAIR_COUNT)
        self.assertTrue(all(pair.correctness_match for pair in result.pairs))
        self.assertEqual(result.proof_scope, "role_cell_product")
        validated = validate_result(result_path, fixture.config)
        self.assertEqual(validated, result)
        for pair in result.pairs:
            for arm in (pair.candidate, pair.core):
                self.assertGreater(arm.wall_ns or 0, 0)
                self.assertGreater(arm.peak_rss_bytes or 0, 0)
                executed = Path(arm.data_dir, "executed.txt").read_text(
                    encoding="utf-8"
                )
                self.assertEqual(executed, arm.command[0])
                self.assertRegex(executed, r"\A/proc/self/fd/[0-9]+\Z")

    def test_run_closes_all_pinned_descriptors(self) -> None:
        before = len(tuple(Path("/proc/self/fd").iterdir()))
        CampaignFixture(self.workspace).run()
        after = len(tuple(Path("/proc/self/fd").iterdir()))
        self.assertEqual(after, before)

    def test_core_prepare_exception_closes_candidate_descriptor(self) -> None:
        fixture = CampaignFixture(self.workspace)
        original_prepare = runner._prepare_program  # pyright: ignore[reportPrivateUsage]
        candidate_descriptor: int | None = None

        def fail_core_prepare(
            program: runner.ProgramIdentity, role: runner.Role, run_dir: Path
        ) -> runner.ProgramCustody:
            nonlocal candidate_descriptor
            if role is runner.Role.CORE:
                raise OSError("core preparation failed")
            custody = original_prepare(program, role, run_dir)
            if isinstance(custody, runner.PreparedProgram):
                candidate_descriptor = custody.descriptor
            return custody

        with (
            patch.object(runner, "_prepare_program", fail_core_prepare),
            self.assertRaisesRegex(OSError, "core preparation failed"),
        ):
            fixture.run()
        self.assertIsNotNone(candidate_descriptor)
        with self.assertRaises(OSError):
            os.fstat(candidate_descriptor or -1)

    def test_path_taskset_interposition_is_ignored(self) -> None:
        fixture = CampaignFixture(self.workspace)
        fake_bin = self.workspace / "fake-bin"
        fake_bin.mkdir()
        marker = self.workspace / "taskset-ran"
        _write_executable(
            fake_bin / "taskset",
            f"#!/bin/sh\nprintf ran > {marker}\nexit 99\n",
        )
        with patch.dict(os.environ, {"PATH": f"{fake_bin}:{os.environ['PATH']}"}):
            result, _path = fixture.run()
        self.assertEqual(result.valid_pairs, PAIR_COUNT)
        self.assertFalse(marker.exists())

    def test_child_affinity_is_applied_without_a_launcher(self) -> None:
        parent_affinity = os.sched_getaffinity(0)
        affinity = (max(parent_affinity),)
        result, _path = CampaignFixture(self.workspace, affinity=affinity).run()
        self.assertEqual(os.sched_getaffinity(0), parent_affinity)
        for pair in result.pairs:
            for arm in (pair.candidate, pair.core):
                observed = json.loads(
                    Path(arm.data_dir, "affinity.json").read_text(encoding="utf-8")
                )
                self.assertEqual(observed, list(affinity))

    def test_unavailable_child_affinity_fails_the_run(self) -> None:
        unavailable = max(os.sched_getaffinity(0)) + 1
        result, _path = CampaignFixture(self.workspace, affinity=(unavailable,)).run()
        self.assertEqual(result.valid_pairs, 0)
        self.assertEqual(result.verdict, Verdict.FAIL_RUN)

    def test_spawn_failure_restores_parent_affinity(self) -> None:
        parent_affinity = os.sched_getaffinity(0)
        if len(parent_affinity) < 2:
            self.skipTest("affinity restoration needs a strict CPU subset")
        affinity = (min(parent_affinity),)
        fixture = CampaignFixture(self.workspace, affinity=affinity)
        with patch.object(
            runner.subprocess, "Popen", side_effect=OSError("spawn failed")
        ):
            result, _path = fixture.run()
        self.assertEqual(os.sched_getaffinity(0), parent_affinity)
        self.assertEqual(result.verdict, Verdict.FAIL_RUN)

    def test_affinity_readback_mismatch_rejects_before_spawn(self) -> None:
        parent_affinity = frozenset({0, 1, 2})
        configured = (0, 1)
        configured_set = frozenset(configured)
        fixture = CampaignFixture(self.workspace, affinity=configured)
        current_affinity = parent_affinity

        def mock_setaffinity(
            _pid: int, mask: tuple[int, ...] | frozenset[int]
        ) -> None:
            nonlocal current_affinity
            requested = frozenset(mask)
            current_affinity = (
                frozenset({configured[0]})
                if requested == configured_set
                else requested
            )

        def mock_getaffinity(_pid: int) -> frozenset[int]:
            return current_affinity

        with (
            patch.object(os, "sched_setaffinity", side_effect=mock_setaffinity),
            patch.object(os, "sched_getaffinity", side_effect=mock_getaffinity),
            patch.object(runner.subprocess, "Popen") as popen,
        ):
            result, _path = fixture.run()

        popen.assert_not_called()
        self.assertEqual(current_affinity, parent_affinity)
        self.assertEqual(result.verdict, Verdict.FAIL_RUN)

    def test_restore_swap_consumes_pinned_corpus_before_detection(self) -> None:
        fixture = CampaignFixture(self.workspace, restore_swap_input=True)
        expected = _sha256(fixture.corpus)
        result, result_path = fixture.run()
        self.assertEqual(result.verdict, Verdict.FAIL_RUN)
        consumed = [
            path.read_text(encoding="ascii")
            for pair in result.pairs
            if (path := Path(pair.candidate.data_dir, "consumed.sha256")).is_file()
        ]
        self.assertTrue(consumed)
        self.assertEqual(set(consumed), {expected})
        self.assertEqual(validate_result(result_path, fixture.config), result)

    def test_zero_candidate_witness_fails_correctness(self) -> None:
        result, _path = CampaignFixture(self.workspace, candidate_witness=0).run()
        self.assertEqual(result.valid_pairs, PAIR_COUNT)
        self.assertEqual(result.verdict, Verdict.FAIL_CORRECTNESS)

    def test_wrong_candidate_tip_fails_correctness(self) -> None:
        result, _path = CampaignFixture(self.workspace, candidate_hash="c" * 64).run()
        self.assertEqual(result.verdict, Verdict.FAIL_CORRECTNESS)

    def test_core_without_full_validation_marker_fails_correctness(self) -> None:
        result, _path = CampaignFixture(
            self.workspace, core_full_validation=False
        ).run()
        self.assertEqual(result.verdict, Verdict.FAIL_CORRECTNESS)

    def test_core_update_tip_gap_fails_correctness(self) -> None:
        result, _path = CampaignFixture(self.workspace, core_gap=True).run()
        self.assertEqual(result.verdict, Verdict.FAIL_CORRECTNESS)

    def test_incorrect_unpaired_arm_still_fails_correctness(self) -> None:
        for incorrect_role in (runner.Role.CANDIDATE, runner.Role.CORE):
            if incorrect_role is runner.Role.CANDIDATE:
                fixture = CampaignFixture(
                    self.workspace, candidate_hash="c" * 64, core_exit=7
                )
            else:
                fixture = CampaignFixture(
                    self.workspace, candidate_exit=7, core_hash="c" * 64
                )
            with self.subTest(incorrect_role=incorrect_role.value):
                result, result_path = fixture.run()
                self.assertEqual(result.valid_pairs, 0)
                self.assertTrue(
                    all(pair.correctness_match is False for pair in result.pairs)
                )
                self.assertEqual(result.verdict, Verdict.FAIL_CORRECTNESS)
                self.assertEqual(
                    validate_result(result_path, fixture.config),
                    result,
                )

    def test_native_process_failure_is_not_replaced(self) -> None:
        result, _path = CampaignFixture(self.workspace, candidate_exit=7).run()
        self.assertEqual(result.scheduled_pairs, PAIR_COUNT)
        self.assertEqual(result.valid_pairs, 0)
        self.assertEqual(result.verdict, Verdict.FAIL_RUN)

    def test_malformed_native_evidence_fails_run(self) -> None:
        result, _path = CampaignFixture(self.workspace, candidate_malformed=True).run()
        self.assertEqual(result.verdict, Verdict.FAIL_RUN)

    def test_input_mutation_fails_run(self) -> None:
        result, _path = CampaignFixture(self.workspace, mutate_input=True).run()
        self.assertEqual(result.verdict, Verdict.FAIL_RUN)

    def test_native_parsing_happens_after_wait4(self) -> None:
        fixture = CampaignFixture(self.workspace)
        wait_completed = False
        original_wait = runner._wait_and_measure  # pyright: ignore[reportPrivateUsage]
        original_parse = runner._parse_native_result  # pyright: ignore[reportPrivateUsage]

        def observed_wait(
            process: runner.subprocess.Popen[bytes],
        ) -> tuple[int, int, int, int, int, int]:
            nonlocal wait_completed
            result = original_wait(process)
            wait_completed = True
            return result

        def guarded_parse(
            config: runner.CellConfig,
            proof: runner.CellProof,
            role: runner.Role,
            command: tuple[str, ...],
            data_dir: Path,
            result_path: Path,
            inputs: runner.InputCustody,
            paths: dict[str, str],
        ) -> runner.NativeArmResult:
            self.assertTrue(wait_completed)
            return original_parse(
                config, proof, role, command, data_dir, result_path, inputs, paths
            )

        with (
            patch.object(runner, "_wait_and_measure", observed_wait),
            patch.object(runner, "_parse_native_result", guarded_parse),
        ):
            fixture.run()


class EvidenceCustodyTests(WorkspaceTestCase):
    def test_role_executable_descriptor_must_not_change(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        raw = _object(json.loads(result_path.read_text(encoding="utf-8")))
        pair = _object(_array(raw["pairs"])[0])
        candidate = _object(pair["candidate"])
        command = _array(candidate["command"])
        command[0] = "/proc/self/fd/999"
        result_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "descriptor changed"):
            validate_result(result_path, fixture.config)

    def test_candidate_and_core_executable_descriptors_must_differ(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        raw = _object(json.loads(result_path.read_text(encoding="utf-8")))
        pairs = _array(raw["pairs"])
        first_pair = _object(pairs[0])
        candidate = _object(first_pair["candidate"])
        candidate_descriptor = _array(candidate["command"])[0]
        for pair_value in pairs:
            pair = _object(pair_value)
            core = _object(pair["core"])
            _array(core["command"])[0] = candidate_descriptor
        result_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "must be distinct"):
            validate_result(result_path, fixture.config)

    def test_reused_executable_and_input_descriptor_is_rejected(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        raw = _object(json.loads(result_path.read_text(encoding="utf-8")))
        pair = _object(_array(raw["pairs"])[0])
        candidate = _object(pair["candidate"])
        command = _array(candidate["command"])
        corpus_index = command.index("--blocks-file") + 1
        command[0] = command[corpus_index]
        result_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "reuses.*descriptor"):
            validate_result(result_path, fixture.config)

    def test_repeated_validation_closes_program_snapshots(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        before = len(tuple(Path("/proc/self/fd").iterdir()))
        for _ in range(3):
            validate_result(result_path, fixture.config)
        after = len(tuple(Path("/proc/self/fd").iterdir()))
        self.assertEqual(after, before)

    def test_result_file_must_remain_in_its_configured_run_directory(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        copied = self.workspace / "copied" / "custody-result.json"
        copied.parent.mkdir()
        copied.write_bytes(result_path.read_bytes())
        with self.assertRaisesRegex(ContractError, "output_root"):
            validate_result(copied, fixture.config)

    def test_tampered_native_evidence_is_rejected(self) -> None:
        fixture = CampaignFixture(self.workspace)
        result, result_path = fixture.run()
        Path(result.pairs[0].candidate.result_path).write_text("{}", encoding="utf-8")
        with self.assertRaises(ContractError):
            validate_result(result_path, fixture.config)

    def test_tampered_proof_is_rejected(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        fixture.proof.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "proof_path hash mismatch"):
            validate_result(result_path, fixture.config)

    def test_successful_arm_requires_complete_measurements(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        raw = _object(json.loads(result_path.read_text(encoding="utf-8")))
        for field in (
            "pid",
            "pid_starttime",
            "wall_ns",
            "cpu_user_ns",
            "cpu_system_ns",
            "peak_rss_bytes",
        ):
            with self.subTest(field=field):
                mutated = _object(json.loads(json.dumps(raw)))
                pair = _object(_array(mutated["pairs"])[0])
                candidate = _object(pair["candidate"])
                candidate[field] = None
                result_path.write_text(json.dumps(mutated), encoding="utf-8")
                with self.assertRaisesRegex(ContractError, "valid was tampered"):
                    validate_result(result_path, fixture.config)

    def test_post_wait_parse_latency_is_not_in_arm_wall(self) -> None:
        fixture = CampaignFixture(self.workspace)
        original_parse = runner._parse_native_result  # pyright: ignore[reportPrivateUsage]

        def slow_parse(
            config: runner.CellConfig,
            proof: runner.CellProof,
            role: runner.Role,
            command: tuple[str, ...],
            data_dir: Path,
            result_path: Path,
            inputs: runner.InputCustody,
            paths: dict[str, str],
        ) -> runner.NativeArmResult:
            time.sleep(0.03)
            return original_parse(
                config, proof, role, command, data_dir, result_path, inputs, paths
            )

        started = time.monotonic()
        with patch.object(runner, "_parse_native_result", slow_parse):
            result, _path = fixture.run()
        elapsed = time.monotonic() - started
        walls = [
            arm.wall_ns or 0
            for pair in result.pairs
            for arm in (pair.candidate, pair.core)
        ]
        self.assertGreater(elapsed, 0.42)
        self.assertLess(max(walls), 500_000_000)


class HostArchitectureTests(WorkspaceTestCase):
    def test_x86_cell_rejects_aarch64_host(self) -> None:
        fixture = CampaignFixture(self.workspace)
        with patch.object(runner, "_host_architecture", return_value=Architecture.AARCH64):
            with self.assertRaisesRegex(ContractError, "requires x86_64.*host is aarch64"):
                fixture.run()

    def test_aarch64_cell_rejects_x86_host(self) -> None:
        fixture = CampaignFixture(self.workspace)
        raw = _object(json.loads(fixture.config.read_text(encoding="utf-8")))
        cells = _array(raw["cells"])
        aarch64_cell = runner.CellId(
            runner.Domain.OFFLINE,
            runner.Corpus.C150,
            Architecture.AARCH64,
            runner.Backend.FJALL,
        )
        for cell_entry in cells:
            entry = _object(cell_entry)
            cell_obj = _object(entry["cell"])
            if (
                cell_obj["architecture"] == "aarch64"
                and cell_obj["corpus"] == "c150"
                and cell_obj["domain"] == "offline"
            ):
                entry["blocked_reason"] = None
                entry["proof_path"] = str(fixture.proof)
                entry["proof_sha256"] = _sha256(fixture.proof)
            elif (
                cell_obj["architecture"] == "x86_64"
                and cell_obj["corpus"] == "c150"
                and cell_obj["domain"] == "offline"
            ):
                entry["blocked_reason"] = "not configured"
                entry["proof_path"] = None
                entry["proof_sha256"] = None
        fixture.config.write_text(json.dumps(raw), encoding="utf-8")
        with patch.object(runner, "_host_architecture", return_value=Architecture.X86_64):
            with self.assertRaisesRegex(ContractError, "requires aarch64.*host is x86_64"):
                run_cell(load_config(fixture.config), aarch64_cell)

    def test_matching_architecture_proceeds(self) -> None:
        fixture = CampaignFixture(self.workspace)
        with patch.object(runner.platform, "machine", return_value="AMD64"):
            result, _path = fixture.run()
        self.assertEqual(result.valid_pairs, PAIR_COUNT)


class FixedChildEnvTests(WorkspaceTestCase):
    def test_hostile_parent_variable_does_not_reach_child(self) -> None:
        fixture = CampaignFixture(self.workspace)
        with patch.dict(os.environ, {"BENCHMARK_HOSTILE": "pwned"}):
            result, _path = fixture.run()
        self.assertEqual(result.valid_pairs, PAIR_COUNT)
        for pair in result.pairs:
            for arm in (pair.candidate, pair.core):
                child_env = _object(
                    json.loads(
                        Path(arm.data_dir, "environment.json").read_text(
                            encoding="utf-8"
                        )
                    )
                )
                self.assertNotIn("BENCHMARK_HOSTILE", child_env)
                self.assertNotIn("PATH", child_env)
                self.assertEqual(child_env.get("LC_ALL"), "C")
                self.assertEqual(child_env.get("TZ"), "UTC")

    def test_child_process_runs_without_path(self) -> None:
        fixture = CampaignFixture(self.workspace)
        result, _path = fixture.run()
        self.assertEqual(result.valid_pairs, PAIR_COUNT)
        for pair in result.pairs:
            for arm in (pair.candidate, pair.core):
                self.assertTrue(
                    Path(arm.data_dir, "executed.txt").is_file(),
                    "child process must execute successfully without PATH",
                )


class ScheduleSeedValidationTests(WorkspaceTestCase):
    def test_mismatched_schedule_seed_is_rejected(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        raw = _object(json.loads(result_path.read_text(encoding="utf-8")))
        raw["schedule_seed"] = 999
        result_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(ContractError, "schedule seed does not match"):
            validate_result(result_path, fixture.config)


class DescriptorLifetimeTests(WorkspaceTestCase):
    def test_descriptors_open_during_evidence_verification(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        checked: list[bool] = []
        original = runner._verify_recorded_evidence  # pyright: ignore[reportPrivateUsage]

        def assert_open(
            observation: runner.ArmObservation,
            config: runner.CellConfig,
            proof: runner.CellProof,
            inputs: runner.InputCustody,
            paths: dict[str, str],
        ) -> None:
            for descriptor in (
                inputs.corpus.descriptor,
                inputs.manifest.descriptor,
                inputs.proof.descriptor,
            ):
                os.fstat(descriptor)
            checked.append(True)
            original(observation, config, proof, inputs, paths)

        with patch.object(runner, "_verify_recorded_evidence", assert_open):
            validate_result(result_path, fixture.config)
        self.assertTrue(checked)
        self.assertEqual(len(checked), PAIR_COUNT * 2)

    def test_final_validation_rechecks_input_path_custody(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        original = runner._verify_recorded_evidence  # pyright: ignore[reportPrivateUsage]
        checked = 0

        def replace_after_final_evidence_check(
            observation: runner.ArmObservation,
            config: runner.CellConfig,
            proof: runner.CellProof,
            inputs: runner.InputCustody,
            paths: dict[str, str],
        ) -> None:
            nonlocal checked
            original(observation, config, proof, inputs, paths)
            checked += 1
            if checked == PAIR_COUNT * 2:
                held = fixture.corpus.with_name("held-corpus.bin")
                fixture.corpus.rename(held)
                fixture.corpus.write_bytes(held.read_bytes())

        with (
            patch.object(
                runner,
                "_verify_recorded_evidence",
                replace_after_final_evidence_check,
            ),
            self.assertRaisesRegex(ContractError, "corpus_path changed"),
        ):
            validate_result(result_path, fixture.config)
        self.assertEqual(checked, PAIR_COUNT * 2)

    def test_error_path_closes_input_descriptors(self) -> None:
        fixture = CampaignFixture(self.workspace)
        _result, result_path = fixture.run()
        raw = _object(json.loads(result_path.read_text(encoding="utf-8")))
        raw["proof_sha256"] = "0" * 64
        result_path.write_text(json.dumps(raw), encoding="utf-8")
        before = len(tuple(Path("/proc/self/fd").iterdir()))
        with self.assertRaises(ContractError):
            validate_result(result_path, fixture.config)
        after = len(tuple(Path("/proc/self/fd").iterdir()))
        self.assertEqual(after, before)

    def test_native_evidence_retained_through_result_publication(self) -> None:
        fixture = CampaignFixture(self.workspace)
        original = runner._atomic_write_json  # pyright: ignore[reportPrivateUsage]
        publication_checks: list[int] = []

        def mutate_then_publish(path: Path, value: object) -> None:
            result_files = tuple(sorted(path.parent.glob("pair-*/replay.json"))) + tuple(
                sorted(path.parent.glob("pair-*/debug.log"))
            )
            self.assertEqual(len(result_files), PAIR_COUNT * 2)
            open_targets: set[Path] = set()
            for descriptor in Path("/proc/self/fd").iterdir():
                try:
                    target = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                if target.startswith("/"):
                    open_targets.add(Path(target))
            self.assertTrue(set(result_files) <= open_targets)
            with result_files[0].open("ab") as stream:
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            publication_checks.append(len(result_files))
            original(path, value)

        before = len(tuple(Path("/proc/self/fd").iterdir()))
        with patch.object(runner, "_atomic_write_json", mutate_then_publish):
            with self.assertRaisesRegex(ContractError, "native evidence changed"):
                fixture.run()
        after = len(tuple(Path("/proc/self/fd").iterdir()))
        self.assertEqual(publication_checks, [PAIR_COUNT * 2])
        self.assertEqual(after, before)

    def test_native_evidence_closes_when_parser_raises(self) -> None:
        fixture = CampaignFixture(self.workspace)

        def fail_parse(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("unexpected parser failure")

        before = len(tuple(Path("/proc/self/fd").iterdir()))
        with patch.object(runner, "_parse_native_result", fail_parse):
            with self.assertRaisesRegex(RuntimeError, "unexpected parser failure"):
                fixture.run()
        after = len(tuple(Path("/proc/self/fd").iterdir()))
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
