#!/usr/bin/env python3
# pyright: strict
"""Strict native evidence contracts for offline benchmark cells."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TypeIs

CELL_PROOF_SCHEMA = "benchmark-campaign-cell-proof-v1"
REPLAY_SCHEMA = "mainnet-prefix-replay-v3"
PROOF_SCOPE = "role_cell_product"
MAINNET_MAGIC = "f9beb4d9"
MAINNET_GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_CORE_VERSION_RE = re.compile(r"^\S+ Bitcoin Core version v31\.1\.0 \(release build\)$")
_CORE_ARG_RE = re.compile(r'^\S+ Command-line arg: ([a-z0-9]+)="(.*)"$')
_CORE_TIP_RE = re.compile(
    r"^\S+ UpdateTip: new best=([0-9a-f]{64}) height=([0-9]+)(?:\s|$)"
)
_REPLAY_KEYS = frozenset(
    {
        "schema",
        "network",
        "network_magic",
        "genesis_hash",
        "start_height",
        "start_hash",
        "stop_height",
        "stop_hash",
        "block_count",
        "window",
        "assume_valid_height",
        "window_verify_success_total",
        "corpus_manifest",
        "archive",
        "block_bytes",
        "block_source",
        "blocks_per_second",
        "checkpoint_generation",
        "data_dir",
        "decode_seconds",
        "elapsed_seconds",
        "fetch_seconds",
        "git_head",
        "measurement_target",
        "rss_high_water_bytes",
        "stage_seconds",
        "storage_backend",
        "tx_count",
        "txindex",
        "txindex_worker_catchup_seconds",
        "txindex_total_elapsed_seconds",
    }
)


class ContractError(ValueError):
    """Untrusted benchmark evidence violates its executable contract."""


class AdapterKind(str, Enum):
    BITCOIN_RS_REPLAY = "bitcoin_rs_replay_v3"
    BITCOIN_CORE_LOADBLOCK = "bitcoin_core_loadblock_v31"


ADAPTER_PLACEHOLDERS: dict[AdapterKind, frozenset[str]] = {
    AdapterKind.BITCOIN_RS_REPLAY: frozenset(
        {"data_dir", "corpus_path", "manifest_path", "result_path"}
    ),
    AdapterKind.BITCOIN_CORE_LOADBLOCK: frozenset(
        {"data_dir", "corpus_path", "result_path"}
    ),
}


@dataclass(frozen=True)
class CertifiedState:
    height: int
    bestblock: str
    txouts: int
    total_amount_sat: int
    muhash: str
    utxo_hash_serialized_3: str


@dataclass(frozen=True)
class ProofExpectation:
    cell_key: str
    corpus_sha256: str
    corpus_bytes: int
    manifest_sha256: str
    manifest_bytes: int
    affinity: tuple[int, ...]
    candidate_program_sha256: str
    core_program_sha256: str


@dataclass(frozen=True)
class CellProof:
    sha256: str
    scope: str
    runtime_dispatch: str
    state: CertifiedState
    candidate_durability_ok: bool
    core_durability_ok: bool


@dataclass(frozen=True)
class CandidateExpectation:
    state: CertifiedState
    data_dir: str
    corpus_path: str
    corpus_sha256: str
    corpus_bytes: int
    manifest_path: str
    manifest_sha256: str
    manifest_bytes: int
    backend: str
    commit: str


@dataclass(frozen=True)
class CoreExpectation:
    state: CertifiedState
    expected_args: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class NativeArmResult:
    height: int
    bestblock: str
    full_validation_witness: int
    evidence_sha256: str
    evidence_bytes: int
    correctness_ok: bool
    environment_valid: bool
    environment_reason: str | None


def _is_object(value: object) -> TypeIs[dict[str, object]]:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in value)  # pyright: ignore[reportUnknownVariableType]


def _is_array(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _object(value: object, field: str, keys: frozenset[str]) -> dict[str, object]:
    if not _is_object(value):
        raise ContractError(f"{field} must be a JSON object")
    actual = frozenset(value)
    if actual != keys:
        raise ContractError(
            f"{field} has wrong keys; missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def _array(value: object, field: str) -> list[object]:
    if not _is_array(value):
        raise ContractError(f"{field} must be an array")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{field} must be a nonempty string")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{field} must be a boolean")
    return value


def _uint(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a nonnegative integer")
    return value


def _finite_float(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, float):
        raise ContractError(f"{field} must be a float")
    if not math.isfinite(value) or value < 0.0:
        raise ContractError(f"{field} must be finite and nonnegative")
    return value


def _optional_finite_float(value: object, field: str) -> None:
    if value is not None:
        _finite_float(value, field)


def _hash(value: object, field: str) -> str:
    text = _text(value, field)
    if _HASH_RE.fullmatch(text) is None:
        raise ContractError(f"{field} must be a lowercase SHA-256")
    return text


def _state(value: object, field: str) -> CertifiedState:
    item = _object(
        value,
        field,
        frozenset(
            {
                "height",
                "bestblock",
                "txouts",
                "total_amount_sat",
                "muhash",
                "utxo_hash_serialized_3",
            }
        ),
    )
    return CertifiedState(
        height=_uint(item["height"], f"{field}.height"),
        bestblock=_hash(item["bestblock"], f"{field}.bestblock"),
        txouts=_uint(item["txouts"], f"{field}.txouts"),
        total_amount_sat=_uint(item["total_amount_sat"], f"{field}.total_amount_sat"),
        muhash=_hash(item["muhash"], f"{field}.muhash"),
        utxo_hash_serialized_3=_hash(
            item["utxo_hash_serialized_3"], f"{field}.utxo_hash_serialized_3"
        ),
    )


def state_from_json(value: object, field: str) -> CertifiedState:
    return _state(value, field)


def state_json(state: CertifiedState) -> dict[str, object]:
    return {
        "height": state.height,
        "bestblock": state.bestblock,
        "txouts": state.txouts,
        "total_amount_sat": state.total_amount_sat,
        "muhash": state.muhash,
        "utxo_hash_serialized_3": state.utxo_hash_serialized_3,
    }


def parse_cell_proof(
    path: Path, expected_sha256: str, expected: ProofExpectation
) -> CellProof:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ContractError(f"cannot read cell proof {path}: {error}") from error
    observed_sha256 = hashlib.sha256(payload).hexdigest()
    if observed_sha256 != expected_sha256:
        raise ContractError(
            f"cell proof hash mismatch: expected {expected_sha256}, got {observed_sha256}"
        )
    try:
        raw: object = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot parse cell proof {path}: {error}") from error
    item = _object(
        raw,
        "cell_proof",
        frozenset(
            {
                "schema",
                "scope",
                "cell",
                "inputs",
                "affinity",
                "runtime_dispatch",
                "expected_state",
                "candidate",
                "core",
            }
        ),
    )
    if _text(item["schema"], "cell_proof.schema") != CELL_PROOF_SCHEMA:
        raise ContractError(f"cell_proof.schema must be {CELL_PROOF_SCHEMA!r}")
    if _text(item["scope"], "cell_proof.scope") != PROOF_SCOPE:
        raise ContractError(f"cell_proof.scope must be {PROOF_SCOPE!r}")
    if _text(item["cell"], "cell_proof.cell") != expected.cell_key:
        raise ContractError("cell proof does not bind the configured cell")
    inputs = _object(
        item["inputs"],
        "cell_proof.inputs",
        frozenset(
            {"corpus_sha256", "corpus_bytes", "manifest_sha256", "manifest_bytes"}
        ),
    )
    input_binding = (
        _hash(inputs["corpus_sha256"], "cell_proof.inputs.corpus_sha256"),
        _uint(inputs["corpus_bytes"], "cell_proof.inputs.corpus_bytes"),
        _hash(inputs["manifest_sha256"], "cell_proof.inputs.manifest_sha256"),
        _uint(inputs["manifest_bytes"], "cell_proof.inputs.manifest_bytes"),
    )
    if input_binding != (
        expected.corpus_sha256,
        expected.corpus_bytes,
        expected.manifest_sha256,
        expected.manifest_bytes,
    ):
        raise ContractError("cell proof input identity does not match config")
    affinity = tuple(
        _uint(value, f"cell_proof.affinity[{index}]")
        for index, value in enumerate(_array(item["affinity"], "cell_proof.affinity"))
    )
    if affinity != expected.affinity:
        raise ContractError("cell proof affinity does not match config")
    state = _state(item["expected_state"], "cell_proof.expected_state")
    candidate = _object(
        item["candidate"],
        "cell_proof.candidate",
        frozenset(
            {
                "program_identity_sha256",
                "native_evidence_sha256",
                "validation_sha256",
                "durability_proof_sha256",
                "proof_tool_identity_sha256",
                "state",
                "durability_ok",
            }
        ),
    )
    core = _object(
        item["core"],
        "cell_proof.core",
        frozenset(
            {
                "program_identity_sha256",
                "native_evidence_sha256",
                "restart_log_sha256",
                "gettxoutsetinfo_sha256",
                "state",
                "restart_count",
                "durability_ok",
            }
        ),
    )
    if (
        _hash(
            candidate["program_identity_sha256"],
            "cell_proof.candidate.program_identity_sha256",
        )
        != expected.candidate_program_sha256
    ):
        raise ContractError("cell proof candidate identity does not match config")
    if (
        _hash(
            core["program_identity_sha256"], "cell_proof.core.program_identity_sha256"
        )
        != expected.core_program_sha256
    ):
        raise ContractError("cell proof Core identity does not match config")
    for field in (
        "native_evidence_sha256",
        "validation_sha256",
        "durability_proof_sha256",
        "proof_tool_identity_sha256",
    ):
        _hash(candidate[field], f"cell_proof.candidate.{field}")
    for field in (
        "native_evidence_sha256",
        "restart_log_sha256",
        "gettxoutsetinfo_sha256",
    ):
        _hash(core[field], f"cell_proof.core.{field}")
    candidate_state = _state(candidate["state"], "cell_proof.candidate.state")
    core_state = _state(core["state"], "cell_proof.core.state")
    if candidate_state != state or core_state != state:
        raise ContractError("cell proof role states do not equal expected_state")
    candidate_durability = _boolean(
        candidate["durability_ok"], "cell_proof.candidate.durability_ok"
    )
    core_durability = _boolean(core["durability_ok"], "cell_proof.core.durability_ok")
    if not candidate_durability or not core_durability:
        raise ContractError("cell proof requires successful durability for both roles")
    if _uint(core["restart_count"], "cell_proof.core.restart_count") < 1:
        raise ContractError("cell proof Core certification requires a restart")
    return CellProof(
        sha256=observed_sha256,
        scope=PROOF_SCOPE,
        runtime_dispatch=_text(item["runtime_dispatch"], "cell_proof.runtime_dispatch"),
        state=state,
        candidate_durability_ok=candidate_durability,
        core_durability_ok=core_durability,
    )


def _custody_ref(
    value: object, field: str, *, with_schema: bool
) -> tuple[str, int, str, str | None, int | None]:
    keys = {"path", "bytes", "sha256"}
    if with_schema:
        keys.update({"schema", "version"})
    item = _object(value, field, frozenset(keys))
    schema = _text(item["schema"], f"{field}.schema") if with_schema else None
    version = _uint(item["version"], f"{field}.version") if with_schema else None
    return (
        _text(item["path"], f"{field}.path"),
        _uint(item["bytes"], f"{field}.bytes"),
        _hash(item["sha256"], f"{field}.sha256"),
        schema,
        version,
    )


def _validate_stage_seconds(value: object) -> None:
    for index, entry in enumerate(_array(value, "replay.stage_seconds")):
        item = _object(
            entry,
            f"replay.stage_seconds[{index}]",
            frozenset({"count", "stage", "sum_seconds"}),
        )
        _uint(item["count"], f"replay.stage_seconds[{index}].count")
        _text(item["stage"], f"replay.stage_seconds[{index}].stage")
        _finite_float(item["sum_seconds"], f"replay.stage_seconds[{index}].sum_seconds")


def parse_candidate_file(path: Path, expected: CandidateExpectation) -> NativeArmResult:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ContractError(
            f"cannot read candidate evidence {path}: {error}"
        ) from error
    try:
        raw: object = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(
            f"cannot parse candidate evidence {path}: {error}"
        ) from error
    item = _object(raw, "replay", _REPLAY_KEYS)
    manifest = _custody_ref(
        item["corpus_manifest"], "replay.corpus_manifest", with_schema=True
    )
    archive = _custody_ref(item["archive"], "replay.archive", with_schema=False)
    height = _uint(item["stop_height"], "replay.stop_height")
    bestblock = _hash(item["stop_hash"], "replay.stop_hash")
    witness = _uint(
        item["window_verify_success_total"], "replay.window_verify_success_total"
    )
    block_count = _uint(item["block_count"], "replay.block_count")
    window = _uint(item["window"], "replay.window")
    checkpoint_generation = _uint(
        item["checkpoint_generation"], "replay.checkpoint_generation"
    )
    git_head = _text(item["git_head"], "replay.git_head")
    if _COMMIT_RE.fullmatch(git_head) is None:
        raise ContractError("replay.git_head must be a full lowercase Git commit")
    _uint(item["block_bytes"], "replay.block_bytes")
    _uint(item["rss_high_water_bytes"], "replay.rss_high_water_bytes")
    _uint(item["tx_count"], "replay.tx_count")
    for field in (
        "blocks_per_second",
        "decode_seconds",
        "elapsed_seconds",
        "fetch_seconds",
    ):
        _finite_float(item[field], f"replay.{field}")
    _optional_finite_float(
        item["txindex_worker_catchup_seconds"],
        "replay.txindex_worker_catchup_seconds",
    )
    _optional_finite_float(
        item["txindex_total_elapsed_seconds"],
        "replay.txindex_total_elapsed_seconds",
    )
    _validate_stage_seconds(item["stage_seconds"])
    correctness = all(
        (
            _text(item["schema"], "replay.schema") == REPLAY_SCHEMA,
            _text(item["measurement_target"], "replay.measurement_target")
            == "mainnet-prefix-replay",
            _text(item["network"], "replay.network") == "mainnet",
            _text(item["network_magic"], "replay.network_magic") == MAINNET_MAGIC,
            _hash(item["genesis_hash"], "replay.genesis_hash") == MAINNET_GENESIS,
            _uint(item["start_height"], "replay.start_height") == 0,
            _hash(item["start_hash"], "replay.start_hash") == MAINNET_GENESIS,
            height == expected.state.height,
            bestblock == expected.state.bestblock,
            block_count == height + 1,
            window > 1,
            _uint(item["assume_valid_height"], "replay.assume_valid_height") == 0,
            witness > 0,
            checkpoint_generation > 0,
            manifest
            == (
                expected.manifest_path,
                expected.manifest_bytes,
                expected.manifest_sha256,
                "bitcoin-rs-corpus-manifest",
                1,
            ),
            archive
            == (
                expected.corpus_path,
                expected.corpus_bytes,
                expected.corpus_sha256,
                None,
                None,
            ),
            _text(item["block_source"], "replay.block_source") == "file",
            not _boolean(item["txindex"], "replay.txindex"),
            _text(item["storage_backend"], "replay.storage_backend")
            == expected.backend,
            _text(item["data_dir"], "replay.data_dir") == expected.data_dir,
            git_head == expected.commit,
        )
    )
    return NativeArmResult(
        height=height,
        bestblock=bestblock,
        full_validation_witness=witness,
        evidence_sha256=hashlib.sha256(payload).hexdigest(),
        evidence_bytes=len(payload),
        correctness_ok=correctness,
        environment_valid=True,
        environment_reason=None,
    )


def _core_expected_args(command_args: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    parsed: list[tuple[str, str]] = []
    for argument in command_args:
        if not argument.startswith("-") or "=" not in argument:
            raise ContractError(
                "Core command arguments must use canonical -name=value syntax"
            )
        name, value = argument[1:].split("=", 1)
        if not name or not value or not name.isalnum():
            raise ContractError(f"invalid Core command argument {argument!r}")
        parsed.append((name.lower(), value))
    if len({name for name, _value in parsed}) != len(parsed):
        raise ContractError("Core command arguments must not repeat options")
    return tuple(sorted(parsed))


def core_expectation(
    state: CertifiedState, command_args: tuple[str, ...]
) -> CoreExpectation:
    return CoreExpectation(state=state, expected_args=_core_expected_args(command_args))


def parse_core_file(path: Path, expected: CoreExpectation) -> NativeArmResult:
    digest = hashlib.sha256()
    size = 0
    sessions = 0
    args: dict[str, str] = {}
    next_height = 0
    updates_contiguous = True
    final_height = -1
    final_hash = ""
    full_validation = False
    clean_shutdown_after_tip = False
    fatal_error = False
    try:
        stream = path.open("rb")
    except OSError as error:
        raise ContractError(f"cannot read Core evidence {path}: {error}") from error
    with stream:
        for line_number, raw_line in enumerate(stream, 1):
            digest.update(raw_line)
            size += len(raw_line)
            try:
                line = raw_line.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError as error:
                raise ContractError(
                    f"Core evidence line {line_number} is not UTF-8"
                ) from error
            if _CORE_VERSION_RE.fullmatch(line):
                sessions += 1
                continue
            argument = _CORE_ARG_RE.fullmatch(line)
            if argument is not None:
                name, value = argument.groups()
                if name in args:
                    raise ContractError(
                        f"Core log repeats command-line option {name!r}"
                    )
                args[name] = value
                continue
            update = _CORE_TIP_RE.match(line)
            if update is not None:
                block_hash, height_text = update.groups()
                height = int(height_text)
                if height != next_height:
                    updates_contiguous = False
                next_height = height + 1
                final_height = height
                final_hash = block_hash
                continue
            if line.endswith("Validating signatures for all blocks."):
                full_validation = True
            if line.endswith("Shutdown done") and final_height >= 0:
                clean_shutdown_after_tip = True
            if "ERROR:" in line or "Fatal error" in line:
                fatal_error = True
    if sessions != 1:
        raise ContractError("Core evidence must contain exactly one v31.1 session")
    if size == 0:
        raise ContractError("Core evidence is empty")
    observed_args = tuple(sorted(args.items()))
    expected_args = expected.expected_args
    correctness = all(
        (
            observed_args == expected_args,
            full_validation,
            updates_contiguous,
            next_height == expected.state.height + 1,
            final_height == expected.state.height,
            final_hash == expected.state.bestblock,
            clean_shutdown_after_tip,
            not fatal_error,
        )
    )
    return NativeArmResult(
        height=max(final_height, 0),
        bestblock=final_hash
        if _HASH_RE.fullmatch(final_hash) is not None
        else "0" * 64,
        full_validation_witness=next_height if full_validation else 0,
        evidence_sha256=digest.hexdigest(),
        evidence_bytes=size,
        correctness_ok=correctness,
        environment_valid=True,
        environment_reason=None,
    )


def arm_result_json(result: NativeArmResult) -> dict[str, object]:
    return {
        "height": result.height,
        "bestblock": result.bestblock,
        "full_validation_witness": result.full_validation_witness,
        "evidence_sha256": result.evidence_sha256,
        "evidence_bytes": result.evidence_bytes,
        "correctness_ok": result.correctness_ok,
        "environment_valid": result.environment_valid,
        "environment_reason": result.environment_reason,
    }


def arm_result_from_json(value: object, field: str) -> NativeArmResult:
    item = _object(
        value,
        field,
        frozenset(
            {
                "height",
                "bestblock",
                "full_validation_witness",
                "evidence_sha256",
                "evidence_bytes",
                "correctness_ok",
                "environment_valid",
                "environment_reason",
            }
        ),
    )
    reason_value = item["environment_reason"]
    reason = (
        None
        if reason_value is None
        else _text(reason_value, f"{field}.environment_reason")
    )
    environment_valid = _boolean(
        item["environment_valid"], f"{field}.environment_valid"
    )
    if environment_valid == (reason is not None):
        raise ContractError(
            f"{field}.environment_reason must exist exactly when environment is invalid"
        )
    return NativeArmResult(
        height=_uint(item["height"], f"{field}.height"),
        bestblock=_hash(item["bestblock"], f"{field}.bestblock"),
        full_validation_witness=_uint(
            item["full_validation_witness"], f"{field}.full_validation_witness"
        ),
        evidence_sha256=_hash(item["evidence_sha256"], f"{field}.evidence_sha256"),
        evidence_bytes=_uint(item["evidence_bytes"], f"{field}.evidence_bytes"),
        correctness_ok=_boolean(item["correctness_ok"], f"{field}.correctness_ok"),
        environment_valid=environment_valid,
        environment_reason=reason,
    )
