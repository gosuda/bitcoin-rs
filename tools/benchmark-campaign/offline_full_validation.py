#!/usr/bin/env python3.14
# pyright: strict
"""Strict offline full-validation comparator for Bitcoin Core and bitcoin-rs.

Both arms consume one hash-pinned Core-framed archive and one manifest,
start from a fresh native store, run full validation, persist bodies and
undo under the production durability contract, and exit only after a
clean durable shutdown. Wall time is an external monotonic interval from
process creation through that exit. A ratio is published only after every
custody and correctness gate passes.

Addresses issue #34. Implements the #46 parity contract.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, TypedDict, TypeIs

from p2p_loopback import ContractError as _P2PContractError
from p2p_loopback import _ChildSubreaperScope, _direct_children_pids

CONFIG_SCHEMA = "offline-full-validation-config-v1"
MANIFEST_SCHEMA = "core-framed-archive-manifest-v1"
RESULT_SCHEMA = "offline-full-validation-result-v1"
PAIR_COUNT = 7
HEADER_BYTES = 80
MAX_PAYLOAD_BYTES = 4_000_000
MAX_ARCHIVE_BYTES = 1 * 1024 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 512 * 1024 * 1024
MAX_CONFIG_BYTES = 1 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_COMMAND_ARGS = 256
MAX_BLOCKS = 2_000_000
MAX_ARM_TIMEOUT_NS = 4 * 60 * 60 * 1_000_000_000
MIN_ARM_TIMEOUT_NS = 1_000_000_000
CHILD_TERMINATE_GRACE_NS = 1_000_000_000
CHILD_KILL_REAP_NS = 1_000_000_000
_HASH_LENGTH = 64
CACHE_POLICIES = frozenset({"process-cold/page-cache-unspecified"})
_ASSUME_VALID_OFF_EQUAL = frozenset(
    {
        "-assumevalid=0",
        "--assumevalid=0",
        "-assume-valid=0",
        "--assume-valid=0",
        "-assume-valid-height=0",
        "--assume-valid-height=0",
    }
)
_ASSUME_VALID_OFF_FLAGS = frozenset(
    {
        "-assumevalid",
        "--assumevalid",
        "-assume-valid",
        "--assume-valid",
        "-assume-valid-height",
        "--assume-valid-height",
    }
)
_INDEX_ON_TOKENS = frozenset(
    {
        "-txindex",
        "-txindex=1",
        "-txindex=true",
        "--txindex",
        "--txindex=1",
        "--txindex=true",
        "-blockfilterindex",
        "-blockfilterindex=1",
        "-blockfilterindex=true",
        "--blockfilterindex",
        "--blockfilterindex=1",
        "--blockfilterindex=true",
        "-coinstatsindex",
        "-coinstatsindex=1",
        "-coinstatsindex=true",
        "--coinstatsindex",
        "--coinstatsindex=1",
        "--coinstatsindex=true",
    }
)
ALLOWED_PLACEHOLDERS = frozenset(
    {
        "{binary}",
        "{data_dir}",
        "{corpus_path}",
        "{manifest_path}",
        "{state_path}",
    }
)
_PUBLIC_PLACEHOLDERS = {
    "{binary}": "<binary>",
    "{data_dir}": "<data-dir>",
    "{corpus_path}": "<corpus-path>",
    "{manifest_path}": "<manifest-path>",
    "{state_path}": "<state-path>",
}
_ARGUMENT_MARKER = "<argument>"
_STATE_KEYS = frozenset(
    {
        "height",
        "bestblock",
        "txouts",
        "total_amount_sat",
        "muhash",
        "utxo_hash_serialized_3",
        "bodies_available",
        "disconnect_ready",
    }
)
_POSTURE_KEYS = frozenset(
    {
        "assume_valid",
        "txindex",
        "blockfilterindex",
        "coinstatsindex",
        "cache_policy",
    }
)
_PROGRAM_KEYS = frozenset(
    {"binary", "binary_sha256", "command", "reopen_command"}
)
_CORPUS_KEYS = frozenset({"archive", "manifest"})
_FILE_REF_KEYS = frozenset({"path", "sha256", "bytes"})
_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "network",
        "network_magic",
        "start_height",
        "stop_height",
        "archive_sha256",
        "archive_bytes",
        "blocks",
    }
)
_BLOCK_ENTRY_KEYS = frozenset({"height", "hash", "offset", "payload_length"})
_CONFIG_KEYS = frozenset(
    {
        "schema",
        "network_magic",
        "arm_timeout_ns",
        "posture",
        "corpus",
        "expected_state",
        "core",
        "candidate",
        "lifecycle",
    }
)
_LIFECYCLE_KEYS = frozenset({"mode", "expected_reopen_state"})

JsonObject = dict[str, object]


class ContractError(ValueError):
    """The comparator cannot make a controlled comparison."""


class Summary(TypedDict):
    samples: int
    p50_ns: int
    p95_ns: int
    p99_ns: int
    max_ns: int


@dataclass(frozen=True)
class FileRef:
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class FileIdentity:
    dev: int
    ino: int
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class PinnedCorpus:
    archive: FileRef
    archive_identity: FileIdentity
    manifest: FileRef
    manifest_identity: FileIdentity


@dataclass(frozen=True)
class BlockEntry:
    height: int
    block_hash: str
    offset: int
    payload_length: int


@dataclass(frozen=True)
class Manifest:
    network: str
    network_magic: bytes
    start_height: int
    stop_height: int
    archive_sha256: str
    archive_bytes: int
    blocks: tuple[BlockEntry, ...]


@dataclass(frozen=True)
class CertifiedState:
    height: int
    bestblock: str
    txouts: int
    total_amount_sat: int
    muhash: str
    utxo_hash_serialized_3: str
    bodies_available: bool
    disconnect_ready: bool


@dataclass(frozen=True)
class Posture:
    assume_valid: bool
    txindex: bool
    blockfilterindex: bool
    coinstatsindex: bool
    cache_policy: str


@dataclass(frozen=True)
class Program:
    role: str
    binary: Path
    binary_sha256: str
    command: tuple[str, ...]
    reopen_command: tuple[str, ...] | None


@dataclass(frozen=True)
class Config:
    network_magic: bytes
    arm_timeout_ns: int
    posture: Posture
    archive: FileRef
    archive_identity: FileIdentity
    manifest: FileRef
    manifest_document: Manifest
    expected_state: CertifiedState
    core: Program
    candidate: Program
    lifecycle_mode: str
    expected_reopen_state: CertifiedState | None
    canonical_sha256: str


@dataclass(frozen=True)
class ArmObservation:
    pair_index: int
    order_index: int
    role: str
    binary_sha256: str
    command_sha256: str
    command_arg_count: int
    reopen_command_sha256: str | None
    wall_ns: int
    cpu_ns: int
    peak_rss_bytes: int
    exit_code: int
    final_state: JsonObject
    final_state_sha256: str
    reopen_exit_code: int | None
    reopen_state: JsonObject | None
    reopen_state_sha256: str | None
    durability_ok: bool
    state_ok: bool
    error: str | None


def _is_object(value: object) -> TypeIs[JsonObject]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _object(value: object, field: str, keys: frozenset[str]) -> JsonObject:
    if not _is_object(value):
        raise ContractError(f"{field} must be a JSON object")
    actual = frozenset(value)
    if actual != keys:
        raise ContractError(
            f"{field} has wrong keys; missing_count={len(keys - actual)}, "
            f"unknown_count={len(actual - keys)}"
        )
    return value


def _array(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(f"{field} must be an array")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ContractError(f"{field} must be a nonempty NUL-free string")
    return value


def _uint(value: object, field: str, maximum: int = (1 << 63) - 1) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise ContractError(f"{field} must be an integer in [0, {maximum}]")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{field} must be a boolean")
    return value


def _hash(value: object, field: str) -> str:
    text = _text(value, field)
    if len(text) != _HASH_LENGTH or any(ch not in "0123456789abcdef" for ch in text):
        raise ContractError(f"{field} must be a lowercase SHA-256")
    return text


def _magic(value: object, field: str) -> bytes:
    text = _text(value, field)
    try:
        magic = bytes.fromhex(text)
    except ValueError as error:
        raise ContractError(f"{field} must be hexadecimal") from error
    if len(magic) != 4:
        raise ContractError(f"{field} must contain exactly four bytes")
    return magic


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as error:
        raise ContractError("value is not canonical JSON") from error


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _validate_json_depth(value: object, field: str) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError(f"{field} exceeds JSON depth limit {MAX_JSON_DEPTH}")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _open_regular(path: Path, field: str) -> int:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
    except OSError as error:
        raise ContractError(f"cannot open {field} {path}: {error}") from error
    try:
        info = os.fstat(descriptor)
    except OSError as error:
        os.close(descriptor)
        raise ContractError(f"cannot stat {field} {path}: {error}") from error
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise ContractError(f"{field} is not a regular file")
    return descriptor


def _load_json(path: Path, field: str, maximum_bytes: int) -> object:
    descriptor = _open_regular(path, field)
    owned = False
    try:
        info = os.fstat(descriptor)
        if info.st_size > maximum_bytes:
            raise ContractError(f"{field} exceeds byte limit {maximum_bytes}")
        with os.fdopen(descriptor, "rb") as stream:
            owned = True
            raw = stream.read(maximum_bytes + 1)
    except OSError as error:
        raise ContractError(f"cannot read {field} {path}") from error
    finally:
        if not owned:
            os.close(descriptor)
    if len(raw) > maximum_bytes:
        raise ContractError(f"{field} exceeds byte limit {maximum_bytes}")
    try:
        value: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContractError(f"{field} is not bounded valid JSON") from error
    _validate_json_depth(value, field)
    return value


def _file_ref(raw: object, field: str, maximum_bytes: int) -> FileRef:
    item = _object(raw, field, _FILE_REF_KEYS)
    path = Path(_text(item["path"], f"{field}.path")).absolute()
    digest = _hash(item["sha256"], f"{field}.sha256")
    size = _uint(item["bytes"], f"{field}.bytes", maximum_bytes)
    if size == 0:
        raise ContractError(f"{field}.bytes must be positive")
    return FileRef(path, digest, size)


def _identity_from_stat(info: os.stat_result, digest: str) -> FileIdentity:
    return FileIdentity(
        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, digest
    )


def header_hash(payload: bytes) -> str:
    """Display-hex of double-SHA256 of the 80-byte header.

    This is Bitcoin Core ``CBlockHeader::GetHash`` (``HashWriter`` over the
    header, then byte-reversed hex). Independent vector: the published
    mainnet genesis header hashes to
    ``000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f``
    (Bitcoin Core ``CMainParams``, bitcoin-rs ``MAINNET_GENESIS``).
    """
    if len(payload) < HEADER_BYTES:
        raise ContractError("block payload is shorter than a header")
    digest = hashlib.sha256(hashlib.sha256(payload[:HEADER_BYTES]).digest()).digest()
    return digest[::-1].hex()


def _parse_manifest(value: object, archive: FileRef, magic: bytes) -> Manifest:
    root = _object(value, "manifest", _MANIFEST_KEYS)
    if root["schema"] != MANIFEST_SCHEMA:
        raise ContractError(f"manifest.schema must be {MANIFEST_SCHEMA}")
    network = _text(root["network"], "manifest.network")
    documented_magic = _magic(root["network_magic"], "manifest.network_magic")
    if documented_magic != magic:
        raise ContractError("manifest network magic does not match the config")
    start = _uint(root["start_height"], "manifest.start_height")
    stop = _uint(root["stop_height"], "manifest.stop_height")
    if stop < start:
        raise ContractError("manifest stop_height is before start_height")
    archive_digest = _hash(root["archive_sha256"], "manifest.archive_sha256")
    archive_bytes = _uint(root["archive_bytes"], "manifest.archive_bytes", MAX_ARCHIVE_BYTES)
    if archive_digest != archive.sha256 or archive_bytes != archive.size:
        raise ContractError("manifest archive identity does not match the corpus FileRef")
    raw_blocks = _array(root["blocks"], "manifest.blocks")
    expected = stop - start + 1
    if not raw_blocks or len(raw_blocks) != expected or len(raw_blocks) > MAX_BLOCKS:
        raise ContractError("manifest.blocks must list every height exactly once")
    blocks: list[BlockEntry] = []
    cursor = 0
    for index, raw in enumerate(raw_blocks):
        item = _object(raw, f"manifest.blocks[{index}]", _BLOCK_ENTRY_KEYS)
        height = _uint(item["height"], f"manifest.blocks[{index}].height")
        if height != start + index:
            raise ContractError("manifest heights must be contiguous from start_height")
        offset = _uint(item["offset"], f"manifest.blocks[{index}].offset", MAX_ARCHIVE_BYTES)
        payload_length = _uint(
            item["payload_length"],
            f"manifest.blocks[{index}].payload_length",
            MAX_PAYLOAD_BYTES,
        )
        if payload_length < HEADER_BYTES:
            raise ContractError(f"manifest.blocks[{index}] payload is shorter than a header")
        if offset != cursor:
            raise ContractError(f"manifest.blocks[{index}] offset is not packed")
        record_length = 8 + payload_length
        if offset + record_length > archive.size:
            raise ContractError(f"manifest.blocks[{index}] overruns the archive")
        blocks.append(
            BlockEntry(
                height,
                _hash(item["hash"], f"manifest.blocks[{index}].hash"),
                offset,
                payload_length,
            )
        )
        cursor += record_length
    if cursor != archive.size:
        raise ContractError("manifest does not consume the archive exactly")
    return Manifest(
        network,
        documented_magic,
        start,
        stop,
        archive_digest,
        archive_bytes,
        tuple(blocks),
    )


def _verify_archive(archive: FileRef, manifest: Manifest, magic: bytes) -> FileIdentity:
    """Walk a Core ``blk*.dat`` stream: 4-byte message start, 4-byte LE size, block."""
    descriptor = _open_regular(archive.path, "archive")
    digest = hashlib.sha256()
    try:
        info = os.fstat(descriptor)
        if info.st_size != archive.size:
            raise ContractError("archive size does not match the FileRef")
        if info.st_size > MAX_ARCHIVE_BYTES:
            raise ContractError("archive exceeds MAX_ARCHIVE_BYTES")
        for index, entry in enumerate(manifest.blocks):
            header = os.read(descriptor, 8)
            if len(header) != 8:
                raise ContractError("archive ended inside a record header")
            digest.update(header)
            if header[:4] != magic:
                raise ContractError(f"archive record {index} has the wrong network magic")
            payload_length = int.from_bytes(header[4:], "little")
            if payload_length != entry.payload_length:
                raise ContractError(f"archive record {index} length does not match the manifest")
            payload = os.read(descriptor, payload_length)
            if len(payload) != payload_length:
                raise ContractError("archive ended inside a block payload")
            digest.update(payload)
            if header_hash(payload) != entry.block_hash:
                raise ContractError(f"archive record {index} header hash does not match the manifest")
        trailing = os.read(descriptor, 1)
        if trailing:
            raise ContractError("archive contains trailing bytes after the last record")
        observed = digest.hexdigest()
        if observed != archive.sha256:
            raise ContractError("archive digest does not match the FileRef")
        return _identity_from_stat(info, observed)
    except OSError as error:
        raise ContractError(f"cannot read archive: {error}") from error
    finally:
        os.close(descriptor)


def _hash_regular(path: Path, field: str) -> tuple[os.stat_result, str]:
    descriptor = _open_regular(path, field)
    digest = hashlib.sha256()
    try:
        info = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as error:
        raise ContractError(f"cannot hash {field}: {error}") from error
    finally:
        os.close(descriptor)
    return info, digest.hexdigest()


def _require_pin(path: Path, expected: FileIdentity, field: str) -> None:
    info, digest = _hash_regular(path, field)
    current = _identity_from_stat(info, digest)
    if (
        current.dev != expected.dev
        or current.ino != expected.ino
        or current.size != expected.size
        or current.mtime_ns != expected.mtime_ns
        or digest != expected.sha256
    ):
        raise ContractError(f"{field} changed after custody verification")


def _assert_pins(pinned: PinnedCorpus) -> None:
    _require_pin(pinned.archive.path, pinned.archive_identity, "archive")
    _require_pin(pinned.manifest.path, pinned.manifest_identity, "manifest")


def _certified_state(value: object, field: str) -> CertifiedState:
    item = _object(value, field, _STATE_KEYS)
    state = CertifiedState(
        _uint(item["height"], f"{field}.height"),
        _hash(item["bestblock"], f"{field}.bestblock"),
        _uint(item["txouts"], f"{field}.txouts"),
        _uint(item["total_amount_sat"], f"{field}.total_amount_sat"),
        _hash(item["muhash"], f"{field}.muhash"),
        _hash(item["utxo_hash_serialized_3"], f"{field}.utxo_hash_serialized_3"),
        _boolean(item["bodies_available"], f"{field}.bodies_available"),
        _boolean(item["disconnect_ready"], f"{field}.disconnect_ready"),
    )
    if not state.bodies_available or not state.disconnect_ready:
        raise ContractError(f"{field} must prove body availability and disconnect readiness")
    return state


def state_json(state: CertifiedState) -> JsonObject:
    return {
        "height": state.height,
        "bestblock": state.bestblock,
        "txouts": state.txouts,
        "total_amount_sat": state.total_amount_sat,
        "muhash": state.muhash,
        "utxo_hash_serialized_3": state.utxo_hash_serialized_3,
        "bodies_available": state.bodies_available,
        "disconnect_ready": state.disconnect_ready,
    }


def _posture(value: object) -> Posture:
    item = _object(value, "posture", _POSTURE_KEYS)
    posture = Posture(
        _boolean(item["assume_valid"], "posture.assume_valid"),
        _boolean(item["txindex"], "posture.txindex"),
        _boolean(item["blockfilterindex"], "posture.blockfilterindex"),
        _boolean(item["coinstatsindex"], "posture.coinstatsindex"),
        _text(item["cache_policy"], "posture.cache_policy"),
    )
    if posture.assume_valid:
        raise ContractError("full validation is mandatory; assume_valid must be false")
    if posture.txindex or posture.blockfilterindex or posture.coinstatsindex:
        raise ContractError("auxiliary indexes must be off")
    if posture.cache_policy not in CACHE_POLICIES:
        raise ContractError("posture.cache_policy is not a declared cache policy")
    return posture


def _assume_valid_is_off(parts: Sequence[str]) -> bool:
    if any(part in _ASSUME_VALID_OFF_EQUAL for part in parts):
        return True
    for index, part in enumerate(parts[:-1]):
        if part in _ASSUME_VALID_OFF_FLAGS and parts[index + 1] == "0":
            return True
    return False


def _require_timed_command_tokens(parts: Sequence[str], field: str) -> None:
    if not _assume_valid_is_off(parts):
        raise ContractError(
            f"{field} must disable assume-valid "
            "(-assumevalid=0 or --assume-valid-height=0)"
        )
    for part in parts:
        if part in _INDEX_ON_TOKENS:
            raise ContractError(f"{field} enables an auxiliary index ({part})")


def _command(
    raw: object, field: str, *, require_validation_tokens: bool
) -> tuple[str, ...]:
    parts = tuple(_text(part, field) for part in _array(raw, field))
    if not parts or len(parts) > MAX_COMMAND_ARGS:
        raise ContractError(f"{field} must contain 1 to {MAX_COMMAND_ARGS} arguments")
    if parts[0] != "{binary}":
        raise ContractError(f"{field}[0] must be {{binary}}")
    required = {"{data_dir}", "{corpus_path}", "{state_path}"}
    present = set(parts)
    if not required <= present:
        raise ContractError(f"{field} must name data_dir, corpus_path, and state_path")
    for part in parts:
        for start in range(len(part)):
            if part[start] == "{":
                end = part.find("}", start)
                if end < 0 or part[start : end + 1] not in ALLOWED_PLACEHOLDERS:
                    raise ContractError(f"{field} contains an unsupported placeholder")
    if require_validation_tokens:
        _require_timed_command_tokens(parts, field)
    return parts


def _program(raw: object, role: str, reopen_required: bool) -> Program:
    item = _object(raw, role, _PROGRAM_KEYS)
    command = _command(
        item["command"], f"{role}.command", require_validation_tokens=True
    )
    reopen_raw = item["reopen_command"]
    reopen: tuple[str, ...] | None = None
    if reopen_raw is not None:
        reopen = _command(
            reopen_raw, f"{role}.reopen_command", require_validation_tokens=False
        )
    elif reopen_required:
        raise ContractError(f"{role}.reopen_command is required for reopen lifecycle")
    return Program(
        role,
        Path(_text(item["binary"], f"{role}.binary")).absolute(),
        _hash(item["binary_sha256"], f"{role}.binary_sha256"),
        command,
        reopen,
    )


def parse_config(value: object) -> Config:
    root = _object(value, "config", _CONFIG_KEYS)
    if root["schema"] != CONFIG_SCHEMA:
        raise ContractError(f"config.schema must be {CONFIG_SCHEMA}")
    magic = _magic(root["network_magic"], "network_magic")
    timeout = _uint(root["arm_timeout_ns"], "arm_timeout_ns", MAX_ARM_TIMEOUT_NS)
    if timeout < MIN_ARM_TIMEOUT_NS:
        raise ContractError("arm_timeout_ns is below the one-second floor")
    posture = _posture(root["posture"])
    corpus_raw = _object(root["corpus"], "corpus", _CORPUS_KEYS)
    archive = _file_ref(corpus_raw["archive"], "corpus.archive", MAX_ARCHIVE_BYTES)
    manifest_ref = _file_ref(
        corpus_raw["manifest"], "corpus.manifest", MAX_MANIFEST_BYTES
    )
    manifest = _parse_manifest(
        _load_json(manifest_ref.path, "manifest", MAX_MANIFEST_BYTES),
        archive,
        magic,
    )
    descriptor = _open_regular(manifest_ref.path, "manifest")
    try:
        manifest_info = os.fstat(descriptor)
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
        if hasher.hexdigest() != manifest_ref.sha256:
            raise ContractError("manifest digest does not match the FileRef")
        if manifest_info.st_size != manifest_ref.size:
            raise ContractError("manifest size does not match the FileRef")
    except OSError as error:
        raise ContractError(f"cannot hash manifest: {error}") from error
    finally:
        os.close(descriptor)
    archive_identity = _verify_archive(archive, manifest, magic)
    expected = _certified_state(root["expected_state"], "expected_state")
    if expected.height != manifest.stop_height:
        raise ContractError("expected_state.height must equal the manifest stop height")
    if expected.bestblock != manifest.blocks[-1].block_hash:
        raise ContractError("expected_state.bestblock must equal the final archive block hash")
    lifecycle_raw = _object(root["lifecycle"], "lifecycle", _LIFECYCLE_KEYS)
    mode = _text(lifecycle_raw["mode"], "lifecycle.mode")
    if mode not in {"fresh", "reopen"}:
        raise ContractError("lifecycle.mode must be fresh or reopen")
    reopen_state_raw = lifecycle_raw["expected_reopen_state"]
    reopen_state: CertifiedState | None = None
    if mode == "reopen":
        reopen_state = _certified_state(reopen_state_raw, "lifecycle.expected_reopen_state")
        if reopen_state != expected:
            raise ContractError("reopen state must equal the timed-trial certified state")
    elif reopen_state_raw is not None:
        raise ContractError("fresh lifecycle forbids expected_reopen_state")
    core = _program(root["core"], "core", mode == "reopen")
    candidate = _program(root["candidate"], "candidate", mode == "reopen")
    public_root = dict(root)
    for role, program in (("core", core), ("candidate", candidate)):
        raw_value = root[role]
        if not _is_object(raw_value):
            raise ContractError(f"{role} must be a JSON object")
        projected = dict(raw_value)
        projected["command"] = _public_argv(program.command)
        projected["reopen_command"] = (
            None if program.reopen_command is None else _public_argv(program.reopen_command)
        )
        public_root[role] = projected
    return Config(
        magic,
        timeout,
        posture,
        archive,
        archive_identity,
        manifest_ref,
        manifest,
        expected,
        core,
        candidate,
        mode,
        reopen_state,
        canonical_sha256(public_root),
    )


def load_config(path: Path) -> Config:
    return parse_config(_load_json(path, "config", MAX_CONFIG_BYTES))


def _public_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        return []
    projected = ["<executable>"]
    after_options = False
    for part in argv[1:]:
        if after_options:
            projected.append(_ARGUMENT_MARKER)
        elif part == "--":
            projected.append("<end-options>")
            after_options = True
        elif part in _PUBLIC_PLACEHOLDERS:
            projected.append(_PUBLIC_PLACEHOLDERS[part])
        elif part.startswith("--"):
            projected.append("<long-option=value>" if "=" in part else "<long-option>")
        elif part.startswith("-"):
            projected.append("<short-option>")
        else:
            projected.append(_ARGUMENT_MARKER)
    return projected


def _argv_digest(argv: Sequence[str]) -> str:
    return hashlib.sha256(canonical_bytes(_public_argv(argv))).hexdigest()


def _expand_command(
    template: tuple[str, ...],
    *,
    binary_path: Path,
    data_dir: Path,
    corpus_path: Path,
    manifest_path: Path,
    state_path: Path,
) -> tuple[str, ...]:
    replacements = {
        "{binary}": str(binary_path),
        "{data_dir}": str(data_dir),
        "{corpus_path}": str(corpus_path),
        "{manifest_path}": str(manifest_path),
        "{state_path}": str(state_path),
    }
    return tuple(replacements.get(part, part) for part in template)


def _verified_copy(program: Program, arm_dir: Path) -> Path:
    descriptor = _open_regular(program.binary, f"{program.role} binary")
    digest = hashlib.sha256()
    target = arm_dir / "node-under-test"
    try:
        info = os.fstat(descriptor)
        if info.st_size > MAX_BINARY_BYTES:
            raise ContractError(f"{program.role}.binary exceeds MAX_BINARY_BYTES")
        target_fd = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o500
        )
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                written = 0
                while written < len(chunk):
                    written += os.write(target_fd, chunk[written:])
            os.fsync(target_fd)
        finally:
            os.close(target_fd)
    except OSError as error:
        raise ContractError(f"cannot copy {program.role} binary: {error}") from error
    finally:
        os.close(descriptor)
    if digest.hexdigest() != program.binary_sha256:
        target.unlink(missing_ok=True)
        raise ContractError(f"{program.role} copied binary digest mismatch")
    target.chmod(0o500)
    return target


def _verify_copy_digest(binary_path: Path, expected: str) -> None:
    descriptor = _open_regular(binary_path, "arm binary")
    owned = False
    try:
        with os.fdopen(descriptor, "rb") as stream:
            owned = True
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise ContractError(f"cannot verify arm binary bytes: {error}") from error
    finally:
        if not owned:
            os.close(descriptor)
    if digest != expected:
        raise ContractError("arm binary changed after its verified copy")


def _copy_readonly(
    source: Path,
    dest: Path,
    expected_sha256: str,
    expected_size: int,
    field: str,
) -> FileIdentity:
    descriptor = _open_regular(source, field)
    digest = hashlib.sha256()
    copied = 0
    try:
        dest_fd = os.open(
            dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400
        )
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                digest.update(chunk)
                written = 0
                while written < len(chunk):
                    written += os.write(dest_fd, chunk[written:])
            os.fsync(dest_fd)
            info = os.fstat(dest_fd)
        finally:
            os.close(dest_fd)
    except OSError as error:
        dest.unlink(missing_ok=True)
        raise ContractError(f"cannot pin {field}: {error}") from error
    finally:
        os.close(descriptor)
    observed = digest.hexdigest()
    if copied != expected_size or observed != expected_sha256:
        dest.unlink(missing_ok=True)
        raise ContractError(f"{field} changed before the campaign pin")
    dest.chmod(0o400)
    return _identity_from_stat(info, observed)


def _pin_corpus(config: Config, root: Path) -> PinnedCorpus:
    custody = root / "custody"
    custody.mkdir()
    archive_path = custody / "archive"
    manifest_path = custody / "manifest"
    archive_identity = _copy_readonly(
        config.archive.path,
        archive_path,
        config.archive.sha256,
        config.archive.size,
        "archive",
    )
    manifest_identity = _copy_readonly(
        config.manifest.path,
        manifest_path,
        config.manifest.sha256,
        config.manifest.size,
        "manifest",
    )
    try:
        dirfd = os.open(custody, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as error:
        raise ContractError(f"cannot dirsync custody pin: {error}") from error
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    return PinnedCorpus(
        FileRef(archive_path, config.archive.sha256, config.archive.size),
        archive_identity,
        FileRef(manifest_path, config.manifest.sha256, config.manifest.size),
        manifest_identity,
    )


def _state(path: Path, field: str) -> CertifiedState:
    return _certified_state(_load_json(path, field, MAX_STATE_BYTES), field)


def _clk_tck() -> int:
    ticks = os.sysconf("SC_CLK_TCK")
    if ticks <= 0:
        raise ContractError("cannot read SC_CLK_TCK")
    return ticks


def _page_size() -> int:
    size = os.sysconf("SC_PAGESIZE")
    if size <= 0:
        raise ContractError("cannot read SC_PAGESIZE")
    return size


def _sample_child(pid: int) -> tuple[int, int] | None:
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    fields = stat_text.rpartition(")")[2].split()
    if len(fields) < 22:
        return None
    try:
        utime = int(fields[11])
        stime = int(fields[12])
        rss_pages = int(fields[21])
    except ValueError:
        return None
    cpu_ns = (utime + stime) * 1_000_000_000 // _clk_tck()
    rss_bytes = rss_pages * _page_size()
    return cpu_ns, rss_bytes


def _wait_child(
    process: subprocess.Popen[bytes], deadline_ns: int
) -> tuple[int, int, int]:
    peak_rss = 0
    cpu_ns = 0
    while True:
        sample = _sample_child(process.pid)
        if sample is not None:
            cpu_ns, rss = sample
            if rss > peak_rss:
                peak_rss = rss
        remaining = deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            _kill_tree(process)
            raise ContractError("arm exceeded its monotonic deadline")
        try:
            code = process.wait(timeout=min(0.05, remaining / 1_000_000_000))
        except subprocess.TimeoutExpired:
            continue
        if code is None:
            raise ContractError("child wait returned without an exit code")
        return code, cpu_ns, peak_rss


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    grace = time.monotonic_ns() + CHILD_TERMINATE_GRACE_NS
    while time.monotonic_ns() < grace:
        if process.poll() is not None:
            return
        time.sleep(0.01)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    kill_deadline = time.monotonic_ns() + CHILD_KILL_REAP_NS
    while time.monotonic_ns() < kill_deadline:
        if process.poll() is not None:
            return
        time.sleep(0.01)
    raise ContractError("child process group did not terminate")


def _kill_pids(pids: Sequence[int]) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic_ns() + CHILD_KILL_REAP_NS
    remaining = set(pids)
    while remaining and time.monotonic_ns() < deadline:
        for pid in tuple(remaining):
            try:
                waited, _status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                remaining.discard(pid)
                continue
            if waited == pid:
                remaining.discard(pid)
        if remaining:
            time.sleep(0.01)


def _reap_owned_descendants() -> list[int]:
    leftover = _direct_children_pids()
    if leftover:
        _kill_pids(leftover)
    return leftover


def _settle_after_wait(process: subprocess.Popen[bytes]) -> None:
    group_left = False
    try:
        os.killpg(process.pid, 0)
        group_left = True
    except ProcessLookupError:
        pass
    if group_left:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            group_left = False
    leftover = _reap_owned_descendants()
    if group_left or leftover:
        listed = ",".join(str(pid) for pid in leftover) or str(process.pid)
        raise ContractError(f"arm left descendant processes after exit: {listed}")


def _child_env(arm_dir: Path) -> dict[str, str]:
    tmp = arm_dir / "tmp"
    tmp.mkdir(exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(arm_dir),
        "TMPDIR": str(tmp),
        "LC_ALL": "C",
    }


def _run_phase(
    argv: tuple[str, ...],
    arm_dir: Path,
    deadline_ns: int,
) -> tuple[int, int, int, int]:
    env = _child_env(arm_dir)
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=env,
            cwd=arm_dir,
        )
    except OSError as error:
        raise ContractError(f"cannot spawn arm process: {error}") from error
    try:
        code, cpu_ns, peak_rss = _wait_child(process, deadline_ns)
        _settle_after_wait(process)
    except BaseException:
        if process.poll() is None:
            _kill_tree(process)
        _reap_owned_descendants()
        raise
    wall_ns = time.monotonic_ns() - started
    if wall_ns <= 0:
        raise ContractError("arm wall time was not positive")
    return code, wall_ns, cpu_ns, peak_rss


def _run_arm(
    config: Config,
    program: Program,
    pair_index: int,
    order_index: int,
    root: Path,
    pinned: PinnedCorpus,
) -> ArmObservation:
    arm_dir = root / f"{order_index:02d}-{program.role}"
    arm_dir.mkdir(parents=True)
    data_dir = arm_dir / "data"
    data_dir.mkdir()
    binary_path = _verified_copy(program, arm_dir)
    _assert_pins(pinned)
    _verify_copy_digest(binary_path, program.binary_sha256)
    state_path = arm_dir / "state.json"
    argv = _expand_command(
        program.command,
        binary_path=binary_path,
        data_dir=data_dir,
        corpus_path=pinned.archive.path,
        manifest_path=pinned.manifest.path,
        state_path=state_path,
    )
    deadline = time.monotonic_ns() + config.arm_timeout_ns
    code, wall_ns, cpu_ns, peak_rss = _run_phase(argv, arm_dir, deadline)
    _assert_pins(pinned)
    final = _state(state_path, f"{program.role} final state")
    expected_json = state_json(config.expected_state)
    durability_ok = code == 0
    state_ok = state_json(final) == expected_json
    reopen_exit: int | None = None
    reopen_state: JsonObject | None = None
    reopen_hash: str | None = None
    reopen_digest: str | None = None
    if config.lifecycle_mode == "reopen":
        if program.reopen_command is None:
            raise ContractError(f"{program.role} has no reopen command")
        reopen_path = arm_dir / "reopen-state.json"
        _assert_pins(pinned)
        _verify_copy_digest(binary_path, program.binary_sha256)
        reopen_argv = _expand_command(
            program.reopen_command,
            binary_path=binary_path,
            data_dir=data_dir,
            corpus_path=pinned.archive.path,
            manifest_path=pinned.manifest.path,
            state_path=reopen_path,
        )
        reopen_deadline = time.monotonic_ns() + config.arm_timeout_ns
        reopen_exit, _, _, _ = _run_phase(reopen_argv, arm_dir, reopen_deadline)
        _assert_pins(pinned)
        reopened = _state(reopen_path, f"{program.role} reopen state")
        reopen_state = state_json(reopened)
        reopen_hash = canonical_sha256(reopen_state)
        reopen_digest = _argv_digest(program.reopen_command)
        durability_ok = durability_ok and reopen_exit == 0
        state_ok = state_ok and reopen_state == expected_json
    errors: list[str] = []
    if not durability_ok:
        errors.append("durable clean exit failed")
    if not state_ok:
        errors.append("certified state contract failed")
    return ArmObservation(
        pair_index,
        order_index,
        program.role,
        program.binary_sha256,
        _argv_digest(program.command),
        len(program.command),
        reopen_digest,
        wall_ns,
        cpu_ns,
        peak_rss,
        code,
        state_json(final),
        canonical_sha256(state_json(final)),
        reopen_exit,
        reopen_state,
        reopen_hash,
        durability_ok,
        state_ok,
        "; ".join(errors) or None,
    )


def _percentile(values: Sequence[int], percentile: float) -> int:
    if not values:
        raise ContractError("cannot summarize an empty sample")
    ordered = sorted(values)
    rank = math.ceil(percentile * len(ordered)) - 1
    return ordered[max(0, rank)]


def summarize(values: Sequence[int]) -> Summary:
    return {
        "samples": len(values),
        "p50_ns": _percentile(values, 0.50),
        "p95_ns": _percentile(values, 0.95),
        "p99_ns": _percentile(values, 0.99),
        "max_ns": max(values),
    }


def _arm_json(arm: ArmObservation) -> JsonObject:
    return {
        "pair_index": arm.pair_index,
        "order_index": arm.order_index,
        "role": arm.role,
        "binary_sha256": arm.binary_sha256,
        "command_sha256": arm.command_sha256,
        "command_arg_count": arm.command_arg_count,
        "reopen_command_sha256": arm.reopen_command_sha256,
        "wall_ns": arm.wall_ns,
        "cpu_ns": arm.cpu_ns,
        "peak_rss_bytes": arm.peak_rss_bytes,
        "exit_code": arm.exit_code,
        "final_state": arm.final_state,
        "final_state_sha256": arm.final_state_sha256,
        "reopen_exit_code": arm.reopen_exit_code,
        "reopen_state": arm.reopen_state,
        "reopen_state_sha256": arm.reopen_state_sha256,
        "durability_ok": arm.durability_ok,
        "state_ok": arm.state_ok,
        "error": arm.error,
    }


def _require_comparable(config: Config, arms: Sequence[ArmObservation]) -> None:
    if len(arms) != 2 * PAIR_COUNT:
        raise ContractError("campaign must contain exactly fourteen arms")
    for pair_index in range(PAIR_COUNT):
        first, second = arms[2 * pair_index], arms[2 * pair_index + 1]
        expected_first = "core" if pair_index % 2 == 0 else "candidate"
        expected_second = "candidate" if expected_first == "core" else "core"
        if first.role != expected_first or second.role != expected_second:
            raise ContractError("pair order must alternate Core-first then candidate-first")
        if first.pair_index != pair_index or second.pair_index != pair_index:
            raise ContractError("pair index is inconsistent")
        for arm in (first, second):
            if not arm.durability_ok or not arm.state_ok or arm.error is not None:
                raise ContractError(f"{arm.role} arm {arm.order_index} failed its gates")
            if arm.binary_sha256 != (
                config.core.binary_sha256
                if arm.role == "core"
                else config.candidate.binary_sha256
            ):
                raise ContractError("arm binary identity drifted")
            if arm.final_state != state_json(config.expected_state):
                raise ContractError("arm certified state diverged")
        if first.final_state != second.final_state:
            raise ContractError("paired arms did not certify the same state")


def run_campaign(config: Config, output_root: Path) -> JsonObject:
    if sys.platform != "linux":
        raise ContractError("offline full-validation comparator requires Linux")
    output_root.mkdir(parents=True, exist_ok=True)
    pinned = _pin_corpus(config, output_root)
    arms: list[ArmObservation] = []
    order_index = 0
    try:
        with _ChildSubreaperScope():
            for pair_index in range(PAIR_COUNT):
                first = config.core if pair_index % 2 == 0 else config.candidate
                second = config.candidate if first is config.core else config.core
                arms.append(
                    _run_arm(
                        config, first, pair_index, order_index, output_root, pinned
                    )
                )
                order_index += 1
                arms.append(
                    _run_arm(
                        config, second, pair_index, order_index, output_root, pinned
                    )
                )
                order_index += 1
    except _P2PContractError as error:
        raise ContractError(str(error)) from error
    _require_comparable(config, arms)
    core_walls = [arm.wall_ns for arm in arms if arm.role == "core"]
    candidate_walls = [arm.wall_ns for arm in arms if arm.role == "candidate"]
    core_summary = summarize(core_walls)
    candidate_summary = summarize(candidate_walls)
    ratio = candidate_summary["p50_ns"] / core_summary["p50_ns"]
    result: JsonObject = {
        "schema": RESULT_SCHEMA,
        "config_sha256": config.canonical_sha256,
        "pair_count": PAIR_COUNT,
        "arm_count": len(arms),
        "custody": {
            "network_magic": config.network_magic.hex(),
            "network": config.manifest_document.network,
            "start_height": config.manifest_document.start_height,
            "stop_height": config.manifest_document.stop_height,
            "archive_sha256": config.archive.sha256,
            "archive_bytes": config.archive.size,
            "manifest_sha256": config.manifest.sha256,
            "manifest_bytes": config.manifest.size,
            "core_binary_sha256": config.core.binary_sha256,
            "candidate_binary_sha256": config.candidate.binary_sha256,
            "assume_valid": config.posture.assume_valid,
            "txindex": config.posture.txindex,
            "blockfilterindex": config.posture.blockfilterindex,
            "coinstatsindex": config.posture.coinstatsindex,
            "cache_policy": config.posture.cache_policy,
            "lifecycle_mode": config.lifecycle_mode,
        },
        "correctness": {
            "arm_count_ok": True,
            "alternation_ok": True,
            "archive_ok": True,
            "full_validation_ok": True,
            "indexes_off_ok": True,
            "durability_ok": True,
            "state_equal": True,
            "reopen_ok": True,
        },
        "arms": [_arm_json(arm) for arm in arms],
        "core": core_summary,
        "candidate": candidate_summary,
        "candidate_over_core_p50_ratio": ratio,
    }
    result["result_sha256"] = canonical_sha256(result)
    return result


def _publish_result(result: JsonObject, output: Path) -> None:
    """Atomically publish one result document.

    Commit point is successful ``linkat(AT_EMPTY_PATH)``. Bytes are written
    to an unnamed ``O_TMPFILE`` inode, flushed, and fsynced; only then is
    the inode named in the output directory. ``os.fsync`` of that directory
    follows a successful link so the directory entry is durable.

    Crash before the link leaves the destination unchanged. The unnamed
    inode vanishes with the descriptor; the run is retriable against the
    same output path. Crash after the link (or a retry against an existing
    name) surfaces ``EEXIST``: the published bytes are the committed
    document and must not be overwritten. This function does not retry;
    the caller owns retry policy and must choose a new output path.
    """
    if sys.platform != "linux":
        raise ContractError("publication requires Linux O_TMPFILE support")
    at_empty_path = getattr(os, "AT_EMPTY_PATH", 0x1000)
    payload = canonical_bytes(result) + b"\n"
    try:
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as error:
        raise ContractError(f"cannot open output directory {output.parent}: {error}") from error
    try:
        try:
            descriptor = os.open(
                output.parent, os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC, 0o600
            )
        except OSError as error:
            raise ContractError(
                f"cannot create unnamed temp file in {output.parent}: {error}"
            ) from error
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(descriptor)
            libc = ctypes.CDLL(None, use_errno=True)
            linkat = libc.linkat
            linkat.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
            )
            linked = linkat(
                descriptor,
                b"",
                directory,
                os.fsencode(output.name),
                at_empty_path,
            )
            if linked != 0:
                failure = ctypes.get_errno()
                if failure == errno.EEXIST:
                    raise ContractError(f"output already exists: {output}")
                raise ContractError(f"cannot link published result: {os.strerror(failure)}")
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = load_config(args.config)
    output = args.output
    if output.exists():
        raise ContractError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="offline-full-validation-", dir=output.parent
    ) as temporary:
        result = run_campaign(config, Path(temporary) / "arms")
        _publish_result(result, output)
    return 0


def _fatal(error: Exception) -> NoReturn:
    print(f"offline-full-validation: {error}", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as error:
        _fatal(error)
