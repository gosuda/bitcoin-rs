#!/usr/bin/env python3.14
# pyright: strict
"""Deterministic, correctness-gated Bitcoin P2P loopback comparator."""

import argparse
import ctypes
import hashlib
import json
import math
import os
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from types import FrameType, TracebackType
from typing import NoReturn, Self

from evidence import (
    ContractError,
    JsonObject,
    _array,
    _is_object,
    _object,
    _text,
    _uint,
    _validate_json_depth,
    canonical_bytes,
    canonical_sha256,
    copy_pinned,
    process_start_time,
    publish_result,
    summarize,
)

CONFIG_SCHEMA = "p2p-loopback-config-v1"
RESULT_SCHEMA = "p2p-loopback-result-v2"
PAIR_COUNT = 7
MAX_FRAME_BYTES = 4_000_024
MAX_CORPUS_BYTES = 16 * 1024 * 1024
MAX_INBOUND_BYTES = 16 * 1024 * 1024
MAX_STEPS = 4_096
MAX_COMMAND_ARGS = 256
MAX_CONFIG_BYTES = 40 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
MAX_CONNECT_TIMEOUT_NS = 10_000_000_000
MAX_IO_TIMEOUT_NS = 120_000_000_000
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_ARM_DURATION_NS = 180_000_000_000
CHILD_TERMINATE_GRACE_NS = 1_000_000_000
CHILD_KILL_REAP_NS = 1_000_000_000
WORKER_JOIN_GRACE_NS = 1_000_000_000
_CANCEL_SLICE_NS = 50_000_000
_OWNERSHIP_CLEANUP_RESERVE_NS = (
    CHILD_TERMINATE_GRACE_NS + CHILD_KILL_REAP_NS + WORKER_JOIN_GRACE_NS
)
_MAX_PENDING_CANDIDATES = 16
_MAX_ACCEPTS_PER_TICK = 16
_MAX_CLASSIFICATIONS_PER_TICK = 16
_HASH_LENGTH = 64


@dataclass(frozen=True)
class Frame:
    wire: bytes
    sha256: str


@dataclass(frozen=True)
class Step:
    kind: str
    frame: int | None
    delay_ns: int
    bandwidth_bytes_per_second: int | None
    duration_ns: int
    after_bytes: int | None


@dataclass(frozen=True)
class PeerContract:
    network_magic: bytes
    protocol_version: int
    services: int
    connect_timeout_ns: int
    io_timeout_ns: int
    socket_buffer_bytes: int
    expected_inbound_sha256: str | None


@dataclass(frozen=True)
class LifecycleContract:
    mode: str
    generation: int
    initial_state: JsonObject
    expected_final_state: JsonObject
    expected_restart_state: JsonObject | None


@dataclass(frozen=True)
class Program:
    role: str
    binary: Path
    binary_sha256: str
    command: tuple[str, ...]
    restart_command: tuple[str, ...] | None


@dataclass(frozen=True)
class Config:
    peer: PeerContract
    lifecycle: LifecycleContract
    corpus: tuple[Frame, ...]
    schedule: tuple[Step, ...]
    core: Program
    candidate: Program
    corpus_sha256: str
    schedule_sha256: str
    peer_sha256: str
    lifecycle_sha256: str
    canonical_sha256: str


@dataclass(frozen=True)
class PeerObservation:
    connected: bool
    sent_bytes: int
    sent_sha256: str
    inbound_bytes: int
    inbound_sha256: str
    completed_steps: int
    disconnect_expected: bool
    error: str | None


@dataclass(frozen=True)
class ArmObservation:
    pair_index: int
    order_index: int
    role: str
    binary_path: str
    binary_sha256: str
    command_sha256: str
    command_arg_count: int
    restart_command_sha256: str | None
    restart_command_arg_count: int | None
    wall_ns: int
    exit_code: int
    peer: PeerObservation
    final_state: JsonObject
    final_state_sha256: str
    restart_exit_code: int | None
    restart_state: JsonObject | None
    restart_state_sha256: str | None
    protocol_ok: bool
    state_ok: bool
    error: str | None


def _positive(value: object, field: str, maximum: int = (1 << 63) - 1) -> int:
    result = _uint(value, field, maximum)
    if result == 0:
        raise ContractError(f"{field} must be positive")
    return result


def _optional_hash(value: object, field: str) -> str | None:
    if value is None:
        return None
    text = _text(value, field)
    if len(text) != _HASH_LENGTH or any(ch not in "0123456789abcdef" for ch in text):
        raise ContractError(f"{field} must be a lowercase SHA-256")
    return text


def _load_json(path: Path, field: str, maximum_bytes: int) -> object:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ContractError(f"cannot read {field} {path}") from error
    owned = False
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(f"{field} is not a regular file")
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


def _frame(raw: object, index: int, magic: bytes) -> Frame:
    text = _text(raw, f"corpus[{index}]")
    try:
        wire = bytes.fromhex(text)
    except ValueError as error:
        raise ContractError(f"corpus[{index}] must be hexadecimal") from error
    if len(wire) < 24 or len(wire) > MAX_FRAME_BYTES:
        raise ContractError(f"corpus[{index}] has invalid framed length {len(wire)}")
    if wire[:4] != magic:
        raise ContractError(f"corpus[{index}] has wrong network magic")
    command = wire[4:16]
    if b"\0" in command:
        head, padding = command.split(b"\0", 1)
        if not head or any(padding):
            raise ContractError(f"corpus[{index}] has invalid command padding")
    elif not command:
        raise ContractError(f"corpus[{index}] has empty command")
    payload_length = int.from_bytes(wire[16:20], "little")
    if payload_length != len(wire) - 24:
        raise ContractError(f"corpus[{index}] payload length does not match frame")
    if wire[20:24] != hashlib.sha256(hashlib.sha256(wire[24:]).digest()).digest()[:4]:
        raise ContractError(f"corpus[{index}] payload checksum is invalid")
    return Frame(wire=wire, sha256=hashlib.sha256(wire).hexdigest())


def _step(raw: object, index: int, frame_count: int) -> Step:
    item = _object(
        raw,
        f"schedule[{index}]",
        frozenset(
            {
                "kind",
                "frame",
                "delay_ns",
                "bandwidth_bytes_per_second",
                "duration_ns",
                "after_bytes",
            }
        ),
    )
    kind = _text(item["kind"], f"schedule[{index}].kind")
    if kind not in {"send", "stall", "disconnect"}:
        raise ContractError(f"schedule[{index}].kind is unsupported")
    frame_value = item["frame"]
    frame = (
        None if frame_value is None else _uint(frame_value, f"schedule[{index}].frame")
    )
    delay_ns = _uint(item["delay_ns"], f"schedule[{index}].delay_ns")
    bandwidth_value = item["bandwidth_bytes_per_second"]
    bandwidth = (
        None
        if bandwidth_value is None
        else _positive(bandwidth_value, f"schedule[{index}].bandwidth_bytes_per_second")
    )
    duration_ns = _uint(item["duration_ns"], f"schedule[{index}].duration_ns")
    after_value = item["after_bytes"]
    after_bytes = (
        None
        if after_value is None
        else _uint(after_value, f"schedule[{index}].after_bytes")
    )
    if kind == "send":
        if frame is None or frame >= frame_count:
            raise ContractError(f"schedule[{index}] send frame is out of range")
        if duration_ns or after_bytes is not None:
            raise ContractError(
                f"schedule[{index}] send has fields for another step kind"
            )
    elif kind == "stall":
        if (
            frame is not None
            or bandwidth is not None
            or duration_ns == 0
            or after_bytes is not None
        ):
            raise ContractError(f"schedule[{index}] stall has inconsistent fields")
    else:
        if frame is not None or bandwidth is not None or duration_ns:
            raise ContractError(f"schedule[{index}] disconnect has inconsistent fields")
    return Step(kind, frame, delay_ns, bandwidth, duration_ns, after_bytes)


def _schedule_duration_ns(corpus: Sequence[Frame], schedule: Sequence[Step]) -> int:
    duration = 0
    for step in schedule:
        duration += step.delay_ns + step.duration_ns
        if step.kind == "send" and step.bandwidth_bytes_per_second is not None:
            if step.frame is None:
                raise ContractError("send step has no frame")
            duration += math.ceil(
                len(corpus[step.frame].wire)
                * 1_000_000_000
                / step.bandwidth_bytes_per_second
            )
        if duration > MAX_ARM_DURATION_NS:
            return duration
    return duration


def _program(raw: object, role: str) -> Program:
    item = _object(
        raw,
        role,
        frozenset({"binary", "binary_sha256", "command", "restart_command"}),
    )
    binary = Path(_text(item["binary"], f"{role}.binary"))
    digest = _optional_hash(item["binary_sha256"], f"{role}.binary_sha256")
    if digest is None:
        raise ContractError(f"{role}.binary_sha256 must be a lowercase SHA-256")
    command = tuple(
        _text(part, f"{role}.command")
        for part in _array(item["command"], f"{role}.command")
    )
    if not command or len(command) > MAX_COMMAND_ARGS:
        raise ContractError(
            f"{role}.command must contain 1 to {MAX_COMMAND_ARGS} arguments"
        )
    if command[0] != "{binary}":
        raise ContractError(f"{role}.command[0] must be {{binary}}")
    restart_raw = item["restart_command"]
    restart = None
    if restart_raw is not None:
        restart = tuple(
            _text(part, f"{role}.restart_command")
            for part in _array(restart_raw, f"{role}.restart_command")
        )
        if not restart or len(restart) > MAX_COMMAND_ARGS:
            raise ContractError(
                f"{role}.restart_command must contain 1 to {MAX_COMMAND_ARGS} arguments"
            )
        if restart[0] != "{binary}":
            raise ContractError(f"{role}.restart_command[0] must be {{binary}}")
    allowed = {"{binary}", "{peer_host}", "{peer_port}", "{data_dir}", "{state_path}"}
    for part in command + (() if restart is None else restart):
        for start in range(len(part)):
            if part[start] == "{":
                end = part.find("}", start)
                if end < 0 or part[start : end + 1] not in allowed:
                    raise ContractError(
                        f"{role} command contains unsupported placeholder"
                    )
    return Program(role, binary, digest, command, restart)


def parse_config(value: object) -> Config:
    root = _object(
        value,
        "config",
        frozenset(
            {"schema", "peer", "lifecycle", "corpus", "schedule", "core", "candidate"}
        ),
    )
    if root["schema"] != CONFIG_SCHEMA:
        raise ContractError(f"config.schema must be {CONFIG_SCHEMA}")
    peer_raw = _object(
        root["peer"],
        "peer",
        frozenset(
            {
                "network_magic",
                "protocol_version",
                "services",
                "connect_timeout_ns",
                "io_timeout_ns",
                "socket_buffer_bytes",
                "expected_inbound_sha256",
            }
        ),
    )
    magic_text = _text(peer_raw["network_magic"], "peer.network_magic")
    try:
        magic = bytes.fromhex(magic_text)
    except ValueError as error:
        raise ContractError("peer.network_magic must be hexadecimal") from error
    if len(magic) != 4:
        raise ContractError("peer.network_magic must contain exactly four bytes")
    peer = PeerContract(
        magic,
        _positive(peer_raw["protocol_version"], "peer.protocol_version", (1 << 31) - 1),
        _uint(peer_raw["services"], "peer.services", (1 << 64) - 1),
        _positive(
            peer_raw["connect_timeout_ns"],
            "peer.connect_timeout_ns",
            MAX_CONNECT_TIMEOUT_NS,
        ),
        _positive(
            peer_raw["io_timeout_ns"],
            "peer.io_timeout_ns",
            MAX_IO_TIMEOUT_NS,
        ),
        _positive(
            peer_raw["socket_buffer_bytes"],
            "peer.socket_buffer_bytes",
            MAX_INBOUND_BYTES,
        ),
        _optional_hash(
            peer_raw["expected_inbound_sha256"], "peer.expected_inbound_sha256"
        ),
    )
    lifecycle_raw = _object(
        root["lifecycle"],
        "lifecycle",
        frozenset(
            {
                "mode",
                "generation",
                "initial_state",
                "expected_final_state",
                "expected_restart_state",
            }
        ),
    )
    mode = _text(lifecycle_raw["mode"], "lifecycle.mode")
    if mode not in {"fresh", "restart"}:
        raise ContractError("lifecycle.mode must be fresh or restart")
    initial = lifecycle_raw["initial_state"]
    final = lifecycle_raw["expected_final_state"]
    restart_state = lifecycle_raw["expected_restart_state"]
    if not _is_object(initial) or not _is_object(final):
        raise ContractError("lifecycle states must be JSON objects")
    if restart_state is not None and not _is_object(restart_state):
        raise ContractError(
            "lifecycle.expected_restart_state must be an object or null"
        )
    if mode == "restart" and restart_state is None:
        raise ContractError("restart lifecycle requires expected_restart_state")
    lifecycle = LifecycleContract(
        mode,
        _uint(lifecycle_raw["generation"], "lifecycle.generation"),
        initial,
        final,
        restart_state,
    )
    corpus_raw = _array(root["corpus"], "corpus")
    if not corpus_raw:
        raise ContractError("corpus must not be empty")
    corpus = tuple(_frame(raw, index, magic) for index, raw in enumerate(corpus_raw))
    if sum(len(frame.wire) for frame in corpus) > MAX_CORPUS_BYTES:
        raise ContractError("corpus exceeds the bounded byte limit")
    schedule_raw = _array(root["schedule"], "schedule")
    if not schedule_raw or len(schedule_raw) > MAX_STEPS:
        raise ContractError("schedule must contain a bounded nonzero number of steps")
    schedule = tuple(
        _step(raw, index, len(corpus)) for index, raw in enumerate(schedule_raw)
    )
    schedule_duration_ns = _schedule_duration_ns(corpus, schedule)
    if schedule_duration_ns > peer.io_timeout_ns:
        raise ContractError("schedule worst-case duration exceeds peer.io_timeout_ns")
    if schedule_duration_ns > MAX_ARM_DURATION_NS:
        raise ContractError("schedule worst-case duration exceeds fixed arm bound")
    sent_indices = [step.frame for step in schedule if step.kind == "send"]
    if sent_indices != list(range(len(corpus))):
        raise ContractError(
            "schedule must send every corpus frame exactly once in corpus order"
        )
    if schedule[-1].kind != "disconnect" or any(
        step.kind == "disconnect" for step in schedule[:-1]
    ):
        raise ContractError("disconnect must be the final schedule step")
    core = _program(root["core"], "core")
    candidate = _program(root["candidate"], "candidate")
    corpus_json = [frame.wire.hex() for frame in corpus]
    schedule_json = schedule_raw
    peer_json = peer_raw
    lifecycle_json = lifecycle_raw
    public_root = dict(root)
    for role, program in (("core", core), ("candidate", candidate)):
        raw_value = root[role]
        if not _is_object(raw_value):
            raise ContractError(f"{role} must be a JSON object")
        raw_program = dict(raw_value)
        raw_program["command"] = _public_argv(program.command)
        raw_program["restart_command"] = (
            None
            if program.restart_command is None
            else _public_argv(program.restart_command)
        )
        public_root[role] = raw_program
    return Config(
        peer,
        lifecycle,
        corpus,
        schedule,
        core,
        candidate,
        canonical_sha256(corpus_json),
        canonical_sha256(schedule_json),
        canonical_sha256(peer_json),
        canonical_sha256(lifecycle_json),
        canonical_sha256(public_root),
    )


def load_config(path: Path) -> Config:
    return parse_config(_load_json(path, "config", MAX_CONFIG_BYTES))


def _hash_file(path: Path) -> str:
    """Hash regular-file bytes through one no-follow, nonblocking fd."""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ContractError(f"cannot open binary {path}: {error}") from error
    digest = hashlib.sha256()
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError(f"binary {path} is not a regular file")
        if info.st_size > MAX_BINARY_BYTES:
            raise ContractError(f"binary {path} exceeds MAX_BINARY_BYTES")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise ContractError(f"cannot hash binary {path}: {error}") from error
    finally:
        os.close(descriptor)


def _sleep_until(deadline_ns: int, cancel: threading.Event) -> None:
    while not cancel.is_set():
        remaining = deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            return
        time.sleep(min(remaining, _CANCEL_SLICE_NS) / 1_000_000_000)
    raise ContractError("loopback peer wait was cancelled")


def _send_paced(
    connection: socket.socket,
    payload: bytes,
    rate: int | None,
    cancel: threading.Event,
) -> None:
    offset = 0
    started = time.monotonic_ns()
    while offset < len(payload):
        if cancel.is_set():
            raise ContractError("loopback peer wait was cancelled")
        chunk_end = min(offset + 64 * 1024, len(payload))
        if rate is not None:
            target = started + math.ceil(chunk_end * 1_000_000_000 / rate)
            _sleep_until(target, cancel)
        written = connection.send(payload[offset:chunk_end])
        if written <= 0:
            raise ConnectionError("socket made no forward progress")
        offset += written


def _candidate_magic(candidate: socket.socket, magic: bytes) -> str:
    """Classify one candidate without consuming its network-magic prefix."""
    try:
        chunk = candidate.recv(len(magic), socket.MSG_PEEK)
    except BlockingIOError:
        return "pending"
    except OSError:
        return "reject"
    if not chunk or not magic.startswith(chunk):
        return "reject"
    return "ok" if len(chunk) == len(magic) else "pending"


def _accept_magic_peer(
    listener: socket.socket,
    magic: bytes,
    cancel: threading.Event,
    deadline_ns: int,
) -> socket.socket:
    """Select the first matching peer without head-of-line blocking."""
    selector = selectors.DefaultSelector()
    pending: list[socket.socket] = []
    winner: socket.socket | None = None
    listener.setblocking(False)
    selector.register(listener, selectors.EVENT_READ)
    try:
        while winner is None:
            if cancel.is_set():
                raise ContractError("loopback peer wait was cancelled")
            remaining_ns = deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                raise ContractError(
                    "loopback peer never presented the configured magic"
                )
            selector.select(min(remaining_ns, _CANCEL_SLICE_NS) / 1_000_000_000)

            for _ in range(_MAX_ACCEPTS_PER_TICK):
                if cancel.is_set():
                    raise ContractError("loopback peer wait was cancelled")
                if time.monotonic_ns() >= deadline_ns:
                    raise ContractError(
                        "loopback peer never presented the configured magic"
                    )
                try:
                    candidate, _ = listener.accept()
                except BlockingIOError:
                    break
                candidate.setblocking(False)
                if len(pending) == _MAX_PENDING_CANDIDATES:
                    _close_quietly(candidate)
                    continue
                pending.append(candidate)
                selector.register(candidate, selectors.EVENT_READ)

            snapshot = tuple(pending[:_MAX_CLASSIFICATIONS_PER_TICK])
            for candidate in snapshot:
                if cancel.is_set():
                    raise ContractError("loopback peer wait was cancelled")
                if time.monotonic_ns() >= deadline_ns:
                    raise ContractError(
                        "loopback peer never presented the configured magic"
                    )
                verdict = _candidate_magic(candidate, magic)
                if verdict == "pending":
                    continue
                pending.remove(candidate)
                selector.unregister(candidate)
                if verdict == "ok":
                    winner = candidate
                    break
                _close_quietly(candidate)
        return winner
    finally:
        for candidate in pending:
            _close_quietly(candidate)
        selector.close()


def _peer_worker(
    listener: socket.socket,
    config: Config,
    ready: threading.Event,
    observations: list[PeerObservation],
    cancel: threading.Event,
    connections: list[socket.socket],
    deadline_ns: int,
) -> None:
    inbound = bytearray()
    sent = bytearray()
    completed = 0
    connected = False
    expected_disconnect = any(step.kind == "disconnect" for step in config.schedule)
    error: str | None = None
    connection: socket.socket | None = None
    ready.set()
    try:
        connection = _accept_magic_peer(
            listener,
            config.peer.network_magic,
            cancel,
            deadline_ns,
        )
        connected = True
        connections.append(connection)
        connection.settimeout(config.peer.io_timeout_ns / 1_000_000_000)
        connection.setsockopt(
            socket.SOL_SOCKET, socket.SO_SNDBUF, config.peer.socket_buffer_bytes
        )
        connection.setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF, config.peer.socket_buffer_bytes
        )
        for step in config.schedule:
            if step.delay_ns:
                _sleep_until(time.monotonic_ns() + step.delay_ns, cancel)
            if step.kind == "stall":
                _sleep_until(time.monotonic_ns() + step.duration_ns, cancel)
            elif step.kind == "send":
                if step.frame is None or step.frame >= len(config.corpus):
                    raise ContractError("worker received an out-of-range send frame")
                wire = config.corpus[step.frame].wire
                _send_paced(connection, wire, step.bandwidth_bytes_per_second, cancel)
                sent.extend(wire)
            elif step.kind == "disconnect":
                if step.after_bytes:
                    remaining = step.after_bytes
                    while remaining:
                        chunk = connection.recv(min(64 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError(
                                "peer closed before disconnect read point"
                            )
                        inbound.extend(chunk)
                        if len(inbound) > MAX_INBOUND_BYTES:
                            raise ContractError("inbound transcript exceeded bound")
                        remaining -= len(chunk)
                connection.shutdown(socket.SHUT_RDWR)
            completed += 1
        if not expected_disconnect:
            while True:
                try:
                    chunk = connection.recv(64 * 1024)
                except TimeoutError:
                    break
                if not chunk:
                    break
                inbound.extend(chunk)
                if len(inbound) > MAX_INBOUND_BYTES:
                    raise ContractError("inbound transcript exceeded bound")
    except (OSError, ContractError) as caught:
        error = str(caught)
    finally:
        if connection is not None:
            connection.close()
        listener.close()
        observations.append(
            PeerObservation(
                connected,
                len(sent),
                hashlib.sha256(sent).hexdigest(),
                len(inbound),
                hashlib.sha256(inbound).hexdigest(),
                completed,
                expected_disconnect,
                error,
            )
        )


def _expand_command(
    template: tuple[str, ...],
    binary_path: Path,
    host: str,
    port: int,
    data_dir: Path,
    state_path: Path,
) -> tuple[str, ...]:
    replacements = {
        "{binary}": str(binary_path),
        "{peer_host}": host,
        "{peer_port}": str(port),
        "{data_dir}": str(data_dir),
        "{state_path}": str(state_path),
    }
    return tuple(replacements.get(part, part) for part in template)


def _state(path: Path, field: str) -> JsonObject:
    value = _load_json(path, field, MAX_STATE_BYTES)
    if not _is_object(value):
        raise ContractError(f"{field} must be a JSON object")
    canonical_bytes(value)
    return value


_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_SUBREAPER_SCOPE_LOCK = threading.Lock()


class _ChildSubreaperScope:
    """Own every orphaned descendant for one serial campaign.

    Linux reparents orphans to the nearest living marked ancestor
    (``PR_SET_CHILD_SUBREAPER``) independently of session and process
    group, so ``setsid`` and double-fork daemonization cannot leave a
    candidate descendant outside comparator custody. The setting is
    process-wide: entry refuses while any direct child already exists,
    install and restore are serialized under one exclusive lock, and
    the prior setting is restored only after a final verified-empty
    ownership check. Any ambiguity fails closed before the first arm.
    """

    def __init__(self) -> None:
        self._entered = False
        self._previous = 0
        try:
            self._prctl = ctypes.CDLL(None, use_errno=True).prctl
        except (OSError, AttributeError) as error:
            raise ContractError(
                "child-subreaper ownership requires prctl(2)"
            ) from error
        # glibc prctl(2) is variadic: pin every argument to its full
        # 64-bit width so the kernel reads what the call site means.
        self._prctl.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        self._prctl.restype = ctypes.c_int

    def _get(self) -> int:
        value = ctypes.c_int(0)
        if (
            self._prctl(
                _PR_GET_CHILD_SUBREAPER,
                ctypes.addressof(value),
                0,
                0,
                0,
            )
            != 0
        ):
            raise ContractError(
                f"cannot read child-subreaper state: {os.strerror(ctypes.get_errno())}"
            )
        return value.value

    def _set(self, flag: int) -> None:
        if self._prctl(_PR_SET_CHILD_SUBREAPER, flag, 0, 0, 0) != 0:
            raise ContractError(
                f"cannot set child-subreaper state: {os.strerror(ctypes.get_errno())}"
            )

    def __enter__(self) -> Self:
        if sys.platform != "linux":
            raise ContractError("child-subreaper ownership requires Linux")
        if not _SUBREAPER_SCOPE_LOCK.acquire(blocking=False):
            raise ContractError("another child-subreaper ownership scope is active")
        try:
            try:
                thread_count = len(
                    [name for name in os.listdir("/proc/self/task") if name.isdigit()]
                )
            except OSError as error:
                raise ContractError(
                    f"cannot verify comparator thread ownership: {error}"
                ) from error
            if thread_count != 1:
                raise ContractError(
                    "child-subreaper ownership requires a single-threaded host at entry"
                )
            unowned = sorted(_direct_children_pids())
            if unowned:
                listed = ",".join(str(pid) for pid in unowned)
                raise ContractError(
                    f"comparator already owns child processes at entry: {listed}"
                )
            self._previous = self._get()
            self._set(1)
            if self._get() != 1:
                raise ContractError("child-subreaper state did not verify")
            self._entered = True
            return self
        except BaseException:
            _SUBREAPER_SCOPE_LOCK.release()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if not self._entered:
            return
        try:
            self._entered = False
            adopted = sorted(_direct_children_pids())
            if adopted:
                listed = ",".join(str(pid) for pid in adopted)
                raise ContractError(
                    f"comparator still owns adopted processes at exit: {listed}"
                )
            self._set(self._previous)
            if self._get() != self._previous:
                raise ContractError("child-subreaper state was not restored")
        finally:
            _SUBREAPER_SCOPE_LOCK.release()


def _read_proc_children(pid: int) -> list[int]:
    """List direct child pids from /proc, tolerating mid-read exits."""
    children: list[int] = []
    tasks = Path(f"/proc/{pid}/task")
    try:
        threads = [name for name in os.listdir(tasks) if name.isdigit()]
    except OSError:
        return children  # the process already exited; nothing to list
    for thread in threads:
        try:
            listing = (tasks / thread / "children").read_text()
        except OSError:
            continue  # the thread or process exited during the walk
        children.extend(int(token) for token in listing.split())
    return children


def _direct_children_pids() -> list[int]:
    return sorted(set(_read_proc_children(os.getpid())))


def _process_start_time(pid: int) -> int | None:
    """Read /proc start-time ticks; None once the process is gone."""
    try:
        return process_start_time(pid)
    except ContractError:
        return None


def _process_state_and_parent(pid: int) -> tuple[str, int] | None:
    """Read state and parent from one /proc stat snapshot."""
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    fields = stat_text.rpartition(")")[2].split()
    if len(fields) < 2:
        return None
    try:
        return fields[0], int(fields[1])
    except ValueError:
        return None


_DEAD_PROCESS_STATES = frozenset("ZX")


def _owning_start_time(pid: int) -> int | None:
    """Start-time ticks of a process that can still own children.

    The kernel reparents every child at the moment its parent exits, so
    an unreaped zombie owns nothing even though its /proc entry still
    verifies; treat it as gone for parent-edge validation.
    """
    start_time = _process_start_time(pid)
    observed = _process_state_and_parent(pid)
    if (
        start_time is None
        or observed is None
        or observed[0] in _DEAD_PROCESS_STATES
    ):
        return None
    return start_time


@dataclass(frozen=True)
class ProcessGeneration:
    pid: int
    start_time: int


def _process_parent_and_generation(pid: int) -> tuple[int, ProcessGeneration] | None:
    """Read parent and generation for one stable /proc generation."""
    before = _process_start_time(pid)
    if before is None:
        return None
    observed = _process_state_and_parent(pid)
    if observed is None:
        return None
    if _process_start_time(pid) != before:
        return None
    return observed[1], ProcessGeneration(pid, before)


def _self_generation() -> ProcessGeneration:
    """Pin this process's own generation for direct-child validation."""
    start_time = _process_start_time(os.getpid())
    if start_time is None:
        raise ContractError("cannot verify comparator process identity")
    return ProcessGeneration(os.getpid(), start_time)


def _host_child_generations(parent: ProcessGeneration) -> set[ProcessGeneration]:
    """Pin the host's own children before this process spawns a tree.

    Captured by the owner immediately before the spawn, so no member of
    the tree can exist yet: every direct child here belongs to the host
    and is never adopted, signaled, or reaped (P2P-OWNERSHIP-003). The
    set is generation-keyed, so a recycled pid is never covered by the
    entry that retired with the pid's previous generation, and a child
    that appears afterwards is a reparented tree member even when the
    leader exited before its identity could be published.
    """
    baseline: set[ProcessGeneration] = set()
    for pid in _direct_children_pids():
        identity = ProcessIdentity.adopt(pid, parent)
        if identity is None:
            continue
        baseline.add(identity.generation)
        identity.close()
    return baseline


@dataclass
class ProcessIdentity:
    """One owned process, addressable only through its verified pidfd."""

    pid: int
    start_time: int
    pidfd: int
    parent: ProcessGeneration | None = None

    @property
    def generation(self) -> ProcessGeneration:
        return ProcessGeneration(self.pid, self.start_time)

    @classmethod
    def adopt(
        cls, pid: int, expected_parent: ProcessGeneration | None = None
    ) -> "ProcessIdentity | None":
        """Pin one generation and prove its owned parent after pidfd_open."""
        first = _process_parent_and_generation(pid)
        if first is None:
            return None
        first_parent, generation = first
        if expected_parent is not None:
            parent_alive = (
                _owning_start_time(expected_parent.pid) == expected_parent.start_time
            )
            claimed = expected_parent.pid if parent_alive else os.getpid()
            if first_parent != claimed:
                return None  # pid reused before the first read: different parent
        try:
            pidfd = os.pidfd_open(pid)
        except OSError:
            return None  # the process exited between the two reads
        second = _process_parent_and_generation(pid)
        if second is None or second[1] != generation:
            os.close(pidfd)
            return None  # identity changed; the pid was reused
        if expected_parent is None:
            return cls(pid, generation.start_time, pidfd)
        parent_alive = (
            _owning_start_time(expected_parent.pid) == expected_parent.start_time
        )
        still_owned_child = second[0] == expected_parent.pid and parent_alive
        valid_reparent = second[0] == os.getpid() and not parent_alive
        if not (still_owned_child or valid_reparent):
            os.close(pidfd)
            return None  # the pinned process is not the listed owned child
        return cls(pid, generation.start_time, pidfd, expected_parent)

    def _still_owned(self) -> bool:
        current = _process_parent_and_generation(self.pid)
        if current is None or current[1] != self.generation:
            return False
        if self.parent is None:
            return True
        parent_start = _owning_start_time(self.parent.pid)
        return (
            current[0] == self.parent.pid and parent_start == self.parent.start_time
        ) or (current[0] == os.getpid() and parent_start != self.parent.start_time)

    def exists(self) -> bool:
        """True while this exact generation is still present in /proc."""
        current = _process_parent_and_generation(self.pid)
        return current is not None and current[1] == self.generation

    def signal(self, number: int) -> bool:
        """Signal only while generation and owned ancestry still verify."""
        if not self._still_owned():
            return False
        try:
            signal.pidfd_send_signal(self.pidfd, number)
            return True
        except ProcessLookupError:
            return False
        except (OSError, ValueError):
            return False  # kernel refusal or invalid signal: treat as unsettled

    def alive(self) -> bool:
        return self.signal(0)

    def close(self) -> None:
        try:
            os.close(self.pidfd)
        except OSError:
            pass  # already closed by a prior release of this identity


class _DescendantDrain:
    """Drives one arm's descendant tree to an empty owned fixed point.

    Membership is generation-keyed ``(pid, start_time)`` state backed by
    a pidfd per member: discovery walks owned parent edges, revalidates
    parentage and generation after every pidfd_open, and never signals
    or reaps from a bare pid. The arm owner pins the host's own children
    before the spawn and injects them here; the set stays forbidden for
    the drain's lifetime, so a direct child appearing afterwards is a
    reparented tree member — swept whether or not the leader's identity
    ever published — and double-fork daemonization cannot disguise an
    escapee as host-owned.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes] | None,
        root: ProcessIdentity | ProcessGeneration | None,
        host_baseline: set[ProcessGeneration] | None = None,
    ) -> None:
        self._process = process
        self._root = (
            None
            if root is None
            else (root.generation if isinstance(root, ProcessIdentity) else root)
        )
        self._identities: dict[ProcessGeneration, ProcessIdentity] = {}
        self._gone: set[ProcessGeneration] = set()
        self._termed: set[ProcessGeneration] = set()
        self._forbidden = set() if host_baseline is None else set(host_baseline)
        self.violated = False

    @property
    def settled(self) -> bool:
        return not self._identities

    def _root_gone(self) -> bool:
        return self._process is None or self._process.poll() is not None

    def _discover(self) -> None:
        """Acquire undiscovered tree members, bounded by one cancel slice.

        While the leader lives the walk starts at its generation plus
        every tracked identity. After it is reaped, reparented tree
        members appear as direct children of this process; the sweep
        adopts them through a revalidated parent edge and never a
        pre-spawn host identity, whether or not the leader's identity
        published. Each adoption pins the pidfd first and rechecks
        generation and ancestry afterwards (P2P-IDENTITY-004).
        """
        frontier: list[ProcessGeneration] = []
        if self._root_gone():
            self_generation = _self_generation()
            for pid in _direct_children_pids():
                identity = ProcessIdentity.adopt(pid, self_generation)
                if identity is None:
                    continue
                generation = identity.generation
                if (
                    generation in self._forbidden
                    or generation in self._gone
                    or generation in self._identities
                ):
                    identity.close()
                    continue
                self._identities[generation] = identity
                frontier.append(generation)
        elif self._root is not None:
            frontier.append(self._root)
        frontier.extend(identity.generation for identity in self._identities.values())
        seen = set(frontier)
        seen_pids = {generation.pid for generation in seen}
        budget = time.monotonic_ns() + _CANCEL_SLICE_NS
        while frontier:
            parent = frontier.pop()
            if _process_start_time(parent.pid) != parent.start_time:
                continue  # parent exited or its pid was reused: no owned edge
            for child in _read_proc_children(parent.pid):
                if child in seen_pids:
                    continue
                identity = ProcessIdentity.adopt(child, parent)
                if identity is None:
                    continue
                generation = identity.generation
                seen_pids.add(generation.pid)
                if generation in seen or generation in self._gone:
                    identity.close()
                    continue
                seen.add(generation)
                self._identities[generation] = identity
                frontier.append(generation)
            if time.monotonic_ns() >= budget:
                return  # the next sweep continues the walk

    def observe(self) -> None:
        """Capture owned edges and exits under the pinned host baseline.

        Host children were pinned once when this drain was created, so
        classification never runs here; anything newly visible is a
        reparented tree member discovered through owned edges
        (P2P-OWNERSHIP-003).
        """
        self._discover()
        self._reap_gone()

    def _reap_gone(self) -> None:
        """Reap exactly known generations; never retain a numeric tombstone.

        A member that is not this process's child yet is retired only once
        its generation has left /proc: a refused signal is not an exit, and
        a live member still under another tree member reparents here later
        and must stay tracked until it is reaped.
        """
        for generation, identity in list(self._identities.items()):
            try:
                done, _ = os.waitpid(identity.pid, os.WNOHANG)
            except ChildProcessError:
                if not identity.exists():
                    identity.close()
                    del self._identities[generation]
                    self._gone.add(generation)
                continue
            if done == identity.pid:
                identity.close()
                del self._identities[generation]
                self._gone.add(generation)

    def _signal_all(self, number: int, *, only_new: bool = False) -> None:
        for generation, identity in list(self._identities.items()):
            if only_new:
                if generation in self._termed:
                    continue
                self._termed.add(generation)
            identity.signal(number)

    def finish(self, *, violated_when_present: bool, deadline_ns: int) -> None:
        """TERM, KILL, reap, and rescan to two consecutive empty sweeps."""
        exhausted = "descendant ownership did not drain to an empty fixed point"
        term_deadline = min(deadline_ns, time.monotonic_ns() + CHILD_TERMINATE_GRACE_NS)
        while True:
            now = time.monotonic_ns()
            if now >= deadline_ns:
                raise ContractError(exhausted)
            self._discover()
            if self._identities and violated_when_present:
                self.violated = True
            self._reap_gone()
            if not self._identities:
                slice_s = min(_CANCEL_SLICE_NS, deadline_ns - now) / 1_000_000_000
                time.sleep(max(0.0, slice_s))
                if time.monotonic_ns() >= deadline_ns:
                    raise ContractError(exhausted)
                self._discover()
                if not self._identities:
                    return
                if violated_when_present:
                    self.violated = True
                term_deadline = min(
                    deadline_ns, time.monotonic_ns() + CHILD_TERMINATE_GRACE_NS
                )
                self._signal_all(signal.SIGTERM, only_new=True)
            elif now >= term_deadline:
                self._signal_all(signal.SIGKILL)
            else:
                self._signal_all(signal.SIGTERM, only_new=True)
            slice_s = min(_CANCEL_SLICE_NS, deadline_ns - time.monotonic_ns())
            time.sleep(max(0.0, slice_s / 1_000_000_000))


def _close_quietly(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # never connected or already closed; close() below is the authority
    connection.close()


class ArmState(Enum):
    """The one-way lifecycle of a single arm under its sole owner."""

    CREATED = auto()
    WORKER_RUNNING = auto()
    PRIMARY_RUNNING = auto()
    PRIMARY_CLEAN = auto()
    RESTART_RUNNING = auto()
    RESTART_CLEAN = auto()
    CLOSED = auto()


class ArmProcess:
    """Single owner of one arm's sockets, worker, leaders, and deadline.

    Entering the context starts the peer worker; from that moment every
    outcome — digest failure, spawn failure, timeout, restart, or any
    exception — leaves through the same ``close()``: owned leaders are
    TERMed, KILLed, and reaped through verified pidfd identity,
    descendants are drained to an empty fixed point, sockets are shut
    down, and the worker is joined inside the arm deadline's cleanup
    reserve. ``start_new_session`` is terminal isolation only; process
    ownership never derives from session or process group.
    """

    def __init__(
        self,
        config: Config,
        role: str,
        binary_path: Path,
        arm_dir: Path,
        deadline_ns: int,
    ) -> None:
        self._config = config
        self._role = role
        self._binary_path = binary_path
        self._arm_dir = arm_dir
        self._deadline_ns = deadline_ns
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.setsockopt(
            socket.SOL_SOCKET, socket.SO_SNDBUF, config.peer.socket_buffer_bytes
        )
        self._listener.setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF, config.peer.socket_buffer_bytes
        )
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(config.peer.connect_timeout_ns / 1_000_000_000)
        host, port = self._listener.getsockname()
        self._host = str(host)
        self._port = int(port)
        self._cancel = threading.Event()
        self._ready = threading.Event()
        self._worker: threading.Thread | None = None
        self._observations: list[PeerObservation] = []
        self._connections: list[socket.socket] = []
        self._process: subprocess.Popen[bytes] | None = None
        self._root_identity: ProcessIdentity | None = None
        self._descendants: _DescendantDrain | None = None
        self._surviving_descendant_seen = False
        self._state = ArmState.CREATED

    def __enter__(self) -> Self:
        if self._state is not ArmState.CREATED:
            raise ContractError("arm context is not reenterable")
        if self._deadline_ns - time.monotonic_ns() <= 0:
            raise ContractError(f"{self._role} ran out of its arm deadline")
        self._worker = threading.Thread(
            target=_peer_worker,
            args=(
                self._listener,
                self._config,
                self._ready,
                self._observations,
                self._cancel,
                self._connections,
                self._deadline_ns,
            ),
            name=f"p2p-loopback-peer-{self._port}",
        )
        self._worker.start()
        self._state = ArmState.WORKER_RUNNING
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def observations(self) -> list[PeerObservation]:
        return self._observations

    def worker_alive(self) -> bool:
        return self._worker is not None and self._worker.is_alive()

    @property
    def surviving_descendant_seen(self) -> bool:
        return self._surviving_descendant_seen

    def require_ready(self) -> None:
        """Wait for the peer worker within the arm deadline."""
        if self._state is not ArmState.WORKER_RUNNING:
            raise ContractError("arm worker was not started")
        budget_s = (self._deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if budget_s <= 0:
            raise ContractError(f"{self._role} ran out of its arm deadline")
        if not self._ready.wait(budget_s):
            raise ContractError("loopback peer did not become ready")

    def launch(self, command: Sequence[str], phase: str) -> None:
        """Spawn and publish ownership as one interruption-safe transaction."""
        allowed = (ArmState.WORKER_RUNNING, ArmState.PRIMARY_CLEAN)
        if self._state not in allowed:
            raise ContractError(f"arm cannot launch {phase} in {self._state.name}")
        budget_s = (self._deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if budget_s <= 0:
            raise ContractError(f"{self._role} ran out of its arm deadline")
        state_path = self._arm_dir / (
            "restart-state.json" if phase == "restart" else "state.json"
        )
        expanded = _expand_command(
            tuple(command),
            self._binary_path,
            self._host,
            self._port,
            self._arm_dir / "data",
            state_path,
        )
        process: subprocess.Popen[bytes] | None = None
        identity: ProcessIdentity | None = None
        root: ProcessGeneration | None = None
        published = False
        # Pin the supervisor and its children before the spawn. Every later
        # identity must prove an edge back to this exact process generation.
        supervisor = _self_generation()
        host_baseline = _host_child_generations(supervisor)
        try:
            process = subprocess.Popen(
                expanded, shell=False, close_fds=True, start_new_session=True
            )
            snapshot = _process_parent_and_generation(process.pid)
            root = None if snapshot is None else snapshot[1]
            identity = ProcessIdentity.adopt(process.pid, supervisor)
            if identity is None:
                raise ContractError(
                    f"{self._role} {phase} process identity failed verification"
                )
            descendants = _DescendantDrain(process, identity, host_baseline)
            descendants.observe()
            self._process = process
            self._root_identity = identity
            self._descendants = descendants
            self._state = (
                ArmState.RESTART_RUNNING
                if phase == "restart"
                else ArmState.PRIMARY_RUNNING
            )
            published = True
        except BaseException as error:
            if process is not None and not published:
                try:
                    self._cleanup_unpublished_process(
                        process, identity, root, supervisor, host_baseline
                    )
                # An interrupt does not release ownership of the unpublished child.
                except BaseException as cleanup_error:  # noqa: BLE001
                    error.add_note(f"spawn cleanup also failed: {cleanup_error}")
            raise

    def wait_clean(self) -> int:
        """Reap the leader and drain descendants; return the leader's code.

        A leader outliving the work deadline (the arm deadline minus its
        cleanup reserve) is TERMed, KILLed, and reaped first; the
        timeout itself is then fatal. A descendant discovered after a
        normal leader exit rejects the arm even if cleanup succeeds.
        """
        running = (ArmState.PRIMARY_RUNNING, ArmState.RESTART_RUNNING)
        if self._state not in running:
            raise ContractError("arm has no running leader to wait for")
        process = self._process
        identity = self._root_identity
        descendants = self._descendants
        if process is None or identity is None or descendants is None:
            raise ContractError("arm has no owned leader to wait for")
        work_deadline = self._deadline_ns - _OWNERSHIP_CLEANUP_RESERVE_NS
        code: int | None = None
        if time.monotonic_ns() < work_deadline:
            code = self._wait_popen(process, work_deadline, descendants.observe)
        if code is None:
            self._terminate_and_reap(process, identity, self._deadline_ns)
            self._drain(violated_when_present=False, deadline_ns=self._deadline_ns)
            if self._state is ArmState.RESTART_RUNNING:
                raise ContractError(
                    f"{self._role} restart exceeded its monotonic deadline"
                )
            raise ContractError(f"{self._role} exceeded its monotonic arm deadline")
        self._release_root()
        self._drain(violated_when_present=True, deadline_ns=self._deadline_ns)
        self._state = (
            ArmState.RESTART_CLEAN
            if self._state is ArmState.RESTART_RUNNING
            else ArmState.PRIMARY_CLEAN
        )
        return code

    def collect_worker(self) -> None:
        """Boundedly settle the worker after its leader has been reaped."""
        if self._worker is None or not self._worker.is_alive():
            return
        if not self._connections:
            # The leader is gone, so no valid peer can present the magic;
            # stop the hunt instead of waiting out the arm deadline.
            self._cancel.set()
        self._worker.join(WORKER_JOIN_GRACE_NS / 1_000_000_000)

    def terminate_worker(self) -> None:
        """Force the peer worker out of blocking calls, then bound its join."""
        self._cancel.set()
        for connection in self._connections:
            _close_quietly(connection)
        _close_quietly(self._listener)
        if self._worker is not None:
            self._worker.join(WORKER_JOIN_GRACE_NS / 1_000_000_000)

    def close(self) -> None:
        """Settle every resource under a fresh deadline; remain retryable if not settled."""
        if self._state is ArmState.CLOSED:
            return
        cleanup_deadline = time.monotonic_ns() + _OWNERSHIP_CLEANUP_RESERVE_NS
        first_error: BaseException | None = None

        def attempt(operation: Callable[[], None]) -> None:
            nonlocal first_error
            try:
                operation()
            # Close must settle later resources after any process-level interrupt.
            except BaseException as error:  # noqa: BLE001
                if first_error is None:
                    first_error = error

        process = self._process
        identity = self._root_identity
        if process is not None and identity is not None:
            attempt(
                lambda: self._terminate_and_reap(process, identity, cleanup_deadline)
            )
        if self._descendants is not None:
            attempt(
                lambda: self._drain(
                    violated_when_present=False, deadline_ns=cleanup_deadline
                )
            )

        def close_peer() -> None:
            self._cancel.set()
            for connection in self._connections:
                _close_quietly(connection)
            _close_quietly(self._listener)

        attempt(close_peer)

        def join_worker() -> None:
            worker = self._worker
            if worker is None:
                return
            remaining = max(0, cleanup_deadline - time.monotonic_ns())
            worker.join(min(WORKER_JOIN_GRACE_NS, remaining) / 1_000_000_000)
            if worker.is_alive():
                raise ContractError("loopback peer did not terminate after cancel")

        attempt(join_worker)
        attempt(self._release_root_if_reaped)
        settled = (
            self._process is None
            and self._root_identity is None
            and self._descendants is None
            and (self._worker is None or not self._worker.is_alive())
            and self._listener.fileno() == -1
        )
        if settled:
            self._state = ArmState.CLOSED
        if first_error is not None:
            raise first_error
        if not settled:
            raise ContractError("arm cleanup did not settle all owned resources")

    @staticmethod
    def _wait_popen(
        process: subprocess.Popen[bytes],
        deadline_ns: int,
        observe: Callable[[], None] | None = None,
    ) -> int | None:
        while True:
            if observe is not None:
                observe()
            try:
                return process.wait(timeout=0.005)
            except subprocess.TimeoutExpired:
                pass  # keep waiting inside the same bounded deadline
            if time.monotonic_ns() >= deadline_ns:
                return None

    def _terminate_and_reap(
        self,
        process: subprocess.Popen[bytes],
        identity: ProcessIdentity,
        deadline_ns: int,
    ) -> None:
        descendants = self._descendants
        observe = None if descendants is None else descendants.observe
        if identity.alive():
            identity.signal(signal.SIGTERM)
            grace = min(deadline_ns, time.monotonic_ns() + CHILD_TERMINATE_GRACE_NS)
            if self._wait_popen(process, grace, observe) is None and identity.alive():
                identity.signal(signal.SIGKILL)
        if self._wait_popen(process, deadline_ns, observe) is None:
            raise ContractError(
                f"{self._role} process resisted termination within its deadline"
            )
        self._release_root()

    def _cleanup_unpublished_process(
        self,
        process: subprocess.Popen[bytes],
        identity: ProcessIdentity | None,
        root: ProcessGeneration | None,
        supervisor: ProcessGeneration,
        host_baseline: set[ProcessGeneration],
    ) -> None:
        if identity is None and root is not None:
            recovered = ProcessIdentity.adopt(root.pid, supervisor)
            if recovered is not None:
                if recovered.generation == root:
                    identity = recovered
                else:
                    recovered.close()
        deadline = time.monotonic_ns() + _OWNERSHIP_CLEANUP_RESERVE_NS
        drain = _DescendantDrain(
            process, identity if identity is not None else root, host_baseline
        )
        drain.observe()
        if process.poll() is None and identity is not None:
            identity.signal(signal.SIGTERM)
            grace = min(deadline, time.monotonic_ns() + CHILD_TERMINATE_GRACE_NS)
            if (
                self._wait_popen(process, grace, drain.observe) is None
                and identity.alive()
            ):
                identity.signal(signal.SIGKILL)
        if self._wait_popen(process, deadline, drain.observe) is None:
            if identity is None:
                raise ContractError(
                    "spawned process identity could not be verified during cleanup"
                )
            raise ContractError("spawned process resisted registration-failure cleanup")
        if identity is not None:
            identity.close()
        drain.finish(violated_when_present=False, deadline_ns=deadline)

    def _release_root_if_reaped(self) -> None:
        if self._process is not None and self._process.poll() is None:
            raise ContractError("owned leader is still running")
        self._release_root()

    def _release_root(self) -> None:
        if self._root_identity is not None:
            self._root_identity.close()
            self._root_identity = None
        self._process = None

    def _drain(self, *, violated_when_present: bool, deadline_ns: int) -> None:
        drain = self._descendants
        if drain is None:
            return
        try:
            drain.finish(
                violated_when_present=violated_when_present, deadline_ns=deadline_ns
            )
        finally:
            if drain.violated:
                self._surviving_descendant_seen = True
        if drain.settled:
            self._descendants = None
        if drain.violated:
            suffix = " restart" if "RESTART" in self._state.name else ""
            raise ContractError(
                f"{self._role}{suffix} left descendant processes running after exit"
            )


_PUBLIC_PLACEHOLDERS = {
    "{binary}": "<binary>",
    "{peer_host}": "<peer-host>",
    "{peer_port}": "<peer-port>",
    "{data_dir}": "<data-dir>",
    "{state_path}": "<state-path>",
}
_ARGUMENT_MARKER = "<argument>"


def _public_argv(argv: Sequence[str]) -> list[str]:
    """Project argv to categories containing no arbitrary token text."""
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
    """Hash the canonical public argv projection; raw text is never durable."""
    return hashlib.sha256(canonical_bytes(_public_argv(argv))).hexdigest()


def _run_arm(
    config: Config, program: Program, pair_index: int, order_index: int, root: Path
) -> ArmObservation:
    arm_start = time.monotonic_ns()
    arm_deadline_ns = arm_start + config.peer.connect_timeout_ns + MAX_ARM_DURATION_NS
    arm_dir = root / f"{order_index:02d}-{program.role}"
    arm_dir.mkdir(parents=True)
    binary_path = copy_pinned(
        program.binary, arm_dir / "node-under-test", program.binary_sha256
    )
    data_dir = arm_dir / "data"
    data_dir.mkdir()
    (data_dir / "lifecycle-initial.json").write_bytes(
        canonical_bytes(config.lifecycle.initial_state)
    )
    with ArmProcess(config, program.role, binary_path, arm_dir, arm_deadline_ns) as arm:
        arm.require_ready()
        started = time.monotonic_ns()
        arm.launch(program.command, "primary")
        exit_code = arm.wait_clean()
        arm.collect_worker()
        if arm.worker_alive():
            arm.terminate_worker()
            if arm.worker_alive():
                raise ContractError("loopback peer did not terminate after cancel")
            else:
                raise ContractError(
                    f"{program.role} exited before the peer contract completed"
                )
        if len(arm.observations) != 1:
            raise ContractError("loopback peer did not publish exactly one observation")
        peer = arm.observations[0]
        final_state = _state(arm_dir / "state.json", f"{program.role} final state")
        final_hash = canonical_sha256(final_state)
        wall_ns = time.monotonic_ns() - started
        restart_exit: int | None = None
        restart_state: JsonObject | None = None
        restart_hash: str | None = None
        restart_digest: str | None = None
        restart_arg_count: int | None = None
        if config.lifecycle.mode == "restart":
            if program.restart_command is None:
                raise ContractError(f"{program.role} has no restart command")
            arm.launch(program.restart_command, "restart")
            restart_exit = arm.wait_clean()
            restart_state = _state(
                arm_dir / "restart-state.json", f"{program.role} restart state"
            )
            restart_hash = canonical_sha256(restart_state)
            restart_digest = _argv_digest(program.restart_command)
            restart_arg_count = len(program.restart_command)
        full_corpus = b"".join(frame.wire for frame in config.corpus)
        inbound_ok = (
            config.peer.expected_inbound_sha256 is None
            or peer.inbound_sha256 == config.peer.expected_inbound_sha256
        )
        protocol_ok = (
            exit_code == 0
            and peer.connected
            and peer.error is None
            and peer.completed_steps == len(config.schedule)
            and peer.sent_bytes == len(full_corpus)
            and peer.sent_sha256 == hashlib.sha256(full_corpus).hexdigest()
            and inbound_ok
        )
        state_ok = final_state == config.lifecycle.expected_final_state
        if config.lifecycle.mode == "restart":
            state_ok = (
                state_ok
                and restart_exit == 0
                and restart_state == config.lifecycle.expected_restart_state
            )
        errors: list[str] = []
        if not protocol_ok:
            errors.append("protocol contract failed")
        if not state_ok:
            errors.append("lifecycle state contract failed")
        return ArmObservation(
            pair_index,
            order_index,
            program.role,
            str(binary_path),
            program.binary_sha256,
            _argv_digest(program.command),
            len(program.command),
            restart_digest,
            restart_arg_count,
            wall_ns,
            exit_code,
            peer,
            final_state,
            final_hash,
            restart_exit,
            restart_state,
            restart_hash,
            protocol_ok,
            state_ok,
            "; ".join(errors) or None,
        )


def _peer_json(peer: PeerObservation) -> JsonObject:
    return {
        "connected": peer.connected,
        "sent_bytes": peer.sent_bytes,
        "sent_sha256": peer.sent_sha256,
        "inbound_bytes": peer.inbound_bytes,
        "inbound_sha256": peer.inbound_sha256,
        "completed_steps": peer.completed_steps,
        "disconnect_expected": peer.disconnect_expected,
        "error": peer.error,
    }


def _arm_json(arm: ArmObservation) -> JsonObject:
    return {
        "pair_index": arm.pair_index,
        "order_index": arm.order_index,
        "role": arm.role,
        "binary_path": arm.binary_path,
        "binary_sha256": arm.binary_sha256,
        "command_sha256": arm.command_sha256,
        "command_arg_count": arm.command_arg_count,
        "restart_command_sha256": arm.restart_command_sha256,
        "restart_command_arg_count": arm.restart_command_arg_count,
        "wall_ns": arm.wall_ns,
        "exit_code": arm.exit_code,
        "peer": _peer_json(arm.peer),
        "final_state": arm.final_state,
        "final_state_sha256": arm.final_state_sha256,
        "restart_exit_code": arm.restart_exit_code,
        "restart_state": arm.restart_state,
        "restart_state_sha256": arm.restart_state_sha256,
        "protocol_ok": arm.protocol_ok,
        "state_ok": arm.state_ok,
        "error": arm.error,
    }


def _require_comparable(config: Config, arms: Sequence[ArmObservation]) -> None:
    if len(arms) != PAIR_COUNT * 2:
        raise ContractError("campaign does not contain exactly seven pairs")
    for pair_index in range(PAIR_COUNT):
        pair = [arm for arm in arms if arm.pair_index == pair_index]
        if len(pair) != 2 or {arm.role for arm in pair} != {"core", "candidate"}:
            raise ContractError(f"pair {pair_index} does not contain both roles")
        first_role = "core" if pair_index % 2 == 0 else "candidate"
        if min(pair, key=lambda arm: arm.order_index).role != first_role:
            raise ContractError(f"pair {pair_index} violates alternating order")
        left, right = pair
        custody_left = (
            config.corpus_sha256,
            config.schedule_sha256,
            config.peer_sha256,
            config.lifecycle_sha256,
            left.peer.sent_sha256,
            left.peer.sent_bytes,
        )
        custody_right = (
            config.corpus_sha256,
            config.schedule_sha256,
            config.peer_sha256,
            config.lifecycle_sha256,
            right.peer.sent_sha256,
            right.peer.sent_bytes,
        )
        if custody_left != custody_right:
            raise ContractError(
                f"pair {pair_index} consumed different bytes or peer contracts"
            )
        if not left.protocol_ok or not right.protocol_ok:
            raise ContractError(f"pair {pair_index} has a protocol failure")
        if (
            not left.state_ok
            or not right.state_ok
            or left.final_state != right.final_state
        ):
            raise ContractError(f"pair {pair_index} has a lifecycle state mismatch")
        if left.restart_state != right.restart_state:
            raise ContractError(f"pair {pair_index} has a restart state mismatch")


def _supervisor_interrupt(signum: int, frame: FrameType | None) -> None:
    """Turn a termination signal into an interrupt so cleanup chains run."""
    del frame
    raise KeyboardInterrupt(f"campaign supervisor received signal {signum}")


def _reject_multithreaded_host() -> None:
    """Refuse to fork from a host whose threads cannot be proven absent."""
    try:
        threads = os.listdir("/proc/self/task")
    except OSError as error:
        raise ContractError(f"cannot inspect host threads: {error}") from error
    if sum(1 for name in threads if name.isdigit()) != 1:
        raise ContractError("campaign requires a single-threaded host process")


def _report_campaign_outcome(write_fd: int, payload: JsonObject) -> None:
    """Best-effort report to the host; a dead host means nothing to tell."""
    try:
        data = json.dumps(payload).encode("utf-8")
        while data:
            written = os.write(write_fd, data)
            data = data[written:]
    except BrokenPipeError:
        return  # the host closed the pipe; there is nobody left to report to


def _collect_campaign_report(read_fd: int) -> JsonObject:
    """Read the supervisor report until end-of-file."""
    chunks: list[bytes] = []
    while True:
        chunk = os.read(read_fd, 65_536)
        if not chunk:
            break
        chunks.append(chunk)
    if not chunks:
        raise ContractError("campaign supervisor exited without a report")
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ContractError(
            f"campaign supervisor report is unreadable: {error}"
        ) from error
    if not isinstance(payload, dict):
        raise ContractError("campaign supervisor report is malformed")
    return payload


def _stop_supervisor(pid: int) -> None:
    """Stop the supervisor so its own cleanup drains the tree, then reap it."""
    deadline = time.monotonic_ns() + CHILD_TERMINATE_GRACE_NS + CHILD_KILL_REAP_NS
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass  # the supervisor already exited; only the reap below remains
    while True:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return  # the supervisor was reaped elsewhere; nothing left to own
        if done == pid:
            return
        if time.monotonic_ns() >= deadline:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # the supervisor exited between the check and the kill
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass  # the supervisor was reaped elsewhere; nothing left to own
            return
        time.sleep(0.005)


def run_campaign(config: Config, output_root: Path) -> JsonObject:
    """Run one comparator campaign inside a dedicated supervisor process.

    The supervisor is forked from a verified single-threaded host and is
    the only process that installs child-subreaper ownership, so every
    direct child it can ever see belongs to the benchmark tree; host
    children of the embedding process are never adopted, signaled, or
    reaped (P2P-OWNERSHIP-003). The supervisor reports the result or
    the failure over one pipe, and on host cancellation it is stopped so
    its own finally-chains drain the tree before it exits.
    """
    _reject_multithreaded_host()
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except OSError as error:
        os.close(read_fd)
        os.close(write_fd)
        raise ContractError(f"cannot start campaign supervisor: {error}") from error
    if pid == 0:
        # Supervisor: its only possible children are the benchmark arms.
        os.close(read_fd)
        code = 0
        try:
            signal.signal(signal.SIGTERM, _supervisor_interrupt)
            try:
                result = _run_campaign_locked(config, output_root)
            # The supervisor must report every terminating exception to its parent.
            except BaseException as error:  # noqa: BLE001
                _report_campaign_outcome(
                    write_fd,
                    {
                        "kind": "error",
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                )
                code = 1
            else:
                _report_campaign_outcome(write_fd, {"kind": "result", "result": result})
        finally:
            os.close(write_fd)
        os._exit(code)
    os.close(write_fd)
    payload: JsonObject | None = None
    reaped = False
    try:
        payload = _collect_campaign_report(read_fd)
        os.waitpid(pid, 0)
        reaped = True
    finally:
        if not reaped:
            # The host is unwinding (for example KeyboardInterrupt): stop the
            # supervisor so its own finally-chains drain the tree, then reap.
            _stop_supervisor(pid)
        os.close(read_fd)
    if payload is not None and payload.get("kind") == "result":
        result = payload.get("result")
        if not isinstance(result, dict):
            raise ContractError("campaign supervisor reported a malformed result")
        return result
    if payload is not None and payload.get("kind") == "error":
        type_name = str(payload.get("type", ""))
        message = str(payload.get("message", ""))
        if type_name == "ContractError":
            raise ContractError(message)
        if type_name == "KeyboardInterrupt":
            raise KeyboardInterrupt(message)
        raise ContractError(f"campaign supervisor failed: {type_name}: {message}")
    raise ContractError("campaign supervisor did not report a result")


def _run_campaign_locked(config: Config, output_root: Path) -> JsonObject:
    """The campaign body that must run under child-subreaper ownership."""
    if _hash_file(config.core.binary) != config.core.binary_sha256:
        raise ContractError("core binary identity does not match config")
    if _hash_file(config.candidate.binary) != config.candidate.binary_sha256:
        raise ContractError("candidate binary identity does not match config")
    with _ChildSubreaperScope():
        output_root.mkdir(parents=True, exist_ok=False)
        arms: list[ArmObservation] = []
        order_index = 0
        for pair_index in range(PAIR_COUNT):
            programs = (
                (config.core, config.candidate)
                if pair_index % 2 == 0
                else (config.candidate, config.core)
            )
            for program in programs:
                arms.append(
                    _run_arm(config, program, pair_index, order_index, output_root)
                )
                order_index += 1
    _require_comparable(config, arms)
    core_values = [arm.wall_ns for arm in arms if arm.role == "core"]
    candidate_values = [arm.wall_ns for arm in arms if arm.role == "candidate"]
    core_summary = summarize(core_values)
    candidate_summary = summarize(candidate_values)
    core_p50 = core_summary["p50_ns"]
    candidate_p50 = candidate_summary["p50_ns"]
    result: JsonObject = {
        "schema": RESULT_SCHEMA,
        "config_sha256": config.canonical_sha256,
        "pair_count": PAIR_COUNT,
        "alternation": "core-first-on-even-pairs",
        "custody": {
            "network_magic": config.peer.network_magic.hex(),
            "protocol_version": config.peer.protocol_version,
            "services": config.peer.services,
            "corpus_sha256": config.corpus_sha256,
            "schedule_sha256": config.schedule_sha256,
            "peer_sha256": config.peer_sha256,
            "lifecycle_sha256": config.lifecycle_sha256,
            "core_binary_sha256": config.core.binary_sha256,
            "candidate_binary_sha256": config.candidate.binary_sha256,
            "lifecycle_mode": config.lifecycle.mode,
            "lifecycle_generation": config.lifecycle.generation,
        },
        "correctness": {
            "bytes_equal": True,
            "schedule_equal": True,
            "peer_parameters_equal": True,
            "protocol_ok": True,
            "state_equal": True,
            "restart_state_equal": True,
        },
        "arms": [_arm_json(arm) for arm in arms],
        "statistics": {"core": core_summary, "candidate": candidate_summary},
        "candidate_over_core_p50_ratio": candidate_p50 / core_p50,
    }
    result["result_sha256"] = canonical_sha256(result)
    return result


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
        prefix="p2p-loopback-", dir=output.parent
    ) as temporary:
        work = Path(temporary) / "arms"
        result = run_campaign(config, work)
        publish_result(result, output)
    return 0


def _fatal(error: Exception) -> NoReturn:
    print(f"p2p-loopback: {error}", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContractError, OSError, subprocess.SubprocessError) as error:
        _fatal(error)
