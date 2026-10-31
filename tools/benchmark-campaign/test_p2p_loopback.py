#!/usr/bin/env python3.14
# pyright: strict
"""Behavioral tests for the deterministic P2P loopback comparator."""

import hashlib
import json
import math
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import TypeIs
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))

import p2p_loopback
from evidence import (
    MAX_JSON_DEPTH,
    ContractError,
    _percentile,
    _publish_result,
    canonical_bytes,
    canonical_sha256,
    summarize,
)
from p2p_loopback import (
    _MAX_PENDING_CANDIDATES,
    CONFIG_SCHEMA,
    MAX_ARM_DURATION_NS,
    MAX_COMMAND_ARGS,
    MAX_CONFIG_BYTES,
    MAX_CONNECT_TIMEOUT_NS,
    MAX_CORPUS_BYTES,
    MAX_FRAME_BYTES,
    MAX_IO_TIMEOUT_NS,
    MAX_STATE_BYTES,
    PAIR_COUNT,
    RESULT_SCHEMA,
    ArmObservation,
    ArmProcess,
    Config,
    PeerObservation,
    ProcessGeneration,
    ProcessIdentity,
    Program,
    _accept_magic_peer,
    _argv_digest,
    _candidate_magic,
    _ChildSubreaperScope,
    _DescendantDrain,
    _hash_file,
    _host_child_generations,
    _load_json,
    _process_start_time,
    _public_argv,
    _require_comparable,
    _self_generation,
    _send_paced,
    _sleep_until,
    _state,
    _verified_copy,
    _verify_copy_digest,
    load_config,
    main,
    parse_config,
    run_campaign,
)

JsonObject = dict[str, object]
MAGIC = "f9beb4d9"
HASH64 = "ab" * 32
OUTPUT_NAME = Path("out") / "result.json"


def _is_object(value: object) -> TypeIs[JsonObject]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _object(value: object) -> JsonObject:
    if not _is_object(value):
        raise TypeError("expected JSON object")
    return value


def _array(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"{field} must be an array")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    return value


def _number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{field} must be a number")
    return float(value)


def _arms_list(value: object) -> list[object]:
    return _array(value, "result.arms")


def _frame(index: int, command: str, payload: bytes, magic: str = MAGIC) -> bytes:
    wire_payload = bytes([index]) * 8 + payload
    head = bytes.fromhex(magic) + command.encode("ascii").ljust(12, b"\0")[:12]
    head += len(wire_payload).to_bytes(4, "little")
    head += hashlib.sha256(hashlib.sha256(wire_payload).digest()).digest()[:4]
    return head + wire_payload


def _write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wait_pid_gone(pid: int, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            return True
        time.sleep(0.02)
    return False


def _wait_for_file(path: Path, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.02)
    return False


def _escape_helper_pids(arms_dir: Path) -> list[int]:
    markers = sorted(arms_dir.rglob("*.helper-pid"))
    return [int(marker.read_text()) for marker in markers]


def _no_survivor_markers(arms_dir: Path) -> bool:
    return not any(True for _ in arms_dir.rglob("*.helper-survived"))


class _RecvMeter:
    def __init__(self) -> None:
        self.total = 0


class _FakePeer:
    def __init__(self, chunks: list[bytes | None], meter: _RecvMeter) -> None:
        self._chunks = list(chunks)
        self._meter = meter
        self.closed = False
        self.recvs = 0

    def setblocking(self, flag: bool) -> None:
        return None

    def recv(self, size: int, flags: int = 0) -> bytes:
        self.recvs += 1
        self._meter.total += 1
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if chunk is None:
            raise BlockingIOError()
        return chunk

    def shutdown(self, how: int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeListener:
    def __init__(self) -> None:
        self.arrivals: list[_FakePeer] = []
        self.accepts = 0

    def setblocking(self, flag: bool) -> None:
        return None

    def accept(self) -> tuple[_FakePeer, tuple[str, int]]:
        if not self.arrivals:
            raise BlockingIOError()
        self.accepts += 1
        return self.arrivals.pop(0), ("127.0.0.1", 1)

    def close(self) -> None:
        return None


class _FakeSelector:
    def __init__(self, listener: _FakeListener, meter: _RecvMeter) -> None:
        self._listener = listener
        self._meter = meter
        self._registered: list[object] = []
        self.tick_count = 0
        self.max_accepts_per_tick = 0
        self.max_recvs_per_tick = 0

    def register(self, fileobj: object, events: int) -> None:
        self._registered.append(fileobj)

    def unregister(self, fileobj: object) -> None:
        self._registered.remove(fileobj)

    def select(self, timeout: float | None = None) -> list[object]:
        if self.tick_count:
            previous = self._marker()
            self.max_accepts_per_tick = max(
                self.max_accepts_per_tick, self._listener.accepts - previous[0]
            )
            self.max_recvs_per_tick = max(
                self.max_recvs_per_tick, self._meter.total - previous[1]
            )
        self.tick_count += 1
        return []

    def _marker(self) -> tuple[int, int]:
        return (self._listener.accepts, self._meter.total)

    def close(self) -> None:
        return None


def _node_source(
    *,
    expect_bytes: int,
    echo: bytes,
    final_state: JsonObject,
    restart_state: JsonObject | None,
    exit_code: int,
    crash_after_connect: bool,
    probe_first: bool = False,
    silent_first: bool = False,
    escape: str = "none",
) -> str:
    return f"""#!{sys.executable}
import json
import os
import socket
import sys
import time
from pathlib import Path

restart = "--restart" in sys.argv
paired_args = [part for part in sys.argv[1:] if part != "--restart"]
args = dict(zip(paired_args[::2], paired_args[1::2], strict=True))
escape = {escape!r}
if escape == "restart" and not restart:
    escape = ""
if escape in ("setsid", "double-fork"):
    if os.fork():
        raise SystemExit(0)
    if escape == "double-fork":
        if os.fork():
            os._exit(0)
    os.setsid()
    Path(args['--state-path']).with_suffix('.helper-pid').write_text(
        str(os.getpid())
    )
if {probe_first!r}:
    probe = socket.create_connection(
        (args['--peer-host'], int(args['--peer-port'])), timeout=5.0
    )
    probe.sendall(b'GET / HT')
    probe.close()
if {silent_first!r}:
    silent = socket.create_connection(
        (args['--peer-host'], int(args['--peer-port'])), timeout=5.0
    )
if restart:
    if escape == "restart":
        if os.fork():
            pass  # the leader writes restart state and exits zero below
        else:
            if os.fork():
                os._exit(0)
            os.setsid()
            Path(args['--state-path']).with_suffix('.helper-pid').write_text(
                str(os.getpid())
            )
            time.sleep(5.0)
            Path(args['--state-path']).with_suffix(
                '.helper-survived'
            ).write_text('x')
            os._exit(0)
    payload = dict({restart_state!r})
    payload["copied_executable"] = Path(sys.argv[0]).name == "node-under-test"
    with open(args['--state-path'], 'w', encoding='utf-8') as stream:
        json.dump(payload, stream, sort_keys=True)
    raise SystemExit({exit_code!r})
connection = socket.create_connection(
    (args['--peer-host'], int(args['--peer-port'])), timeout=5.0
)
if {crash_after_connect!r}:
    payload = {final_state!r}
    with open(args['--state-path'], 'w', encoding='utf-8') as stream:
        json.dump(payload, stream, sort_keys=True)
    connection.close()
    raise SystemExit(0)
if {echo.hex()!r}:
    connection.send(bytes.fromhex({echo.hex()!r}))
remaining = {expect_bytes!r}
while remaining:
    chunk = connection.recv(min(65536, remaining))
    if not chunk:
        raise SystemExit(9)
    remaining -= len(chunk)
with open(args['--state-path'], 'w', encoding='utf-8') as stream:
    json.dump({final_state!r}, stream, sort_keys=True)
connection.close()
if escape in ("setsid", "double-fork"):
    time.sleep(5.0)
    Path(args['--state-path']).with_suffix('.helper-survived').write_text('x')
raise SystemExit({exit_code!r})
"""


def _step(
    kind: str,
    *,
    frame: int | None = None,
    delay_ns: int = 0,
    bandwidth: int | None = None,
    duration_ns: int = 0,
    after_bytes: int | None = None,
) -> JsonObject:
    return {
        "kind": kind,
        "frame": frame,
        "delay_ns": delay_ns,
        "bandwidth_bytes_per_second": bandwidth,
        "duration_ns": duration_ns,
        "after_bytes": after_bytes,
    }


def _default_schedule(echo: bytes) -> list[JsonObject]:
    return [
        _step("send", frame=0, delay_ns=1_000_000),
        _step("stall", duration_ns=2_000_000),
        _step("send", frame=1, bandwidth=33_554_432),
        _step("send", frame=2),
        _step("disconnect", after_bytes=len(echo) or None),
    ]


class CampaignFixture:
    """Builds a deterministic two-node loopback campaign in a workspace."""

    def __init__(
        self,
        workspace: Path,
        *,
        mode: str = "fresh",
        echo: bytes = bytes.fromhex(MAGIC) + b"\x11version",
        exit_code: int = 0,
        crash_after_connect: bool = False,
        final_state: JsonObject | None = None,
        final_mismatch: bool = False,
        restart_mismatch: bool = False,
        schedule: list[JsonObject] | None = None,
        extra_command_args: list[str] | None = None,
        probe_first: bool = False,
        silent_first: bool = False,
        escape: str = "none",
    ) -> None:
        self.echo = echo
        self.extra_command_args = extra_command_args or []
        self.probe_first = probe_first
        self.silent_first = silent_first
        self.escape = escape
        frames = [
            _frame(i, ("tx", "block", "tx")[i], bytes([0x45 + i]) * (100 + i))
            for i in range(3)
        ]
        self.final_state: JsonObject = (
            {"phase": "final", "rows": 3, "tip": "f" * 64}
            if final_state is None
            else final_state
        )
        written_final = (
            {"phase": "divergent", "rows": 9, "tip": "0" * 64}
            if final_mismatch
            else self.final_state
        )
        self.restart_state: JsonObject | None = (
            {"phase": "restart", "rows": 3, "tip": "f" * 64}
            if mode == "restart"
            else None
        )
        self.expected_restart_state: JsonObject | None = (
            {**self.restart_state, "copied_executable": True}
            if self.restart_state is not None
            else None
        )
        written_restart = (
            {"phase": "divergent-restart", "rows": 4, "tip": "1" * 64}
            if restart_mismatch
            else self.restart_state
        )
        expect_bytes = sum(len(frame) for frame in frames)
        command = [
            "{binary}",
            "--peer-host",
            "{peer_host}",
            "--peer-port",
            "{peer_port}",
            "--state-path",
            "{state_path}",
        ] + self.extra_command_args
        restart_command: list[str] | None = None
        if mode == "restart":
            restart_command = [
                "{binary}",
                "--peer-host",
                "{peer_host}",
                "--peer-port",
                "{peer_port}",
                "--state-path",
                "{state_path}",
                "--restart",
            ] + self.extra_command_args
        config = {
            "schema": CONFIG_SCHEMA,
            "peer": {
                "network_magic": MAGIC,
                "protocol_version": 70016,
                "services": 1,
                "connect_timeout_ns": 5_000_000_000,
                "io_timeout_ns": 5_000_000_000,
                "socket_buffer_bytes": 262_144,
                "expected_inbound_sha256": hashlib.sha256(echo).hexdigest()
                if echo
                else None,
            },
            "lifecycle": {
                "mode": mode,
                "generation": 4,
                "initial_state": {"generation": 3, "tip": "e" * 64},
                "expected_final_state": self.final_state,
                "expected_restart_state": self.expected_restart_state,
            },
            "corpus": [frame.hex() for frame in frames],
            "schedule": _default_schedule(echo) if schedule is None else schedule,
            "core": self._program(
                workspace,
                "core",
                expect_bytes,
                written_final,
                written_restart,
                exit_code,
                crash_after_connect,
                probe_first,
                silent_first,
                escape,
                command,
                restart_command,
            ),
            "candidate": self._program(
                workspace,
                "candidate",
                expect_bytes,
                written_final,
                written_restart,
                exit_code,
                crash_after_connect,
                probe_first,
                silent_first,
                escape,
                command,
                restart_command,
            ),
        }
        self.command = command
        self.restart_command = restart_command
        self.config_path = workspace / "config.json"
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

    def _program(
        self,
        workspace: Path,
        role: str,
        expect_bytes: int,
        written_final: JsonObject,
        written_restart: JsonObject | None,
        exit_code: int,
        crash_after_connect: bool,
        probe_first: bool,
        silent_first: bool,
        escape: str,
        command: list[str],
        restart_command: list[str] | None,
    ) -> JsonObject:
        binary = _write_executable(
            workspace / f"{role}-node.py",
            _node_source(
                expect_bytes=expect_bytes,
                echo=self.echo,
                final_state=written_final,
                restart_state=written_restart,
                exit_code=exit_code,
                crash_after_connect=crash_after_connect,
                probe_first=probe_first,
                silent_first=silent_first,
                escape=escape,
            ),
        )
        return {
            "binary": str(binary),
            "binary_sha256": _sha256_file(binary),
            "command": command,
            "restart_command": restart_command,
        }

    def load(self) -> Config:
        return load_config(self.config_path)


def _arm(
    role: str,
    pair_index: int,
    order_index: int,
    *,
    sent_sha256: str = HASH64,
    protocol_ok: bool = True,
    state_ok: bool = True,
    final_state: JsonObject | None = None,
    restart_state: JsonObject | None = None,
) -> ArmObservation:
    state = {"tip": "1" * 64} if final_state is None else final_state
    return ArmObservation(
        pair_index=pair_index,
        order_index=order_index,
        role=role,
        binary_path=f"/bin/{role}",
        binary_sha256=HASH64,
        command_sha256=_argv_digest([role]),
        command_arg_count=1,
        restart_command_sha256=None,
        restart_command_arg_count=None,
        wall_ns=1_000,
        exit_code=0 if protocol_ok else 1,
        peer=PeerObservation(
            connected=True,
            sent_bytes=10,
            sent_sha256=sent_sha256,
            inbound_bytes=0,
            inbound_sha256=hashlib.sha256(b"").hexdigest(),
            completed_steps=2,
            disconnect_expected=True,
            error=None,
        ),
        final_state=state,
        final_state_sha256=canonical_sha256(state),
        restart_exit_code=None,
        restart_state=restart_state,
        restart_state_sha256=None
        if restart_state is None
        else canonical_sha256(restart_state),
        protocol_ok=protocol_ok,
        state_ok=state_ok,
        error=None if protocol_ok and state_ok else "synthetic",
    )


def _comparable_arms() -> list[ArmObservation]:
    arms: list[ArmObservation] = []
    order = 0
    for pair in range(PAIR_COUNT):
        first, second = (
            ("core", "candidate") if pair % 2 == 0 else ("candidate", "core")
        )
        arms.append(_arm(first, pair, order))
        order += 1
        arms.append(_arm(second, pair, order))
        order += 1
    return arms


def _good_config_value() -> JsonObject:
    return {
        "schema": CONFIG_SCHEMA,
        "peer": {
            "network_magic": MAGIC,
            "protocol_version": 70016,
            "services": 1,
            "connect_timeout_ns": 1_000_000,
            "io_timeout_ns": 1_000_000,
            "socket_buffer_bytes": 4096,
            "expected_inbound_sha256": None,
        },
        "lifecycle": {
            "mode": "fresh",
            "generation": 0,
            "initial_state": {},
            "expected_final_state": {},
            "expected_restart_state": None,
        },
        "corpus": [_frame(0, "tx", b"payload").hex()],
        "schedule": [_step("send", frame=0), _step("disconnect")],
        "core": {
            "binary": "/bin/core",
            "binary_sha256": HASH64,
            "command": ["{binary}", "--host", "{peer_host}"],
            "restart_command": None,
        },
        "candidate": {
            "binary": "/bin/candidate",
            "binary_sha256": HASH64,
            "command": ["{binary}"],
            "restart_command": None,
        },
    }


def _stub_config() -> Config:
    return p2p_loopback.parse_config(_good_config_value())


class ParseConfigTests(unittest.TestCase):
    def test_accepts_deterministic_config(self) -> None:
        value = _good_config_value()
        config = p2p_loopback.parse_config(json.loads(json.dumps(value)))
        corpus = _array(value["corpus"], "config.corpus")
        self.assertEqual(config.peer.network_magic, bytes.fromhex(MAGIC))
        self.assertEqual(config.corpus_sha256, canonical_sha256([corpus[0]]))
        public = json.loads(json.dumps(value))
        for role in ("core", "candidate"):
            program = _object(public[role])
            program["command"] = _public_argv(
                tuple(_array(program["command"], f"{role}.command"))
            )
        self.assertEqual(config.canonical_sha256, canonical_sha256(public))
        again = p2p_loopback.parse_config(json.loads(json.dumps(value)))
        self.assertEqual(config.canonical_sha256, again.canonical_sha256)

    def test_rejects_schema_and_key_drift(self) -> None:
        value = _good_config_value()
        value["schema"] = "p2p-loopback-config-v0"
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(value)
        trimmed = _good_config_value()
        del trimmed["peer"]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(trimmed)

    def test_rejects_bad_framing(self) -> None:
        wrong_magic = _good_config_value()
        wrong_magic["corpus"] = [_frame(0, "tx", b"x", magic="0709110b").hex()]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(wrong_magic)
        corrupted = bytearray(_frame(0, "tx", b"x"))
        corrupted[-1] ^= 0xFF
        bad_checksum = _good_config_value()
        bad_checksum["corpus"] = [bytes(corrupted).hex()]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(bad_checksum)
        truncated = _good_config_value()
        truncated["corpus"] = [_frame(0, "tx", b"x")[:23].hex()]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(truncated)
        oversized = _good_config_value()
        oversized["corpus"] = [_frame(0, "tx", b"x" * (MAX_FRAME_BYTES + 1)).hex()]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(oversized)

    def test_rejects_schedule_drift(self) -> None:
        corpus = [_frame(0, "tx", b"a").hex(), _frame(1, "block", b"b").hex()]
        swapped = _good_config_value()
        swapped["corpus"] = corpus
        swapped["schedule"] = [
            _step("send", frame=1),
            _step("send", frame=0),
            _step("disconnect"),
        ]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(swapped)
        missing = _good_config_value()
        missing["schedule"] = [_step("send", frame=0)]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(missing)
        early_disconnect = _good_config_value()
        early_disconnect["corpus"] = corpus
        early_disconnect["schedule"] = [
            _step("disconnect"),
            _step("send", frame=0),
            _step("send", frame=1),
        ]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(early_disconnect)
        bad_stall = _good_config_value()
        bad_stall["schedule"] = [_step("send", frame=0), _step("stall")]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(bad_stall)

    def test_rejects_restart_without_state_and_bad_placeholders(self) -> None:
        restart = _good_config_value()
        _object(restart["lifecycle"])["mode"] = "restart"
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(restart)
        injection = _good_config_value()
        _object(injection["core"])["command"] = ["{binary}", "{shell_escape}"]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(injection)
        unbalanced = _good_config_value()
        _object(unbalanced["core"])["command"] = ["{binary", "arg"]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(unbalanced)

    def test_module_imports_standalone(self) -> None:
        probe = subprocess.run(
            [sys.executable, "-c", "import p2p_loopback"],
            cwd=str(Path(__file__).parent),
            check=False,
            capture_output=True,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)


class StatisticsTests(unittest.TestCase):
    def test_percentile_edges(self) -> None:
        self.assertEqual(_percentile([5], 0.99), 5)
        self.assertEqual(_percentile([4, 1, 3, 2], 0.50), 2)
        self.assertEqual(_percentile([10, 20, 30, 40, 50, 60, 70], 0.95), 70)
        self.assertEqual(_percentile([10, 20, 30, 40, 50, 60, 70], 0.50), 40)
        with self.assertRaises(ContractError):
            _percentile([], 0.5)

    def test_summarize_shape(self) -> None:
        summary = summarize([7, 1, 3])
        self.assertEqual(summary["samples"], 3)
        self.assertEqual(summary["p50_ns"], 3)
        self.assertEqual(summary["p95_ns"], 7)
        self.assertEqual(summary["p99_ns"], 7)
        self.assertEqual(summary["max_ns"], 7)


class GateTests(unittest.TestCase):
    def test_accepts_seven_alternating_pairs(self) -> None:
        _require_comparable(_stub_config(), _comparable_arms())

    def test_refuses_pair_count_and_role_drift(self) -> None:
        stub = _stub_config()
        with self.assertRaises(ContractError):
            _require_comparable(stub, _comparable_arms()[: 2 * PAIR_COUNT - 1])
        same_role = _comparable_arms()
        same_role[1] = _arm("core", 0, 1)
        with self.assertRaises(ContractError):
            _require_comparable(stub, same_role)
        swapped = _comparable_arms()
        swapped[0] = _arm("candidate", 0, 0)
        swapped[1] = _arm("core", 0, 1)
        with self.assertRaises(ContractError):
            _require_comparable(stub, swapped)

    def test_refuses_byte_custody_mismatch(self) -> None:
        arms = _comparable_arms()
        arms[3] = _arm(
            arms[3].role, arms[3].pair_index, arms[3].order_index, sent_sha256="ff" * 32
        )
        with self.assertRaises(ContractError):
            _require_comparable(_stub_config(), arms)

    def test_refuses_protocol_failure(self) -> None:
        arms = _comparable_arms()
        arms[10] = _arm(
            arms[10].role, arms[10].pair_index, arms[10].order_index, protocol_ok=False
        )
        with self.assertRaises(ContractError):
            _require_comparable(_stub_config(), arms)

    def test_refuses_state_and_restart_mismatch(self) -> None:
        stub = _stub_config()
        arms = _comparable_arms()
        arms[5] = _arm(
            arms[5].role,
            arms[5].pair_index,
            arms[5].order_index,
            state_ok=False,
            final_state={"tip": "2" * 64},
        )
        with self.assertRaises(ContractError):
            _require_comparable(stub, arms)
        arms = _comparable_arms()
        arms[4] = _arm(
            arms[4].role,
            arms[4].pair_index,
            arms[4].order_index,
            restart_state={"a": 1},
        )
        with self.assertRaises(ContractError):
            _require_comparable(stub, arms)


class PacingTests(unittest.TestCase):
    def test_unpaced_send_is_exact(self) -> None:
        left, right = socket.socketpair()
        payload = b"x" * 200_000
        started = time.monotonic_ns()
        _send_paced(left, payload, None, threading.Event())
        elapsed_ns = time.monotonic_ns() - started
        received = bytearray()
        right.settimeout(2.0)
        while len(received) < len(payload):
            chunk = right.recv(65_536)
            if not chunk:
                break
            received.extend(chunk)
        self.assertEqual(bytes(received), payload)
        self.assertLess(elapsed_ns, 2_000_000_000)
        left.close()
        right.close()

    def test_paced_send_respects_rate_floor(self) -> None:
        left, right = socket.socketpair()
        rate = 4_000_000
        payload = b"y" * (rate // 5)
        floor_ns = (len(payload) * 1_000_000_000) // rate

        def drain() -> None:
            seen = 0
            right.settimeout(5.0)
            while seen < len(payload):
                chunk = right.recv(65_536)
                if not chunk:
                    break
                seen += len(chunk)

        reader = threading.Thread(target=drain)
        reader.start()
        left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        right.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        started = time.monotonic_ns()
        _send_paced(left, payload, rate, threading.Event())
        elapsed_ns = time.monotonic_ns() - started
        reader.join(5.0)
        self.assertGreaterEqual(elapsed_ns, floor_ns - 20_000_000)
        left.close()
        right.close()


class MagicGateTests(unittest.TestCase):
    """Unit-proofs for the pre-schedule network-magic gate."""

    MAGIC = bytes.fromhex("f9beb4d9")

    def _listener(self) -> socket.socket:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(_MAX_PENDING_CANDIDATES + 4)
        listener.setblocking(False)
        return listener

    def _connect(self, host: str, port: int) -> socket.socket:
        return socket.create_connection((host, port), timeout=5.0)

    def _classify(self, payload: bytes | None, close_peer: bool = False) -> str:
        left, right = socket.socketpair()
        if payload is not None:
            left.sendall(payload)
        if close_peer:
            left.close()
        right.setblocking(False)
        verdict = _candidate_magic(right, self.MAGIC)
        if not close_peer:
            left.close()
        right.close()
        return verdict

    def test_classifies_full_magic_as_ok(self) -> None:
        self.assertEqual(self._classify(self.MAGIC), "ok")

    def test_classifies_partial_magic_as_pending(self) -> None:
        self.assertEqual(self._classify(self.MAGIC[:2]), "pending")

    def test_classifies_http_probe_as_reject(self) -> None:
        self.assertEqual(self._classify(b"GET / HT"), "reject")

    def test_classifies_clean_close_as_reject(self) -> None:
        self.assertEqual(self._classify(None, close_peer=True), "reject")

    def test_selector_skips_silent_probe_for_valid_peer(self) -> None:
        listener = self._listener()
        host, port = listener.getsockname()[:2]
        silent = self._connect(host, port)
        peer = self._connect(host, port)
        peer.sendall(self.MAGIC + b"\x11marker")
        winner = _accept_magic_peer(
            listener,
            self.MAGIC,
            threading.Event(),
            time.monotonic_ns() + 5_000_000_000,
        )
        self.assertIsNotNone(winner)
        winner.settimeout(2.0)
        self.assertEqual(winner.recv(32, socket.MSG_PEEK), self.MAGIC + b"\x11marker")
        silent.settimeout(2.0)
        self.assertEqual(silent.recv(1), b"")
        for sock in (silent, peer, winner, listener):
            sock.close()

    def test_selector_closes_every_loser_on_success(self) -> None:
        listener = self._listener()
        host, port = listener.getsockname()[:2]
        losers = []
        for payload in (b"GET / HT", None, self.MAGIC[:3]):
            sock = self._connect(host, port)
            if payload:
                sock.sendall(payload)
            losers.append(sock)
        peer = self._connect(host, port)
        peer.sendall(self.MAGIC)
        winner = _accept_magic_peer(
            listener,
            self.MAGIC,
            threading.Event(),
            time.monotonic_ns() + 5_000_000_000,
        )
        self.assertIsNotNone(winner)
        for sock in losers:
            sock.settimeout(2.0)
            self.assertEqual(sock.recv(1), b"")
        for sock in (*losers, peer, winner, listener):
            sock.close()

    def test_candidate_overflow_closes_newest_instead(self) -> None:
        listener = self._listener()
        host, port = listener.getsockname()[:2]
        probes = [self._connect(host, port) for _ in range(_MAX_PENDING_CANDIDATES)]
        winner = self._connect(host, port)
        winner.sendall(self.MAGIC)
        with self.assertRaisesRegex(ContractError, "never presented"):
            _accept_magic_peer(
                listener,
                self.MAGIC,
                threading.Event(),
                time.monotonic_ns() + 300_000_000,
            )
        winner.settimeout(2.0)
        self.assertEqual(winner.recv(1), b"")  # newest closed, pending kept
        for sock in (*probes, winner, listener):
            sock.close()

    def test_flood_closes_newest_and_never_evicts_pending(self) -> None:
        listener = _FakeListener()
        meter = _RecvMeter()
        selector = _FakeSelector(listener, meter)
        silent = [
            _FakePeer([None, None, b""], meter) for _ in range(_MAX_PENDING_CANDIDATES)
        ]
        flood = [_FakePeer([None, None], meter) for _ in range(_MAX_PENDING_CANDIDATES)]
        listener.arrivals = silent + flood
        with (
            mock.patch.object(
                p2p_loopback.selectors, "DefaultSelector", lambda: selector
            ),
            self.assertRaises(ContractError),
        ):
            _accept_magic_peer(
                listener,
                bytes.fromhex(MAGIC),
                threading.Event(),
                time.monotonic_ns() + 150_000_000,
            )
        self.assertGreater(selector.tick_count, 3)
        self.assertTrue(all(peer.closed and peer.recvs == 0 for peer in flood))
        self.assertTrue(all(peer.recvs == 3 and peer.closed for peer in silent))
        self.assertLessEqual(selector.max_accepts_per_tick, _MAX_PENDING_CANDIDATES)
        self.assertLessEqual(selector.max_recvs_per_tick, _MAX_PENDING_CANDIDATES)

    def test_cancel_breaks_selector_and_closes_candidates(self) -> None:
        listener = self._listener()
        host, port = listener.getsockname()[:2]
        silent = self._connect(host, port)
        cancel = threading.Event()
        outcome: dict[str, ContractError] = {}

        def run() -> None:
            try:
                _accept_magic_peer(
                    listener,
                    self.MAGIC,
                    cancel,
                    time.monotonic_ns() + 30_000_000_000,
                )
            except ContractError as caught:
                outcome["error"] = caught

        reader = threading.Thread(target=run)
        reader.start()
        time.sleep(0.05)
        cancel.set()
        reader.join(2.0)
        self.assertFalse(reader.is_alive())
        self.assertIsInstance(outcome.get("error"), ContractError)
        silent.settimeout(2.0)
        self.assertEqual(silent.recv(1), b"")
        silent.close()
        listener.close()

    def test_deadline_expiry_refuses_without_peer(self) -> None:
        listener = self._listener()
        with self.assertRaisesRegex(ContractError, "never presented"):
            _accept_magic_peer(
                listener,
                self.MAGIC,
                threading.Event(),
                time.monotonic_ns() + 100_000_000,
            )
        listener.close()


class CampaignTests(unittest.TestCase):
    def _run_main(self, workspace: Path, config_path: Path) -> bytes:
        output = workspace / OUTPUT_NAME
        self.assertEqual(
            main(["--config", str(config_path), "--output", str(output)]), 0
        )
        return output.read_bytes()

    def test_seven_alternating_pairs_emit_custody_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-loopback-fresh-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace)
            result = _object(json.loads(self._run_main(workspace, fixture.config_path)))
            self.assertEqual(result["schema"], RESULT_SCHEMA)
            self.assertEqual(result["pair_count"], PAIR_COUNT)
            arms = _arms_list(result["arms"])
            self.assertEqual(len(arms), 2 * PAIR_COUNT)
            for index, arm_value in enumerate(arms):
                arm = _object(arm_value)
                pair_index = index // 2
                roles = (
                    ("core", "candidate")
                    if pair_index % 2 == 0
                    else ("candidate", "core")
                )
                expected_role = roles[index % 2]
                self.assertEqual(arm["pair_index"], index // 2)
                self.assertEqual(arm["order_index"], index)
                self.assertEqual(arm["role"], expected_role)
                self.assertTrue(arm["protocol_ok"])
                self.assertTrue(arm["state_ok"])
                self.assertIsNone(arm["error"])
            config = fixture.load()
            custody = _object(result["custody"])
            self.assertEqual(custody["network_magic"], MAGIC)
            self.assertEqual(custody["protocol_version"], 70016)
            self.assertEqual(custody["services"], 1)
            self.assertEqual(custody["corpus_sha256"], config.corpus_sha256)
            self.assertEqual(custody["schedule_sha256"], config.schedule_sha256)
            self.assertEqual(custody["peer_sha256"], config.peer_sha256)
            self.assertEqual(custody["lifecycle_sha256"], config.lifecycle_sha256)
            self.assertEqual(custody["lifecycle_mode"], "fresh")
            correctness = _object(result["correctness"])
            self.assertTrue(all(value is True for value in correctness.values()))
            stats = _object(result["statistics"])
            core = _object(stats["core"])
            walls = sorted(
                _integer(_object(arm)["wall_ns"], "arm.wall_ns")
                for arm in arms
                if _object(arm)["role"] == "core"
            )
            self.assertEqual(core["p50_ns"], walls[len(walls) // 2])
            self.assertEqual(core["max_ns"], walls[-1])
            self.assertTrue(
                math.isfinite(
                    _number(
                        result["candidate_over_core_p50_ratio"],
                        "result.candidate_over_core_p50_ratio",
                    )
                )
            )
            canonical = canonical_bytes(
                {key: value for key, value in result.items() if key != "result_sha256"}
            )
            self.assertEqual(
                result["result_sha256"], hashlib.sha256(canonical).hexdigest()
            )
            output = workspace / OUTPUT_NAME
            self.assertEqual(output.read_bytes(), canonical_bytes(result) + b"\n")

    def test_restart_lifecycle_records_resumed_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-loopback-restart-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, mode="restart")
            result = _object(json.loads(self._run_main(workspace, fixture.config_path)))
            arms = _arms_list(result["arms"])
            for arm_value in arms:
                arm = _object(arm_value)
                self.assertEqual(arm["restart_exit_code"], 0)
                restart_expected = fixture.expected_restart_state
                if restart_expected is None:
                    raise TypeError("restart fixture requires restart state")
                self.assertEqual(_object(arm["restart_state"]), restart_expected)
                self.assertIs(restart_expected["copied_executable"], True)
                self.assertEqual(
                    arm["restart_state_sha256"], canonical_sha256(restart_expected)
                )

    def test_refuses_node_protocol_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-loopback-fail-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, exit_code=3)
            with self.assertRaisesRegex(ContractError, "protocol"):
                run_campaign(fixture.load(), workspace / "arms")

    def test_refuses_crashing_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-loopback-crash-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, crash_after_connect=True)
            with self.assertRaisesRegex(ContractError, "protocol"):
                run_campaign(fixture.load(), workspace / "arms")

    def test_refuses_final_state_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-loopback-state-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, final_mismatch=True)
            with self.assertRaisesRegex(ContractError, "state"):
                run_campaign(fixture.load(), workspace / "arms")

    def test_refuses_restart_state_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-loopback-restart-bad-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, mode="restart", restart_mismatch=True)
            with self.assertRaisesRegex(ContractError, "state"):
                run_campaign(fixture.load(), workspace / "arms")


class SecurityContractTests(unittest.TestCase):
    """Adversarial coverage for the executor-binding security contract."""

    def test_rejects_alternate_argv0(self) -> None:
        value = _good_config_value()
        _object(value["core"])["command"] = ["/bin/core", "--host", "{peer_host}"]
        with self.assertRaises(ContractError):
            p2p_loopback.parse_config(value)

    def test_rejects_alternate_restart_argv0(self) -> None:
        value = _good_config_value()
        _object(value["core"])["restart_command"] = ["/bin/core", "--restart"]
        with self.assertRaisesRegex(ContractError, r"restart_command\[0\] must be"):
            p2p_loopback.parse_config(value)

    def test_rejects_command_arg_overflow(self) -> None:
        value = _good_config_value()
        _object(value["core"])["command"] = [
            "{binary}",
            *(f"--arg{index}" for index in range(MAX_COMMAND_ARGS + 1)),
        ]
        with self.assertRaisesRegex(ContractError, "must contain 1 to"):
            p2p_loopback.parse_config(value)

    def test_argv_digest_is_projection_only(self) -> None:
        argv = ["node", "--port=8333", "{peer_port}"]
        digest = _argv_digest(argv)
        self.assertEqual(
            digest,
            hashlib.sha256(canonical_bytes(_public_argv(argv))).hexdigest(),
        )
        self.assertNotEqual(
            digest, hashlib.sha256(canonical_bytes(list(argv))).hexdigest()
        )
        self.assertNotEqual(digest, _argv_digest(argv[:-1]))
        self.assertEqual(digest, _argv_digest(list(argv)))
        self.assertNotIn(b"8333", canonical_bytes(_public_argv(argv)))

    def _copy_program(self, source: Path, digest: str | None = None) -> Program:
        return Program(
            role="core",
            binary=source,
            binary_sha256=digest if digest is not None else _sha256_file(source),
            command=("{binary}",),
            restart_command=None,
        )

    def test_verified_copy_binds_digest_and_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-copy-ok-") as raw:
            workspace = Path(raw)
            source = _write_executable(workspace / "node.py", "#!-ok\n")
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            copy = _verified_copy(self._copy_program(source), arm_dir)
            self.assertEqual(copy, arm_dir / "node-under-test")
            self.assertEqual(copy.read_bytes(), source.read_bytes())
            self.assertEqual(_sha256_file(copy), _sha256_file(source))
            self.assertEqual(
                stat.S_IMODE(copy.stat().st_mode), stat.S_IRUSR | stat.S_IXUSR
            )

    def test_verified_copy_refuses_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-copy-bad-") as raw:
            workspace = Path(raw)
            source = _write_executable(workspace / "node.py", "#!-bad\n")
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            with self.assertRaisesRegex(ContractError, "digest mismatch"):
                _verified_copy(self._copy_program(source, digest=HASH64), arm_dir)
            self.assertFalse((arm_dir / "node-under-test").exists())

    def test_verified_copy_refuses_non_regular_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-copy-dir-") as raw:
            workspace = Path(raw)
            source = workspace / "node-dir"
            source.mkdir()
            with self.assertRaisesRegex(ContractError, "not a regular file"):
                _verified_copy(self._copy_program(source, digest=HASH64), workspace)

    def test_copy_reverified_before_spawn_binds_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-reverify-") as raw:
            workspace = Path(raw)
            source = _write_executable(workspace / "node.py", "#!-v1\n")
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            copy = _verified_copy(self._copy_program(source), arm_dir)
            _verify_copy_digest(copy, _sha256_file(source))
            copy.chmod(stat.S_IRUSR | stat.S_IWUSR)
            copy.write_bytes(b"#!-tampered\n")
            copy.chmod(stat.S_IRUSR | stat.S_IXUSR)
            with self.assertRaisesRegex(
                ContractError, "changed after its verified copy"
            ):
                _verify_copy_digest(copy, _sha256_file(source))

    def test_spawn_verification_refuses_symlinked_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-symlink-") as raw:
            workspace = Path(raw)
            source = _write_executable(workspace / "node.py", "#!-v1\n")
            link = workspace / "node-under-test"
            os.symlink(source, link)
            with self.assertRaisesRegex(ContractError, "spawn verification"):
                _verify_copy_digest(link, _sha256_file(source))

    def test_publication_never_clobbers_existing_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-publish-") as raw:
            workspace = Path(raw)
            output = workspace / "out" / "result.json"
            output.parent.mkdir()
            _publish_result({"run": 1}, output)
            published = output.read_bytes()
            scratch = output.parent / f".p2p-loopback-result.{os.getpid()}.tmp"
            self.assertFalse(scratch.exists())
            with self.assertRaisesRegex(ContractError, "output already exists"):
                _publish_result({"run": 2}, output)
            self.assertEqual(output.read_bytes(), published)

    def test_result_omits_raw_command_and_secrets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-secret-ok-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(
                workspace,
                extra_command_args=["--rpcpassword", "supersecret-token"],
            )
            output = workspace / OUTPUT_NAME
            self.assertEqual(
                main(["--config", str(fixture.config_path), "--output", str(output)]),
                0,
            )
            payload = output.read_bytes()
            for leak in (
                b"supersecret-token",
                b"--rpcpassword",
                b"--peer-host",
                b"--state-path",
                b"node.py",
            ):
                self.assertNotIn(leak, payload)
            config = fixture.load()
            result = _object(json.loads(payload))
            arms = _arms_list(result["arms"])
            for arm_value in arms:
                arm = _object(arm_value)
                self.assertNotIn("command", arm)
                self.assertNotIn("restart_command", arm)
                self.assertEqual(len(arm["command_sha256"]), 64)
                self.assertEqual(arm["command_arg_count"], len(fixture.command))
                binary_path = Path(str(arm["binary_path"]))
                self.assertEqual(binary_path.name, "node-under-test")
                self.assertEqual(binary_path.parent.parent.name, "arms")
                scratch = binary_path.parent.parent.parent
                self.assertTrue(scratch.name.startswith("p2p-loopback-"))
                self.assertEqual(scratch.parent, output.parent)
                self.assertEqual(arm["binary_sha256"], config.core.binary_sha256)

    def test_loader_refuses_symlinked_config(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-load-sym-") as raw:
            workspace = Path(raw)
            target = workspace / "real.json"
            target.write_text(json.dumps(_good_config_value()), encoding="utf-8")
            link = workspace / "config.json"
            os.symlink(target, link)
            with self.assertRaisesRegex(ContractError, "cannot read"):
                _load_json(link, "config", MAX_CONFIG_BYTES)

    def test_loader_refuses_fifo_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-load-fifo-") as raw:
            workspace = Path(raw)
            path = workspace / "state.fifo"
            os.mkfifo(path)
            with self.assertRaisesRegex(ContractError, "not a regular file"):
                _load_json(path, "state", MAX_STATE_BYTES)

    def test_http_probe_cannot_steal_the_loopback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-probe-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, probe_first=True)
            result = _object(json.loads(self._run_main(workspace, fixture.config_path)))
            arms = _arms_list(result["arms"])
            self.assertEqual(len(arms), 2 * PAIR_COUNT)
            for arm_value in arms:
                arm = _object(arm_value)
                self.assertTrue(arm["protocol_ok"])
                self.assertIsNone(arm["error"])
                peer = _object(arm["peer"])
                self.assertEqual(peer["inbound_bytes"], len(fixture.echo))
                self.assertEqual(
                    peer["inbound_sha256"], hashlib.sha256(fixture.echo).hexdigest()
                )

    def test_silent_probe_cannot_head_of_line_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-silent-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, silent_first=True)
            result = _object(json.loads(self._run_main(workspace, fixture.config_path)))
            arms = _arms_list(result["arms"])
            self.assertEqual(len(arms), 2 * PAIR_COUNT)
            for arm_value in arms:
                arm = _object(arm_value)
                self.assertTrue(arm["protocol_ok"])
                self.assertIsNone(arm["error"])
                peer = _object(arm["peer"])
                self.assertEqual(peer["inbound_bytes"], len(fixture.echo))
                self.assertEqual(
                    peer["inbound_sha256"],
                    hashlib.sha256(fixture.echo).hexdigest(),
                )

    def test_setsid_daemon_cannot_score(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-setsid-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, escape="setsid")
            with self.assertRaisesRegex(ContractError, "processes running"):
                run_campaign(fixture.load(), workspace / "arms")
            arms_dir = workspace / "arms"
            for pid in _escape_helper_pids(arms_dir):
                self.assertTrue(_wait_pid_gone(pid), f"helper {pid} survived")
            self.assertTrue(_no_survivor_markers(arms_dir))

    def test_double_fork_daemon_cannot_score(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-2fork-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, escape="double-fork")
            with self.assertRaisesRegex(ContractError, "processes running"):
                run_campaign(fixture.load(), workspace / "arms")
            arms_dir = workspace / "arms"
            for pid in _escape_helper_pids(arms_dir):
                self.assertTrue(_wait_pid_gone(pid), f"helper {pid} survived")
            self.assertTrue(_no_survivor_markers(arms_dir))

    def test_restart_escape_cannot_score(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-restart-esc-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, mode="restart", escape="restart")
            with self.assertRaisesRegex(ContractError, "processes running"):
                run_campaign(fixture.load(), workspace / "arms")
            arms_dir = workspace / "arms"
            for pid in _escape_helper_pids(arms_dir):
                self.assertTrue(_wait_pid_gone(pid), f"helper {pid} survived")
            self.assertTrue(_no_survivor_markers(arms_dir))

    def test_registration_failure_reaps_fast_double_fork_daemon(self) -> None:
        """A daemon escaping before the leader publishes is swept anyway."""
        with tempfile.TemporaryDirectory(prefix="p2p-regfail-") as raw:
            workspace = Path(raw)
            daemon_pid_path = workspace / "daemon-pid"
            survived_path = workspace / "daemon-survived"
            script = (
                "import os, signal, sys, time\n"
                "if os.fork():\n"
                "    os._exit(0)\n"  # the leader exits before publication
                "os.setsid()\n"
                "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "time.sleep(30)\n"
                f"open({str(survived_path)!r}, 'w').write('x')\n"
            )
            binary = _write_executable(
                workspace / "regfail-node", f"#!{sys.executable}\n" + script
            )
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            arm = ArmProcess(
                _stub_config(),
                "core",
                binary,
                arm_dir,
                time.monotonic_ns() + MAX_ARM_DURATION_NS,
            )
            supervisor = _self_generation()
            host_baseline = _host_child_generations(supervisor)
            real_adopt = p2p_loopback.ProcessIdentity.adopt
            observed_adopts = {"leader_failures": 0, "daemon_sweeps": 0}

            def unpublished_leader_adopt(
                pid: int, expected_parent: ProcessGeneration | None = None
            ) -> ProcessIdentity | None:
                if observed_adopts["leader_failures"] == 0:
                    # Deterministic escape window: the daemon exists and
                    # has published its pid before registration fails.
                    _wait_for_file(daemon_pid_path)
                    observed_adopts["leader_failures"] += 1
                    return None
                identity = real_adopt(pid, expected_parent)
                if daemon_pid_path.exists() and pid == int(daemon_pid_path.read_text()):
                    observed_adopts["daemon_sweeps"] += 1
                return identity

            with _ChildSubreaperScope(), arm:
                arm.require_ready()
                with (
                    mock.patch.object(
                        p2p_loopback.ProcessIdentity,
                        "adopt",
                        side_effect=unpublished_leader_adopt,
                    ),
                    mock.patch.object(
                        p2p_loopback,
                        "_host_child_generations",
                        return_value=host_baseline,
                    ),
                    self.assertRaisesRegex(
                        ContractError, "identity failed verification"
                    ),
                ):
                    arm.launch((str(binary), str(daemon_pid_path)), "primary")
            self.assertTrue(_wait_pid_gone(int(daemon_pid_path.read_text())))
            self.assertEqual(observed_adopts["leader_failures"], 1)
            self.assertGreaterEqual(observed_adopts["daemon_sweeps"], 1)
            self.assertFalse(survived_path.exists())
            self.assertIsNone(arm._process)
            self.assertIsNone(arm._root_identity)

    def test_binary_source_refuses_fifo_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-srcfile-") as raw:
            workspace = Path(raw)
            source = _write_executable(workspace / "node.py", "#!-v1\n")
            fifo = workspace / "node.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ContractError, "not a regular file"):
                _hash_file(fifo)
            link = workspace / "node-link"
            link.symlink_to(source)
            program = self._copy_program(link, digest=_sha256_file(source))
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            with self.assertRaisesRegex(ContractError, "cannot open"):
                _verified_copy(program, arm_dir)

    def test_error_output_omits_secrets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-secret-fail-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(
                workspace,
                exit_code=3,
                extra_command_args=["--rpcpassword", "supersecret-token"],
            )
            with self.assertRaises(ContractError) as caught:
                run_campaign(fixture.load(), workspace / "arms")
            message = str(caught.exception)
            self.assertNotIn("supersecret-token", message)
            self.assertNotIn("--rpcpassword", message)

    def test_secret_values_share_one_public_evidence(self) -> None:
        for secret_option in ("--rpcpassword", "--auth", "-rpcauth"):
            self.assertEqual(
                _argv_digest(["node", f"{secret_option}=alpha-secret"]),
                _argv_digest(["node", f"{secret_option}=beta-secret"]),
            )
            self.assertEqual(
                _argv_digest(["node", secret_option, "alpha-secret"]),
                _argv_digest(["node", secret_option, "beta-secret"]),
            )
        self.assertNotEqual(
            _argv_digest(["node", "--rpcpassword=alpha-secret"]),
            _argv_digest(["node", "--rpcpassword", "alpha-secret"]),
        )
        published = canonical_bytes(
            _public_argv(
                [
                    "node",
                    "--rpcpassword=alpha-secret",
                    "--auth",
                    "beta-secret",
                    "-rpcauth=gamma-secret",
                ]
            )
        )
        for secret in (b"alpha-secret", b"beta-secret", b"gamma-secret"):
            self.assertNotIn(secret, published)
        good = _good_config_value()
        _object(good["core"])["command"] = [
            "{binary}",
            "--rpcpassword=alpha-secret",
        ]
        secreted = json.loads(json.dumps(good))
        _object(secreted["core"])["command"] = [
            "{binary}",
            "--rpcpassword=tr9X_different-secret-value",
        ]
        baseline = parse_config(good)
        secreted_config = parse_config(secreted)
        self.assertNotEqual(baseline.core.command, secreted_config.core.command)
        self.assertEqual(baseline.canonical_sha256, secreted_config.canonical_sha256)
        self.assertEqual(
            _argv_digest(baseline.core.command),
            _argv_digest(secreted_config.core.command),
        )

    def test_restart_binds_the_verified_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-restart-copy-") as raw:
            workspace = Path(raw)
            fixture = CampaignFixture(workspace, mode="restart")
            result = _object(json.loads(self._run_main(workspace, fixture.config_path)))
            for arm_value in _arms_list(result["arms"]):
                arm = _object(arm_value)
                self.assertEqual(
                    arm["restart_command_arg_count"],
                    len(fixture.restart_command or []),
                )
                self.assertNotEqual(
                    arm["restart_command_sha256"], arm["command_sha256"]
                )

    def _run_main(self, workspace: Path, config_path: Path) -> bytes:
        output = workspace / OUTPUT_NAME
        self.assertEqual(
            main(["--config", str(config_path), "--output", str(output)]), 0
        )
        return output.read_bytes()

    def test_loader_rejects_config_over_byte_cap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-cap-bytes-") as raw:
            workspace = Path(raw)
            path = workspace / "config.json"
            path.write_text(json.dumps(_good_config_value()), encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "exceeds byte limit"):
                _load_json(path, "config", 64)

    def test_loader_rejects_oversize_config_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-cap-file-") as raw:
            workspace = Path(raw)
            path = workspace / "config.json"
            path.write_text(
                json.dumps(_good_config_value()).ljust(MAX_CONFIG_BYTES + 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ContractError, "exceeds byte limit"):
                load_config(path)

    def test_state_loader_rejects_oversize_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-cap-state-") as raw:
            workspace = Path(raw)
            path = workspace / "state.json"
            path.write_text(
                json.dumps({"pad": "x" * MAX_STATE_BYTES}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ContractError, "exceeds byte limit"):
                _state(path, "final state")

    def test_loaders_reject_deep_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-deep-") as raw:
            workspace = Path(raw)
            path = workspace / "deep.json"
            depth = MAX_JSON_DEPTH + 8
            path.write_text("[" * depth + "]" * depth, encoding="utf-8")
            with self.assertRaisesRegex(ContractError, "depth limit"):
                _load_json(path, "state", MAX_STATE_BYTES)

    def test_loaders_catch_recursion_failures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-recursive-") as raw:
            workspace = Path(raw)
            path = workspace / "deep.json"
            path.write_text("[]", encoding="utf-8")
            with (
                mock.patch.object(
                    json, "loads", side_effect=RecursionError("stack blown")
                ),
                self.assertRaisesRegex(ContractError, "not bounded valid JSON"),
            ):
                _load_json(path, "state", MAX_STATE_BYTES)

    def test_corpus_ceiling_fits_config_cap(self) -> None:
        self.assertLessEqual(MAX_CORPUS_BYTES, MAX_CONFIG_BYTES)
        self.assertLess(MAX_FRAME_BYTES, MAX_CORPUS_BYTES)

    def test_hostile_schedule_duration_refused(self) -> None:
        stalled = _good_config_value()
        stalled["schedule"] = [
            _step("stall", duration_ns=6_000_000_000),
            _step("send", frame=0),
            _step("disconnect"),
        ]
        with self.assertRaisesRegex(ContractError, "exceeds peer.io_timeout_ns"):
            p2p_loopback.parse_config(stalled)
        paced = _good_config_value()
        paced["corpus"] = [_frame(0, "tx", b"p" * 3_900_000).hex()]
        paced["schedule"] = [
            _step("send", frame=0, bandwidth=1),
            _step("disconnect"),
        ]
        with self.assertRaisesRegex(ContractError, "exceeds peer.io_timeout_ns"):
            p2p_loopback.parse_config(paced)

    def test_timing_caps_enforced(self) -> None:
        value = _good_config_value()
        _object(value["peer"])["connect_timeout_ns"] = MAX_CONNECT_TIMEOUT_NS + 1
        with self.assertRaisesRegex(ContractError, "integer in"):
            p2p_loopback.parse_config(value)
        capped = _good_config_value()
        _object(capped["peer"])["io_timeout_ns"] = MAX_IO_TIMEOUT_NS + 1
        with self.assertRaisesRegex(ContractError, "integer in"):
            p2p_loopback.parse_config(capped)

    def test_sleep_until_is_cancellation_aware(self) -> None:
        cancel = threading.Event()
        cancel.set()
        started = time.monotonic_ns()
        with self.assertRaises(ContractError):
            _sleep_until(time.monotonic_ns() + 60_000_000_000, cancel)
        self.assertLess(time.monotonic_ns() - started, 2_000_000_000)

    def test_send_paced_is_cancellation_aware(self) -> None:
        left, right = socket.socketpair()
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(ContractError):
            _send_paced(left, b"z" * 4096, None, cancel)
        right.settimeout(0.2)
        with self.assertRaises(TimeoutError):
            right.recv(4096)
        left.close()
        right.close()

    def test_term_resistant_descendant_killed_within_bound(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-stubborn-") as raw:
            workspace = Path(raw)
            armed = workspace / "armed"
            grandchild_path = workspace / "grandchild-pid"
            inner = (
                "import signal, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "time.sleep(30)\n"
            )
            script = (
                "import signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "open(sys.argv[1], 'w').write('armed')\n"
                f"child = subprocess.Popen([sys.executable, '-c', {inner!r}])\n"
                "open(sys.argv[2], 'w').write(str(child.pid))\n"
                "deadline = time.monotonic() + 30\n"
                "while time.monotonic() < deadline:\n"
                "    pass\n"
            )
            binary = _write_executable(
                workspace / "stubborn-node", f"#!{sys.executable}\n" + script
            )
            deadline = time.monotonic_ns() + 4_000_000_000
            started = time.monotonic()
            with _ChildSubreaperScope():
                arm = ArmProcess(_stub_config(), "core", binary, workspace, deadline)
                with (
                    self.assertRaisesRegex(
                        ContractError, "exceeded its monotonic arm deadline"
                    ),
                    arm,
                ):
                    arm.require_ready()
                    arm.launch(
                        (str(binary), str(armed), str(grandchild_path)),
                        "primary",
                    )
                    arm.wait_clean()
            self.assertLess(time.monotonic() - started, 10.0)
            self.assertTrue(armed.exists())
            self.assertTrue(_wait_pid_gone(int(grandchild_path.read_text())))
            self.assertFalse(arm.surviving_descendant_seen)

    @staticmethod
    def _spawn_grandchild_under_transient_parent() -> tuple[int, int]:
        """Fork a parent that forks a sleeping grandchild and exits unreaped.

        Returns ``(parent_pid, grandchild_pid)`` once the grandchild exists
        and the parent is still alive; the parent exits ~0.3s later and stays
        a zombie until the caller reaps it.
        """
        read_fd, write_fd = os.pipe()
        parent = os.fork()
        if parent == 0:
            os.close(read_fd)
            grandchild = os.fork()
            if grandchild == 0:
                os.close(write_fd)
                time.sleep(30)
                os._exit(0)
            os.write(write_fd, str(grandchild).encode())
            os.close(write_fd)
            time.sleep(0.3)
            os._exit(0)
        os.close(write_fd)
        grandchild = int(os.read(read_fd, 32))
        os.close(read_fd)
        return parent, grandchild

    @staticmethod
    def _wait_for_zombie(pid: int) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
            if state == "Z":
                return
            time.sleep(0.02)
        raise AssertionError(f"{pid} did not become a zombie")

    def test_zombie_parent_forfeits_ownership_of_reparented_member(self) -> None:
        with _ChildSubreaperScope():
            parent, grandchild = self._spawn_grandchild_under_transient_parent()
            try:
                parent_start = _process_start_time(parent)
                assert parent_start is not None
                identity = ProcessIdentity.adopt(
                    grandchild, ProcessGeneration(parent, parent_start)
                )
                assert identity is not None
                self.assertTrue(identity.alive())
                self._wait_for_zombie(parent)
                self.assertTrue(identity.alive())
                self.assertTrue(identity.signal(signal.SIGKILL))
                identity.close()
                self.assertEqual(os.waitpid(grandchild, 0)[0], grandchild)
            finally:
                os.waitpid(parent, 0)

    def test_drain_settles_member_under_unreaped_zombie_parent(self) -> None:
        with _ChildSubreaperScope():
            parent, grandchild = self._spawn_grandchild_under_transient_parent()
            try:
                parent_start = _process_start_time(parent)
                assert parent_start is not None
                parent_generation = ProcessGeneration(parent, parent_start)
                identity = ProcessIdentity.adopt(grandchild, parent_generation)
                assert identity is not None
                # The transient parent is the host's own child here; the
                # member was discovered through its edge while it lived.
                drain = _DescendantDrain(None, None, {parent_generation})
                drain._identities[identity.generation] = identity
                self._wait_for_zombie(parent)
                deadline = time.monotonic_ns() + 4_000_000_000
                drain.finish(violated_when_present=True, deadline_ns=deadline)
                self.assertTrue(drain.settled)
                self.assertTrue(drain.violated)
                self.assertFalse(Path(f"/proc/{grandchild}").exists())
            finally:
                os.waitpid(parent, 0)

    def test_digest_failure_after_worker_start_closes_promptly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-digest-worker-") as raw:
            workspace = Path(raw)
            source = _write_executable(workspace / "node.py", "#!-v1\n")
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            copy = _verified_copy(self._copy_program(source), arm_dir)
            arm = ArmProcess(
                _stub_config(),
                "core",
                copy,
                arm_dir,
                time.monotonic_ns() + MAX_ARM_DURATION_NS,
            )
            with arm:
                arm.require_ready()
                copy.chmod(stat.S_IRUSR | stat.S_IWUSR)
                copy.write_bytes(b"#!-tampered\n")
                copy.chmod(stat.S_IRUSR | stat.S_IXUSR)
                with self.assertRaisesRegex(
                    ContractError, "changed after its verified copy"
                ):
                    _verify_copy_digest(copy, _sha256_file(source))
            self.assertFalse(arm.worker_alive())
            self.assertEqual(arm._listener.fileno(), -1)

    def test_enoexec_after_worker_start_closes_promptly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p2p-enoexec-") as raw:
            workspace = Path(raw)
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            binary = workspace / "format-less"
            binary.write_bytes(b"definitely not an executable format\n")
            binary.chmod(stat.S_IRUSR | stat.S_IXUSR)
            arm = ArmProcess(
                _stub_config(),
                "core",
                binary,
                arm_dir,
                time.monotonic_ns() + MAX_ARM_DURATION_NS,
            )
            started = time.monotonic()
            with arm:
                arm.require_ready()
                with self.assertRaises(OSError):
                    arm.launch((str(binary),), "primary")
            self.assertLess(time.monotonic() - started, 10.0)
            self.assertFalse(arm.worker_alive())
            self.assertEqual(arm._listener.fileno(), -1)

    def test_identity_race_discards_unverified_pid(self) -> None:
        with (
            mock.patch.object(
                p2p_loopback,
                "_process_parent_and_generation",
                side_effect=[
                    (1, ProcessGeneration(os.getpid(), 111)),
                    (1, ProcessGeneration(os.getpid(), 222)),
                ],
            ),
            mock.patch.object(p2p_loopback.os, "close", side_effect=os.close),
        ):
            self.assertIsNone(ProcessIdentity.adopt(os.getpid()))
        identity = ProcessIdentity.adopt(os.getpid())
        if identity is None:
            raise AssertionError("a live self identity must adopt")
        self.assertTrue(identity.alive())
        identity.close()

    def test_reparented_child_stays_owned_after_parent_pid_reuse(self) -> None:
        identity = ProcessIdentity(
            os.getpid(),
            111,
            -1,
            ProcessGeneration(42, 333),
        )
        with (
            mock.patch.object(
                p2p_loopback,
                "_process_parent_and_generation",
                return_value=(os.getpid(), ProcessGeneration(os.getpid(), 111)),
            ),
            mock.patch.object(
                p2p_loopback,
                "_process_start_time",
                return_value=444,
            ),
        ):
            self.assertTrue(identity._still_owned())

    def test_process_start_time_refuses_missing_process(self) -> None:
        self.assertIsNone(_process_start_time(0))

    def test_subreaper_scope_refuses_entry_with_live_child(self) -> None:
        sleeper = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        try:
            with (
                self.assertRaisesRegex(ContractError, "already owns child"),
                _ChildSubreaperScope(),
            ):
                pass
        finally:
            sleeper.kill()
            sleeper.wait(timeout=5.0)

    def test_subreaper_scope_installs_and_restores(self) -> None:
        scope = _ChildSubreaperScope()
        with scope:
            self.assertEqual(scope._get(), 1)
        self.assertEqual(scope._get(), 0)

    def test_launch_adoption_failure_reaps_live_child(self) -> None:
        """A live child is terminated and reaped when pidfd adoption fails."""
        with tempfile.TemporaryDirectory(prefix="p2p-adopt-fail-") as raw:
            workspace = Path(raw)
            script = (
                "import os, signal, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
                "time.sleep(30)\n"
            )
            binary = _write_executable(
                workspace / "sleeper", f"#!{sys.executable}\n" + script
            )
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            pid_path = workspace / "leader-pid"
            arm = ArmProcess(
                _stub_config(),
                "core",
                binary,
                arm_dir,
                time.monotonic_ns() + MAX_ARM_DURATION_NS,
            )
            supervisor = _self_generation()
            host_baseline = _host_child_generations(supervisor)
            real_adopt = p2p_loopback.ProcessIdentity.adopt
            calls = {"count": 0}

            def fail_first_adoption(
                pid: int, expected_parent: ProcessGeneration | None = None
            ) -> ProcessIdentity | None:
                calls["count"] += 1
                if calls["count"] == 1:
                    _wait_for_file(pid_path)
                    return None
                return real_adopt(pid, expected_parent)

            with arm:
                arm.require_ready()
                with (
                    mock.patch.object(
                        p2p_loopback.ProcessIdentity,
                        "adopt",
                        side_effect=fail_first_adoption,
                    ),
                    mock.patch.object(
                        p2p_loopback,
                        "_host_child_generations",
                        return_value=host_baseline,
                    ),
                    self.assertRaises(ContractError),
                ):
                    arm.launch((str(binary), str(pid_path)), "primary")
            self.assertTrue(pid_path.exists())
            self.assertTrue(_wait_pid_gone(int(pid_path.read_text())))
            self.assertIsNone(arm._process)
            self.assertIsNone(arm._root_identity)
            arm.close()

    def test_interrupted_launch_cleans_spawned_child(self) -> None:
        """Interruption between spawn and publication still reaps the child."""
        with tempfile.TemporaryDirectory(prefix="p2p-interrupt-") as raw:
            workspace = Path(raw)
            script = (
                "import os, signal, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
                "time.sleep(30)\n"
            )
            binary = _write_executable(
                workspace / "sleeper", f"#!{sys.executable}\n" + script
            )
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            pid_path = workspace / "leader-pid"
            supervisor = _self_generation()
            host_baseline = _host_child_generations(supervisor)
            real_adopt = p2p_loopback.ProcessIdentity.adopt
            calls = {"count": 0}

            def flaky_adopt(
                pid: int, expected_parent: ProcessGeneration | None = None
            ) -> ProcessIdentity | None:
                calls["count"] += 1
                if calls["count"] == 1:
                    _wait_for_file(pid_path)
                    raise KeyboardInterrupt
                return real_adopt(pid, expected_parent)

            arm = ArmProcess(
                _stub_config(),
                "core",
                binary,
                arm_dir,
                time.monotonic_ns() + MAX_ARM_DURATION_NS,
            )
            with arm:
                arm.require_ready()
                with (
                    mock.patch.object(
                        p2p_loopback.ProcessIdentity,
                        "adopt",
                        side_effect=flaky_adopt,
                    ),
                    mock.patch.object(
                        p2p_loopback,
                        "_host_child_generations",
                        return_value=host_baseline,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    arm.launch((str(binary), str(pid_path)), "primary")
            self.assertTrue(pid_path.exists())
            self.assertTrue(_wait_pid_gone(int(pid_path.read_text())))
            self.assertIsNone(arm._process)
            self.assertIsNone(arm._root_identity)

    def test_late_exception_close_uses_fresh_cleanup_deadline(self) -> None:
        """close() cleans TERM-resistant trees even after the arm deadline."""
        with tempfile.TemporaryDirectory(prefix="p2p-late-close-") as raw:
            workspace = Path(raw)
            armed_path = workspace / "armed"
            grandchild_path = workspace / "grandchild-pid"
            inner = (
                "import signal, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "time.sleep(30)\n"
            )
            script = (
                "import os, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, lambda *_: None)\n"
                "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
                f"child = subprocess.Popen([sys.executable, '-c', {inner!r}])\n"
                "open(sys.argv[2], 'w').write(str(child.pid))\n"
                "time.sleep(30)\n"
            )
            binary = _write_executable(
                workspace / "stubborn-node", f"#!{sys.executable}\n" + script
            )
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            deadline = time.monotonic_ns() + 3_500_000_000
            arm = ArmProcess(_stub_config(), "core", binary, arm_dir, deadline)
            started = time.monotonic()
            with (
                _ChildSubreaperScope(),
                self.assertRaisesRegex(ContractError, "work failed late"),
                arm,
            ):
                arm.require_ready()
                arm.launch(
                    (str(binary), str(armed_path), str(grandchild_path)),
                    "primary",
                )
                time.sleep(0.7)  # the arm's work deadline expires here
                raise ContractError("work failed late")
            self.assertLess(time.monotonic() - started, 15.0)
            self.assertTrue(armed_path.exists())
            self.assertTrue(_wait_pid_gone(int(armed_path.read_text())))
            self.assertTrue(_wait_pid_gone(int(grandchild_path.read_text())))
            self.assertIs(arm._state, p2p_loopback.ArmState.CLOSED)
            arm.close()  # a settled arm tolerates a repeated close safely

    def test_subreaper_scope_rejects_concurrent_entry(self) -> None:
        """Overlapping ownership scopes fail closed and serialize afterwards."""
        with (
            _ChildSubreaperScope(),
            self.assertRaisesRegex(
                ContractError, "another child-subreaper ownership scope is active"
            ),
        ):
            _ChildSubreaperScope().__enter__()
        with _ChildSubreaperScope():
            pass

    def test_subreaper_scope_rejects_multithreaded_host(self) -> None:
        """Scope entry refuses a host process that already runs other threads."""
        thread = threading.Thread(target=time.sleep, args=(0.5,))
        thread.start()
        try:
            with self.assertRaisesRegex(ContractError, "single-threaded host"):
                _ChildSubreaperScope().__enter__()
        finally:
            thread.join()

    def test_post_entry_host_child_is_immune_to_drain(self) -> None:
        """A host child spawned after scope entry is never adopted or signaled."""
        with tempfile.TemporaryDirectory(prefix="p2p-immune-") as raw:
            workspace = Path(raw)
            binary = _write_executable(workspace / "exit-node", f"#!{sys.executable}\n")
            arm_dir = workspace / "00-core"
            arm_dir.mkdir()
            with _ChildSubreaperScope():
                host_child = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"]
                )
                try:
                    arm = ArmProcess(
                        _stub_config(),
                        "core",
                        binary,
                        arm_dir,
                        time.monotonic_ns() + MAX_ARM_DURATION_NS,
                    )
                    with arm:
                        arm.require_ready()
                        arm.launch((str(binary),), "primary")
                        arm.wait_clean()
                    time.sleep(0.1)
                    self.assertIsNone(host_child.poll())
                finally:
                    host_child.kill()
                    host_child.wait(timeout=5.0)

    def test_discovery_rejects_replaced_child_pid(self) -> None:
        """A listed pid whose identity no longer matches is never adopted."""
        leader = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        replacement = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        try:
            started = _process_start_time(leader.pid)
            if started is None:
                raise AssertionError("leader must be alive")
            drain = _DescendantDrain(leader, ProcessGeneration(leader.pid, started))
            with mock.patch.object(
                p2p_loopback,
                "_read_proc_children",
                return_value=[replacement.pid],
            ):
                drain.observe()
            self.assertEqual(drain._identities, {})
            self.assertIsNone(replacement.poll())
        finally:
            leader.kill()
            leader.wait(timeout=5.0)
            replacement.kill()
            replacement.wait(timeout=5.0)

    def test_reaped_generation_does_not_suppress_new_generation(self) -> None:
        """Tombstones are generation-keyed: a stale one cannot hide a child."""
        with tempfile.TemporaryDirectory(prefix="p2p-generation-") as raw:
            workspace = Path(raw)
            child_path = workspace / "child-pid"
            script = (
                "import subprocess, sys, time\n"
                "child = subprocess.Popen("
                "[sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                "open(sys.argv[1], 'w').write(str(child.pid))\n"
                "time.sleep(30)\n"
            )
            binary = _write_executable(
                workspace / "seeder", f"#!{sys.executable}\n" + script
            )
            leader = subprocess.Popen([str(binary), str(child_path)])
            child_pid: int | None = None
            try:
                deadline = time.monotonic() + 5.0
                while not child_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(child_path.exists())
                child_pid = int(child_path.read_text())
                child_start = _process_start_time(child_pid)
                leader_start = _process_start_time(leader.pid)
                if child_start is None or leader_start is None:
                    raise AssertionError("seeded tree must be alive")
                drain = _DescendantDrain(
                    leader, ProcessGeneration(leader.pid, leader_start)
                )
                drain._gone.add(ProcessGeneration(child_pid, child_start - 1))
                drain.observe()
                self.assertEqual(
                    list(drain._identities),
                    [ProcessGeneration(child_pid, child_start)],
                )
            finally:
                leader.kill()
                leader.wait(timeout=5.0)
                if child_pid is not None:
                    try:
                        os.kill(child_pid, 9)
                    except ProcessLookupError:
                        pass  # the seeded child already exited on its own
            self.assertTrue(_wait_pid_gone(child_pid))

    def test_public_argv_is_category_only(self) -> None:
        projected = _public_argv(
            [
                "/tmp/arms/00-core/node-under-test",
                "--rpcpassword=alpha-secret",
                "--datadir",
                "/var/lib/secret",
                "-rpcauthSECRET",
                "-p1234",
                "--",
                "positional-secret",
                "{state_path}",
            ]
        )

        # Only stable categories may survive the projection.
        self.assertEqual(
            projected,
            [
                "<executable>",
                "<long-option=value>",
                "<long-option>",
                "<argument>",
                "<short-option>",
                "<short-option>",
                "<end-options>",
                "<argument>",
                "<argument>",
            ],
        )
        canonical = canonical_bytes(projected)
        for leak in (
            b"alpha-secret",
            b"/var/lib/secret",
            b"rpcauthSECRET",
            b"p1234",
            b"positional-secret",
            b"node-under-test",
            b"datadir",
        ):
            self.assertNotIn(leak, canonical)
        self.assertEqual(
            _argv_digest(["node", "-p1234"]), _argv_digest(["node", "-p9999"])
        )
        self.assertNotEqual(
            _argv_digest(["node", "-p1234"]),
            _argv_digest(["node", "-p1234", "-x"]),
        )
        self.assertEqual(
            _public_argv(
                [
                    "node",
                    "{binary}",
                    "{peer_host}",
                    "{peer_port}",
                    "{data_dir}",
                    "{state_path}",
                ]
            ),
            [
                "<executable>",
                "<binary>",
                "<peer-host>",
                "<peer-port>",
                "<data-dir>",
                "<state-path>",
            ],
        )


if __name__ == "__main__":
    unittest.main()
