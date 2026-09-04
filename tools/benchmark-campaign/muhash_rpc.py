#!/usr/bin/env python3.14
# pyright: strict
"""Fail-closed external MuHash JSON-RPC comparator.

One-shot timed trial, lifecycle/cache campaign controller, and offline
triple aggregator. The campaign owns process lifecycle and cache posture;
the trial client is the only timed RPC speaker; aggregate is the only
verdict publisher.
"""

import argparse
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TypedDict, TypeIs

TRIAL_INPUT_SCHEMA = "muhash-rpc-trial-input-v2"
AGGREGATE_INPUT_SCHEMA = "muhash-rpc-aggregate-input-v2"
CAMPAIGN_CONFIG_SCHEMA = "muhash-rpc-campaign-config-v2"
OBSERVATION_SCHEMA = "muhash-rpc-observation-v2"
PRE_RECEIPT_SCHEMA = "muhash-rpc-pre-receipt-v2"
POST_RECEIPT_SCHEMA = "muhash-rpc-post-receipt-v2"
RESULT_SCHEMA = "muhash-rpc-result-v2"
PAIR_COUNT = 7
TRIPLE_COUNT = 2 * PAIR_COUNT
RPC_METHOD = "gettxoutsetinfo"
RPC_PARAMS: tuple[str, None, bool] = ("muhash", None, False)
CORE_BACKEND = "coinsdb"
BITCOIN_RS_BACKENDS = frozenset({"fjall", "rocksdb", "redb"})
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_COMMAND_ARGS = 64
ARM_READY_TIMEOUT_NS = 10_000_000_000
CHILD_TERMINATE_GRACE_NS = 1_000_000_000
CHILD_KILL_REAP_NS = 1_000_000_000
CACHE_POLICY_ACTIONS = {
    "warm": "warm-untimed-query-done",
    "process-cold/page-cache-unspecified": "fresh-process-before-observation",
    "process-cold/page-cache-evicted": "page-cache-evicted",
}
CACHE_POLICIES = frozenset(CACHE_POLICY_ACTIONS)
_CAMPAIGN_PLACEHOLDERS = frozenset(
    {"{binary}", "{config}", "{data_dir}", "{rpc_port}", "{rpc_bind}", "{cookie}"}
)
_TCP_ESTABLISHED = 0x01
_TCP_LISTEN = 0x0A
_LOOPBACK_V4 = "0100007F"
_LOOPBACK_V6 = "00000000000000000000000001000000"
OPERATOR_TRUST_BOUNDARY = (
    "operator-controlled observation; not remote binary authentication"
)
MAX_INPUT_BYTES = 65_536
MAX_RECEIPT_BYTES = 65_536
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 32
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
type JsonObject = dict[str, object]


class ComparatorError(Exception):
    """Base class for comparator refusals."""


class ContractError(ComparatorError, ValueError):
    """Input or evidence violates the comparator contract."""


class RpcTransportError(ComparatorError):
    """The bounded HTTP exchange failed."""


class RpcProtocolError(ComparatorError):
    """The JSON-RPC response violated the fixed protocol."""


class Statistics(TypedDict):
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
class UtxoState:
    height: int
    bestblock: str
    transactions: int
    txouts: int
    bogosize: int
    disk_size: int
    total_amount: Decimal
    muhash: str


def _is_object(value: object) -> TypeIs[JsonObject]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _is_array(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _object(value: object, field: str, keys: frozenset[str]) -> JsonObject:
    if not _is_object(value):
        raise ContractError(f"{field} must be a JSON object")
    actual = frozenset(value)
    if actual != keys:
        # Diagnostics carry counts only: attacker-controlled member names
        # must never reach stderr.
        raise ContractError(
            f"{field} has wrong keys; missing_count={len(keys - actual)}, "
            f"unknown_count={len(actual - keys)}"
        )
    return value


def _array(value: object, field: str, length: int | None = None) -> list[object]:
    if not _is_array(value):
        raise ContractError(f"{field} must be an array")
    if length is not None and len(value) != length:
        raise ContractError(f"{field} must contain exactly {length} items")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{field} must be a nonempty string")
    return value


def _choice(value: object, field: str, choices: frozenset[str]) -> str:
    text = _text(value, field)
    if text not in choices:
        raise ContractError(f"{field} must be one of {sorted(choices)}")
    return text


def _uint(value: object, field: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a nonnegative integer")
    if positive and value == 0:
        raise ContractError(f"{field} must be positive")
    return value


def _decimal(value: object, field: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal, str)):
        raise ContractError(f"{field} must be a decimal number")
    try:
        result = Decimal(value)
    except (InvalidOperation, ValueError) as error:
        raise ContractError(f"{field} must be a decimal number") from error
    if not result.is_finite() or result < 0 or (positive and result == 0):
        word = "positive" if positive else "nonnegative"
        raise ContractError(f"{field} must be finite and {word}")
    return result


def _amount(value: object, field: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ContractError(f"{field} must be a JSON number")
    amount = _decimal(value, field)
    if amount > Decimal(21_000_000):
        raise ContractError(f"{field} exceeds the Bitcoin money supply")
    if amount == 0:
        return Decimal(0)
    # Inspect the stored exponent directly: normalize() can underflow a
    # tiny exponent to zero and would silently pass the scale check.
    exponent = amount.as_tuple().exponent
    if not isinstance(exponent, int) or exponent < -8:
        raise ContractError(f"{field} must have at most eight fractional digits")
    return amount


def _hash(value: object, field: str) -> str:
    text = _text(value, field)
    if _HASH_RE.fullmatch(text) is None:
        raise ContractError(f"{field} must be a lowercase 64-character hash")
    return text


def _path(value: object, field: str) -> Path:
    path = Path(_text(value, field))
    if not path.is_absolute():
        raise ContractError(f"{field} must be an absolute path")
    return path


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def canonical_json_bytes(value: object) -> bytes:
    """Encode deterministic JSON with Decimal values as normalized numbers."""

    def encode(item: object) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            return str(item)
        if isinstance(item, Decimal):
            if not item.is_finite():
                raise ContractError("canonical JSON cannot encode a non-finite Decimal")
            return _decimal_text(item)
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, (list, tuple)):
            return "[" + ",".join(encode(child) for child in item) + "]"
        if _is_object(item):
            fields = (f"{encode(key)}:{encode(item[key])}" for key in sorted(item))
            return "{" + ",".join(fields) + "}"
        raise ContractError(f"unsupported canonical JSON value: {type(item).__name__}")

    return encode(value).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _check_depth(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
        if _is_object(item):
            stack.extend((child, depth + 1) for child in item.values())
        elif _is_array(item):
            stack.extend((child, depth + 1) for child in item)


def _unique_object(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            # The key text is never echoed: it can carry attacker-controlled
            # bytes from an RPC response into stderr.
            raise ContractError("JSON contains a duplicate member")
        result[key] = value
    return result


def _parse_json(raw: bytes, field: str) -> object:
    try:
        value: object = json.loads(
            raw,
            parse_float=Decimal,
            parse_int=int,
            object_pairs_hook=_unique_object,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ContractError(f"{field} is not valid UTF-8 JSON") from error
    except RecursionError as error:
        # The decoder recurses before MAX_JSON_DEPTH can be enforced.
        raise ContractError(f"{field} JSON could not be decoded") from error
    except ValueError as error:
        # Overlong integer tokens raise plain ValueError from parse_int;
        # our own duplicate-member refusal must keep its identity.
        if isinstance(error, ContractError):
            raise
        raise ContractError(f"{field} JSON could not be decoded") from error
    _check_depth(value)
    return value


def _file_ref(value: object, field: str) -> FileRef:
    item = _object(value, field, frozenset({"path", "sha256", "bytes"}))
    return FileRef(
        path=_path(item["path"], f"{field}.path"),
        sha256=_hash(item["sha256"], f"{field}.sha256"),
        size=_uint(item["bytes"], f"{field}.bytes", positive=True),
    )


def _open_flags() -> int:
    # O_NONBLOCK: a FIFO or device opened before the regular-file check
    # must never park the comparator waiting for a writer.
    return (
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _read_fd(descriptor: int, size: int, cap: int, field: str) -> bytes:
    if size > cap:
        raise ContractError(f"{field} exceeds {cap} bytes")
    chunks: list[bytes] = []
    remaining = size + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) != size:
        raise ContractError(f"{field} changed while being read")
    return raw


def _read_regular_file(path: Path, cap: int, field: str) -> bytes:
    try:
        descriptor = os.open(path, _open_flags())
    except OSError as error:
        raise ContractError(f"cannot open {field}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{field} must be a regular file")
        raw = _read_fd(descriptor, before.st_size, cap, field)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise ContractError(f"{field} changed while being read")
        return raw
    finally:
        os.close(descriptor)


def _verify_file(reference: FileRef, field: str, cap: int = MAX_RECEIPT_BYTES) -> bytes:
    raw = _read_regular_file(reference.path, cap, field)
    if len(raw) != reference.size:
        raise ContractError(f"{field} size does not match its pinned identity")
    if hashlib.sha256(raw).hexdigest() != reference.sha256:
        raise ContractError(f"{field} SHA-256 does not match its pinned identity")
    return raw


def _load_json_path(path: Path, cap: int, field: str) -> tuple[object, bytes]:
    raw = _read_regular_file(path, cap, field)
    return _parse_json(raw, field), raw


def _load_json_ref(reference: FileRef, field: str) -> tuple[object, bytes]:
    raw = _verify_file(reference, field)
    return _parse_json(raw, field), raw


def _coordinates(item: JsonObject, field: str) -> tuple[str, str, int, int, str, str]:
    campaign = _text(item["campaign_id"], f"{field}.campaign_id")
    policy = _choice(item["policy"], f"{field}.policy", CACHE_POLICIES)
    pair = _uint(item["pair_index"], f"{field}.pair_index")
    if pair >= PAIR_COUNT:
        raise ContractError(f"{field}.pair_index must be in 0..6")
    position = _uint(item["position"], f"{field}.position")
    if position not in (0, 1):
        raise ContractError(f"{field}.position must be 0 or 1")
    arm_id = _text(item["arm_id"], f"{field}.arm_id")
    arm_kind = _choice(
        item["arm_kind"], f"{field}.arm_kind", frozenset({"core", "bitcoin-rs"})
    )
    return campaign, policy, pair, position, arm_id, arm_kind


def _validate_endpoint(value: object, field: str) -> str:
    endpoint = _text(value, field)
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except ValueError as error:
        raise ContractError(f"{field} is not a valid URL") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None
        or not parsed.path
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ContractError(
            f"{field} must be literal-loopback HTTP with explicit port and path"
        )
    return endpoint


def _parse_corpus(value: object, field: str) -> JsonObject:
    item = _object(value, field, frozenset({"identity", "file", "height", "bestblock"}))
    return {
        "identity": _text(item["identity"], f"{field}.identity"),
        "file": _file_ref(item["file"], f"{field}.file"),
        "height": _uint(item["height"], f"{field}.height"),
        "bestblock": _hash(item["bestblock"], f"{field}.bestblock"),
    }


def _parse_proc_stat(value: object, field: str) -> JsonObject:
    item = _object(value, field, frozenset({"minflt", "majflt"}))
    return {
        "minflt": _uint(item["minflt"], f"{field}.minflt"),
        "majflt": _uint(item["majflt"], f"{field}.majflt"),
    }


def _parse_proc_io(value: object, field: str) -> JsonObject:
    keys = frozenset({"rchar", "read_bytes", "wchar", "write_bytes", "syscr", "syscw"})
    item = _object(value, field, keys)
    return {key: _uint(item[key], f"{field}.{key}") for key in sorted(keys)}


def _parse_deltas(value: object, field: str, keys: frozenset[str]) -> JsonObject:
    item = _object(value, field, keys)
    return {key: _uint(item[key], f"{field}.{key}") for key in sorted(keys)}


def _parse_pre(value: object, field: str = "pre_receipt") -> JsonObject:
    keys = frozenset(
        {
            "schema",
            "campaign_id",
            "policy",
            "pair_index",
            "position",
            "arm_id",
            "arm_kind",
            "executable",
            "config",
            "corpus",
            "backend",
            "datadir",
            "endpoint",
            "attested_pid",
            "attested_starttime",
            "affinity",
            "cache_policy_action",
            "eviction_procedure",
            "frozen_height",
            "frozen_bestblock",
            "proc_stat_before",
            "proc_io_before",
            "operator_trust_boundary",
        }
    )
    item = _object(value, field, keys)
    if item["schema"] != PRE_RECEIPT_SCHEMA:
        raise ContractError(f"{field}.schema must be {PRE_RECEIPT_SCHEMA}")
    _coordinates(item, field)
    policy = _text(item["policy"], f"{field}.policy")
    executable = _file_ref(item["executable"], f"{field}.executable")
    config = _file_ref(item["config"], f"{field}.config")
    corpus = _parse_corpus(item["corpus"], f"{field}.corpus")
    endpoint = _validate_endpoint(item["endpoint"], f"{field}.endpoint")
    action = _text(item["cache_policy_action"], f"{field}.cache_policy_action")
    if action != CACHE_POLICY_ACTIONS[policy]:
        raise ContractError(f"{field}.cache_policy_action is wrong for {policy}")
    eviction_value = item["eviction_procedure"]
    eviction = (
        None
        if eviction_value is None
        else _file_ref(eviction_value, f"{field}.eviction_procedure")
    )
    if (policy == "process-cold/page-cache-evicted") != (eviction is not None):
        raise ContractError(f"{field}.eviction_procedure is wrong for {policy}")
    if item["operator_trust_boundary"] != OPERATOR_TRUST_BOUNDARY:
        raise ContractError(
            f"{field}.operator_trust_boundary is not the required disclaimer"
        )
    return {
        **item,
        "executable": executable,
        "config": config,
        "corpus": corpus,
        "datadir": _path(item["datadir"], f"{field}.datadir"),
        "endpoint": endpoint,
        "attested_pid": _uint(
            item["attested_pid"], f"{field}.attested_pid", positive=True
        ),
        "attested_starttime": _uint(
            item["attested_starttime"], f"{field}.attested_starttime", positive=True
        ),
        "affinity": _text(item["affinity"], f"{field}.affinity"),
        "eviction_procedure": eviction,
        "frozen_height": _uint(item["frozen_height"], f"{field}.frozen_height"),
        "frozen_bestblock": _hash(
            item["frozen_bestblock"], f"{field}.frozen_bestblock"
        ),
        "proc_stat_before": _parse_proc_stat(
            item["proc_stat_before"], f"{field}.proc_stat_before"
        ),
        "proc_io_before": _parse_proc_io(
            item["proc_io_before"], f"{field}.proc_io_before"
        ),
    }


def _state_json(state: UtxoState) -> JsonObject:
    return {
        "height": state.height,
        "bestblock": state.bestblock,
        "transactions": state.transactions,
        "txouts": state.txouts,
        "bogosize": state.bogosize,
        "disk_size": state.disk_size,
        "total_amount": state.total_amount,
        "muhash": state.muhash,
    }


def _parse_state(value: object, field: str) -> UtxoState:
    keys = frozenset(
        {
            "height",
            "bestblock",
            "transactions",
            "txouts",
            "bogosize",
            "disk_size",
            "total_amount",
            "muhash",
        }
    )
    item = _object(value, field, keys)
    state = UtxoState(
        height=_uint(item["height"], f"{field}.height"),
        bestblock=_hash(item["bestblock"], f"{field}.bestblock"),
        transactions=_uint(item["transactions"], f"{field}.transactions"),
        txouts=_uint(item["txouts"], f"{field}.txouts"),
        bogosize=_uint(item["bogosize"], f"{field}.bogosize"),
        disk_size=_uint(item["disk_size"], f"{field}.disk_size"),
        total_amount=_amount(item["total_amount"], f"{field}.total_amount"),
        muhash=_hash(item["muhash"], f"{field}.muhash"),
    )
    return state


def _state_key(state: UtxoState) -> tuple[object, ...]:
    return (
        state.height,
        state.bestblock,
        state.transactions,
        state.txouts,
        state.total_amount,
        state.muhash,
    )


def _parse_observation(value: object, field: str = "observation") -> JsonObject:
    keys = frozenset(
        {
            "schema",
            "campaign_id",
            "policy",
            "pair_index",
            "position",
            "arm_id",
            "arm_kind",
            "input_sha256",
            "controller_declaration_sha256",
            "query",
            "request_sha256",
            "http_status",
            "raw_response_sha256",
            "raw_response_b64",
            "duration_ns",
            "monotonic_start_ns",
            "monotonic_end_ns",
            "state",
            "self_sha256",
        }
    )
    item = _object(value, field, keys)
    if item["schema"] != OBSERVATION_SCHEMA:
        raise ContractError(f"{field}.schema must be {OBSERVATION_SCHEMA}")
    _coordinates(item, field)
    query = _object(
        item["query"], f"{field}.query", frozenset({"method", "params", "use_index"})
    )
    if query != {
        "method": RPC_METHOD,
        "params": list(RPC_PARAMS),
        "use_index": False,
    }:
        raise ContractError(f"{field}.query is not the fixed production query")
    started = _uint(
        item["monotonic_start_ns"], f"{field}.monotonic_start_ns", positive=True
    )
    ended = _uint(item["monotonic_end_ns"], f"{field}.monotonic_end_ns", positive=True)
    duration = _uint(item["duration_ns"], f"{field}.duration_ns", positive=True)
    if ended <= started or duration != ended - started:
        raise ContractError(f"{field} has inconsistent monotonic timing")
    if item["http_status"] != 200:
        raise ContractError(f"{field}.http_status must be 200")
    _text(item["raw_response_b64"], f"{field}.raw_response_b64")
    try:
        raw_response = base64.b64decode(item["raw_response_b64"], validate=True)
    except (ValueError, TypeError) as error:
        raise ContractError(f"{field}.raw_response_b64 is not valid base64") from error
    if len(raw_response) > MAX_RESPONSE_BYTES:
        raise ContractError(f"{field}.raw_response_b64 exceeds the response cap")
    if hashlib.sha256(raw_response).hexdigest() != item["raw_response_sha256"]:
        raise ContractError(f"{field}.raw_response_sha256 does not bind its bytes")
    raw_envelope = _parse_json(raw_response, f"{field}.raw response")
    raw_item = _object(
        raw_envelope,
        f"{field}.raw response envelope",
        frozenset({"jsonrpc", "id", "result", "error"}),
    )
    if raw_item != {
        "jsonrpc": "2.0",
        "id": 1,
        "error": None,
        "result": item["state"],
    }:
        raise ContractError(f"{field}.raw response does not reproduce its state")
    state = _parse_state(item["state"], f"{field}.state")
    for hash_field in (
        "input_sha256",
        "controller_declaration_sha256",
        "request_sha256",
        "raw_response_sha256",
        "self_sha256",
    ):
        _hash(item[hash_field], f"{field}.{hash_field}")
    unhashed = dict(item)
    recorded = unhashed.pop("self_sha256")
    if canonical_sha256(unhashed) != recorded:
        raise ContractError(f"{field}.self_sha256 does not recompute")
    return {**item, "state": state, "raw_response": raw_response}


def _parse_post(value: object, field: str = "post_receipt") -> JsonObject:
    keys = frozenset(
        {
            "schema",
            "campaign_id",
            "policy",
            "pair_index",
            "position",
            "arm_id",
            "arm_kind",
            "pre_receipt_sha256",
            "observation_sha256",
            "attested_pid",
            "attested_starttime",
            "proc_stat_after",
            "proc_io_after",
            "faults_delta",
            "io_delta",
            "eviction_execution",
        }
    )
    item = _object(value, field, keys)
    if item["schema"] != POST_RECEIPT_SCHEMA:
        raise ContractError(f"{field}.schema must be {POST_RECEIPT_SCHEMA}")
    _coordinates(item, field)
    _hash(item["pre_receipt_sha256"], f"{field}.pre_receipt_sha256")
    _hash(item["observation_sha256"], f"{field}.observation_sha256")
    execution = item["eviction_execution"]
    if execution is not None:
        execution_item = _object(
            execution,
            f"{field}.eviction_execution",
            frozenset({"procedure_sha256", "exit_status", "monotonic_ns"}),
        )
        _hash(
            execution_item["procedure_sha256"],
            f"{field}.eviction_execution.procedure_sha256",
        )
        if execution_item["exit_status"] != 0:
            raise ContractError(f"{field}.eviction_execution did not succeed")
        _uint(
            execution_item["monotonic_ns"],
            f"{field}.eviction_execution.monotonic_ns",
            positive=True,
        )
    return {
        **item,
        "attested_pid": _uint(
            item["attested_pid"], f"{field}.attested_pid", positive=True
        ),
        "attested_starttime": _uint(
            item["attested_starttime"], f"{field}.attested_starttime", positive=True
        ),
        "proc_stat_after": _parse_proc_stat(
            item["proc_stat_after"], f"{field}.proc_stat_after"
        ),
        "proc_io_after": _parse_proc_io(
            item["proc_io_after"], f"{field}.proc_io_after"
        ),
        "faults_delta": _parse_deltas(
            item["faults_delta"],
            f"{field}.faults_delta",
            frozenset({"minflt", "majflt"}),
        ),
        "io_delta": _parse_deltas(
            item["io_delta"],
            f"{field}.io_delta",
            frozenset({"rchar", "read_bytes", "wchar", "write_bytes"}),
        ),
    }


MAX_HEADER_BYTES = 16_384

_AT_EMPTY_PATH = 0x1000


def _remaining(deadline_ns: int) -> float:
    remaining = (deadline_ns - time.perf_counter_ns()) / 1_000_000_000
    if remaining <= 0:
        raise RpcTransportError("RPC end-to-end deadline exceeded")
    return remaining


def _wait(
    selector: selectors.BaseSelector,
    event: int,
    deadline_ns: int,
) -> None:
    # Every wait is bounded by the remaining absolute budget, so no
    # readiness event can extend the deadline. The socket stays registered
    # for both directions; a mismatching readiness event simply keeps the
    # loop within the same budget.
    while True:
        ready = selector.select(_remaining(deadline_ns))
        if not ready:
            raise RpcTransportError("RPC end-to-end deadline exceeded")
        if ready[0][1] & event:
            return


def _send_all(
    sock: socket.socket,
    selector: selectors.BaseSelector,
    payload: bytes,
    deadline_ns: int,
) -> None:
    view = memoryview(payload)
    while view:
        _wait(selector, selectors.EVENT_WRITE, deadline_ns)
        sent = sock.send(view)
        view = view[sent:]


def _recv_until(
    sock: socket.socket,
    selector: selectors.BaseSelector,
    terminator: bytes,
    cap: int,
    deadline_ns: int,
) -> bytes:
    buffer = bytearray()
    while terminator not in buffer:
        _wait(selector, selectors.EVENT_READ, deadline_ns)
        chunk = sock.recv(65_536)
        if not chunk:
            raise RpcTransportError("RPC connection closed mid-exchange")
        buffer.extend(chunk)
        if len(buffer) > cap:
            raise RpcTransportError(f"RPC response exceeds {cap} bytes")
    return bytes(buffer)


def _parse_header_block(block: bytes, max_bytes: int) -> int:
    try:
        text = block.decode("ascii")
    except UnicodeDecodeError as error:
        raise RpcProtocolError("RPC response headers are not ASCII") from error
    lines = text.split("\r\n")
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise RpcProtocolError("RPC response has no status line")
    status = lines[0].split(" ")
    if len(status) < 2 or not status[0].startswith("HTTP/") or status[1] != "200":
        raise RpcTransportError("RPC did not return HTTP status 200")
    content_lengths: list[str] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t":
            raise RpcProtocolError("RPC response uses obsolete header folding")
        name, separator, value = line.partition(":")
        if not separator:
            raise RpcProtocolError("RPC response header is malformed")
        field = name.strip().lower()
        if field == "transfer-encoding":
            raise RpcProtocolError("RPC transfer-encoding is refused")
        if field == "content-length":
            content_lengths.append(value.strip())
    if len(content_lengths) != 1:
        raise RpcProtocolError("RPC response must carry exactly one content-length")
    declared = content_lengths[0]
    if not declared.isascii() or not declared.isdigit():
        raise RpcProtocolError("RPC content-length is not a valid length")
    if declared[0] == "0" and len(declared) > 1:
        raise RpcProtocolError("RPC content-length has a leading zero")
    # Bound the token before int(): a 5,000-digit length fits the header
    # cap but would raise ValueError from the integer-digit limit.
    if len(declared) > len(str(max_bytes)):
        raise RpcTransportError(f"RPC response exceeds {max_bytes} bytes")
    length = int(declared)
    if length > max_bytes:
        raise RpcTransportError(f"RPC response exceeds {max_bytes} bytes")
    return length


def _rpc_once(
    endpoint: str,
    credentials: tuple[str, str],
    timeout: Decimal,
    max_bytes: int,
    expected_height: int,
    expected_hash: str,
    owner_pid: int,
    owner_starttime: int,
) -> tuple[bytes, bytes, int, int, UtxoState]:
    body = _request_body()
    parsed = urllib.parse.urlsplit(endpoint)
    host = parsed.hostname or ""
    port = parsed.port
    assert port is not None
    host_header = f"[{host}]" if ":" in host else host
    token = base64.b64encode(f"{credentials[0]}:{credentials[1]}".encode()).decode(
        "ascii"
    )
    request_head = (
        f"POST {parsed.path} HTTP/1.1\r\n"
        f"Host: {host_header}:{port}\r\n"
        f"Authorization: Basic {token}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    request = request_head + body
    started = time.perf_counter_ns()
    deadline = started + int(timeout * Decimal(1_000_000_000))
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    try:
        connection = socket.socket(family, socket.SOCK_STREAM)
        selector = selectors.DefaultSelector()
        try:
            connection.setblocking(False)
            connection.connect_ex((host, port))
            selector.register(connection, selectors.EVENT_WRITE)
            while True:
                _wait(selector, selectors.EVENT_WRITE, deadline)
                if connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    break
                raise RpcTransportError("RPC connect failed")
            _require_peer_owned(
                connection, host, port, owner_pid, owner_starttime, deadline
            )
            _send_all(connection, selector, request, deadline)
            # Receive phases register read interest only: a permanently
            # write-ready socket must never wake a read wait.
            selector.modify(connection, selectors.EVENT_READ)
            header_block = _recv_until(
                connection, selector, b"\r\n\r\n", MAX_HEADER_BYTES, deadline
            )
            content_length = _parse_header_block(header_block, max_bytes)
            buffer = bytearray(header_block.split(b"\r\n\r\n", 1)[1])
            if len(buffer) > content_length:
                # Coalesced bytes beyond the declared length arrive in the
                # same packet as the headers; refuse before any parsing.
                raise RpcTransportError(f"RPC response exceeds {content_length} bytes")
            while len(buffer) < content_length:
                _wait(selector, selectors.EVENT_READ, deadline)
                chunk = connection.recv(65_536)
                if not chunk:
                    raise RpcTransportError("RPC connection closed mid-exchange")
                buffer.extend(chunk)
                if len(buffer) > content_length:
                    raise RpcTransportError(
                        f"RPC response exceeds {content_length} bytes"
                    )
            # The exact length matched: prove the peer sends nothing more
            # (or closes) under the same absolute deadline.
            while True:
                _wait(selector, selectors.EVENT_READ, deadline)
                trailing = connection.recv(65_536)
                if not trailing:
                    break
                raise RpcTransportError("RPC response carried extra body bytes")
            raw = bytes(buffer)
        finally:
            selector.close()
            connection.close()
    except (OSError, TimeoutError) as error:
        raise RpcTransportError("RPC transport failed or deadline expired") from error
    parsed_body = _parse_json(raw, "RPC response")
    try:
        envelope = _object(
            parsed_body,
            "JSON-RPC response",
            frozenset({"jsonrpc", "id", "result", "error"}),
        )
    except ContractError as error:
        raise RpcProtocolError("RPC response envelope is malformed") from error
    if envelope["jsonrpc"] != "2.0" or envelope["id"] != 1:
        raise RpcProtocolError("RPC returned mismatched JSON-RPC metadata")
    if envelope["error"] is not None:
        raise RpcProtocolError("RPC returned an error")
    try:
        state = _parse_state(envelope["result"], "RPC result")
    except ContractError as error:
        raise RpcProtocolError("RPC result schema is malformed") from error
    if state.height != expected_height or state.bestblock != expected_hash:
        raise ContractError("RPC result does not match the frozen tip")
    ended = time.perf_counter_ns()
    if ended <= started or ended > deadline:
        raise RpcTransportError("RPC end-to-end deadline exceeded")
    return body, raw, started, ended, state


def _load_credentials(reference: FileRef) -> tuple[str, str]:
    try:
        descriptor = os.open(reference.path, _open_flags())
    except OSError as error:
        raise ContractError("cannot open credential_file") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError("credential_file must be a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ContractError("credential_file must not grant group or other access")
        raw = _read_fd(descriptor, info.st_size, MAX_INPUT_BYTES, "credential_file")
        after = os.fstat(descriptor)
        if (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ContractError("credential_file changed while being read")
    finally:
        os.close(descriptor)
    if len(raw) != reference.size:
        raise ContractError("credential_file size does not match its pinned identity")
    if hashlib.sha256(raw).hexdigest() != reference.sha256:
        raise ContractError(
            "credential_file SHA-256 does not match its pinned identity"
        )
    try:
        text = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise ContractError("credential_file must be UTF-8") from error
    if ":" not in text:
        raise ContractError("credential_file must contain user:password")
    user, password = text.split(":", 1)
    if (
        not user
        or not password
        or "\n" in user
        or "\n" in password
        or "\r" in user
        or "\r" in password
    ):
        raise ContractError("credential_file must contain one user:password record")
    return user, password


def _request_body() -> bytes:
    return canonical_json_bytes(
        {"jsonrpc": "2.0", "id": 1, "method": RPC_METHOD, "params": list(RPC_PARAMS)}
    )


def _parse_trial_input(value: object) -> JsonObject:
    keys = frozenset(
        {
            "schema",
            "campaign_id",
            "policy",
            "pair_index",
            "position",
            "arm_id",
            "arm_kind",
            "endpoint",
            "credential_file",
            "timeout_seconds",
            "max_response_bytes",
            "corpus",
            "expected",
            "controller_pre_receipt",
        }
    )
    item = _object(value, "trial input", keys)
    if item["schema"] != TRIAL_INPUT_SCHEMA:
        raise ContractError(f"trial input.schema must be {TRIAL_INPUT_SCHEMA}")
    _coordinates(item, "trial input")
    timeout = _decimal(
        item["timeout_seconds"], "trial input.timeout_seconds", positive=True
    )
    if timeout > 300:
        raise ContractError("trial input.timeout_seconds must not exceed 300")
    max_bytes = _uint(
        item["max_response_bytes"], "trial input.max_response_bytes", positive=True
    )
    if max_bytes > MAX_RESPONSE_BYTES:
        raise ContractError(
            f"trial input.max_response_bytes must not exceed {MAX_RESPONSE_BYTES}"
        )
    expected = _object(
        item["expected"], "trial input.expected", frozenset({"height", "bestblock"})
    )
    return {
        **item,
        "endpoint": _validate_endpoint(item["endpoint"], "trial input.endpoint"),
        "credential_file": _file_ref(
            item["credential_file"], "trial input.credential_file"
        ),
        "timeout_seconds": timeout,
        "max_response_bytes": max_bytes,
        "corpus": _parse_corpus(item["corpus"], "trial input.corpus"),
        "expected": {
            "height": _uint(expected["height"], "trial input.expected.height"),
            "bestblock": _hash(expected["bestblock"], "trial input.expected.bestblock"),
        },
        "controller_pre_receipt": _file_ref(
            item["controller_pre_receipt"], "trial input.controller_pre_receipt"
        ),
    }


def run_trial(input_path: Path) -> JsonObject:
    value, _ = _load_json_path(input_path, MAX_INPUT_BYTES, "trial input")
    trial = _parse_trial_input(value)
    corpus = trial["corpus"]
    if not _is_object(corpus):
        raise ContractError("trial input.corpus is malformed")
    corpus_ref = corpus["file"]
    if not isinstance(corpus_ref, FileRef):
        raise ContractError("trial input.corpus.file is malformed")
    _verify_file(corpus_ref, "trial input.corpus.file", MAX_RESPONSE_BYTES)
    pre_ref = trial["controller_pre_receipt"]
    if not isinstance(pre_ref, FileRef):
        raise ContractError("trial input.controller_pre_receipt is malformed")
    pre_value, pre_raw = _load_json_ref(pre_ref, "controller pre-receipt")
    pre = _parse_pre(pre_value, "controller pre-receipt")
    if _coordinates(pre, "controller pre-receipt") != _coordinates(
        trial, "trial input"
    ):
        raise ContractError(
            "controller pre-receipt coordinates do not match trial input"
        )
    if pre["endpoint"] != trial["endpoint"]:
        raise ContractError(
            "controller pre-receipt endpoint does not match trial input"
        )
    pre_corpus = pre["corpus"]
    if not _is_object(pre_corpus) or pre_corpus != corpus:
        raise ContractError("controller pre-receipt corpus does not match trial input")
    expected = trial["expected"]
    if not _is_object(expected):
        raise ContractError("trial input.expected is malformed")
    if (
        pre["frozen_height"] != expected["height"]
        or pre["frozen_bestblock"] != expected["bestblock"]
    ):
        raise ContractError(
            "controller pre-receipt frozen tip does not match trial input"
        )
    credential_ref = trial["credential_file"]
    if not isinstance(credential_ref, FileRef):
        raise ContractError("trial input.credential_file is malformed")
    credentials = _load_credentials(credential_ref)
    body, raw, started, ended, state = _rpc_once(
        _text(trial["endpoint"], "trial input.endpoint"),
        credentials,
        _decimal(
            trial["timeout_seconds"], "trial input.timeout_seconds", positive=True
        ),
        _uint(
            trial["max_response_bytes"], "trial input.max_response_bytes", positive=True
        ),
        _uint(expected["height"], "trial input.expected.height"),
        _hash(expected["bestblock"], "trial input.expected.bestblock"),
        _uint(pre["attested_pid"], "controller pre-receipt.attested_pid", positive=True),
        _uint(
            pre["attested_starttime"],
            "controller pre-receipt.attested_starttime",
            positive=True,
        ),
    )
    observation: JsonObject = {
        "schema": OBSERVATION_SCHEMA,
        "campaign_id": trial["campaign_id"],
        "policy": trial["policy"],
        "pair_index": trial["pair_index"],
        "position": trial["position"],
        "arm_id": trial["arm_id"],
        "arm_kind": trial["arm_kind"],
        "input_sha256": canonical_sha256(value),
        "controller_declaration_sha256": hashlib.sha256(pre_raw).hexdigest(),
        "query": {
            "method": RPC_METHOD,
            "params": list(RPC_PARAMS),
            "use_index": False,
        },
        "request_sha256": hashlib.sha256(body).hexdigest(),
        "http_status": 200,
        "raw_response_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_response_b64": base64.b64encode(raw).decode("ascii"),
        "duration_ns": ended - started,
        "monotonic_start_ns": started,
        "monotonic_end_ns": ended,
        "state": _state_json(state),
    }
    observation["self_sha256"] = canonical_sha256(observation)
    return observation


def trial_order(pair_index: int) -> tuple[str, str]:
    return ("core", "bitcoin-rs") if pair_index % 2 == 0 else ("bitcoin-rs", "core")


def nearest_rank(samples: list[int], percentile: int) -> int:
    if not samples:
        raise ContractError("cannot summarize an empty sample set")
    if percentile <= 0 or percentile > 100:
        raise ContractError("percentile must be in 1..100")
    ordered = sorted(samples)
    return ordered[(percentile * len(ordered) + 99) // 100 - 1]


def _stats(samples: list[int]) -> Statistics:
    if len(samples) != PAIR_COUNT:
        raise ContractError(f"each arm must have exactly {PAIR_COUNT} samples")
    return {
        "p50_ns": nearest_rank(samples, 50),
        "p95_ns": nearest_rank(samples, 95),
        "p99_ns": nearest_rank(samples, 99),
        "max_ns": max(samples),
    }


def _int_map(value: object, field: str) -> dict[str, int]:
    if not _is_object(value):
        raise ContractError(f"{field} must be an object of integers")
    result: dict[str, int] = {}
    for key, item in value.items():
        if isinstance(item, bool) or not isinstance(item, int):
            raise ContractError(f"{field}.{key} must be an integer")
        result[key] = item
    return result


def _validate_deltas(pre: JsonObject, post: JsonObject, field: str) -> None:
    before_stat = _int_map(pre["proc_stat_before"], f"{field}.proc_stat_before")
    after_stat = _int_map(post["proc_stat_after"], f"{field}.proc_stat_after")
    faults = _int_map(post["faults_delta"], f"{field}.faults_delta")
    before_io = _int_map(pre["proc_io_before"], f"{field}.proc_io_before")
    after_io = _int_map(post["proc_io_after"], f"{field}.proc_io_after")
    io_delta = _int_map(post["io_delta"], f"{field}.io_delta")
    for key in ("minflt", "majflt"):
        if (
            after_stat[key] < before_stat[key]
            or faults[key] != after_stat[key] - before_stat[key]
        ):
            raise ContractError(f"{field}.faults_delta is inconsistent")
    for key in ("rchar", "read_bytes", "wchar", "write_bytes"):
        if (
            after_io[key] < before_io[key]
            or io_delta[key] != after_io[key] - before_io[key]
        ):
            raise ContractError(f"{field}.io_delta is inconsistent")
    for key in ("syscr", "syscw"):
        if after_io[key] < before_io[key]:
            raise ContractError(f"{field}.proc_io counters decreased")


def aggregate(input_path: Path) -> JsonObject:
    manifest_value, manifest_raw = _load_json_path(
        input_path, MAX_INPUT_BYTES, "aggregate input"
    )
    root = _object(
        manifest_value,
        "aggregate input",
        frozenset({"schema", "campaign_id", "policy", "corpus", "triples"}),
    )
    if root["schema"] != AGGREGATE_INPUT_SCHEMA:
        raise ContractError(f"aggregate input.schema must be {AGGREGATE_INPUT_SCHEMA}")
    campaign_id = _text(root["campaign_id"], "aggregate input.campaign_id")
    policy = _choice(root["policy"], "aggregate input.policy", CACHE_POLICIES)
    manifest_corpus = _parse_corpus(root["corpus"], "aggregate input.corpus")
    triples = _array(root["triples"], "aggregate input.triples", TRIPLE_COUNT)

    records: list[
        tuple[JsonObject, JsonObject, JsonObject, FileRef, FileRef, FileRef, JsonObject]
    ] = []
    previous_observation_end: int | None = None
    for index, value in enumerate(triples):
        refs = _object(
            value,
            f"aggregate input.triples[{index}]",
            frozenset({"trial_input", "pre_receipt", "observation", "post_receipt"}),
        )
        trial_ref = _file_ref(
            refs["trial_input"], f"aggregate input.triples[{index}].trial_input"
        )
        pre_ref = _file_ref(
            refs["pre_receipt"], f"aggregate input.triples[{index}].pre_receipt"
        )
        obs_ref = _file_ref(
            refs["observation"], f"aggregate input.triples[{index}].observation"
        )
        post_ref = _file_ref(
            refs["post_receipt"], f"aggregate input.triples[{index}].post_receipt"
        )
        trial_value, _ = _load_json_ref(trial_ref, f"triple[{index}] trial input")
        trial = _parse_trial_input(trial_value)
        pre_value, pre_raw = _load_json_ref(pre_ref, f"triple[{index}] pre-receipt")
        obs_value, _ = _load_json_ref(obs_ref, f"triple[{index}] observation")
        post_value, _ = _load_json_ref(post_ref, f"triple[{index}] post-receipt")
        pre = _parse_pre(pre_value, f"triple[{index}] pre-receipt")
        observation = _parse_observation(obs_value, f"triple[{index}] observation")
        post = _parse_post(post_value, f"triple[{index}] post-receipt")
        coordinates = _coordinates(pre, f"triple[{index}] pre-receipt")
        if (
            coordinates != _coordinates(trial, f"triple[{index}] trial input")
            or coordinates != _coordinates(observation, f"triple[{index}] observation")
            or coordinates != _coordinates(post, f"triple[{index}] post-receipt")
        ):
            raise ContractError(f"triple[{index}] coordinates disagree")
        expected_pair = index // 2
        expected_position = index % 2
        if (
            coordinates[0] != campaign_id
            or coordinates[1] != policy
            or coordinates[2:4] != (expected_pair, expected_position)
        ):
            raise ContractError(f"triple[{index}] is missing, duplicated, or reordered")
        if coordinates[5] != trial_order(expected_pair)[expected_position]:
            raise ContractError(
                f"triple[{index}] violates the alternating arm schedule"
            )
        if canonical_sha256(trial_value) != observation["input_sha256"]:
            raise ContractError(f"triple[{index}] trial input hash graph is broken")
        if trial["endpoint"] != pre["endpoint"]:
            raise ContractError(f"triple[{index}] trial input endpoint disagrees")
        if trial["corpus"] != pre["corpus"]:
            raise ContractError(f"triple[{index}] trial input corpus disagrees")
        trial_expected = trial["expected"]
        if (
            not _is_object(trial_expected)
            or trial_expected.get("height") != pre["frozen_height"]
            or trial_expected.get("bestblock") != pre["frozen_bestblock"]
        ):
            raise ContractError(f"triple[{index}] trial input frozen tip disagrees")
        if trial["controller_pre_receipt"] != pre_ref:
            raise ContractError(
                f"triple[{index}] trial input pre-receipt ref disagrees"
            )
        if hashlib.sha256(_request_body()).hexdigest() != observation["request_sha256"]:
            raise ContractError(f"triple[{index}] request hash graph is broken")
        pre_digest = hashlib.sha256(pre_raw).hexdigest()
        if (
            observation["controller_declaration_sha256"] != pre_digest
            or post["pre_receipt_sha256"] != pre_digest
        ):
            raise ContractError(f"triple[{index}] pre-receipt hash graph is broken")
        if post["observation_sha256"] != observation["self_sha256"]:
            raise ContractError(f"triple[{index}] observation hash graph is broken")
        if (
            post["attested_pid"] != pre["attested_pid"]
            or post["attested_starttime"] != pre["attested_starttime"]
        ):
            raise ContractError(
                f"triple[{index}] PID/socket lifecycle changed during observation"
            )
        _validate_deltas(pre, post, f"triple[{index}]")
        started = _uint(
            observation["monotonic_start_ns"],
            f"triple[{index}].monotonic_start_ns",
            positive=True,
        )
        ended = _uint(
            observation["monotonic_end_ns"],
            f"triple[{index}].monotonic_end_ns",
            positive=True,
        )
        if previous_observation_end is not None and started < previous_observation_end:
            raise ContractError("observations overlap or are out of schedule order")
        previous_observation_end = ended
        eviction = pre["eviction_procedure"]
        execution = post["eviction_execution"]
        if policy == "process-cold/page-cache-evicted":
            if not isinstance(eviction, FileRef) or not _is_object(execution):
                raise ContractError(
                    f"triple[{index}] lacks page-cache eviction evidence"
                )
            _verify_file(eviction, f"triple[{index}] eviction procedure")
            if execution["procedure_sha256"] != eviction.sha256:
                raise ContractError(
                    f"triple[{index}] eviction execution does not bind its procedure"
                )
            executed_ns = _uint(
                execution["monotonic_ns"],
                f"triple[{index}].eviction_execution.monotonic_ns",
                positive=True,
            )
            if executed_ns >= started:
                raise ContractError(
                    f"triple[{index}] eviction did not precede the observation"
                )
        elif eviction is not None or execution is not None:
            raise ContractError(
                f"triple[{index}] has eviction evidence under the wrong policy"
            )
        records.append(
            (pre, observation, post, pre_ref, post_ref, trial_ref, trial_value)
        )

    arms: dict[str, JsonObject] = {}
    lifecycles: dict[str, list[tuple[int, int]]] = {}
    endpoints: dict[str, str] = {}
    reference_state: tuple[object, ...] | None = None
    frozen_state: JsonObject | None = None
    durations: dict[str, list[int]] = {}
    result_triples: list[JsonObject] = []
    corpus_reference: tuple[object, ...] | None = None

    for index, (
        pre,
        observation,
        post,
        pre_ref,
        post_ref,
        trial_ref,
        _trial_value,
    ) in enumerate(records):
        arm_id = _text(pre["arm_id"], f"triple[{index}].arm_id")
        executable = pre["executable"]
        config = pre["config"]
        corpus = pre["corpus"]
        if (
            not isinstance(executable, FileRef)
            or not isinstance(config, FileRef)
            or not _is_object(corpus)
        ):
            raise ContractError(f"triple[{index}] custody evidence is malformed")
        corpus_file = corpus["file"]
        if not isinstance(corpus_file, FileRef):
            raise ContractError(f"triple[{index}] corpus FileRef is malformed")
        _verify_file(executable, f"triple[{index}] executable", MAX_RESPONSE_BYTES)
        _verify_file(config, f"triple[{index}] config", MAX_RESPONSE_BYTES)
        _verify_file(corpus_file, f"triple[{index}] corpus", MAX_RESPONSE_BYTES)
        corpus_key = (
            corpus["identity"],
            corpus_file,
            corpus["height"],
            corpus["bestblock"],
        )
        if corpus_reference is None:
            corpus_reference = corpus_key
        elif corpus_key != corpus_reference:
            raise ContractError("corpus identity differs across observations")
        manifest_file = manifest_corpus["file"]
        if not isinstance(manifest_file, FileRef):
            raise ContractError("aggregate input corpus FileRef is malformed")
        manifest_key = (
            manifest_corpus["identity"],
            manifest_file,
            manifest_corpus["height"],
            manifest_corpus["bestblock"],
        )
        if corpus_key != manifest_key:
            raise ContractError("receipt corpus does not match aggregate input")
        if (
            pre["frozen_height"] != corpus["height"]
            or pre["frozen_bestblock"] != corpus["bestblock"]
        ):
            raise ContractError(
                f"triple[{index}] frozen coordinates disagree with corpus"
            )
        arm_record = {
            "arm_id": arm_id,
            "arm_kind": pre["arm_kind"],
            "executable_sha256": executable.sha256,
            "config_sha256": config.sha256,
            "backend": pre["backend"],
        }
        if arm_id in arms and arms[arm_id] != arm_record:
            raise ContractError("an arm's custody changed during the campaign")
        arms[arm_id] = arm_record
        endpoint = _text(pre["endpoint"], f"triple[{index}].endpoint")
        if arm_id in endpoints and endpoints[arm_id] != endpoint:
            raise ContractError("an arm's endpoint changed during the campaign")
        endpoints[arm_id] = endpoint
        lifecycles.setdefault(arm_id, []).append(
            (
                _uint(
                    pre["attested_pid"], f"triple[{index}].attested_pid", positive=True
                ),
                _uint(
                    pre["attested_starttime"],
                    f"triple[{index}].attested_starttime",
                    positive=True,
                ),
            )
        )
        state = observation["state"]
        if not isinstance(state, UtxoState):
            raise ContractError(f"triple[{index}] state is malformed")
        state_key = _state_key(state)
        if reference_state is None:
            reference_state = state_key
            frozen_state = _state_json(state)
        elif state_key != reference_state:
            raise ContractError("UTXO state changed or diverged during the campaign")
        durations.setdefault(arm_id, []).append(
            _uint(
                observation["duration_ns"],
                f"triple[{index}].duration_ns",
                positive=True,
            )
        )
        result_triples.append(
            {
                "pair_index": pre["pair_index"],
                "position": pre["position"],
                "arm_id": arm_id,
                "order": index,
                "input_sha256": observation["input_sha256"],
                "trial_input_sha256": trial_ref.sha256,
                "controller_declaration_sha256": observation[
                    "controller_declaration_sha256"
                ],
                "observation_self_sha256": observation["self_sha256"],
                "pre_receipt_sha256": pre_ref.sha256,
                "post_receipt_sha256": post_ref.sha256,
                "duration_ns": observation["duration_ns"],
                "faults_delta": post["faults_delta"],
                "io_delta": post["io_delta"],
            }
        )

    if len(arms) != 2 or {arm["arm_kind"] for arm in arms.values()} != {
        "core",
        "bitcoin-rs",
    }:
        raise ContractError("campaign must contain exactly one arm of each kind")
    if len(set(endpoints.values())) != 2:
        raise ContractError("arms must use distinct endpoints")
    if policy == "warm":
        for identities in lifecycles.values():
            if len(set(identities)) != 1:
                raise ContractError(
                    "warm policy requires a stable PID/starttime per arm"
                )
        if len({identities[0] for identities in lifecycles.values()}) != len(
            lifecycles
        ):
            raise ContractError(
                "warm policy requires distinct PID/starttime identities between arms"
            )
    else:
        all_identities = [
            identity for identities in lifecycles.values() for identity in identities
        ]
        if len(set(all_identities)) != TRIPLE_COUNT:
            raise ContractError(
                "process-cold policy requires a fresh PID/starttime per observation"
            )

    statistics = {arm_id: _stats(samples) for arm_id, samples in durations.items()}
    p50 = {arm_id: values["p50_ns"] for arm_id, values in statistics.items()}
    fastest = min(p50.values())
    winners = [arm_id for arm_id, value in p50.items() if value == fastest]
    faster_arm = winners[0] if len(winners) == 1 else None
    manifest_file = manifest_corpus["file"]
    if frozen_state is None or not isinstance(manifest_file, FileRef):
        raise ContractError("campaign contains no usable observations")
    result: JsonObject = {
        "schema": RESULT_SCHEMA,
        "campaign_id": campaign_id,
        "policy": policy,
        "query": {"method": RPC_METHOD, "params": list(RPC_PARAMS), "use_index": False},
        "corpus": {
            "identity": manifest_corpus["identity"],
            "sha256": manifest_file.sha256,
            "bytes": manifest_file.size,
            "height": manifest_corpus["height"],
            "bestblock": manifest_corpus["bestblock"],
        },
        "arms": sorted(arms.values(), key=lambda arm: str(arm["arm_kind"])),
        "frozen_state": frozen_state,
        "triples": result_triples,
        "statistics": statistics,
        "verdict": {
            "metric": "nearest_rank_p50_ns",
            "outcome": "faster_arm" if faster_arm is not None else "tie",
            "faster_arm": faster_arm,
        },
        "config_sha256": hashlib.sha256(manifest_raw).hexdigest(),
    }
    result["result_sha256"] = canonical_sha256(result)
    return result


@dataclass(frozen=True)
class ArmSpec:
    kind: str
    arm_id: str
    binary: Path
    binary_sha256: str
    command: tuple[str, ...]
    backend: str
    config: FileRef
    datadir: Path


@dataclass(frozen=True)
class CampaignConfig:
    campaign_id: str
    policy: str
    corpus: JsonObject
    expected: JsonObject
    timeout_seconds: Decimal
    max_response_bytes: int
    credential_file: FileRef
    affinity: str
    core: ArmSpec
    candidate: ArmSpec
    eviction_procedure: FileRef | None


def _command(value: object, field: str) -> tuple[str, ...]:
    items = _array(value, field)
    if not items or len(items) > MAX_COMMAND_ARGS:
        raise ContractError(f"{field} must contain 1..{MAX_COMMAND_ARGS} arguments")
    command = tuple(_text(item, f"{field}[{index}]") for index, item in enumerate(items))
    if command[0] != "{binary}":
        raise ContractError(f"{field}[0] must be {{binary}}")
    if "{config}" not in command:
        raise ContractError(f"{field} must include {{config}}")
    for part in command:
        if "{" in part and part not in _CAMPAIGN_PLACEHOLDERS:
            raise ContractError(f"{field} contains an unsupported placeholder")
    return command


def _parse_arm(value: object, field: str, kind: str) -> ArmSpec:
    item = _object(
        value,
        field,
        frozenset(
            {
                "arm_id",
                "binary",
                "binary_sha256",
                "command",
                "backend",
                "config",
                "datadir",
            }
        ),
    )
    backend = _text(item["backend"], f"{field}.backend")
    allowed = {CORE_BACKEND} if kind == "core" else BITCOIN_RS_BACKENDS
    if backend not in allowed:
        raise ContractError(f"{field}.backend must be one of {sorted(allowed)}")
    return ArmSpec(
        kind,
        _text(item["arm_id"], f"{field}.arm_id"),
        _path(item["binary"], f"{field}.binary"),
        _hash(item["binary_sha256"], f"{field}.binary_sha256"),
        _command(item["command"], f"{field}.command"),
        backend,
        _file_ref(item["config"], f"{field}.config"),
        _path(item["datadir"], f"{field}.datadir"),
    )


def _parse_campaign_config(value: object) -> CampaignConfig:
    item = _object(
        value,
        "campaign config",
        frozenset(
            {
                "schema",
                "campaign_id",
                "policy",
                "corpus",
                "expected",
                "timeout_seconds",
                "max_response_bytes",
                "credential_file",
                "affinity",
                "core",
                "candidate",
                "eviction_procedure",
            }
        ),
    )
    if item["schema"] != CAMPAIGN_CONFIG_SCHEMA:
        raise ContractError(f"campaign config.schema must be {CAMPAIGN_CONFIG_SCHEMA}")
    policy = _choice(item["policy"], "campaign config.policy", CACHE_POLICIES)
    timeout = _decimal(
        item["timeout_seconds"], "campaign config.timeout_seconds", positive=True
    )
    if timeout > 300:
        raise ContractError("campaign config.timeout_seconds must not exceed 300")
    max_bytes = _uint(
        item["max_response_bytes"], "campaign config.max_response_bytes", positive=True
    )
    if max_bytes > MAX_RESPONSE_BYTES:
        raise ContractError(
            f"campaign config.max_response_bytes must not exceed {MAX_RESPONSE_BYTES}"
        )
    expected = _object(
        item["expected"], "campaign config.expected", frozenset({"height", "bestblock"})
    )
    eviction_value = item["eviction_procedure"]
    eviction = (
        None
        if eviction_value is None
        else _file_ref(eviction_value, "campaign config.eviction_procedure")
    )
    if (policy == "process-cold/page-cache-evicted") != (eviction is not None):
        raise ContractError("campaign config.eviction_procedure is wrong for the policy")
    core = _parse_arm(item["core"], "campaign config.core", "core")
    candidate = _parse_arm(
        item["candidate"], "campaign config.candidate", "bitcoin-rs"
    )
    if core.arm_id == candidate.arm_id:
        raise ContractError("campaign arms must have distinct arm_id values")
    return CampaignConfig(
        _text(item["campaign_id"], "campaign config.campaign_id"),
        policy,
        _parse_corpus(item["corpus"], "campaign config.corpus"),
        {
            "height": _uint(expected["height"], "campaign config.expected.height"),
            "bestblock": _hash(
                expected["bestblock"], "campaign config.expected.bestblock"
            ),
        },
        timeout,
        max_bytes,
        _file_ref(item["credential_file"], "campaign config.credential_file"),
        _text(item["affinity"], "campaign config.affinity"),
        core,
        candidate,
        eviction,
    )


def _ref_json(reference: FileRef) -> JsonObject:
    return {
        "path": str(reference.path),
        "sha256": reference.sha256,
        "bytes": reference.size,
    }


def _file_ref_from_path(path: Path, cap: int, field: str) -> FileRef:
    raw = _read_regular_file(path, cap, field)
    return FileRef(path, hashlib.sha256(raw).hexdigest(), len(raw))


def _write_json(
    path: Path, record: JsonObject, cap: int = MAX_RECEIPT_BYTES
) -> FileRef:
    _write_record(path, record)
    return _file_ref_from_path(path, cap, str(path))


def _allocate_distinct_loopback_ports(count: int) -> tuple[int, ...]:
    held: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            held.append(sock)
        ports = tuple(int(sock.getsockname()[1]) for sock in held)
        if len(set(ports)) != count or any(port <= 0 for port in ports):
            raise ContractError("could not allocate distinct loopback RPC ports")
        return ports
    finally:
        for sock in held:
            sock.close()


def _loopback_endpoint(host: str, port: int) -> tuple[Path, str]:
    if host == "127.0.0.1":
        return Path("/proc/net/tcp"), f"{_LOOPBACK_V4}:{port:04X}"
    if host == "::1":
        return Path("/proc/net/tcp6"), f"{_LOOPBACK_V6}:{port:04X}"
    raise ContractError("RPC peer is not loopback")


def _tcp_inodes(
    table: Path, local: str, remote: str | None, state: int
) -> set[int]:
    inodes: set[int] = set()
    try:
        text = table.read_text()
    except OSError as error:
        raise ContractError(f"cannot read {table}") from error
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        if fields[1].upper() != local:
            continue
        if remote is not None and fields[2].upper() != remote:
            continue
        try:
            if int(fields[3], 16) != state:
                continue
            inode = int(fields[9])
        except ValueError as error:
            raise ContractError(f"{table} is unparsable") from error
        if inode == 0:
            continue
        inodes.add(inode)
    return inodes


def _listen_inodes(port: int) -> set[int]:
    table, local = _loopback_endpoint("127.0.0.1", port)
    return _tcp_inodes(table, local, None, _TCP_LISTEN)


def _established_inodes(host: str, server_port: int, client_port: int) -> set[int]:
    table, local = _loopback_endpoint(host, server_port)
    _, remote = _loopback_endpoint(host, client_port)
    return _tcp_inodes(table, local, remote, _TCP_ESTABLISHED)


def _pid_owns_inode(pid: int, inode: int) -> bool:
    want = f"socket:[{inode}]"
    try:
        names = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return False
    for name in names:
        try:
            if os.readlink(f"/proc/{pid}/fd/{name}") == want:
                return True
        except OSError:
            continue
    return False


def _endpoint_owned_by(pid: int, port: int) -> None:
    inodes = _listen_inodes(port)
    if len(inodes) != 1:
        raise ContractError("RPC port does not have exactly one loopback listener")
    if not _pid_owns_inode(pid, next(iter(inodes))):
        raise ContractError("RPC endpoint is not owned by the arm process")


def _require_peer_owned(
    connection: socket.socket,
    host: str,
    server_port: int,
    pid: int,
    starttime: int,
    deadline_ns: int,
) -> None:
    while True:
        if _read_starttime(pid) != starttime:
            raise ContractError("arm process identity changed")
        try:
            client_port = int(connection.getsockname()[1])
        except (OSError, TypeError, ValueError) as error:
            raise ContractError("RPC connection has no local port") from error
        inodes = _established_inodes(host, server_port, client_port)
        if len(inodes) > 1:
            raise ContractError("RPC connection is not unique")
        if len(inodes) == 1:
            if not _pid_owns_inode(pid, next(iter(inodes))):
                raise ContractError("RPC connection is not owned by the arm process")
            return
        if time.perf_counter_ns() >= deadline_ns:
            raise ContractError("RPC connection was never owned by the arm process")
        time.sleep(0.001)


def _wait_owned_endpoint(
    process: subprocess.Popen[bytes], port: int, deadline_ns: int
) -> None:
    while True:
        if process.poll() is not None:
            raise ContractError("arm process exited before RPC was ready")
        remaining = deadline_ns - time.perf_counter_ns()
        if remaining <= 0:
            raise ContractError("arm RPC endpoint never became ready")
        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=min(0.05, remaining / 1_000_000_000)
            ):
                _endpoint_owned_by(process.pid, port)
                return
        except OSError:
            time.sleep(0.01)


def _read_starttime(pid: int) -> int:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError as error:
        raise ContractError("cannot read arm /proc/pid/stat") from error
    fields = text.rpartition(")")[2].split()
    if len(fields) < 20:
        raise ContractError("arm /proc/pid/stat is truncated")
    try:
        return int(fields[19])
    except ValueError as error:
        raise ContractError("arm /proc/pid/stat is unparsable") from error


def _read_proc_faults(pid: int) -> JsonObject:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError as error:
        raise ContractError("cannot read arm /proc/pid/stat") from error
    fields = text.rpartition(")")[2].split()
    if len(fields) < 10:
        raise ContractError("arm /proc/pid/stat is truncated")
    try:
        return {"minflt": int(fields[7]), "majflt": int(fields[9])}
    except ValueError as error:
        raise ContractError("arm /proc/pid/stat is unparsable") from error


def _read_proc_io(pid: int) -> JsonObject:
    try:
        text = Path(f"/proc/{pid}/io").read_text()
    except OSError as error:
        raise ContractError("cannot read arm /proc/pid/io") from error
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if not separator:
            continue
        if name in {"rchar", "read_bytes", "wchar", "write_bytes", "syscr", "syscw"}:
            try:
                values[name] = int(raw.strip())
            except ValueError as error:
                raise ContractError("arm /proc/pid/io is unparsable") from error
    required = {"rchar", "read_bytes", "wchar", "write_bytes", "syscr", "syscw"}
    if set(values) != required:
        raise ContractError("arm /proc/pid/io is missing counters")
    return {key: values[key] for key in sorted(required)}


def _copy_pinned_file(
    source: Path,
    expected: str,
    destination: Path,
    *,
    cap: int,
    mode: int,
    field: str,
) -> Path:
    """Copy pinned bytes onto a new workspace path.

    The commit point is ``fsync`` of the destination fd, then ``chmod``.
    The parent directory is not fsynced: this is a campaign workspace
    artifact, not a published result. ``O_EXCL`` refuses a destination
    that already exists. Hash mismatch and any I/O failure after create
    unlink the destination and raise ``ContractError``; those failures
    are not retried here. ``run_campaign`` owns the workspace and does
    not retry a failed copy. Spawn re-hashes the copy before exec.
    """
    created = False
    try:
        descriptor = os.open(
            source,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise ContractError(f"cannot open {field}") from error
    digest = hashlib.sha256()
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError(f"{field} must be a regular file")
        if info.st_size > cap:
            raise ContractError(f"{field} exceeds the size cap")
        target_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            mode,
        )
        created = True
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
        if created:
            destination.unlink(missing_ok=True)
        raise ContractError(f"cannot copy {field}") from error
    finally:
        os.close(descriptor)
    if digest.hexdigest() != expected:
        destination.unlink(missing_ok=True)
        raise ContractError(f"{field} SHA-256 does not match its pin")
    try:
        destination.chmod(mode)
    except OSError as error:
        destination.unlink(missing_ok=True)
        raise ContractError(f"cannot copy {field}") from error
    return destination


def _verify_binary_copy(source: Path, expected: str, destination: Path) -> Path:
    return _copy_pinned_file(
        source,
        expected,
        destination,
        cap=MAX_BINARY_BYTES,
        mode=0o500,
        field="arm binary",
    )


def _open_verified_inode(path: Path, expected: str, cap: int, field: str) -> int:
    """Return a sealed, non-CLOEXEC fd containing the verified file bytes."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        source = os.open(path, flags)
    except OSError as error:
        raise ContractError(f"cannot open {field}") from error
    snapshot = -1
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{field} must be a regular file")
        raw = _read_fd(source, before.st_size, cap, field)
        after = os.fstat(source)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise ContractError(f"{field} changed while being read")
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ContractError(f"{field} changed after its verified copy")
        try:
            snapshot = os.memfd_create(f"verified-{field}", os.MFD_ALLOW_SEALING)
            written = 0
            while written < len(raw):
                written += os.write(snapshot, raw[written:])
            fcntl.fcntl(
                snapshot,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SEAL,
            )
        except (AttributeError, OSError) as error:
            raise ContractError(f"cannot create sealed {field}") from error
        return snapshot
    except Exception:
        if snapshot >= 0:
            os.close(snapshot)
        raise
    finally:
        os.close(source)


def _expand_command(
    template: tuple[str, ...],
    *,
    binary: Path,
    config: Path,
    data_dir: Path,
    port: int,
    cookie: Path,
) -> list[str]:
    replacements = {
        "{binary}": str(binary),
        "{config}": str(config),
        "{data_dir}": str(data_dir),
        "{rpc_port}": str(port),
        "{rpc_bind}": "127.0.0.1",
        "{cookie}": str(cookie),
    }
    return [replacements.get(part, part) for part in template]


class _ArmProcess:
    """One owned RPC arm: a single child, one loopback port, one identity."""

    def __init__(
        self,
        spec: ArmSpec,
        binary: Path,
        config: Path,
        cookie: Path,
        port: int,
        credentials: tuple[str, str],
        timeout: Decimal,
        max_bytes: int,
        expected_height: int,
        expected_hash: str,
    ) -> None:
        self.spec = spec
        self.binary = binary
        self.config = config
        self.cookie = cookie
        self.port = port
        self.endpoint = f"http://127.0.0.1:{port}/"
        self._credentials = credentials
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._expected_height = expected_height
        self._expected_hash = expected_hash
        self._process: subprocess.Popen[bytes] | None = None
        self._pid: int | None = None
        self._starttime: int | None = None
        self._warmed = False

    def spawn(self) -> None:
        if self._process is not None:
            raise ContractError(f"{self.spec.kind} process is already running")
        self.spec.datadir.mkdir(parents=True, exist_ok=True)
        binary_fd = _open_verified_inode(
            self.binary, self.spec.binary_sha256, MAX_BINARY_BYTES, "arm binary copy"
        )
        try:
            config_fd = _open_verified_inode(
                self.config,
                self.spec.config.sha256,
                MAX_RECEIPT_BYTES,
                "arm config copy",
            )
            try:
                argv = _expand_command(
                    self.spec.command,
                    binary=Path(f"/proc/self/fd/{binary_fd}"),
                    config=Path(f"/proc/self/fd/{config_fd}"),
                    data_dir=self.spec.datadir,
                    port=self.port,
                    cookie=self.cookie,
                )
                self._process = subprocess.Popen(
                    argv,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(binary_fd, config_fd),
                )
            finally:
                os.close(config_fd)
        except OSError as error:
            raise ContractError(f"cannot spawn {self.spec.kind} process") from error
        finally:
            os.close(binary_fd)
        self._pid = self._process.pid
        _wait_owned_endpoint(
            self._process, self.port, time.perf_counter_ns() + ARM_READY_TIMEOUT_NS
        )
        self._starttime = _read_starttime(self._pid)
        self._warmed = False

    def require_endpoint(self) -> None:
        if self._process is None or self._pid is None:
            raise ContractError(f"{self.spec.kind} process is not running")
        if self._process.poll() is not None:
            raise ContractError(f"{self.spec.kind} process exited")
        self.identity()
        _endpoint_owned_by(self._pid, self.port)

    def ensure(self, policy: str) -> None:
        if policy == "warm":
            if self._process is None:
                self.spawn()
                self.warm()
            return
        self.terminate()
        self.spawn()

    def warm(self) -> None:
        if self._warmed:
            return
        self.require_endpoint()
        pid, starttime = self.identity()
        _rpc_once(
            self.endpoint,
            self._credentials,
            self._timeout,
            self._max_bytes,
            self._expected_height,
            self._expected_hash,
            pid,
            starttime,
        )
        self._warmed = True

    def identity(self) -> tuple[int, int]:
        if self._pid is None or self._starttime is None:
            raise ContractError(f"{self.spec.kind} process has no attested identity")
        if _read_starttime(self._pid) != self._starttime:
            raise ContractError(f"{self.spec.kind} process identity changed")
        return self._pid, self._starttime

    def snapshot(self) -> tuple[JsonObject, JsonObject]:
        pid, _ = self.identity()
        return _read_proc_faults(pid), _read_proc_io(pid)

    def terminate(self) -> None:
        process = self._process
        if process is None:
            self._pid = None
            self._starttime = None
            self._warmed = False
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            process.wait(timeout=CHILD_TERMINATE_GRACE_NS / 1_000_000_000)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=CHILD_KILL_REAP_NS / 1_000_000_000)
            except subprocess.TimeoutExpired as error:
                raise ContractError(
                    f"{self.spec.kind} process resisted campaign cleanup"
                ) from error
        self._process = None
        self._pid = None
        self._starttime = None
        self._warmed = False


def _run_eviction(procedure: FileRef) -> JsonObject:
    _verify_file(procedure, "eviction procedure")
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            [str(procedure.path)],
            check=False,
            capture_output=True,
            timeout=CHILD_TERMINATE_GRACE_NS / 1_000_000_000,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ContractError("eviction procedure could not be executed") from error
    if completed.returncode != 0:
        raise ContractError("eviction procedure did not succeed")
    return {
        "procedure_sha256": procedure.sha256,
        "exit_status": 0,
        "monotonic_ns": started,
    }


def _delta_map(before: JsonObject, after: JsonObject, keys: tuple[str, ...]) -> JsonObject:
    result: JsonObject = {}
    for key in keys:
        start = before[key]
        end = after[key]
        if not isinstance(start, int) or not isinstance(end, int) or end < start:
            raise ContractError("process counters decreased during the observation")
        result[key] = end - start
    return result


def run_campaign(config_path: Path, workspace: Path) -> JsonObject:
    value, _ = _load_json_path(config_path, MAX_INPUT_BYTES, "campaign config")
    config = _parse_campaign_config(value)
    corpus = config.corpus
    corpus_file = corpus["file"]
    if not isinstance(corpus_file, FileRef):
        raise ContractError("campaign config.corpus.file is malformed")
    _verify_file(corpus_file, "campaign config.corpus.file", MAX_RESPONSE_BYTES)
    if (
        config.expected["height"] != corpus["height"]
        or config.expected["bestblock"] != corpus["bestblock"]
    ):
        raise ContractError("campaign expected tip does not match the corpus")
    credentials = _load_credentials(config.credential_file)
    _verify_file(config.core.config, "core config")
    _verify_file(config.candidate.config, "candidate config")

    workspace.mkdir(parents=True, exist_ok=True)
    core_bin = _verify_binary_copy(
        config.core.binary,
        config.core.binary_sha256,
        workspace / "core-node",
    )
    candidate_bin = _verify_binary_copy(
        config.candidate.binary,
        config.candidate.binary_sha256,
        workspace / "candidate-node",
    )
    core_config = _copy_pinned_file(
        config.core.config.path,
        config.core.config.sha256,
        workspace / "core-config",
        cap=MAX_RECEIPT_BYTES,
        mode=0o400,
        field="core config",
    )
    candidate_config = _copy_pinned_file(
        config.candidate.config.path,
        config.candidate.config.sha256,
        workspace / "candidate-config",
        cap=MAX_RECEIPT_BYTES,
        mode=0o400,
        field="candidate config",
    )
    expected_height = _uint(config.expected["height"], "campaign expected.height")
    expected_hash = _hash(config.expected["bestblock"], "campaign expected.bestblock")
    core_port, candidate_port = _allocate_distinct_loopback_ports(2)
    arms = {
        "core": _ArmProcess(
            config.core,
            core_bin,
            core_config,
            config.credential_file.path,
            core_port,
            credentials,
            config.timeout_seconds,
            config.max_response_bytes,
            expected_height,
            expected_hash,
        ),
        "bitcoin-rs": _ArmProcess(
            config.candidate,
            candidate_bin,
            candidate_config,
            config.credential_file.path,
            candidate_port,
            credentials,
            config.timeout_seconds,
            config.max_response_bytes,
            expected_height,
            expected_hash,
        ),
    }
    executable_refs = {
        "core": _file_ref_from_path(core_bin, MAX_BINARY_BYTES, "core binary copy"),
        "bitcoin-rs": _file_ref_from_path(
            candidate_bin, MAX_BINARY_BYTES, "candidate binary copy"
        ),
    }
    triples: list[JsonObject] = []
    try:
        if config.policy == "warm":
            for arm in arms.values():
                arm.ensure(config.policy)
        for index in range(TRIPLE_COUNT):
            pair = index // 2
            position = index % 2
            kind = trial_order(pair)[position]
            arm = arms[kind]
            spec = arm.spec
            eviction_execution: JsonObject | None = None
            if config.policy == "process-cold/page-cache-evicted":
                if config.eviction_procedure is None:
                    raise ContractError("eviction policy is missing its procedure")
                eviction_execution = _run_eviction(config.eviction_procedure)
            arm.ensure(config.policy)
            arm.require_endpoint()
            pid, starttime = arm.identity()
            proc_stat_before, proc_io_before = arm.snapshot()
            prefix = f"{index:02d}-{kind}"
            coordinates: JsonObject = {
                "campaign_id": config.campaign_id,
                "policy": config.policy,
                "pair_index": pair,
                "position": position,
                "arm_id": spec.arm_id,
                "arm_kind": kind,
            }
            pre_record: JsonObject = {
                **coordinates,
                "schema": PRE_RECEIPT_SCHEMA,
                "executable": _ref_json(executable_refs[kind]),
                "config": _ref_json(spec.config),
                "corpus": {
                    "identity": corpus["identity"],
                    "file": _ref_json(corpus_file),
                    "height": corpus["height"],
                    "bestblock": corpus["bestblock"],
                },
                "backend": spec.backend,
                "datadir": str(spec.datadir),
                "endpoint": arm.endpoint,
                "attested_pid": pid,
                "attested_starttime": starttime,
                "affinity": config.affinity,
                "cache_policy_action": CACHE_POLICY_ACTIONS[config.policy],
                "eviction_procedure": (
                    None
                    if config.eviction_procedure is None
                    else _ref_json(config.eviction_procedure)
                ),
                "frozen_height": expected_height,
                "frozen_bestblock": expected_hash,
                "proc_stat_before": proc_stat_before,
                "proc_io_before": proc_io_before,
                "operator_trust_boundary": OPERATOR_TRUST_BOUNDARY,
            }
            pre_ref = _write_json(workspace / f"{prefix}-pre.json", pre_record)
            trial_record: JsonObject = {
                **coordinates,
                "schema": TRIAL_INPUT_SCHEMA,
                "endpoint": arm.endpoint,
                "credential_file": _ref_json(config.credential_file),
                "timeout_seconds": config.timeout_seconds,
                "max_response_bytes": config.max_response_bytes,
                "corpus": {
                    "identity": corpus["identity"],
                    "file": _ref_json(corpus_file),
                    "height": corpus["height"],
                    "bestblock": corpus["bestblock"],
                },
                "expected": {
                    "height": expected_height,
                    "bestblock": expected_hash,
                },
                "controller_pre_receipt": _ref_json(pre_ref),
            }
            trial_ref = _write_json(workspace / f"{prefix}-trial.json", trial_record)
            observation = run_trial(trial_ref.path)
            obs_ref = _write_json(
                workspace / f"{prefix}-obs.json", observation, MAX_RESPONSE_BYTES
            )
            proc_stat_after, proc_io_after = arm.snapshot()
            post_record: JsonObject = {
                **coordinates,
                "schema": POST_RECEIPT_SCHEMA,
                "pre_receipt_sha256": pre_ref.sha256,
                "observation_sha256": observation["self_sha256"],
                "attested_pid": pid,
                "attested_starttime": starttime,
                "proc_stat_after": proc_stat_after,
                "proc_io_after": proc_io_after,
                "faults_delta": _delta_map(
                    proc_stat_before, proc_stat_after, ("minflt", "majflt")
                ),
                "io_delta": _delta_map(
                    proc_io_before,
                    proc_io_after,
                    ("rchar", "read_bytes", "wchar", "write_bytes"),
                ),
                "eviction_execution": eviction_execution,
            }
            post_ref = _write_json(workspace / f"{prefix}-post.json", post_record)
            triples.append(
                {
                    "trial_input": _ref_json(trial_ref),
                    "pre_receipt": _ref_json(pre_ref),
                    "observation": _ref_json(obs_ref),
                    "post_receipt": _ref_json(post_ref),
                }
            )
            if config.policy != "warm":
                arm.terminate()
    finally:
        for arm in arms.values():
            arm.terminate()

    manifest: JsonObject = {
        "schema": AGGREGATE_INPUT_SCHEMA,
        "campaign_id": config.campaign_id,
        "policy": config.policy,
        "corpus": {
            "identity": corpus["identity"],
            "file": _ref_json(corpus_file),
            "height": corpus["height"],
            "bestblock": corpus["bestblock"],
        },
        "triples": triples,
    }
    manifest_ref = _write_json(workspace / "aggregate.json", manifest)
    return aggregate(manifest_ref.path)


def _link_tmpfile(fd: int, dir_fd: int, name: str) -> None:
    # linkat with AT_EMPTY_PATH publishes the anonymous O_TMPFILE inode
    # itself. A pathname-based link would re-resolve a replaceable name
    # and let an attacker swap the bytes between write and link.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.linkat.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    if libc.linkat(fd, b"", dir_fd, name.encode(), _AT_EMPTY_PATH) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise ContractError("output path already exists")
        raise ContractError("publication could not link the result inode")


def _open_trusted_dir(path: Path) -> int:
    # Namespace trust is established component by component: every
    # component is opened with O_NOFOLLOW from the previously opened
    # directory fd, so a rename/rebind anywhere on the chain cannot swap
    # an ancestor after it has been approved. Any group- or other-write
    # bit makes a component untrusted, regardless of who owns it: a shared
    # group is not a trust boundary. The single exception is sticky
    # root-owned semantics, and then only when the component beneath it is
    # owned by the effective user and not writable by group or other.
    raw_parts = path.absolute().parts
    resolved: list[str] = [raw_parts[0]]
    for part in raw_parts[1:]:
        if part == "..":
            if len(resolved) > 1:
                resolved.pop()
        elif part != ".":
            resolved.append(part)
    absolute = Path(*resolved)
    if not absolute.is_absolute() or absolute.parent == absolute:
        raise ContractError("output parent must name a directory")
    walk_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NONBLOCK
    )
    euid = os.geteuid()

    def untrusted_writable(info: os.stat_result) -> bool:
        # Group-write and other-write both let someone who is not the
        # owner rename the next component. Ownership of the directory
        # does not make its group trustworthy.
        return bool(stat.S_IMODE(info.st_mode) & 0o022)

    current = os.open("/", walk_flags)
    try:
        for component in absolute.parts[1:]:
            parent_info = os.fstat(current)
            try:
                child = os.open(component, walk_flags, dir_fd=current)
            except OSError as error:
                raise ContractError(
                    "output parent must be an existing directory"
                ) from error
            child_info = os.fstat(child)
            if untrusted_writable(parent_info):
                sticky_root = (
                    parent_info.st_uid == 0
                    and stat.S_IMODE(parent_info.st_mode) & stat.S_ISVTX
                )
                child_safe = child_info.st_uid == euid and not untrusted_writable(
                    child_info
                )
                if not sticky_root or not child_safe:
                    raise ContractError(
                        "output ancestor must not allow untrusted renames"
                    )
            os.close(current)
            current = child
        final_info = os.fstat(current)
        if final_info.st_uid != euid or untrusted_writable(final_info):
            raise ContractError(
                "output parent must be owned by the current user and "
                "not writable by untrusted users"
            )
        return current
    except BaseException:
        os.close(current)
        raise


def _unlink_published(dir_fd: int, name: str, published: os.stat_result) -> None:
    # Roll back only the inode this process linked: the held directory fd
    # is addressed with no symlink following, and the visible inode must
    # still be the linked one. A rename, a replacement, or a hostile
    # symlink at the name is left exactly as found.
    try:
        visible = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        # The name is gone or unreachable, so there is nothing
        # comparator-owned left to remove.
        return
    if (visible.st_dev, visible.st_ino) != (published.st_dev, published.st_ino):
        # The name no longer identifies the linked inode: never remove a
        # substituted artifact.
        return
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        # Rollback could not complete; the primary failure is still
        # reported and the surviving artifact stays visible rather than
        # being half-removed behind a masked error.
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        # Durability of the rollback itself is best effort and must not
        # mask the primary publication failure.
        return


def _publish_result(path: Path, payload: bytes) -> None:
    # The result is written to an anonymous O_TMPFILE inode in a held,
    # trusted output directory and linked into place with linkat
    # AT_EMPTY_PATH. No substitutable temporary name ever exists, the fd
    # stays open until after the link, and the parent namespace identity
    # is re-established immediately before the link so a rename/rebind of
    # the requested pathname cannot yield a success the caller cannot see.
    if path.name == str(path) or path.parent == path:
        raise ContractError("output path must name a file inside a directory")
    dir_fd = _open_trusted_dir(path.parent)
    try:
        tmpfile_flags = (
            os.O_WRONLY | getattr(os, "O_TMPFILE", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        if not tmpfile_flags & getattr(os, "O_TMPFILE", 0):
            raise ContractError("publication requires O_TMPFILE support")
        try:
            temp_fd = os.open(".", tmpfile_flags, 0o600, dir_fd=dir_fd)
        except OSError as error:
            raise ContractError(
                "publication requires O_TMPFILE support on the output filesystem"
            ) from error
        try:
            written = os.write(temp_fd, payload)
            if written != len(payload):
                raise OSError(f"short result write: {written} of {len(payload)} bytes")
            os.fsync(temp_fd)
            # Re-establish the requested parent's namespace identity: the
            # held dirfd must still be the directory the caller named.
            verify_fd = _open_trusted_dir(path.parent)
            try:
                held = os.fstat(dir_fd)
                current = os.fstat(verify_fd)
                if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                    raise ContractError("output parent changed during publication")
            finally:
                os.close(verify_fd)
            _link_tmpfile(temp_fd, dir_fd, path.name)
            published = os.fstat(temp_fd)
            try:
                final = os.stat(path.name, dir_fd=dir_fd)
                if (final.st_dev, final.st_ino) != (
                    published.st_dev,
                    published.st_ino,
                ):
                    raise ContractError("published inode does not match the result fd")
                os.fsync(dir_fd)
            except BaseException:
                # Any failure after the link leaves a receipt-shaped name
                # behind unless it is rolled back; remove only the linked
                # inode and re-raise the primary failure.
                _unlink_published(dir_fd, path.name, published)
                raise
        finally:
            os.close(temp_fd)
    finally:
        os.close(dir_fd)


def _write_record(path: Path, record: JsonObject) -> None:
    _publish_result(path, canonical_json_bytes(record) + b"\n")


def _die(message: str) -> int:
    print(f"muhash comparator refused evidence: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("trial", "aggregate"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--input", required=True, type=Path)
        subparser.add_argument("--output", required=True, type=Path)
    campaign = subparsers.add_parser("campaign")
    campaign.add_argument("--input", required=True, type=Path)
    campaign.add_argument("--output", required=True, type=Path)
    campaign.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "trial":
            record = run_trial(args.input)
        elif args.command == "aggregate":
            record = aggregate(args.input)
        else:
            record = run_campaign(args.input, args.workspace)
        _write_record(args.output, record)
    except ComparatorError as error:
        return _die(str(error))
    except OSError as error:
        return _die(f"I/O failure ({error.errno})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
