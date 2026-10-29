# pyright: strict
"""Shared benchmark evidence encoding, validation, and durable publication."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TypedDict, TypeIs

JsonObject = dict[str, object]
MAX_JSON_DEPTH = 32

class ContractError(ValueError):
    """The comparator cannot make a controlled comparison."""


class Summary(TypedDict):
    samples: int
    p50_ns: int
    p95_ns: int
    p99_ns: int
    max_ns: int


def _is_object(value: object) -> TypeIs[JsonObject]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


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
    # ``canonical_bytes`` would recurse into a hostile nest before any limit
    # applies; validate the depth first so oversized input fails closed here.
    _validate_json_depth(result, "result")
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
