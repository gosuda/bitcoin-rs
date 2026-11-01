# pyright: strict
"""Shared benchmark evidence encoding, validation, custody, and publication."""

import ctypes
import errno
import hashlib
import json
import math
import os
import stat
import sys
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from typing import TypedDict, TypeIs

type JsonObject = dict[str, object]
MAX_JSON_DEPTH = 32


class ContractError(ValueError):
    """The comparator cannot make a controlled comparison."""


class Summary(TypedDict):
    samples: int
    p50_ns: int
    p95_ns: int
    p99_ns: int
    max_ns: int


def _is_array(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


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


def _array(value: object, field: str, length: int | None = None) -> list[object]:
    if not _is_array(value):
        raise ContractError(f"{field} must be an array")
    if length is not None and len(value) != length:
        raise ContractError(f"{field} must contain exactly {length} items")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ContractError(f"{field} must be a nonempty NUL-free string")
    return value


def _uint(
    value: object,
    field: str,
    maximum: int = (1 << 63) - 1,
    *,
    positive: bool = False,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise ContractError(f"{field} must be an integer in [0, {maximum}]")
    if positive and value == 0:
        raise ContractError(f"{field} must be positive")
    return value


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _canonical_scalar(value: object) -> str:
    if value is None:
        return "null"
    if value is False:
        return "false"
    if value is True:
        return "true"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonical_float(value)
    if isinstance(value, Decimal):
        return _canonical_decimal(value)
    raise ContractError("value is not canonical JSON")


def _canonical_float(value: float) -> str:
    try:
        return json.dumps(value, allow_nan=False)
    except ValueError as error:
        raise ContractError("value is not canonical JSON") from error


def _canonical_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise ContractError("value is not canonical JSON")
    return _decimal_text(value)


def _canonical_text(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_text(child) for child in value) + "]"
    if _is_object(value):
        fields = (
            f"{_canonical_text(key)}:{_canonical_text(value[key])}"
            for key in sorted(value)
        )
        return "{" + ",".join(fields) + "}"
    return _canonical_scalar(value)


def canonical_bytes(value: object) -> bytes:
    try:
        return _canonical_text(value).encode("ascii")
    except RecursionError as error:
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


def nearest_rank(values: Sequence[int], percentile: float) -> int:
    if not values:
        raise ContractError("cannot summarize an empty sample")
    if not 0 < percentile <= 1:
        raise ContractError("percentile must be in (0, 1]")
    ordered = sorted(values)
    rank = math.ceil(percentile * len(ordered)) - 1
    return ordered[max(0, rank)]


_percentile = nearest_rank


def summarize(values: Sequence[int]) -> Summary:
    return {
        "samples": len(values),
        "p50_ns": nearest_rank(values, 0.50),
        "p95_ns": nearest_rank(values, 0.95),
        "p99_ns": nearest_rank(values, 0.99),
        "max_ns": max(values),
    }


def _parse_start_time(stat_text: str) -> int:
    fields = stat_text.rpartition(")")[2].split()
    if len(fields) < 20:
        raise ContractError("process stat is truncated")
    try:
        start_time = int(fields[19])
    except ValueError as error:
        raise ContractError("process stat is unparsable") from error
    if start_time < 0:
        raise ContractError("process stat is unparsable")
    return start_time


def process_start_time(pid: int) -> int:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError as error:
        raise ContractError(f"cannot read process {pid} stat") from error
    return _parse_start_time(text)


def _open_pinned_source(source: Path) -> int:
    try:
        return os.open(
            source,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise ContractError(f"cannot open pinned source {source}") from error


def _create_pinned_copy(destination: Path, mode: int) -> int:
    try:
        return os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            mode,
        )
    except OSError as error:
        raise ContractError(f"cannot create pinned copy {destination}") from error


def _write_all(target: int, chunk: bytes) -> None:
    written = 0
    while written < len(chunk):
        count = os.write(target, chunk[written:])
        if count <= 0:
            raise OSError(errno.EIO, "short pinned copy write")
        written += count


def _copy_pinned_data(descriptor: int, target: int, digest: hashlib._Hash) -> None:
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        _write_all(target, chunk)


def hash_regular_file(path: Path) -> str:
    """SHA-256 of one regular file read without following a symlink.

    The path is opened with ``O_NOFOLLOW`` and must be a regular file.
    An open failure and any other file type raise ``ContractError``.
    """
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise ContractError(f"cannot open {path}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(f"{path} is not a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return hashlib.file_digest(stream, "sha256").hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def copy_pinned(
    source: Path,
    destination: Path,
    sha256: str,
    mode: int = 0o500,
) -> Path:
    """Copy pinned bytes onto a new path and verify both ends.

    The source is opened with ``O_NOFOLLOW`` and must be a regular file.
    ``O_EXCL`` refuses an existing destination. The digest is computed
    while copying, the destination is re-opened with ``O_NOFOLLOW`` and
    hashed again, and only then is its mode set. A digest mismatch and
    any I/O failure after create unlink the destination and raise
    ``ContractError``; no failure is retried here.
    """
    descriptor = _open_pinned_source(source)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError(f"pinned source {source} must be a regular file")
        target = _create_pinned_copy(destination, mode)
        digest = hashlib.sha256()
        try:
            _copy_pinned_data(descriptor, target, digest)
            os.fchmod(target, mode)
            os.fsync(target)
        except OSError as error:
            destination.unlink(missing_ok=True)
            raise ContractError(f"cannot copy pinned source {source}") from error
        finally:
            os.close(target)
    finally:
        os.close(descriptor)
    if digest.hexdigest() != sha256:
        destination.unlink(missing_ok=True)
        raise ContractError(f"pinned copy of {source} has the wrong SHA-256")
    try:
        observed = hash_regular_file(destination)
    except (OSError, ContractError):
        destination.unlink(missing_ok=True)
        raise
    if observed != sha256:
        destination.unlink(missing_ok=True)
        raise ContractError(f"pinned copy of {source} has the wrong SHA-256")
    return destination


def _link_tmpfile(descriptor: int, directory: int, name: str) -> None:
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
        os.fsencode(name),
        getattr(os, "AT_EMPTY_PATH", 0x1000),
    )
    if linked != 0:
        failure = ctypes.get_errno()
        if failure == errno.EEXIST:
            raise ContractError(f"output already exists: {name}")
        raise ContractError(f"cannot link published result: {os.strerror(failure)}")


def _lexical_absolute(path: Path) -> Path:
    raw_parts = path.absolute().parts
    resolved: list[str] = [raw_parts[0]]
    for part in raw_parts[1:]:
        if part == "..":
            if len(resolved) > 1:
                resolved.pop()
        elif part != ".":
            resolved.append(part)
    return Path(*resolved)


def _walk_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NONBLOCK
    )


def _untrusted_writable(info: os.stat_result) -> bool:
    return bool(stat.S_IMODE(info.st_mode) & 0o022)


def _require_trusted_link(parent: os.stat_result, child: os.stat_result) -> None:
    if not _untrusted_writable(parent):
        return
    sticky_root = (
        parent.st_uid == 0 and stat.S_IMODE(parent.st_mode) & stat.S_ISVTX
    )
    child_safe = child.st_uid == os.geteuid() and not _untrusted_writable(child)
    if not sticky_root or not child_safe:
        raise ContractError("output ancestor must not allow untrusted renames")


def _descend_trusted(current: int, component: str, flags: int) -> int:
    parent_info = os.fstat(current)
    try:
        child = os.open(component, flags, dir_fd=current)
    except OSError as error:
        raise ContractError(
            "output parent must be an existing directory"
        ) from error
    try:
        _require_trusted_link(parent_info, os.fstat(child))
    except BaseException:
        os.close(child)
        raise
    os.close(current)
    return child


def _walk_trusted(path: Path, flags: int) -> int:
    current = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            current = _descend_trusted(current, component, flags)
        return current
    except BaseException:
        os.close(current)
        raise


def _open_trusted_dir(path: Path) -> int:
    absolute = _lexical_absolute(path)
    if not absolute.is_absolute() or absolute.parent == absolute:
        raise ContractError("output parent must name a directory")
    current = _walk_trusted(absolute, _walk_flags())
    try:
        final_info = os.fstat(current)
        if final_info.st_uid != os.geteuid() or _untrusted_writable(final_info):
            raise ContractError(
                "output parent must be owned by the current user and "
                "not writable by untrusted users"
            )
        return current
    except BaseException:
        os.close(current)
        raise


def _unlink_published(directory: int, name: str, published: os.stat_result) -> None:
    try:
        visible = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError:
        return
    if (visible.st_dev, visible.st_ino) != (published.st_dev, published.st_ino):
        return
    try:
        os.unlink(name, dir_fd=directory)
    except OSError:
        return
    try:
        os.fsync(directory)
    except OSError:
        return


def _create_result_tmpfile(directory: int) -> int:
    tmpfile = getattr(os, "O_TMPFILE", 0)
    if not tmpfile:
        raise ContractError("publication requires O_TMPFILE support")
    try:
        descriptor = os.open(
            ".",
            os.O_WRONLY | tmpfile | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory,
        )
    except OSError as error:
        raise ContractError(
            "publication requires O_TMPFILE support on the output filesystem"
        ) from error
    try:
        os.fchmod(descriptor, 0o600)
    except OSError as error:
        os.close(descriptor)
        raise ContractError("cannot pin the result mode") from error
    return descriptor


def _write_result(descriptor: int, payload: bytes) -> None:
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short result write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as error:
        raise ContractError("cannot write the result payload") from error


def _verify_parent(directory: int, parent: Path) -> None:
    verify = _open_trusted_dir(parent)
    try:
        held = os.fstat(directory)
        current = os.fstat(verify)
        if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
            raise ContractError("output parent changed during publication")
    finally:
        os.close(verify)


def _link_and_fsync(descriptor: int, directory: int, name: str) -> None:
    _link_tmpfile(descriptor, directory, name)
    published = os.fstat(descriptor)
    try:
        final = os.stat(name, dir_fd=directory)
        if (final.st_dev, final.st_ino) != (published.st_dev, published.st_ino):
            raise ContractError("published inode does not match the result fd")
        os.fsync(directory)
    except BaseException:
        _unlink_published(directory, name, published)
        raise


def _publish_payload(payload: bytes, output: Path) -> None:
    if output.name == str(output) or output.parent == output:
        raise ContractError("output path must name a file inside a directory")
    directory = _open_trusted_dir(output.parent)
    try:
        descriptor = _create_result_tmpfile(directory)
        try:
            _write_result(descriptor, payload)
            _verify_parent(directory, output.parent)
            _link_and_fsync(descriptor, directory, output.name)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def publish_result(result: JsonObject, output: Path) -> None:
    """Atomically publish one result document.

    Commit point is successful ``linkat(AT_EMPTY_PATH)``. Bytes are written
    to an unnamed ``O_TMPFILE`` inode in a walked, trusted output directory,
    flushed, and fsynced; only then is the inode named. The parent namespace
    identity is re-established immediately before the link, and the
    directory is fsynced after it.

    Crash before the link leaves the destination unchanged. Crash after the
    link surfaces ``EEXIST`` on a retry: the published bytes are the
    committed document and must not be overwritten. A failure after the
    link removes only the inode this process linked. This function does not
    retry; the caller owns retry policy and must choose a new output path.
    """
    if sys.platform != "linux":
        raise ContractError("publication requires Linux O_TMPFILE support")
    _validate_json_depth(result, "result")
    _publish_payload(canonical_bytes(result) + b"\n", output)
