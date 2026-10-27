#!/usr/bin/env python3
"""Deterministic Core-framed campaign corpus exporter, manifest, and census.

Streaming implementation: one block payload and one manifest entry are in
memory at any moment. Archive and metadata sizes never bound resident set;
the entry metadata spool carries one canonical JSON record per block and the
manifest emitter splices it without materializing the entries array.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import re
import struct
import sys
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

HERE = Path(__file__).resolve().parent
PRODUCTS_PATH = HERE / "products.json"

MANIFEST_SCHEMA = "bitcoin-rs-corpus-manifest"
MANIFEST_VERSION = 1
MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
HEADER_LEN = 8
MAX_PAYLOAD = 4_000_000
MIN_HEADER = 80
ZERO_SHA256 = "0" * 64

# Schema-derived token bounds for the manifest reader. Values are accepted in
# any member order, with arbitrary inter-token whitespace and valid JSON
# escapes; scalar spellings must still satisfy their frozen domains.
_ROOT_KEYS = frozenset(
    {
        "archive",
        "corpus_id",
        "entries",
        "genesis_hash",
        "manifest_sha256",
        "network",
        "network_magic",
        "range",
        "schema",
        "source_tip_hash",
        "version",
    }
)
_ARCHIVE_KEYS = frozenset({"sha256", "size"})
_RANGE_KEYS = frozenset({"start_height", "stop_height"})
_ENTRY_KEYS = frozenset({"height", "hash", "offset", "payload_length"})
_MAX_BLOCK_COUNT = 1_000_000
_MAX_ARCHIVE_SIZE = _MAX_BLOCK_COUNT * (HEADER_LEN + MAX_PAYLOAD)
_MAX_INT_DIGITS = len(str(_MAX_ARCHIVE_SIZE))
_HEX = frozenset("0123456789abcdefABCDEF")

INDEX_SCHEMA = "bitcoin-rs-corpus-index-v1"
INDEX_VERSION = 1
_MAX_SOURCES = 10000
_SOURCE_NAME_RE = re.compile(r"blk\d{5}\.dat")
_INDEX_ROOT_KEYS = frozenset(
    {
        "corpus_id",
        "entries",
        "genesis_hash",
        "index_sha256",
        "logical",
        "network",
        "network_magic",
        "range",
        "schema",
        "source_tip_hash",
        "sources",
        "version",
    }
)
_INDEX_SOURCE_KEYS = frozenset({"name", "sha256", "size"})
_INDEX_ENTRY_KEYS = frozenset({"hash", "height", "length", "offset", "source"})
_INDEX_LOGICAL_KEYS = frozenset({"sha256", "size"})

Fetch = Callable[[str], bytes]


class ContractError(ValueError):
    """The archive, manifest, or census violates the campaign corpus contract."""


@dataclass(frozen=True)
class FrameMeta:
    offset: int
    payload_length: int


@dataclass(frozen=True)
class Product:
    corpus_id: str
    stop_height: int
    stop_hash: str
    block_count: int
    census: Mapping[str, object]
    state: Mapping[str, object]


@dataclass(frozen=True)
class Freeze:
    network: str
    network_magic: bytes
    genesis_hash: str
    assume_valid_height: int
    census_specials: tuple[str, ...]
    core_oracle: Mapping[str, object]
    products: dict[str, Product]


@dataclass(frozen=True)
class PrefixFacts:
    """Verified durable-prefix identity of an in-progress corpus run."""

    count: int
    archive_bytes: int
    entries_bytes: int
    last_hash: str | None
    archive_prefix_sha256: str
    entries_prefix_sha256: str


@dataclass(frozen=True)
class CorpusSummary:
    count: int
    archive_size: int
    archive_sha256: str
    manifest_sha256: str
    manifest_file_sha256: str


@dataclass(frozen=True)
class IndexSource:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class IndexEntry:
    height: int
    hash: str
    source: int
    offset: int
    length: int


@dataclass(frozen=True)
class IndexSummary:
    count: int
    logical_size: int
    logical_sha256: str
    index_sha256: str
    index_file_sha256: str


def load_freeze(path: Path = PRODUCTS_PATH) -> Freeze:
    raw = _load_json(path)
    if raw.get("schema") != "bitcoin-rs-campaign-corpora-v1":
        raise ContractError(
            "products.json schema is not bitcoin-rs-campaign-corpora-v1"
        )
    magic = bytes.fromhex(_text(raw["network_magic"], "network_magic"))
    specials = tuple(
        _text(item, "census_specials[]")
        for item in _array(raw["census_specials"], "census_specials")
    )
    validation = _object(raw["validation"], "validation")
    products: dict[str, Product] = {}
    for corpus_id, body in _object(raw["products"], "products").items():
        row = _object(body, f"products.{corpus_id}")
        products[corpus_id] = Product(
            corpus_id=corpus_id,
            stop_height=_u32(row["stop_height"], f"{corpus_id}.stop_height"),
            stop_hash=_hash(_text(row["stop_hash"], f"{corpus_id}.stop_hash")),
            block_count=_u32(row["block_count"], f"{corpus_id}.block_count"),
            census=_object(row["census"], f"{corpus_id}.census"),
            state=_object(row["state"], f"{corpus_id}.state"),
        )
    return Freeze(
        network=_text(raw["network"], "network"),
        network_magic=magic,
        genesis_hash=_hash(_text(raw["genesis_hash"], "genesis_hash")),
        assume_valid_height=_u32(
            validation["assume_valid_height"], "assume_valid_height"
        ),
        census_specials=specials,
        core_oracle=_object(raw["core_oracle"], "core_oracle"),
        products=products,
    )


def product(freeze: Freeze, corpus_id: str) -> Product:
    try:
        return freeze.products[corpus_id]
    except KeyError as error:
        raise ContractError(f"unknown corpus_id {corpus_id!r}") from error


def header_block_hash(payload: bytes) -> str:
    if len(payload) < MIN_HEADER:
        raise ContractError("payload is shorter than a block header")
    digest = hashlib.sha256(hashlib.sha256(payload[:MIN_HEADER]).digest()).digest()
    return digest[::-1].hex()


def _prev_field_matches(payload: bytes, last_hash: str) -> bool:
    """The header's previous-hash field must carry the prior block's digest."""
    return payload[4:36] == bytes.fromhex(last_hash)[::-1]


def write_frame(payload: bytes, magic: bytes = MAINNET_MAGIC) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ContractError("payload exceeds the 4,000,000-byte consensus maximum")
    return magic + struct.pack("<I", len(payload)) + payload


def _read_exact(source: BinaryIO, count: int, what: str) -> bytes:
    """Read exactly `count` bytes; a short read is truncation, not EOF."""
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = source.read(remaining)
        if not chunk:
            raise ContractError(f"truncated {what}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_frames(
    source: BinaryIO, magic: bytes = MAINNET_MAGIC
) -> Iterator[tuple[FrameMeta, bytes]]:
    """Stream Core-framed payloads. Clean EOF is legal only between frames."""
    offset = 0
    while True:
        head = source.read(1)
        if not head:
            return
        header = head + _read_exact(source, HEADER_LEN - 1, "Core frame header")
        if header[:4] != magic:
            raise ContractError("Core frame magic mismatch")
        length = struct.unpack_from("<I", header, 4)[0]
        if length > MAX_PAYLOAD:
            raise ContractError("Core frame payload exceeds the consensus maximum")
        payload = _read_exact(source, length, "Core frame payload")
        yield FrameMeta(offset=offset, payload_length=length), payload
        offset += HEADER_LEN + length


def iter_length_prefixed(source: BinaryIO) -> Iterator[bytes]:
    """Stream 4-byte-length-prefixed payloads, rejecting over-limit lengths
    before any allocation."""
    while True:
        head = source.read(1)
        if not head:
            return
        prefix = head + _read_exact(source, 3, "length-prefixed header")
        length = struct.unpack("<I", prefix)[0]
        if length > MAX_PAYLOAD:
            raise ContractError("length-prefixed payload exceeds the consensus maximum")
        yield _read_exact(source, length, "length-prefixed payload")


def rest_fetch(hostport: str, path: str, timeout: float = 30.0) -> bytes:
    """Bounded REST read: status is checked before the body, success bodies
    are read up to their schema limit plus one byte, and error bodies are
    drained to a fixed cap instead of being materialized."""
    limit = MAX_PAYLOAD + 1 if path.endswith(".bin") else 66
    host, port = _hostport(hostport)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            response.read(4096)
            raise ContractError(f"REST {path} returned HTTP {response.status}")
        body = _read_exact_stream(response, limit)
        if len(body) == limit and response.read(1):
            raise ContractError(f"REST {path} exceeds the bounded read")
        return body
    finally:
        connection.close()


def _read_exact_stream(response: http.client.HTTPResponse, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = response.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_rest_blocks(
    freeze: Freeze,
    corpus_id: str,
    hostport: str,
    *,
    start_height: int = 0,
    fetch: Fetch | None = None,
) -> Iterator[tuple[str, bytes]]:
    """Yield (advertised header hash, payload) in height order. `start_height`
    is an internal source position; it is never resume evidence on its own."""
    chosen = product(freeze, corpus_id)
    if not 0 <= start_height <= chosen.block_count:
        raise ContractError("REST start height is outside the frozen range")
    getter = fetch or (lambda path: rest_fetch(hostport, path))
    for height in range(start_height, chosen.block_count):
        hash_body = getter(f"/rest/blockhashbyheight/{height}.hex").strip()
        advertised = _hash(hash_body.decode("ascii"))
        payload = getter(f"/rest/block/{advertised}.bin")
        if len(payload) > MAX_PAYLOAD:
            raise ContractError("REST block payload exceeds the consensus maximum")
        yield advertised, payload


def _write_all(stream: BinaryIO, data: bytes) -> None:
    """Write all bytes, tolerating successful short writes."""
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if written is None or written <= 0:
            raise OSError("stream made no progress")
        view = view[written:]


class CorpusWriter:
    """One streaming archive/manifest codec over caller-owned binary files.

    The writer owns the coupled append invariants: contiguous height, the
    frozen block-count capacity, previous-header linkage, the rolling archive
    digest, and the canonical entry spool position. It never discovers run
    directories, never deletes or truncates files, and never publishes paths.
    """

    def __init__(
        self, freeze: Freeze, corpus_id: str, archive: BinaryIO, entries: BinaryIO
    ) -> None:
        self._freeze = freeze
        self._chosen = product(freeze, corpus_id)
        self._archive = archive
        self._entries = entries
        self._count = 0
        self._offset = 0
        self._entries_pos = 0
        self._last_hash: str | None = None
        self._archive_sha = hashlib.sha256()
        self._entries_sha = hashlib.sha256()
        self._tail_pending = False

    def _tail_cleared(self) -> bool:
        """Observe caller-owned truncation: sizes must equal the committed prefix."""
        archive_end = self._archive.seek(0, os.SEEK_END)
        entries_end = self._entries.seek(0, os.SEEK_END)
        self._archive.seek(self._offset)
        self._entries.seek(self._entries_pos)
        return archive_end == self._offset and entries_end == self._entries_pos

    def _check_tail(self) -> None:
        if self._tail_pending:
            if not self._tail_cleared():
                raise ContractError(
                    "unverified tail present: truncate owned files to the recorded prefix first"
                )
            self._tail_pending = False

    def append(self, payload: bytes, *, expected_hash: str | None = None) -> FrameMeta:
        """Commit a frame after both streams accept its complete bytes.

        Validation failures do not write. I/O failures can leave partial tails,
        but preserve prefix_facts() and its digests. Further append/finish calls
        refuse until the caller restores both streams to that prefix or abandons
        the writer. The caller owns flushing, fsync, and checkpoint publication;
        successful write() calls alone do not establish crash durability.
        """
        self._check_tail()
        if self._count >= self._chosen.block_count:
            raise ContractError("append exceeds the frozen block count")
        if len(payload) > MAX_PAYLOAD:
            raise ContractError("payload exceeds the 4,000,000-byte consensus maximum")
        block_hash = header_block_hash(payload)
        if expected_hash is not None and block_hash != _hash(expected_hash):
            raise ContractError("advertised header hash does not match the payload")
        height = self._count
        if height == 0:
            if block_hash != self._freeze.genesis_hash:
                raise ContractError("archive genesis hash is not mainnet genesis")
        else:
            assert self._last_hash is not None
            if not _prev_field_matches(payload, self._last_hash):
                raise ContractError("block header does not link to the previous block")
            if (
                height == self._chosen.stop_height
                and block_hash != self._chosen.stop_hash
            ):
                raise ContractError(
                    f"{self._chosen.corpus_id} stop hash does not match the frozen tip"
                )
        meta = FrameMeta(offset=self._offset, payload_length=len(payload))
        header = self._freeze.network_magic + struct.pack("<I", len(payload))
        line = (
            _entry_chunk(height, block_hash, meta.offset, meta.payload_length) + b"\n"
        )
        self._tail_pending = True
        _write_all(self._archive, header)
        _write_all(self._archive, payload)
        _write_all(self._entries, line)
        self._archive_sha.update(header)
        self._archive_sha.update(payload)
        self._entries_sha.update(line)
        self._count += 1
        self._offset += HEADER_LEN + len(payload)
        self._entries_pos += len(line)
        self._last_hash = block_hash
        self._tail_pending = False
        return meta

    def prefix_facts(self) -> PrefixFacts:
        return PrefixFacts(
            count=self._count,
            archive_bytes=self._offset,
            entries_bytes=self._entries_pos,
            last_hash=self._last_hash,
            archive_prefix_sha256=self._archive_sha.copy().hexdigest(),
            entries_prefix_sha256=self._entries_sha.copy().hexdigest(),
        )

    def finish(self, manifest: BinaryIO) -> CorpusSummary:
        self._check_tail()
        if self._count != self._chosen.block_count:
            raise ContractError(
                f"{self._chosen.corpus_id} archive has {self._count} blocks, expected {self._chosen.block_count}"
            )
        assert self._last_hash is not None
        if self._last_hash != self._chosen.stop_hash:
            raise ContractError(
                f"{self._chosen.corpus_id} stop hash does not match the frozen tip"
            )
        metadata = _manifest_metadata(
            self._freeze, self._chosen, self._offset, self._archive_sha.hexdigest()
        )
        preimage_sha = hashlib.sha256()
        for chunk in _manifest_chunks(metadata, self._replay_entries(), ZERO_SHA256):
            preimage_sha.update(chunk)
        manifest_sha = preimage_sha.hexdigest()
        file_sha = hashlib.sha256()
        for chunk in _manifest_chunks(metadata, self._replay_entries(), manifest_sha):
            file_sha.update(chunk)
            _write_all(manifest, chunk)
        _write_all(manifest, b"\n")
        file_sha.update(b"\n")
        return CorpusSummary(
            count=self._count,
            archive_size=self._offset,
            archive_sha256=self._archive_sha.hexdigest(),
            manifest_sha256=manifest_sha,
            manifest_file_sha256=file_sha.hexdigest(),
        )

    def _replay_entries(self) -> Iterator[bytes]:
        position = self._entries.tell()
        self._entries.seek(0)
        try:
            while True:
                line = self._entries.readline()
                if not line:
                    return
                if not line.endswith(b"\n"):
                    raise ContractError("entry spool ends with a partial record")
                yield line[:-1]
        finally:
            self._entries.seek(position)

    @classmethod
    def resume(
        cls,
        freeze: Freeze,
        corpus_id: str,
        archive: BinaryIO,
        entries: BinaryIO,
        recorded_prefix: PrefixFacts,
    ) -> CorpusWriter:
        """Reconstruct a writer over a previously committed durable prefix.

        The prefix is streamed through the same frame and spool readers; every
        binding, both digests, and the recorded cursor are recomputed from the
        bytes on disk. Serialized hasher state is never trusted. Tails beyond
        the recorded prefix are left untouched; the first append after resume
        refuses while either file is longer than the recorded prefix.
        """
        writer = cls(freeze, corpus_id, archive, entries)
        archive.seek(0)
        entries.seek(0)
        frames = iter_frames(archive, freeze.network_magic)
        while writer._count < recorded_prefix.count:
            line = entries.readline()
            if not line:
                raise ContractError("entry spool is shorter than the recorded prefix")
            if not line.endswith(b"\n"):
                raise ContractError("entry spool ends with a partial record")
            try:
                meta, payload = next(frames)
            except StopIteration:
                raise ContractError(
                    "archive is shorter than the recorded prefix"
                ) from None
            height = writer._count
            block_hash = header_block_hash(payload)
            if height == 0:
                if block_hash != freeze.genesis_hash:
                    raise ContractError("archive genesis hash is not mainnet genesis")
            else:
                assert writer._last_hash is not None
                if not _prev_field_matches(payload, writer._last_hash):
                    raise ContractError(
                        "committed prefix fails previous-header linkage"
                    )
                if (
                    height == writer._chosen.stop_height
                    and block_hash != writer._chosen.stop_hash
                ):
                    raise ContractError("committed prefix carries a foreign stop block")
            if line[:-1] != _entry_chunk(
                height, block_hash, meta.offset, meta.payload_length
            ):
                raise ContractError(
                    "entry spool record does not match the archive frame"
                )
            header = freeze.network_magic + struct.pack("<I", len(payload))
            writer._archive_sha.update(header)
            writer._archive_sha.update(payload)
            writer._entries_sha.update(line)
            writer._count += 1
            writer._offset += HEADER_LEN + len(payload)
            writer._entries_pos += len(line)
            writer._last_hash = block_hash
        facts = writer.prefix_facts()
        if (
            facts.count != recorded_prefix.count
            or facts.archive_bytes != recorded_prefix.archive_bytes
            or facts.entries_bytes != recorded_prefix.entries_bytes
            or facts.last_hash != recorded_prefix.last_hash
            or facts.archive_prefix_sha256
            != _hash(recorded_prefix.archive_prefix_sha256)
            or facts.entries_prefix_sha256
            != _hash(recorded_prefix.entries_prefix_sha256)
        ):
            raise ContractError(
                "durable prefix does not match the recorded checkpoint identity"
            )
        archive_end = archive.seek(0, os.SEEK_END)
        entries_end = entries.seek(0, os.SEEK_END)
        if archive_end < facts.archive_bytes or entries_end < facts.entries_bytes:
            raise ContractError("files are shorter than the recorded prefix")
        if archive_end != facts.archive_bytes or entries_end != facts.entries_bytes:
            writer._tail_pending = True
        archive.seek(facts.archive_bytes)
        entries.seek(facts.entries_bytes)
        return writer


def _entry_chunk(
    height: int, block_hash: str, offset: int, payload_length: int
) -> bytes:
    return canonical_json(
        {
            "hash": block_hash,
            "height": height,
            "offset": offset,
            "payload_length": payload_length,
        }
    )


def _entry_int(entry: Mapping[str, object], key: str) -> int:
    value = entry[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ContractError(f"manifest entry {key} is not a JSON integer")
    return value


def _entry_str(entry: Mapping[str, object], key: str) -> str:
    value = entry[key]
    if not isinstance(value, str):
        raise ContractError(f"manifest entry {key} is not a string")
    return value


def _manifest_metadata(
    freeze: Freeze, chosen: Product, archive_size: int, archive_sha: str
) -> dict[str, object]:
    return {
        "schema": MANIFEST_SCHEMA,
        "version": MANIFEST_VERSION,
        "corpus_id": chosen.corpus_id,
        "network": freeze.network,
        "network_magic": freeze.network_magic.hex(),
        "genesis_hash": freeze.genesis_hash,
        "range": {"start_height": 0, "stop_height": chosen.stop_height},
        "source_tip_hash": chosen.stop_hash,
        "archive": {"size": archive_size, "sha256": archive_sha},
    }


def _manifest_chunks(
    metadata: Mapping[str, object],
    entries: Iterable[bytes],
    manifest_sha256: str,
) -> Iterator[bytes]:
    """Emit canonical manifest-v1 bytes, splicing entry chunks without
    materializing the entries array. Key order is the sorted canonical order;
    scalar chunks reuse the retained canonical_json encoder."""
    archive = _object(metadata["archive"], "archive")
    yield b'{"archive":' + canonical_json(
        {"sha256": archive["sha256"], "size": archive["size"]}
    )
    yield b',"corpus_id":' + canonical_json(metadata["corpus_id"])
    yield b',"entries":['
    first = True
    for chunk in entries:
        if not first:
            yield b","
        first = False
        yield chunk
    yield b"]"
    yield b',"genesis_hash":' + canonical_json(metadata["genesis_hash"])
    yield b',"manifest_sha256":' + canonical_json(manifest_sha256)
    yield b',"network":' + canonical_json(metadata["network"])
    yield b',"network_magic":' + canonical_json(metadata["network_magic"])
    yield b',"range":' + canonical_json(
        {
            "start_height": _object(metadata["range"], "range")["start_height"],
            "stop_height": _object(metadata["range"], "range")["stop_height"],
        }
    )
    yield b',"schema":' + canonical_json(metadata["schema"])
    yield b',"source_tip_hash":' + canonical_json(metadata["source_tip_hash"])
    yield b',"version":' + canonical_json(metadata["version"])
    yield b"}"


class _ManifestReader:
    """Schema-specific bounded JSON reader for manifest-v1.

    Accepts arbitrary member order, arbitrary inter-token whitespace, and any
    valid JSON string escape; enforces the exact v1 field sets and the emitted
    primitive domains (JSON integers, fixed-size hex strings). Canonical entry
    records are spooled to the caller's scratch stream as they are read.
    """

    def __init__(self, source: BinaryIO, entries: BinaryIO, max_entries: int) -> None:
        self._source = source
        self._entries = entries
        self._max_entries = max_entries
        self._buffer = b""
        self._position = 0

    def read_metadata(self) -> dict[str, object]:
        root = self._read_object(_ROOT_KEYS, self._read_root_value)
        self._skip_ws()
        if self._peek() is not None:
            raise ContractError("manifest has trailing content after the root object")
        return root

    def _read_root_value(self, key: str) -> object:
        if key == "entries":
            return self._read_entries()
        if key == "archive":
            return self._read_object(_ARCHIVE_KEYS, self._read_archive_value)
        if key == "range":
            return self._read_object(_RANGE_KEYS, self._read_range_value)
        if key in {"genesis_hash", "manifest_sha256", "source_tip_hash"}:
            return self._read_hash(key)
        if key == "network_magic":
            return self._read_hex(key, 8)
        if key in {"schema", "network", "corpus_id"}:
            return self._read_string(key, 64)
        if key == "version":
            return self._read_int(key, 2)
        raise ContractError(f"unknown manifest member {key!r}")

    def _read_archive_value(self, key: str) -> object:
        if key == "sha256":
            return self._read_hash(key)
        return self._read_int(key, _MAX_INT_DIGITS)

    def _read_range_value(self, key: str) -> object:
        return self._read_int(key, 10)

    def _read_entries(self) -> list[object]:
        self._skip_ws()
        self._expect("[", "entries")
        count = 0
        self._skip_ws()
        if self._peek() == ord("]"):
            self._next()
            return []
        while True:
            entry_holder: dict[str, object] = {}

            def read_entry_value(key: str) -> object:
                if key == "hash":
                    return self._read_hash(key)
                return self._read_int(key, _MAX_INT_DIGITS)

            entry = self._read_object(_ENTRY_KEYS, read_entry_value)
            entry_holder.update(entry)
            if count >= self._max_entries:
                raise ContractError("manifest entries exceed the frozen block count")
            line = _entry_chunk(
                _entry_int(entry_holder, "height"),
                _entry_str(entry_holder, "hash"),
                _entry_int(entry_holder, "offset"),
                _entry_int(entry_holder, "payload_length"),
            )
            self._entries.write(line + b"\n")
            count += 1
            self._skip_ws()
            char = self._peek()
            if char == ord(","):
                self._next()
                self._skip_ws()
                continue
            if char == ord("]"):
                self._next()
                return []
            raise ContractError("manifest entries array is malformed")

    def _read_object(
        self, keys: frozenset[str], read_value: Callable[[str], object]
    ) -> dict[str, object]:
        self._skip_ws()
        self._expect("{", "object")
        result: dict[str, object] = {}
        self._skip_ws()
        if self._peek() == ord("}"):
            self._next()
        else:
            while True:
                key = self._read_string("member name", 32)
                if key not in keys:
                    raise ContractError(f"unknown manifest member {key!r}")
                if key in result:
                    raise ContractError("duplicate object member")
                self._skip_ws()
                self._expect(":", "object")
                self._skip_ws()
                result[key] = read_value(key)
                self._skip_ws()
                char = self._peek()
                if char == ord(","):
                    self._next()
                    self._skip_ws()
                    continue
                if char == ord("}"):
                    self._next()
                    break
                raise ContractError("manifest object is malformed")
        missing = keys - result.keys()
        if missing:
            raise ContractError(
                f"manifest object is missing members: {sorted(missing)}"
            )
        return result

    def _read_string(self, label: str, max_chars: int) -> str:
        self._skip_ws()
        self._expect('"', label)
        raw = bytearray()
        while True:
            char = self._next()
            if char is None:
                raise ContractError(f"manifest {label} is unterminated")
            raw.append(char)
            if char == ord('"') and not _ends_with_odd_escapes(raw[:-1]):
                break
            if len(raw) > max_chars * 8 + 2:
                raise ContractError(
                    f"manifest {label} exceeds its schema-derived bound"
                )
        try:
            value = json.loads(b'"' + bytes(raw))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ContractError(f"manifest {label} is not valid JSON") from error
        if not isinstance(value, str):
            raise ContractError(f"manifest {label} is not a string")
        if len(value) > max_chars:
            raise ContractError(f"manifest {label} exceeds its schema-derived bound")
        return value

    def _read_hash(self, label: str) -> str:
        value = self._read_string(label, 64)
        if len(value) != 64 or any(char not in _HEX for char in value):
            raise ContractError(f"manifest {label} is not a 64-character hex hash")
        return value

    def _read_hex(self, label: str, digits: int) -> str:
        value = self._read_string(label, digits)
        if len(value) != digits or any(char not in _HEX for char in value):
            raise ContractError(
                f"manifest {label} is not a {digits}-character hex value"
            )
        return value

    def _read_int(self, label: str, max_digits: int) -> int:
        self._skip_ws()
        digits = bytearray()
        while True:
            char = self._peek()
            if char is None or not ord("0") <= char <= ord("9"):
                break
            self._next()
            digits.append(char)
            if len(digits) > max_digits:
                raise ContractError(
                    f"manifest {label} exceeds its schema-derived bound"
                )
        if not digits:
            raise ContractError(f"manifest {label} is not a JSON integer")
        return int(digits.decode("ascii"))

    def _skip_ws(self) -> None:
        while True:
            char = self._peek()
            if char is None or char not in (0x20, 0x09, 0x0A, 0x0D):
                return
            self._next()

    def _expect(self, token: str, where: str) -> None:
        char = self._next()
        if char is None or chr(char) != token:
            raise ContractError(f"manifest {where} is malformed: expected {token!r}")

    def _peek(self) -> int | None:
        if self._position >= len(self._buffer):
            self._fill()
            if self._position >= len(self._buffer):
                return None
        return self._buffer[self._position]

    def _next(self) -> int | None:
        char = self._peek()
        if char is not None:
            self._position += 1
        return char

    def _fill(self) -> None:
        if self._position:
            self._buffer = self._buffer[self._position :]
            self._position = 0
        chunk = self._source.read(4096)
        if chunk:
            self._buffer += chunk


def _ends_with_odd_escapes(raw: bytearray | bytes) -> bool:
    count = 0
    for char in reversed(raw):
        if char == ord("\\"):
            count += 1
        else:
            break
    return count % 2 == 1


def _replay_spool(entries: BinaryIO) -> Iterator[bytes]:
    position = entries.tell()
    entries.seek(0)
    try:
        while True:
            line = entries.readline()
            if not line:
                return
            if not line.endswith(b"\n"):
                raise ContractError("entry spool ends with a partial record")
            yield line[:-1]
    finally:
        entries.seek(position)


def verify_archive(
    freeze: Freeze,
    archive: BinaryIO,
    manifest: BinaryIO,
    *,
    entries: BinaryIO,
) -> Product:
    """Bind an archive stream to its manifest stream with bounded memory.

    The manifest is read with the exact v1 schema (member order, whitespace,
    and JSON escapes free); canonical entry records are spooled to `entries`
    and the canonical zero-field preimage digest is recomputed from the
    accepted decoded values, never from a normalized copy.
    """
    max_entries = max(p.block_count for p in freeze.products.values())
    reader = _ManifestReader(manifest, entries, max_entries)
    metadata = reader.read_metadata()
    if metadata["schema"] != MANIFEST_SCHEMA:
        raise ContractError("manifest schema is not bitcoin-rs-corpus-manifest")
    if metadata["version"] != MANIFEST_VERSION:
        raise ContractError("manifest version is not 1")
    declared = _hash(_text(metadata["manifest_sha256"], "manifest_sha256"))
    preimage = hashlib.sha256()
    for chunk in _manifest_chunks(metadata, _replay_spool(entries), ZERO_SHA256):
        preimage.update(chunk)
    if declared != preimage.hexdigest():
        raise ContractError("manifest_sha256 does not match the canonical preimage")
    corpus_id = _text(metadata["corpus_id"], "corpus_id")
    chosen = product(freeze, corpus_id)
    if metadata["network"] != freeze.network:
        raise ContractError("manifest network is not mainnet")
    if (
        bytes.fromhex(_text(metadata["network_magic"], "network_magic"))
        != freeze.network_magic
    ):
        raise ContractError("manifest network magic is not mainnet")
    if _hash(_text(metadata["genesis_hash"], "genesis_hash")) != freeze.genesis_hash:
        raise ContractError("manifest genesis hash is not mainnet genesis")
    range_obj = _object(metadata["range"], "range")
    if range_obj["start_height"] != 0 or range_obj["stop_height"] != chosen.stop_height:
        raise ContractError(
            f"{corpus_id} height range is not genesis through the frozen tip"
        )
    if _hash(_text(metadata["source_tip_hash"], "source_tip_hash")) != chosen.stop_hash:
        raise ContractError(f"{corpus_id} source tip is not the frozen stop hash")
    archive_info = _object(metadata["archive"], "archive")
    archive_size = _u64(archive_info["size"], "archive.size")
    archive_end = archive.seek(0, os.SEEK_END)
    if archive_end != archive_size:
        raise ContractError("manifest archive size does not match the file")
    archive.seek(0)
    archive_sha = hashlib.sha256()
    while True:
        chunk = archive.read(1 << 20)
        if not chunk:
            break
        archive_sha.update(chunk)
    if (
        _hash(_text(archive_info["sha256"], "archive.sha256"))
        != archive_sha.hexdigest()
    ):
        raise ContractError("manifest archive sha256 does not match the file")
    archive.seek(0)
    height = 0
    last_hash: str | None = None
    frames = iter_frames(archive, freeze.network_magic)
    for chunk in _replay_spool(entries):
        entry = json.loads(chunk.decode("ascii"))
        try:
            meta, payload = next(frames)
        except StopIteration:
            raise ContractError(
                f"{corpus_id} entry count is not the frozen block count"
            ) from None
        block_hash = header_block_hash(payload)
        if (
            entry["height"] != height
            or entry["offset"] != meta.offset
            or entry["payload_length"] != meta.payload_length
        ):
            raise ContractError("manifest offsets do not match the archive frames")
        if _hash(_text(entry["hash"], f"entries[{height}].hash")) != block_hash:
            raise ContractError("manifest block hash does not match the framed header")
        if height == 0:
            if block_hash != freeze.genesis_hash:
                raise ContractError("framed genesis is not mainnet genesis")
        else:
            assert last_hash is not None
            if not _prev_field_matches(payload, last_hash):
                raise ContractError("framed archive fails previous-header linkage")
            if height == chosen.stop_height and block_hash != chosen.stop_hash:
                raise ContractError(
                    f"{corpus_id} framed tip is not the frozen stop hash"
                )
        last_hash = block_hash
        height += 1
    if archive.read(1):
        raise ContractError(f"{corpus_id} archive carries frames beyond the manifest")
    if height != chosen.block_count:
        raise ContractError(f"{corpus_id} entry count is not the frozen block count")
    return chosen


def classify_census(
    freeze: Freeze, corpus_id: str, counters: Mapping[str, object]
) -> dict[str, object]:
    chosen = product(freeze, corpus_id)
    specials = {
        name: _u64(counters.get(name, 0), name) for name in freeze.census_specials
    }
    missing = [name for name in freeze.census_specials if name not in counters]
    if missing:
        raise ContractError("census is missing required special context counters")
    if corpus_id == "C150":
        expected = chosen.census
        for key, value in expected.items():
            if key == "specials":
                continue
            if _u64(counters.get(key, -1), key) != value:
                raise ContractError(f"C150 census {key} is not the frozen count")
        if any(count != 0 for count in specials.values()):
            raise ContractError("C150 census must have zero special context counters")
        passed = "c150_passed"
    elif corpus_id == "Cmodern":
        if any(count <= 0 for count in specials.values()):
            raise ContractError(
                "Cmodern census requires a positive count for every special context"
            )
        schnorr_entries = _u64(
            counters.get("checkschnorr_entries", 0), "checkschnorr_entries"
        )
        schnorr_calls = _u64(
            counters.get("schnorr_verify_calls", 0), "schnorr_verify_calls"
        )
        schnorr_ok = _u64(counters.get("schnorr_verify_ok", 0), "schnorr_verify_ok")
        schnorr_fail = _u64(
            counters.get("schnorr_verify_fail", 0), "schnorr_verify_fail"
        )
        if schnorr_entries < schnorr_calls:
            raise ContractError("Cmodern Schnorr entries are below verify calls")
        if schnorr_calls != schnorr_ok + schnorr_fail:
            raise ContractError(
                "Cmodern Schnorr verify calls do not equal ok plus fail"
            )
        passed = "cmodern_passed"
    else:
        raise ContractError(f"unknown corpus_id {corpus_id!r}")
    return {
        "corpus_id": corpus_id,
        "all_passed": True,
        passed: True,
        "specials": specials,
        "assume_valid_height": freeze.assume_valid_height,
        "stop_height": chosen.stop_height,
        "stop_hash": chosen.stop_hash,
    }


def c150_state(freeze: Freeze) -> Mapping[str, object]:
    return product(freeze, "C150").state


def core_oracle_params(freeze: Freeze, corpus_id: str) -> list[object]:
    chosen = product(freeze, corpus_id)
    oracle = freeze.core_oracle
    return [oracle["hash_type"], chosen.stop_height, oracle["use_index"]]


_MAX_INDEX_BYTES = _MAX_BLOCK_COUNT * 256 + (1 << 20)


@dataclass(frozen=True)
class SourceOffset:
    source: int
    offset: int


@dataclass(frozen=True)
class IndexDocument:
    corpus_id: str
    network: str
    network_magic: str
    genesis_hash: str
    start_height: int
    stop_height: int
    source_tip_hash: str
    sources: tuple[IndexSource, ...]
    entries: tuple[IndexEntry, ...]
    logical_size: int
    logical_sha256: str
    index_sha256: str


@dataclass(frozen=True)
class _ScanRecord:
    prev: str
    source: int
    offset: int
    length: int


def _check_source_name(name: object) -> str:
    """Validate an indexed source file name.

    Only Core block-file basenames (``blkNNNNN.dat``) are accepted. This
    rejects absolute paths, directory traversal, separators, and drive
    prefixes by construction. Consistency: callers hold snapshot isolation
    over the source directory (quiescent blk files, no concurrent writer);
    verification is idempotent and safe to retry.
    """
    if not isinstance(name, str) or not name:
        raise ContractError("index source name must be a non-empty string")
    if len(name) > 32:
        raise ContractError("index source name exceeds its length bound")
    if _SOURCE_NAME_RE.fullmatch(name) is None:
        raise ContractError(
            f"index source name {name!r} is not a blkNNNNN.dat basename"
        )
    return name


def _lower_hex(value: object, label: str, digits: int) -> str:
    text = _text(value, label)
    if len(text) != digits:
        raise ContractError(f"{label} is not a {digits}-character hex value")
    if text != text.lower():
        raise ContractError(f"{label} must be lowercase hex")
    if any(char not in "0123456789abcdef" for char in text):
        raise ContractError(f"{label} is not a hex value")
    return text


def _hash_file(path: Path) -> tuple[int, str]:
    """Stream a source file, returning its size and SHA-256 hex digest."""
    hasher = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
    except OSError as err:
        raise ContractError(f"cannot read source file {path}: {err}") from err
    return size, hasher.hexdigest()


def _source_path(source_dir: Path, name: str) -> Path:
    if not source_dir.is_dir():
        raise ContractError(f"source directory {source_dir} is not a directory")
    path = source_dir / name
    if path.is_symlink():
        raise ContractError(f"source {name!r} must not be a symlink")
    if not path.is_file():
        raise ContractError(f"source {name!r} is not a regular file")
    return path


class _SingleSourceReader:
    """Bounded indexed-source reader holding at most one open file.

    The handle stays open while consecutive entries share a source and closes
    on source switch or ``close()``. All indexed paths (build, verify, iterate)
    read through this helper, so frame policy cannot diverge. Callers must call
    ``close()``; the reader never opens more than one file.
    """

    def __init__(
        self, source_dir: Path, sources: Sequence[IndexSource], magic: bytes
    ) -> None:
        self._source_dir = source_dir
        self._sources = sources
        self._magic = magic
        self._current: int | None = None
        self._handle: BinaryIO | None = None
        self._stack = contextlib.ExitStack()

    def read(self, entry: IndexEntry) -> bytes:
        if entry.source < 0 or entry.source >= len(self._sources):
            raise ContractError(
                f"entries[{entry.height}].source is outside the sources array"
            )
        if entry.offset < 0 or entry.length < MIN_HEADER or entry.length > MAX_PAYLOAD:
            raise ContractError(
                f"entries[{entry.height}] has an out-of-range offset/length"
            )
        recorded = self._sources[entry.source]
        if entry.offset + HEADER_LEN + entry.length > recorded.size:
            raise ContractError(
                f"entries[{entry.height}] range exceeds its source size"
            )
        if self._current != entry.source:
            self.close()
            path = _source_path(self._source_dir, recorded.name)
            try:
                self._handle = self._stack.enter_context(path.open("rb"))
            except OSError as err:
                raise ContractError(
                    f"cannot open source {recorded.name}: {err}"
                ) from err
            self._current = entry.source
        handle = self._handle
        if handle is None:
            raise ContractError("indexed source reader lost its handle")
        try:
            handle.seek(entry.offset)
        except OSError as err:
            raise ContractError(
                f"cannot seek entries[{entry.height}] in {recorded.name}: {err}"
            ) from err
        header = _read_exact(handle, HEADER_LEN, "indexed Core frame header")
        if header[:4] != self._magic:
            raise ContractError(f"entries[{entry.height}] magic does not match mainnet")
        if struct.unpack_from("<I", header, 4)[0] != entry.length:
            raise ContractError(
                f"entries[{entry.height}] length does not match the frame header"
            )
        try:
            return _read_exact(handle, entry.length, "indexed Core frame payload")
        except OSError as err:
            raise ContractError(
                f"cannot read entries[{entry.height}] from {recorded.name}: {err}"
            ) from err

    def close(self) -> None:
        try:
            self._stack.close()
        except OSError as err:
            print(f"warning: cannot close source handle: {err}", file=sys.stderr)
        self._handle = None
        self._current = None


def _verify_entry_hash(
    freeze: Freeze,
    chosen: Product,
    entry: IndexEntry,
    height: int,
    payload: bytes,
    last_hash: str | None,
) -> str:
    """Check one payload against its entry, genesis, linkage, and frozen tip."""
    block_hash = header_block_hash(payload)
    if block_hash != entry.hash:
        raise ContractError(f"entries[{height}] hash does not match the payload header")
    if height == 0:
        if block_hash != freeze.genesis_hash:
            raise ContractError("indexed genesis is not mainnet genesis")
    else:
        if last_hash is None:
            raise ContractError("indexed chain lost its linkage cursor")
        if not _prev_field_matches(payload, last_hash):
            raise ContractError("indexed chain fails previous-header linkage")
        if height == chosen.stop_height and block_hash != chosen.stop_hash:
            raise ContractError(
                f"{chosen.corpus_id} indexed tip is not the frozen stop hash"
            )
    return block_hash


def _index_entry_chunk(entry: IndexEntry) -> bytes:
    return canonical_json(
        {
            "hash": entry.hash,
            "height": entry.height,
            "length": entry.length,
            "offset": entry.offset,
            "source": entry.source,
        }
    )


def _index_source_chunk(source: IndexSource) -> bytes:
    return canonical_json(
        {"name": source.name, "sha256": source.sha256, "size": source.size}
    )


def _index_metadata(
    freeze: Freeze,
    corpus_id: str,
    sources: Sequence[IndexSource],
    logical_size: int,
    logical_sha: str,
    index_sha: str,
) -> dict[str, object]:
    chosen = product(freeze, corpus_id)
    return {
        "corpus_id": chosen.corpus_id,
        "genesis_hash": freeze.genesis_hash,
        "logical": {"sha256": logical_sha, "size": logical_size},
        "network": freeze.network,
        "network_magic": freeze.network_magic.hex(),
        "range": {"start_height": 0, "stop_height": chosen.stop_height},
        "schema": INDEX_SCHEMA,
        "source_tip_hash": chosen.stop_hash,
        "version": INDEX_VERSION,
    }


def _index_chunks(
    metadata: Mapping[str, object],
    source_chunks: Iterable[bytes],
    entry_chunks: Iterable[bytes],
    index_sha: str,
) -> Iterator[bytes]:
    """Emit canonical index-v1 bytes, splicing sources/entries without materializing arrays."""
    logical = _object(metadata["logical"], "logical")
    yield b'{"corpus_id":' + canonical_json(metadata["corpus_id"])
    yield b',"entries":['
    first = True
    for chunk in entry_chunks:
        if not first:
            yield b","
        first = False
        yield chunk
    yield b"]"
    yield b',"genesis_hash":' + canonical_json(metadata["genesis_hash"])
    yield b',"index_sha256":' + canonical_json(index_sha)
    yield b',"logical":' + canonical_json(
        {"sha256": logical["sha256"], "size": logical["size"]}
    )
    yield b',"network":' + canonical_json(metadata["network"])
    yield b',"network_magic":' + canonical_json(metadata["network_magic"])
    yield b',"range":' + canonical_json(
        {
            "start_height": _object(metadata["range"], "range")["start_height"],
            "stop_height": _object(metadata["range"], "range")["stop_height"],
        }
    )
    yield b',"schema":' + canonical_json(metadata["schema"])
    yield b',"source_tip_hash":' + canonical_json(metadata["source_tip_hash"])
    yield b',"sources":['
    first = True
    for chunk in source_chunks:
        if not first:
            yield b","
        first = False
        yield chunk
    yield b"]"
    yield b',"version":' + canonical_json(metadata["version"])
    yield b"}"


def _load_index(path: Path) -> IndexDocument:
    """Parse and structurally validate an index file. No source I/O is performed."""
    try:
        data = path.read_bytes()
    except OSError as err:
        raise ContractError(f"cannot read index file {path}: {err}") from err
    if len(data) > _MAX_INDEX_BYTES:
        raise ContractError("index file exceeds its size bound")
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except ValueError as err:
        raise ContractError(f"index file {path} is not valid JSON: {err}") from err
    if not isinstance(raw, dict):
        raise ContractError("index root must be a JSON object")
    if frozenset(raw.keys()) != _INDEX_ROOT_KEYS:
        raise ContractError("index root fields do not match index-v1")
    if _text(raw["schema"], "schema") != INDEX_SCHEMA:
        raise ContractError("index schema is not bitcoin-rs-corpus-index-v1")
    if _u32(raw["version"], "version") != INDEX_VERSION:
        raise ContractError("index version is not 1")
    corpus_id = _text(raw["corpus_id"], "corpus_id")
    network = _text(raw["network"], "network")
    network_magic = _lower_hex(raw["network_magic"], "network_magic", 8)
    genesis_hash = _lower_hex(raw["genesis_hash"], "genesis_hash", 64)
    source_tip_hash = _lower_hex(raw["source_tip_hash"], "source_tip_hash", 64)
    range_obj = _object(raw["range"], "range")
    if frozenset(range_obj.keys()) != _RANGE_KEYS:
        raise ContractError("index range fields do not match v1")
    start_height = _u32(range_obj["start_height"], "range.start_height")
    stop_height = _u32(range_obj["stop_height"], "range.stop_height")
    if start_height != 0:
        raise ContractError("index range must start at genesis")
    logical_obj = _object(raw["logical"], "logical")
    if frozenset(logical_obj.keys()) != _INDEX_LOGICAL_KEYS:
        raise ContractError("index logical fields do not match v1")
    logical_sha256 = _lower_hex(logical_obj["sha256"], "logical.sha256", 64)
    logical_size = _u64(logical_obj["size"], "logical.size")
    index_sha256 = _lower_hex(raw["index_sha256"], "index_sha256", 64)
    raw_sources = _array(raw["sources"], "sources")
    if len(raw_sources) == 0 or len(raw_sources) > _MAX_SOURCES:
        raise ContractError("index sources are outside their count bound")
    sources: list[IndexSource] = []
    seen_names: set[str] = set()
    for position, item in enumerate(raw_sources):
        body = _object(item, f"sources[{position}]")
        if frozenset(body.keys()) != _INDEX_SOURCE_KEYS:
            raise ContractError(f"sources[{position}] fields do not match v1")
        name = _check_source_name(body["name"])
        if name in seen_names:
            raise ContractError(f"duplicate index source {name!r}")
        seen_names.add(name)
        size = _u64(body["size"], f"sources[{position}].size")
        if size > _MAX_ARCHIVE_SIZE:
            raise ContractError(f"sources[{position}].size exceeds its bound")
        sha256 = _lower_hex(body["sha256"], f"sources[{position}].sha256", 64)
        sources.append(IndexSource(name=name, size=size, sha256=sha256))
    raw_entries = _array(raw["entries"], "entries")
    if len(raw_entries) == 0 or len(raw_entries) > _MAX_BLOCK_COUNT:
        raise ContractError("index entries are outside their count bound")
    entries: list[IndexEntry] = []
    for position, item in enumerate(raw_entries):
        body = _object(item, f"entries[{position}]")
        if frozenset(body.keys()) != _INDEX_ENTRY_KEYS:
            raise ContractError(f"entries[{position}] fields do not match v1")
        height = _u64(body["height"], f"entries[{position}].height")
        block_hash = _lower_hex(body["hash"], f"entries[{position}].hash", 64)
        source = _u64(body["source"], f"entries[{position}].source")
        offset = _u64(body["offset"], f"entries[{position}].offset")
        length = _u64(body["length"], f"entries[{position}].length")
        if source >= len(sources):
            raise ContractError(
                f"entries[{position}].source is outside the sources array"
            )
        if length < MIN_HEADER or length > MAX_PAYLOAD:
            raise ContractError(
                f"entries[{position}].length is outside consensus bounds"
            )
        if offset + HEADER_LEN + length > sources[source].size:
            raise ContractError(f"entries[{position}] range exceeds its source size")
        entries.append(
            IndexEntry(
                height=height,
                hash=block_hash,
                source=source,
                offset=offset,
                length=length,
            )
        )
    for position, entry in enumerate(entries):
        if entry.height != position:
            raise ContractError("index entries must be contiguous heights from genesis")
    return IndexDocument(
        corpus_id=corpus_id,
        network=network,
        network_magic=network_magic,
        genesis_hash=genesis_hash,
        start_height=start_height,
        stop_height=stop_height,
        source_tip_hash=source_tip_hash,
        sources=tuple(sources),
        entries=tuple(entries),
        logical_size=logical_size,
        logical_sha256=logical_sha256,
        index_sha256=index_sha256,
    )


def _check_index_digest(doc: IndexDocument) -> None:
    metadata = {
        "corpus_id": doc.corpus_id,
        "genesis_hash": doc.genesis_hash,
        "logical": {"sha256": doc.logical_sha256, "size": doc.logical_size},
        "network": doc.network,
        "network_magic": doc.network_magic,
        "range": {"start_height": doc.start_height, "stop_height": doc.stop_height},
        "schema": INDEX_SCHEMA,
        "source_tip_hash": doc.source_tip_hash,
        "version": INDEX_VERSION,
    }
    preimage = hashlib.sha256()
    for chunk in _index_chunks(
        metadata,
        [_index_source_chunk(source) for source in doc.sources],
        [_index_entry_chunk(entry) for entry in doc.entries],
        ZERO_SHA256,
    ):
        preimage.update(chunk)
    if preimage.hexdigest() != doc.index_sha256:
        raise ContractError("index_sha256 does not match the canonical preimage")


def _check_index_against_freeze(freeze: Freeze, doc: IndexDocument) -> Product:
    chosen = product(freeze, doc.corpus_id)
    if doc.network != freeze.network:
        raise ContractError("index network is not mainnet")
    if doc.network_magic != freeze.network_magic.hex():
        raise ContractError("index network magic is not mainnet")
    if doc.genesis_hash != freeze.genesis_hash:
        raise ContractError("index genesis hash is not mainnet genesis")
    if doc.start_height != 0 or doc.stop_height != chosen.stop_height:
        raise ContractError(
            f"{chosen.corpus_id} index range is not genesis through the frozen tip"
        )
    if doc.source_tip_hash != chosen.stop_hash:
        raise ContractError(f"{chosen.corpus_id} index tip is not the frozen stop hash")
    if len(doc.entries) != chosen.block_count:
        raise ContractError(
            f"{chosen.corpus_id} index entry count is not the frozen block count"
        )
    return chosen


class IndexWriter:
    """Streaming indexed-corpus builder over caller-supplied payloads and locators.

    The writer owns append invariants: contiguous height, frozen capacity,
    previous-header linkage, the rolling logical digest, and per-frame range
    checks against registered source sizes. Source digests are registered by
    the caller (see ``build_index_from_scan`` for custody-derived values);
    ``verify_index`` recomputes them from disk before any frame is accepted.
    Outputs are published atomically with no-clobber semantics; inputs are
    never pruned, truncated, or mutated. Consistency: build on a quiescent
    source directory (snapshot isolation); finishing is idempotent only by
    retrying with a fresh writer and a fresh destination.
    """

    def __init__(self, freeze: Freeze, corpus_id: str) -> None:
        self._freeze = freeze
        self._chosen = product(freeze, corpus_id)
        self._sources: list[IndexSource] = []
        self._entries: list[IndexEntry] = []
        self._count = 0
        self._logical_size = 0
        self._logical_sha = hashlib.sha256()
        self._last_hash: str | None = None

    def add_source(self, source: IndexSource) -> int:
        checked_name = _check_source_name(source.name)
        if source.size > _MAX_ARCHIVE_SIZE:
            raise ContractError("index source size exceeds its bound")
        _lower_hex(source.sha256, "source.sha256", 64)
        for existing in self._sources:
            if existing.name == checked_name:
                raise ContractError(f"duplicate index source {checked_name!r}")
        if len(self._sources) >= _MAX_SOURCES:
            raise ContractError("index sources exceed their count bound")
        index = len(self._sources)
        self._sources.append(
            IndexSource(name=checked_name, size=source.size, sha256=source.sha256)
        )
        return index

    def append(
        self,
        payload: bytes,
        at: SourceOffset,
        expected_hash: str | None = None,
    ) -> IndexEntry:
        if self._count >= self._chosen.block_count:
            raise ContractError("index append exceeds the frozen block count")
        if len(payload) > MAX_PAYLOAD or len(payload) < MIN_HEADER:
            raise ContractError("index payload is outside consensus bounds")
        block_hash = header_block_hash(payload)
        if expected_hash is not None and block_hash != _lower_hex(
            expected_hash, "expected_hash", 64
        ):
            raise ContractError("advertised header hash does not match the payload")
        height = self._count
        if height == 0:
            if block_hash != self._freeze.genesis_hash:
                raise ContractError("index genesis hash is not mainnet genesis")
        else:
            if self._last_hash is None:
                raise ContractError("index writer lost its linkage cursor")
            if not _prev_field_matches(payload, self._last_hash):
                raise ContractError("indexed block does not link to its predecessor")
            if (
                height == self._chosen.stop_height
                and block_hash != self._chosen.stop_hash
            ):
                raise ContractError(
                    f"{self._chosen.corpus_id} index tip is not the frozen stop hash"
                )
        if at.source < 0 or at.source >= len(self._sources):
            raise ContractError("indexed frame source is outside the sources array")
        if at.offset < 0:
            raise ContractError("indexed frame offset is negative")
        recorded = self._sources[at.source]
        if at.offset + HEADER_LEN + len(payload) > recorded.size:
            raise ContractError("indexed frame range exceeds its source size")
        entry = IndexEntry(
            height=height,
            hash=block_hash,
            source=at.source,
            offset=at.offset,
            length=len(payload),
        )
        self._entries.append(entry)
        self._logical_sha.update(
            self._freeze.network_magic + struct.pack("<I", len(payload))
        )
        self._logical_sha.update(payload)
        self._logical_size += HEADER_LEN + len(payload)
        self._count += 1
        self._last_hash = block_hash
        return entry

    def finish(self, index: BinaryIO) -> IndexSummary:
        if self._count != self._chosen.block_count:
            raise ContractError(
                f"{self._chosen.corpus_id} index has {self._count} blocks, expected {self._chosen.block_count}"
            )
        if self._last_hash is None:
            raise ContractError("index writer has no committed tip")
        if self._last_hash != self._chosen.stop_hash:
            raise ContractError(
                f"{self._chosen.corpus_id} index tip is not the frozen stop hash"
            )
        intervals: dict[int, list[tuple[int, int]]] = {}
        for entry in self._entries:
            span = (entry.offset, entry.offset + HEADER_LEN + entry.length)
            intervals.setdefault(entry.source, []).append(span)
        for source, spans in intervals.items():
            spans.sort()
            previous_end: int | None = None
            for start, end in spans:
                if previous_end is not None and start < previous_end:
                    raise ContractError(
                        f"index entries overlap in source {self._sources[source].name!r}"
                    )
                previous_end = end
        logical_sha = self._logical_sha.hexdigest()
        metadata = _index_metadata(
            self._freeze,
            self._chosen.corpus_id,
            self._sources,
            self._logical_size,
            logical_sha,
            ZERO_SHA256,
        )
        preimage = hashlib.sha256()
        for chunk in _index_chunks(
            metadata,
            [_index_source_chunk(source) for source in self._sources],
            [_index_entry_chunk(entry) for entry in self._entries],
            ZERO_SHA256,
        ):
            preimage.update(chunk)
        index_sha = preimage.hexdigest()
        file_sha = hashlib.sha256()
        for chunk in _index_chunks(
            metadata,
            [_index_source_chunk(source) for source in self._sources],
            [_index_entry_chunk(entry) for entry in self._entries],
            index_sha,
        ):
            file_sha.update(chunk)
            _write_all(index, chunk)
        _write_all(index, b"\n")
        file_sha.update(b"\n")
        return IndexSummary(
            count=self._count,
            logical_size=self._logical_size,
            logical_sha256=logical_sha,
            index_sha256=index_sha,
            index_file_sha256=file_sha.hexdigest(),
        )


def build_index_from_scan(
    freeze: Freeze, corpus_id: str, source_dir: Path, index_path: Path
) -> IndexSummary:
    """Scan Core blk files, select the canonical chain, and publish an index.

    Selection walks backward from the frozen stop hash through previous-header
    links, so side-branch blocks in the same files are ignored. Every source
    is fully hashed (streaming) before any frame is accepted, so same-length
    source replacement is rejected. Frames are re-read in height order to bind
    the logical digest. Full proof-of-work, merkle-root recomputation, and
    coinbase consensus rules are not reimplemented here: they remain owned by
    the Rust validation engines that consume the identical logical byte stream
    (the same bytes the packed archive carries), plus ``classify_census`` for
    script census. This keeps one authoritative consensus owner and avoids a
    divergent second implementation. Consistency: snapshot isolation over a
    quiescent ``source_dir``; the build is idempotent by retrying with a fresh
    destination (existing destinations are never clobbered).
    """
    chosen = product(freeze, corpus_id)
    if not source_dir.is_dir():
        raise ContractError(f"source directory {source_dir} is not a directory")
    _refuse_existing(index_path)
    try:
        names = sorted(entry.name for entry in source_dir.iterdir())
    except OSError as err:
        raise ContractError(
            f"cannot list source directory {source_dir}: {err}"
        ) from err
    blk_names = [name for name in names if _SOURCE_NAME_RE.fullmatch(name) is not None]
    if len(blk_names) == 0:
        raise ContractError(
            f"source directory {source_dir} holds no blkNNNNN.dat files"
        )
    if len(blk_names) > _MAX_SOURCES:
        raise ContractError("source file count exceeds its bound")
    for name in blk_names:
        _check_source_name(name)
    sources: list[IndexSource] = []
    for name in blk_names:
        size, digest = _hash_file(source_dir / name)
        sources.append(IndexSource(name=name, size=size, sha256=digest))
    by_hash: dict[str, _ScanRecord] = {}
    for position, source in enumerate(sources):
        path = _source_path(source_dir, source.name)
        try:
            with open(path, "rb") as handle:
                for meta, payload in iter_frames(handle, freeze.network_magic):
                    block_hash = header_block_hash(payload)
                    prev_display = payload[4:36][::-1].hex()
                    if block_hash in by_hash:
                        raise ContractError(
                            f"duplicate block hash {block_hash} across sources"
                        )
                    by_hash[block_hash] = _ScanRecord(
                        prev=prev_display,
                        source=position,
                        offset=meta.offset,
                        length=meta.payload_length,
                    )
        except OSError as err:
            raise ContractError(f"cannot scan source {source.name}: {err}") from err
    tip = chosen.stop_hash
    if tip not in by_hash:
        raise ContractError(f"{corpus_id} stop hash is absent from the sources")
    reversed_hashes: list[str] = [tip]
    seen: set[str] = {tip}
    cursor = tip
    while cursor != freeze.genesis_hash:
        record = by_hash.get(cursor)
        if record is None:
            raise ContractError(f"canonical chain has a gap at {cursor}")
        cursor = record.prev
        if cursor in seen:
            raise ContractError("canonical chain contains a linkage cycle")
        seen.add(cursor)
        reversed_hashes.append(cursor)
        if len(reversed_hashes) > chosen.block_count:
            raise ContractError(
                f"{corpus_id} canonical chain exceeds the frozen block count"
            )
    if len(reversed_hashes) != chosen.block_count:
        raise ContractError(
            f"{corpus_id} canonical chain length is not the frozen block count"
        )
    ordered = list(reversed(reversed_hashes))
    if ordered[0] != freeze.genesis_hash:
        raise ContractError("canonical chain does not start at genesis")
    writer = IndexWriter(freeze, corpus_id)
    for source in sources:
        writer.add_source(source)
    reader = _SingleSourceReader(source_dir, sources, freeze.network_magic)
    try:
        for height, block_hash in enumerate(ordered):
            record = by_hash.get(block_hash)
            if record is None:
                raise ContractError(f"canonical chain has a gap at height {height}")
            entry = IndexEntry(
                height=height,
                hash=block_hash,
                source=record.source,
                offset=record.offset,
                length=record.length,
            )
            payload = reader.read(entry)
            writer.append(
                payload,
                SourceOffset(source=record.source, offset=record.offset),
                expected_hash=block_hash,
            )
    finally:
        reader.close()
    scratch = _unique_scratch(index_path)
    try:
        with open(scratch, "xb") as index_fh:
            summary = writer.finish(index_fh)
            _synced(index_fh)
    except OSError as err:
        raise ContractError(f"cannot write index scratch file: {err}") from err
    try:
        _commit_scratch(scratch, index_path)
    finally:
        try:
            scratch.unlink(missing_ok=True)
        except OSError as err:
            print(f"warning: cannot remove index scratch file: {err}", file=sys.stderr)
    return summary


def verify_index(freeze: Freeze, index_path: Path, source_dir: Path) -> Product:
    """Fully verify an index against its sources. Pre-hashes every source before accepting frames."""
    doc = _load_index(index_path)
    _check_index_digest(doc)
    chosen = _check_index_against_freeze(freeze, doc)
    for source in doc.sources:
        path = _source_path(source_dir, source.name)
        try:
            actual_size = path.stat().st_size
        except OSError as err:
            raise ContractError(f"cannot stat source {source.name}: {err}") from err
        if actual_size != source.size:
            raise ContractError(f"source {source.name} size does not match the index")
        _, digest = _hash_file(path)
        if digest != source.sha256:
            raise ContractError(f"source {source.name} digest does not match the index")
    logical_sha = hashlib.sha256()
    logical_size = 0
    last_hash: str | None = None
    intervals: dict[int, list[tuple[int, int]]] = {}
    reader = _SingleSourceReader(source_dir, doc.sources, freeze.network_magic)
    try:
        for height, entry in enumerate(doc.entries):
            if entry.height != height:
                raise ContractError("index entries are not in height order")
            payload = reader.read(entry)
            last_hash = _verify_entry_hash(
                freeze, chosen, entry, height, payload, last_hash
            )
            logical_sha.update(freeze.network_magic + struct.pack("<I", entry.length))
            logical_sha.update(payload)
            logical_size += HEADER_LEN + entry.length
            intervals.setdefault(entry.source, []).append(
                (entry.offset, entry.offset + HEADER_LEN + entry.length)
            )
    finally:
        reader.close()
    if logical_size != doc.logical_size:
        raise ContractError("indexed logical size does not match the index")
    if logical_sha.hexdigest() != doc.logical_sha256:
        raise ContractError("indexed logical digest does not match the index")
    for source_index, spans in intervals.items():
        spans.sort()
        previous_end: int | None = None
        for start, end in spans:
            if previous_end is not None and start < previous_end:
                raise ContractError(
                    f"index entries overlap in source {doc.sources[source_index].name!r}"
                )
            previous_end = end
    if last_hash != chosen.stop_hash:
        raise ContractError(
            f"{chosen.corpus_id} indexed tip is not the frozen stop hash"
        )
    return chosen


def iter_indexed_payloads(
    freeze: Freeze, index_path: Path, source_dir: Path
) -> Iterator[tuple[int, str, bytes]]:
    """Yield verified (height, hash, payload) triples in height order.

    Every source is fully hashed (streaming) before the first payload is
    yielded, so same-length replacement is rejected up front. Each payload is
    hash- and linkage-checked before it is yielded. The caller must exhaust the
    iterator: the trailing logical-digest check binds stream identity for the
    comparator, and an abandoned prefix must not be accepted. Retrying is
    idempotent.
    """
    doc = _load_index(index_path)
    _check_index_digest(doc)
    chosen = _check_index_against_freeze(freeze, doc)
    for source in doc.sources:
        path = _source_path(source_dir, source.name)
        try:
            actual_size = path.stat().st_size
        except OSError as err:
            raise ContractError(f"cannot stat source {source.name}: {err}") from err
        if actual_size != source.size:
            raise ContractError(f"source {source.name} size does not match the index")
        _, digest = _hash_file(path)
        if digest != source.sha256:
            raise ContractError(f"source {source.name} digest does not match the index")
    logical_sha = hashlib.sha256()
    logical_size = 0
    last_hash: str | None = None
    intervals: dict[int, list[tuple[int, int]]] = {}
    reader = _SingleSourceReader(source_dir, doc.sources, freeze.network_magic)
    try:
        for height, entry in enumerate(doc.entries):
            if entry.height != height:
                raise ContractError("index entries are not in height order")
            payload = reader.read(entry)
            block_hash = _verify_entry_hash(
                freeze, chosen, entry, height, payload, last_hash
            )
            logical_sha.update(freeze.network_magic + struct.pack("<I", entry.length))
            logical_sha.update(payload)
            logical_size += HEADER_LEN + entry.length
            intervals.setdefault(entry.source, []).append(
                (entry.offset, entry.offset + HEADER_LEN + entry.length)
            )
            last_hash = block_hash
            yield height, block_hash, payload
    finally:
        reader.close()
    if logical_size != doc.logical_size:
        raise ContractError("indexed logical size does not match the index")
    if logical_sha.hexdigest() != doc.logical_sha256:
        raise ContractError("indexed logical digest does not match the index")
    if last_hash != chosen.stop_hash:
        raise ContractError(
            f"{chosen.corpus_id} indexed tip is not the frozen stop hash"
        )
    for source_index, spans in intervals.items():
        spans.sort()
        previous_end: int | None = None
        for start, end in spans:
            if previous_end is not None and start < previous_end:
                raise ContractError(
                    f"index entries overlap in source {doc.sources[source_index].name!r}"
                )
            previous_end = end


def iter_indexed_framed(
    freeze: Freeze, index_path: Path, source_dir: Path
) -> Iterator[bytes]:
    """Yield verified Core-framed records identical to the packed archive bytes."""
    for _, _, payload in iter_indexed_payloads(freeze, index_path, source_dir):
        yield write_frame(payload, freeze.network_magic)


def _unique_scratch(dest: Path) -> Path:
    return dest.parent / f".{dest.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}"


def _refuse_existing(dest: Path) -> None:
    if dest.exists() or dest.is_symlink():
        raise ContractError(f"refusing to replace existing {dest}")


def _commit_scratch(scratch: Path, dest: Path) -> None:
    """Publish an fsynced scratch file with an atomic no-clobber link."""
    if dest.exists() or dest.is_symlink():
        raise ContractError(f"refusing to replace existing {dest}")
    try:
        os.link(scratch, dest)
    except FileExistsError as error:
        raise ContractError(f"refusing to replace existing {dest}") from error
    scratch.unlink()
    directory = os.open(dest.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _synced(fh: BinaryIO) -> None:
    fh.flush()
    os.fsync(fh.fileno())


def _run_writer(
    freeze: Freeze,
    corpus_id: str,
    archive_path: Path,
    manifest_path: Path,
    items: Iterable[tuple[str | None, bytes]],
) -> None:
    if archive_path.resolve() == manifest_path.resolve():
        raise ContractError("archive and manifest paths must differ")
    _refuse_existing(archive_path)
    _refuse_existing(manifest_path)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    archive_scratch = _unique_scratch(archive_path)
    manifest_scratch = _unique_scratch(manifest_path)
    spool_scratch = _unique_scratch(archive_path)
    try:
        with (
            open(archive_scratch, "xb") as archive_fh,
            open(spool_scratch, "x+b") as spool_fh,
            open(manifest_scratch, "xb") as manifest_fh,
        ):
            writer = CorpusWriter(freeze, corpus_id, archive_fh, spool_fh)
            for hash_value, payload in items:
                writer.append(payload, expected_hash=hash_value)
            summary = writer.finish(manifest_fh)
            _synced(archive_fh)
            _synced(manifest_fh)
        _commit_scratch(archive_scratch, archive_path)
        _commit_scratch(manifest_scratch, manifest_path)
    finally:
        archive_scratch.unlink(missing_ok=True)
        manifest_scratch.unlink(missing_ok=True)
        spool_scratch.unlink(missing_ok=True)
    print(f"wrote {archive_path} ({summary.archive_size} bytes)")
    print(f"wrote {manifest_path}")
    print(f"archive sha256 {summary.archive_sha256}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    export_cmd = sub.add_parser("export", help="export a frozen corpus from Core REST")
    export_cmd.add_argument("--rest-url", required=True)
    export_cmd.add_argument("--corpus-id", required=True, choices=("C150", "Cmodern"))
    export_cmd.add_argument("--archive", type=Path, required=True)
    export_cmd.add_argument("--manifest", type=Path, required=True)

    convert_cmd = sub.add_parser(
        "convert", help="convert a length-prefixed archive to Core frames"
    )
    convert_cmd.add_argument("--length-prefixed", type=Path, required=True)
    convert_cmd.add_argument("--corpus-id", required=True, choices=("C150", "Cmodern"))
    convert_cmd.add_argument("--archive", type=Path, required=True)
    convert_cmd.add_argument("--manifest", type=Path, required=True)

    verify_cmd = sub.add_parser("verify", help="bind an archive to its manifest")
    verify_cmd.add_argument("--archive", type=Path, required=True)
    verify_cmd.add_argument("--manifest", type=Path, required=True)

    classify_cmd = sub.add_parser("classify", help="classify a census counter file")
    classify_cmd.add_argument("--contract", required=True, choices=("C150", "Cmodern"))
    classify_cmd.add_argument("--counters", type=Path, required=True)

    build_index_cmd = sub.add_parser(
        "build-index", help="build an indexed corpus over Core blk files"
    )
    build_index_cmd.add_argument(
        "--corpus-id", required=True, choices=("C150", "Cmodern")
    )
    build_index_cmd.add_argument("--source-dir", type=Path, required=True)
    build_index_cmd.add_argument("--index", type=Path, required=True)

    verify_index_cmd = sub.add_parser(
        "verify-index", help="verify an indexed corpus against its sources"
    )
    verify_index_cmd.add_argument("--index", type=Path, required=True)
    verify_index_cmd.add_argument("--source-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    freeze = load_freeze()
    if args.command == "export":
        _run_writer(
            freeze,
            args.corpus_id,
            args.archive,
            args.manifest,
            (
                (advertised, payload)
                for advertised, payload in iter_rest_blocks(
                    freeze, args.corpus_id, args.rest_url
                )
            ),
        )
    elif args.command == "convert":
        with open(args.length_prefixed, "rb") as source:
            _run_writer(
                freeze,
                args.corpus_id,
                args.archive,
                args.manifest,
                ((None, payload) for payload in iter_length_prefixed(source)),
            )
    elif args.command == "verify":
        scratch = _unique_scratch(args.archive)
        try:
            with (
                open(args.archive, "rb") as archive_fh,
                open(args.manifest, "rb") as manifest_fh,
                open(scratch, "w+b") as spool_fh,
            ):
                verify_archive(freeze, archive_fh, manifest_fh, entries=spool_fh)
        finally:
            scratch.unlink(missing_ok=True)
        print(f"verified {args.manifest}")
    elif args.command == "classify":
        result = classify_census(freeze, args.contract, _load_json(args.counters))
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    elif args.command == "build-index":
        summary = build_index_from_scan(
            freeze, args.corpus_id, args.source_dir, args.index
        )
        print(f"wrote {args.index} ({summary.logical_size} bytes logical)")
        print(f"logical sha256 {summary.logical_sha256}")
        print(f"index sha256 {summary.index_sha256}")
    elif args.command == "verify-index":
        verify_index(freeze, args.index, args.source_dir)
        print(f"verified {args.index}")
    return 0


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
    )


def _reject_duplicates(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate object member")
        result[key] = value
    return result


def _hostport(value: str) -> tuple[str, int]:
    text = value.removeprefix("http://")
    if ":" not in text:
        raise ContractError("REST URL must be host:port")
    host, port_text = text.rsplit(":", 1)
    if not host or "/" in host:
        raise ContractError("REST URL must be a host:port with no path")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ContractError("REST URL port is not an integer") from error
    return host, port


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _hash(value: str) -> str:
    text = value.strip().lower()
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ContractError("value is not a 64-character hex hash")
    return text


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return value


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _u32(value: object, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 0xFFFFFFFF
    ):
        raise ContractError(f"{label} must be a u32")
    return value


def _u64(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
