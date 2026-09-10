#!/usr/bin/env python3
"""Contract tests for the C150 / Cmodern campaign corpus freeze.

The codec seam under test is the streaming interface: ``iter_frames`` /
``iter_length_prefixed`` / ``iter_rest_blocks`` consume caller-owned binary
streams, ``CorpusWriter`` appends through caller-owned binary streams, and
``verify_archive`` streams a manifest against an archive. Golden archive and
manifest bytes below are established independently in this file (struct
packing plus hashlib over the documented canonical-JSON form), never by
calling the writer under test to produce its own expectations.
"""

import contextlib
import hashlib
import io
import json
import os
import struct
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import corpus
from corpus import ContractError


C150_HASH = "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"
CMODERN_HASH = "00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f"
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
MUHASH = "383a0b41ac28ddf6ac91723b41527fa64c0b54451cee5f2c4b3823ef92117116"

MAGIC = bytes.fromhex("f9beb4d9")
ZERO64 = "0" * 64
MAX_PAYLOAD = 4_000_000
FIX_CORPUS = "C150"  # CLI argparse freezes --corpus-id to C150|Cmodern

# Independently established fixture identity for a three-block linked chain.
# Headers wire prev-block fields in raw digest order per plan §6
# (payload[4:36] == bytes.fromhex(previous_display_hash)[::-1]).
FIX_B1_HASH = "d10e6a5ce499ddd1c36164524c5de23b38f79e629ccab44144dd5bca15924ffd"
FIX_STOP_HASH = "581ac1506032e49032c84833827981b2825444062eaee54a0937f3c842c0c9de"
FIX_ARCHIVE_SHA256 = "6d73b2a1eb0f37607150070fab846a5b4f0830bab5c3ff842a12d9f51aa5bc24"
FIX_MANIFEST_SHA256 = "c605331cf26541da440d07aaba44f088b7219c29a324e8d5192decda947b791a"
FIX_MANIFEST_FILE_SHA256 = "f9f5cd66a463490ab5361f43d17abbc6812fd89523aee6afe281d8e70689e739"
FIX_ARCHIVE_SIZE = 264


# ---------------------------------------------------------------------------
# Independent fixture construction (no corpus.py involvement).
# ---------------------------------------------------------------------------


def _dsha(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _display(payload: bytes) -> str:
    return _dsha(payload[:80])[::-1].hex()


def _header(version: int, prev_digest: bytes, merkle_hex: str, time: int, bits: int, nonce: int) -> bytes:
    return (
        struct.pack("<I", version)
        + prev_digest
        + bytes.fromhex(merkle_hex)
        + struct.pack("<III", time, bits, nonce)
    )


def _frame(payload: bytes, magic: bytes = MAGIC) -> bytes:
    return magic + struct.pack("<I", len(payload)) + payload


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_GENESIS = _header(
    1,
    bytes(32),
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
    1231006505,
    0x1D00FFFF,
    2083236893,
)
_BLOCK1 = _header(1, _dsha(_GENESIS), "11" * 32, 1231006506, 0x1D00FFFF, 4)
_BLOCK2 = _header(1, _dsha(_BLOCK1), "22" * 32, 1231006507, 0x1D00FFFF, 5)
_LINKED = (_GENESIS, _BLOCK1, _BLOCK2)
_EXPECTED_HASHES = (GENESIS_HASH, FIX_B1_HASH, FIX_STOP_HASH)
if [_display(block) for block in _LINKED] != list(_EXPECTED_HASHES):  # pragma: no cover - fixture guard
    raise AssertionError("linked fixture headers drifted from their pinned hashes")


def _golden_archive() -> bytes:
    return b"".join(_frame(payload) for payload in _LINKED)


def _golden_doc() -> dict[str, object]:
    return {
        "schema": "bitcoin-rs-corpus-manifest",
        "version": 1,
        "corpus_id": FIX_CORPUS,
        "network": "mainnet",
        "network_magic": "f9beb4d9",
        "genesis_hash": GENESIS_HASH,
        "range": {"start_height": 0, "stop_height": 2},
        "source_tip_hash": FIX_STOP_HASH,
        "archive": {"size": FIX_ARCHIVE_SIZE, "sha256": FIX_ARCHIVE_SHA256},
        "entries": [
            {"height": 0, "hash": GENESIS_HASH, "offset": 0, "payload_length": 80},
            {"height": 1, "hash": FIX_B1_HASH, "offset": 88, "payload_length": 80},
            {"height": 2, "hash": FIX_STOP_HASH, "offset": 176, "payload_length": 80},
        ],
        "manifest_sha256": FIX_MANIFEST_SHA256,
    }


def _digest_over(doc: dict[str, object]) -> str:
    preimage = dict(doc)
    preimage["manifest_sha256"] = ZERO64
    return _sha256_hex(_canonical(preimage))


_GOLDEN_ARCHIVE = _golden_archive()
_GOLDEN_MANIFEST = _canonical(_golden_doc()) + b"\n"
if _digest_over(_golden_doc()) != FIX_MANIFEST_SHA256:  # pragma: no cover - fixture guard
    raise AssertionError("golden manifest digest drifted from its pinned constant")
if _sha256_hex(_GOLDEN_ARCHIVE) != FIX_ARCHIVE_SHA256:  # pragma: no cover - fixture guard
    raise AssertionError("golden archive digest drifted from its pinned constant")
if _sha256_hex(_GOLDEN_MANIFEST) != FIX_MANIFEST_FILE_SHA256:  # pragma: no cover - fixture guard
    raise AssertionError("golden manifest file digest drifted from its pinned constant")


def _golden_manifest_bytes() -> bytes:
    return _canonical(_golden_doc()) + b"\n"


def _expected_entries() -> list[dict[str, object]]:
    return _golden_doc()["entries"]  # type: ignore[return-value]


def _branch_header(prev_digest: bytes, merkle_seed: str, nonce: int) -> bytes:
    return _header(1, prev_digest, merkle_seed, 1231006508, 0x1D00FFFF, nonce)


def _write_products(directory: Path) -> Path:
    document = {
        "schema": "bitcoin-rs-campaign-corpora-v1",
        "network": "mainnet",
        "network_magic": "f9beb4d9",
        "genesis_hash": GENESIS_HASH,
        "validation": {"assume_valid_height": 0},
        "census_specials": ["taproot_key_path_spends", "p2sh_redeem_spends"],
        "core_oracle": {"hash_type": "muhash", "implementation": "Bitcoin Core 31.1", "use_index": True},
        "products": {
            FIX_CORPUS: {
                "stop_height": 2,
                "stop_hash": FIX_STOP_HASH,
                "block_count": 3,
                "census": {"specials": "none"},
                "state": {
                    "txouts": 1,
                    "total_amount_sat": 50,
                    "muhash": "ab" * 32,
                    "bestblock": FIX_STOP_HASH,
                    "oracle": "core_gettxoutsetinfo_muhash_at_stop",
                },
            }
        },
    }
    path = directory / "products.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def _fixture_freeze(directory: Path):
    return corpus.load_freeze(path=_write_products(directory))


_ORIGINAL_PRODUCTS_PATH = corpus.PRODUCTS_PATH


@contextlib.contextmanager
def _isolated_products():
    """Point the CLI at an isolated synthetic products.json for one test."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        products = _write_products(root)
        original_loader = corpus.load_freeze
        corpus.PRODUCTS_PATH = products
        corpus.load_freeze = lambda path=None: original_loader(products if path is None else path)
        try:
            yield root
        finally:
            corpus.load_freeze = original_loader
            corpus.PRODUCTS_PATH = _ORIGINAL_PRODUCTS_PATH


class _ShortReads(io.RawIOBase):
    """Readable stream whose read() may return fewer bytes than requested."""

    def __init__(self, data: bytes, chunk: int) -> None:
        self._buf = io.BytesIO(data)
        self._chunk = chunk

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._chunk
        return self._buf.read(min(size, self._chunk))

    def readinto(self, buffer) -> int:  # type: ignore[override]
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


class _RecordingReads:
    """Readable stream that records every requested read size."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)
        self.requests: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        return self._buf.read(size)

    def readinto(self, buffer) -> int:
        # A BufferedReader-wrapping implementation would otherwise read the
        # whole stream through this unrecorded path.
        self.requests.append(len(buffer))
        return self._buf.readinto(buffer)

    def __getattr__(self, name: str):
        return getattr(self._buf, name)


class _FlakyWrites:
    """Writable stream wrapper that can inject a partial write then fail."""

    def __init__(self, stream: io.BufferedIOBase) -> None:
        self._stream = stream
        self.poisoned = False

    def write(self, data) -> int:
        if self.poisoned:
            self.poisoned = False
            if len(data) > 1:
                self._stream.write(data[: len(data) // 2])
            raise OSError("injected partial write failure")
        return self._stream.write(data)

    def __getattr__(self, name: str):
        return getattr(self._stream, name)


class _ShortWrites:
    """Writable stream wrapper that succeeds after writing only a short prefix."""

    def __init__(self, stream: io.BufferedIOBase, chunk: int) -> None:
        self._stream = stream
        self._chunk = chunk

    def write(self, data) -> int:
        return self._stream.write(data[: self._chunk])

    def __getattr__(self, name: str):
        return getattr(self._stream, name)


class _RestHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        server = self.server
        if self.path.startswith("/rest/blockhashbyheight/"):
            height = int(self.path.rsplit("/", 1)[1].split(".", 1)[0])
            self._respond(200, server.advertised(height).encode("ascii") + b"\n")
        elif self.path.startswith("/rest/block/"):
            token = self.path.rsplit("/", 1)[1].split(".", 1)[0]
            payload = server.block_for(token)
            if payload is None:
                self._respond(404, b"not found")
                return
            if server.on_block is not None:
                server.on_block()
            self._respond(200, payload)
        else:
            self._respond(404, b"not found")

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _RestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, blocks, advertised=None, fallback=None, on_block=None) -> None:
        self._blocks = blocks
        self._advertised = advertised or {}
        self._by_hash = {_display(block): block for block in blocks.values()}
        self._fallback = fallback
        self.on_block = on_block
        super().__init__(("127.0.0.1", 0), _RestHandler)

    def advertised(self, height: int) -> str:
        return self._advertised.get(height, _display(self._blocks[height]))

    def block_for(self, token: str):
        if token in self._by_hash:
            return self._by_hash[token]
        return self._fallback


@contextlib.contextmanager
def _rest_server(blocks, advertised=None, fallback=None, on_block=None):
    server = _RestServer(blocks, advertised=advertised, fallback=fallback, on_block=on_block)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextlib.contextmanager
def _writer_streams(root: Path, name: str):
    archive_path = root / f"{name}.archive"
    entries_path = root / f"{name}.entries"
    with archive_path.open("w+b") as archive, entries_path.open("w+b") as entries:
        yield archive, entries, archive_path, entries_path


def _finish_to(root: Path, writer, name: str):
    manifest_path = root / f"{name}.manifest"
    with manifest_path.open("w+b") as manifest:
        summary = writer.finish(manifest)
        manifest.flush()
    return summary, manifest_path.read_bytes()


def _verify(freeze, root: Path, manifest: bytes, archive: bytes | None = None):
    archive_bytes = _GOLDEN_ARCHIVE if archive is None else archive
    archive_path = root / "verify.archive"
    manifest_path = root / "verify.manifest"
    archive_path.write_bytes(archive_bytes)
    manifest_path.write_bytes(manifest)
    with archive_path.open("rb") as a, manifest_path.open("rb") as m, (root / "verify.spool").open("w+b") as spool:
        return corpus.verify_archive(freeze, a, m, entries=spool)


def _c150_counters(**overrides: object) -> dict[str, object]:
    freeze = corpus.load_freeze()
    counters: dict[str, object] = {
        "context_count": 2_868_199,
        "ffi_verify_entries": 2_868_199,
        "eval_script_entries": 5_736_398,
        "op_checksig": 2_868_199,
        "op_checksigverify": 0,
        "op_checkmultisig": 0,
        "op_checkmultisigverify": 0,
        "op_checksigadd": 0,
        "checkschnorr_entries": 0,
        "schnorr_verify_calls": 0,
    }
    for name in freeze.census_specials:
        counters[name] = 0
    counters.update(overrides)
    return counters


def _cmodern_counters(**overrides: object) -> dict[str, object]:
    freeze = corpus.load_freeze()
    counters: dict[str, object] = {
        "checkschnorr_entries": 4,
        "schnorr_verify_calls": 3,
        "schnorr_verify_ok": 3,
        "schnorr_verify_fail": 0,
    }
    for index, name in enumerate(freeze.census_specials, start=1):
        counters[name] = index
    counters.update(overrides)
    return counters


# ---------------------------------------------------------------------------
# Frozen freeze pins (real products.json, unchanged contracts).
# ---------------------------------------------------------------------------


class FreezePins(unittest.TestCase):
    def setUp(self) -> None:
        self.freeze = corpus.load_freeze()

    def test_exactly_two_product_corpora(self) -> None:
        self.assertEqual(set(self.freeze.products), {"C150", "Cmodern"})

    def test_c150_tip_and_state(self) -> None:
        c150 = self.freeze.products["C150"]
        self.assertEqual(c150.stop_height, 150_000)
        self.assertEqual(c150.stop_hash, C150_HASH)
        self.assertEqual(c150.block_count, 150_001)
        self.assertEqual(c150.state["txouts"], 1_127_181)
        self.assertEqual(c150.state["total_amount_sat"], 749_989_998_999_999)
        self.assertEqual(c150.state["muhash"], MUHASH)
        self.assertEqual(c150.state["bestblock"], C150_HASH)

    def test_cmodern_tip_is_first_full_coverage_height(self) -> None:
        cmodern = self.freeze.products["Cmodern"]
        self.assertEqual(cmodern.stop_height, 709_635)
        self.assertEqual(cmodern.stop_hash, CMODERN_HASH)
        self.assertEqual(cmodern.block_count, 709_636)
        self.assertEqual(cmodern.census["specials"], "all_positive")
        self.assertEqual(cmodern.state["oracle"], "core_gettxoutsetinfo_muhash_at_stop")

    def test_validation_posture_and_oracle(self) -> None:
        self.assertEqual(self.freeze.assume_valid_height, 0)
        self.assertEqual(self.freeze.network, "mainnet")
        self.assertEqual(self.freeze.genesis_hash, GENESIS_HASH)
        self.assertEqual(self.freeze.network_magic, MAGIC)
        self.assertEqual(self.freeze.core_oracle["implementation"], "Bitcoin Core 31.1")
        self.assertEqual(corpus.core_oracle_params(self.freeze, "C150"), ["muhash", 150_000, True])
        self.assertEqual(corpus.core_oracle_params(self.freeze, "Cmodern"), ["muhash", 709_635, True])

    def test_eleven_named_special_contexts(self) -> None:
        self.assertEqual(len(self.freeze.census_specials), 11)
        self.assertIn("taproot_key_path_spends", self.freeze.census_specials)
        self.assertIn("tapscript_checksigadd_checks", self.freeze.census_specials)
        self.assertIn("p2sh_redeem_spends", self.freeze.census_specials)


# ---------------------------------------------------------------------------
# Streaming framing.
# ---------------------------------------------------------------------------


class Framing(unittest.TestCase):
    def test_genesis_header_hash(self) -> None:
        self.assertEqual(corpus.header_block_hash(_GENESIS), GENESIS_HASH)

    def test_fixture_prev_fields_follow_wire_order(self) -> None:
        # Plan §6 linkage: payload[4:36] == bytes.fromhex(prev_display)[::-1].
        # Pure struct/hashlib so a fixture error never masquerades as a
        # corpus.py failure.
        self.assertEqual(_BLOCK1[4:36], bytes.fromhex(GENESIS_HASH)[::-1])
        self.assertEqual(_BLOCK2[4:36], bytes.fromhex(FIX_B1_HASH)[::-1])

    def test_iter_frames_streams_frames_and_offsets(self) -> None:
        frames = list(corpus.iter_frames(io.BytesIO(_GOLDEN_ARCHIVE)))
        self.assertEqual(len(frames), 3)
        self.assertEqual([meta.offset for meta, _ in frames], [0, 88, 176])
        self.assertEqual([meta.payload_length for meta, _ in frames], [80, 80, 80])
        self.assertEqual([payload for _, payload in frames], list(_LINKED))

    def test_iter_frames_survives_short_reads(self) -> None:
        for chunk in (1, 3, 7):
            with self.subTest(chunk=chunk):
                frames = list(corpus.iter_frames(_ShortReads(_GOLDEN_ARCHIVE, chunk)))
                self.assertEqual([payload for _, payload in frames], list(_LINKED))

    def test_iter_frames_clean_eof_ends_iteration(self) -> None:
        self.assertEqual(list(corpus.iter_frames(io.BytesIO(b""))), [])
        self.assertEqual(list(corpus.iter_frames(_ShortReads(b"", 4))), [])

    def test_iter_frames_rejects_wrong_magic(self) -> None:
        archive = _frame(_GENESIS, magic=b"TEST")
        with self.assertRaises(ContractError):
            list(corpus.iter_frames(io.BytesIO(archive)))

    def test_iter_frames_rejects_truncated_header(self) -> None:
        for cut in (1, 4, 7):
            with self.subTest(cut=cut):
                with self.assertRaises(ContractError):
                    list(corpus.iter_frames(io.BytesIO(_GOLDEN_ARCHIVE[:cut])))

    def test_iter_frames_rejects_truncated_payload(self) -> None:
        with self.assertRaises(ContractError):
            list(corpus.iter_frames(io.BytesIO(_GOLDEN_ARCHIVE[:88 - 1])))
        with self.assertRaises(ContractError):
            list(corpus.iter_frames(io.BytesIO(_GOLDEN_ARCHIVE[:-1])))

    def test_iter_frames_rejects_oversize_length_before_payload_read(self) -> None:
        oversized = MAGIC + struct.pack("<I", 0xFFFFFFFF)
        stream = _RecordingReads(oversized)
        with self.assertRaises(ContractError):
            list(corpus.iter_frames(stream))
        self.assertTrue(stream.requests)
        self.assertTrue(all(0 < size <= 8 for size in stream.requests))

    def test_iter_frames_read_requests_are_bounded(self) -> None:
        stream = _RecordingReads(_GOLDEN_ARCHIVE)
        frames = list(corpus.iter_frames(stream))
        self.assertEqual(len(frames), 3)
        # No request may exceed one frame header (8) or one declared payload
        # (80); a whole-file read request would show up here.
        self.assertTrue(all(0 < size <= 88 for size in stream.requests), stream.requests)

    def test_iter_length_prefixed_round_trips_payloads(self) -> None:
        payloads = [_GENESIS, b"q" * 80, _BLOCK1]
        blob = b"".join(struct.pack("<I", len(item)) + item for item in payloads)
        recovered = list(corpus.iter_length_prefixed(io.BytesIO(blob)))
        self.assertEqual(recovered, payloads)

    def test_iter_length_prefixed_survives_short_reads(self) -> None:
        payloads = [_GENESIS, b"q" * 80]
        blob = b"".join(struct.pack("<I", len(item)) + item for item in payloads)
        recovered = list(corpus.iter_length_prefixed(_ShortReads(blob, 2)))
        self.assertEqual(recovered, payloads)

    def test_iter_length_prefixed_rejects_truncation(self) -> None:
        payload = b"z" * 40
        blob = struct.pack("<I", len(payload)) + payload
        for cut in (1, 2, 3, len(blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(ContractError):
                    list(corpus.iter_length_prefixed(io.BytesIO(blob[:cut])))

    def test_iter_length_prefixed_rejects_oversize_before_payload_read(self) -> None:
        stream = _RecordingReads(struct.pack("<I", 0xFFFFFFFF))
        with self.assertRaises(ContractError):
            list(corpus.iter_length_prefixed(stream))
        self.assertTrue(all(0 < size <= 4 for size in stream.requests))


# ---------------------------------------------------------------------------
# CorpusWriter append/finish invariants.
# ---------------------------------------------------------------------------


class WriterContract(unittest.TestCase):
    def test_writer_emits_golden_archive_manifest_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "full") as (archive, entries, archive_path, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                metas = [
                    writer.append(payload, expected_hash=expected)
                    for payload, expected in zip(_LINKED, _EXPECTED_HASHES)
                ]
                self.assertEqual(
                    [(meta.offset, meta.payload_length) for meta in metas],
                    [(0, 80), (88, 80), (176, 80)],
                )
                summary, manifest_bytes = _finish_to(root, writer, "full")
                archive.flush()
                self.assertEqual(archive_path.read_bytes(), _GOLDEN_ARCHIVE)
                self.assertEqual(manifest_bytes, _GOLDEN_MANIFEST)
                self.assertEqual(summary.count, 3)
                self.assertEqual(summary.archive_size, FIX_ARCHIVE_SIZE)
                self.assertEqual(summary.archive_sha256, FIX_ARCHIVE_SHA256)
                self.assertEqual(summary.manifest_sha256, FIX_MANIFEST_SHA256)
                self.assertEqual(summary.manifest_file_sha256, FIX_MANIFEST_FILE_SHA256)

    def test_prefix_facts_report_committed_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "facts") as (archive, entries, _, entries_path):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                zero = writer.prefix_facts()
                self.assertEqual(zero.count, 0)
                self.assertIsNone(zero.last_hash)
                writer.append(_GENESIS, expected_hash=GENESIS_HASH)
                facts = writer.prefix_facts()
                archive.flush()
                entries.flush()
                self.assertEqual(facts.count, 1)
                self.assertEqual(facts.archive_bytes, 88)
                self.assertEqual(facts.last_hash, GENESIS_HASH)
                self.assertEqual(facts.archive_prefix_sha256, _sha256_hex(_frame(_GENESIS)))
                self.assertEqual(facts.entries_bytes, len(_canonical(_expected_entries()[0])) + 1)
                self.assertEqual(
                    facts.entries_prefix_sha256,
                    _sha256_hex(_canonical(_expected_entries()[0]) + b"\n"),
                )

    def test_writer_refuses_oversize_payload(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "big") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                with self.assertRaises(ContractError):
                    writer.append(b"\x00" * (MAX_PAYLOAD + 1))
                self.assertEqual(writer.prefix_facts().count, 0)

    def test_writer_refuses_payload_without_complete_header(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "short") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                with self.assertRaises(ContractError):
                    writer.append(b"short")
                self.assertEqual(writer.prefix_facts().count, 0)

    def test_writer_requires_frozen_genesis_first(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "gen") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                with self.assertRaises(ContractError):
                    writer.append(_BLOCK1, expected_hash=FIX_B1_HASH)
                self.assertEqual(writer.prefix_facts().count, 0)

    def test_writer_refuses_branch_mixed_middle_linkage(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "link") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                writer.append(_GENESIS, expected_hash=GENESIS_HASH)
                writer.append(_BLOCK1, expected_hash=FIX_B1_HASH)
                # Links to genesis instead of block 1: a branch-mixed middle.
                stray = _branch_header(_dsha(_GENESIS), "33" * 32, 6)
                with self.assertRaises(ContractError):
                    writer.append(stray)
                self.assertEqual(writer.prefix_facts().count, 2)

    def test_writer_refuses_stop_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "stop") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                writer.append(_GENESIS, expected_hash=GENESIS_HASH)
                writer.append(_BLOCK1, expected_hash=FIX_B1_HASH)
                impostor = _branch_header(_dsha(_BLOCK1), "44" * 32, 7)
                with self.assertRaises(ContractError):
                    writer.append(impostor)
                self.assertEqual(writer.prefix_facts().count, 2)

    def test_writer_refuses_append_past_frozen_stop(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "past") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                for payload, expected in zip(_LINKED, _EXPECTED_HASHES):
                    writer.append(payload, expected_hash=expected)
                extra = _branch_header(_dsha(_BLOCK2), "55" * 32, 8)
                with self.assertRaises(ContractError):
                    writer.append(extra)
                self.assertEqual(writer.prefix_facts().count, 3)

    def test_writer_refuses_advertised_hash_mismatch_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "adv") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                with self.assertRaises(ContractError):
                    writer.append(_GENESIS, expected_hash="ff" * 32)
                facts = writer.prefix_facts()
                self.assertEqual(facts.count, 0)
                self.assertEqual(facts.archive_bytes, 0)

    def test_finish_refuses_prefix_as_complete_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with _writer_streams(root, "prefix") as (archive, entries, _, _):
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                writer.append(_GENESIS, expected_hash=GENESIS_HASH)
                writer.append(_BLOCK1, expected_hash=FIX_B1_HASH)
                with self.assertRaises(ContractError):
                    _finish_to(root, writer, "prefix")

    def test_unknown_corpus_is_refused_everywhere(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            with self.assertRaises(ContractError):
                corpus.product(freeze, "GHOST")
            with _writer_streams(root, "ghost") as (archive, entries, _, _):
                with self.assertRaises(ContractError):
                    corpus.CorpusWriter(freeze, "GHOST", archive, entries)


# ---------------------------------------------------------------------------
# Prefix facts, resume, and tail custody.
# ---------------------------------------------------------------------------


class ResumeContract(unittest.TestCase):
    def test_resume_at_every_boundary_matches_uninterrupted_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            for boundary in range(4):
                with self.subTest(boundary=boundary):
                    with _writer_streams(root, f"resume{boundary}") as (
                        archive,
                        entries,
                        archive_path,
                        _,
                    ):
                        writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                        zero = writer.prefix_facts()
                        self.assertEqual(zero.count, 0)
                        self.assertIsNone(zero.last_hash)
                        for height, payload in enumerate(_LINKED):
                            if height == boundary:
                                archive.flush()
                                entries.flush()
                                writer = corpus.CorpusWriter.resume(
                                    freeze, FIX_CORPUS, archive, entries, writer.prefix_facts()
                                )
                            writer.append(payload, expected_hash=_EXPECTED_HASHES[height])
                        if boundary == 3:
                            archive.flush()
                            entries.flush()
                            writer = corpus.CorpusWriter.resume(
                                freeze, FIX_CORPUS, archive, entries, writer.prefix_facts()
                            )
                        summary, manifest_bytes = _finish_to(root, writer, f"resume{boundary}")
                        archive.flush()
                        self.assertEqual(archive_path.read_bytes(), _GOLDEN_ARCHIVE)
                        self.assertEqual(manifest_bytes, _GOLDEN_MANIFEST)
                        self.assertEqual(summary.count, 3)
                        self.assertEqual(summary.archive_sha256, FIX_ARCHIVE_SHA256)
                        self.assertEqual(summary.manifest_sha256, FIX_MANIFEST_SHA256)
                        self.assertEqual(summary.manifest_file_sha256, FIX_MANIFEST_FILE_SHA256)

    def _full_prefix(self, root: Path, name: str):
        freeze = _fixture_freeze(root)
        context = _writer_streams(root, name)
        archive, entries, archive_path, entries_path = context.__enter__()
        writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
        for payload, expected in zip(_LINKED, _EXPECTED_HASHES):
            writer.append(payload, expected_hash=expected)
        archive.flush()
        entries.flush()
        return freeze, context, writer, archive_path, entries_path

    def test_resume_rejects_corrupt_committed_archive_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze, context, writer, archive_path, entries_path = self._full_prefix(root, "corrupt")
            try:
                facts = writer.prefix_facts()
                with archive_path.open("r+b") as handle:
                    handle.seek(8)
                    handle.write(b"\xff")
                with archive_path.open("r+b") as archive, entries_path.open("r+b") as entries:
                    with self.assertRaises(ContractError):
                        corpus.CorpusWriter.resume(freeze, FIX_CORPUS, archive, entries, facts)
            finally:
                context.__exit__(None, None, None)

    def test_resume_rejects_corrupt_entry_spool(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze, context, writer, archive_path, entries_path = self._full_prefix(root, "spool")
            try:
                facts = writer.prefix_facts()
                spool = entries_path.read_bytes()
                tampered = spool.replace(GENESIS_HASH.encode("ascii"), b"ab" * 32, 1)
                self.assertEqual(len(tampered), len(spool))
                entries_path.write_bytes(tampered)
                with archive_path.open("r+b") as archive, entries_path.open("r+b") as entries:
                    with self.assertRaises(ContractError):
                        corpus.CorpusWriter.resume(freeze, FIX_CORPUS, archive, entries, facts)
            finally:
                context.__exit__(None, None, None)

    def test_resume_rejects_mismatched_recorded_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze, context, writer, archive_path, entries_path = self._full_prefix(root, "record")
            try:
                facts = writer.prefix_facts()
                mutations = {
                    "count": replace(facts, count=2),
                    "last_hash": replace(facts, last_hash="ff" * 32),
                    "archive_prefix_sha256": replace(facts, archive_prefix_sha256="cd" * 32),
                    "entries_prefix_sha256": replace(facts, entries_prefix_sha256="ef" * 32),
                    "archive_bytes_short_file": replace(facts, archive_bytes=facts.archive_bytes + 1),
                    "entries_bytes_short_file": replace(facts, entries_bytes=facts.entries_bytes + 1),
                }
                for label, recorded in mutations.items():
                    with self.subTest(recorded=label):
                        with archive_path.open("r+b") as archive, entries_path.open("r+b") as entries:
                            with self.assertRaises(ContractError):
                                corpus.CorpusWriter.resume(freeze, FIX_CORPUS, archive, entries, recorded)
            finally:
                context.__exit__(None, None, None)

    def test_resume_leaves_tail_untouched_until_caller_truncates(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze, context, writer, archive_path, entries_path = self._full_prefix(root, "tail")
            try:
                # A one-block checkpoint hand-derived from the documented
                # PrefixFacts semantics, older than the three-block files.
                checkpoint = replace(
                    writer.prefix_facts(),
                    count=1,
                    archive_bytes=88,
                    entries_bytes=len(_canonical(_expected_entries()[0])) + 1,
                    last_hash=GENESIS_HASH,
                    archive_prefix_sha256=_sha256_hex(_frame(_GENESIS)),
                    entries_prefix_sha256=_sha256_hex(_canonical(_expected_entries()[0]) + b"\n"),
                )
                size_before = (archive_path.stat().st_size, entries_path.stat().st_size)
                with archive_path.open("r+b") as archive, entries_path.open("r+b") as entries:
                    resumed = corpus.CorpusWriter.resume(freeze, FIX_CORPUS, archive, entries, checkpoint)
                    # Resume verifies but never truncates: files keep their tails.
                    self.assertEqual(
                        (archive_path.stat().st_size, entries_path.stat().st_size), size_before
                    )
                    # The uncommitted tail is not appendable until the caller truncates.
                    with self.assertRaises(ContractError):
                        resumed.append(_BLOCK1, expected_hash=FIX_B1_HASH)
                    self.assertEqual(
                        (archive_path.stat().st_size, entries_path.stat().st_size), size_before
                    )
                    archive.truncate(checkpoint.archive_bytes)
                    entries.truncate(checkpoint.entries_bytes)
                    resumed.append(_BLOCK1, expected_hash=FIX_B1_HASH)
                    resumed.append(_BLOCK2, expected_hash=FIX_STOP_HASH)
                    summary, manifest_bytes = _finish_to(root, resumed, "tail-final")
                self.assertEqual(archive_path.read_bytes(), _GOLDEN_ARCHIVE)
                self.assertEqual(manifest_bytes, _GOLDEN_MANIFEST)
                self.assertEqual(summary.manifest_sha256, FIX_MANIFEST_SHA256)
            finally:
                context.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# Partial-write poisoning.
# ---------------------------------------------------------------------------


class PartialWrite(unittest.TestCase):
    def test_poisoned_append_keeps_committed_prefix_and_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            freeze = _fixture_freeze(root)
            archive_path = root / "poison.archive"
            entries_path = root / "poison.entries"
            backing_archive = archive_path.open("w+b")
            backing_entries = entries_path.open("w+b")
            archive = _FlakyWrites(backing_archive)
            entries = _FlakyWrites(backing_entries)
            try:
                writer = corpus.CorpusWriter(freeze, FIX_CORPUS, archive, entries)
                writer.append(_GENESIS, expected_hash=GENESIS_HASH)
                writer.append(_BLOCK1, expected_hash=FIX_B1_HASH)
                facts = writer.prefix_facts()
                archive.poisoned = True
                with self.assertRaises(OSError):
                    writer.append(_BLOCK2, expected_hash=FIX_STOP_HASH)
                # The failed append is not a commit: the cursor is unchanged.
                self.assertEqual(writer.prefix_facts(), facts)
                backing_archive.flush()
                self.assertGreater(archive_path.stat().st_size, facts.archive_bytes)
                # An old valid checkpoint may discard the poisoned tail, but the
                # coordinator (here, the test) owns the truncation.
                resumed = corpus.CorpusWriter.resume(freeze, FIX_CORPUS, archive, entries, facts)
                with self.assertRaises(ContractError):
                    resumed.append(_BLOCK2, expected_hash=FIX_STOP_HASH)
                archive.truncate(facts.archive_bytes)
                entries.truncate(facts.entries_bytes)
                resumed.append(_BLOCK2, expected_hash=FIX_STOP_HASH)
                # The caller owns the streams: drain its buffer before reading
                # the file back through a separate handle.
                backing_archive.flush()
                backing_entries.flush()
                summary, manifest_bytes = _finish_to(root, resumed, "poison-final")
                self.assertEqual(archive_path.read_bytes(), _GOLDEN_ARCHIVE)
                self.assertEqual(manifest_bytes, _GOLDEN_MANIFEST)
                self.assertEqual(summary.archive_sha256, FIX_ARCHIVE_SHA256)
            finally:
                backing_archive.close()
                backing_entries.close()


# ---------------------------------------------------------------------------
# Verifier schema: exact fields, types, duplicates, digests, linkage.
# ---------------------------------------------------------------------------


class ManifestSchema(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.freeze = _fixture_freeze(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_golden_manifest_verifies_and_returns_product(self) -> None:
        product = _verify(self.freeze, self.root, _GOLDEN_MANIFEST)
        self.assertEqual(product.corpus_id, FIX_CORPUS)
        self.assertEqual(product.stop_height, 2)
        self.assertEqual(product.stop_hash, FIX_STOP_HASH)

    def test_reordered_whitespace_and_escapes_preserve_digest(self) -> None:
        text = json.dumps(_golden_doc(), indent=2)
        text = text.replace('"mainnet"', '"mai\\u006enet"')
        self.assertNotEqual(text.encode("ascii"), _GOLDEN_MANIFEST)
        product = _verify(self.freeze, self.root, text.encode("ascii") + b"\n\n")
        self.assertEqual(product.corpus_id, FIX_CORPUS)

    # Hex fields keep their fixed-size domain across case; schema, network,
    # and corpus strings are known constants and stay lowercase.
    _HEX_FIELDS = frozenset(
        {"hash", "sha256", "genesis_hash", "source_tip_hash", "network_magic", "manifest_sha256"}
    )

    @classmethod
    def _with_uppercase_hex(cls, value: object) -> object:
        if isinstance(value, dict):
            return {
                key: value[key].upper()
                if key in cls._HEX_FIELDS
                else cls._with_uppercase_hex(value[key])
                for key in value
            }
        if isinstance(value, list):
            return [cls._with_uppercase_hex(item) for item in value]
        return value

    def test_uppercase_hex_is_accepted_with_digest_over_decoded_originals(self) -> None:
        doc = self._with_uppercase_hex(json.loads(_GOLDEN_MANIFEST.decode("ascii")))
        doc["manifest_sha256"] = _digest_over(doc)
        product = _verify(self.freeze, self.root, json.dumps(doc, indent=1).encode("ascii"))
        self.assertEqual(product.stop_hash, FIX_STOP_HASH)

    def test_digest_is_not_computed_from_normalized_lowercase_copies(self) -> None:
        # Uppercase-hex document carrying the lowercase-computed digest:
        # accepting it would mean the verifier hashed a normalized replacement
        # document instead of the accepted decoded values.
        doc = self._with_uppercase_hex(json.loads(_GOLDEN_MANIFEST.decode("ascii")))
        doc["manifest_sha256"] = FIX_MANIFEST_SHA256
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, json.dumps(doc).encode("ascii"))

    def test_extra_root_member_is_rejected_even_with_matching_digest(self) -> None:
        doc = _golden_doc()
        doc["extra"] = "ignored-by-old-verifier"
        doc["manifest_sha256"] = _digest_over(doc)
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, _canonical(doc) + b"\n")

    def test_extra_nested_member_is_rejected(self) -> None:
        for label, mutate in (
            ("range", lambda doc: doc["range"].update({"extra": 1})),
            ("archive", lambda doc: doc["archive"].update({"note": "x"})),
            ("entry", lambda doc: doc["entries"][1].update({"kind": "block"})),
        ):
            with self.subTest(member=label):
                doc = _golden_doc()
                mutate(doc)
                doc["manifest_sha256"] = _digest_over(doc)
                with self.assertRaises(ContractError):
                    _verify(self.freeze, self.root, _canonical(doc) + b"\n")

    def test_missing_member_is_rejected(self) -> None:
        doc = _golden_doc()
        del doc["source_tip_hash"]
        doc["manifest_sha256"] = _digest_over(doc)
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, _canonical(doc) + b"\n")

    def test_duplicate_members_are_rejected(self) -> None:
        canonical = _GOLDEN_MANIFEST.decode("ascii")
        root_dup = canonical.replace(
            '"network":"mainnet"', '"network":"mainnet","network":"mainnet"', 1
        )
        self.assertNotEqual(root_dup, canonical)
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, root_dup.encode("ascii"))
        entry_dup = canonical.replace(
            '"hash":"' + FIX_B1_HASH + '","height":1',
            '"hash":"' + FIX_B1_HASH + '","height":1,"height":1',
            1,
        )
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, entry_dup.encode("ascii"))

    def test_float_and_bool_integer_aliases_are_rejected(self) -> None:
        for label, mutate in (
            ("version-float", lambda doc: doc.update({"version": 1.0})),
            ("version-bool", lambda doc: doc.update({"version": True})),
            ("start-float", lambda doc: doc["range"].update({"start_height": 0.0})),
            ("size-float", lambda doc: doc["archive"].update({"size": float(FIX_ARCHIVE_SIZE)})),
            ("length-float", lambda doc: doc["entries"][2].update({"payload_length": 80.0})),
        ):
            with self.subTest(alias=label):
                doc = _golden_doc()
                mutate(doc)
                doc["manifest_sha256"] = _digest_over(doc)
                with self.assertRaises(ContractError):
                    _verify(self.freeze, self.root, _canonical(doc) + b"\n")

    def test_leading_zero_json_integer_is_rejected(self) -> None:
        canonical = _GOLDEN_MANIFEST.decode("ascii")
        malformed = canonical.replace('"version":1', '"version":01', 1)
        self.assertNotEqual(malformed, canonical)
        # Decoding 01 as integer 1 would reproduce the same canonical
        # preimage and therefore pass the digest check. JSON itself forbids it.
        with self.assertRaisesRegex(ContractError, "leading-zero JSON integer"):
            _verify(self.freeze, self.root, malformed.encode("ascii"))

    def test_manifest_entry_spool_survives_successful_short_writes(self) -> None:
        archive = io.BytesIO(_GOLDEN_ARCHIVE)
        manifest = io.BytesIO(_GOLDEN_MANIFEST)
        backing = io.BytesIO()
        spool = _ShortWrites(backing, 3)
        product = corpus.verify_archive(self.freeze, archive, manifest, entries=spool)
        self.assertEqual(product.corpus_id, FIX_CORPUS)
        backing.seek(0)
        lines = backing.readlines()
        self.assertEqual(len(lines), len(_expected_entries()))
        self.assertTrue(all(line.endswith(b"\n") for line in lines))

    def test_out_of_domain_scalars_are_rejected(self) -> None:
        for label, mutate in (
            ("version", lambda doc: doc.update({"version": 2})),
            ("stop-height", lambda doc: doc["range"].update({"stop_height": 3})),
            ("magic-length", lambda doc: doc.update({"network_magic": "f9beb4d90"})),
            ("magic-not-hex", lambda doc: doc.update({"network_magic": "f9beb4zz"})),
            ("hash-length", lambda doc: doc.update({"genesis_hash": GENESIS_HASH[:63]})),
            ("hash-padded", lambda doc: doc.update({"genesis_hash": " " + GENESIS_HASH})),
            ("hash-not-hex", lambda doc: doc.update({"source_tip_hash": "zz" * 32})),
        ):
            with self.subTest(scalar=label):
                doc = _golden_doc()
                mutate(doc)
                doc["manifest_sha256"] = _digest_over(doc)
                with self.assertRaises(ContractError):
                    _verify(self.freeze, self.root, _canonical(doc) + b"\n")

    def test_trailing_content_is_rejected_but_trailing_whitespace_is_not(self) -> None:
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, _GOLDEN_MANIFEST + b" trailing")
        product = _verify(self.freeze, self.root, _GOLDEN_MANIFEST + b"\n \n")
        self.assertEqual(product.stop_height, 2)

    def test_tampered_archive_fails_verification(self) -> None:
        tampered = bytearray(_GOLDEN_ARCHIVE)
        tampered[10] ^= 0x01
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, _GOLDEN_MANIFEST, bytes(tampered))

    def test_branch_mixed_middle_is_rejected_despite_matching_genesis_and_stop(self) -> None:
        # Frames [genesis, stray, stop]: a fully self-consistent manifest for a
        # chain whose middle block does not link to its predecessor.
        stray = _branch_header(_dsha(_BLOCK2), "66" * 32, 9)
        payloads = [_GENESIS, stray, _BLOCK2]
        archive = b"".join(_frame(payload) for payload in payloads)
        doc = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "corpus_id": FIX_CORPUS,
            "network": "mainnet",
            "network_magic": "f9beb4d9",
            "genesis_hash": GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 2},
            "source_tip_hash": FIX_STOP_HASH,
            "archive": {"size": len(archive), "sha256": _sha256_hex(archive)},
            "entries": [
                {"height": height, "hash": _display(payload), "offset": 88 * height, "payload_length": 80}
                for height, payload in enumerate(payloads)
            ],
            "manifest_sha256": ZERO64,
        }
        doc["manifest_sha256"] = _digest_over(doc)
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, _canonical(doc) + b"\n", archive)

    def test_wrong_entry_count_is_rejected(self) -> None:
        doc = _golden_doc()
        doc["entries"] = doc["entries"][:2]
        doc["manifest_sha256"] = _digest_over(doc)
        with self.assertRaises(ContractError):
            _verify(self.freeze, self.root, _canonical(doc) + b"\n")

    def _forged_c150_doc(self, freeze) -> dict[str, object]:
        archive = _frame(_GENESIS)
        doc = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "corpus_id": "C150",
            "network": freeze.network,
            "network_magic": freeze.network_magic.hex(),
            "genesis_hash": freeze.genesis_hash,
            "range": {"start_height": 0, "stop_height": 150_000},
            "source_tip_hash": C150_HASH,
            "archive": {"size": len(archive), "sha256": _sha256_hex(archive)},
            "entries": [{"height": 0, "hash": GENESIS_HASH, "offset": 0, "payload_length": 80}],
            "manifest_sha256": ZERO64,
        }
        doc["manifest_sha256"] = _digest_over(doc)
        return doc

    def test_forged_real_freeze_document_is_rejected(self) -> None:
        freeze = corpus.load_freeze()
        doc = self._forged_c150_doc(freeze)
        # Digest-consistent but claiming one block for a 150,001-block corpus.
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(ContractError):
                _verify(freeze, Path(raw), _canonical(doc) + b"\n", _frame(_GENESIS))

    def test_digest_tamper_is_rejected(self) -> None:
        freeze = corpus.load_freeze()
        doc = self._forged_c150_doc(freeze)
        doc["source_tip_hash"] = "ff" * 32
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(ContractError):
                _verify(freeze, Path(raw), _canonical(doc) + b"\n", _frame(_GENESIS))


# ---------------------------------------------------------------------------
# Ordinary command publication: refusal, no-clobber, foreign tempfiles.
# ---------------------------------------------------------------------------


def _write_convert_input(root: Path) -> Path:
    blob = b"".join(struct.pack("<I", len(payload)) + payload for payload in _LINKED)
    path = root / "input.lengthprefixed"
    path.write_bytes(blob)
    return path


def _convert_args(archive: Path, manifest: Path, input_path: Path) -> list[str]:
    return [
        "convert",
        "--length-prefixed",
        str(input_path),
        "--corpus-id",
        FIX_CORPUS,
        "--archive",
        str(archive),
        "--manifest",
        str(manifest),
    ]


class Publication(unittest.TestCase):
    def test_convert_round_trips_golden_bytes_and_stdout(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            archive = root / "out.archive"
            manifest = root / "out.manifest"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                status = corpus.main(_convert_args(archive, manifest, input_path))
            self.assertEqual(status, 0)
            self.assertEqual(archive.read_bytes(), _GOLDEN_ARCHIVE)
            self.assertEqual(manifest.read_bytes(), _GOLDEN_MANIFEST)
            self.assertIn(FIX_ARCHIVE_SHA256, buffer.getvalue())
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                status = corpus.main(["verify", "--archive", str(archive), "--manifest", str(manifest)])
            self.assertEqual(status, 0)
            self.assertIn("verified", buffer.getvalue())

    def test_verify_cli_rejects_tampered_manifest(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            archive = root / "out.archive"
            manifest = root / "out.manifest"
            with redirect_stdout(io.StringIO()):
                corpus.main(_convert_args(archive, manifest, input_path))
            tampered = bytearray(manifest.read_bytes())
            tampered[-10] ^= 0x01  # a hex digit inside manifest_sha256
            manifest.write_bytes(bytes(tampered))
            with self.assertRaises(ContractError):
                corpus.main(["verify", "--archive", str(archive), "--manifest", str(manifest)])

    def test_existing_archive_file_is_refused_unchanged(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            archive = root / "kept.archive"
            manifest = root / "new.manifest"
            archive.write_bytes(b"keep")
            with self.assertRaises(ContractError):
                corpus.main(_convert_args(archive, manifest, input_path))
            self.assertEqual(archive.read_bytes(), b"keep")
            self.assertFalse(manifest.exists())

    def test_existing_manifest_directory_is_refused_before_publication(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            archive = root / "late.archive"
            manifest = root / "dir.manifest"
            manifest.mkdir()
            with self.assertRaises(ContractError):
                corpus.main(_convert_args(archive, manifest, input_path))
            self.assertFalse(archive.exists())

    def test_dangling_symlink_destination_is_refused(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            archive = root / "link.archive"
            manifest = root / "plain.manifest"
            os.symlink(root / "missing.target", archive)
            with self.assertRaises(ContractError):
                corpus.main(_convert_args(archive, manifest, input_path))
            self.assertTrue(archive.is_symlink())
            self.assertFalse((root / "missing.target").exists())
            self.assertFalse(manifest.exists())

    def test_symlink_to_existing_file_is_refused_and_target_untouched(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            target = root / "target.bin"
            target.write_bytes(b"target")
            archive = root / "alias.archive"
            manifest = root / "plain2.manifest"
            os.symlink(target, archive)
            with self.assertRaises(ContractError):
                corpus.main(_convert_args(archive, manifest, input_path))
            self.assertEqual(target.read_bytes(), b"target")

    def test_archive_and_manifest_must_differ(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            same = root / "same.out"
            with self.assertRaises(ContractError):
                corpus.main(_convert_args(same, same, input_path))

    def test_output_must_not_alias_the_conversion_input(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            original = input_path.read_bytes()
            with self.assertRaises(ContractError):
                corpus.main(_convert_args(input_path, root / "m.out", input_path))
            self.assertEqual(input_path.read_bytes(), original)

    def test_foreign_temp_file_is_preserved(self) -> None:
        with _isolated_products() as root:
            input_path = _write_convert_input(root)
            archive = root / "preserved.archive"
            manifest = root / "preserved.manifest"
            foreign = root / "preserved.archive.tmp"
            foreign.write_bytes(b"foreign")
            with redirect_stdout(io.StringIO()):
                corpus.main(_convert_args(archive, manifest, input_path))
            self.assertEqual(foreign.read_bytes(), b"foreign")
            self.assertEqual(archive.read_bytes(), _GOLDEN_ARCHIVE)

    def test_export_via_loopback_rest_matches_golden(self) -> None:
        with _isolated_products() as root:
            blocks = {0: _GENESIS, 1: _BLOCK1, 2: _BLOCK2}
            with _rest_server(blocks) as rest_url:
                archive = root / "rest.archive"
                manifest = root / "rest.manifest"
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    status = corpus.main(
                        [
                            "export",
                            "--rest-url",
                            rest_url,
                            "--corpus-id",
                            FIX_CORPUS,
                            "--archive",
                            str(archive),
                            "--manifest",
                            str(manifest),
                        ]
                    )
            self.assertEqual(status, 0)
            self.assertEqual(archive.read_bytes(), _GOLDEN_ARCHIVE)
            self.assertEqual(manifest.read_bytes(), _GOLDEN_MANIFEST)
            self.assertIn(FIX_ARCHIVE_SHA256, buffer.getvalue())

    def test_export_refuses_advertised_hash_mismatch(self) -> None:
        with _isolated_products() as root:
            blocks = {0: _GENESIS, 1: _BLOCK1, 2: _BLOCK2}
            advertised = {1: "ff" * 32}
            with _rest_server(blocks, advertised=advertised, fallback=_BLOCK1) as rest_url:
                archive = root / "mismatch.archive"
                manifest = root / "mismatch.manifest"
                with self.assertRaises(ContractError):
                    corpus.main(
                        [
                            "export",
                            "--rest-url",
                            rest_url,
                            "--corpus-id",
                            FIX_CORPUS,
                            "--archive",
                            str(archive),
                            "--manifest",
                            str(manifest),
                        ]
                    )
            self.assertFalse(archive.exists())
            self.assertFalse(manifest.exists())

    def test_export_never_clobbers_destination_appearing_mid_export(self) -> None:
        with _isolated_products() as root:
            blocks = {0: _GENESIS, 1: _BLOCK1, 2: _BLOCK2}
            archive = root / "race.archive"
            manifest = root / "race.manifest"
            racer = b"competitor wrote first"

            def appear_mid_export() -> None:
                if not archive.exists():
                    archive.write_bytes(racer)

            with _rest_server(blocks, on_block=appear_mid_export) as rest_url:
                with self.assertRaises(ContractError):
                    corpus.main(
                        [
                            "export",
                            "--rest-url",
                            rest_url,
                            "--corpus-id",
                            FIX_CORPUS,
                            "--archive",
                            str(archive),
                            "--manifest",
                            str(manifest),
                        ]
                    )
            self.assertEqual(archive.read_bytes(), racer)
            self.assertFalse(manifest.exists())


# ---------------------------------------------------------------------------
# REST source generator.
# ---------------------------------------------------------------------------


class RestSource(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.freeze = _fixture_freeze(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_iter_rest_blocks_yields_advertised_pairs_in_height_order(self) -> None:
        blocks = {0: _GENESIS, 1: _BLOCK1, 2: _BLOCK2}
        with _rest_server(blocks) as rest_url:
            pairs = list(corpus.iter_rest_blocks(self.freeze, FIX_CORPUS, rest_url))
        self.assertEqual(pairs, list(zip(_EXPECTED_HASHES, _LINKED)))

    def test_iter_rest_blocks_rejects_oversize_injected_payload(self) -> None:
        def fetch(path: str) -> bytes:
            if path.startswith("/rest/blockhashbyheight/"):
                return (GENESIS_HASH + "\n").encode("ascii")
            return b"\x00" * (MAX_PAYLOAD + 1)

        with self.assertRaises(ContractError):
            list(corpus.iter_rest_blocks(self.freeze, FIX_CORPUS, "127.0.0.1:1", fetch=fetch))

    def test_rest_fetch_rejects_non_200_status(self) -> None:
        with _rest_server({}) as rest_url:
            with self.assertRaises(ContractError):
                corpus.rest_fetch(rest_url, "/rest/block/missing.bin")

    def test_rest_fetch_rejects_hostport_with_path(self) -> None:
        with self.assertRaises(ContractError):
            corpus.rest_fetch("127.0.0.1:8332/rest", "/rest/block/x.bin")


# ---------------------------------------------------------------------------
# Census classification (unchanged contracts).
# ---------------------------------------------------------------------------


class Census(unittest.TestCase):
    def test_c150_historical_census_passes(self) -> None:
        freeze = corpus.load_freeze()
        result = corpus.classify_census(freeze, "C150", _c150_counters())
        self.assertTrue(result["c150_passed"])
        self.assertTrue(result["all_passed"])
        self.assertEqual(result["stop_hash"], C150_HASH)

    def test_c150_rejects_nonzero_special(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(ContractError):
            corpus.classify_census(freeze, "C150", _c150_counters(p2sh_redeem_spends=1))

    def test_c150_rejects_wrong_ordinary_count(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(ContractError):
            corpus.classify_census(freeze, "C150", _c150_counters(op_checksig=1))

    def test_cmodern_requires_every_special_positive(self) -> None:
        freeze = corpus.load_freeze()
        result = corpus.classify_census(freeze, "Cmodern", _cmodern_counters())
        self.assertTrue(result["cmodern_passed"])
        self.assertEqual(result["stop_height"], 709_635)

    def test_cmodern_rejects_a_zero_special(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(ContractError):
            corpus.classify_census(
                freeze, "Cmodern", _cmodern_counters(tapscript_checksigadd_checks=0)
            )

    def test_cmodern_rejects_missing_special(self) -> None:
        freeze = corpus.load_freeze()
        counters = _cmodern_counters()
        del counters["tapscript_spends"]
        with self.assertRaises(ContractError):
            corpus.classify_census(freeze, "Cmodern", counters)

    def test_classify_cli_emits_c150_passed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "counters.json"
            path.write_bytes(corpus.canonical_json(_c150_counters()) + b"\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                status = corpus.main(
                    ["classify", "--contract", "C150", "--counters", str(path)]
                )
            self.assertEqual(status, 0)
            self.assertIn("c150_passed", buf.getvalue())

    def test_cmodern_rejects_broken_schnorr_equation(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(ContractError):
            corpus.classify_census(
                freeze,
                "Cmodern",
                _cmodern_counters(schnorr_verify_calls=9, schnorr_verify_ok=1, schnorr_verify_fail=1),
            )


if __name__ == "__main__":
    unittest.main()
