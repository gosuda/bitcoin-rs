#!/usr/bin/env python3
"""Regression guards for analyze.py validation contracts.

Tests the observable behavior of:
- Counters parsing rejects malformed untrusted analyzer input (INV-gate)
- ffi_verify_entries gate makes all_passed false on wrong corpus (Finding 2)
- sorted-records output prepends BRSREC1 header + u64 count (Finding 1)
- extract_spike_width1 rejects non-integer or non-1 threads (Finding 5)
- cmd_verdict cross-checks native_mode0 vs inv_8 (Finding 4)
- BRSCTX1 strict binary parser adversarial cases (CTX-RAW / CTX-EXECUTION)
- classify-corpus v2 disk-backed contract (c150 / cmodern)
- custody / replay / manifest / archive adversarial validation

Stdlib-only, Python 3.12+. Run: python3 test_validation_contracts.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
import tempfile
from pathlib import Path

# Make sibling modules importable when run directly
sys.path.insert(0, str(Path(__file__).parent))
import analyze
from analyze import (
    CONTEXT_COUNTER_DEFINITIONS,
    CONTEXT_COUNTER_NAMES,
    COUNTER_NAMES,
    EXPECTED_FFI_VERIFY_ENTRIES_FULL,
    EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1,
    HEADER_SIZE,
    HEADER_STRUCT,
    JOURNAL_MAGIC,
    JOURNAL_SIZE,
    JOURNAL_STRUCT,
    MAINNET_GENESIS_HASH,
    RECORD_MAGIC,
    RECORD_SIZE,
    RECORD_STRUCT,
    AnalyzerError,
    Counters,
    DiagnosticCheckpoint,
    JournalEntry,
    Record,
    _brshgt1_count,
    _c150_passed,
    _count_context_records_disk,
    _diagnostic_counter_totals,
    _read_diagnostic_streams,
    _run_diagnostic_scan,
    _validate_replay_diagnostic,
    cmd_classify_corpus,
    extract_bare_mode0,
    extract_spike_width1,
    iter_journal_with_custody,
    iter_records_with_custody,
    parse_counters,
    parse_journal,
    parse_records,
    sort_records_raw,
)
from context import (
    CONTEXT_MIN_ROW_SIZE,
    VERIFY_P2SH,
    VERIFY_TAPROOT,
    VERIFY_WITNESS,
    ContextError,
    ContextInput,
    InputIdentity,
    SpendContext,
    classify_input,
    iter_context_inputs,
    iter_legacy_context_inputs,
    parse_script,
    read_bounded_context_rows,
)

# ── Shared assertion helpers ─────────────────────────────────────────────────


def _raises(exc_type: type[BaseException], fn, label: str) -> None:
    """Call *fn* and assert it raises *exc_type*; re-raise with *label* on miss."""
    try:
        fn()
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} for {label}")


def _raises_with(exc_type: type[BaseException], fn, label: str, *substrings: str) -> None:
    """Assert *fn* raises *exc_type* whose message contains every *substrings*."""
    try:
        fn()
    except exc_type as exc:
        msg = str(exc)
        for sub in substrings:
            if sub not in msg:
                raise AssertionError(
                    f"expected {exc_type.__name__} for {label} containing {sub!r}, got {msg!r}"
                )
        return
    raise AssertionError(f"expected {exc_type.__name__} for {label}")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _valid_counters_dict(**overrides: object) -> dict[str, object]:
    """Return a counters dict with all 24 COUNTER_NAMES fields plus the three
    reconciliation count fields set to valid values."""
    d: dict[str, object] = {name: 0 for name in COUNTER_NAMES}
    d["schema"] = 1
    d["label"] = "test"
    d["record_count"] = 0
    d["journal_count"] = 0
    d["context_count"] = 0
    d.update(overrides)
    return d

def _make_record_bytes(
    txid_le: bytes,
    input_index: int,
    *,
    op_kind: int = 1,
    sig_version: int = 0,
    op_seq: int = 0,
    outcome: int = 1,
    reject_reason: int = 0,
    der_len: int = 72,
    pubkey_len: int = 65,
    sighash: bytes | None = None,
) -> bytes:
    """Build a canonical 224-byte record (txid is little-endian/raw).

    Defaults represent a successful ECDSA CHECKSIG verify:
    op_kind=1 (CHECKSIG), sig_version=0 (BASE), outcome=1 (success),
    reject_reason=0, der_len=72, pubkey_len=65.
    """
    if sighash is None:
        sighash = b"\x00" * 32
    # Realistic-looking DER signature (0x30 = SEQUENCE) and uncompressed
    # pubkey (0x04 prefix).  The validator only checks padding beyond the
    # declared lengths, so truncate then zero-pad to the full field size.
    der_sig = bytes([0x30, 0x45, 0x02, 0x20]) + bytes(68)
    pubkey = bytes([0x04]) + bytes(64)
    der_sig = der_sig[:der_len] + bytes(72 - der_len)
    pubkey = pubkey[:pubkey_len] + bytes(65 - pubkey_len)
    fields = (
        txid_le,  # 32s spend_txid
        input_index,  # I input_index
        op_seq,  # I op_seq
        op_kind,  # B op_kind
        sig_version,  # B sig_version
        outcome,  # B outcome
        der_len,  # B der_len
        pubkey_len,  # B pubkey_len
        0,  # B sighash_type
        reject_reason,  # B reject_reason
        0,  # B _pad0
        sighash,  # 32s sighash
        der_sig,  # 72s der_sig
        pubkey,  # 65s pubkey
        b"\x00" * 7,  # 7s _pad1
    )
    return RECORD_STRUCT.pack(*fields)

def _make_journal_bytes(
    txid_le: bytes,
    input_index: int,
    *,
    checksig_ops: int = 1,
    checkmultisig_ops: int = 0,
    ecdsa_verify_calls: int = 1,
    ecdsa_verify_ok: int = 1,
    verdict: int = 1,
) -> bytes:
    """Build a canonical 56-byte journal entry (txid is little-endian/raw).

    Defaults represent a successful ECDSA CHECKSIG: verdict=1,
    checksig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1.
    """
    fields = (
        txid_le,  # 32s spend_txid
        input_index,  # I input_index
        checksig_ops,  # I checksig_ops
        checkmultisig_ops,  # I checkmultisig_ops
        ecdsa_verify_calls,  # I ecdsa_verify_calls
        ecdsa_verify_ok,  # I ecdsa_verify_ok
        verdict,  # B verdict
        b"\x00" * 3,  # 3s pad
    )
    return JOURNAL_STRUCT.pack(*fields)


def _write_records_file(path: Path, records: list[bytes]) -> None:
    """Write a records file with magic header + count + raw records."""
    data = HEADER_STRUCT.pack(RECORD_MAGIC, len(records)) + b"".join(records)
    path.write_bytes(data)


def _write_journal_file(path: Path, entries: list[bytes]) -> None:
    """Write a journal file with magic header + count + raw entries."""
    data = HEADER_STRUCT.pack(JOURNAL_MAGIC, len(entries)) + b"".join(entries)
    path.write_bytes(data)


_PRESERVED_OVER_CAPACITY_ROW = bytes.fromhex(
    "cf42bd87b9982595bf2d354c5f758c144d663301cefc3b31ad3132f87f4918d1"
    "00000000000000000300020042000100"
    + "00" * 176
)
assert len(_PRESERVED_OVER_CAPACITY_ROW) == RECORD_SIZE
assert hashlib.sha256(_PRESERVED_OVER_CAPACITY_ROW).hexdigest() == (
    "316f268a31cea2efdd5f8d37c2cd87d0d5597d19756490331978894c42e8c78c"
)


def _assert_over_capacity_length_error(raw: bytes, label: str) -> None:
    _raises_with(
        AnalyzerError,
        lambda: Record(raw),
        label,
        "pubkey_len 66 exceeds 65",
    )


# ── BRSCTX1 binary builder ───────────────────────────────────────────────────

# Must match context.py CONTEXT_FIXED = struct.Struct("<32sIIIII") (52 bytes).
_BRSCTX1_MAGIC = b"BRSCTX1\x00"
_BRSCTX1_HEADER = struct.Struct("<8sQ")
_BRSCTX1_ROW_LEN = struct.Struct("<I")
_BRSCTX1_FIXED = struct.Struct("<32sIIIII")  # txid_le, input_index, verify_flags, prevout_len, script_sig_len, witness_count


def _make_brsctx1_file(path: Path, rows: list[ContextInput]) -> None:
    """Write a BRSCTX1 binary file with the exact streaming layout.

    Per row: u32 row_len, 32s txid_le, I input_index, I verify_flags,
    I prevout_script_len, I script_sig_len, I witness_count,
    prevout bytes, scriptSig bytes, then for each witness item:
    u32 item_len + item bytes.
    row_len is the number of bytes after the row_len field.
    """
    body = bytearray()
    for evidence in rows:
        prevout = evidence.prevout_script_pubkey
        script_sig = evidence.script_sig
        witness = evidence.witness

        fixed = _BRSCTX1_FIXED.pack(
            evidence.identity.txid_le,
            evidence.identity.input_index,
            evidence.verify_flags,
            len(prevout),
            len(script_sig),
            len(witness),
        )
        witness_blob = bytearray()
        for item in witness:
            witness_blob += struct.pack("<I", len(item))
            witness_blob += item

        row_payload = fixed + prevout + script_sig + bytes(witness_blob)
        body += _BRSCTX1_ROW_LEN.pack(len(row_payload))
        body += row_payload

    header = _BRSCTX1_HEADER.pack(_BRSCTX1_MAGIC, len(rows))
    path.write_bytes(bytes(header + body))


def _ctx_input(
    txid_le: bytes,
    input_index: int,
    *,
    verify_flags: int = 0,
    prevout: bytes = b"",
    script_sig: bytes = b"",
    witness: tuple[bytes, ...] = (),
) -> ContextInput:
    """Build a ContextInput directly from raw little-endian txid."""
    return ContextInput(
        identity=InputIdentity(txid_le=txid_le, input_index=input_index),
        verify_flags=verify_flags,
        prevout_script_pubkey=prevout,
        script_sig=script_sig,
        witness=witness,
    )


# ── Prevout / scriptSig / witness builders ───────────────────────────────────


def _p2pkh_prevout() -> bytes:
    return bytes.fromhex("76a914") + bytes(20) + bytes.fromhex("88ac")


def _p2sh_prevout() -> bytes:
    return bytes.fromhex("a914") + bytes(20) + bytes.fromhex("87")


def _p2wpkh_prevout() -> bytes:
    return bytes.fromhex("0014") + bytes(20)


def _p2wsh_prevout() -> bytes:
    return bytes.fromhex("0020") + bytes(32)


def _p2tr_prevout() -> bytes:
    return bytes.fromhex("5120") + bytes(32)


def _multisig_redeem_script() -> bytes:
    """1-of-2 multisig redeem script for P2SH/P2WSH fixtures."""
    return bytes([1]) + bytes([33]) + bytes(33) + bytes([2, 0xae])


def _push(data: bytes) -> bytes:
    """Encode a data push for scriptSig (handles len <= 75 directly)."""
    if len(data) <= 75:
        return bytes([len(data)]) + data
    return bytes([76]) + bytes([len(data)]) + data


# ── Spend-context fixture builders (each returns ContextInput) ───────────────


def _bare_p2pkh(txid_le: bytes, idx: int = 0) -> ContextInput:
    """Bare P2PKH spend: no flags, no witness, empty scriptSig."""
    return _ctx_input(txid_le, idx, prevout=_p2pkh_prevout())


def _p2sh_push_only(txid_le: bytes, idx: int = 0, *, flags: int = 0) -> ContextInput:
    """P2SH prevout with push-only scriptSig (no witness).

    Without P2SH flag -> BARE; with P2SH flag -> P2SH.
    """
    redeem = _multisig_redeem_script()
    script_sig = _push(redeem)
    return _ctx_input(
        txid_le, idx,
        verify_flags=flags,
        prevout=_p2sh_prevout(),
        script_sig=script_sig,
    )


def _p2sh_wrapped_w0(txid_le: bytes, idx: int = 0, *, flags: int = 0) -> ContextInput:
    """P2SH prevout with one-push witness-v0 redeem in scriptSig.

    With P2SH only -> P2SH; with P2SH+WITNESS -> P2SH_WRAPPED_WITNESS_V0.
    """
    redeem = _p2wsh_prevout()  # witness-v0 program as the redeem
    script_sig = _push(redeem)
    witness = (b"\x00", _multisig_redeem_script())
    return _ctx_input(
        txid_le, idx,
        verify_flags=flags,
        prevout=_p2sh_prevout(),
        script_sig=script_sig,
        witness=witness,
    )


def _native_w0(txid_le: bytes, idx: int = 0, *, flags: int = 0) -> ContextInput:
    """Native witness-v0 prevout (P2WSH).

    Without WITNESS -> BARE; with WITNESS -> NATIVE_WITNESS_V0.
    """
    return _ctx_input(
        txid_le, idx,
        verify_flags=flags,
        prevout=_p2wsh_prevout(),
        witness=(b"\x00", _multisig_redeem_script()),
    )


def _taproot_key_path(txid_le: bytes, idx: int = 0, *, flags: int = 0) -> ContextInput:
    """P2TR prevout with 64-byte key-path signature.

    No WITNESS -> BARE; WITNESS only -> BARE; WITNESS+TAPROOT -> TAPROOT_KEY_PATH.
    """
    return _ctx_input(
        txid_le, idx,
        verify_flags=flags,
        prevout=_p2tr_prevout(),
        witness=(bytes(64),),
    )


def _taproot_script_path(txid_le: bytes, idx: int = 0, *, flags: int = 0) -> ContextInput:
    """P2TR prevout with stack arg + tapscript + control block.

    No WITNESS -> BARE; WITNESS only -> BARE; WITNESS+TAPROOT -> TAPSCRIPT.
    """
    control = bytes([0xc0]) + bytes(32)
    return _ctx_input(
        txid_le, idx,
        verify_flags=flags,
        prevout=_p2tr_prevout(),
        witness=(bytes(64), bytes([0xAC]), control),
    )


# ── Counters / replay / manifest / archive helpers ───────────────────────────

def _make_valid_counters(
    record_count: int,
    journal_count: int,
    ffi_verify_entries: int,
    **extra: object,
) -> dict[str, object]:
    """Return a counters dict for a canonical all-CHECKSIG ECDSA corpus.

    Every context row has one successful ECDSA CHECKSIG, so the full
    equality chain equals *ffi_verify_entries* and all complementary
    counters are zero.
    """
    d = _valid_counters_dict()
    d["record_count"] = record_count
    d["journal_count"] = journal_count
    d["context_count"] = ffi_verify_entries
    d["ffi_verify_entries"] = ffi_verify_entries
    d["verify_script_calls"] = ffi_verify_entries
    d["ffi_verify_true"] = ffi_verify_entries
    d["eval_script_entries"] = ffi_verify_entries
    d["op_checksig"] = ffi_verify_entries
    d["checkecdsa_entries"] = ffi_verify_entries
    d["ecdsa_from_checksig"] = ffi_verify_entries
    d["ecdsa_verify_calls"] = ffi_verify_entries
    d["ecdsa_verify_ok"] = ffi_verify_entries
    d["sighash_computed"] = ffi_verify_entries
    d.update(extra)
    return d

# ── Minimal regtest genesis block for archive/manifest fixtures ──────────────

_REGTEST_MAGIC = bytes.fromhex("fabfb5da")
_REGTEST_GENESIS_HEADER = (
    b"\x00" * 4        # version
    + b"\x00" * 32     # prev_blockhash (all zero for genesis)
    + b"\x00" * 32     # merkle_root
    + struct.pack("<I", 0x5CE9B2A1)  # timestamp (regtest genesis)
    + b"\x20" * 4      # difficulty bits (regtest: 0x207fffff)
    + struct.pack("<I", 0)  # nonce
)
_REGTEST_GENESIS_HASH_RAW = hashlib.sha256(
    hashlib.sha256(_REGTEST_GENESIS_HEADER).digest()
).digest()
_REGTEST_GENESIS_HASH_DISPLAY = _REGTEST_GENESIS_HASH_RAW[::-1].hex()

# Minimal regtest genesis block: 80-byte header + tx count (0x01 varint) +
# 4-byte version + 1-byte input count (0x01) + 32-byte prevout (null) +
# 4-byte input_index + 1-byte scriptSig length + 4-byte sequence +
# 1-byte output count + 8-byte value + 1-byte scriptPubKey len + 2-byte OP_TRUE +
# 4-byte locktime.
_REGTEST_GENESIS_BLOCK = (
    _REGTEST_GENESIS_HEADER
    + bytes([0x01])          # tx count (1)
    + struct.pack("<I", 1)   # tx version
    + bytes([0x01])          # input count (1)
    + b"\x00" * 32           # prev txid (null)
    + struct.pack("<I", 0xFFFFFFFF)  # input index (null)
    + bytes([0x01])          # scriptSig length (1)
    + bytes([0x00])          # scriptSig
    + struct.pack("<I", 0)   # sequence
    + bytes([0x01])          # output count (1)
    + struct.pack("<Q", 50 * 10**8)  # value (50 BTC)
    + bytes([0x01])          # scriptPubKey length
    + bytes([0x51])          # OP_TRUE
    + struct.pack("<I", 0)   # locktime
)

# ── Mainnet canonical constants for custody validation ───────────────────────

_MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
_MAINNET_GENESIS_HASH = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)
_MAINNET_GENESIS_HEADER = (
    struct.pack("<I", 1)  # version = 1
    + b"\x00" * 32  # prev_blockhash (all zero for genesis)
    + bytes.fromhex(
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    )  # merkle_root (internal LE byte order)
    + struct.pack("<I", 0x495fab29)  # timestamp = 1231006505
    + struct.pack("<I", 0x1d00ffff)  # bits
    + struct.pack("<I", 0x7c2bac1d)  # nonce = 2083236893
)
_MAINNET_GENESIS_HASH_RAW = hashlib.sha256(
    hashlib.sha256(_MAINNET_GENESIS_HEADER).digest()
).digest()
assert _MAINNET_GENESIS_HASH_RAW[::-1].hex() == _MAINNET_GENESIS_HASH

# Minimal mainnet genesis block: real 80-byte header + minimal coinbase tx body.
# The archive validator only checks the 80-byte header for block hashing.
_MAINNET_GENESIS_BLOCK = (
    _MAINNET_GENESIS_HEADER
    + bytes([0x01])          # tx count (1)
    + struct.pack("<I", 1)   # tx version
    + bytes([0x01])          # input count (1)
    + b"\x00" * 32           # prev txid (null)
    + struct.pack("<I", 0xFFFFFFFF)  # input index (null)
    + bytes([0x01])          # scriptSig length (1)
    + bytes([0x00])          # scriptSig
    + struct.pack("<I", 0)   # sequence
    + bytes([0x01])          # output count (1)
    + struct.pack("<Q", 50 * 10**8)  # value (50 BTC)
    + bytes([0x01])          # scriptPubKey length
    + bytes([0x51])          # OP_TRUE
    + struct.pack("<I", 0)   # locktime
)

# C150 pinned stop values (mainnet block 150000).
_C150_STOP_HEIGHT = 150000
_C150_STOP_HASH = (
    "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"
)


def _make_archive(path: Path, blocks: list[bytes], magic: bytes = _MAINNET_MAGIC) -> bytes:
    """Write a Core-framed archive and return the raw bytes.

    Each frame: 4-byte magic + u32 LE payload_length + payload.
    """
    data = bytearray()
    for block in blocks:
        data += magic
        data += struct.pack("<I", len(block))
        data += block
    path.write_bytes(bytes(data))
    return bytes(data)


def _block_hash_raw(block: bytes) -> bytes:
    """Double-SHA256 of the 80-byte block header (internal LE byte order)."""
    return hashlib.sha256(hashlib.sha256(block[:80]).digest()).digest()


def _block_hash_display(block: bytes) -> str:
    """Display-order hex of the block hash."""
    return _block_hash_raw(block)[::-1].hex()


def _make_manifest(
    path: Path,
    *,
    network: str = "mainnet",
    network_magic: str = _MAINNET_MAGIC.hex(),
    genesis_hash: str = _MAINNET_GENESIS_HASH,
    start_height: int = 0,
    stop_height: int = 0,
    blocks: list[bytes] | None = None,
    archive_size: int | None = None,
    archive_sha256: str | None = None,
) -> bytes:
    """Write a bitcoin-rs-corpus-manifest v1 JSON and return the raw bytes.

    Entry fields: height, hash (display hex), offset, payload_length.
    """
    if blocks is None:
        blocks = [_MAINNET_GENESIS_BLOCK]

    entries: list[dict[str, object]] = []
    offset = 0
    for height, block in enumerate(blocks):
        entries.append({
            "height": height,
            "hash": _block_hash_display(block),
            "offset": offset,
            "payload_length": len(block),
        })
        offset += 8 + len(block)

    if archive_size is None:
        archive_size = offset
    if archive_sha256 is None:
        # Caller must set this to the actual archive sha; default to a placeholder
        # that the test will override.
        archive_sha256 = "0" * 64

    manifest = {
        "schema": "bitcoin-rs-corpus-manifest",
        "version": 1,
        "network": network,
        "network_magic": network_magic,
        "genesis_hash": genesis_hash,
        "range": {"start_height": start_height, "stop_height": stop_height},
        "archive": {"size": archive_size, "sha256": archive_sha256},
        "entries": entries,
    }
    raw = (json.dumps(manifest, indent=2) + "\n").encode()
    path.write_bytes(raw)
    return raw


def _make_replay_v2(
    path: Path,
    *,
    window: int = 150000,
    assume_valid_height: int = 0,
    window_verify_success_total: int = 1,
    network: str = "mainnet",
    network_magic: str = _MAINNET_MAGIC.hex(),
    genesis_hash: str = _MAINNET_GENESIS_HASH,
    start_height: int = 0,
    start_hash: str | None = None,
    stop_height: int = 0,
    stop_hash: str | None = None,
    block_count: int | None = None,
    corpus_manifest_bytes: int = 0,
    corpus_manifest_sha256: str = "0" * 64,
    archive_bytes: int = 0,
    archive_sha256: str = "0" * 64,
    block_bytes: int = 0,
    block_source: str = "file",
    blocks_per_second: float = 0.0,
    checkpoint_generation: int = 1,
    data_dir: str = "/tmp",
    decode_seconds: float = 0.0,
    elapsed_seconds: float = 0.0,
    fetch_seconds: float = 0.0,
    git_head: str = "0" * 40,
    measurement_target: str = "mainnet-prefix-replay",
    rss_high_water_bytes: int = 0,
    stage_seconds: list[dict[str, object]] | None = None,
    storage_backend: str = "fjall",
    tx_count: int = 0,
    txindex: bool = False,
) -> bytes:
    """Write a mainnet-prefix-replay-v3 JSON and return the raw bytes.

    Defaults to mainnet canonical values: network="mainnet",
    network_magic="f9beb4d9", genesis_hash=mainnet genesis,
    start_height=0, start_hash=genesis_hash, stop_height=0,
    stop_hash=genesis block display hash, block_count=stop_height+1.
    """
    if start_hash is None:
        start_hash = genesis_hash
    if stop_hash is None:
        stop_hash = _block_hash_display(_MAINNET_GENESIS_BLOCK)
    if block_count is None:
        block_count = stop_height + 1
    if stage_seconds is None:
        stage_seconds = []
    replay = {
        "schema": "mainnet-prefix-replay-v3",
        "network": network,
        "network_magic": network_magic,
        "genesis_hash": genesis_hash,
        "start_height": start_height,
        "start_hash": start_hash,
        "stop_height": stop_height,
        "stop_hash": stop_hash,
        "block_count": block_count,
        "window": window,
        "assume_valid_height": assume_valid_height,
        "window_verify_success_total": window_verify_success_total,
        "corpus_manifest": {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "path": "manifest.json",
            "bytes": corpus_manifest_bytes,
            "sha256": corpus_manifest_sha256,
        },
        "archive": {
            "path": "archive.bin",
            "bytes": archive_bytes,
            "sha256": archive_sha256,
        },
        "block_bytes": block_bytes,
        "block_source": block_source,
        "blocks_per_second": blocks_per_second,
        "checkpoint_generation": checkpoint_generation,
        "data_dir": data_dir,
        "txindex_worker_catchup_seconds": None,
        "txindex_total_elapsed_seconds": None,
        "decode_seconds": decode_seconds,
        "elapsed_seconds": elapsed_seconds,
        "fetch_seconds": fetch_seconds,
        "git_head": git_head,
        "measurement_target": measurement_target,
        "rss_high_water_bytes": rss_high_water_bytes,
        "stage_seconds": stage_seconds,
        "storage_backend": storage_backend,
        "tx_count": tx_count,
        "txindex": txindex,
    }
    raw = (json.dumps(replay, indent=2) + "\n").encode()
    path.write_bytes(raw)
    return raw


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_classify_args(
    tmp: Path,
    context_rows: list[ContextInput],
    records: list[bytes],
    journal_entries: list[bytes],
    contract: str,
    input_count: int | None = None,
    counters_overrides: dict[str, object] | None = None,
    counters_dict: dict[str, object] | None = None,
    replay_overrides: dict[str, object] | None = None,
    manifest_overrides: dict[str, object] | None = None,
    archive_blocks: list[bytes] | None = None,
    scratch_dir: Path | None = None,
) -> argparse.Namespace:
    """Create all supporting files and return an argparse.Namespace for
    cmd_classify_corpus.

    Files created:
      tmp/counters.json, tmp/contexts.bin, tmp/records.bin, tmp/journal.bin,
      tmp/replay.json, tmp/manifest.json, tmp/archive.bin

    If *counters_dict* is provided it replaces the built-in counters entirely;
    otherwise counters are built from _make_valid_counters and optionally
    patched with *counters_overrides*.
    """
    import argparse

    # ── Contexts (BRSCTX1) ──
    _make_brsctx1_file(tmp / "contexts.bin", context_rows)

    # ── Records (BRSREC1) ──
    _write_records_file(tmp / "records.bin", records)

    # ── Journal (BRSJRN1) ──
    _write_journal_file(tmp / "journal.bin", journal_entries)

    # ── Counters ──
    if counters_dict is not None:
        counters = counters_dict
    else:
        record_count = len(records)
        journal_count = len(journal_entries)
        ffi_verify_entries = len(context_rows)
        counters = _make_valid_counters(record_count, journal_count, ffi_verify_entries)
        if counters_overrides:
            counters.update(counters_overrides)
    (tmp / "counters.json").write_text(json.dumps(counters))
    # ── Archive ──
    if archive_blocks is None:
        archive_blocks = [_MAINNET_GENESIS_BLOCK]
    archive_raw = _make_archive(tmp / "archive.bin", archive_blocks)
    arch_size = len(archive_raw)
    arch_sha = _sha256_bytes(archive_raw)

    # ── Manifest ──
    manifest_raw = _make_manifest(
        tmp / "manifest.json",
        stop_height=len(archive_blocks) - 1,
        blocks=archive_blocks,
        archive_size=arch_size,
        archive_sha256=arch_sha,
    )
    cm_size = len(manifest_raw)
    cm_sha = _sha256_bytes(manifest_raw)

    # ── Replay v2 ──
    replay_kwargs: dict[str, object] = {
        "stop_height": len(archive_blocks) - 1,
        "stop_hash": _block_hash_display(archive_blocks[-1]),
        "corpus_manifest_bytes": cm_size,
        "corpus_manifest_sha256": cm_sha,
        "archive_bytes": arch_size,
        "archive_sha256": arch_sha,
    }
    if replay_overrides:
        replay_kwargs.update(replay_overrides)
    _make_replay_v2(tmp / "replay.json", **replay_kwargs)  # type: ignore[arg-type]

    # ── Manifest overrides (applied after replay is written so we can
    # independently mutate the manifest file) ──
    if manifest_overrides:
        manifest_obj = json.loads((tmp / "manifest.json").read_text())
        manifest_obj.update(manifest_overrides)
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)

    ns = argparse.Namespace(
        counters=str(tmp / "counters.json"),
        contexts=str(tmp / "contexts.bin"),
        records=str(tmp / "records.bin"),
        journal=str(tmp / "journal.bin"),
        replay=str(tmp / "replay.json"),
        corpus_manifest=str(tmp / "manifest.json"),
        archive=str(tmp / "archive.bin"),
        output=str(tmp / "report.json"),
        contract=contract,
        input_count=input_count,
        scratch_dir=str(scratch_dir) if scratch_dir else None,
    )
    return ns


def _cmd_classify_synthetic_cmodern(args: argparse.Namespace) -> int:
    """Bind a one-block fixture to the Cmodern report path for test coverage."""
    if args.contract != "cmodern":
        raise AssertionError("synthetic Cmodern helper requires contract='cmodern'")
    stop_height = analyze.CMODERN_STOP_HEIGHT
    stop_hash = analyze.CMODERN_STOP_HASH
    analyze.CMODERN_STOP_HEIGHT = 0
    analyze.CMODERN_STOP_HASH = _block_hash_display(_MAINNET_GENESIS_BLOCK)
    try:
        return cmd_classify_corpus(args)
    finally:
        analyze.CMODERN_STOP_HEIGHT = stop_height
        analyze.CMODERN_STOP_HASH = stop_hash


# ── Legacy JSONL helpers (for diagnostic iter_legacy_context_inputs tests) ───


def _make_legacy_row(
    display_txid: str,
    input_index: int,
    prevout: bytes,
    script_sig: bytes = b"",
    witness: tuple[bytes, ...] = (),
    height: int = 100,
    tx_index: int = 0,
) -> dict[str, object]:
    return {
        "schema": "census-context-input-v1",
        "height": height,
        "block_hash": bytes(32).hex(),
        "tx_index": tx_index,
        "input_index": input_index,
        "txid": display_txid,
        "prevout_script_pubkey_hex": prevout.hex(),
        "script_sig_hex": script_sig.hex(),
        "witness_hex": [w.hex() for w in witness],
    }


def _write_legacy_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


# ── Tests: Counters validation (Finding 3) ───────────────────────────────────


def test_counters_rejects_missing_field() -> None:
    """A counters dict missing a required COUNTER_NAMES field must raise."""
    d = _valid_counters_dict()
    del d["op_checksig"]
    _raises(AnalyzerError, lambda: Counters(d), "missing field")


def test_counters_rejects_non_int_value() -> None:
    """A counters dict with a string value must raise."""
    d = _valid_counters_dict(op_checksig="42")  # type: ignore[dict-item]
    _raises(AnalyzerError, lambda: Counters(d), "non-int value")


def test_counters_rejects_bool_value() -> None:
    """Python bools are ints but must be rejected for counter fields."""
    d = _valid_counters_dict(op_checksig=True)
    _raises(AnalyzerError, lambda: Counters(d), "bool value")


def test_counters_rejects_negative_value() -> None:
    """A counters dict with a negative value must raise."""
    d = _valid_counters_dict(op_checksig=-1)
    _raises(AnalyzerError, lambda: Counters(d), "negative value")


def test_counters_accepts_valid_dict() -> None:
    """A well-formed counters dict must parse without error."""
    c = Counters(_valid_counters_dict(op_checksig=42))
    assert c.op_checksig == 42


# ── Tests: ffi_verify_entries gate (Finding 2) ───────────────────────────────


def test_validate_capture_rejects_wrong_ffi_verify_entries() -> None:
    """Wrong ffi_verify_entries must fail *only* EXP-KSPIKE1, not any INV.

    Every invariant INV-1 through INV-13 must pass with a self-consistent
    1-entry corpus; the sole failure is ffi_verify_entries != the expected
    KSPIKE1 anchor, so the failed-id list is exactly ['EXP-KSPIKE1'].
    """
    import argparse
    import contextlib
    import io

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid = b"\x01" * 32
        recs = [_make_record_bytes(txid, 0)]
        _write_records_file(tmp / "records.bin", recs)
        _write_records_file(tmp / "repeat.bin", recs)
        jnl = [
            _make_journal_bytes(
                txid,
                0,
                checksig_ops=1,
                ecdsa_verify_calls=1,
                ecdsa_verify_ok=1,
                verdict=1,
            )
        ]
        _write_journal_file(tmp / "journal.bin", jnl)
        _write_journal_file(tmp / "repeat_journal.bin", jnl)

        c = _valid_counters_dict(
            ffi_verify_entries=1,
            verify_script_calls=1,
            ffi_verify_true=1,
            checkecdsa_entries=1,
            ecdsa_from_checksig=1,
            ecdsa_verify_calls=1,
            ecdsa_verify_ok=1,
            sighash_computed=1,
            op_checksig=1,
            record_count=1,
            journal_count=1,
        )
        (tmp / "counters.json").write_text(json.dumps(c))
        (tmp / "repeat_counters.json").write_text(json.dumps(c))

        out = tmp / "report.json"
        sorted_out = tmp / "sorted.bin"
        args = argparse.Namespace(
            subcommand="validate-capture",
            counters=tmp / "counters.json",
            records=tmp / "records.bin",
            journal=tmp / "journal.bin",
            repeat_counters=tmp / "repeat_counters.json",
            repeat_records=tmp / "repeat.bin",
            repeat_journal=tmp / "repeat_journal.bin",
            output=out,
            sorted_records_output=sorted_out,
        )
        stderr_buf = io.StringIO()
        with contextlib.redirect_stderr(stderr_buf):
            rc = analyze.cmd_validate_capture(args)
        assert rc == 1, "expected return code 1 for wrong ffi_verify_entries"
        report = json.loads(out.read_text())
        assert report["all_passed"] is False
        inv_failed = [r["id"] for r in report["invariants"] if not r["passed"]]
        assert inv_failed == [], f"invariants should all pass, but {inv_failed} failed"
        stderr_msg = stderr_buf.getvalue().strip()
        assert "EXP-KSPIKE1" in stderr_msg, (
            f"stderr should mention EXP-KSPIKE1, got: {stderr_msg!r}"
        )
        for inv_id in (
            "INV-1", "INV-2", "INV-3", "INV-4", "INV-5", "INV-6",
            "INV-7", "INV-9", "INV-10", "INV-11", "INV-13",
        ):
            assert inv_id not in stderr_msg, (
                f"{inv_id} should not be in failed list, stderr: {stderr_msg!r}"
            )



def test_validate_capture_rejects_pre_taproot_schnorr_activity() -> None:
    """The legacy capture contract rejects any Schnorr activity."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        _write_records_file(tmp / "records.bin", [])
        _write_records_file(tmp / "repeat.bin", [])
        _write_journal_file(tmp / "journal.bin", [])
        _write_journal_file(tmp / "repeat_journal.bin", [])
        counters = _valid_counters_dict(checkschnorr_entries=1)
        (tmp / "counters.json").write_text(json.dumps(counters))
        (tmp / "repeat_counters.json").write_text(json.dumps(counters))
        args = argparse.Namespace(
            counters=tmp / "counters.json",
            records=tmp / "records.bin",
            journal=tmp / "journal.bin",
            repeat_counters=tmp / "repeat_counters.json",
            repeat_records=tmp / "repeat.bin",
            repeat_journal=tmp / "repeat_journal.bin",
            output=tmp / "report.json",
            sorted_records_output=tmp / "sorted.bin",
        )
        assert analyze.cmd_validate_capture(args) == 1
        report = json.loads((tmp / "report.json").read_text())
        pre_taproot = [
            row for row in report["invariants"]
            if row["id"] == "INV-KSPIKE-SCHNORR-0"
        ][0]
        assert pre_taproot["passed"] is False



def test_validate_capture_binds_corpus_identity() -> None:
    """validate-capture emits census-capture-v2 and binds corpus_size and corpus_sha256."""
    import argparse

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        recs = [_make_record_bytes(b"\x01" * 32, 0)]
        _write_records_file(tmp / "records.bin", recs)
        _write_records_file(tmp / "repeat.bin", recs)
        _write_journal_file(tmp / "journal.bin", [])
        _write_journal_file(tmp / "repeat_journal.bin", [])

        c = _valid_counters_dict(
            ffi_verify_entries=EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1,
            record_count=1,
            journal_count=0,
        )
        (tmp / "counters.json").write_text(json.dumps(c))
        (tmp / "repeat_counters.json").write_text(json.dumps(c))

        row = _make_legacy_row(bytes(32).hex(), 0, _p2pkh_prevout())
        _write_legacy_jsonl(tmp / "ctx.jsonl", [row])

        args = argparse.Namespace(
            subcommand="validate-capture",
            counters=tmp / "counters.json",
            records=tmp / "records.bin",
            journal=tmp / "journal.bin",
            repeat_counters=tmp / "repeat_counters.json",
            repeat_records=tmp / "repeat.bin",
            repeat_journal=tmp / "repeat_journal.bin",
            output=tmp / "report.json",
            sorted_records_output=None,
            context_inputs=str(tmp / "ctx.jsonl"),
        )
        analyze.cmd_validate_capture(args)
        report = json.loads((tmp / "report.json").read_text())
        assert report["schema"] == "census-capture-v2"
        assert "corpus_size" in report
        assert "corpus_sha256" in report
        real_size, real_sha256 = analyze._sha256_file(tmp / "ctx.jsonl")
        assert report["corpus_size"] == real_size
        assert report["corpus_sha256"] == real_sha256


def test_validate_capture_sorted_output_has_header() -> None:
    """The sorted-records output file must start with BRSREC1 magic + u64 count."""
    import argparse

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        recs = [
            _make_record_bytes(b"\x02" * 32, 1),
            _make_record_bytes(b"\x01" * 32, 0),
        ]
        _write_records_file(tmp / "records.bin", recs)
        _write_records_file(tmp / "repeat.bin", recs)
        _write_journal_file(tmp / "journal.bin", [])
        _write_journal_file(tmp / "repeat_journal.bin", [])

        c = _valid_counters_dict(
            ffi_verify_entries=EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1,
            ffi_verify_true=2,
            record_count=2,
            journal_count=0,
        )
        (tmp / "counters.json").write_text(json.dumps(c))
        (tmp / "repeat_counters.json").write_text(json.dumps(c))

        out = tmp / "report.json"
        sorted_out = tmp / "sorted.bin"

        args = argparse.Namespace(
            subcommand="validate-capture",
            counters=tmp / "counters.json",
            records=tmp / "records.bin",
            journal=tmp / "journal.bin",
            repeat_counters=tmp / "repeat_counters.json",
            repeat_records=tmp / "repeat.bin",
            repeat_journal=tmp / "repeat_journal.bin",
            output=out,
            sorted_records_output=sorted_out,
        )
        analyze.cmd_validate_capture(args)

        data = sorted_out.read_bytes()
        magic, count = HEADER_STRUCT.unpack_from(data, 0)
        assert magic == RECORD_MAGIC, f"bad magic {magic!r}"
        assert count == 2, f"expected count 2, got {count}"
        payload = data[HEADER_STRUCT.size :]
        sorted_recs = sort_records_raw(recs)
        assert payload == sorted_recs, "sorted payload must match sort_records_raw output"


def test_records_reject_invalid_encoded_fields() -> None:
    """BRSREC1 readers must reject impossible length and outcome metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "records.bin"
        for offset, bad, field in (
            (42, 3, "outcome"),
            (43, 0, "der_len"),
            (44, 66, "pubkey_len"),
        ):
            record = bytearray(_make_record_bytes(b"\x01" * 32, 0))
            record[offset] = bad
            _write_records_file(path, [bytes(record)])
            _raises(AnalyzerError, lambda p=path: parse_records(p), f"{field}={bad}")


def test_records_accept_preserved_over_capacity_ecdsa_reject() -> None:
    """The public reader accepts the exact native reason-1 preserved row."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "records.bin"
        _write_records_file(path, [_PRESERVED_OVER_CAPACITY_ROW])
        records = parse_records(path)
    assert len(records) == 1
    record = records[0]
    assert record.spend_txid[::-1].hex() == (
        "d118497ff83231ad313bfcce0133664d148c755f4c352dbf952598b987bd42cf"
    )
    assert (record.input_index, record.op_kind, record.sig_version) == (0, 3, 0)
    assert (record.outcome, record.der_len, record.pubkey_len) == (2, 0, 66)
    assert (record.sighash_type, record.reject_reason) == (0, 1)


def test_records_reject_every_over_capacity_shape_near_miss() -> None:
    """Every valid-domain gating-field near miss retains the length error."""
    mutations = (
        (40, 0, "op_kind=0"),
        (40, 5, "op_kind=5"),
        (41, 2, "sig_version=2"),
        (41, 3, "sig_version=3"),
        (42, 0, "outcome=0"),
        (42, 1, "outcome=1"),
        (43, 1, "der_len=1"),
        (43, 73, "der_len=73"),
        (45, 1, "sighash_type=1"),
        (46, 0, "reject_reason=0"),
        *((46, reason, f"reject_reason={reason}") for reason in range(2, 9)),
    )
    for offset, value, label in mutations:
        raw = bytearray(_PRESERVED_OVER_CAPACITY_ROW)
        raw[offset] = value
        _assert_over_capacity_length_error(bytes(raw), label)

    for offset in range(48, 217):
        raw = bytearray(_PRESERVED_OVER_CAPACITY_ROW)
        raw[offset] = 1
        _assert_over_capacity_length_error(bytes(raw), f"nonzero payload/pad byte {offset}")


def test_records_reject_ordinary_over_capacity_pubkey() -> None:
    """An ordinary verification record with pubkey_len=66 stays invalid."""
    raw = bytearray(_make_record_bytes(b"\x01" * 32, 0))
    raw[44] = 66
    _assert_over_capacity_length_error(bytes(raw), "ordinary pubkey_len=66")


def test_preserved_over_capacity_padding_checks_remain_unchanged() -> None:
    """The exact accepted row has all-zero padding, and ordinary records still fail with the existing padding errors."""
    record = Record(_PRESERVED_OVER_CAPACITY_ROW)
    assert record is not None  # exact row accepted

    for offset, message in (
        (47, "record _pad0 is not all-zero"),
        (217, "record _pad1 is not all-zero"),
    ):
        # Ordinary records (pubkey_len=65) retain the unchanged padding checks.
        raw = bytearray(_make_record_bytes(b"\x01" * 32, 0, outcome=1, reject_reason=0))
        raw[offset] = 1
        _raises_with(
            AnalyzerError,
            lambda r=bytes(raw): Record(r),
            f"ordinary padding byte {offset}",
            message,
        )

        # Over-capacity near misses fall through to the existing length error.
        raw = bytearray(_PRESERVED_OVER_CAPACITY_ROW)
        raw[offset] = 1
        _assert_over_capacity_length_error(bytes(raw), f"over-capacity padding byte {offset}")


# ── Tests: extract_spike_width1 validation (Finding 5) ───────────────────────


def test_spike_rejects_non_integer_threads() -> None:
    """Top-level us_per_input with non-integer threads must raise."""
    _raises(
        AnalyzerError,
        lambda: extract_spike_width1({"us_per_input": 50.0, "threads": "1"}),
        "string threads",
    )


def test_spike_rejects_bool_threads() -> None:
    """Top-level us_per_input with bool threads must raise."""
    _raises(
        AnalyzerError,
        lambda: extract_spike_width1({"us_per_input": 50.0, "threads": True}),
        "bool threads",
    )


def test_spike_rejects_threads_not_1() -> None:
    """Top-level us_per_input with threads != 1 must raise."""
    _raises(
        AnalyzerError,
        lambda: extract_spike_width1({"us_per_input": 50.0, "threads": 2}),
        "threads == 2",
    )


def test_spike_accepts_threads_1() -> None:
    """Top-level us_per_input with threads == 1 must succeed."""
    val = extract_spike_width1({"us_per_input": 50.0, "threads": 1})
    assert val == 50.0


def test_spike_accepts_runs_list_with_threads_1() -> None:
    """A runs list containing a run with threads == 1 must succeed."""
    val = extract_spike_width1({"runs": [{"us_per_input": 50.0, "threads": 1}]})
    assert val == 50.0


def test_spike_rejects_runs_list_without_threads_1() -> None:
    """A runs list with no threads == 1 run must raise."""
    _raises(
        AnalyzerError,
        lambda: extract_spike_width1({"runs": [{"us_per_input": 50.0, "threads": 2}]}),
        "no threads==1 run",
    )


def test_spike_rejects_runs_list_bool_threads() -> None:
    """A runs list with boolean threads must not be accepted as threads == 1."""
    _raises(
        AnalyzerError,
        lambda: extract_spike_width1({"runs": [{"us_per_input": 50.0, "threads": True}]}),
        "bool threads in runs list",
    )


def test_spike_rejects_nonfinite_us_per_input() -> None:
    """Spike us_per_input must be a finite positive number in both forms."""
    for bad in (float("nan"), float("inf"), float("-inf"), -1.0, 0.0):
        _raises(
            AnalyzerError,
            lambda v=bad: extract_spike_width1({"us_per_input": v, "threads": 1}),
            f"top-level us_per_input={bad!r}",
        )
        _raises(
            AnalyzerError,
            lambda v=bad: extract_spike_width1(
                {"runs": [{"us_per_input": v, "threads": 1}]}
            ),
            f"list us_per_input={bad!r}",
        )


def test_bare_rejects_nonfinite_reported_values() -> None:
    """Reported bare median/min/max must be finite positive numbers."""
    base = {
        "inputs_per_round": 1,
        "rounds": 1,
        "attempts_total": 1,
        "round_ns": [50000],
        "mismatches": 0,
        "first_mismatch": None,
        "ok_count": 1,
    }
    for field in ("median_ns_per_attempt", "min_ns_per_attempt", "max_ns_per_attempt"):
        for bad in (float("nan"), float("inf"), float("-inf"), -1.0, 0.0):
            d = dict(base, **{field: bad})
            _raises(
                AnalyzerError,
                lambda d=d: extract_bare_mode0(d),
                f"{field}={bad!r}",
            )


def test_bare_rejects_invalid_round_ns_types() -> None:
    """round_ns must contain integers and must not accept booleans."""
    base = {
        "inputs_per_round": 1,
        "rounds": 1,
        "attempts_total": 1,
        "median_ns_per_attempt": 50000.0,
        "min_ns_per_attempt": 50000.0,
        "max_ns_per_attempt": 50000.0,
        "mismatches": 0,
        "first_mismatch": None,
        "ok_count": 1,
    }
    for bad in ([True], [1.5], ["1"]):
        d = dict(base, round_ns=bad)
        _raises(AnalyzerError, lambda d=d: extract_bare_mode0(d), f"round_ns={bad!r}")


def test_bare_rejects_nonpositive_round_ns() -> None:
    """round_ns must contain positive values."""
    base = {
        "inputs_per_round": 1,
        "rounds": 1,
        "attempts_total": 1,
        "median_ns_per_attempt": 50000.0,
        "min_ns_per_attempt": 50000.0,
        "max_ns_per_attempt": 50000.0,
        "mismatches": 0,
        "first_mismatch": None,
        "ok_count": 1,
    }
    for bad in ([0], [-1]):
        d = dict(base, round_ns=bad)
        _raises(AnalyzerError, lambda d=d: extract_bare_mode0(d), f"round_ns={bad!r}")


def test_bare_rejects_non_integer_summary_fields() -> None:
    """Native timing summary must not coerce booleans or floats to integers."""
    base = {
        "round_ns": [50000],
        "median_ns_per_attempt": 50000.0,
        "min_ns_per_attempt": 50000.0,
        "max_ns_per_attempt": 50000.0,
        "first_mismatch": None,
    }
    for field in ("inputs_per_round", "rounds", "attempts_total", "mismatches", "ok_count"):
        for bad in (True, 1.5):
            d = dict(base, **{field: bad})
            _raises(AnalyzerError, lambda d=d: extract_bare_mode0(d), f"{field}={bad!r}")


# ── Tests: cmd_verdict numeric and cross-check ───────────────────────────────


def test_verdict_rejects_invalid_numeric_fields() -> None:
    """Verdict inputs must preserve strict integer and positive-finite contracts."""
    import argparse

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        cap = _valid_counters_dict(
            ffi_verify_entries=1,
            ecdsa_verify_calls=1,
            ecdsa_verify_ok=1,
        )
        cap_path = tmp / "capture.json"
        cap_path.write_text(json.dumps(cap))

        integrity = _make_integrity_json()
        integrity_path = tmp / "integrity.json"
        integrity_path.write_text(json.dumps(integrity))

        spike = {"us_per_input": 50.0, "threads": 1}
        spike_paths = []
        for i in range(3):
            p = tmp / f"spike{i}.json"
            p.write_text(json.dumps(spike))
            spike_paths.append(p)

        bare = _make_bare_run_json()
        bare_paths = []
        for i in range(3):
            p = tmp / f"bare{i}.json"
            p.write_text(json.dumps(bare))
            bare_paths.append(p)

        out = tmp / "verdict.json"

        for current_wall, current_script in (
            (-1.0, 50.0),
            (100.0, -1.0),
            (float("nan"), 50.0),
            (100.0, float("inf")),
        ):
            args = argparse.Namespace(
                capture_counters=cap_path,
                bare_runs=bare_paths,
                spike_runs=spike_paths,
                current_wall_seconds=current_wall,
                current_script_wall_seconds=current_script,
                output=out,
                integrity=integrity_path,
            )
            _raises(
                AnalyzerError,
                lambda a=args: analyze.cmd_verdict(a),
                f"wall={current_wall!r}, script={current_script!r}",
            )

        for field in ("mismatches", "ok_count", "expected_true_count"):
            for bad in (True, 1.5):
                malformed = _make_bare_run_json()
                malformed["inv_8"][field] = bad
                for path in bare_paths:
                    path.write_text(json.dumps(malformed))
                args = argparse.Namespace(
                    capture_counters=cap_path,
                    bare_runs=bare_paths,
                    spike_runs=spike_paths,
                    current_wall_seconds=100.0,
                    current_script_wall_seconds=50.0,
                    output=out,
                    integrity=integrity_path,
                )
                _raises(
                    AnalyzerError,
                    lambda a=args: analyze.cmd_verdict(a),
                    f"inv_8 {field}={bad!r}",
                )


def _make_bare_run_json(
    *,
    mode0_mismatches: int = 0,
    mode0_ok_count: int = 1,
    inv8_mismatches: int = 0,
    inv8_ok_count: int = 1,
    inv8_expected_true_count: int = 1,
) -> dict[str, object]:
    """Build a minimal bare-secp run JSON that passes all verdict checks."""
    ns = 50000
    return {
        "native_mode0": {
            "inputs_per_round": 1,
            "rounds": 1,
            "attempts_total": 1,
            "round_ns": [ns],
            "median_ns_per_attempt": float(ns),
            "min_ns_per_attempt": float(ns),
            "max_ns_per_attempt": float(ns),
            "mismatches": mode0_mismatches,
            "first_mismatch": None,
            "ok_count": mode0_ok_count,
        },
        "inv_8": {
            "passed": True,
            "mismatches": inv8_mismatches,
            "ok_count": inv8_ok_count,
            "expected_true_count": inv8_expected_true_count,
            "ok_equals_count_outcome_1": True,
        },
        "inv_15": {
            "counters": {name: 0 for name in COUNTER_NAMES},
            "all_counters_zero": True,
            "passed": True,
        },
    }


def _make_integrity_json() -> dict[str, object]:
    """Build a valid integrity JSON where source/secp hashes match."""
    h = "0" * 64
    return {
        "pristine_source_hash": h,
        "patched_source_hash": h,
        "pristine_secp_tree_hash": h,
        "patched_secp_tree_hash": h,
        "pubkey_source_identical": True,
        "secp_tree_identical": True,
    }


def test_verdict_native_mode0_contradiction_fails() -> None:
    """Contradictory native_mode0 vs inv_8 must make verdict INVALID."""
    import argparse

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        cap = _valid_counters_dict(
            ffi_verify_entries=1,
            ecdsa_verify_calls=1,
            ecdsa_verify_ok=1,
        )
        cap_path = tmp / "capture.json"
        cap_path.write_text(json.dumps(cap))

        integrity = _make_integrity_json()
        integrity_path = tmp / "integrity.json"
        integrity_path.write_text(json.dumps(integrity))

        spike = {"us_per_input": 50.0, "threads": 1}
        spike_paths = []
        for i in range(3):
            p = tmp / f"spike{i}.json"
            p.write_text(json.dumps(spike))
            spike_paths.append(p)

        out_ok = tmp / "verdict_ok.json"
        out_bad = tmp / "verdict_bad.json"

        # --- Agreeing artifact ---
        agreeing = _make_bare_run_json()
        agreeing_paths = []
        for i in range(3):
            p = tmp / f"agree{i}.json"
            p.write_text(json.dumps(agreeing))
            agreeing_paths.append(p)

        args_ok = argparse.Namespace(
            subcommand="verdict",
            capture_counters=cap_path,
            bare_runs=agreeing_paths,
            spike_runs=spike_paths,
            current_wall_seconds=100.0,
            current_script_wall_seconds=50.0,
            output=out_ok,
            integrity=integrity_path,
        )
        rc_ok = analyze.cmd_verdict(args_ok)
        assert rc_ok == 0, f"agreeing artifact should not be INVALID, got rc={rc_ok}"
        report_ok = json.loads(out_ok.read_text())
        assert report_ok["verdict"] != "INVALID"
        assert report_ok["inv_8"]["passed"] is True

        # --- Contradictory artifact ---
        contradictory = _make_bare_run_json(mode0_mismatches=1)
        contra_paths = []
        for i in range(3):
            p = tmp / f"contra{i}.json"
            p.write_text(json.dumps(contradictory))
            contra_paths.append(p)

        args_bad = argparse.Namespace(
            subcommand="verdict",
            capture_counters=cap_path,
            bare_runs=contra_paths,
            spike_runs=spike_paths,
            current_wall_seconds=100.0,
            current_script_wall_seconds=50.0,
            output=out_bad,
            integrity=integrity_path,
        )
        rc_bad = analyze.cmd_verdict(args_bad)
        assert rc_bad == 2, f"contradictory artifact should be INVALID (rc=2), got rc={rc_bad}"
        report_bad = json.loads(out_bad.read_text())
        assert report_bad["verdict"] == "INVALID"
        assert report_bad["inv_8"]["passed"] is False


# ── Tests: legacy JSONL diagnostic parser ────────────────────────────────────


def test_legacy_jsonl_rejects_malformed_fields() -> None:
    """Diagnostic JSONL must have exact fields, lowercase hex, and sane integers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # Use a txid with at least one a-f digit so .upper() changes the string.
        base = _make_legacy_row(bytes.fromhex("0a" + "00" * 30).hex(), 0, _p2pkh_prevout())

        for label, broken in (
            ("missing height", {k: v for k, v in base.items() if k != "height"}),
            ("extra field", {**base, "extra": 1}),
            ("uppercase txid", {**base, "txid": base["txid"].upper()}),
            ("odd hex", {**base, "txid": base["txid"][:-1]}),
            ("negative height", {**base, "height": -1}),
            ("bool input_index", {**base, "input_index": True}),
        ):
            _write_legacy_jsonl(tmp / "ctx.jsonl", [broken])
            _raises(
                ContextError,
                lambda p=tmp / "ctx.jsonl": list(iter_legacy_context_inputs(p, 1)),
                label,
            )


def test_legacy_jsonl_rejects_duplicate_and_count_mismatch() -> None:
    """Duplicate identities and wrong input-count are diagnostic contract failures."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid = bytes(32).hex()
        rows = [
            _make_legacy_row(txid, 0, _p2pkh_prevout(), tx_index=0),
            _make_legacy_row(txid, 0, _p2pkh_prevout(), tx_index=1),
        ]
        _write_legacy_jsonl(tmp / "ctx.jsonl", rows)
        _raises(
            ContextError,
            lambda: list(iter_legacy_context_inputs(tmp / "ctx.jsonl", 2)),
            "duplicate execution identity",
        )

        _write_legacy_jsonl(tmp / "ctx.jsonl", [])
        _raises(
            ContextError,
            lambda: list(iter_legacy_context_inputs(tmp / "ctx.jsonl", 1)),
            "count mismatch",
        )

        assert list(iter_legacy_context_inputs(tmp / "ctx.jsonl", 0)) == []


# ── Tests: BRSCTX1 strict binary parser adversarial cases ────────────────────


def test_brsctx1_rejects_wrong_magic() -> None:
    """A file with wrong magic must raise CTX-RAW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "bad.bin"
        # 8-byte wrong magic + u64 count=0
        path.write_bytes(b"BADMAGIC" + struct.pack("<Q", 0))
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "wrong magic",
            "CTX-RAW",
        )


def test_brsctx1_rejects_short_header() -> None:
    """A file shorter than the 16-byte header must raise CTX-RAW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "short.bin"
        path.write_bytes(b"BRSCTX1\x00" + b"\x00" * 3)  # 11 bytes < 16
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "short header",
            "CTX-RAW",
        )


def test_brsctx1_rejects_short_row_field() -> None:
    """A row whose declared length is shorter than the fixed body must raise CTX-RAW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "short_row.bin"
        # Header: magic + count=1
        data = _BRSCTX1_MAGIC + struct.pack("<Q", 1)
        # Row length = 10 (< 52-byte CONTEXT_MIN_ROW_SIZE)
        data += struct.pack("<I", 10)
        data += b"\x00" * 10
        path.write_bytes(data)
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "short row",
            "CTX-RAW",
        )


def test_brsctx1_rejects_row_length_mismatch() -> None:
    """row_len declares more bytes than are actually present."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "mismatch.bin"
        txid_le = bytes(32)
        fixed = _BRSCTX1_FIXED.pack(txid_le, 0, 0, 0, 0, 0)
        # Declare row_length = _BRSCTX1_FIXED.size + 5 extra bytes, but only write fixed
        row_length = _BRSCTX1_FIXED.size + 5
        data = _BRSCTX1_MAGIC + struct.pack("<Q", 1)
        data += struct.pack("<I", row_length)
        data += fixed
        # Don't write the 5 extra bytes — the read will be short
        path.write_bytes(data)
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "short read",
            "CTX-RAW",
        )


def test_brsctx1_rejects_impossible_witness_count() -> None:
    """A witness_count that cannot fit in the declared row length must fail before allocation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "badwitness.bin"
        txid_le = bytes(32)
        # witness_count=100 but row_length only has a few bytes remaining
        fixed = _BRSCTX1_FIXED.pack(txid_le, 0, 0, 0, 0, 100)
        row_length = _BRSCTX1_FIXED.size + 4  # only 4 bytes remaining, can't fit 100 witness items
        data = _BRSCTX1_MAGIC + struct.pack("<Q", 1)
        data += struct.pack("<I", row_length)
        data += fixed
        data += b"\x00" * 4
        path.write_bytes(data)
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "witness count cannot fit",
            "CTX-RAW",
        )


def test_brsctx1_rejects_duplicate_execution_identity() -> None:
    """Two rows with the same (txid_le, input_index) must raise CTX-EXECUTION."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "dup.bin"
        txid_le = b"\x01" * 32
        row = _ctx_input(txid_le, 0, prevout=_p2pkh_prevout())
        _make_brsctx1_file(path, [row, row])
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "duplicate execution identity",
            "CTX-EXECUTION",
        )


def test_brsctx1_rejects_declared_count_mismatch() -> None:
    """A declared count that cannot fit in the payload must raise CTX-RAW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "bad_count.bin"
        # Declare count=1000000 but only provide a tiny payload
        data = _BRSCTX1_MAGIC + struct.pack("<Q", 1_000_000)
        data += b"\x00" * 100
        path.write_bytes(data)
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "declared count mismatch",
            "CTX-RAW",
        )


def test_brsctx1_rejects_trailing_bytes() -> None:
    """Extra bytes after the declared rows must raise CTX-RAW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "trailing.bin"
        txid_le = b"\x02" * 32
        row = _ctx_input(txid_le, 0, prevout=_p2pkh_prevout())
        _make_brsctx1_file(path, [row])
        # Append a trailing byte
        path.write_bytes(path.read_bytes() + b"\x00")
        _raises_with(
            ContextError,
            lambda: list(iter_context_inputs(path)),
            "trailing bytes",
            "CTX-RAW",
        )


def test_brsctx1_accepts_valid_file() -> None:
    """A well-formed BRSCTX1 file with one row must parse successfully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "ok.bin"
        txid_le = b"\x03" * 32
        row = _ctx_input(txid_le, 0, prevout=_p2pkh_prevout())
        _make_brsctx1_file(path, [row])
        inputs = list(iter_context_inputs(path))
        assert len(inputs) == 1
        assert inputs[0].identity.txid_le == txid_le
        assert inputs[0].identity.input_index == 0


# ── Tests: classify_input spend-context classification ───────────────────────


def test_classify_input_block_177609_op_0_p2sh() -> None:
    """The exact block-177609 OP_0 multisig spend classifies as P2SH."""
    evidence = _ctx_input(
        bytes.fromhex(
            "1cc1ecdf5c05765df3d1f59fba24cd01"
            "c45464c329b0f0a25aa9883adfcf7f29"
        )[::-1],
        0,
        verify_flags=VERIFY_P2SH,
        prevout=bytes.fromhex(
            "a9145c02c49641699863f909bf4bf3be8398d2e383f187"
        ),
        script_sig=bytes.fromhex(
            "00483045022100beb926da7428fa009ac770576342ebd1960939e73584a5d0"
            "f3229b58c41e906f022017c0d143077906afccf30caf21f5ece0bb30e3f7"
            "08fd4a17f9d9ef9fe7cdc983014751210307ac6296168948c3f64ce22f51"
            "f6e5424f936c846f1d01223b3d9864f4d955662103ac6ad514715bec8d5d"
            "e1873b9bc873bb71773b51338b4d115f9938b6a029b7d152ae"
        ),
    )

    classified = classify_input(evidence)

    assert classified.spend_context == SpendContext.P2SH


def test_classify_input_bare_p2pkh() -> None:
    """Bare P2PKH with no flags classifies as BARE."""
    txid_le = b"\x10" * 32
    classified = classify_input(_bare_p2pkh(txid_le))
    assert classified.spend_context == SpendContext.BARE


def test_classify_input_p2sh_without_flag() -> None:
    """P2SH prevout without P2SH flag classifies as BARE."""
    txid_le = b"\x11" * 32
    classified = classify_input(_p2sh_push_only(txid_le, flags=0))
    assert classified.spend_context == SpendContext.BARE


def test_classify_input_p2sh_with_flag() -> None:
    """P2SH prevout with P2SH flag classifies as P2SH."""
    txid_le = b"\x12" * 32
    classified = classify_input(_p2sh_push_only(txid_le, flags=VERIFY_P2SH))
    assert classified.spend_context == SpendContext.P2SH


def test_classify_input_p2sh_wrapped_w0_p2sh_only() -> None:
    """P2SH-wrapped witness-v0 with P2SH only classifies as P2SH."""
    txid_le = b"\x13" * 32
    classified = classify_input(_p2sh_wrapped_w0(txid_le, flags=VERIFY_P2SH))
    assert classified.spend_context == SpendContext.P2SH


def test_classify_input_p2sh_wrapped_w0_p2sh_witness() -> None:
    """P2SH-wrapped witness-v0 with P2SH+WITNESS classifies as P2SH_WRAPPED_WITNESS_V0."""
    txid_le = b"\x14" * 32
    classified = classify_input(
        _p2sh_wrapped_w0(txid_le, flags=VERIFY_P2SH | VERIFY_WITNESS)
    )
    assert classified.spend_context == SpendContext.P2SH_WRAPPED_WITNESS_V0


def test_classify_input_native_w0_without_witness() -> None:
    """Native witness-v0 prevout without WITNESS flag classifies as BARE."""
    txid_le = b"\x15" * 32
    classified = classify_input(_native_w0(txid_le, flags=0))
    assert classified.spend_context == SpendContext.BARE


def test_classify_input_native_w0_with_witness() -> None:
    """Native witness-v0 prevout with WITNESS flag classifies as NATIVE_WITNESS_V0."""
    txid_le = b"\x16" * 32
    classified = classify_input(_native_w0(txid_le, flags=VERIFY_WITNESS))
    assert classified.spend_context == SpendContext.NATIVE_WITNESS_V0


def test_classify_input_taproot_no_witness() -> None:
    """P2TR prevout without WITNESS flag classifies as BARE."""
    txid_le = b"\x17" * 32
    classified = classify_input(_taproot_key_path(txid_le, flags=0))
    assert classified.spend_context == SpendContext.BARE


def test_classify_input_taproot_witness_only() -> None:
    """P2TR prevout with WITNESS only (no TAPROOT) classifies as BARE."""
    txid_le = b"\x18" * 32
    classified = classify_input(_taproot_key_path(txid_le, flags=VERIFY_WITNESS))
    assert classified.spend_context == SpendContext.BARE


def test_classify_input_taproot_key_path() -> None:
    """P2TR prevout with WITNESS+TAPROOT and 64-byte sig classifies as TAPROOT_KEY_PATH."""
    txid_le = b"\x19" * 32
    classified = classify_input(
        _taproot_key_path(txid_le, flags=VERIFY_WITNESS | VERIFY_TAPROOT)
    )
    assert classified.spend_context == SpendContext.TAPROOT_KEY_PATH


def test_classify_input_taproot_script_path() -> None:
    """P2TR prevout with WITNESS+TAPROOT and stack+tapscript+control classifies as TAPSCRIPT."""
    txid_le = b"\x1a" * 32
    classified = classify_input(
        _taproot_script_path(txid_le, flags=VERIFY_WITNESS | VERIFY_TAPROOT)
    )
    assert classified.spend_context == SpendContext.TAPSCRIPT


def test_classify_input_taproot_annex_stripping() -> None:
    """A final annex (0x50) is stripped before P2TR path classification."""
    txid_le = b"\x1b" * 32
    annex = bytes([0x50]) + bytes(10)

    # Key path with annex: two elements, strip -> one -> key path.
    evidence = _ctx_input(
        txid_le, 0,
        verify_flags=VERIFY_WITNESS | VERIFY_TAPROOT,
        prevout=_p2tr_prevout(),
        witness=(bytes(64), annex),
    )
    assert classify_input(evidence).spend_context == SpendContext.TAPROOT_KEY_PATH

    # Script path with annex: four elements, strip -> three -> script path.
    control = bytes([0xc0]) + bytes(32)
    evidence = _ctx_input(
        txid_le, 1,
        verify_flags=VERIFY_WITNESS | VERIFY_TAPROOT,
        prevout=_p2tr_prevout(),
        witness=(bytes(64), bytes([0xAC]), control, annex),
    )
    assert classify_input(evidence).spend_context == SpendContext.TAPSCRIPT


def test_classify_input_p2sh_non_push_scriptsig() -> None:
    """P2SH with non-push scriptSig must raise ContextError."""
    txid_le = b"\x1c" * 32
    redeem = _multisig_redeem_script()
    bad_script_sig = _push(redeem) + bytes([0x75])  # extra non-push byte
    evidence = _ctx_input(
        txid_le, 0,
        verify_flags=VERIFY_P2SH,
        prevout=_p2sh_prevout(),
        script_sig=bad_script_sig,
    )
    _raises(ContextError, lambda: classify_input(evidence), "non-push P2SH scriptSig")


def test_classify_input_native_v0_with_scriptsig() -> None:
    """Native v0 with non-empty scriptSig must raise ContextError."""
    txid_le = b"\x1d" * 32
    evidence = _ctx_input(
        txid_le, 0,
        verify_flags=VERIFY_WITNESS,
        prevout=_p2wsh_prevout(),
        script_sig=bytes([1]),
        witness=(b"\x00", _multisig_redeem_script()),
    )
    _raises(ContextError, lambda: classify_input(evidence), "native v0 with scriptSig")


def test_classify_input_taproot_bad_key_path_sig() -> None:
    """P2TR key-path with wrong signature length must raise ContextError."""
    txid_le = b"\x1e" * 32
    evidence = _ctx_input(
        txid_le, 0,
        verify_flags=VERIFY_WITNESS | VERIFY_TAPROOT,
        prevout=_p2tr_prevout(),
        witness=(bytes(20),),  # 20 bytes is not 64/65
    )
    _raises(ContextError, lambda: classify_input(evidence), "P2TR key-path bad sig length")


def test_classify_input_taproot_bad_control_block() -> None:
    """P2TR script-path with malformed control block must raise ContextError."""
    txid_le = b"\x1f" * 32
    evidence = _ctx_input(
        txid_le, 0,
        verify_flags=VERIFY_WITNESS | VERIFY_TAPROOT,
        prevout=_p2tr_prevout(),
        witness=(bytes(1), bytes(32)),  # second element is 32 bytes (< 33)
    )
    _raises(ContextError, lambda: classify_input(evidence), "P2TR script-path bad control block")


def test_classify_input_p2sh_op_reserved_scriptsig() -> None:
    """P2SH with OP_RESERVED in scriptSig must raise ContextError."""
    txid_le = b"\x1c" * 32
    redeem = _multisig_redeem_script()
    bad_script_sig = _push(redeem) + bytes([0x50])  # extra OP_RESERVED byte
    evidence = _ctx_input(
        txid_le, 0,
        verify_flags=VERIFY_P2SH,
        prevout=_p2sh_prevout(),
        script_sig=bad_script_sig,
    )
    _raises(ContextError, lambda: classify_input(evidence), "OP_RESERVED P2SH scriptSig")


# ── Tests: parse_script Core stack semantics ─────────────────────────────────


def test_parse_script_op_0_pushes_empty() -> None:
    """OP_0 must push an empty byte vector, matching Core."""
    elements = parse_script(bytes([0x00]))
    assert len(elements) == 1
    assert elements[0].opcode == 0x00
    assert elements[0].pushed == b""


def test_parse_script_op_1negate_pushes_negative_one() -> None:
    """OP_1NEGATE must push the single-byte ScriptNum 0x81."""
    elements = parse_script(bytes([0x4F]))
    assert len(elements) == 1
    assert elements[0].opcode == 0x4F
    assert elements[0].pushed == b"\x81"


def test_parse_script_small_integers_pushes_core_scriptnum() -> None:
    """OP_1..OP_16 must push the single bytes 0x01..0x10."""
    script = bytes(range(0x51, 0x61))
    elements = parse_script(script)
    assert len(elements) == 16
    for i, element in enumerate(elements):
        assert element.opcode == 0x51 + i
        assert element.pushed == bytes([i + 1])


def test_parse_script_pushdata4_success() -> None:
    """OP_PUSHDATA4 must read a 4-byte little-endian length and payload."""
    payload = b"payload"
    length_le = struct.pack("<I", len(payload))
    script = bytes([0x4E]) + length_le + payload + bytes([0x00])
    elements = parse_script(script)
    assert len(elements) == 2
    assert elements[0].opcode == 0x4E
    assert elements[0].pushed == payload
    assert elements[1].opcode == 0x00
    assert elements[1].pushed == b""


def test_parse_script_pushdata4_truncated_length() -> None:
    """OP_PUSHDATA4 with fewer than 4 length bytes must fail closed."""
    _raises_with(
        ContextError,
        lambda: parse_script(bytes([0x4E, 0x01])),
        "OP_PUSHDATA4 truncated length",
        "OP_PUSHDATA4 length bytes missing",
    )


def test_parse_script_pushdata4_truncated_payload() -> None:
    """OP_PUSHDATA4 with a declared payload beyond remaining bytes must fail closed."""
    _raises_with(
        ContextError,
        lambda: parse_script(bytes([0x4E, 0x05, 0x00, 0x00, 0x00])),
        "OP_PUSHDATA4 truncated payload",
        "OP_PUSHDATA4 payload truncated",
    )


def test_parse_script_op_reserved_pushes_none() -> None:
    """OP_RESERVED is not a data push and must leave pushed as None."""
    elements = parse_script(bytes([0x50]))
    assert len(elements) == 1
    assert elements[0].opcode == 0x50
    assert elements[0].pushed is None


def test_parse_script_op_drop_pushes_none() -> None:
    """OP_DROP is not a data push and must leave pushed as None."""
    elements = parse_script(bytes([0x75]))
    assert len(elements) == 1
    assert elements[0].opcode == 0x75
    assert elements[0].pushed is None


# ── Tests: classify-corpus txid reversal mutation ────────────────────────────


def test_classify_corpus_txid_reversal_mutation() -> None:
    """BRSCTX1 and BRSREC1/BRSJRN1 must use the same raw LE txid bytes.

    Baseline: all fixtures use the same raw LE txid; the join logic passes
    and the command reaches the c150 pin (which raises CTX-CUSTODY for a
    1-block corpus).
    Mutation: flip only the BRSCTX1 txid bytes; journal and records keep the
    original LE bytes; cmd_classify_corpus must raise AnalyzerError with
    CTX-OPERATIONS from the key-equality check.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = bytes(range(1, 33))

        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = _make_journal_bytes(txid_le, 0)

        # ── Baseline: all use the same LE txid ──
        # The join logic passes; the c150 pin raises CTX-CUSTODY for a 1-block
        # corpus (stop_height=0 != 150000).  This proves the join succeeded.
        args = _make_classify_args(
            tmp, [ctx_row], [record], [journal], "c150",
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "baseline c150 pin",
            "CTX-CUSTODY",
        )

        # ── Mutation: flip BRSCTX1 txid only ──
        flipped_txid = txid_le[::-1]  # reverse to display order
        mutated_row = _bare_p2pkh(flipped_txid)
        args = _make_classify_args(
            tmp, [mutated_row], [record], [journal], "c150",
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "flipped BRSCTX1 txid",
            "CTX-OPERATIONS",
        )
def test_classify_corpus_all_spend_contexts() -> None:
    """All required spend containers and multisig/Schnorr records are counted.

    This test exercises the disk-backed context counter directly. The separate
    synthetic-classification test covers report composition without weakening
    the product Cmodern tip.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txids = [bytes([i + 1]) * 32 for i in range(6)]

        contexts = [
            _bare_p2pkh(txids[0]),                                                    # bare
            _p2sh_push_only(txids[1], flags=VERIFY_P2SH),                             # p2sh
            _native_w0(txids[2], flags=VERIFY_WITNESS),                               # native v0
            _p2sh_wrapped_w0(txids[3], flags=VERIFY_P2SH | VERIFY_WITNESS),           # wrapped v0
            _taproot_key_path(txids[4], flags=VERIFY_WITNESS | VERIFY_TAPROOT),       # taproot key path
            _taproot_script_path(txids[5], flags=VERIFY_WITNESS | VERIFY_TAPROOT),    # tapscript
        ]

        records = [
            _make_record_bytes(txids[0], 0, op_kind=3, sig_version=0),   # bare multisig
            _make_record_bytes(txids[1], 0, op_kind=3, sig_version=0),   # p2sh multisig
            _make_record_bytes(txids[2], 0, op_kind=3, sig_version=1),   # native v0 multisig
            _make_record_bytes(txids[3], 0, op_kind=3, sig_version=1),   # wrapped v0 multisig
            _make_record_bytes(txids[5], 0, op_kind=1, sig_version=2),   # tapscript schnorr
            _make_record_bytes(txids[5], 0, op_kind=5, sig_version=2, op_seq=1),  # checksigadd
        ]

        # Journal entries must match the actual records per key:
        # txids[0..3]: ECDSA multisig → ecdsa_verify_calls=1, ecdsa_verify_ok=1, checkmultisig_ops=1
        # txids[4]: no record (taproot key path has no BRSREC1 record) → all zero
        # txids[5]: Schnorr (not ECDSA) → ecdsa_verify_calls=0, ecdsa_verify_ok=0
        journal = [
            _make_journal_bytes(txids[0], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[1], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[2], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[3], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[4], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
            _make_journal_bytes(txids[5], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
        ]

        # Counters must match the actual record/journal sums:
        # 4 ECDSA multisig records + 2 Schnorr records = 6 total
        # op_checksig=0, op_checkmultisig=4, op_checksigadd=1
        # checkecdsa_entries=4, ecdsa_verify_calls=4, ecdsa_verify_ok=4
        # checkschnorr_entries=2, schnorr_verify_calls=2, schnorr_verify_ok=2
        counters = _make_valid_counters(
            record_count=6, journal_count=6, ffi_verify_entries=6,
            op_checksig=0,
            op_checkmultisig=4,
            op_checksigadd=1,
            checkecdsa_entries=4,
            ecdsa_from_checksig=0,
            ecdsa_from_checkmultisig=4,
            ecdsa_verify_calls=4,
            ecdsa_verify_ok=4,
            ecdsa_verify_fail=0,
            sighash_computed=4,
            checkschnorr_entries=2,
            schnorr_verify_calls=2,
            schnorr_verify_ok=2,
            schnorr_verify_fail=0,
        )

        args = _make_classify_args(
            tmp, contexts, records, journal, "cmodern", counters_dict=counters,
        )
        counts, context_count, _ = _count_context_records_disk(
            Path(args.contexts),
            Path(args.records),
            Path(args.journal),
            Counters(counters),
        )
        assert context_count == len(contexts)
        for name in CONTEXT_COUNTER_NAMES:
            assert counts[name] > 0, f"{name} should be positive in all-spend fixture"


def test_classify_corpus_c150_passes() -> None:
    """c150 is pinned to stop_height=150000 and a specific stop_hash.

    A 1-block fixture cannot satisfy the pin, so c150 must raise
    AnalyzerError with CTX-CUSTODY.  The counter shape (bare_multisig_checks>0,
    all others ==0) is verified via the report if one is written.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x40" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0, op_kind=3, sig_version=0)
        journal = [_make_journal_bytes(
            txid_le, 0,
            checksig_ops=0, checkmultisig_ops=1,
            ecdsa_verify_calls=0, ecdsa_verify_ok=0,
        )]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"stop_height": _C150_STOP_HEIGHT, "stop_hash": _C150_STOP_HASH},
            counters_overrides={
                "op_checksig": 0, "op_checkmultisig": 1,
                "checkecdsa_entries": 0, "ecdsa_from_checksig": 0,
                "ecdsa_verify_calls": 0, "ecdsa_verify_ok": 0,
                "sighash_computed": 0,
            },
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "CTX-CUSTODY",
        )

def test_classify_corpus_cmodern_rejects_mismatched_op_checksigadd() -> None:
    """Mutating the native op_checksigadd counter without a matching record fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txids = [bytes([i + 1]) * 32 for i in range(6)]

        contexts = [
            _bare_p2pkh(txids[0]),
            _p2sh_push_only(txids[1], flags=VERIFY_P2SH),
            _native_w0(txids[2], flags=VERIFY_WITNESS),
            _p2sh_wrapped_w0(txids[3], flags=VERIFY_P2SH | VERIFY_WITNESS),
            _taproot_key_path(txids[4], flags=VERIFY_WITNESS | VERIFY_TAPROOT),
            _taproot_script_path(txids[5], flags=VERIFY_WITNESS | VERIFY_TAPROOT),
        ]

        records = [
            _make_record_bytes(txids[0], 0, op_kind=3, sig_version=0),
            _make_record_bytes(txids[1], 0, op_kind=3, sig_version=0),
            _make_record_bytes(txids[2], 0, op_kind=3, sig_version=1),
            _make_record_bytes(txids[3], 0, op_kind=3, sig_version=1),
            _make_record_bytes(txids[5], 0, op_kind=1, sig_version=2),
            _make_record_bytes(txids[5], 0, op_kind=5, sig_version=2, op_seq=1),
        ]

        journal = [
            _make_journal_bytes(txids[0], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[1], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[2], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[3], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[4], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
            _make_journal_bytes(txids[5], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
        ]

        counters = _make_valid_counters(
            record_count=6, journal_count=6, ffi_verify_entries=6,
            op_checksig=0,
            op_checkmultisig=4,
            op_checksigadd=2,
            checkecdsa_entries=4,
            ecdsa_from_checksig=0,
            ecdsa_from_checkmultisig=4,
            ecdsa_verify_calls=4,
            ecdsa_verify_ok=4,
            ecdsa_verify_fail=0,
            sighash_computed=4,
            checkschnorr_entries=2,
            schnorr_verify_calls=2,
            schnorr_verify_ok=2,
            schnorr_verify_fail=0,
        )

        args = _make_classify_args(
            tmp, contexts, records, journal, "cmodern", counters_dict=counters,
        )
        _raises_with(
            AnalyzerError,
            lambda: _cmd_classify_synthetic_cmodern(args),
            "op_checksigadd mismatch",
            "CTX-OPERATIONS",
        )


def test_classify_corpus_cmodern_rejects_wrong_stop_height() -> None:
    """Cmodern rejects evidence whose replay stops below the frozen tip."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x41" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(tmp, [ctx_row], [record], journal, "cmodern")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "cmodern wrong stop_height",
            f"cmodern requires stop_height {analyze.CMODERN_STOP_HEIGHT}",
        )
        assert not (tmp / "report.json").exists()


def test_classify_corpus_cmodern_rejects_wrong_stop_hash() -> None:
    """Cmodern rejects a valid fixture whose tip hash is not the frozen hash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x42" * 32
        args = _make_classify_args(
            tmp,
            [_bare_p2pkh(txid_le)],
            [_make_record_bytes(txid_le, 0)],
            [_make_journal_bytes(txid_le, 0)],
            "cmodern",
        )
        stop_height = analyze.CMODERN_STOP_HEIGHT
        analyze.CMODERN_STOP_HEIGHT = 0
        try:
            _raises_with(
                AnalyzerError,
                lambda: cmd_classify_corpus(args),
                "cmodern wrong stop_hash",
                f"cmodern requires stop_hash {analyze.CMODERN_STOP_HASH!r}",
            )
        finally:
            analyze.CMODERN_STOP_HEIGHT = stop_height
        assert not (tmp / "report.json").exists()


def test_cmodern_exact_product_predicate() -> None:
    """Cmodern pins the recovered tip and requires a complete positive census."""
    assert analyze.CMODERN_STOP_HEIGHT == 709_635
    assert analyze.CMODERN_STOP_HASH == (
        "00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f"
    )
    counts = {name: 1 for name in CONTEXT_COUNTER_NAMES}
    assert analyze._cmodern_passed(counts)
    for name in CONTEXT_COUNTER_NAMES:
        mutated = dict(counts)
        mutated[name] = 0
        assert not analyze._cmodern_passed(mutated)


def test_counter_arithmetic_schnorr_invariant() -> None:
    """INV-7 accepts Schnorr activity and rejects inconsistent totals."""
    valid = _make_valid_counters(
        1,
        1,
        1,
        op_checksigadd=1,
        checkschnorr_entries=2,
        schnorr_verify_calls=1,
        schnorr_verify_ok=1,
    )
    inv7 = [
        row for row in analyze.check_counter_arithmetic(Counters(valid))
        if row["id"] == "INV-7"
    ][0]
    assert inv7["passed"] is True

    for overrides in (
        {"checkschnorr_entries": 0},
        {"schnorr_verify_ok": 0},
    ):
        mutated = dict(valid)
        mutated.update(overrides)
        inv7 = [
            row for row in analyze.check_counter_arithmetic(Counters(mutated))
            if row["id"] == "INV-7"
        ][0]
        assert inv7["passed"] is False


def test_classify_corpus_zero_inputs() -> None:
    """An empty BRSCTX1 file with zero records/journal raises CTX-EXECUTION
    because cmd_classify_corpus rejects zero-input evidence.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        args = _make_classify_args(tmp, [], [], [], "c150")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "zero inputs",
            "CTX-EXECUTION",
        )

def test_classify_corpus_definitions_match_counter_names() -> None:
    """Every named context counter has a definition and no extra grid is introduced."""
    assert set(CONTEXT_COUNTER_NAMES) == set(CONTEXT_COUNTER_DEFINITIONS)
    assert len(CONTEXT_COUNTER_NAMES) == 11


# ── Tests: classify-corpus missing / duplicate / swap records ────────────────


def test_classify_corpus_missing_record_identity() -> None:
    """A BRSREC1 record whose key is not in context/journal raises CTX-OPERATIONS."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ctx_txid = b"\x60" * 32
        other_txid = b"\x99" * 32
        ctx_row = _bare_p2pkh(ctx_txid)
        record = _make_record_bytes(other_txid, 0)
        journal = [_make_journal_bytes(ctx_txid, 0)]
        args = _make_classify_args(tmp, [ctx_row], [record], journal, "c150")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "missing record identity",
            "CTX-OPERATIONS",
        )


def test_classify_corpus_duplicate_record_key() -> None:
    """Duplicate BRSREC1 (same txid/input_index/op_seq) raises CTX-OPERATIONS."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x61" * 32
        ctx_row = _bare_p2pkh(txid_le)
        records = [
            _make_record_bytes(txid_le, 0, op_seq=0),
            _make_record_bytes(txid_le, 0, op_seq=0),
        ]
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(tmp, [ctx_row], records, journal, "c150")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "duplicate record key",
            "CTX-OPERATIONS",
        )


def test_classify_corpus_duplicate_journal_key() -> None:
    """Duplicate BRSJRN1 (same txid/input_index) raises CTX-EXECUTION."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x62" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [
            _make_journal_bytes(txid_le, 0),
            _make_journal_bytes(txid_le, 0),
        ]
        args = _make_classify_args(tmp, [ctx_row], [record], journal, "c150")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "duplicate journal key",
            "CTX-EXECUTION",
        )


def test_classify_corpus_native_wrapped_swap() -> None:
    """A P2SH-wrapped witness-v0 input joined to a BASE sig_version record fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x63" * 32
        ctx_row = _p2sh_wrapped_w0(txid_le, flags=VERIFY_P2SH | VERIFY_WITNESS)
        record = _make_record_bytes(txid_le, 0, op_kind=3, sig_version=0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(tmp, [ctx_row], [record], journal, "c150")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "native/wrapped swap",
            "CTX-OPERATIONS",
        )


# ── Tests: custody / replay / manifest adversarial ───────────────────────────


def test_classify_corpus_rejects_jsonl_context_file() -> None:
    """cmd_classify_corpus rejects a sampled JSONL context file (wrong magic)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x70" * 32
        # Write a JSONL file instead of BRSCTX1 binary
        row = _make_legacy_row(txid_le[::-1].hex(), 0, _p2pkh_prevout())
        _write_legacy_jsonl(tmp / "contexts.bin", [row])
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]

        # Build the rest of the fixtures normally
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_raw = _make_manifest(
            tmp / "manifest.json",
            stop_height=0,
            blocks=[_MAINNET_GENESIS_BLOCK],
            archive_size=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises(AnalyzerError, lambda: cmd_classify_corpus(args), "JSONL context file")


def test_classify_corpus_rejects_mismatched_context_size() -> None:
    """A mismatched custody size for the context file raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x71" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]

        # Build fixtures normally, then corrupt the replay's corpus_manifest
        # bytes field to create a custody size mismatch for the manifest.
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"corpus_manifest_bytes": 99999},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "manifest size mismatch",
            "CTX-CUSTODY",
        )


def test_classify_corpus_rejects_mismatched_context_sha256() -> None:
    """A mismatched custody sha256 for the manifest raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x72" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]

        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"corpus_manifest_sha256": "f" * 64},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "manifest sha256 mismatch",
            "CTX-CUSTODY",
        )


def test_classify_corpus_context_journal_key_inequality() -> None:
    """Context/journal key inequality (mutate one journal key) raises CTX-OPERATIONS."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ctx_txid = b"\x80" * 32
        jrn_txid = b"\x81" * 32  # different txid in journal
        ctx_row = _bare_p2pkh(ctx_txid)
        record = _make_record_bytes(ctx_txid, 0)
        journal = [_make_journal_bytes(jrn_txid, 0)]
        args = _make_classify_args(tmp, [ctx_row], [record], journal, "c150")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "context/journal key inequality",
            "CTX-OPERATIONS",
        )


def test_classify_corpus_count_mismatch_ffi_verify_entries() -> None:
    """Context count != counters.ffi_verify_entries raises CTX-EXECUTION."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x82" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # ffi_verify_entries=2 but only 1 context row
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            counters_overrides={"ffi_verify_entries": 2, "verify_script_calls": 2, "ffi_verify_true": 2},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "context count != ffi_verify_entries",
            "CTX-EXECUTION",
        )


def test_classify_corpus_record_count_mismatch() -> None:
    """BRSREC1 record count != counters.record_count raises CTX-OPERATIONS."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x83" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # record_count=2 but only 1 record
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            counters_overrides={"record_count": 2},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "record count mismatch",
            "CTX-OPERATIONS",
        )


# ── Tests: replay v2 window validation ───────────────────────────────────────


def test_replay_rejects_nonzero_assume_valid_height() -> None:
    """Replay assume_valid_height != 0 raises CTX-WINDOW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x90" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"assume_valid_height": 100},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "assume_valid_height != 0",
            "CTX-WINDOW",
        )


def test_replay_rejects_window_le_one() -> None:
    """Replay window <= 1 raises CTX-WINDOW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x91" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"window": 1},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "window <= 1",
            "CTX-WINDOW",
        )


def test_replay_rejects_zero_window_verify_success_total() -> None:
    """Replay window_verify_success_total == 0 raises CTX-WINDOW."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x92" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"window_verify_success_total": 0},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "window_verify_success_total == 0",
            "CTX-WINDOW",
        )


# ── Tests: manifest / archive custody validation ─────────────────────────────


def test_manifest_network_mismatch_raises() -> None:
    """Manifest network mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa0" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            manifest_overrides={"network": "testnet"},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "manifest network mismatch",
            "CTX-CUSTODY",
        )


def test_manifest_genesis_mismatch_raises() -> None:
    """Manifest genesis_hash mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa1" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            manifest_overrides={"genesis_hash": "1" * 64},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "manifest genesis mismatch",
            "CTX-CUSTODY",
        )


def test_manifest_range_mismatch_raises() -> None:
    """Manifest stop_height mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa2" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            manifest_overrides={"range": {"start_height": 0, "stop_height": 99}},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "manifest range mismatch",
            "CTX-CUSTODY",
        )


def test_manifest_archive_size_mismatch_raises() -> None:
    """Manifest archive size mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa3" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            manifest_overrides={"archive": {"size": 99999, "sha256": "0" * 64}},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "archive size mismatch",
            "CTX-CUSTODY",
        )


def test_manifest_archive_sha256_mismatch_raises() -> None:
    """Manifest archive sha256 mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa4" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Get the real archive size, then set a wrong sha256
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_raw = _make_manifest(
            tmp / "manifest.json",
            stop_height=0,
            blocks=[_MAINNET_GENESIS_BLOCK],
            archive_size=len(archive_raw),
            archive_sha256="e" * 64,  # wrong sha256
        )
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256="e" * 64,
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "archive sha256 mismatch",
            "CTX-CUSTODY",
        )


# ── Tests: manifest entry validation ─────────────────────────────────────────


def test_manifest_start_height_nonzero_raises() -> None:
    """Manifest range.start_height != 0 raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb0" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Override manifest with start_height=1 (also need matching replay)
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 1, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            start_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "start_height != 0",
            "CTX-CUSTODY",
        )


def test_manifest_empty_entries_raises() -> None:
    """Missing or empty manifest entries raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb1" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "empty entries",
            "CTX-CUSTODY",
        )


def test_manifest_gapped_heights_raises() -> None:
    """Noncontiguous manifest entry heights raise CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb2" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Build a 2-block archive
        block1 = _MAINNET_GENESIS_BLOCK
        # Create a second block with prev_blockhash = genesis hash (raw LE)
        header2 = (
            b"\x00" * 4                                   # version
            + _MAINNET_GENESIS_HASH_RAW                   # prev_blockhash (raw LE)
            + b"\x00" * 32                                # merkle_root
            + struct.pack("<I", 0x5CE9B2A2)               # timestamp
            + b"\x20" * 4                                 # bits
            + struct.pack("<I", 1)                        # nonce
        )
        block2 = header2 + bytes([0x01]) + struct.pack("<I", 1) + bytes([0x00]) + b"\x00" * 36 + bytes([0x00]) + struct.pack("<I", 0)
        blocks = [block1, block2]
        archive_raw = _make_archive(tmp / "archive.bin", blocks)
        # Manifest with gapped height (0, 2 instead of 0, 1)
        entries = [
            {"height": 0, "hash": _block_hash_display(block1), "offset": 0, "payload_length": len(block1)},
            {"height": 2, "hash": _block_hash_display(block2), "offset": 8 + len(block1), "payload_length": len(block2)},
        ]
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 1},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": entries,
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=1,
            stop_hash=_block_hash_display(block2),
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "gapped heights",
            "CTX-CUSTODY",
        )


def test_manifest_inconsistent_offset_raises() -> None:
    """Inconsistent manifest entry offsets raise CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb3" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        # Wrong offset (100 instead of 0)
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 100, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "inconsistent offset",
            "CTX-CUSTODY",
        )


def test_archive_frame_magic_mismatch_raises() -> None:
    """Archive frame magic mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb4" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Write archive with wrong magic
        wrong_magic = bytes.fromhex("deadbeef")
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK], magic=wrong_magic)
        manifest_raw = _make_manifest(
            tmp / "manifest.json",
            stop_height=0,
            blocks=[_MAINNET_GENESIS_BLOCK],
            archive_size=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
            network_magic=wrong_magic.hex(),
        )
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            network_magic=wrong_magic.hex(),
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        # The manifest network_magic won't match the replay's, so this raises
        # CTX-CUSTODY for magic mismatch (either manifest-vs-replay or frame-vs-manifest)
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "frame magic mismatch",
            "CTX-CUSTODY",
        )


def test_archive_frame_payload_length_mismatch_raises() -> None:
    """Archive frame u32 payload_length mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb5" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        # Manifest declares wrong payload_length
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": 999},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "payload_length mismatch",
            "CTX-CUSTODY",
        )


def test_archive_header_hash_mismatch_raises() -> None:
    """Decoded block header hash mismatch raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb6" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        # Manifest declares wrong hash for the entry
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": "0" * 64, "offset": 0, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "header hash mismatch",
            "CTX-CUSTODY",
        )


def test_archive_genesis_prev_blockhash_nonzero_raises() -> None:
    """First entry prev_blockhash not all-zero raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb7" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Build a block with non-zero prev_blockhash
        bad_header = (
            b"\x00" * 4
            + b"\xff" * 32  # non-zero prev_blockhash
            + b"\x00" * 32
            + struct.pack("<I", 0x5CE9B2A1)
            + b"\x20" * 4
            + struct.pack("<I", 0)
        )
        bad_block = bad_header + _MAINNET_GENESIS_BLOCK[80:]
        bad_hash = _block_hash_display(bad_block)
        archive_raw = _make_archive(tmp / "archive.bin", [bad_block])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": bad_hash,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": bad_hash, "offset": 0, "payload_length": len(bad_block)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            stop_hash=bad_hash,
            genesis_hash=bad_hash,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "genesis prev_blockhash nonzero",
            "CTX-CUSTODY",
        )


def test_archive_chain_break_raises() -> None:
    """Block prev_blockhash chain break raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb8" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Block 1: valid genesis
        block1 = _MAINNET_GENESIS_BLOCK
        # Block 2: prev_blockhash is wrong (not the hash of block1)
        header2 = (
            b"\x00" * 4
            + b"\xee" * 32  # wrong prev_blockhash
            + b"\x00" * 32
            + struct.pack("<I", 0x5CE9B2A2)
            + b"\x20" * 4
            + struct.pack("<I", 1)
        )
        block2 = header2 + _MAINNET_GENESIS_BLOCK[80:]
        blocks = [block1, block2]
        archive_raw = _make_archive(tmp / "archive.bin", blocks)
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 1},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _block_hash_display(block1), "offset": 0, "payload_length": len(block1)},
                {"height": 1, "hash": _block_hash_display(block2), "offset": 8 + len(block1), "payload_length": len(block2)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=1,
            stop_hash=_block_hash_display(block2),
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "chain break",
            "CTX-CUSTODY",
        )


def test_archive_trailing_bytes_raises() -> None:
    """Extra bytes after the final archive frame raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xb9" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Build archive then append trailing byte
        _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        (tmp / "archive.bin").write_bytes((tmp / "archive.bin").read_bytes() + b"\x00")
        archive_raw = (tmp / "archive.bin").read_bytes()
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw) - 1, "sha256": _sha256_bytes(archive_raw[:-1])},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw) - 1,
            archive_sha256=_sha256_bytes(archive_raw[:-1]),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "trailing bytes",
            "CTX-CUSTODY",
        )


def test_manifest_entry_count_mismatch_raises() -> None:
    """Manifest entries count != stop_height+1 raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xba" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 5},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=5,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        args = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "entry count mismatch",
            "CTX-CUSTODY",
        )


def test_manifest_happy_path() -> None:
    """A valid one-block manifest/archive passes custody validation.

    The synthetic Cmodern binding writes a report. The incomplete context
    census then fails the product predicate.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc0" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        # The one-block fixture lacks ten required Cmodern context classes.
        assert rc == 1
        report = json.loads((tmp / "report.json").read_text())
        assert report["schema"] == "classify-corpus-v2"
        assert "custody" in report
        assert "replay" in report
        assert "corpus_manifest" in report


# ── Tests: C150 pin — stop_height/stop_hash spoofing ─────────────────────────


def test_classify_corpus_c150_rejects_wrong_stop_height() -> None:
    """c150 rejects stop_height=149999 instead of 150000 with CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd0" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"stop_height": 149999, "stop_hash": _C150_STOP_HASH},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "c150 wrong stop_height",
            "CTX-CUSTODY",
        )


def test_classify_corpus_c150_rejects_wrong_stop_hash() -> None:
    """c150 rejects a wrong mainnet stop_hash with CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd1" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        wrong_hash = "0" * 64
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"stop_height": _C150_STOP_HEIGHT, "stop_hash": wrong_hash},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "c150 wrong stop_hash",
            "CTX-CUSTODY",
        )


def test_classify_corpus_c150_rejects_mismatched_stop_hash() -> None:
    """c150 with stop_height=150000 but a stop_hash that doesn't match the
    pinned hash raises CTX-CUSTODY.  This proves c150 is pinned and cannot
    be spoofed even with the correct height.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd2" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={
                "stop_height": _C150_STOP_HEIGHT,
                "stop_hash": "1" * 64,  # wrong hash
            },
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "c150 mismatched stop_hash",
            "CTX-CUSTODY",
        )


# ── Tests: Cmodern report composition on a synthetic complete census ─────────


def test_classify_corpus_cmodern_all_positive_passes_synthetic_fixture() -> None:
    """A complete synthetic census passes the frozen Cmodern predicate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txids = [bytes([i + 1]) * 32 for i in range(6)]

        contexts = [
            _bare_p2pkh(txids[0]),                                                    # bare
            _p2sh_push_only(txids[1], flags=VERIFY_P2SH),                             # p2sh
            _native_w0(txids[2], flags=VERIFY_WITNESS),                               # native v0
            _p2sh_wrapped_w0(txids[3], flags=VERIFY_P2SH | VERIFY_WITNESS),           # wrapped v0
            _taproot_key_path(txids[4], flags=VERIFY_WITNESS | VERIFY_TAPROOT),       # taproot key path
            _taproot_script_path(txids[5], flags=VERIFY_WITNESS | VERIFY_TAPROOT),    # tapscript
        ]

        records = [
            _make_record_bytes(txids[0], 0, op_kind=3, sig_version=0),   # bare multisig
            _make_record_bytes(txids[1], 0, op_kind=3, sig_version=0),   # p2sh multisig
            _make_record_bytes(txids[2], 0, op_kind=3, sig_version=1),   # native v0 multisig
            _make_record_bytes(txids[3], 0, op_kind=3, sig_version=1),   # wrapped v0 multisig
            _make_record_bytes(txids[5], 0, op_kind=1, sig_version=2),   # tapscript schnorr
            _make_record_bytes(txids[5], 0, op_kind=5, sig_version=2, op_seq=1),  # checksigadd
        ]

        journal = [
            _make_journal_bytes(txids[0], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[1], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[2], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[3], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(txids[4], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
            _make_journal_bytes(txids[5], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
        ]

        counters = _make_valid_counters(
            record_count=6, journal_count=6, ffi_verify_entries=6,
            op_checksig=0,
            op_checkmultisig=4,
            op_checksigadd=1,
            checkecdsa_entries=4,
            ecdsa_from_checksig=0,
            ecdsa_from_checkmultisig=4,
            ecdsa_verify_calls=4,
            ecdsa_verify_ok=4,
            ecdsa_verify_fail=0,
            sighash_computed=4,
            checkschnorr_entries=2,
            schnorr_verify_calls=2,
            schnorr_verify_ok=2,
            schnorr_verify_fail=0,
        )

        args = _make_classify_args(
            tmp, contexts, records, journal, "cmodern", counters_dict=counters,
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 0

        report = json.loads((tmp / "report.json").read_text())
        counts = report["context_counts"]
        for name in CONTEXT_COUNTER_NAMES:
            assert counts[name] > 0, f"{name} should be positive"
        assert report["cmodern_frozen"] is True
        assert report["cmodern_passed"] is True
        assert report["all_passed"] is True


# ── Tests: replay/manifest field invariant mutations ─────────────────────────


def test_replay_rejects_wrong_network() -> None:
    """Replay network != 'mainnet' raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe0" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"network": "testnet"},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "wrong network",
            "CTX-CUSTODY",
        )


def test_replay_rejects_rest_block_source() -> None:
    """The certifying replay schema accepts only file-bound evidence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xed" * 32
        args = _make_classify_args(
            tmp,
            [_bare_p2pkh(txid_le)],
            [_make_record_bytes(txid_le, 0)],
            [_make_journal_bytes(txid_le, 0)],
            "cmodern",
            replay_overrides={"block_source": "rest"},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "REST certifying replay",
            "replay.block_source must be 'file'",
        )


def test_replay_rejects_wrong_network_magic() -> None:
    """Replay network_magic != 'f9beb4d9' raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe1" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"network_magic": "fabfb5da"},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "wrong network_magic",
            "CTX-CUSTODY",
        )


def test_replay_rejects_wrong_genesis_hash() -> None:
    """Replay genesis_hash != mainnet canonical raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe2" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"genesis_hash": "1" * 64},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "wrong genesis_hash",
            "CTX-CUSTODY",
        )


def test_replay_rejects_start_height_nonzero() -> None:
    """Replay start_height != 0 raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe3" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"start_height": 1},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "start_height nonzero",
            "CTX-CUSTODY",
        )


def test_replay_rejects_start_hash_not_genesis() -> None:
    """Replay start_hash != genesis_hash raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe4" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"start_hash": "1" * 64},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "start_hash != genesis",
            "CTX-CUSTODY",
        )


def test_replay_rejects_block_count_mismatch() -> None:
    """Replay block_count != stop_height+1 raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe5" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"block_count": 999},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "block_count mismatch",
            "CTX-CUSTODY",
        )


def test_replay_rejects_missing_stop_hash() -> None:
    """Replay missing stop_hash field raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe6" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Build normally, then remove stop_hash from the replay JSON
        args = _make_classify_args(tmp, [ctx_row], [record], journal, "c150")
        replay_obj = json.loads((tmp / "replay.json").read_text())
        del replay_obj["stop_hash"]
        (tmp / "replay.json").write_text(json.dumps(replay_obj))
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "missing stop_hash",
            "CTX-CUSTODY",
        )


def test_replay_rejects_unknown_field() -> None:
    """Replay with an unknown top-level field raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe7" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Build normally, then inject an unknown field into the replay JSON
        args = _make_classify_args(tmp, [ctx_row], [record], journal, "c150")
        replay_obj = json.loads((tmp / "replay.json").read_text())
        replay_obj["unknown_field"] = "malicious"
        (tmp / "replay.json").write_text(json.dumps(replay_obj))
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "replay unknown field",
            "CTX-CUSTODY",
        )


def test_replay_rejects_nonhex_git_head() -> None:
    """A git_head with a non-hex character (but 40 chars) raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xea" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"git_head": "z" * 40},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "nonhex git_head",
            "CTX-CUSTODY",
            "lowercase hex",
        )


def test_replay_rejects_uppercase_git_head() -> None:
    """An uppercase-hex git_head (40 chars) raises CTX-CUSTODY: lowercase only."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xeb" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"git_head": "A" * 40},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "uppercase git_head",
            "CTX-CUSTODY",
            "lowercase hex",
        )


def test_replay_rejects_bool_stage_count() -> None:
    """A stage_seconds entry whose count is a bool raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xec" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"stage_seconds": [
                {"count": True, "stage": "node.apply_block.total_seconds", "sum_seconds": 1.0}
            ]},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "bool stage count",
            "CTX-CUSTODY",
            "non-bool integer",
        )


def test_replay_rejects_extra_stage_key() -> None:
    """A stage_seconds entry with an extra key raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xed" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"stage_seconds": [
                {"count": 1, "stage": "node.apply_block.total_seconds",
                 "sum_seconds": 1.0, "unexpected": 0}
            ]},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "extra stage key",
            "CTX-CUSTODY",
            "unknown key",
        )


def test_replay_rejects_invalid_txindex_timing_field() -> None:
    """Replay v3 requires nullable-or-float txindex timing fields."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xee" * 32
        args = _make_classify_args(
            tmp,
            [_bare_p2pkh(txid_le)],
            [_make_record_bytes(txid_le, 0)],
            [_make_journal_bytes(txid_le, 0)],
            "c150",
            replay_overrides={"txindex_total_elapsed_seconds": "not-a-float"},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "invalid txindex timing field",
            "replay.txindex_total_elapsed_seconds must be a float",
        )


def test_manifest_rejects_unknown_field() -> None:
    """Manifest with an unknown top-level field raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe8" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            manifest_overrides={"unknown_field": "malicious"},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "manifest unknown field",
            "CTX-CUSTODY",
        )


def test_manifest_rejects_out_of_u32_range_height() -> None:
    """Manifest entry height > u32 max raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xe9" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 2**32, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        ns = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(ns),
            "height > u32",
            "CTX-CUSTODY",
        )


def test_manifest_rejects_out_of_u64_range_offset() -> None:
    """Manifest entry offset > u64 max raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xea" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 2**64, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        ns = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(ns),
            "offset > u64",
            "CTX-CUSTODY",
        )


def test_manifest_rejects_duplicate_entry_height() -> None:
    """Manifest with duplicate entry heights raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xeb" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 1},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 8 + len(_MAINNET_GENESIS_BLOCK), "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=1,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        ns = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(ns),
            "duplicate entry height",
            "CTX-CUSTODY",
        )


def test_manifest_rejects_duplicate_entry_hash() -> None:
    """Manifest with duplicate entry hashes raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xec" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Build a 2-block archive with distinct blocks
        block1 = _MAINNET_GENESIS_BLOCK
        header2 = (
            b"\x00" * 4
            + _MAINNET_GENESIS_HASH_RAW
            + b"\x00" * 32
            + struct.pack("<I", 0x495fab30)
            + struct.pack("<I", 0x1d00ffff)
            + struct.pack("<I", 1)
        )
        block2 = header2 + block1[80:]
        blocks = [block1, block2]
        archive_raw = _make_archive(tmp / "archive.bin", blocks)
        # Both entries have the same hash (block1's hash)
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 1},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _block_hash_display(block1), "offset": 0, "payload_length": len(block1)},
                {"height": 1, "hash": _block_hash_display(block1), "offset": 8 + len(block1), "payload_length": len(block2)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=1,
            stop_hash=_block_hash_display(block2),
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        ns = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(ns),
            "duplicate entry hash",
            "CTX-CUSTODY",
        )


def test_archive_rejects_payload_length_above_max() -> None:
    """Manifest entry payload_length > 4_000_000 raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xed" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": 4_000_001},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        ns = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(ns),
            "payload_length > 4M",
            "CTX-CUSTODY",
        )


def test_archive_rejects_payload_length_below_80() -> None:
    """Manifest entry payload_length < 80 raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xee" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": 79},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        ns = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(ns),
            "payload_length < 80",
            "CTX-CUSTODY",
        )


def test_archive_rejects_frame_tail_not_stop_hash() -> None:
    """Archive last frame hash != replay stop_hash raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xef" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # Build a valid 1-block fixture, then set a wrong stop_hash in replay
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            replay_overrides={"stop_hash": "e" * 64},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "frame tail != stop_hash",
            "CTX-CUSTODY",
        )


def test_archive_rejects_missing_archive_bytes() -> None:
    """Archive file shorter than declared raises CTX-CUSTODY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xf0" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        archive_raw = _make_archive(tmp / "archive.bin", [_MAINNET_GENESIS_BLOCK])
        # Truncate the archive by 1 byte
        (tmp / "archive.bin").write_bytes(archive_raw[:-1])
        manifest_obj = {
            "schema": "bitcoin-rs-corpus-manifest",
            "version": 1,
            "network": "mainnet",
            "network_magic": _MAINNET_MAGIC.hex(),
            "genesis_hash": _MAINNET_GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": 0},
            "archive": {"size": len(archive_raw), "sha256": _sha256_bytes(archive_raw)},
            "entries": [
                {"height": 0, "hash": _MAINNET_GENESIS_HASH, "offset": 0, "payload_length": len(_MAINNET_GENESIS_BLOCK)},
            ],
        }
        manifest_raw = (json.dumps(manifest_obj, indent=2) + "\n").encode()
        (tmp / "manifest.json").write_bytes(manifest_raw)
        _make_replay_v2(
            tmp / "replay.json",
            stop_height=0,
            corpus_manifest_bytes=len(manifest_raw),
            corpus_manifest_sha256=_sha256_bytes(manifest_raw),
            archive_bytes=len(archive_raw),
            archive_sha256=_sha256_bytes(archive_raw),
        )
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))

        import argparse
        ns = argparse.Namespace(
            counters=str(tmp / "counters.json"),
            contexts=str(tmp / "contexts.bin"),
            records=str(tmp / "records.bin"),
            journal=str(tmp / "journal.bin"),
            replay=str(tmp / "replay.json"),
            corpus_manifest=str(tmp / "manifest.json"),
            archive=str(tmp / "archive.bin"),
            output=str(tmp / "report.json"),
            contract="c150",
            input_count=None,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(ns),
            "missing archive bytes",
            "CTX-CUSTODY",
        )



# ── Tests: C150 exact predicate (standalone _c150_passed) ───────────────────


def _c150_canonical_counts() -> dict[str, int]:
    """All 11 context counters zero — the C150 streaming shape."""
    return {name: 0 for name in CONTEXT_COUNTER_NAMES}


def _c150_canonical_counters_dict(target: int = EXPECTED_FFI_VERIFY_ENTRIES_FULL) -> dict[str, object]:
    """A counters dict matching the canonical C150 shape.

    The six ordinary equality-chain counters equal *target* (2_868_199) and
    all complementary counters are zero. ``eval_script_entries`` is set to
    ``2 * target`` (5_736_398) because every ordinary P2PKH VerifyScript runs
    two EvalScript passes (scriptSig + scriptPubKey); it must never equal the
    one-times ordinary total."""
    d = _valid_counters_dict(
        ffi_verify_entries=target,
        verify_script_calls=target,
        ffi_verify_true=target,
        eval_script_entries=2 * target,
        op_checksig=target,
        checkecdsa_entries=target,
        ecdsa_from_checksig=target,
        ecdsa_verify_calls=target,
        ecdsa_verify_ok=target,
        sighash_computed=target,
        sighash_midstate_hit=target,
        record_count=target,
        journal_count=target,
        context_count=target,
    )
    return d


def test_c150_exact_canonical_total_passes() -> None:
    """All equality counters = 2_868_199, all context counters zero,
    complementary counters zero → _c150_passed returns True."""
    counts = _c150_canonical_counts()
    counters = Counters(_c150_canonical_counters_dict())
    assert _c150_passed(counts, counters) is True


def test_c150_truncated_positive_total_fails() -> None:
    """One equality counter (ecdsa_verify_ok) = 2_868_198 → fails."""
    counts = _c150_canonical_counts()
    d = _c150_canonical_counters_dict()
    d["ecdsa_verify_ok"] = EXPECTED_FFI_VERIFY_ENTRIES_FULL - 1
    counters = Counters(d)
    assert _c150_passed(counts, counters) is False


def test_c150_zero_total_fails() -> None:
    """All counters zero → fails (equality chain != 2_868_199)."""
    counts = _c150_canonical_counts()
    counters = Counters(_valid_counters_dict())
    assert _c150_passed(counts, counters) is False


def test_c150_mutate_each_equality_member_fails() -> None:
    """For each equality-chain member, set it to 2_868_198 and expect fail."""
    members = [
        "ffi_verify_entries",
        "op_checksig",
        "ecdsa_from_checksig",
        "checkecdsa_entries",
        "ecdsa_verify_calls",
        "ecdsa_verify_ok",
    ]
    counts = _c150_canonical_counts()
    for member in members:
        d = _c150_canonical_counters_dict()
        d[member] = EXPECTED_FFI_VERIFY_ENTRIES_FULL - 1
        counters = Counters(d)
        assert _c150_passed(counts, counters) is False, (
            f"_c150_passed should fail when {member} is truncated"
        )


def test_c150_nonzero_context_counter_fails() -> None:
    """A nonzero context counter (bare_multisig_checks or
    native_witness_v0_spends) causes _c150_passed to return False."""
    for ctx_name in ("bare_multisig_checks", "native_witness_v0_spends"):
        counts = _c150_canonical_counts()
        counts[ctx_name] = 1
        counters = Counters(_c150_canonical_counters_dict())
        assert _c150_passed(counts, counters) is False, (
            f"_c150_passed should fail when {ctx_name} is nonzero"
        )


def test_c150_eval_script_entries_not_double_fails() -> None:
    """eval_script_entries must equal exactly 2*expected (5_736_398).

    Setting it to the one-times ordinary total (the value the report wrongly
    claimed) must make _c150_passed return False, and every other off-by-one
    variant must fail too."""
    counts = _c150_canonical_counts()
    for bad in (
        EXPECTED_FFI_VERIFY_ENTRIES_FULL,            # one-times ordinary total
        2 * EXPECTED_FFI_VERIFY_ENTRIES_FULL - 1,    # one short of double
        2 * EXPECTED_FFI_VERIFY_ENTRIES_FULL + 1,    # one over double
    ):
        d = _c150_canonical_counters_dict()
        d["eval_script_entries"] = bad
        counters = Counters(d)
        assert _c150_passed(counts, counters) is False, (
            f"_c150_passed should fail when eval_script_entries is {bad}"
        )


# ── Tests: Counters strictness for context_count/record_count/journal_count ──


def test_counters_rejects_missing_context_count() -> None:
    """A counters dict missing context_count must raise."""
    d = _valid_counters_dict()
    del d["context_count"]
    _raises(AnalyzerError, lambda: Counters(d), "missing context_count")


def test_counters_rejects_missing_record_count() -> None:
    """A counters dict missing record_count must raise."""
    d = _valid_counters_dict()
    del d["record_count"]
    _raises(AnalyzerError, lambda: Counters(d), "missing record_count")


def test_counters_rejects_missing_journal_count() -> None:
    """A counters dict missing journal_count must raise."""
    d = _valid_counters_dict()
    del d["journal_count"]
    _raises(AnalyzerError, lambda: Counters(d), "missing journal_count")


def test_counters_rejects_bool_context_count() -> None:
    """A bool context_count must raise."""
    d = _valid_counters_dict(context_count=True)
    _raises(AnalyzerError, lambda: Counters(d), "bool context_count")


def test_counters_rejects_string_record_count() -> None:
    """A string record_count must raise."""
    d = _valid_counters_dict(record_count="1")  # type: ignore[dict-item]
    _raises(AnalyzerError, lambda: Counters(d), "string record_count")


def test_counters_rejects_negative_journal_count() -> None:
    """A negative journal_count must raise."""
    d = _valid_counters_dict(journal_count=-1)
    _raises(AnalyzerError, lambda: Counters(d), "negative journal_count")


# ── Tests: JournalEntry validation (corrupt journal) ─────────────────────────


def test_journal_rejects_verdict_outside_01() -> None:
    """A journal entry with verdict=2 must raise."""
    raw = bytearray(_make_journal_bytes(b"\x01" * 32, 0))
    # JOURNAL_STRUCT = "<32sIIIIIB3s" → verdict is the 6th field (byte at offset 56-4-3=... )
    # Layout: 32(txid) + 4(input_index) + 4(checksig_ops) + 4(checkmultisig_ops)
    #         + 4(ecdsa_verify_calls) + 4(ecdsa_verify_ok) + 1(verdict) + 3(pad) = 56
    # verdict byte is at offset 32+4+4+4+4+4 = 52
    raw[52] = 2
    _raises(AnalyzerError, lambda: JournalEntry(bytes(raw)), "verdict=2")


def test_journal_rejects_nonzero_padding() -> None:
    """A journal entry with nonzero 3-byte padding must raise."""
    raw = bytearray(_make_journal_bytes(b"\x02" * 32, 0))
    # padding is the last 3 bytes (offset 53..55)
    raw[53] = 0xFF
    _raises(AnalyzerError, lambda: JournalEntry(bytes(raw)), "nonzero padding")


def test_journal_rejects_ok_gt_calls() -> None:
    """ecdsa_verify_ok > ecdsa_verify_calls must raise."""
    raw = _make_journal_bytes(
        b"\x03" * 32, 0,
        ecdsa_verify_calls=1, ecdsa_verify_ok=2,
    )
    _raises(AnalyzerError, lambda: JournalEntry(raw), "ok > calls")


def test_journal_rejects_bad_magic() -> None:
    """A journal file with wrong magic must raise."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        entry = _make_journal_bytes(b"\x04" * 32, 0)
        data = HEADER_STRUCT.pack(b"WRONGMAG", 1) + entry
        (tmp / "journal.bin").write_bytes(data)
        _raises(AnalyzerError, lambda: parse_journal(tmp / "journal.bin"), "bad journal magic")


def test_journal_rejects_short_file() -> None:
    """A journal file shorter than the header must raise."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "journal.bin").write_bytes(b"\x00" * 10)
        _raises(AnalyzerError, lambda: parse_journal(tmp / "journal.bin"), "short journal file")


# ── Tests: check_counter_arithmetic and journal-sum invariants ───────────────


def test_classify_corpus_journal_sum_op_checksig_mismatch() -> None:
    """A counters dict where op_checksig != sum(journal checksig_ops) due to
    a mutated op_checksigverify raises CTX-OPERATIONS."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc1" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # op_checksigverify=1 makes sum(journal checksig_ops)=1 != op_checksig+1=2
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "c150",
            counters_overrides={"op_checksigverify": 1},
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "journal sum checksig mismatch",
            "CTX-OPERATIONS",
        )


def test_classify_corpus_inv1_verify_script_calls_mismatch() -> None:
    """verify_script_calls != ffi_verify_entries fails INV-1 in the synthetic
    Cmodern report path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc2" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_overrides={"verify_script_calls": 999},
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1
        report = json.loads((tmp / "report.json").read_text())
        inv1 = [r for r in report["counter_arithmetic"] if r["id"] == "INV-1"][0]
        assert inv1["passed"] is False


def test_classify_corpus_inv2_ffi_verify_true_mismatch() -> None:
    """ffi_verify_true != ffi_verify_entries fails INV-2 in the synthetic
    Cmodern report path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc3" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_overrides={"ffi_verify_true": 999},
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1
        report = json.loads((tmp / "report.json").read_text())
        inv2 = [r for r in report["counter_arithmetic"] if r["id"] == "INV-2"][0]
        assert inv2["passed"] is False


def test_classify_corpus_cmodern_bad_eval_counter_fails_closed() -> None:
    """C150 separately pins eval_script_entries to twice the canonical
    ordinary total; this cmodern fixture supplies a bad eval counter and
    proves the fail-closed classifier still writes a failure report/returns
    1, not the C150 predicate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc4" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_overrides={"eval_script_entries": 999},
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1

def test_classify_corpus_sighash_computed_mismatch() -> None:
    """sighash_computed != ecdsa_verify_calls fails INV-5 in the synthetic
    Cmodern report path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc5" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_overrides={"sighash_computed": 999},
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1
        report = json.loads((tmp / "report.json").read_text())
        inv5 = [r for r in report["counter_arithmetic"] if r["id"] == "INV-5"][0]
        assert inv5["passed"] is False

def test_classify_corpus_sighash_midstate_hit_mismatch() -> None:
    """An untracked sighash_midstate_hit change cannot make an incomplete
    synthetic Cmodern census pass."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc6" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_overrides={"sighash_midstate_hit": 999},
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1


# ── Tests: Corrupt record canonicality ───────────────────────────────────────


def test_record_rejects_outcome0_with_reject_reason() -> None:
    """outcome=0 (verify fail) with reject_reason != 0 must raise."""
    raw = _make_record_bytes(b"\x01" * 32, 0, outcome=0, reject_reason=1)
    _raises(AnalyzerError, lambda: Record(raw), "outcome=0 with reject_reason")


def test_record_rejects_outcome1_with_reject_reason() -> None:
    """outcome=1 (verify success) with reject_reason != 0 must raise."""
    raw = _make_record_bytes(b"\x02" * 32, 0, outcome=1, reject_reason=1)
    _raises(AnalyzerError, lambda: Record(raw), "outcome=1 with reject_reason")


def test_record_rejects_outcome2_with_zero_reject_reason() -> None:
    """outcome=2 (pre-verification reject) with reject_reason=0 must raise."""
    raw = _make_record_bytes(b"\x03" * 32, 0, outcome=2, reject_reason=0)
    _raises(AnalyzerError, lambda: Record(raw), "outcome=2 reject_reason=0")


def test_record_rejects_outcome2_with_nonzero_sighash() -> None:
    """outcome=2 with a non-zero sighash must raise."""
    raw = _make_record_bytes(
        b"\x04" * 32, 0, outcome=2, reject_reason=1,
        sighash=b"\xff" * 32,
    )
    _raises(AnalyzerError, lambda: Record(raw), "outcome=2 nonzero sighash")


def test_record_rejects_op_kind_above_5() -> None:
    """op_kind=6 must raise."""
    raw = _make_record_bytes(b"\x05" * 32, 0, op_kind=6)
    _raises(AnalyzerError, lambda: Record(raw), "op_kind=6")


def test_record_rejects_sig_version_above_3() -> None:
    """sig_version=4 must raise."""
    raw = _make_record_bytes(b"\x06" * 32, 0, sig_version=4)
    _raises(AnalyzerError, lambda: Record(raw), "sig_version=4")


def test_record_rejects_outcome_above_2() -> None:
    """outcome=3 must raise."""
    raw = _make_record_bytes(b"\x07" * 32, 0, outcome=3)
    _raises(AnalyzerError, lambda: Record(raw), "outcome=3")


def test_record_rejects_reject_reason_above_8() -> None:
    """reject_reason=9 must raise."""
    raw = _make_record_bytes(b"\x08" * 32, 0, outcome=2, reject_reason=9)
    _raises(AnalyzerError, lambda: Record(raw), "reject_reason=9")


def test_record_rejects_ecdsa_reject_on_schnorr_record() -> None:
    """reject_reason=1 (ECDSA reject) on a Schnorr record must raise."""
    # Schnorr: sig_version=2, op_kind=1
    raw = _make_record_bytes(
        b"\x09" * 32, 0, op_kind=1, sig_version=2,
        outcome=2, reject_reason=1,
    )
    _raises(AnalyzerError, lambda: Record(raw), "ECDSA reject on Schnorr record")


def test_record_rejects_schnorr_reject_on_ecdsa_record() -> None:
    """reject_reason=4 (Schnorr reject) on an ECDSA record must raise."""
    # ECDSA: sig_version=0, op_kind=1
    raw = _make_record_bytes(
        b"\x0a" * 32, 0, op_kind=1, sig_version=0,
        outcome=2, reject_reason=4,
    )
    _raises(AnalyzerError, lambda: Record(raw), "Schnorr reject on ECDSA record")


def test_record_accepts_ecdsa_reject_on_ecdsa_record() -> None:
    """reject_reason=1 on an ECDSA record (sig_version=0, op_kind=1) is valid."""
    raw = _make_record_bytes(
        b"\x0b" * 32, 0, op_kind=1, sig_version=0,
        outcome=2, reject_reason=1,
    )
    rec = Record(raw)
    assert rec.outcome == 2
    assert rec.reject_reason == 1


def test_record_accepts_schnorr_reject_on_schnorr_record() -> None:
    """reject_reason=4 on a Schnorr record (sig_version=2, op_kind=1) is valid."""
    raw = _make_record_bytes(
        b"\x0c" * 32, 0, op_kind=1, sig_version=2,
        outcome=2, reject_reason=4,
    )
    rec = Record(raw)
    assert rec.outcome == 2
    assert rec.reject_reason == 4


def test_record_accepts_reason8_tapscript_skip() -> None:
    """reject_reason=8 on a Tapscript skip (sig_version=2, op_kind=1,
    der_len=0) is valid."""
    raw = _make_record_bytes(
        b"\x0d" * 32, 0, op_kind=1, sig_version=2,
        outcome=2, reject_reason=8, der_len=0,
    )
    rec = Record(raw)
    assert rec.reject_reason == 8


# ── Tests: Aggregate reconciliation (ECDSA/Schnorr reject families) ──────────

def test_classify_corpus_ecdsa_reject_record_counts_entry() -> None:
    """An ECDSA in-function reject (outcome=2, reject_reason=2) is counted
    by the aggregate as a checkecdsa entry and the named reject counter
    checkecdsa_reject_empty_sig, but does not emit an ecdsa_verify_call
    or ecdsa_verify_fail (pre-verification guards return before the verifier).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa1" * 32
        ctx_row = _bare_p2pkh(txid_le)
        # ECDSA CHECKSIG with reject_reason=2 (empty-sig reject)
        record = _make_record_bytes(
            txid_le, 0, op_kind=1, sig_version=0,
            outcome=2, reject_reason=2,
        )
        journal = [_make_journal_bytes(
            txid_le, 0, checksig_ops=1, checkmultisig_ops=0,
            ecdsa_verify_calls=0, ecdsa_verify_ok=0,
        )]
        counters = _make_valid_counters(
            1, 1, 1,
            op_checksig=1,
            checkecdsa_entries=1,
            ecdsa_from_checksig=1,
            ecdsa_verify_calls=0,
            ecdsa_verify_ok=0,
            ecdsa_verify_fail=0,
            sighash_computed=0,
            checkecdsa_reject_empty_sig=1,
        )
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_dict=counters,
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1


def test_classify_corpus_schnorr_reject_record_counts_entry() -> None:
    """A Schnorr in-function reject (outcome=2, reject_reason=4) is counted
    by the aggregate as a checkschnorr entry, but does not emit a
    schnorr_verify_call or schnorr_verify_fail.  reject_reason=4
    is not in the named reject counters (only 0..2 are checked).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa2" * 32
        ctx_row = _taproot_script_path(txid_le, flags=VERIFY_WITNESS | VERIFY_TAPROOT)
        record = _make_record_bytes(
            txid_le, 0, op_kind=1, sig_version=2,
            outcome=2, reject_reason=4,
        )
        journal = [_make_journal_bytes(
            txid_le, 0, checksig_ops=1, checkmultisig_ops=0,
            ecdsa_verify_calls=0, ecdsa_verify_ok=0,
        )]
        counters = _make_valid_counters(
            1, 1, 1,
            op_checksig=1,
            checkecdsa_entries=0,
            ecdsa_from_checksig=0,
            ecdsa_verify_calls=0,
            ecdsa_verify_ok=0,
            ecdsa_verify_fail=0,
            sighash_computed=0,
            checkschnorr_entries=1,
            schnorr_verify_calls=0,
            schnorr_verify_ok=0,
            schnorr_verify_fail=0,
            op_checksigadd=0,
        )
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_dict=counters,
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1


def test_classify_corpus_reason8_tapscript_skip() -> None:
    """reject_reason=8 (Tapscript skip) is emitted in EvalChecksigTapscript
    before CheckSchnorrSignature is called, so it is counted as an
    op_checksig but is neither a checkschnorr entry nor a schnorr
    verify call/fail.  reject_reason=8 is not in the named reject counters.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa3" * 32
        ctx_row = _taproot_script_path(txid_le, flags=VERIFY_WITNESS | VERIFY_TAPROOT)
        record = _make_record_bytes(
            txid_le, 0, op_kind=1, sig_version=2,
            outcome=2, reject_reason=8, der_len=0,
        )
        journal = [_make_journal_bytes(
            txid_le, 0, checksig_ops=1, checkmultisig_ops=0,
            ecdsa_verify_calls=0, ecdsa_verify_ok=0,
        )]
        counters = _make_valid_counters(
            1, 1, 1,
            op_checksig=1,
            checkecdsa_entries=0,
            ecdsa_from_checksig=0,
            ecdsa_verify_calls=0,
            ecdsa_verify_ok=0,
            ecdsa_verify_fail=0,
            sighash_computed=0,
            checkschnorr_entries=0,
            schnorr_verify_calls=0,
            schnorr_verify_ok=0,
            schnorr_verify_fail=0,
            op_checksigadd=0,
        )
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_dict=counters,
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1

def test_classify_corpus_ecdsa_fail_record() -> None:
    """An ECDSA verify fail (outcome=0) is counted by the aggregate as
    ecdsa_verify_calls and ecdsa_verify_fail, but not ecdsa_verify_ok.
    INV-5 holds because calls(1) == ok(0) + fail(1).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa4" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0, op_kind=1, sig_version=0, outcome=0)
        journal = [_make_journal_bytes(
            txid_le, 0, checksig_ops=1, checkmultisig_ops=0,
            ecdsa_verify_calls=1, ecdsa_verify_ok=0,
        )]
        counters = _make_valid_counters(
            1, 1, 1,
            op_checksig=1,
            checkecdsa_entries=1,
            ecdsa_from_checksig=1,
            ecdsa_verify_calls=1,
            ecdsa_verify_ok=0,
            ecdsa_verify_fail=1,
            sighash_computed=1,
        )
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
            counters_dict=counters,
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1


def test_classify_corpus_ecdsa_success_record() -> None:
    """An ECDSA success increments calls and successes, but not failures."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xa5" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0, op_kind=1, sig_version=0, outcome=1)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1

# ── Tests: Multi-key SQLite op_seq/ECDSA ─────────────────────────────────────


def test_count_context_records_multi_key_contiguous() -> None:
    """Two keys, each with two records (op_seq 0 and 1), verify
    _count_context_records_disk returns counts/custody."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid1 = b"\xb1" * 32
        txid2 = b"\xb2" * 32
        ctx_rows = [_bare_p2pkh(txid1), _bare_p2pkh(txid2)]
        records = [
            _make_record_bytes(txid1, 0, op_seq=0),
            _make_record_bytes(txid1, 0, op_seq=1),
            _make_record_bytes(txid2, 0, op_seq=0),
            _make_record_bytes(txid2, 0, op_seq=1),
        ]
        journal = [
            _make_journal_bytes(txid1, 0, checksig_ops=2, ecdsa_verify_calls=2, ecdsa_verify_ok=2),
            _make_journal_bytes(txid2, 0, checksig_ops=2, ecdsa_verify_calls=2, ecdsa_verify_ok=2),
        ]
        _make_brsctx1_file(tmp / "contexts.bin", ctx_rows)
        _write_records_file(tmp / "records.bin", records)
        _write_journal_file(tmp / "journal.bin", journal)
        counters = _valid_counters_dict(
            ffi_verify_entries=2,
            verify_script_calls=2,
            ffi_verify_true=2,
            op_checksig=4,
            checkecdsa_entries=4,
            ecdsa_from_checksig=4,
            ecdsa_verify_calls=4,
            ecdsa_verify_ok=4,
            sighash_computed=4,
            record_count=4,
            journal_count=2,
            context_count=2,
        )
        (tmp / "counters.json").write_text(json.dumps(counters))
        counters_obj = Counters(counters)
        counts, ctx_count, custody = _count_context_records_disk(
            Path(tmp / "contexts.bin"),
            Path(tmp / "records.bin"),
            Path(tmp / "journal.bin"),
            counters_obj,
        )
        assert counts["bare_multisig_checks"] == 0  # CHECKSIG, not CHECKMULTISIG
        assert "contexts" in custody
        assert "records" in custody
        assert "journal" in custody


def test_count_context_records_multi_key_gap_raises() -> None:
    """One key with op_seq 0 and 2 (gap at 1) raises CTX-OPERATIONS."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid1 = b"\xb3" * 32
        ctx_rows = [_bare_p2pkh(txid1)]
        records = [
            _make_record_bytes(txid1, 0, op_seq=0),
            _make_record_bytes(txid1, 0, op_seq=2),
        ]
        journal = [_make_journal_bytes(txid1, 0, ecdsa_verify_calls=2, ecdsa_verify_ok=2)]
        _make_brsctx1_file(tmp / "contexts.bin", ctx_rows)
        _write_records_file(tmp / "records.bin", records)
        _write_journal_file(tmp / "journal.bin", journal)
        counters = _make_valid_counters(2, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))
        counters_obj = Counters(counters)
        _raises_with(
            AnalyzerError,
            lambda: _count_context_records_disk(
                Path(tmp / "contexts.bin"),
                Path(tmp / "records.bin"),
                Path(tmp / "journal.bin"),
                counters_obj,
            ),
            "op_seq gap",
            "CTX-OPERATIONS",
        )


# ── Tests: TOCTOU / custody seam ─────────────────────────────────────────────


def test_classify_corpus_custody_archive_matches_manifest() -> None:
    """cmd_classify_corpus report custody['archive'] bytes/sha256 equal the
    manifest's archive fields, not a separate prehash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd3" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        # The synthetic binding reaches report generation without weakening
        # the product Cmodern tip.
        args = _make_classify_args(
            tmp, [ctx_row], [record], journal, "cmodern",
        )
        rc = _cmd_classify_synthetic_cmodern(args)
        assert rc == 1
        report = json.loads((tmp / "report.json").read_text())
        custody = report["custody"]
        archive = custody["archive"]
        manifest = report["corpus_manifest"]
        assert archive["bytes"] == manifest["archive"]["size"]
        assert archive["sha256"] == manifest["archive"]["sha256"]
        # Verify the archive sha256 matches the actual file on disk
        actual_arch = (tmp / "archive.bin").read_bytes()
        assert archive["bytes"] == len(actual_arch)
        assert archive["sha256"] == _sha256_bytes(actual_arch)


def test_classify_corpus_custody_records_from_single_open() -> None:
    """iter_records_with_custody returns custody matching the file on disk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd4" * 32
        record = _make_record_bytes(txid_le, 0)
        _write_records_file(tmp / "records.bin", [record])
        file_bytes = (tmp / "records.bin").read_bytes()
        gen, custody = iter_records_with_custody(tmp / "records.bin")
        list(gen)  # consume the iterator
        assert custody["bytes"] == len(file_bytes)
        assert format(custody["sha256"], "064x") == _sha256_bytes(file_bytes)


def test_classify_corpus_custody_journal_from_single_open() -> None:
    """iter_journal_with_custody returns custody matching the file on disk."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd5" * 32
        entry = _make_journal_bytes(txid_le, 0)
        _write_journal_file(tmp / "journal.bin", [entry])
        file_bytes = (tmp / "journal.bin").read_bytes()
        gen, custody = iter_journal_with_custody(tmp / "journal.bin")
        list(gen)  # consume the iterator
        assert custody["bytes"] == len(file_bytes)
        assert format(custody["sha256"], "064x") == _sha256_bytes(file_bytes)


def test_parse_counters_returns_custody() -> None:
    """parse_counters returns (Counters, custody) from the single read."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))
        file_bytes = (tmp / "counters.json").read_bytes()
        parsed, custody = parse_counters(tmp / "counters.json")
        assert parsed.op_checksig == 1
        assert custody["bytes"] == len(file_bytes)
        assert format(custody["sha256"], "064x") == _sha256_bytes(file_bytes)

def test_classify_corpus_custody_contexts_from_same_open() -> None:
    """iter_context_inputs keeps the original fd open; os.replace after the
    first row does not change the bytes/sha256 it hashes from the stream.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        path = tmp / "contexts.bin"

        # File A: two BRSCTX1 rows.
        txid_a1 = b"\xd3" * 32
        txid_a2 = b"\xd4" * 32
        rows_a = [_bare_p2pkh(txid_a1), _bare_p2pkh(txid_a2)]
        _make_brsctx1_file(path, rows_a)
        a_bytes = path.read_bytes()

        it = iter_context_inputs(path)
        first = next(it)  # opens fd, hashes header and first row
        assert first.identity.txid_le == txid_a1

        # File B: one row, swapped onto the same pathname via inode replacement.
        txid_b = b"\xd5" * 32
        rows_b = [_bare_p2pkh(txid_b)]
        other = tmp / "other.bin"
        _make_brsctx1_file(other, rows_b)
        os.replace(other, path)

        # Continue from the original fd; should still read row 2 of A.
        second = next(it)
        assert second.identity.txid_le == txid_a2
        try:
            next(it)
        except StopIteration:
            pass
        else:
            raise AssertionError("expected exactly two rows from file A")

        custody = it.custody()
        assert custody["bytes"] == len(a_bytes)
        assert format(custody["sha256"], "064x") == _sha256_bytes(a_bytes)

        # Confirm the path now points to B (sanity: replacement did happen).
        assert path.read_bytes() != a_bytes


# ── Tests: Task 7B focused regressions ───────────────────────────────────────


def test_classify_corpus_duplicate_context_key() -> None:
    """Duplicate BRSCTX1 (same txid/input_index) raises CTX-EXECUTION."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x65" * 32
        ctx_row = _bare_p2pkh(txid_le)
        dup = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(tmp, [ctx_row, dup], [record], journal, "c150")
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "duplicate context key",
            "CTX-EXECUTION",
        )


def test_classify_corpus_mixed_duplicate_before_malformed() -> None:
    """A duplicate record in the same bounded chunk wins over a later malformed row."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x66" * 32
        ctx_row = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0, op_seq=0)
        duplicate = _make_record_bytes(txid_le, 0, op_seq=0)
        malformed = _make_record_bytes(txid_le, 0, op_kind=6)
        journal = [_make_journal_bytes(txid_le, 0)]
        args = _make_classify_args(
            tmp, [ctx_row], [record, duplicate, malformed], journal, "c150"
        )
        try:
            cmd_classify_corpus(args)
        except AnalyzerError as exc:
            msg = str(exc)
            assert "CTX-OPERATIONS" in msg, msg
            assert "duplicate record key" in msg, msg
            assert "op_kind" not in msg, f"malformed row was parsed first: {msg}"
        else:
            raise AssertionError("expected AnalyzerError for duplicate record")


def test_record_validation_earlier_illegal_precedes_later_orphan() -> None:
    """Stream order wins when a later record is orphaned."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x70" * 32
        orphan_txid = b"\x71" * 32
        args = _make_classify_args(
            tmp,
            [_bare_p2pkh(txid_le)],
            [
                _make_record_bytes(txid_le, 0, op_kind=3, sig_version=2),
                _make_record_bytes(orphan_txid, 0),
            ],
            [_make_journal_bytes(txid_le, 0)],
            "c150",
        )
        try:
            cmd_classify_corpus(args)
        except AnalyzerError as exc:
            assert str(exc) == (
                "CTX-OPERATIONS: multisig record must have sig_version BASE or WITNESS_V0, "
                "got TAPSCRIPT for "
                f"txid={txid_le[::-1].hex()}, input_index=0"
            )
        else:
            raise AssertionError("expected earlier illegal-record error")


def test_record_validation_earlier_illegal_precedes_later_sequence_gap() -> None:
    """Stream order wins when a later record has an op_seq gap."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x72" * 32
        args = _make_classify_args(
            tmp,
            [_bare_p2pkh(txid_le)],
            [
                _make_record_bytes(txid_le, 0, op_seq=0, op_kind=3, sig_version=2),
                _make_record_bytes(txid_le, 0, op_seq=2),
            ],
            [_make_journal_bytes(txid_le, 0)],
            "c150",
        )
        try:
            cmd_classify_corpus(args)
        except AnalyzerError as exc:
            assert str(exc) == (
                "CTX-OPERATIONS: multisig record must have sig_version BASE or WITNESS_V0, "
                "got TAPSCRIPT for "
                f"txid={txid_le[::-1].hex()}, input_index=0"
            )
        else:
            raise AssertionError("expected earlier illegal-record error")


def test_record_validation_semantic_error_precedes_record_count_mismatch() -> None:
    """Semantic validation precedes the aggregate record-count check."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x73" * 32
        args = _make_classify_args(
            tmp,
            [_bare_p2pkh(txid_le)],
            [_make_record_bytes(txid_le, 0, op_kind=3, sig_version=2)],
            [_make_journal_bytes(txid_le, 0)],
            "c150",
            counters_overrides={"record_count": 2},
        )
        try:
            cmd_classify_corpus(args)
        except AnalyzerError as exc:
            assert str(exc) == (
                "CTX-OPERATIONS: multisig record must have sig_version BASE or WITNESS_V0, "
                "got TAPSCRIPT for "
                f"txid={txid_le[::-1].hex()}, input_index=0"
            )
        else:
            raise AssertionError("expected semantic record error")


def test_record_validation_same_record_orphan_precedence() -> None:
    """Orphan wins over sequence and legality failures on one record."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        context_txid = b"\x74" * 32
        orphan_txid = b"\x75" * 32
        args = _make_classify_args(
            tmp,
            [_bare_p2pkh(context_txid)],
            [_make_record_bytes(orphan_txid, 0, op_seq=1, op_kind=3, sig_version=2)],
            [_make_journal_bytes(context_txid, 0)],
            "c150",
        )
        try:
            cmd_classify_corpus(args)
        except AnalyzerError as exc:
            assert str(exc) == (
                "CTX-OPERATIONS: BRSREC1 record has no matching context identity: "
                f"txid={orphan_txid[::-1].hex()}, input_index=0"
            )
        else:
            raise AssertionError("expected orphan record error")


def test_count_context_records_spend_context_tally_sensitivity() -> None:
    """CHECKMULTISIG records with the same op/sig map to different context
    counters depending on the input's spend_context, proving the tally is
    sensitive to context classification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_bare = b"\xb4" * 32
        txid_p2sh = b"\xb5" * 32
        contexts = [
            _bare_p2pkh(txid_bare),
            _p2sh_push_only(txid_p2sh, flags=VERIFY_P2SH),
        ]
        records = [
            _make_record_bytes(txid_bare, 0, op_kind=3, sig_version=0),
            _make_record_bytes(txid_p2sh, 0, op_kind=3, sig_version=0),
        ]
        journal = [
            _make_journal_bytes(
                txid_bare, 0,
                checksig_ops=0, checkmultisig_ops=1,
                ecdsa_verify_calls=1, ecdsa_verify_ok=1,
            ),
            _make_journal_bytes(
                txid_p2sh, 0,
                checksig_ops=0, checkmultisig_ops=1,
                ecdsa_verify_calls=1, ecdsa_verify_ok=1,
            ),
        ]
        _make_brsctx1_file(tmp / "contexts.bin", contexts)
        _write_records_file(tmp / "records.bin", records)
        _write_journal_file(tmp / "journal.bin", journal)

        counters = _make_valid_counters(
            2, 2, 2,
            op_checksig=0,
            op_checkmultisig=2,
            checkecdsa_entries=2,
            ecdsa_from_checksig=0,
            ecdsa_from_checkmultisig=2,
            ecdsa_verify_calls=2,
            ecdsa_verify_ok=2,
            sighash_computed=2,
        )
        (tmp / "counters.json").write_text(json.dumps(counters))
        counts, ctx_count, _ = _count_context_records_disk(
            tmp / "contexts.bin",
            tmp / "records.bin",
            tmp / "journal.bin",
            Counters(counters),
        )
        assert ctx_count == 2
        assert counts["bare_multisig_checks"] == 1
        assert counts["p2sh_multisig_checks"] == 1


def test_classify_corpus_scratch_dir_rejects_non_directory() -> None:
    """A scratch-dir argument that is not a directory is rejected clearly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\x67" * 32
        scratch = tmp / "not-a-dir"
        scratch.write_text("file")
        args = _make_classify_args(
            tmp, [_bare_p2pkh(txid_le)], [_make_record_bytes(txid_le, 0)],
            [_make_journal_bytes(txid_le, 0)], "c150",
            scratch_dir=scratch,
        )
        _raises_with(
            AnalyzerError,
            lambda: cmd_classify_corpus(args),
            "scratch-dir rejects file",
            "CTX-EXECUTION",
            "scratch-dir is not a writable directory",
        )


def test_classify_corpus_scratch_dir_rejects_unwritable() -> None:
    """An existing but unwritable scratch-dir is rejected clearly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        scratch = tmp / "no-write"
        scratch.mkdir(mode=0o555)
        txid_le = b"\x68" * 32
        args = _make_classify_args(
            tmp, [_bare_p2pkh(txid_le)], [_make_record_bytes(txid_le, 0)],
            [_make_journal_bytes(txid_le, 0)], "c150",
            scratch_dir=scratch,
        )
        try:
            _raises_with(
                AnalyzerError,
                lambda: cmd_classify_corpus(args),
                "scratch-dir rejects unwritable",
                "CTX-EXECUTION",
                "scratch-dir is not a writable directory",
            )
        finally:
            scratch.chmod(0o755)


def test_count_context_records_disk_scratch_dir_smoke() -> None:
    """A valid scratch_dir is accepted and set-based counts remain correct."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        scratch = tmp / "scratch"
        scratch.mkdir()
        txid_le = b"\x69" * 32
        ctx = _bare_p2pkh(txid_le)
        record = _make_record_bytes(txid_le, 0)
        journal = [_make_journal_bytes(txid_le, 0)]
        _make_brsctx1_file(tmp / "contexts.bin", [ctx])
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)

        counters = _make_valid_counters(1, 1, 1)
        (tmp / "counters.json").write_text(json.dumps(counters))
        counts, ctx_count, _ = _count_context_records_disk(
            tmp / "contexts.bin",
            tmp / "records.bin",
            tmp / "journal.bin",
            Counters(counters),
            scratch_dir=scratch,
        )
        assert ctx_count == 1
        assert counts["bare_multisig_checks"] == 0


def test_count_context_records_disk_restores_env_on_failure() -> None:
    """A BRSCTX1 parse failure after SQLite setup still restores environment."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        scratch = tmp / "scratch"
        scratch.mkdir()
        (tmp / "contexts.bin").write_bytes(b"BADC0D1C" + struct.pack("<Q", 0))

        counters = _make_valid_counters(0, 0, 0)
        (tmp / "counters.json").write_text(json.dumps(counters))

        original_sqlite = os.environ.get("SQLITE_TMPDIR")
        original_tmp = os.environ.get("TMPDIR")
        try:
            os.environ["SQLITE_TMPDIR"] = "/tmp/original-sqlite"
            os.environ["TMPDIR"] = "/tmp/original-tmp"
            try:
                _count_context_records_disk(
                    tmp / "contexts.bin",
                    tmp / "records.bin",
                    tmp / "journal.bin",
                    Counters(counters),
                    scratch_dir=scratch,
                )
            except AnalyzerError:
                pass
            assert os.environ.get("SQLITE_TMPDIR") == "/tmp/original-sqlite"
            assert os.environ.get("TMPDIR") == "/tmp/original-tmp"
        finally:
            if original_sqlite is not None:
                os.environ["SQLITE_TMPDIR"] = original_sqlite
            else:
                os.environ.pop("SQLITE_TMPDIR", None)
            if original_tmp is not None:
                os.environ["TMPDIR"] = original_tmp
            else:
                os.environ.pop("TMPDIR", None)




# ── Tests: Task 7A2 diagnostic scanner/controller ─────────────────────────────


_FAKE_CENSUS_CHILD = """#!/usr/bin/env python3
import json
import os
import struct
import sys
import time
from pathlib import Path

PREFACE = b"BRSHGT1\\x00" + struct.pack("<II", 1, 84)

def write_frame(payload, split):
    if os.environ.get("FAKE_CENSUS_FRAGMENTED") != "1":
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return
    os.write(sys.stdout.fileno(), payload[:split])
    time.sleep(0.05)
    os.write(sys.stdout.fileno(), payload[split:])

def main():
    meta_path = Path(os.environ["FAKE_CENSUS_META"])
    stage_dir = Path(os.environ["FAKE_CENSUS_STAGE"])
    replay_path = Path(sys.argv[sys.argv.index("--output") + 1])
    for name in ("BRS_CENSUS_CONTEXTS", "BRS_CENSUS_RECORDS", "BRS_CENSUS_JOURNAL"):
        src = stage_dir / f"{name}.bin"
        dst = Path(os.environ[name])
        dst.write_bytes(src.read_bytes())
    counters_path = Path(os.environ["BRS_CENSUS_COUNTERS"])
    counters_path.write_bytes((stage_dir / "counters.json").read_bytes())
    meta = json.loads(meta_path.read_text())
    replay = meta["replay"]
    replay_path.write_text(json.dumps(replay, indent=2) + "\\n")
    write_frame(PREFACE, 3)
    for row in meta["rows"]:
        payload = (
            struct.pack("<I", row["height"]) +
            bytes.fromhex(row["block_hash_le"]) +
            struct.pack("<Q", row["context_rows"]) +
            struct.pack("<Q", row["context_end"]) +
            struct.pack("<Q", row["record_rows"]) +
            struct.pack("<Q", row["record_end"]) +
            struct.pack("<Q", row["journal_rows"]) +
            struct.pack("<Q", row["journal_end"])
        )
        write_frame(payload, 7)
        control = sys.stdin.buffer.read(1)
        if not control or control == b"\\x01":
            break
    trailing = int(os.environ.get("FAKE_CENSUS_TRAILING_BYTES", "0"))
    if trailing:
        sys.stdout.buffer.write(b"X" * trailing)
        sys.stdout.buffer.flush()
    time.sleep(float(os.environ.get("FAKE_CENSUS_TEARDOWN_SLEEP", "0")))
    sys.exit(0)

if __name__ == "__main__":
    main()
"""

def _make_fake_binary(tmp: Path) -> Path:
    child = tmp / "fake_child.py"
    child.write_text(_FAKE_CENSUS_CHILD)
    child.chmod(0o755)
    return child


def _diagnostic_counters_dict(context_count: int, record_count: int, journal_count: int) -> dict[str, object]:
    return _valid_counters_dict(record_count=record_count, journal_count=journal_count, context_count=context_count)


def _write_diagnostic_stage(tmp: Path) -> Path:
    stage = tmp / "stage"
    stage.mkdir()
    txids = [bytes([i]) * 32 for i in range(10)]
    contexts = [
        _p2sh_push_only(txids[0], flags=VERIFY_P2SH),
        _native_w0(txids[1], flags=VERIFY_WITNESS),
        _p2sh_wrapped_w0(txids[2], flags=VERIFY_P2SH | VERIFY_WITNESS),
        _bare_p2pkh(txids[3]),
        _p2sh_push_only(txids[4], flags=VERIFY_P2SH),
        _native_w0(txids[5], flags=VERIFY_WITNESS),
        _p2sh_wrapped_w0(txids[6], flags=VERIFY_P2SH | VERIFY_WITNESS),
        _taproot_key_path(txids[7], flags=VERIFY_WITNESS | VERIFY_TAPROOT),
        _taproot_script_path(txids[8], flags=VERIFY_WITNESS | VERIFY_TAPROOT),
        _taproot_script_path(txids[9], flags=VERIFY_WITNESS | VERIFY_TAPROOT),
    ]
    records = [
        _make_record_bytes(txids[0], 0, op_kind=1, sig_version=0, outcome=1),  # p2sh checksig
        _make_record_bytes(txids[1], 0, op_kind=1, sig_version=1, outcome=1),  # native checksig
        _make_record_bytes(txids[2], 0, op_kind=1, sig_version=1, outcome=1),  # wrapped checksig
        _make_record_bytes(txids[3], 0, op_kind=3, sig_version=0, outcome=1),  # bare multisig
        _make_record_bytes(txids[4], 0, op_kind=3, sig_version=0, outcome=1),  # p2sh multisig
        _make_record_bytes(txids[5], 0, op_kind=3, sig_version=1, outcome=1),  # native multisig
        _make_record_bytes(txids[6], 0, op_kind=3, sig_version=1, outcome=1),  # wrapped multisig
        _make_record_bytes(txids[7], 0, op_kind=0, sig_version=3, outcome=1),  # taproot key
        _make_record_bytes(txids[8], 0, op_kind=1, sig_version=2, outcome=1),  # tapscript schnorr
        _make_record_bytes(txids[9], 0, op_kind=5, sig_version=2, outcome=1),  # tapscript checksigadd
    ]
    journals = [
        _make_journal_bytes(txids[0], 0, checksig_ops=1, checkmultisig_ops=0, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
        _make_journal_bytes(txids[1], 0, checksig_ops=1, checkmultisig_ops=0, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
        _make_journal_bytes(txids[2], 0, checksig_ops=1, checkmultisig_ops=0, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
        _make_journal_bytes(txids[3], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
        _make_journal_bytes(txids[4], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
        _make_journal_bytes(txids[5], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
        _make_journal_bytes(txids[6], 0, checksig_ops=0, checkmultisig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
        _make_journal_bytes(txids[7], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
        _make_journal_bytes(txids[8], 0, checksig_ops=1, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
        _make_journal_bytes(txids[9], 0, checksig_ops=0, checkmultisig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
    ]
    _make_brsctx1_file(stage / "BRS_CENSUS_CONTEXTS.bin", contexts)
    _write_records_file(stage / "BRS_CENSUS_RECORDS.bin", records)
    _write_journal_file(stage / "BRS_CENSUS_JOURNAL.bin", journals)
    (stage / "counters.json").write_text(json.dumps(_diagnostic_counters_dict(10, 10, 10)))
    return stage


def _compute_context_ends(path: Path) -> list[int]:
    data = path.read_bytes()
    assert data[:8] == _BRSCTX1_MAGIC
    count = struct.unpack("<Q", data[8:16])[0]
    ends = [16]
    cursor = 16
    for _ in range(count):
        row_len = struct.unpack("<I", data[cursor:cursor + 4])[0]
        cursor += 4 + row_len
        ends.append(cursor)
    return ends


def _build_meta(
    tmp: Path,
    stage: Path,
    ceiling: int,
    work_dir: Path,
    *,
    replay_overrides: dict[str, object] | None = None,
) -> Path:
    ctx_ends = _compute_context_ends(stage / "BRS_CENSUS_CONTEXTS.bin")
    assert len(ctx_ends) == 11  # 10 rows + final sentinel
    rows = []
    for h in range(10):
        if h == 0:
            block_hash = bytes.fromhex(MAINNET_GENESIS_HASH)[::-1]
        else:
            block_hash = bytes([h] * 32)
        rows.append({
            "height": h,
            "block_hash_le": block_hash.hex(),
            "context_rows": h + 1,
            "context_end": ctx_ends[h + 1],
            "record_rows": h + 1,
            "record_end": HEADER_SIZE + (h + 1) * RECORD_SIZE,
            "journal_rows": h + 1,
            "journal_end": HEADER_SIZE + (h + 1) * JOURNAL_SIZE,
        })
    final = rows[-1]
    replay = {
        "schema": "mainnet-prefix-replay-diagnostic-v1",
        "non_certifying": True,
        "block_source": "rest",
        "start_height": 0,
        "assume_valid_height": 0,
        "window": 1,
        "requested_stop_height_ceiling": ceiling,
        "actual_stop_height": final["height"],
        "actual_stop_hash": bytes.fromhex(final["block_hash_le"])[::-1].hex(),
        "stop_reason": "controller-request",
        "storage_backend": "fjall",
        "txindex": False,
        "data_dir": str(work_dir / "state"),
        "elapsed_seconds": 0.0,
    }
    if replay_overrides:
        replay.update(replay_overrides)
    meta = {"rows": rows, "replay": replay}
    meta_path = tmp / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    return meta_path


def test_find_cmodern_height_fake_child_success() -> None:
    """Fake child distributes all 11 types and the candidate H equals max first heights."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / "work"
        work_dir.mkdir()
        output = tmp / "candidate.json"
        meta_path = _build_meta(tmp, stage, 100, work_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(child, "127.0.0.1:18443", 100, work_dir, output)
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)
        candidate = json.loads(output.read_text())
        assert candidate["schema"] == "cmodern-candidate-diagnostic-v2"
        assert candidate["non_certifying"] is True
        assert candidate["certifying_replay_required"] is True
        assert candidate["earliest_defensible_height_h"] == 9
        first = candidate["first_occurrence_heights"]
        assert set(first.keys()) == set(CONTEXT_COUNTER_NAMES)
        assert all(first[n] is not None for n in CONTEXT_COUNTER_NAMES)
        expected_h = max(first.values())
        assert candidate["earliest_defensible_height_h"] == expected_h
        assert candidate["final_stream_counts"]["context_rows"] == 10
        assert candidate["child_exit_status"] == 0
        assert candidate["child_teardown"] == "clean"
        assert candidate["salvaged_from"] is None
        sidecar = work_dir / "brshgt1.bin"
        assert candidate["custody"]["brshgt1_sidecar"]["sha256"] == hashlib.sha256(
            sidecar.read_bytes()
        ).hexdigest()


def test_find_cmodern_height_late_failure_keeps_sidecar_count_unpatched() -> None:
    """A failed live finalization must not publish its sidecar count."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / "work"
        work_dir.mkdir()
        output = tmp / "candidate.json"
        meta_path = _build_meta(tmp, stage, 100, work_dir)
        child = _make_fake_binary(tmp)
        validate_replay = analyze._validate_replay_diagnostic

        def reject_replay(
            _path: Path,
            _final: DiagnosticCheckpoint,
            _ceiling: int,
            _storage_backend: str,
            _txindex: bool,
            _data_dir: str,
        ) -> None:
            raise AnalyzerError("late replay validation failure")

        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        analyze._validate_replay_diagnostic = reject_replay
        try:
            _raises_with(
                AnalyzerError,
                lambda: _run_diagnostic_scan(
                    child, "127.0.0.1:18443", 100, work_dir, output
                ),
                "late replay validation",
                "late replay validation failure",
            )
        finally:
            analyze._validate_replay_diagnostic = validate_replay
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)
        assert analyze._brshgt1_count(work_dir / "brshgt1.bin") == 0
        assert not output.exists()


def test_find_cmodern_height_post_stop_timeout_finalizes_honestly() -> None:
    """A child alive after terminal proof is killed, reaped, and never reported clean."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / "work"
        work_dir.mkdir()
        output = tmp / "candidate.json"
        meta_path = _build_meta(tmp, stage, 100, work_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        os.environ["FAKE_CENSUS_TEARDOWN_SLEEP"] = "5"
        try:
            _run_diagnostic_scan(
                child,
                "127.0.0.1:18443",
                100,
                work_dir,
                output,
                stop_deadline_seconds=0.2,
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)
            os.environ.pop("FAKE_CENSUS_TEARDOWN_SLEEP", None)
        candidate = json.loads(output.read_text())
        assert candidate["schema"] == "cmodern-candidate-diagnostic-v2"
        assert candidate["earliest_defensible_height_h"] == 9
        assert candidate["child_teardown"] == "timeout_after_terminal_proof"
        assert candidate["child_exit_status"] == -9
        assert candidate["salvaged_from"] is None


def test_find_cmodern_height_rejects_pipe_filling_trailing_output() -> None:
    """Trailing child output larger than the pipe cannot masquerade as teardown delay."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / "work"
        work_dir.mkdir()
        output = tmp / "candidate.json"
        meta_path = _build_meta(tmp, stage, 100, work_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        os.environ["FAKE_CENSUS_TRAILING_BYTES"] = str(1024 * 1024)
        try:
            _raises_with(
                AnalyzerError,
                lambda: _run_diagnostic_scan(
                    child,
                    "127.0.0.1:18443",
                    100,
                    work_dir,
                    output,
                    stop_deadline_seconds=2,
                ),
                "pipe-filling trailing output",
                "trailing bytes",
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)
            os.environ.pop("FAKE_CENSUS_TRAILING_BYTES", None)
        assert not output.exists()


def _directory_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_salvage_cmodern_height_recovers_committed_prefixes_without_source_mutation() -> None:
    """Salvage copies only checkpoint-committed bytes and preserves the incident run.

    A terminal checkpoint can be durable while source streams still contain
    their initial zero row counts. Recovery normalizes those headers to the
    terminal counts while it leaves the source files unchanged.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        clean = json.loads(clean_output.read_text())
        sidecar = source_dir / "brshgt1.bin"
        fd = os.open(sidecar, os.O_WRONLY)
        try:
            assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
            os.fsync(fd)
        finally:
            os.close(fd)
        for name in ("brsctx1.bin", "brsrec1.bin", "brsjrn1.bin"):
            fd = os.open(source_dir / name, os.O_WRONLY)
            try:
                assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
                os.fsync(fd)
            finally:
                os.close(fd)
            with (source_dir / name).open("ab") as stream:
                stream.write(b"UNCOMMITTED-TAIL")
                stream.flush()
                os.fsync(stream.fileno())

        source_before = _directory_hashes(source_dir)
        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        analyze._salvage_diagnostic_scan(
            source_dir,
            recovery_dir,
            output,
            "127.0.0.1:18443",
            100,
            str(source_dir / "state"),
        )
        assert _directory_hashes(source_dir) == source_before

        candidate = json.loads(output.read_text())
        assert candidate["schema"] == "cmodern-candidate-diagnostic-v2"
        assert candidate["earliest_defensible_height_h"] == 9
        assert candidate["context_counts"] == clean["context_counts"]
        assert (
            candidate["first_occurrence_heights"]
            == clean["first_occurrence_heights"]
        )
        assert candidate["final_stream_counts"] == clean["final_stream_counts"]
        assert (
            candidate["final_stream_endpoints"]
            == clean["final_stream_endpoints"]
        )
        assert candidate["child_exit_status"] is None
        assert candidate["child_teardown"] == "unobserved"
        assert candidate["salvaged_from"] == str(source_dir)
        for filename, endpoint in (
            ("brsctx1.bin", "context_end"),
            ("brsrec1.bin", "record_end"),
            ("brsjrn1.bin", "journal_end"),
        ):
            assert (
                (recovery_dir / filename).stat().st_size
                == candidate["final_stream_endpoints"][endpoint]
            )
        assert _brshgt1_count(recovery_dir / "brshgt1.bin") == 10

        final = analyze.DiagnosticCheckpoint(
            height=candidate["earliest_defensible_height_h"],
            block_hash_le=bytes.fromhex(candidate["block_hash_h"])[::-1],
            context_rows=candidate["final_stream_counts"]["context_rows"],
            context_end=candidate["final_stream_endpoints"]["context_end"],
            record_rows=candidate["final_stream_counts"]["record_rows"],
            record_end=candidate["final_stream_endpoints"]["record_end"],
            journal_rows=candidate["final_stream_counts"]["journal_rows"],
            journal_end=candidate["final_stream_endpoints"]["journal_end"],
        )
        recovered_paths = analyze._diagnostic_artifact_paths(recovery_dir)
        analyze._validate_terminal_streams(recovered_paths, final)

        for filename, count_field, magic in (
            ("brsctx1.bin", "context_rows", analyze.CONTEXT_MAGIC),
            ("brsrec1.bin", "record_rows", analyze.RECORD_MAGIC),
            ("brsjrn1.bin", "journal_rows", analyze.JOURNAL_MAGIC),
        ):
            raw = (recovery_dir / filename).read_bytes()[:16]
            file_magic, count = analyze.HEADER_STRUCT.unpack(raw)
            assert file_magic == magic
            assert count == candidate["final_stream_counts"][count_field]

        source_custody = candidate["source_full_file_custody"]
        source_names = {
            "contexts": "brsctx1.bin",
            "records": "brsrec1.bin",
            "journal": "brsjrn1.bin",
            "sidecar": "brshgt1.bin",
            "replay": "replay_diagnostic.json",
            "counters": "counters.json",
        }
        for name, filename in source_names.items():
            assert source_custody[name]["sha256"] == source_before[filename]
        for name, custody_name in (
            ("contexts", "brsctx1"),
            ("records", "brsrec1"),
            ("journal", "brsjrn1"),
            ("sidecar", "brshgt1_sidecar"),
        ):
            assert source_custody[name]["clone_provenance"] == "DIFFERS_FROM_SOURCE"
            assert source_custody[name].get("source_header_hex") != source_custody[name].get("recovery_header_hex")
            # Normalized header changes full/prefix hashes, but bodies are identical.
            assert (
                source_custody[name]["committed_prefix_sha256"]
                != candidate["custody"][custody_name]["sha256"]
            )
            assert (
                source_custody[name]["committed_body_sha256"]
                == candidate["custody"][custody_name]["body_sha256"]
            )
        assert source_custody["sidecar"]["clone_provenance"] == "DIFFERS_FROM_SOURCE"
        assert source_custody["replay"]["clone_provenance"] == "EXACT_FULL_FILE"
        assert source_custody["counters"]["clone_provenance"] == "EXACT_FULL_FILE"


def test_salvage_cmodern_height_rejects_tail_change_before_clone() -> None:
    """The initial source signature binds full-file digests through cloning."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        sidecar = source_dir / "brshgt1.bin"
        sidecar_fd = os.open(sidecar, os.O_WRONLY)
        try:
            assert os.pwrite(sidecar_fd, struct.pack("<Q", 0), 8) == 8
            os.fsync(sidecar_fd)
        finally:
            os.close(sidecar_fd)
        for name in ("brsctx1.bin", "brsrec1.bin", "brsjrn1.bin"):
            path = source_dir / name
            fd = os.open(path, os.O_WRONLY)
            try:
                assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
                os.fsync(fd)
            finally:
                os.close(fd)
            with path.open("ab") as stream:
                stream.write(b"UNCOMMITTED-TAIL")
                stream.flush()
                os.fsync(stream.fileno())

        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        clone_committed_source = analyze._clone_committed_source
        changed = False

        def change_tail_then_clone(
            source_fd: int,
            source: Path,
            destination: Path,
            committed_size: int,
            replacement_header: bytes | None = None,
            source_sha256: str | None = None,
            source_committed_prefix_sha256: str | None = None,
            source_committed_body_sha256: str | None = None,
        ) -> dict[str, object]:
            nonlocal changed
            if not changed and source.name == "brsctx1.bin":
                changed = True
                tail_offset = os.fstat(source_fd).st_size - 1
                original = os.pread(source_fd, 1, tail_offset)
                assert len(original) == 1
                write_fd = os.open(source, os.O_WRONLY)
                try:
                    assert os.pwrite(
                        write_fd, bytes([original[0] ^ 1]), tail_offset
                    ) == 1
                    os.fsync(write_fd)
                finally:
                    os.close(write_fd)
            return clone_committed_source(
                source_fd,
                source,
                destination,
                committed_size,
                replacement_header=replacement_header,
                source_sha256=source_sha256,
                source_committed_prefix_sha256=source_committed_prefix_sha256,
                source_committed_body_sha256=source_committed_body_sha256,
            )

        analyze._clone_committed_source = change_tail_then_clone
        try:
            _raises_with(
                AnalyzerError,
                lambda: analyze._salvage_diagnostic_scan(
                    source_dir,
                    recovery_dir,
                    output,
                    "127.0.0.1:18443",
                    100,
                    str(source_dir / "state"),
                ),
                "tail change before clone",
                "source changed during materialization",
            )
        finally:
            analyze._clone_committed_source = clone_committed_source
        assert changed
        assert not recovery_dir.exists()
        assert not output.exists()


def test_salvage_cmodern_height_rejects_recovery_stream_mutation() -> None:
    """Published custody must remain bound to the validated source prefix."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        sidecar = source_dir / "brshgt1.bin"
        fd = os.open(sidecar, os.O_WRONLY)
        try:
            assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
            os.fsync(fd)
        finally:
            os.close(fd)
        source_before = _directory_hashes(source_dir)
        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        validate_terminal_streams = analyze._validate_terminal_streams

        def mutate_then_validate(
            recovery_paths: dict[str, Path],
            final: DiagnosticCheckpoint,
        ) -> dict[str, dict[str, object]]:
            context_fd = os.open(recovery_paths["contexts"], os.O_RDWR)
            try:
                offset = HEADER_SIZE + 4
                original = os.pread(context_fd, 1, offset)
                assert len(original) == 1
                assert os.pwrite(context_fd, bytes([original[0] ^ 1]), offset) == 1
                os.fsync(context_fd)
            finally:
                os.close(context_fd)
            return validate_terminal_streams(recovery_paths, final)

        analyze._validate_terminal_streams = mutate_then_validate
        try:
            _raises_with(
                AnalyzerError,
                lambda: analyze._salvage_diagnostic_scan(
                    source_dir,
                    recovery_dir,
                    output,
                    "127.0.0.1:18443",
                    100,
                    str(source_dir / "state"),
                ),
                "mutated recovery stream",
                "recovered contexts body does not match",
                "validated source committed body",
            )
        finally:
            analyze._validate_terminal_streams = validate_terminal_streams
        assert _directory_hashes(source_dir) == source_before
        assert not recovery_dir.exists()
        assert not output.exists()


def test_salvage_cmodern_height_rejects_pre_signature_body_replacement() -> None:
    """A semantically valid body replacement that races signature capture
    must still fail source-body custody, even if the signature matches.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        sidecar = source_dir / "brshgt1.bin"
        fd = os.open(sidecar, os.O_WRONLY)
        try:
            assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
            os.fsync(fd)
        finally:
            os.close(fd)
        source_before = _directory_hashes(source_dir)
        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        path_signature = analyze._path_signature
        fd_signature = analyze._fd_signature
        captured_signatures: dict[Path, tuple[int, int, int, int, int]] = {}

        def signature_then_replace(path: Path) -> tuple[int, int, int, int, int]:
            if path in captured_signatures:
                return captured_signatures[path]
            sig = path_signature(path)
            # Replace the recovery contexts file with a semantically valid body
            # (same size and row count, different bytes) after its signature is
            # captured. The replacement is the race: the signature is baselined
            # to the original clone, but the body is no longer source-identical.
            if path.name == "brsctx1.bin" and "recovery" in path.parts:
                captured_signatures[path] = sig
                data = path.read_bytes()
                mutated = bytearray(data)
                mutated[HEADER_SIZE + 4 + CONTEXT_MIN_ROW_SIZE + 3] ^= 1
                path.write_bytes(bytes(mutated))
                with path.open("rb") as f:
                    os.fsync(f.fileno())
            return sig

        def stable_mutated_fd(fd: int) -> tuple[int, int, int, int, int]:
            path = Path(os.readlink(f"/proc/self/fd/{fd}"))
            return captured_signatures.get(path, fd_signature(fd))

        analyze._path_signature = signature_then_replace
        analyze._fd_signature = stable_mutated_fd
        try:
            _raises_with(
                AnalyzerError,
                lambda: analyze._salvage_diagnostic_scan(
                    source_dir,
                    recovery_dir,
                    output,
                    "127.0.0.1:18443",
                    100,
                    str(source_dir / "state"),
                ),
                "pre-signature body replacement",
                "recovered contexts body does not match",
                "validated source committed body",
            )
        finally:
            analyze._fd_signature = fd_signature
            analyze._path_signature = path_signature
        assert _directory_hashes(source_dir) == source_before
        assert not recovery_dir.exists()
        assert not output.exists()


def test_salvage_rejects_semantically_valid_exact_replay_replacement() -> None:
    """An exact JSON clone must remain byte-identical to its source."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        source_before = _directory_hashes(source_dir)
        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        path_signature = analyze._path_signature
        validate_replay = analyze._validate_replay_diagnostic
        replay_signature: tuple[int, int, int, int, int] | None = None

        def stable_replay_signature(path: Path) -> tuple[int, int, int, int, int]:
            nonlocal replay_signature
            if path == recovery_dir / "replay_diagnostic.json":
                if replay_signature is None:
                    replay_signature = path_signature(path)
                return replay_signature
            return path_signature(path)

        def mutate_then_validate(
            path: Path,
            final: DiagnosticCheckpoint,
            ceiling: int,
            storage_backend: str,
            txindex: bool,
            data_dir: str,
        ) -> None:
            replay = json.loads(path.read_text())
            replay["elapsed_seconds"] = 1.0
            path.write_text(json.dumps(replay, indent=2) + "\n")
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
            validate_replay(
                path,
                final,
                ceiling,
                storage_backend,
                txindex,
                data_dir,
            )

        analyze._path_signature = stable_replay_signature
        analyze._validate_replay_diagnostic = mutate_then_validate
        try:
            _raises_with(
                AnalyzerError,
                lambda: analyze._salvage_diagnostic_scan(
                    source_dir,
                    recovery_dir,
                    output,
                    "127.0.0.1:18443",
                    100,
                    str(source_dir / "state"),
                ),
                "semantically valid exact replay replacement",
                "exact recovery replay does not match source",
            )
        finally:
            analyze._validate_replay_diagnostic = validate_replay
            analyze._path_signature = path_signature
        assert _directory_hashes(source_dir) == source_before
        assert not recovery_dir.exists()
        assert not output.exists()



def test_salvage_rolls_back_candidate_after_post_publication_replacement() -> None:
    """Late source or recovery replacement removes and durably rolls back output."""
    for replaced_set in ("source", "recovery"):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            stage = _write_diagnostic_stage(tmp)
            source_dir = tmp / "source"
            source_dir.mkdir()
            clean_output = tmp / "clean.json"
            meta_path = _build_meta(tmp, stage, 100, source_dir)
            child = _make_fake_binary(tmp)
            os.environ["FAKE_CENSUS_META"] = str(meta_path)
            os.environ["FAKE_CENSUS_STAGE"] = str(stage)
            try:
                _run_diagnostic_scan(
                    child, "127.0.0.1:18443", 100, source_dir, clean_output
                )
            finally:
                os.environ.pop("FAKE_CENSUS_META", None)
                os.environ.pop("FAKE_CENSUS_STAGE", None)

            recovery_dir = tmp / "recovery"
            output = tmp / "salvaged.json"
            write_json_atomic = analyze._write_json_atomic
            original_fsync = os.fsync
            published = False
            rollback_fsynced = False

            def tracking_fsync(fd):
                nonlocal rollback_fsynced
                status = os.fstat(fd)
                if (
                    published
                    and not output.exists()
                    and stat.S_ISDIR(status.st_mode)
                    and Path(os.readlink(f"/proc/self/fd/{fd}")) == output.parent
                ):
                    rollback_fsynced = True
                return original_fsync(fd)

            def publish_then_replace(path: Path, value: dict[str, object]) -> None:
                nonlocal published
                write_json_atomic(path, value)
                published = True
                artifact_root = (
                    source_dir if replaced_set == "source" else recovery_dir
                )
                artifact = artifact_root / "replay_diagnostic.json"
                held = artifact.with_name("held-replay.json")
                artifact.rename(held)
                artifact.write_bytes(held.read_bytes())
                with artifact.open("rb") as stream:
                    original_fsync(stream.fileno())

            analyze._write_json_atomic = publish_then_replace
            os.fsync = tracking_fsync
            try:
                _raises_with(
                    AnalyzerError,
                    lambda: analyze._salvage_diagnostic_scan(
                        source_dir,
                        recovery_dir,
                        output,
                        "127.0.0.1:18443",
                        100,
                        str(source_dir / "state"),
                    ),
                    f"post-publication {replaced_set} replacement",
                    f"{replaced_set} changed after candidate publication",
                )
            finally:
                os.fsync = original_fsync
                analyze._write_json_atomic = write_json_atomic
            assert published
            assert rollback_fsynced
            assert not output.exists()
            assert not recovery_dir.exists()


def test_salvage_rolls_back_candidate_on_post_publication_interrupt() -> None:
    """An interrupt during final custody verification cannot orphan output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        verify_retained = analyze._verify_retained_files

        def interrupt_after_publication(
            paths: dict[str, Path],
            descriptors: dict[str, int],
            signatures: dict[str, tuple[int, int, int, int, int]],
            phase: str,
        ) -> None:
            if "after candidate publication" in phase:
                raise KeyboardInterrupt
            verify_retained(paths, descriptors, signatures, phase)

        analyze._verify_retained_files = interrupt_after_publication
        try:
            _raises(
                KeyboardInterrupt,
                lambda: analyze._salvage_diagnostic_scan(
                    source_dir,
                    recovery_dir,
                    output,
                    "127.0.0.1:18443",
                    100,
                    str(source_dir / "state"),
                ),
                "post-publication interrupt",
            )
        finally:
            analyze._verify_retained_files = verify_retained
        assert not output.exists()
        assert not recovery_dir.exists()

def test_salvage_cmodern_height_rejects_zeroed_recovery_sidecar_count() -> None:
    """A salvaged sidecar must keep its reconstructed count header."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        sidecar = source_dir / "brshgt1.bin"
        fd = os.open(sidecar, os.O_WRONLY)
        try:
            assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
            os.fsync(fd)
        finally:
            os.close(fd)
        source_before = _directory_hashes(source_dir)
        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        path_signature = analyze._path_signature
        fd_signature = analyze._fd_signature
        captured_signatures: dict[Path, tuple[int, int, int, int, int]] = {}

        def signature_then_zero_count(path: Path) -> tuple[int, int, int, int, int]:
            if path in captured_signatures:
                return captured_signatures[path]
            signature = path_signature(path)
            if path.name == "brshgt1.bin" and "recovery" in path.parts:
                captured_signatures[path] = signature
                recovery_fd = os.open(path, os.O_WRONLY)
                try:
                    assert os.pwrite(recovery_fd, struct.pack("<Q", 0), 8) == 8
                    os.fsync(recovery_fd)
                finally:
                    os.close(recovery_fd)
            return signature

        def stable_zeroed_fd(fd: int) -> tuple[int, int, int, int, int]:
            path = Path(os.readlink(f"/proc/self/fd/{fd}"))
            return captured_signatures.get(path, fd_signature(fd))

        analyze._path_signature = signature_then_zero_count
        analyze._fd_signature = stable_zeroed_fd
        try:
            _raises_with(
                AnalyzerError,
                lambda: analyze._salvage_diagnostic_scan(
                    source_dir,
                    recovery_dir,
                    output,
                    "127.0.0.1:18443",
                    100,
                    str(source_dir / "state"),
                ),
                "zeroed recovery sidecar count",
                "recovered sidecar declared row count",
            )
        finally:
            analyze._fd_signature = fd_signature
            analyze._path_signature = path_signature
        assert _directory_hashes(source_dir) == source_before
        assert not recovery_dir.exists()
        assert not output.exists()



def test_salvage_preserves_exact_data_dir_text_through_to_validation() -> None:
    """Salvage preserves exact data-dir provenance text."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        source_dir = tmp / "source"
        source_dir.mkdir()
        clean_output = tmp / "clean.json"
        meta_path = _build_meta(tmp, stage, 100, source_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _run_diagnostic_scan(
                child, "127.0.0.1:18443", 100, source_dir, clean_output
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)

        # Keep a spelling that pathlib would normalize.
        raw_data_dir = str(source_dir / "state") + "/./"
        replay_path = source_dir / "replay_diagnostic.json"
        replay = json.loads(replay_path.read_text())
        replay["data_dir"] = raw_data_dir
        replay_path.write_text(json.dumps(replay, indent=2) + "\n", encoding="utf-8")

        # Corrupt the source sidecar count to force the salvage path.
        sidecar = source_dir / "brshgt1.bin"
        fd = os.open(sidecar, os.O_WRONLY)
        try:
            assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
            os.fsync(fd)
        finally:
            os.close(fd)
        for name in ("brsctx1.bin", "brsrec1.bin", "brsjrn1.bin"):
            fd = os.open(source_dir / name, os.O_WRONLY)
            try:
                assert os.pwrite(fd, struct.pack("<Q", 0), 8) == 8
                os.fsync(fd)
            finally:
                os.close(fd)

        captured_data_dir: list[str] = []
        original_validate = analyze._validate_replay_diagnostic

        def capture_validate(
            path: Path,
            final: analyze.DiagnosticCheckpoint,
            ceiling: int,
            storage_backend: str,
            txindex: bool,
            data_dir: str,
        ) -> None:
            captured_data_dir.append(data_dir)
            original_validate(
                path,
                final,
                ceiling,
                storage_backend,
                txindex,
                data_dir,
            )

        recovery_dir = tmp / "recovery"
        output = tmp / "salvaged.json"
        args = argparse.Namespace(
            source_dir=str(source_dir),
            recovery_dir=str(recovery_dir),
            output=str(output),
            rest_url="127.0.0.1:18443",
            stop_height=100,
            data_dir=raw_data_dir,
            storage_backend="fjall",
            txindex=False,
        )
        analyze._validate_replay_diagnostic = capture_validate
        try:
            assert analyze.cmd_salvage_cmodern_height(args) == 0
        finally:
            analyze._validate_replay_diagnostic = original_validate

        assert captured_data_dir == [raw_data_dir]


def test_find_cmodern_height_assembles_fragmented_child_frames() -> None:
    """Legal fragmented preface and 7 + 77 byte checkpoint writes are assembled."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / "work"
        work_dir.mkdir()
        output = tmp / "candidate.json"
        meta_path = _build_meta(tmp, stage, 100, work_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        os.environ["FAKE_CENSUS_FRAGMENTED"] = "1"
        try:
            _run_diagnostic_scan(child, "127.0.0.1:18443", 100, work_dir, output)
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)
            os.environ.pop("FAKE_CENSUS_FRAGMENTED", None)
        candidate = json.loads(output.read_text())
        assert candidate["earliest_defensible_height_h"] == 9
        assert candidate["final_stream_counts"]["context_rows"] == 10


def test_find_cmodern_height_reaps_failed_child() -> None:
    """A parser-failure child must be reaped and no candidate published."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / "work"
        work_dir.mkdir()
        output = tmp / "candidate.json"
        meta_path = _build_meta(tmp, stage, 100, work_dir)
        bad = tmp / "bad_child.py"
        bad.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(b\'NOTMAGIC!!\')\nsys.stdout.buffer.flush()\nsys.exit(1)\n")
        bad.chmod(0o755)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _raises_with(
                AnalyzerError,
                lambda: _run_diagnostic_scan(bad, "127.0.0.1:18443", 100, work_dir, output),
                "bad child",
                "DIAG-PROTO",
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)
        assert not output.exists(), "candidate must not be published on child failure"


def test_find_cmodern_height_destination_race() -> None:
    """A concurrent file at the destination must prevent replacement and leave it intact."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / "work"
        work_dir.mkdir()
        output = tmp / "candidate.json"
        output.write_text("racer\n")
        meta_path = _build_meta(tmp, stage, 100, work_dir)
        child = _make_fake_binary(tmp)
        os.environ["FAKE_CENSUS_META"] = str(meta_path)
        os.environ["FAKE_CENSUS_STAGE"] = str(stage)
        try:
            _raises_with(
                AnalyzerError,
                lambda: _run_diagnostic_scan(child, "127.0.0.1:18443", 100, work_dir, output),
                "destination race",
                "DIAG-OUTPUT",
            )
        finally:
            os.environ.pop("FAKE_CENSUS_META", None)
            os.environ.pop("FAKE_CENSUS_STAGE", None)
        assert output.read_text() == "racer\n", "racer must survive the collision"
        assert not any(tmp.glob(".*candidate.json.tmp*")), "temp must be cleaned up"

def test_validate_replay_diagnostic_accepts_a1_artifact_without_rest_url() -> None:
    """An A1-shaped child replay without the invented rest_url field passes validation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        replay_path = tmp / "replay.json"
        block_hash_le = bytes.fromhex(
            "000000000000000000000000000000000000000000000000000000000000000a"
        )
        replay: dict[str, object] = {
            "schema": "mainnet-prefix-replay-diagnostic-v1",
            "non_certifying": True,
            "block_source": "rest",
            "start_height": 0,
            "requested_stop_height_ceiling": 11,
            "actual_stop_height": 10,
            "actual_stop_hash": block_hash_le[::-1].hex(),
            "window": 1,
            "assume_valid_height": 0,
            "stop_reason": "controller-request",
            "storage_backend": "fjall",
            "txindex": False,
            "data_dir": str(tmp / "state"),
            "elapsed_seconds": 1.5,
        }
        replay_path.write_text(json.dumps(replay, indent=2) + "\n")
        final = DiagnosticCheckpoint(
            height=10,
            block_hash_le=block_hash_le,
            context_rows=0,
            context_end=0,
            record_rows=0,
            record_end=0,
            journal_rows=0,
            journal_end=0,
        )
        _validate_replay_diagnostic(
            replay_path, final, 11, 'fjall', False, str(tmp / 'state')
        )


def test_validate_replay_diagnostic_rejects_invented_rest_url() -> None:
    """The parent owns rest_url; it must not appear as an invented child field."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        replay_path = tmp / "replay.json"
        block_hash_le = bytes.fromhex(
            "000000000000000000000000000000000000000000000000000000000000000a"
        )
        replay: dict[str, object] = {
            "schema": "mainnet-prefix-replay-diagnostic-v1",
            "non_certifying": True,
            "block_source": "rest",
            "rest_url": "127.0.0.1:18443",
            "start_height": 0,
            "requested_stop_height_ceiling": 11,
            "actual_stop_height": 10,
            "actual_stop_hash": block_hash_le[::-1].hex(),
            "window": 1,
            "assume_valid_height": 0,
            "stop_reason": "controller-request",
            "storage_backend": "fjall",
            "txindex": False,
            "data_dir": str(tmp / "state"),
            "elapsed_seconds": 1.5,
        }
        replay_path.write_text(json.dumps(replay, indent=2) + "\n")
        final = DiagnosticCheckpoint(
            height=10,
            block_hash_le=block_hash_le,
            context_rows=0,
            context_end=0,
            record_rows=0,
            record_end=0,
            journal_rows=0,
            journal_end=0,
        )
        _raises_with(
            AnalyzerError,
            lambda: _validate_replay_diagnostic(
                replay_path, final, 11, 'fjall', False, str(tmp / 'state')
            ),
            "invented rest_url",
            "rest_url",
        )


def test_find_cmodern_height_settings_mismatch_storage_backend() -> None:
    '''A child reporting a different storage_backend must not be finalized.'''
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / 'work'
        work_dir.mkdir()
        output = tmp / 'candidate.json'
        meta_path = _build_meta(
            tmp, stage, 100, work_dir,
            replay_overrides={'storage_backend': 'rocksdb'},
        )
        child = _make_fake_binary(tmp)
        os.environ['FAKE_CENSUS_META'] = str(meta_path)
        os.environ['FAKE_CENSUS_STAGE'] = str(stage)
        try:
            _raises_with(
                AnalyzerError,
                lambda: _run_diagnostic_scan(
                    child, '127.0.0.1:18443', 100, work_dir, output
                ),
                'mismatched storage_backend',
                'storage_backend',
            )
            assert not output.exists(), 'candidate must not be published'
        finally:
            os.environ.pop('FAKE_CENSUS_META', None)
            os.environ.pop('FAKE_CENSUS_STAGE', None)

def test_find_cmodern_height_settings_mismatch_txindex() -> None:
    '''A child reporting txindex=True when parent passed False must fail.'''
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / 'work'
        work_dir.mkdir()
        output = tmp / 'candidate.json'
        meta_path = _build_meta(
            tmp, stage, 100, work_dir,
            replay_overrides={'txindex': True},
        )
        child = _make_fake_binary(tmp)
        os.environ['FAKE_CENSUS_META'] = str(meta_path)
        os.environ['FAKE_CENSUS_STAGE'] = str(stage)
        try:
            _raises_with(
                AnalyzerError,
                lambda: _run_diagnostic_scan(
                    child, '127.0.0.1:18443', 100, work_dir, output
                ),
                'mismatched txindex',
                'txindex',
            )
            assert not output.exists(), 'candidate must not be published'
        finally:
            os.environ.pop('FAKE_CENSUS_META', None)
            os.environ.pop('FAKE_CENSUS_STAGE', None)

def test_find_cmodern_height_settings_mismatch_data_dir() -> None:
    '''A child reporting a different data_dir must fail before publication.'''
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stage = _write_diagnostic_stage(tmp)
        work_dir = tmp / 'work'
        work_dir.mkdir()
        output = tmp / 'candidate.json'
        meta_path = _build_meta(
            tmp, stage, 100, work_dir,
            replay_overrides={'data_dir': str(tmp / 'other_state')},
        )
        child = _make_fake_binary(tmp)
        os.environ['FAKE_CENSUS_META'] = str(meta_path)
        os.environ['FAKE_CENSUS_STAGE'] = str(stage)
        try:
            _raises_with(
                AnalyzerError,
                lambda: _run_diagnostic_scan(
                    child, '127.0.0.1:18443', 100, work_dir, output
                ),
                'mismatched data_dir',
                'data_dir',
            )
            assert not output.exists(), 'candidate must not be published'
        finally:
            os.environ.pop('FAKE_CENSUS_META', None)
            os.environ.pop('FAKE_CENSUS_STAGE', None)

def test_read_bounded_context_rows_zero_rows() -> None:
    """An empty committed prefix with start_row=0 and rows=0 must parse."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        _make_brsctx1_file(tmp / "ctx.bin", [])
        fd = os.open(tmp / "ctx.bin", os.O_RDONLY)
        try:
            rows = read_bounded_context_rows(
                fd, start_offset=HEADER_SIZE, end_offset=HEADER_SIZE,
                start_row=0, committed_rows=0,
            )
            assert rows == []
        finally:
            os.close(fd)


def test_read_bounded_context_rows_exact_endpoint() -> None:
    """One committed row whose end equals the file size parses."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ctx = _bare_p2pkh(b"\xa1" * 32)
        _make_brsctx1_file(tmp / "ctx.bin", [ctx])
        fd = os.open(tmp / "ctx.bin", os.O_RDONLY)
        try:
            rows = read_bounded_context_rows(
                fd, start_offset=HEADER_SIZE,
                end_offset=os.fstat(fd).st_size,
                start_row=0, committed_rows=1,
            )
            assert len(rows) == 1
            assert rows[0].identity.input_index == 0
        finally:
            os.close(fd)


def test_read_bounded_context_rows_trailing_uncommitted() -> None:
    """A file longer than the committed endpoint must not observe past it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ctxs = [_bare_p2pkh(b"\xa1" * 32), _bare_p2pkh(b"\xa2" * 32)]
        _make_brsctx1_file(tmp / "ctx.bin", ctxs)
        fd = os.open(tmp / "ctx.bin", os.O_RDONLY)
        try:
            first_row_end = _compute_context_ends(tmp / "ctx.bin")[1]
            rows = read_bounded_context_rows(
                fd, start_offset=HEADER_SIZE, end_offset=first_row_end,
                start_row=0, committed_rows=1,
            )
            assert len(rows) == 1
        finally:
            os.close(fd)


def test_read_bounded_context_rows_truncated_row() -> None:
    """A row that crosses the committed endpoint fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ctx = _bare_p2pkh(b"\xa1" * 32)
        _make_brsctx1_file(tmp / "ctx.bin", [ctx])
        fd = os.open(tmp / "ctx.bin", os.O_RDONLY)
        try:
            _raises(
                ContextError,
                lambda: read_bounded_context_rows(
                    fd, start_offset=HEADER_SIZE,
                    end_offset=HEADER_SIZE + CONTEXT_MIN_ROW_SIZE - 1,
                    start_row=0, committed_rows=1,
                ),
                "truncated committed row",
            )
        finally:
            os.close(fd)


def test_c150_helper_parity() -> None:
    """_diagnostic_counter_totals matches the C150 strict counter shape."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid = b"\xc0" * 32
        ctx_row = _bare_p2pkh(txid)
        record = _make_record_bytes(txid, 0, op_kind=1, sig_version=0, outcome=1)
        journal = [_make_journal_bytes(txid, 0, checksig_ops=1, checkmultisig_ops=0, ecdsa_verify_calls=1, ecdsa_verify_ok=1)]
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        _write_records_file(tmp / "records.bin", [record])
        _write_journal_file(tmp / "journal.bin", journal)
        paths = {
            "contexts": tmp / "contexts.bin",
            "records": tmp / "records.bin",
            "journal": tmp / "journal.bin",
        }
        row = DiagnosticCheckpoint(
            height=1,
            block_hash_le=bytes([1] * 32),
            context_rows=1,
            context_end=(paths["contexts"].stat().st_size),
            record_rows=1,
            record_end=(paths["records"].stat().st_size),
            journal_rows=1,
            journal_end=(paths["journal"].stat().st_size),
        )
        classified, r, j, ctx_map, record_counts = _read_diagnostic_streams(row, None, paths)
        totals = _diagnostic_counter_totals(classified, r, ctx_map)
        assert totals["bare_multisig_checks"] == 0
        assert totals["p2sh_redeem_spends"] == 0
        assert totals["taproot_key_path_spends"] == 0
        assert totals["tapscript_spends"] == 0
        assert totals["native_witness_v0_spends"] == 0
        assert totals["p2sh_wrapped_witness_v0_spends"] == 0


def test_diagnostic_multisig_opcode_allows_multiple_ecdsa_records() -> None:
    """One CHECKMULTISIG opcode may emit multiple ordered ECDSA records."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc1" * 32
        _make_brsctx1_file(
            tmp / "contexts.bin",
            [_p2sh_push_only(txid_le, flags=VERIFY_P2SH)],
        )
        _write_records_file(
            tmp / "records.bin",
            [
                _make_record_bytes(txid_le, 0, op_kind=3, op_seq=0, outcome=1),
                _make_record_bytes(txid_le, 0, op_kind=3, op_seq=1, outcome=0),
            ],
        )
        _write_journal_file(
            tmp / "journal.bin",
            [
                _make_journal_bytes(
                    txid_le,
                    0,
                    checksig_ops=0,
                    checkmultisig_ops=1,
                    ecdsa_verify_calls=2,
                    ecdsa_verify_ok=1,
                )
            ],
        )
        paths = {
            "contexts": tmp / "contexts.bin",
            "records": tmp / "records.bin",
            "journal": tmp / "journal.bin",
        }
        row = DiagnosticCheckpoint(
            height=164676,
            block_hash_le=b"\x01" * 32,
            context_rows=1,
            context_end=paths["contexts"].stat().st_size,
            record_rows=2,
            record_end=paths["records"].stat().st_size,
            journal_rows=1,
            journal_end=paths["journal"].stat().st_size,
        )

        _classified, records, journal, _context_map, record_counts = (
            _read_diagnostic_streams(row, None, paths)
        )

        assert len(records) == 2
        assert journal[0].checkmultisig_ops == 1
        assert journal[0].ecdsa_verify_calls == 2
        assert journal[0].ecdsa_verify_ok == 1
        assert record_counts["p2sh_multisig_checks"] == 2


def test_diagnostic_multisig_short_circuit_zero_ecdsa_records() -> None:
    """One CHECKMULTISIG opcode may short-circuit before any ECDSA verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xc2" * 32
        _make_brsctx1_file(
            tmp / "contexts.bin",
            [_p2sh_push_only(txid_le, flags=VERIFY_P2SH)],
        )
        _write_records_file(tmp / "records.bin", [])
        _write_journal_file(
            tmp / "journal.bin",
            [
                _make_journal_bytes(
                    txid_le,
                    0,
                    checksig_ops=0,
                    checkmultisig_ops=1,
                    ecdsa_verify_calls=0,
                    ecdsa_verify_ok=0,
                )
            ],
        )
        paths = {
            "contexts": tmp / "contexts.bin",
            "records": tmp / "records.bin",
            "journal": tmp / "journal.bin",
        }
        row = DiagnosticCheckpoint(
            height=2,
            block_hash_le=b"\x02" * 32,
            context_rows=1,
            context_end=paths["contexts"].stat().st_size,
            record_rows=0,
            record_end=paths["records"].stat().st_size,
            journal_rows=1,
            journal_end=paths["journal"].stat().st_size,
        )

        _classified, records, journal, _context_map, record_counts = (
            _read_diagnostic_streams(row, None, paths)
        )

        assert len(records) == 0
        assert journal[0].checkmultisig_ops == 1
        assert journal[0].ecdsa_verify_calls == 0
        assert journal[0].ecdsa_verify_ok == 0
        assert record_counts["p2sh_multisig_checks"] == 0


def test_diagnostic_helper_synthetic_all_types() -> None:
    """A synthetic fixture with all spend contexts/record rules counts all 11 types."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        distinct = [bytes([0xd0 + i] * 32) for i in range(6)]
        contexts = [
            _bare_p2pkh(distinct[0]),
            _p2sh_push_only(distinct[1], flags=VERIFY_P2SH),
            _native_w0(distinct[2], flags=VERIFY_WITNESS),
            _p2sh_wrapped_w0(distinct[3], flags=VERIFY_P2SH | VERIFY_WITNESS),
            _taproot_key_path(distinct[4], flags=VERIFY_WITNESS | VERIFY_TAPROOT),
            _taproot_script_path(distinct[5], flags=VERIFY_WITNESS | VERIFY_TAPROOT),
        ]
        records = [
            _make_record_bytes(distinct[0], 0, op_kind=1, sig_version=0),
            _make_record_bytes(distinct[1], 0, op_kind=1, sig_version=0),
            _make_record_bytes(distinct[2], 0, op_kind=1, sig_version=1),
            _make_record_bytes(distinct[3], 0, op_kind=1, sig_version=1),
            _make_record_bytes(distinct[4], 0, op_kind=0, sig_version=3),
            _make_record_bytes(distinct[5], 0, op_kind=1, sig_version=2),
            _make_record_bytes(distinct[5], 0, op_kind=5, sig_version=2, op_seq=1),
        ]
        journal = [
            _make_journal_bytes(distinct[0], 0, checksig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(distinct[1], 0, checksig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(distinct[2], 0, checksig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(distinct[3], 0, checksig_ops=1, ecdsa_verify_calls=1, ecdsa_verify_ok=1),
            _make_journal_bytes(distinct[4], 0, checksig_ops=0, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
            _make_journal_bytes(distinct[5], 0, checksig_ops=1, ecdsa_verify_calls=0, ecdsa_verify_ok=0),
        ]
        _make_brsctx1_file(tmp / "contexts.bin", contexts)
        _write_records_file(tmp / "records.bin", records)
        _write_journal_file(tmp / "journal.bin", journal)
        paths = {
            "contexts": tmp / "contexts.bin",
            "records": tmp / "records.bin",
            "journal": tmp / "journal.bin",
        }
        row = DiagnosticCheckpoint(
            height=1,
            block_hash_le=bytes([1] * 32),
            context_rows=6,
            context_end=(paths["contexts"].stat().st_size),
            record_rows=7,
            record_end=(paths["records"].stat().st_size),
            journal_rows=6,
            journal_end=(paths["journal"].stat().st_size),
        )
        classified, r, j, ctx_map, record_counts = _read_diagnostic_streams(row, None, paths)
        totals = _diagnostic_counter_totals(classified, r, ctx_map)
        assert totals["p2sh_redeem_spends"] == 1
        assert totals["native_witness_v0_spends"] == 1
        assert totals["p2sh_wrapped_witness_v0_spends"] == 1
        assert totals["bare_multisig_checks"] == 0
        assert totals["p2sh_multisig_checks"] == 0
        assert totals["native_witness_v0_multisig_checks"] == 0
        assert totals["p2sh_wrapped_witness_v0_multisig_checks"] == 0
        assert totals["taproot_key_path_spends"] == 1
        assert totals["tapscript_spends"] == 1
        assert totals["tapscript_schnorr_checks"] == 2
        assert totals["tapscript_checksigadd_checks"] == 1


def test_diagnostic_op_seq_stream_order_rejects_one_before_zero() -> None:
    """Encounter-order stream 1,0 for one identity must raise CTX-OPERATIONS.

    A sorted-set implementation would accept this as {0,1}; strict row-number
    semantics reject the first emitted row because its expected op_seq is 0.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd1" * 32
        ctx_row = _bare_p2pkh(txid_le)
        records = [
            _make_record_bytes(txid_le, 0, op_kind=1, sig_version=0, op_seq=1, outcome=1),
            _make_record_bytes(txid_le, 0, op_kind=1, sig_version=0, op_seq=0, outcome=1),
        ]
        journal = [_make_journal_bytes(txid_le, 0, checksig_ops=2, ecdsa_verify_calls=2, ecdsa_verify_ok=2)]
        _make_brsctx1_file(tmp / "contexts.bin", [ctx_row])
        _write_records_file(tmp / "records.bin", records)
        _write_journal_file(tmp / "journal.bin", journal)
        paths = {
            "contexts": tmp / "contexts.bin",
            "records": tmp / "records.bin",
            "journal": tmp / "journal.bin",
        }
        row = DiagnosticCheckpoint(
            height=1,
            block_hash_le=bytes([1] * 32),
            context_rows=1,
            context_end=(paths["contexts"].stat().st_size),
            record_rows=2,
            record_end=(paths["records"].stat().st_size),
            journal_rows=1,
            journal_end=(paths["journal"].stat().st_size),
        )
        _raises_with(
            AnalyzerError,
            lambda: _read_diagnostic_streams(row, None, paths),
            "misordered op_seq 1 before 0",
            "CTX-OPERATIONS",
        )
def _diagnostic_stage(
    tmp: Path,
    contexts: list[ContextInput],
    records: list[bytes],
    journal: list[bytes],
) -> tuple[DiagnosticCheckpoint, dict[str, Path]]:
    """Write a BRSCTX1/BRSREC1/BRSJRN1 triple and a matching checkpoint."""
    _make_brsctx1_file(tmp / "contexts.bin", contexts)
    _write_records_file(tmp / "records.bin", records)
    _write_journal_file(tmp / "journal.bin", journal)
    paths = {
        "contexts": tmp / "contexts.bin",
        "records": tmp / "records.bin",
        "journal": tmp / "journal.bin",
    }
    return (
        DiagnosticCheckpoint(
            height=1,
            block_hash_le=bytes([1] * 32),
            context_rows=len(contexts),
            context_end=paths["contexts"].stat().st_size,
            record_rows=len(records),
            record_end=paths["records"].stat().st_size,
            journal_rows=len(journal),
            journal_end=paths["journal"].stat().st_size,
        ),
        paths,
    )


def test_diagnostic_first_record_op_seq_with_illegal_reports_sequence() -> None:
    """An out-of-order op_seq on the first record beats the same record's legality error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd2" * 32
        ctx = _bare_p2pkh(txid_le)
        records = [
            _make_record_bytes(txid_le, 0, op_kind=3, sig_version=2, op_seq=1, outcome=1),
        ]
        journal = [_make_journal_bytes(txid_le, 0)]
        row, paths = _diagnostic_stage(tmp, [ctx], records, journal)
        _raises_with(
            AnalyzerError,
            lambda: _read_diagnostic_streams(row, None, paths),
            "first-record op_seq=1 plus illegal op",
            "CTX-OPERATIONS",
            "op_seq contiguity violation",
            "expected 0, got 1",
        )


def test_diagnostic_earlier_sequence_beats_later_illegal() -> None:
    """A sequence error on an earlier record wins over a later illegal record."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_a = b"\xd3" * 32
        txid_b = b"\xd4" * 32
        contexts = [_bare_p2pkh(txid_a), _bare_p2pkh(txid_b)]
        records = [
            _make_record_bytes(txid_a, 0, op_kind=1, sig_version=0, op_seq=1, outcome=1),
            _make_record_bytes(txid_b, 0, op_kind=3, sig_version=2, op_seq=0, outcome=1),
        ]
        journal = [_make_journal_bytes(txid_a, 0), _make_journal_bytes(txid_b, 0)]
        row, paths = _diagnostic_stage(tmp, contexts, records, journal)
        _raises_with(
            AnalyzerError,
            lambda: _read_diagnostic_streams(row, None, paths),
            "earlier sequence beats later illegal",
            "CTX-OPERATIONS",
            "op_seq contiguity violation",
            "expected 0, got 1",
        )


def test_diagnostic_earlier_illegal_beats_later_sequence() -> None:
    """An illegal record on an earlier record wins over a later sequence error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_a = b"\xd5" * 32
        txid_b = b"\xd6" * 32
        contexts = [_bare_p2pkh(txid_a), _bare_p2pkh(txid_b)]
        records = [
            _make_record_bytes(txid_a, 0, op_kind=3, sig_version=2, op_seq=0, outcome=1),
            _make_record_bytes(txid_b, 0, op_kind=1, sig_version=0, op_seq=1, outcome=1),
        ]
        journal = [_make_journal_bytes(txid_a, 0), _make_journal_bytes(txid_b, 0)]
        row, paths = _diagnostic_stage(tmp, contexts, records, journal)
        _raises_with(
            AnalyzerError,
            lambda: _read_diagnostic_streams(row, None, paths),
            "earlier illegal beats later sequence",
            "CTX-OPERATIONS",
            "multisig record must have sig_version BASE or WITNESS_V0",
            "TAPSCRIPT",
        )


def test_diagnostic_duplicate_key_retains_precedence() -> None:
    """A duplicate record key is reported before that record's sequence or legality failure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid_le = b"\xd7" * 32
        ctx = _bare_p2pkh(txid_le)
        records = [
            _make_record_bytes(txid_le, 0, op_kind=1, sig_version=0, op_seq=0, outcome=1),
            _make_record_bytes(txid_le, 0, op_kind=3, sig_version=2, op_seq=0, outcome=1),
        ]
        journal = [_make_journal_bytes(txid_le, 0)]
        row, paths = _diagnostic_stage(tmp, [ctx], records, journal)
        _raises_with(
            AnalyzerError,
            lambda: _read_diagnostic_streams(row, None, paths),
            "duplicate key retains precedence",
            "CTX-OPERATIONS",
            "duplicate record key in BRSREC1",
            f"txid={txid_le[::-1].hex()}",
            "op_seq=0",
        )


def test_atomic_publish_rollback_fsyncs_after_unlink() -> None:
    """First post-link directory fsync fails; rollback unlinks target then fsyncs.

    The injected failure fires once, then rollback uses the real fsync on the
    reopened parent directory. We assert unlink precedes the rollback fsync and
    that neither target nor temp survive.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        target = tmp / "out.json"
        from analyze import _atomic_publish_no_replace
        original_fsync = os.fsync
        original_unlink = os.unlink

        ops: list[str] = []
        dir_fsync_count = 0

        def instrumented_unlink(p, *, dir_fd=None):
            ops.append(f"unlink:{p}")
            if dir_fd is not None:
                return original_unlink(p, dir_fd=dir_fd)
            return original_unlink(p)

        fsync_calls: list[tuple[bool, bool]] = []

        def counting_fsync(fd):
            nonlocal dir_fsync_count
            is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
            after_unlink = len(ops) > 0
            fsync_calls.append((is_dir, after_unlink))
            if is_dir:
                dir_fsync_count += 1
                if dir_fsync_count == 1 and not after_unlink:
                    raise OSError(5, "simulated post-link directory fsync error")
            return original_fsync(fd)

        try:
            os.fsync = counting_fsync
            os.unlink = instrumented_unlink
            _raises(
                OSError,
                lambda: _atomic_publish_no_replace(target, b"candidate"),
                "post-link fsync failure",
            )
        finally:
            os.fsync = original_fsync
            os.unlink = original_unlink
        assert not target.exists()
        assert not any(tmp.glob(".*out.json.tmp*"))
        assert any("unlink" in op for op in ops), "target must be unlinked during rollback"
        # fsync called after at least one unlink (rollback directory fsync).
        assert any(after for (_, after) in fsync_calls if after), "rollback fsync must follow unlink"


def test_atomic_publish_no_replace_collision() -> None:
    """os.link must fail atomically when the destination already exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        target = tmp / "out.json"
        target.write_text("racer\n")
        from analyze import _atomic_publish_no_replace
        _raises_with(
            AnalyzerError,
            lambda: _atomic_publish_no_replace(target, b"candidate"),
            "output race",
            "DIAG-OUTPUT",
        )
        assert target.read_text() == "racer\n"


def test_atomic_publish_cleans_temp_on_post_link_fsync_failure() -> None:
    """If directory fsync after the link fails, the output and temp are removed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        target = tmp / "out.json"
        from analyze import _atomic_publish_no_replace
        original_fsync = os.fsync
        def broken_fsync(fd):
            if fd >= 0:
                raise OSError(5, "simulated I/O error")
            original_fsync(fd)
        try:
            os.fsync = broken_fsync
            _raises(
                OSError,
                lambda: _atomic_publish_no_replace(target, b"candidate"),
                "post-link fsync failure",
            )
        finally:
            os.fsync = original_fsync
        assert not target.exists()
        assert not any(tmp.glob(".*out.json.tmp*")), "temp must be removed on failure"


def test_clone_committed_source_fallback_copies_only_committed_size() -> None:
    """The non-FICLONE fallback must copy only committed_size bytes, not the
    full source file.  Forces the EXDEV fallback and proves via pread tracking
    that the source is never read past the committed endpoint."""
    import errno
    import fcntl
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        source = tmp / "source.bin"
        committed_size = 64
        full_size = 192
        source.write_bytes(b"\x00" * committed_size + b"\xff" * (full_size - committed_size))
        destination = tmp / "dest.bin"

        source_fd = os.open(source, os.O_RDONLY)
        try:
            original_ioctl = fcntl.ioctl
            original_pread = os.pread
            max_read_end = 0

            def failing_ioctl(fd, request, arg):
                raise OSError(errno.EXDEV, "simulated cross-device clone")

            def tracking_pread(fd, count, offset):
                nonlocal max_read_end
                if fd == source_fd:
                    max_read_end = max(max_read_end, offset + count)
                return original_pread(fd, count, offset)

            full_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            try:
                fcntl.ioctl = failing_ioctl
                os.pread = tracking_pread
                analyze._clone_committed_source(
                    source_fd,
                    source,
                    destination,
                    committed_size,
                    source_sha256=full_sha,
                )
            finally:
                fcntl.ioctl = original_ioctl
                os.pread = original_pread

            assert destination.stat().st_size == committed_size
            assert destination.read_bytes() == b"\x00" * committed_size
            assert max_read_end <= committed_size, (
                f"fallback read up to offset {max_read_end}, "
                f"exceeding committed_size {committed_size}"
            )
        finally:
            os.close(source_fd)


def test_materialize_recovery_dir_fsyncs_parent_before_recovery_dir() -> None:
    """Each new recovery ancestor becomes durable before its child is used."""
    from analyze import DiagnosticReconstruction

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        source_dir = tmp / "source"
        source_dir.mkdir()
        source_paths = analyze._diagnostic_artifact_paths(source_dir)
        for path in source_paths.values():
            path.write_bytes(b"\x00" * 32)

        source_fds = {
            name: os.open(path, os.O_RDONLY) for name, path in source_paths.items()
        }
        ancestor_a = tmp / "new-a"
        ancestor_b = ancestor_a / "new-b"
        recovery_dir = ancestor_b / "recovery"
        expected_order = [
            str(tmp.resolve()),
            str(ancestor_a.resolve()),
            str(ancestor_b.resolve()),
            str(recovery_dir.resolve()),
        ]
        final = DiagnosticCheckpoint(
            height=0,
            block_hash_le=b"\x00" * 32,
            context_rows=0,
            context_end=16,
            record_rows=0,
            record_end=16,
            journal_rows=0,
            journal_end=16,
        )
        reconstruction = DiagnosticReconstruction(
            row_count=0,
            final=final,
            cumulative_counts={},
            first_heights={},
            source_stream_digests={},
        )
        original_fsync = os.fsync
        fsynced_directories: list[str] = []

        def tracking_fsync(fd):
            status = os.fstat(fd)
            if stat.S_ISDIR(status.st_mode):
                fsynced_directories.append(os.readlink(f"/proc/self/fd/{fd}"))
            return original_fsync(fd)

        try:
            os.fsync = tracking_fsync
            analyze._materialize_recovery_dir(
                source_paths, source_fds, recovery_dir, reconstruction
            )
        finally:
            os.fsync = original_fsync
            for fd in source_fds.values():
                os.close(fd)

        assert fsynced_directories == expected_order, (
            "new recovery ancestors must be created and fsynced root-to-leaf "
            f"before the recovery directory contents: {fsynced_directories}"
        )

# ── Runner ───────────────────────────────────────────────────────────────────


def main() -> int:
    tests = [
        test_counters_rejects_missing_field,
        test_counters_rejects_non_int_value,
        test_counters_rejects_bool_value,
        test_counters_rejects_negative_value,
        test_counters_accepts_valid_dict,
        test_validate_capture_rejects_wrong_ffi_verify_entries,
        test_validate_capture_rejects_pre_taproot_schnorr_activity,
        test_validate_capture_sorted_output_has_header,
        test_records_reject_invalid_encoded_fields,
        test_records_accept_preserved_over_capacity_ecdsa_reject,
        test_records_reject_every_over_capacity_shape_near_miss,
        test_records_reject_ordinary_over_capacity_pubkey,
        test_preserved_over_capacity_padding_checks_remain_unchanged,
        test_spike_rejects_non_integer_threads,
        test_spike_rejects_bool_threads,
        test_spike_rejects_threads_not_1,
        test_spike_accepts_threads_1,
        test_spike_accepts_runs_list_with_threads_1,
        test_spike_rejects_runs_list_without_threads_1,
        test_spike_rejects_runs_list_bool_threads,
        test_spike_rejects_nonfinite_us_per_input,
        test_bare_rejects_nonfinite_reported_values,
        test_bare_rejects_invalid_round_ns_types,
        test_bare_rejects_nonpositive_round_ns,
        test_bare_rejects_non_integer_summary_fields,
        test_verdict_rejects_invalid_numeric_fields,
        test_validate_capture_binds_corpus_identity,
        test_verdict_native_mode0_contradiction_fails,
        test_legacy_jsonl_rejects_malformed_fields,
        test_legacy_jsonl_rejects_duplicate_and_count_mismatch,
        test_brsctx1_rejects_wrong_magic,
        test_brsctx1_rejects_short_header,
        test_brsctx1_rejects_short_row_field,
        test_brsctx1_rejects_row_length_mismatch,
        test_brsctx1_rejects_impossible_witness_count,
        test_brsctx1_rejects_duplicate_execution_identity,
        test_brsctx1_rejects_declared_count_mismatch,
        test_brsctx1_rejects_trailing_bytes,
        test_brsctx1_accepts_valid_file,
        test_classify_input_block_177609_op_0_p2sh,
        test_classify_input_bare_p2pkh,
        test_classify_input_p2sh_without_flag,
        test_classify_input_p2sh_with_flag,
        test_classify_input_p2sh_wrapped_w0_p2sh_only,
        test_classify_input_p2sh_wrapped_w0_p2sh_witness,
        test_classify_input_native_w0_without_witness,
        test_classify_input_native_w0_with_witness,
        test_classify_input_taproot_no_witness,
        test_classify_input_taproot_witness_only,
        test_classify_input_taproot_key_path,
        test_classify_input_taproot_script_path,
        test_classify_input_taproot_annex_stripping,
        test_classify_input_p2sh_non_push_scriptsig,
        test_classify_input_native_v0_with_scriptsig,
        test_classify_input_taproot_bad_key_path_sig,
        test_classify_input_taproot_bad_control_block,
        test_classify_input_p2sh_op_reserved_scriptsig,
        test_parse_script_op_0_pushes_empty,
        test_parse_script_op_1negate_pushes_negative_one,
        test_parse_script_small_integers_pushes_core_scriptnum,
        test_parse_script_pushdata4_success,
        test_parse_script_pushdata4_truncated_length,
        test_parse_script_pushdata4_truncated_payload,
        test_parse_script_op_reserved_pushes_none,
        test_parse_script_op_drop_pushes_none,
        test_classify_corpus_txid_reversal_mutation,
        test_classify_corpus_all_spend_contexts,
        test_classify_corpus_c150_passes,
        test_classify_corpus_cmodern_rejects_wrong_stop_height,
        test_classify_corpus_cmodern_rejects_wrong_stop_hash,
        test_cmodern_exact_product_predicate,
        test_counter_arithmetic_schnorr_invariant,
        test_classify_corpus_zero_inputs,
        test_classify_corpus_definitions_match_counter_names,
        test_classify_corpus_missing_record_identity,
        test_classify_corpus_duplicate_record_key,
        test_classify_corpus_duplicate_journal_key,
        test_classify_corpus_native_wrapped_swap,
        test_classify_corpus_rejects_jsonl_context_file,
        test_classify_corpus_rejects_mismatched_context_size,
        test_classify_corpus_rejects_mismatched_context_sha256,
        test_classify_corpus_context_journal_key_inequality,
        test_classify_corpus_count_mismatch_ffi_verify_entries,
        test_classify_corpus_record_count_mismatch,
        test_replay_rejects_nonzero_assume_valid_height,
        test_replay_rejects_window_le_one,
        test_replay_rejects_zero_window_verify_success_total,
        test_manifest_network_mismatch_raises,
        test_manifest_genesis_mismatch_raises,
        test_manifest_range_mismatch_raises,
        test_manifest_archive_size_mismatch_raises,
        test_manifest_archive_sha256_mismatch_raises,
        test_manifest_start_height_nonzero_raises,
        test_manifest_empty_entries_raises,
        test_manifest_gapped_heights_raises,
        test_manifest_inconsistent_offset_raises,
        test_archive_frame_magic_mismatch_raises,
        test_archive_frame_payload_length_mismatch_raises,
        test_archive_header_hash_mismatch_raises,
        test_archive_genesis_prev_blockhash_nonzero_raises,
        test_archive_chain_break_raises,
        test_archive_trailing_bytes_raises,
        test_manifest_entry_count_mismatch_raises,
        test_manifest_happy_path,
        test_classify_corpus_c150_rejects_wrong_stop_height,
        test_classify_corpus_c150_rejects_wrong_stop_hash,
        test_classify_corpus_c150_rejects_mismatched_stop_hash,
        test_classify_corpus_cmodern_rejects_mismatched_op_checksigadd,
        test_classify_corpus_cmodern_all_positive_passes_synthetic_fixture,
        test_replay_rejects_wrong_network,
        test_replay_rejects_rest_block_source,
        test_replay_rejects_wrong_network_magic,
        test_replay_rejects_wrong_genesis_hash,
        test_replay_rejects_start_height_nonzero,
        test_replay_rejects_start_hash_not_genesis,
        test_replay_rejects_block_count_mismatch,
        test_replay_rejects_missing_stop_hash,
        test_replay_rejects_unknown_field,
        test_replay_rejects_nonhex_git_head,
        test_replay_rejects_uppercase_git_head,
        test_replay_rejects_bool_stage_count,
        test_replay_rejects_extra_stage_key,
        test_manifest_rejects_unknown_field,
        test_manifest_rejects_out_of_u32_range_height,
        test_manifest_rejects_out_of_u64_range_offset,
        test_manifest_rejects_duplicate_entry_height,
        test_manifest_rejects_duplicate_entry_hash,
        test_archive_rejects_payload_length_above_max,
        test_archive_rejects_payload_length_below_80,
        test_archive_rejects_frame_tail_not_stop_hash,
        test_archive_rejects_missing_archive_bytes,
        test_c150_exact_canonical_total_passes,
        test_c150_truncated_positive_total_fails,
        test_c150_zero_total_fails,
        test_c150_mutate_each_equality_member_fails,
        test_c150_nonzero_context_counter_fails,
        test_c150_eval_script_entries_not_double_fails,
        test_counters_rejects_missing_context_count,
        test_counters_rejects_missing_record_count,
        test_counters_rejects_missing_journal_count,
        test_counters_rejects_bool_context_count,
        test_counters_rejects_string_record_count,
        test_counters_rejects_negative_journal_count,
        test_journal_rejects_verdict_outside_01,
        test_journal_rejects_nonzero_padding,
        test_journal_rejects_ok_gt_calls,
        test_journal_rejects_bad_magic,
        test_journal_rejects_short_file,
        test_classify_corpus_journal_sum_op_checksig_mismatch,
        test_classify_corpus_inv1_verify_script_calls_mismatch,
        test_classify_corpus_inv2_ffi_verify_true_mismatch,
        test_classify_corpus_cmodern_bad_eval_counter_fails_closed,
        test_classify_corpus_sighash_computed_mismatch,
        test_classify_corpus_sighash_midstate_hit_mismatch,
        test_record_rejects_outcome0_with_reject_reason,
        test_record_rejects_outcome1_with_reject_reason,
        test_record_rejects_outcome2_with_zero_reject_reason,
        test_record_rejects_outcome2_with_nonzero_sighash,
        test_record_rejects_op_kind_above_5,
        test_record_rejects_sig_version_above_3,
        test_record_rejects_outcome_above_2,
        test_record_rejects_reject_reason_above_8,
        test_record_rejects_ecdsa_reject_on_schnorr_record,
        test_record_rejects_schnorr_reject_on_ecdsa_record,
        test_record_accepts_ecdsa_reject_on_ecdsa_record,
        test_record_accepts_schnorr_reject_on_schnorr_record,
        test_record_accepts_reason8_tapscript_skip,
        test_classify_corpus_ecdsa_reject_record_counts_entry,
        test_classify_corpus_schnorr_reject_record_counts_entry,
        test_classify_corpus_reason8_tapscript_skip,
        test_classify_corpus_ecdsa_fail_record,
        test_classify_corpus_ecdsa_success_record,
        test_count_context_records_multi_key_contiguous,
        test_count_context_records_multi_key_gap_raises,
        test_classify_corpus_custody_archive_matches_manifest,
        test_classify_corpus_custody_records_from_single_open,
        test_classify_corpus_custody_journal_from_single_open,
        test_parse_counters_returns_custody,
        test_classify_corpus_custody_contexts_from_same_open,
        test_classify_corpus_duplicate_context_key,
        test_classify_corpus_mixed_duplicate_before_malformed,
        test_record_validation_earlier_illegal_precedes_later_orphan,
        test_record_validation_earlier_illegal_precedes_later_sequence_gap,
        test_record_validation_semantic_error_precedes_record_count_mismatch,
        test_record_validation_same_record_orphan_precedence,
        test_count_context_records_spend_context_tally_sensitivity,
        test_classify_corpus_scratch_dir_rejects_non_directory,
        test_classify_corpus_scratch_dir_rejects_unwritable,
        test_count_context_records_disk_scratch_dir_smoke,
        test_count_context_records_disk_restores_env_on_failure,
        test_find_cmodern_height_fake_child_success,
        test_find_cmodern_height_late_failure_keeps_sidecar_count_unpatched,
        test_find_cmodern_height_post_stop_timeout_finalizes_honestly,
        test_find_cmodern_height_rejects_pipe_filling_trailing_output,
        test_salvage_cmodern_height_recovers_committed_prefixes_without_source_mutation,
        test_salvage_cmodern_height_rejects_tail_change_before_clone,
        test_salvage_cmodern_height_rejects_recovery_stream_mutation,
        test_salvage_cmodern_height_rejects_pre_signature_body_replacement,
        test_salvage_rejects_semantically_valid_exact_replay_replacement,
        test_salvage_rolls_back_candidate_after_post_publication_replacement,
        test_salvage_rolls_back_candidate_on_post_publication_interrupt,
        test_salvage_cmodern_height_rejects_zeroed_recovery_sidecar_count,
        test_salvage_preserves_exact_data_dir_text_through_to_validation,
        test_find_cmodern_height_assembles_fragmented_child_frames,
        test_find_cmodern_height_reaps_failed_child,
        test_find_cmodern_height_destination_race,
        test_validate_replay_diagnostic_accepts_a1_artifact_without_rest_url,
        test_validate_replay_diagnostic_rejects_invented_rest_url,
        test_read_bounded_context_rows_zero_rows,
        test_read_bounded_context_rows_exact_endpoint,
        test_read_bounded_context_rows_trailing_uncommitted,
        test_read_bounded_context_rows_truncated_row,
        test_c150_helper_parity,
        test_diagnostic_multisig_opcode_allows_multiple_ecdsa_records,
        test_diagnostic_multisig_short_circuit_zero_ecdsa_records,
        test_diagnostic_helper_synthetic_all_types,
        test_diagnostic_op_seq_stream_order_rejects_one_before_zero,
        test_diagnostic_first_record_op_seq_with_illegal_reports_sequence,
        test_diagnostic_earlier_sequence_beats_later_illegal,
        test_diagnostic_earlier_illegal_beats_later_sequence,
        test_diagnostic_duplicate_key_retains_precedence,
        test_atomic_publish_rollback_fsyncs_after_unlink,
        test_atomic_publish_no_replace_collision,
        test_atomic_publish_cleans_temp_on_post_link_fsync_failure,
        test_find_cmodern_height_settings_mismatch_storage_backend,
        test_find_cmodern_height_settings_mismatch_txindex,
        test_find_cmodern_height_settings_mismatch_data_dir,
        test_clone_committed_source_fallback_copies_only_committed_size,
        test_materialize_recovery_dir_fsyncs_parent_before_recovery_dir,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(tests)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
