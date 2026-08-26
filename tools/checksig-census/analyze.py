#!/usr/bin/env python3
"""CHECKSIG census analyzer.

Three subcommands:
  validate-capture  — validate Run B capture artifacts (INV-1..INV-11, INV-13)
  validate-census   — validate Run A census + cross-check with Run B (INV-12, EXP-1..4)
  verdict           — compute OPEN/CLOSED/INVALID from timing and census data

Stdlib-only, Python 3.12+.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO, NamedTuple

from context import (
    CONTEXT_MAGIC,
    CONTEXT_MIN_ROW_SIZE,
    ClassifiedInput,
    ContextError,
    SpendContext,
    classify_input,
    iter_context_inputs,
    read_bounded_context_rows,
)

# ── Constants ───────────────────────────────────────────────────────────────

RECORD_MAGIC = b"BRSREC1\x00"
JOURNAL_MAGIC = b"BRSJRN1\x00"
RECORD_SIZE = 224
JOURNAL_SIZE = 56
HEADER_SIZE = 16

EXPECTED_FFI_VERIFY_ENTRIES_FULL = 2_868_199
EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1 = 159_259

COUNTER_NAMES: list[str] = [
    "verify_script_calls",
    "ffi_verify_entries",
    "ffi_verify_true",
    "eval_script_entries",
    "op_checksig",
    "op_checksigverify",
    "op_checkmultisig",
    "op_checkmultisigverify",
    "op_checksigadd",
    "checkecdsa_entries",
    "checkecdsa_reject_pubkey",
    "checkecdsa_reject_empty_sig",
    "checkecdsa_reject_missing_data",
    "ecdsa_verify_calls",
    "ecdsa_verify_ok",
    "ecdsa_verify_fail",
    "ecdsa_from_checksig",
    "ecdsa_from_checkmultisig",
    "sighash_computed",
    "sighash_midstate_hit",
    "checkschnorr_entries",
    "schnorr_verify_calls",
    "schnorr_verify_ok",
    "schnorr_verify_fail",
]


CONTEXT_INPUT_SCHEMA = "census-context-input-v1"

CONTEXT_COUNTER_NAMES: list[str] = [
    "p2sh_redeem_spends",
    "native_witness_v0_spends",
    "p2sh_wrapped_witness_v0_spends",
    "bare_multisig_checks",
    "p2sh_multisig_checks",
    "native_witness_v0_multisig_checks",
    "p2sh_wrapped_witness_v0_multisig_checks",
    "taproot_key_path_spends",
    "tapscript_spends",
    "tapscript_schnorr_checks",
    "tapscript_checksigadd_checks",
]

CONTEXT_COUNTER_DEFINITIONS: dict[str, str] = {
    "p2sh_redeem_spends": "non-coinbase inputs whose prevout is P2SH and whose redeem script is not a witness-v0 program",
    "native_witness_v0_spends": "non-coinbase inputs whose prevout is a native witness-v0 program (P2WPKH or P2WSH)",
    "p2sh_wrapped_witness_v0_spends": "non-coinbase inputs whose prevout is P2SH and whose redeem script is a witness-v0 program",
    "bare_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a bare legacy input",
    "p2sh_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a P2SH input",
    "native_witness_v0_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a native witness-v0 input",
    "p2sh_wrapped_witness_v0_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a P2SH-wrapped witness-v0 input",
    "taproot_key_path_spends": "P2TR inputs with one witness element after optional annex removal",
    "tapscript_spends": "P2TR inputs with at least two witness elements after optional annex removal",
    "tapscript_schnorr_checks": "BRSREC1 executed-operation records with sig_version TAPSCRIPT and op_kind CHECKSIG, CHECKSIGVERIFY, or CHECKSIGADD",
    "tapscript_checksigadd_checks": "BRSREC1 executed-operation records with sig_version TAPSCRIPT and op_kind CHECKSIGADD",
}

MULTISIG_ELIGIBLE_CONTEXTS: frozenset[SpendContext] = frozenset((
    SpendContext.BARE,
    SpendContext.P2SH,
    SpendContext.NATIVE_WITNESS_V0,
    SpendContext.P2SH_WRAPPED_WITNESS_V0,
))
HEADER_STRUCT = struct.Struct("<8sQ")
RECORD_STRUCT = struct.Struct("<32sIIBBBBBBBB32s72s65s7s")
JOURNAL_STRUCT = struct.Struct("<32sIIIIIB3s")

assert HEADER_STRUCT.size == HEADER_SIZE
assert RECORD_STRUCT.size == RECORD_SIZE
assert JOURNAL_STRUCT.size == JOURNAL_SIZE

# ── Canonical mainnet constants ─────────────────────────────────────────────

MAINNET_MAGIC = "f9beb4d9"
MAINNET_GENESIS_HASH = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)
C150_STOP_HEIGHT = 150_000
C150_STOP_HASH = (
    "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"
)
# The recovered diagnostic candidate selects this product tip. It does not
# certify a corpus. Certification still requires a fresh file-bound replay.
CMODERN_STOP_HEIGHT = 709_635
CMODERN_STOP_HASH = (
    "00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f"
)


# ── Exceptions ──────────────────────────────────────────────────────────────


class AnalyzerError(Exception):
    """Fatal: malformed input or unparseable file."""


def _require_positive_finite_float(value: object, field: str) -> float:
    """Return value as float, or raise AnalyzerError if it is not a finite,
    non-boolean, positive int/float.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalyzerError(
            f"{field} must be a non-boolean int or float, got {type(value).__name__}"
        )
    f = float(value)
    if math.isnan(f) or math.isinf(f):
        raise AnalyzerError(f"{field} must be finite, got {value!r}")
    if f <= 0.0:
        raise AnalyzerError(f"{field} must be > 0, got {value!r}")
    return f


def _require_non_bool_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalyzerError(
            f"{field} must be a non-boolean integer, got {type(value).__name__}"
        )
    return value


def _require_exact_keys(
    d: dict[str, object], expected: set[str], label: str
) -> None:
    """Reject unknown or missing keys in *d* against *expected*."""
    actual = set(d.keys())
    unknown = actual - expected
    if unknown:
        raise AnalyzerError(
            f"CTX-CUSTODY: {label} has unknown key(s): {sorted(unknown)}"
        )
    missing = expected - actual
    if missing:
        raise AnalyzerError(
            f"CTX-CUSTODY: {label} missing required key(s): {sorted(missing)}"
        )


def _require_u32(value: object, field: str) -> int:
    """Validate a u32 (0 ..= 2**32-1)."""
    v = _require_non_bool_int(value, field)
    if v < 0 or v > 0xFFFFFFFF:
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be u32 (0..{0xFFFFFFFF}), got {v}"
        )
    return v


def _require_u64(value: object, field: str) -> int:
    """Validate a u64 (0 ..= 2**64-1)."""
    v = _require_non_bool_int(value, field)
    if v < 0 or v > 0xFFFFFFFFFFFFFFFF:
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be u64, got {v}"
        )
    return v


def _require_custody_ref(value: object, label: str, *, with_schema: bool = False) -> dict[str, object]:
    """Validate a custody reference object (path/bytes/sha256, optionally schema/version)."""
    if not isinstance(value, dict):
        raise AnalyzerError(f"CTX-CUSTODY: {label} must be an object")
    expected = {"path", "bytes", "sha256"}
    if with_schema:
        expected |= {"schema", "version"}
    _require_exact_keys(value, expected, label)
    path = value["path"]
    if not isinstance(path, str) or len(path) == 0:
        raise AnalyzerError(f"CTX-CUSTODY: {label}.path must be a nonempty string")
    bytes_val = _require_non_bool_int(value["bytes"], f"{label}.bytes")
    if bytes_val < 0:
        raise AnalyzerError(f"CTX-CUSTODY: {label}.bytes must be >= 0, got {bytes_val}")
    sha = _require_hex_str(value["sha256"], f"{label}.sha256", 64)
    result: dict[str, object] = {"path": path, "bytes": bytes_val, "sha256": sha}
    if with_schema:
        schema = value["schema"]
        if schema != "bitcoin-rs-corpus-manifest":
            raise AnalyzerError(
                f"CTX-CUSTODY: {label}.schema is {schema!r}, "
                f"expected 'bitcoin-rs-corpus-manifest'"
            )
        version = _require_int_field(value["version"], f"{label}.version")
        if version != 1:
            raise AnalyzerError(f"CTX-CUSTODY: {label}.version must be 1, got {version}")
        result["schema"] = schema
        result["version"] = version
    return result


# ── Data classes ────────────────────────────────────────────────────────────


class Counters:
    """Parsed counters JSON."""

    verify_script_calls: int
    ffi_verify_entries: int
    ffi_verify_true: int
    eval_script_entries: int
    op_checksig: int
    op_checksigverify: int
    op_checkmultisig: int
    op_checkmultisigverify: int
    op_checksigadd: int
    checkecdsa_entries: int
    checkecdsa_reject_pubkey: int
    checkecdsa_reject_empty_sig: int
    checkecdsa_reject_missing_data: int
    ecdsa_verify_calls: int
    ecdsa_verify_ok: int
    ecdsa_verify_fail: int
    ecdsa_from_checksig: int
    ecdsa_from_checkmultisig: int
    sighash_computed: int
    sighash_midstate_hit: int
    checkschnorr_entries: int
    schnorr_verify_calls: int
    schnorr_verify_ok: int
    schnorr_verify_fail: int
    context_count: int

    def __init__(self, raw: dict[str, object]) -> None:
        self._raw = raw
        self.schema: int = int(raw.get("schema", 0))
        self.label: str = str(raw.get("label", ""))
        for name in COUNTER_NAMES:
            if name not in raw:
                raise AnalyzerError(f"counters JSON: missing required field {name!r}")
            value = raw[name]
            if isinstance(value, bool) or not isinstance(value, int):
                raise AnalyzerError(
                    f"counters JSON: field {name!r} must be int, got {type(value).__name__}"
                )
            if value < 0:
                raise AnalyzerError(
                    f"counters JSON: field {name!r} must be >= 0, got {value}"
                )
            setattr(self, name, value)
        # ── Reconciliation count fields: required, strict non-bool nonnegative int ──
        for _rc_field in ("record_count", "journal_count", "context_count"):
            if _rc_field not in raw:
                raise AnalyzerError(
                    f"counters JSON: missing required field {_rc_field!r}"
                )
            _rc_val = raw[_rc_field]
            if isinstance(_rc_val, bool) or not isinstance(_rc_val, int):
                raise AnalyzerError(
                    f"counters JSON: field {_rc_field!r} must be int, "
                    f"got {type(_rc_val).__name__}"
                )
            if _rc_val < 0:
                raise AnalyzerError(
                    f"counters JSON: field {_rc_field!r} must be >= 0, got {_rc_val}"
                )
        self.record_count: int = raw["record_count"]
        self.journal_count: int = raw["journal_count"]
        self.context_count: int = raw["context_count"]

class Record:
    """Parsed 224-byte record."""

    __slots__ = (
        "der_len",
        "der_sig",
        "input_index",
        "op_kind",
        "op_seq",
        "outcome",
        "pubkey",
        "pubkey_len",
        "reject_reason",
        "sig_version",
        "sighash",
        "sighash_type",
        "spend_txid",
    )

    def __init__(self, raw: bytes) -> None:
        unpacked = RECORD_STRUCT.unpack(raw)
        (
            self.spend_txid,
            self.input_index,
            self.op_seq,
            self.op_kind,
            self.sig_version,
            self.outcome,
            self.der_len,
            self.pubkey_len,
            self.sighash_type,
            self.reject_reason,
            _pad0,
            self.sighash,
            self.der_sig,
            self.pubkey,
            _pad1,
        ) = unpacked
        # Exact over-capacity ECDSA reject shape accepted by both BRSREC1 readers.
        # Native reason-1 records may preserve the original (>=66) pubkey_len only
        # for outcome 2 with a null payload and unchanged padding.
        _is_exact_over_capacity_reject = (
            self.outcome == 2
            and self.reject_reason == 1
            and 1 <= self.op_kind <= 4
            and self.sig_version in (0, 1)
            and self.der_len == 0
            and self.sighash_type == 0
            and _pad0 == 0
            and _pad1 == b"\x00" * 7
            and self.sighash == b"\x00" * 32
            and self.der_sig == b"\x00" * 72
            and self.pubkey == b"\x00" * 65
        )
        if self.pubkey_len > 65 and not _is_exact_over_capacity_reject:
            raise AnalyzerError(f"CTX-OPERATIONS: record pubkey_len {self.pubkey_len} exceeds 65")
        # ── Canonical field-range validation ──
        if self.op_kind > 5:
            raise AnalyzerError(f"CTX-OPERATIONS: record op_kind {self.op_kind} exceeds 5")
        if self.sig_version > 3:
            raise AnalyzerError(f"CTX-OPERATIONS: record sig_version {self.sig_version} exceeds 3")
        if self.outcome > 2:
            raise AnalyzerError(f"CTX-OPERATIONS: record outcome {self.outcome} exceeds 2")
        if self.reject_reason > 8:
            raise AnalyzerError(f"CTX-OPERATIONS: record reject_reason {self.reject_reason} exceeds 8")
        # Canonical outcome/reject combinations:
        # outcome 0/1 (post-verification) must not carry a reject reason.
        # outcome 2 (pre-verification reject) must have a valid reason and no sighash.
        if self.outcome in (0, 1) and self.reject_reason != 0:
            raise AnalyzerError(
                f"CTX-OPERATIONS: outcome {self.outcome} must have reject_reason 0, "
                f"got {self.reject_reason}"
            )
        if self.outcome == 2:
            if self.reject_reason == 0:
                raise AnalyzerError(
                    "CTX-OPERATIONS: outcome 2 (pre-verification reject) must have a non-zero reject_reason"
                )
            if self.sighash != b"\x00" * 32:
                raise AnalyzerError(
                    "CTX-OPERATIONS: pre-verification reject must have an all-zero sighash"
                )
            # ── Reject-family compatibility: exact native emission ──
            _is_ecdsa_rec = self.sig_version in (0, 1) and self.op_kind in (1, 2, 3, 4)
            _is_schnorr_rec = (
                (self.sig_version == 2 and self.op_kind in (1, 2, 5))
                or (self.sig_version == 3 and self.op_kind == 0)
            )
            _is_tapscript_skip = (
                self.sig_version == 2 and self.op_kind in (1, 2, 5)
                and self.der_len == 0
            )
            if self.reject_reason in (1, 2, 3):
                if not _is_ecdsa_rec:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: reject_reason {self.reject_reason} "
                        f"requires ECDSA record (sig_version 0/1, op_kind 1..4), "
                        f"got sig_version {self.sig_version}, op_kind {self.op_kind}"
                    )
            elif self.reject_reason in (4, 5, 6, 7):
                if not _is_schnorr_rec:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: reject_reason {self.reject_reason} "
                        f"requires Schnorr record (sig_version 2 op 1/2/5, "
                        f"or sig_version 3 op 0), got sig_version "
                        f"{self.sig_version}, op_kind {self.op_kind}"
                    )
            elif self.reject_reason == 8:
                if not _is_tapscript_skip:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: reject_reason 8 requires Tapscript "
                        f"skipped call (sig_version 2, op_kind 1/2/5, "
                        f"empty signature), got sig_version "
                        f"{self.sig_version}, op_kind {self.op_kind}, "
                        f"der_len {self.der_len}"
                    )
        if self.der_len > 72:
            # The native instrumented kernel stores the original vchSig length in
            # der_len but only copies up to 72 bytes into the fixed-size der_sig
            # field.  Lengths > 72 therefore mean the signature was truncated; the
            # record still contains at most 72 meaningful bytes, so we clamp the
            # padding check to the field size.
            effective_der_len = 72
        else:
            effective_der_len = self.der_len
        # ── Padding must be all-zero ──
        if _pad0 != 0:
            raise AnalyzerError("CTX-OPERATIONS: record _pad0 is not all-zero")
        if _pad1 != b"\x00" * 7:
            raise AnalyzerError("CTX-OPERATIONS: record _pad1 is not all-zero")
        # ── Trailing bytes in der_sig / pubkey beyond their lengths must be zero ──
        if self.der_sig[effective_der_len:] != b"\x00" * (72 - effective_der_len):
            raise AnalyzerError(
                f"CTX-OPERATIONS: record der_sig has non-zero padding beyond der_len={self.der_len}"
            )
        if self.pubkey[self.pubkey_len:] != b"\x00" * (65 - self.pubkey_len):
            raise AnalyzerError(
                f"CTX-OPERATIONS: record pubkey has non-zero padding beyond pubkey_len={self.pubkey_len}"
            )

    @property
    def sort_key(self) -> tuple[bytes, int, int]:
        return (self.spend_txid, self.input_index, self.op_seq)


class JournalEntry:
    """Parsed 56-byte journal entry."""

    __slots__ = (
        "checkmultisig_ops",
        "checksig_ops",
        "ecdsa_verify_calls",
        "ecdsa_verify_ok",
        "input_index",
        "spend_txid",
        "verdict",
    )

    def __init__(self, raw: bytes) -> None:
        unpacked = JOURNAL_STRUCT.unpack(raw)
        (
            self.spend_txid,
            self.input_index,
            self.checksig_ops,
            self.checkmultisig_ops,
            self.ecdsa_verify_calls,
            self.ecdsa_verify_ok,
            self.verdict,
            _pad,
        ) = unpacked
        # ── Canonical field-range validation ──
        if self.verdict not in (0, 1):
            raise AnalyzerError(
                f"CTX-OPERATIONS: journal verdict {self.verdict} must be 0 or 1"
            )
        if _pad != b"\x00" * 3:
            raise AnalyzerError("CTX-OPERATIONS: journal padding is not all-zero")
        if self.ecdsa_verify_ok > self.ecdsa_verify_calls:
            raise AnalyzerError(
                f"CTX-OPERATIONS: ecdsa_verify_ok {self.ecdsa_verify_ok} > "
                f"ecdsa_verify_calls {self.ecdsa_verify_calls}"
            )

    @property
    def key(self) -> tuple[bytes, int]:
        return (self.spend_txid, self.input_index)



# ── Canonical BRSREC1 interpretation (shared by disk classifier and diagnostic scanner)


# Each rule is a list of (op_kind, sig_version, spend_context) triples.
# Used both by the diagnostic per-block loop and the set-based disk classifier.
_RECORD_COUNTER_RULES: list[tuple[str, list[tuple[int, int, str]]]] = [
    ("bare_multisig_checks", [(3, 0, "bare"), (4, 0, "bare")]),
    ("p2sh_multisig_checks", [(3, 0, "p2sh"), (4, 0, "p2sh")]),
    ("native_witness_v0_multisig_checks", [(3, 1, "native_witness_v0"), (4, 1, "native_witness_v0")]),
    ("p2sh_wrapped_witness_v0_multisig_checks", [(3, 1, "p2sh_wrapped_witness_v0"), (4, 1, "p2sh_wrapped_witness_v0")]),
    ("tapscript_schnorr_checks", [(5, 2, "tapscript"), (1, 2, "tapscript"), (2, 2, "tapscript")]),
    ("tapscript_checksigadd_checks", [(5, 2, "tapscript")]),
]


def _record_matches_rule(
    record: Record,
    spend_context: str,
    rule: list[tuple[int, int, str]],
) -> bool:
    """Test a BRSREC1 record against one counter rule."""
    return (record.op_kind, record.sig_version, spend_context) in rule


def _record_legality_error(record: Record, spend_context: str) -> str | None:
    """Return the canonical CTX-OPERATIONS error code for a record, or None.

    This must match the SQL CASE in ``_count_context_records_disk`` exactly;
    it is the single source of truth for BRSREC1 op/sig/context legality.
    """
    op, sig, ctx = record.op_kind, record.sig_version, spend_context

    if op in (3, 4):
        if sig not in (0, 1):
            return "multisig_sig"
        if ctx == "bare" and sig != 0:
            return "bare_multisig"
        if ctx == "p2sh" and sig != 0:
            return "p2sh_multisig"
        if ctx == "native_witness_v0" and sig != 1:
            return "native_multisig"
        if ctx == "p2sh_wrapped_witness_v0" and sig != 1:
            return "wrapped_multisig"
        if ctx in ("taproot_key_path", "tapscript"):
            return "taproot_multisig"

    if op == 5:
        if sig != 2:
            return "checksigadd_sig"
        if ctx != "tapscript":
            return "checksigadd_context"

    if op == 0:
        if sig != 3:
            return "keypath_sig"
        if ctx != "taproot_key_path":
            return "keypath_context"

    if op in (1, 2):
        if sig == 2 and ctx != "tapscript":
            return "tapscript_checksig"
        if sig == 1 and ctx not in ("native_witness_v0", "p2sh_wrapped_witness_v0"):
            return "witness_checksig"
        if sig == 0 and ctx not in ("bare", "p2sh"):
            return "base_checksig"
        if sig not in (0, 1, 2):
            return "unknown_checksig"

    if op not in (0, 1, 2, 3, 4, 5):
        return "unknown_op"

    return None


def _diagnostic_spend_counts(classified: list[ClassifiedInput]) -> dict[str, int]:
    """Derive the five spend-context counters from classified BRSCTX1 inputs."""
    counts: dict[str, int] = {
        "p2sh_redeem_spends": 0,
        "native_witness_v0_spends": 0,
        "p2sh_wrapped_witness_v0_spends": 0,
        "taproot_key_path_spends": 0,
        "tapscript_spends": 0,
    }
    for evidence in classified:
        sc = evidence.spend_context.value
        if sc == SpendContext.P2SH.value:
            counts["p2sh_redeem_spends"] += 1
        elif sc == SpendContext.NATIVE_WITNESS_V0.value:
            counts["native_witness_v0_spends"] += 1
        elif sc == SpendContext.P2SH_WRAPPED_WITNESS_V0.value:
            counts["p2sh_wrapped_witness_v0_spends"] += 1
        elif sc == SpendContext.TAPROOT_KEY_PATH.value:
            counts["taproot_key_path_spends"] += 1
        elif sc == SpendContext.TAPSCRIPT.value:
            counts["tapscript_spends"] += 1
    return counts


def _diagnostic_record_counts(
    records: list[Record],
    context_map: dict[tuple[bytes, int], str],
) -> tuple[dict[str, int], dict[tuple[bytes, int, int], int]]:
    """Derive the six record-derived context counters from one block's records.

    Validates each record in stream order, checking:
      1. the record's context identity exists (orphan),
      2. the (txid, input_index, op_seq) key is not a duplicate,
      3. the per-identity op_seq matches the next expected value,
      4. the (op_kind, sig_version, spend_context) triple is legal,
    before incrementing the relevant context counter.

    Returns (counts, op_seq_by_identity) where op_seq_by_identity is the
    set of exact record keys seen during the stream.
    """
    counts: dict[str, int] = {
        "bare_multisig_checks": 0,
        "p2sh_multisig_checks": 0,
        "native_witness_v0_multisig_checks": 0,
        "p2sh_wrapped_witness_v0_multisig_checks": 0,
        "tapscript_schnorr_checks": 0,
        "tapscript_checksigadd_checks": 0,
    }
    op_seq_by_identity: dict[tuple[bytes, int, int], int] = {}
    next_op_seq: dict[tuple[bytes, int], int] = {}

    for record in records:
        key = (record.spend_txid, record.input_index)
        if key not in context_map:
            display_txid = record.spend_txid[::-1].hex()
            raise AnalyzerError(
                f"CTX-OPERATIONS: BRSREC1 record has no matching context identity: "
                f"txid={display_txid}, input_index={record.input_index}"
            )

        ctx = context_map[key]

        seq_key = (record.spend_txid, record.input_index, record.op_seq)
        if seq_key in op_seq_by_identity:
            display_txid = record.spend_txid[::-1].hex()
            raise AnalyzerError(
                f"CTX-OPERATIONS: duplicate record key in BRSREC1: "
                f"txid={display_txid}, input_index={record.input_index}, op_seq={record.op_seq}"
            )
        op_seq_by_identity[seq_key] = 1

        expected_op_seq = next_op_seq.get(key, 0)
        if record.op_seq != expected_op_seq:
            display_txid = record.spend_txid[::-1].hex()
            raise AnalyzerError(
                f"CTX-OPERATIONS: op_seq contiguity violation for {display_txid}:{record.input_index}: "
                f"expected {expected_op_seq}, got {record.op_seq}"
            )

        error = _record_legality_error(record, ctx)
        if error is not None:
            sig_name = _sig_version_name(record.sig_version)
            op_name = _op_kind_name(record.op_kind)
            display_txid = record.spend_txid[::-1].hex()
            identity = f"txid={display_txid}, input_index={record.input_index}"
            message = _record_legality_message(error, op_name, sig_name, identity)
            raise AnalyzerError(f"CTX-OPERATIONS: {message}")

        next_op_seq[key] = record.op_seq + 1

        for name, rule in _RECORD_COUNTER_RULES:
            if _record_matches_rule(record, ctx, rule):
                counts[name] += 1

    return counts, op_seq_by_identity


def _record_legality_message(error: str, op_name: str, sig_name: str, identity: str) -> str:
    """Human-readable message for a BRSREC1 legality error code."""
    if error == "multisig_sig":
        return f"multisig record must have sig_version BASE or WITNESS_V0, got {sig_name} for {identity}"
    if error == "bare_multisig":
        return f"bare multisig record has sig_version {sig_name}, expected BASE for {identity}"
    if error == "p2sh_multisig":
        return f"P2SH multisig record has sig_version {sig_name}, expected BASE for {identity}"
    if error == "native_multisig":
        return f"native witness-v0 multisig record has sig_version {sig_name}, expected WITNESS_V0 for {identity}"
    if error == "wrapped_multisig":
        return f"P2SH-wrapped witness-v0 multisig record has sig_version {sig_name}, expected WITNESS_V0 for {identity}"
    if error == "taproot_multisig":
        return f"multisig record joined to a Taproot input {identity}"
    if error == "checksigadd_sig":
        return f"CHECKSIGADD record must have sig_version TAPSCRIPT, got {sig_name} for {identity}"
    if error == "checksigadd_context":
        return f"CHECKSIGADD record joined to a non-Tapscript input {identity}"
    if error == "keypath_sig":
        return f"key-path record must have sig_version TAPROOT, got {sig_name} for {identity}"
    if error == "keypath_context":
        return f"key-path record joined to a non-key-path input {identity}"
    if error == "tapscript_checksig":
        return f"Tapscript CHECKSIG record joined to a non-Tapscript input {identity}"
    if error == "witness_checksig":
        return f"WITNESS_V0 CHECKSIG record joined to a non-witness-v0 input {identity}"
    if error == "base_checksig":
        return f"BASE CHECKSIG record joined to a non-legacy input {identity}"
    if error == "unknown_checksig":
        return f"CHECKSIG record has unknown sig_version {sig_name} for {identity}"
    if error == "unknown_op":
        return f"unknown op_kind {op_name} for {identity}"
    return f"unknown error code {error} for {identity}"


def _diagnostic_counter_totals(
    classified: list[ClassifiedInput],
    records: list[Record],
    context_map: dict[tuple[bytes, int], str],
) -> dict[str, int]:
    """Combine spend-context and record-derived counters into the 11 canonical values."""
    spend_counts = _diagnostic_spend_counts(classified)
    record_counts, _ = _diagnostic_record_counts(records, context_map)
    return {**spend_counts, **record_counts}
def _accumulate_block_counts(
    block_counts: dict[str, int],
    height: int,
    cumulative_counts: dict[str, int],
    first_heights: dict[str, int],
) -> None:
    """Merge one block's 11 context counters into the scan aggregates."""
    for name in CONTEXT_COUNTER_NAMES:
        cumulative_counts[name] += block_counts[name]
        if block_counts[name] > 0 and name not in first_heights:
            first_heights[name] = height





# ── Cmodern diagnostic checkpoint protocol


DIAGNOSTIC_PREFACE_SIZE = 16
DIAGNOSTIC_ROW_SIZE = 84
DIAGNOSTIC_MAGIC = b"BRSHGT1\x00"
DIAGNOSTIC_VERSION = 1

BRSHGT1_HEADER_STRUCT = struct.Struct("<8sQ")
BRSHGT1_ROW_STRUCT = struct.Struct("<I32sQQQQQQ")


class DiagnosticCheckpoint(NamedTuple):
    height: int
    block_hash_le: bytes
    context_rows: int
    context_end: int
    record_rows: int
    record_end: int
    journal_rows: int
    journal_end: int


class DiagnosticTeardown(NamedTuple):
    """Observed child teardown and optional offline-salvage provenance."""

    exit_status: int | None
    state: str
    salvaged_from: str | None
    source_custody: dict[str, dict[str, object]] | None


class DiagnosticStreamDigests(NamedTuple):
    """Hashes of one validated source stream, its committed prefix, and body."""

    full_file_sha256: str
    committed_prefix_sha256: str
    committed_body_sha256: str


class DiagnosticReconstruction(NamedTuple):
    """Validated aggregate state reconstructed from committed evidence."""

    row_count: int
    final: DiagnosticCheckpoint
    cumulative_counts: dict[str, int]
    first_heights: dict[str, int]
    source_stream_digests: dict[str, DiagnosticStreamDigests]




def _read_exact_stream(stream: BinaryIO, length: int, field: str) -> bytes:
    """Read exactly *length* bytes from the child protocol stream.

    Python's read(n) may return fewer than n bytes before EOF (e.g. when
    the kernel has not yet delivered the rest of a pipe frame).  We
    accumulate short reads into a single bounded buffer and only stop
    at the exact requested length or at a true EOF (empty read).
    """
    if length < 0:
        raise AnalyzerError(f"DIAG-PROTO: invalid read length {length} for {field}")
    out = bytearray(length)
    received = 0
    while received < length:
        chunk = stream.read(length - received)
        if not chunk:
            raise AnalyzerError(
                f"DIAG-PROTO: short {field}: expected {length} bytes, got {received}"
            )
        got = len(chunk)
        if got > length - received:
            raise AnalyzerError(
                f"DIAG-PROTO: overlong {field}: expected {length - received} bytes, got {got}"
            )
        out[received : received + got] = chunk
        received += got
    return bytes(out)


def _read_diagnostic_preface(stream: BinaryIO) -> None:
    """Validate the 16-byte preface on child stdout."""
    preface = _read_exact_stream(stream, DIAGNOSTIC_PREFACE_SIZE, "preface")
    magic = preface[:8]
    version = struct.unpack_from("<I", preface, 8)[0]
    row_size = struct.unpack_from("<I", preface, 12)[0]
    if magic != DIAGNOSTIC_MAGIC:
        raise AnalyzerError(f"DIAG-PROTO: wrong preface magic {magic!r}")
    if version != DIAGNOSTIC_VERSION:
        raise AnalyzerError(f"DIAG-PROTO: unsupported protocol version {version}")
    if row_size != DIAGNOSTIC_ROW_SIZE:
        raise AnalyzerError(f"DIAG-PROTO: unsupported row size {row_size}, expected {DIAGNOSTIC_ROW_SIZE}")


def _read_checkpoint_row(stream: BinaryIO) -> DiagnosticCheckpoint:
    """Read one 84-byte BRSHGT1 row from the child protocol stream."""
    raw = _read_exact_stream(stream, DIAGNOSTIC_ROW_SIZE, "checkpoint row")
    (
        height,
        block_hash_le,
        context_rows,
        context_end,
        record_rows,
        record_end,
        journal_rows,
        journal_end,
    ) = BRSHGT1_ROW_STRUCT.unpack(raw)
    return DiagnosticCheckpoint(
        height=height,
        block_hash_le=block_hash_le,
        context_rows=context_rows,
        context_end=context_end,
        record_rows=record_rows,
        record_end=record_end,
        journal_rows=journal_rows,
        journal_end=journal_end,
    )


def _write_brshgt1_preface(fd: int) -> None:
    """Write the 16-byte BRSHGT1 placeholder header."""
    header = BRSHGT1_HEADER_STRUCT.pack(DIAGNOSTIC_MAGIC, 0)
    written = os.write(fd, header)
    if written != len(header):
        raise AnalyzerError("DIAG-SIDECAR: short write of BRSHGT1 placeholder header")
    os.fsync(fd)


def _write_brshgt1_row(fd: int, row: DiagnosticCheckpoint) -> None:
    """Append one 84-byte row and fsync the sidecar."""
    raw = BRSHGT1_ROW_STRUCT.pack(*row)
    written = os.write(fd, raw)
    if written != len(raw):
        raise AnalyzerError("DIAG-SIDECAR: short write of BRSHGT1 row")
    os.fsync(fd)


def _patch_brshgt1_count(sidecar_path: Path, count: int) -> None:
    """Patch the row count in the sidecar header, fsync, then sync parent dir."""
    fd = os.open(sidecar_path, os.O_RDWR)
    try:
        header = os.pread(fd, BRSHGT1_HEADER_STRUCT.size, 0)
        if len(header) != BRSHGT1_HEADER_STRUCT.size:
            raise AnalyzerError("DIAG-SIDECAR: cannot read header for count patch")
        magic, _old = BRSHGT1_HEADER_STRUCT.unpack(header)
        if magic != DIAGNOSTIC_MAGIC:
            raise AnalyzerError("DIAG-SIDECAR: wrong magic while patching count")
        os.pwrite(fd, struct.pack("<Q", count), 8)
        os.fsync(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(sidecar_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _brshgt1_count(sidecar_path: Path) -> int:
    """Return the declared row count from a finalized BRSHGT1 sidecar."""
    fd = os.open(sidecar_path, os.O_RDONLY)
    try:
        header = os.pread(fd, BRSHGT1_HEADER_STRUCT.size, 0)
        if len(header) != BRSHGT1_HEADER_STRUCT.size:
            raise AnalyzerError("DIAG-SIDECAR: short header")
        magic, count = BRSHGT1_HEADER_STRUCT.unpack(header)
        if magic != DIAGNOSTIC_MAGIC:
            raise AnalyzerError("DIAG-SIDECAR: wrong magic")
        return count
    finally:
        os.close(fd)


def _open_brshgt1_read_fd(sidecar_path: Path) -> int:
    """Open a BRSHGT1 sidecar and validate its preface/header."""
    fd = os.open(sidecar_path, os.O_RDONLY)
    valid = False
    try:
        header = os.pread(fd, BRSHGT1_HEADER_STRUCT.size, 0)
        if len(header) != BRSHGT1_HEADER_STRUCT.size:
            raise AnalyzerError("DIAG-SIDECAR: short header")
        magic, count = BRSHGT1_HEADER_STRUCT.unpack(header)
        if magic != DIAGNOSTIC_MAGIC:
            raise AnalyzerError(f"DIAG-SIDECAR: wrong magic {magic!r}")
        file_size = os.fstat(fd).st_size
        expected = BRSHGT1_HEADER_STRUCT.size + count * DIAGNOSTIC_ROW_SIZE
        if file_size != expected:
            raise AnalyzerError(
                f"DIAG-SIDECAR: size {file_size} != header {BRSHGT1_HEADER_STRUCT.size} + "
                f"{count} x {DIAGNOSTIC_ROW_SIZE} = {expected}"
            )
        valid = True
        return fd
    finally:
        if not valid:
            os.close(fd)


def _read_brshgt1_row(fd: int, row_number: int) -> DiagnosticCheckpoint:
    """Read the Nth 84-byte row from a sidecar (1-indexed)."""
    offset = BRSHGT1_HEADER_STRUCT.size + (row_number - 1) * DIAGNOSTIC_ROW_SIZE
    raw = os.pread(fd, DIAGNOSTIC_ROW_SIZE, offset)
    if len(raw) != DIAGNOSTIC_ROW_SIZE:
        raise AnalyzerError(f"DIAG-SIDECAR: short row {row_number}")
    (
        height,
        block_hash_le,
        context_rows,
        context_end,
        record_rows,
        record_end,
        journal_rows,
        journal_end,
    ) = BRSHGT1_ROW_STRUCT.unpack(raw)
    return DiagnosticCheckpoint(
        height=height,
        block_hash_le=block_hash_le,
        context_rows=context_rows,
        context_end=context_end,
        record_rows=record_rows,
        record_end=record_end,
        journal_rows=journal_rows,
        journal_end=journal_end,
    )




def _read_fixed_entries_slice(
    fd: int,
    start_offset: int,
    end_offset: int,
    start_row: int,
    committed_rows: int,
    entry_size: int,
    name: str,
    observe_bytes: Callable[[bytes], None] | None = None,
) -> list[bytes]:
    """Read a committed slice of fixed-size entries using pread."""
    if start_row < 0 or committed_rows < start_row:
        raise AnalyzerError(f"DIAG-PROTO: invalid {name} row range {start_row}..{committed_rows}")
    if start_offset < HEADER_SIZE or end_offset < start_offset:
        raise AnalyzerError(f"DIAG-PROTO: invalid {name} byte range {start_offset}..{end_offset}")
    expected_start = HEADER_SIZE + start_row * entry_size
    expected_end = HEADER_SIZE + committed_rows * entry_size
    if start_offset != expected_start or end_offset != expected_end:
        raise AnalyzerError(
            f"DIAG-PROTO: {name} endpoint mismatch: "
            f"expected {expected_start}..{expected_end}, got {start_offset}..{end_offset}"
        )
    file_size = os.fstat(fd).st_size
    if end_offset > file_size:
        raise AnalyzerError(
            f"DIAG-PROTO: {name} endpoint {end_offset} exceeds file size {file_size}"
        )
    slice_size = end_offset - start_offset
    if slice_size != (committed_rows - start_row) * entry_size:
        raise AnalyzerError(f"DIAG-PROTO: {name} slice size {slice_size} does not match row delta")
    raw = os.pread(fd, slice_size, start_offset)
    if len(raw) != slice_size:
        raise AnalyzerError(f"DIAG-PROTO: short pread for {name}")
    if raw and observe_bytes is not None:
        observe_bytes(raw)
    return [
        raw[i * entry_size : (i + 1) * entry_size]
        for i in range(committed_rows - start_row)
    ]


def _read_diagnostic_streams_from_fds(
    row: DiagnosticCheckpoint,
    prev: DiagnosticCheckpoint | None,
    ctx_fd: int,
    rec_fd: int,
    jrn_fd: int,
    observe_context_bytes: Callable[[bytes], None] | None = None,
    observe_record_bytes: Callable[[bytes], None] | None = None,
    observe_journal_bytes: Callable[[bytes], None] | None = None,
) -> tuple[
    list[ClassifiedInput],
    list[Record],
    list[JournalEntry],
    dict[tuple[bytes, int], str],
    dict[str, int],
]:
    """Parse and validate one block's committed stream slices."""
    prev_ctx = prev.context_rows if prev is not None else 0
    prev_ctx_end = prev.context_end if prev is not None else HEADER_SIZE
    prev_rec = prev.record_rows if prev is not None else 0
    prev_rec_end = prev.record_end if prev is not None else HEADER_SIZE
    prev_jrn = prev.journal_rows if prev is not None else 0
    prev_jrn_end = prev.journal_end if prev is not None else HEADER_SIZE

    context_inputs = read_bounded_context_rows(
        ctx_fd,
        start_offset=prev_ctx_end,
        end_offset=row.context_end,
        start_row=prev_ctx,
        committed_rows=row.context_rows,
        observe_bytes=observe_context_bytes,
    )
    classified: list[ClassifiedInput] = []
    context_map: dict[tuple[bytes, int], str] = {}
    for inp in context_inputs:
        ci = classify_input(inp)
        key = (inp.identity.txid_le, inp.identity.input_index)
        if key in context_map:
            display_txid = inp.identity.txid_le[::-1].hex()
            raise AnalyzerError(
                f"CTX-EXECUTION: duplicate context execution identity "
                f"{display_txid}:{inp.identity.input_index}"
            )
        context_map[key] = ci.spend_context.value
        classified.append(ci)

    journal_raws = _read_fixed_entries_slice(
        jrn_fd,
        prev_jrn_end,
        row.journal_end,
        prev_jrn,
        row.journal_rows,
        JOURNAL_SIZE,
        "journal",
        observe_journal_bytes,
    )
    journal = [JournalEntry(raw) for raw in journal_raws]
    journal_keys: set[tuple[bytes, int]] = set()
    for entry in journal:
        if entry.verdict != 1:
            display_txid = entry.spend_txid[::-1].hex()
            raise AnalyzerError(
                f"CTX-EXECUTION: journal verdict {entry.verdict} != 1 for "
                f"{display_txid}:{entry.input_index}"
            )
        key = (entry.spend_txid, entry.input_index)
        if key in journal_keys:
            display_txid = entry.spend_txid[::-1].hex()
            raise AnalyzerError(
                f"CTX-EXECUTION: duplicate journal key in BRSJRN1: "
                f"{display_txid}:{entry.input_index}"
            )
        journal_keys.add(key)

    context_keys = set(context_map.keys())
    if context_keys != journal_keys:
        missing = journal_keys - context_keys
        extra = context_keys - journal_keys
        raise AnalyzerError(
            f"CTX-OPERATIONS: context/journal key-set mismatch: "
            f"missing={len(missing)} extra={len(extra)}"
        )

    record_raws = _read_fixed_entries_slice(
        rec_fd,
        prev_rec_end,
        row.record_end,
        prev_rec,
        row.record_rows,
        RECORD_SIZE,
        "records",
        observe_record_bytes,
    )
    records = [Record(raw) for raw in record_raws]
    record_counts, _ = _diagnostic_record_counts(records, context_map)

    record_sums: dict[tuple[bytes, int], list[int]] = {}
    for record in records:
        key = (record.spend_txid, record.input_index)
        sums = record_sums.setdefault(key, [0, 0])
        if record.sig_version in (0, 1) and record.op_kind in (1, 2, 3, 4):
            if record.outcome != 2:
                sums[0] += 1
            if record.outcome == 1:
                sums[1] += 1

    for entry in journal:
        actual_ecdsa = record_sums.get(entry.key, [0, 0])
        expected_ecdsa = [entry.ecdsa_verify_calls, entry.ecdsa_verify_ok]
        if actual_ecdsa != expected_ecdsa:
            display_txid = entry.spend_txid[::-1].hex()
            raise AnalyzerError(
                f"CTX-OPERATIONS: journal/record ECDSA totals mismatch for "
                f"{display_txid}:{entry.input_index}: "
                f"expected {expected_ecdsa}, got {actual_ecdsa}"
            )

    return classified, records, journal, context_map, record_counts


def _read_diagnostic_streams(
    row: DiagnosticCheckpoint,
    prev: DiagnosticCheckpoint | None,
    paths: dict[str, Path],
) -> tuple[
    list[ClassifiedInput],
    list[Record],
    list[JournalEntry],
    dict[tuple[bytes, int], str],
    dict[str, int],
]:
    """Open the evidence streams and parse one committed block."""
    ctx_fd = os.open(paths["contexts"], os.O_RDONLY)
    rec_fd = os.open(paths["records"], os.O_RDONLY)
    jrn_fd = os.open(paths["journal"], os.O_RDONLY)
    try:
        return _read_diagnostic_streams_from_fds(
            row, prev, ctx_fd, rec_fd, jrn_fd
        )
    finally:
        os.close(ctx_fd)
        os.close(rec_fd)
        os.close(jrn_fd)


def _validate_checkpoint_bounds(
    row: DiagnosticCheckpoint,
    prev: DiagnosticCheckpoint | None,
    file_sizes: dict[str, int],
) -> None:
    """Validate checkpoint ordering, framing, hashes, and committed endpoints."""
    if prev is None:
        if row.height != 0:
            raise AnalyzerError("DIAG-PROTO: first checkpoint row must have height 0")
        genesis_le = bytes.fromhex(MAINNET_GENESIS_HASH)[::-1]
        if row.block_hash_le != genesis_le:
            raise AnalyzerError("DIAG-PROTO: height 0 checkpoint hash is not mainnet genesis")
    else:
        if row.height != prev.height + 1:
            raise AnalyzerError(
                f"DIAG-PROTO: height {row.height} does not follow {prev.height}"
            )
        if row.block_hash_le == prev.block_hash_le:
            raise AnalyzerError(
                f"DIAG-PROTO: checkpoint hash repeated at height {row.height}"
            )

    if row.block_hash_le == bytes(32):
        raise AnalyzerError(f"DIAG-PROTO: zero block hash at height {row.height}")

    for name in ("context", "record", "journal"):
        end = getattr(row, f"{name}_end")
        count = getattr(row, f"{name}_rows")
        previous_end = getattr(prev, f"{name}_end", HEADER_SIZE) if prev else HEADER_SIZE
        previous_count = getattr(prev, f"{name}_rows", 0) if prev else 0
        if count < previous_count:
            raise AnalyzerError(
                f"DIAG-PROTO: {name}_rows decreased from {previous_count} to {count}"
            )
        if end < previous_end:
            raise AnalyzerError(
                f"DIAG-PROTO: {name}_end decreased from {previous_end} to {end}"
            )
        if end > file_sizes[name]:
            raise AnalyzerError(
                f"DIAG-PROTO: {name}_end {end} exceeds current file size {file_sizes[name]}"
            )

    expected_record_end = HEADER_SIZE + row.record_rows * RECORD_SIZE
    if row.record_end != expected_record_end:
        raise AnalyzerError(
            f"DIAG-PROTO: record_end {row.record_end} != {expected_record_end}"
        )
    expected_journal_end = HEADER_SIZE + row.journal_rows * JOURNAL_SIZE
    if row.journal_end != expected_journal_end:
        raise AnalyzerError(
            f"DIAG-PROTO: journal_end {row.journal_end} != {expected_journal_end}"
        )
    minimum_context_end = HEADER_SIZE + row.context_rows * CONTEXT_MIN_ROW_SIZE
    if row.context_end < minimum_context_end:
        raise AnalyzerError(
            f"DIAG-PROTO: context_end {row.context_end} is below minimum {minimum_context_end}"
        )


_ATOMIC_PUBLISH_COUNTER = 0


def _atomic_publish_no_replace(path: Path, content: bytes) -> None:
    """Fsync an exclusive sibling temp and hard-link it without replacement."""
    parent = path.parent if str(path.parent) else Path(".")
    parent.mkdir(parents=True, exist_ok=True)
    global _ATOMIC_PUBLISH_COUNTER
    _ATOMIC_PUBLISH_COUNTER += 1
    temp = parent / f".{path.name}.tmp.{os.getpid()}.{_ATOMIC_PUBLISH_COUNTER}"
    link_created = False
    dir_fd: int | None = None

    def _unlink_temp() -> None:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass

    try:
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written == 0:
                    raise AnalyzerError("DIAG-OUTPUT: zero-byte write to temporary file")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.link(temp, path)
        except FileExistsError as exc:
            raise AnalyzerError(f"DIAG-OUTPUT: output already exists: {path}") from exc
        except OSError as exc:
            raise AnalyzerError(
                f"DIAG-OUTPUT: atomic no-replace publication failed: {exc}"
            ) from exc
        link_created = True
        os.fsync(dir_fd)
        _unlink_temp()
        os.fsync(dir_fd)
    except BaseException as publish_error:
        rollback_error: BaseException | None = None
        if link_created:
            try:
                path.unlink()
                if dir_fd is None:
                    dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                os.fsync(dir_fd)
            except BaseException as exc:
                rollback_error = exc
        try:
            _unlink_temp()
        except BaseException as exc:
            if rollback_error is None:
                rollback_error = exc
        if rollback_error is not None:
            raise rollback_error from publish_error
        raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
        _unlink_temp()

    if not link_created:
        raise AnalyzerError("DIAG-OUTPUT: publication did not create a link")


def _write_json_atomic(path: Path, content: dict[str, object]) -> None:
    rendered = json.dumps(content, indent=2).encode("utf-8") + b"\n"
    _atomic_publish_no_replace(path, rendered)


def _close_stream(stream: BinaryIO | None) -> None:
    if stream is None or stream.closed:
        return
    try:
        stream.close()
    except OSError:
        return


def _reap_child(
    proc: subprocess.Popen, stderr_file: BinaryIO, *, timeout: float = 5.0
) -> None:
    """Close stdin, wait, kill only on timeout, then close remaining handles."""
    _close_stream(proc.stdin)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise AnalyzerError("DIAG-PROTO: child did not exit after kill") from exc
    finally:
        _close_stream(proc.stdout)
        _close_stream(proc.stderr)
        _close_stream(stderr_file)


def _launch_diagnostic_child(
    binary: Path,
    rest_url: str,
    ceiling: int,
    work_dir: Path,
    replay_json: Path,
    data_dir: Path,
    stderr_path: Path,
    counters_path: Path,
    storage_backend: str,
    txindex: bool,
) -> tuple[subprocess.Popen, BinaryIO]:
    env = os.environ.copy()
    env.update({
        "BRS_CENSUS_COUNTERS": str(counters_path),
        "BRS_CENSUS_CONTEXTS": str(work_dir / "brsctx1.bin"),
        "BRS_CENSUS_RECORDS": str(work_dir / "brsrec1.bin"),
        "BRS_CENSUS_JOURNAL": str(work_dir / "brsjrn1.bin"),
        "BRS_CENSUS_LABEL": "cmodern-diagnostic",
    })
    command = [
        str(binary),
        "--cmodern-diagnostic-protocol",
        "--rest-url", rest_url,
        "--start-height", "0",
        "--assume-valid-height", "0",
        "--window", "1",
        "--stop-height", str(ceiling),
        "--data-dir", str(data_dir),
        "--output", str(replay_json),
        "--storage-backend", storage_backend,
    ]
    if txindex:
        command.append("--txindex")

    stderr_file = stderr_path.open("xb")
    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            env=env,
            bufsize=0,
            close_fds=True,
        )
    except OSError as exc:
        stderr_file.close()
        raise AnalyzerError(f"DIAG-SETUP: failed to launch child: {exc}") from exc
    return proc, stderr_file


def _validate_replay_diagnostic(
    path: Path,
    final: DiagnosticCheckpoint,
    ceiling: int,
    storage_backend: str,
    txindex: bool,
    data_dir: str,
) -> None:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalyzerError(f"DIAG-CUSTODY: invalid child replay JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise AnalyzerError("DIAG-CUSTODY: child replay JSON root is not an object")

    expected_keys = {
        "schema",
        "non_certifying",
        "block_source",
        "start_height",
        "requested_stop_height_ceiling",
        "actual_stop_height",
        "actual_stop_hash",
        "window",
        "assume_valid_height",
        "stop_reason",
        "storage_backend",
        "txindex",
        "data_dir",
        "elapsed_seconds",
    }
    _require_exact_keys(raw, expected_keys, "child replay")

    if raw["schema"] != "mainnet-prefix-replay-diagnostic-v1":
        raise AnalyzerError(
            f"DIAG-CUSTODY: child replay schema {raw['schema']!r} "
            "!= 'mainnet-prefix-replay-diagnostic-v1'"
        )
    if raw["non_certifying"] is not True:
        raise AnalyzerError(
            f"DIAG-CUSTODY: child replay non_certifying {raw['non_certifying']!r} != True"
        )
    if raw["block_source"] != "rest":
        raise AnalyzerError(
            f"DIAG-CUSTODY: child replay block_source {raw['block_source']!r} != 'rest'"
        )
    start_height = _require_u32(raw["start_height"], "start_height")
    if start_height != 0:
        raise AnalyzerError(
            f"DIAG-CUSTODY: start_height {start_height} != 0"
        )
    requested = _require_u32(
        raw["requested_stop_height_ceiling"], "requested_stop_height_ceiling"
    )
    if requested != ceiling:
        raise AnalyzerError(
            f"DIAG-CUSTODY: requested_stop_height_ceiling {requested} != {ceiling}"
        )
    actual = _require_u32(raw["actual_stop_height"], "actual_stop_height")
    if actual != final.height:
        raise AnalyzerError(
            f"DIAG-CUSTODY: actual_stop_height {actual} != {final.height}"
        )
    actual_hash = _require_hex_str(raw["actual_stop_hash"], "actual_stop_hash", 64)
    expected_hash = final.block_hash_le[::-1].hex()
    if actual_hash != expected_hash:
        raise AnalyzerError(
            f"DIAG-CUSTODY: actual_stop_hash {actual_hash} != {expected_hash}"
        )
    window = _require_u32(raw["window"], "window")
    if window != 1:
        raise AnalyzerError(f"DIAG-CUSTODY: child replay window {window} != 1")
    assume = _require_u32(raw["assume_valid_height"], "assume_valid_height")
    if assume != 0:
        raise AnalyzerError(
            f"DIAG-CUSTODY: assume_valid_height {assume} != 0"
        )
    if raw["stop_reason"] != "controller-request":
        raise AnalyzerError(
            f"DIAG-CUSTODY: stop_reason {raw['stop_reason']!r} != 'controller-request'"
        )

    if raw["storage_backend"] != storage_backend:
        raise AnalyzerError(
            f"DIAG-CUSTODY: storage_backend {raw['storage_backend']!r} "
            f"!= {storage_backend!r}"
        )
    if raw["txindex"] is not txindex:
        raise AnalyzerError(
            f"DIAG-CUSTODY: txindex {raw['txindex']!r} != {txindex!r}"
        )
    if raw["data_dir"] != data_dir:
        raise AnalyzerError(
            f"DIAG-CUSTODY: data_dir {raw['data_dir']!r} != {data_dir!r}"
        )

    elapsed = raw["elapsed_seconds"]
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
        raise AnalyzerError(
            f"DIAG-CUSTODY: elapsed_seconds must be a finite non-negative number, got {elapsed!r}"
        )
    elapsed_f = float(elapsed)
    if math.isnan(elapsed_f) or math.isinf(elapsed_f):
        raise AnalyzerError(
            f"DIAG-CUSTODY: elapsed_seconds must be finite, got {elapsed!r}"
        )
    if elapsed_f < 0.0:
        raise AnalyzerError(
            f"DIAG-CUSTODY: elapsed_seconds must be non-negative, got {elapsed_f}"
        )

def _validate_native_counters(path: Path, final: DiagnosticCheckpoint) -> None:
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalyzerError(f"DIAG-CUSTODY: invalid counters JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise AnalyzerError("DIAG-CUSTODY: counters JSON root is not an object")
    counters = Counters(raw)
    expected = {
        "context_count": final.context_rows,
        "record_count": final.record_rows,
        "journal_count": final.journal_rows,
    }
    for field, value in expected.items():
        if getattr(counters, field) != value:
            raise AnalyzerError(
                f"DIAG-CUSTODY: counters {field} {getattr(counters, field)} != {value}"
            )


def _validate_terminal_streams(
    paths: dict[str, Path], final: DiagnosticCheckpoint
) -> dict[str, dict[str, object]]:
    custody: dict[str, dict[str, object]] = {}
    context_iter = iter_context_inputs(paths["contexts"])
    for _ in context_iter:
        continue
    context_custody = context_iter.custody()
    if context_custody["count"] != final.context_rows or context_custody["bytes"] != final.context_end:
        raise AnalyzerError("DIAG-CUSTODY: terminal context header/checkpoint mismatch")
    custody["contexts"] = {
        "path": str(paths["contexts"]),
        "bytes": context_custody["bytes"],
        "sha256": format(context_custody["sha256"], "064x"),
        "body_sha256": format(context_custody["body_sha256"], "064x"),
    }

    record_iter, record_custody = iter_records_with_custody(paths["records"])
    for _ in record_iter:
        continue
    record_count = (record_custody["bytes"] - HEADER_SIZE) // RECORD_SIZE
    if record_count != final.record_rows or record_custody["bytes"] != final.record_end:
        raise AnalyzerError("DIAG-CUSTODY: terminal record header/checkpoint mismatch")
    custody["records"] = {
        "path": str(paths["records"]),
        "bytes": record_custody["bytes"],
        "sha256": format(record_custody["sha256"], "064x"),
        "body_sha256": format(record_custody["body_sha256"], "064x"),
    }

    journal_iter, journal_custody = iter_journal_with_custody(paths["journal"])
    for _ in journal_iter:
        continue
    journal_count = (journal_custody["bytes"] - HEADER_SIZE) // JOURNAL_SIZE
    if journal_count != final.journal_rows or journal_custody["bytes"] != final.journal_end:
        raise AnalyzerError("DIAG-CUSTODY: terminal journal header/checkpoint mismatch")
    custody["journal"] = {
        "path": str(paths["journal"]),
        "bytes": journal_custody["bytes"],
        "sha256": format(journal_custody["sha256"], "064x"),
        "body_sha256": format(journal_custody["body_sha256"], "064x"),
    }

    sidecar_size = paths["sidecar"].stat().st_size
    # _validate_sidecar_terminal already validated framing; derive row count from size.
    sidecar_count = (sidecar_size - BRSHGT1_HEADER_STRUCT.size) // DIAGNOSTIC_ROW_SIZE
    sidecar_fd = os.open(paths["sidecar"], os.O_RDONLY)
    try:
        sidecar_header = os.pread(sidecar_fd, BRSHGT1_HEADER_STRUCT.size, 0)
        if len(sidecar_header) != BRSHGT1_HEADER_STRUCT.size:
            raise AnalyzerError("DIAG-CUSTODY: terminal sidecar short header")
        magic, _ = BRSHGT1_HEADER_STRUCT.unpack(sidecar_header)
        if magic != DIAGNOSTIC_MAGIC:
            raise AnalyzerError("DIAG-CUSTODY: terminal sidecar wrong magic")
        expected_size = BRSHGT1_HEADER_STRUCT.size + sidecar_count * DIAGNOSTIC_ROW_SIZE
        if sidecar_size != expected_size:
            raise AnalyzerError(
                f"DIAG-CUSTODY: terminal sidecar size {sidecar_size} != {expected_size}"
            )
        full_hasher = hashlib.sha256()
        body_hasher = hashlib.sha256()
        full_hasher.update(sidecar_header)
        offset = BRSHGT1_HEADER_STRUCT.size
        body_end = expected_size
        while offset < body_end:
            chunk = os.pread(sidecar_fd, min(8 * 1024 * 1024, body_end - offset), offset)
            if not chunk:
                raise AnalyzerError(f"DIAG-CUSTODY: terminal sidecar ended at {offset}")
            full_hasher.update(chunk)
            body_hasher.update(chunk)
            offset += len(chunk)
        custody["sidecar"] = {
            "path": str(paths["sidecar"]),
            "bytes": sidecar_size,
            "sha256": full_hasher.hexdigest(),
            "body_sha256": body_hasher.hexdigest(),
        }
    finally:
        os.close(sidecar_fd)
    return custody


def _validate_sidecar_terminal_fd(
    fd: int,
    row_count: int,
    final: DiagnosticCheckpoint,
) -> int:
    """Validate a complete sidecar through one retained descriptor."""
    if row_count < 1:
        raise AnalyzerError("DIAG-SIDECAR: sidecar has no checkpoint rows")
    header = os.pread(fd, BRSHGT1_HEADER_STRUCT.size, 0)
    if len(header) != BRSHGT1_HEADER_STRUCT.size:
        raise AnalyzerError("DIAG-SIDECAR: short header")
    magic, declared_count = BRSHGT1_HEADER_STRUCT.unpack(header)
    if magic != DIAGNOSTIC_MAGIC:
        raise AnalyzerError(f"DIAG-SIDECAR: wrong magic {magic!r}")
    expected_size = BRSHGT1_HEADER_STRUCT.size + row_count * DIAGNOSTIC_ROW_SIZE
    actual_size = os.fstat(fd).st_size
    if actual_size != expected_size:
        raise AnalyzerError(
            f"DIAG-SIDECAR: size {actual_size} != {expected_size}"
        )
    if declared_count not in (0, row_count):
        raise AnalyzerError(
            f"DIAG-SIDECAR: declared row count {declared_count} "
            f"is neither 0 nor {row_count}"
        )
    if _read_brshgt1_row(fd, row_count) != final:
        raise AnalyzerError("DIAG-SIDECAR: terminal row mismatch")
    return declared_count


def _validate_sidecar_terminal(
    path: Path,
    row_count: int,
    final: DiagnosticCheckpoint,
) -> int:
    """Validate a complete sidecar without changing its declared row count."""
    fd = os.open(path, os.O_RDONLY)
    try:
        return _validate_sidecar_terminal_fd(fd, row_count, final)
    finally:
        os.close(fd)


def _finalize_candidate(
    paths: dict[str, Path],
    sidecar_row_count: int,
    final: DiagnosticCheckpoint,
    cumulative_counts: dict[str, int],
    first_heights: dict[str, int],
    rest_url: str,
    ceiling: int,
    output_path: Path,
    storage_backend: str,
    txindex: bool,
    data_dir: str,
    teardown: DiagnosticTeardown,
    recovery_signatures: dict[str, tuple[int, int, int, int, int]] | None = None,
) -> None:
    """Validate terminal proof, finalize custody, then publish one candidate."""
    if recovery_signatures is not None:
        for name, signature in recovery_signatures.items():
            if _path_signature(paths[name]) != signature:
                raise AnalyzerError(
                    f"DIAG-SALVAGE: recovery {name} changed before validation"
                )
    declared_count = _validate_sidecar_terminal(
        paths["sidecar"], sidecar_row_count, final
    )
    if recovery_signatures is not None and declared_count != sidecar_row_count:
        raise AnalyzerError(
            f"DIAG-SALVAGE: recovered sidecar declared row count "
            f"{declared_count} != {sidecar_row_count}"
        )
    stream_custody = _validate_terminal_streams(paths, final)
    _validate_replay_diagnostic(
        paths["replay"],
        final,
        ceiling,
        storage_backend,
        txindex,
        data_dir,
    )
    _validate_native_counters(paths["counters"], final)
    if len(first_heights) != len(CONTEXT_COUNTER_NAMES):
        raise AnalyzerError("DIAG-CUSTODY: terminal proof lacks all 11 contexts")
    if max(first_heights.values()) != final.height:
        raise AnalyzerError(
            "DIAG-CUSTODY: terminal height does not equal the last first occurrence"
        )

    if declared_count == 0:
        _patch_brshgt1_count(paths["sidecar"], sidecar_row_count)
        sidecar_size, sidecar_sha256 = _sha256_file(paths["sidecar"])
        stream_custody["sidecar"]["bytes"] = sidecar_size
        stream_custody["sidecar"]["sha256"] = sidecar_sha256
    if _brshgt1_count(paths["sidecar"]) != sidecar_row_count:
        raise AnalyzerError("DIAG-SIDECAR: finalized row count mismatch")

    custody: dict[str, dict[str, object]] = {}
    custody["sidecar"] = stream_custody["sidecar"]
    for name in ("replay", "counters"):
        size, digest = _sha256_file(paths[name])
        custody[name] = {
            "path": str(paths[name]),
            "bytes": size,
            "sha256": digest,
        }
    finalized_recovery_signatures = {
        name: _path_signature(path) for name, path in paths.items()
    }
    source_custody = teardown.source_custody
    if source_custody is not None:
        source_custody = {
            name: dict(identity) for name, identity in source_custody.items()
        }
        for name, identity in source_custody.items():
            if not isinstance(identity.get("sha256"), str):
                raise AnalyzerError(
                    f"DIAG-SALVAGE: source {name} lacks full-file custody"
                )
            provenance = identity.get("clone_provenance")
            if provenance not in (CLONE_EXACT_FULL_FILE, CLONE_DIFFERS_FROM_SOURCE):
                raise AnalyzerError(
                    f"DIAG-SALVAGE: source {name} has invalid clone provenance"
                )
        for name in ("replay", "counters"):
            identity = source_custody[name]
            if identity["clone_provenance"] != CLONE_EXACT_FULL_FILE:
                raise AnalyzerError(
                    f"DIAG-SALVAGE: source {name} must be an exact full-file clone"
                )
            if (
                identity["bytes"] != custody[name]["bytes"]
                or identity["sha256"] != custody[name]["sha256"]
            ):
                raise AnalyzerError(
                    f"DIAG-SALVAGE: exact recovery {name} does not match source"
                )
        for name in ("contexts", "records", "journal", "sidecar"):
            identity = source_custody[name]
            source_body_sha256 = identity.get("committed_body_sha256")
            if not isinstance(source_body_sha256, str):
                raise AnalyzerError(
                    f"DIAG-SALVAGE: source {name} lacks committed-body custody"
                )
            if stream_custody[name]["body_sha256"] != source_body_sha256:
                raise AnalyzerError(
                    f"DIAG-SALVAGE: recovered {name} body does not match "
                    "the validated source committed body"
                )
            source_prefix_sha256 = identity.get("committed_prefix_sha256")
            if not isinstance(source_prefix_sha256, str):
                raise AnalyzerError(
                    f"DIAG-SALVAGE: source {name} lacks committed-prefix custody"
                )
            if (
                identity["clone_provenance"] == CLONE_EXACT_FULL_FILE
                and identity["sha256"] != source_prefix_sha256
            ):
                raise AnalyzerError(
                    f"DIAG-SALVAGE: exact source {name} clone has unequal hashes"
                )

    candidate: dict[str, object] = {
        "schema": "cmodern-candidate-diagnostic-v2",
        "non_certifying": True,
        "certifying_replay_required": True,
        "network": "mainnet",
        "block_source": "rest",
        "rest_url": rest_url,
        "start_height": 0,
        "assume_valid_height": 0,
        "window": 1,
        "stop_height_ceiling": ceiling,
        "earliest_defensible_height_h": final.height,
        "block_hash_h": final.block_hash_le[::-1].hex(),
        "first_occurrence_heights": {
            name: first_heights[name] for name in CONTEXT_COUNTER_NAMES
        },
        "context_counts": {
            name: cumulative_counts[name] for name in CONTEXT_COUNTER_NAMES
        },
        "context_counter_definitions": CONTEXT_COUNTER_DEFINITIONS,
        "final_stream_counts": {
            "context_rows": final.context_rows,
            "record_rows": final.record_rows,
            "journal_rows": final.journal_rows,
        },
        "final_stream_endpoints": {
            "context_end": final.context_end,
            "record_end": final.record_end,
            "journal_end": final.journal_end,
        },
        "child_exit_status": teardown.exit_status,
        "child_teardown": teardown.state,
        "salvaged_from": teardown.salvaged_from,
        "source_full_file_custody": source_custody,
        "child_replay_schema": "mainnet-prefix-replay-diagnostic-v1",
        "custody": {
            "brshgt1_sidecar": custody["sidecar"],
            "child_replay_json": custody["replay"],
            "counters_json": custody["counters"],
            "brsctx1": stream_custody["contexts"],
            "brsrec1": stream_custody["records"],
            "brsjrn1": stream_custody["journal"],
        },
    }
    if source_custody is not None:
        for identity in source_custody.values():
            source_path = Path(str(identity["path"]))
            if _path_signature(source_path) != (
                identity["device"],
                identity["inode"],
                identity["bytes"],
                identity["mtime_ns"],
                identity["ctime_ns"],
            ):
                raise AnalyzerError(
                    f"DIAG-SALVAGE: source changed before candidate publication: "
                    f"{source_path}"
                )
    candidate["rest_url_provenance"] = (
        "live_parent_argv"
        if teardown.salvaged_from is None
        else "operator_supplied_original_argv"
    )
    for name, signature in finalized_recovery_signatures.items():
        if _path_signature(paths[name]) != signature:
            raise AnalyzerError(
                f"DIAG-CUSTODY: {name} changed before candidate publication"
            )
    _write_json_atomic(output_path, candidate)


def _send_control(proc: subprocess.Popen, control: bytes) -> None:
    if proc.stdin is None:
        raise AnalyzerError("DIAG-SETUP: child stdin is not piped")
    try:
        proc.stdin.write(control)
        proc.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        raise AnalyzerError(f"DIAG-PROTO: failed to send control byte: {exc}") from exc
class _TrailingDrain:
    """Bounded state for draining child stdout concurrently with teardown."""

    def __init__(self) -> None:
        self.bytes_read = 0
        self.error: OSError | None = None

    def run(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                self.bytes_read += len(chunk)
        except OSError as exc:
            self.error = exc


def _await_child_after_terminal(
    proc: subprocess.Popen,
    *,
    stop_deadline_seconds: float,
    reap_deadline_seconds: float,
) -> DiagnosticTeardown:
    """Drain stdout while waiting so trailing output cannot deadlock the child."""
    if proc.stdout is None:
        raise AnalyzerError("DIAG-SETUP: child stdout is not piped")
    drain = _TrailingDrain()
    drain_thread = threading.Thread(
        target=drain.run,
        args=(proc.stdout,),
        name="cmodern-terminal-drain",
        daemon=True,
    )
    drain_thread.start()

    timed_out = False
    try:
        exit_status = proc.wait(timeout=stop_deadline_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        if proc.poll() is None:
            proc.kill()
        try:
            exit_status = proc.wait(timeout=reap_deadline_seconds)
        except subprocess.TimeoutExpired as exc:
            raise AnalyzerError(
                "DIAG-PROTO: child did not exit after terminal-proof kill"
            ) from exc

    drain_thread.join(timeout=reap_deadline_seconds)
    if drain_thread.is_alive():
        raise AnalyzerError("DIAG-PROTO: child stdout remained open after exit")
    if drain.error is not None:
        raise AnalyzerError(
            f"DIAG-PROTO: failed to drain child stdout: {drain.error}"
        ) from drain.error
    if drain.bytes_read != 0:
        raise AnalyzerError(
            f"DIAG-PROTO: {drain.bytes_read} trailing bytes after terminal checkpoint"
        )
    if not timed_out and exit_status != 0:
        raise AnalyzerError(
            f"DIAG-PROTO: child exited with status {exit_status}"
        )

    state = "timeout_after_terminal_proof" if timed_out else "clean"
    return DiagnosticTeardown(exit_status, state, None, None)




def _run_diagnostic_scan(
    binary: Path,
    rest_url: str,
    ceiling: int,
    work_dir: Path,
    output_path: Path,
    storage_backend: str = "fjall",
    txindex: bool = False,
    *,
    stop_deadline_seconds: float = 10.0,
    reap_deadline_seconds: float = 5.0,
) -> None:
    paths = {
        "contexts": work_dir / "brsctx1.bin",
        "records": work_dir / "brsrec1.bin",
        "journal": work_dir / "brsjrn1.bin",
        "sidecar": work_dir / "brshgt1.bin",
        "replay": work_dir / "replay_diagnostic.json",
        "stderr": work_dir / "stderr.log",
        "counters": work_dir / "counters.json",
    }
    data_dir = work_dir / "state"
    data_dir.mkdir(exist_ok=False)
    sidecar_fd: int | None = os.open(
        paths["sidecar"], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644
    )
    _write_brshgt1_preface(sidecar_fd)
    proc: subprocess.Popen | None = None
    stderr_file: BinaryIO | None = None
    child_closed = False
    try:
        proc, stderr_file = _launch_diagnostic_child(
            binary, rest_url, ceiling, work_dir, paths["replay"], data_dir,
            paths["stderr"], paths["counters"], storage_backend, txindex,
        )
        if proc.stdout is None:
            raise AnalyzerError("DIAG-SETUP: child stdout is not piped")
        _read_diagnostic_preface(proc.stdout)
        previous: DiagnosticCheckpoint | None = None
        cumulative_counts = {name: 0 for name in CONTEXT_COUNTER_NAMES}
        first_heights: dict[str, int] = {}
        row_count = 0

        while True:
            row = _read_checkpoint_row(proc.stdout)
            file_sizes = {
                "context": paths["contexts"].stat().st_size,
                "record": paths["records"].stat().st_size,
                "journal": paths["journal"].stat().st_size,
            }
            _validate_checkpoint_bounds(row, previous, file_sizes)
            classified, _records, _journal, _context_map, record_counts = (
                _read_diagnostic_streams(row, previous, paths)
            )
            block_counts = {
                **_diagnostic_spend_counts(classified),
                **record_counts,
            }
            _accumulate_block_counts(
                block_counts,
                row.height,
                cumulative_counts,
                first_heights,
            )

            _write_brshgt1_row(sidecar_fd, row)
            row_count += 1
            if len(first_heights) == len(CONTEXT_COUNTER_NAMES):
                expected_h = max(first_heights.values())
                if row.height != expected_h:
                    raise AnalyzerError(
                        f"DIAG-PROTO: current height {row.height} != derived H {expected_h}"
                    )
                _send_control(proc, b"\x01")
                break
            if row.height >= ceiling:
                raise AnalyzerError(
                    f"DIAG-PROTO: safety ceiling {ceiling} exhausted without all 11 types"
                )
            _send_control(proc, b"\x00")
            previous = row

        _close_stream(proc.stdin)
        teardown = _await_child_after_terminal(
            proc,
            stop_deadline_seconds=stop_deadline_seconds,
            reap_deadline_seconds=reap_deadline_seconds,
        )
        _close_stream(proc.stdout)
        _close_stream(proc.stderr)
        _close_stream(stderr_file)
        child_closed = True

        os.fsync(sidecar_fd)
        os.close(sidecar_fd)
        sidecar_fd = None
        _finalize_candidate(
            paths,
            row_count,
            row,
            cumulative_counts,
            first_heights,
            rest_url,
            ceiling,
            output_path,
            storage_backend,
            txindex,
            str(data_dir),
            teardown,
        )
    finally:
        if proc is not None and stderr_file is not None and not child_closed:
            _reap_child(proc, stderr_file)
        if sidecar_fd is not None:
            os.close(sidecar_fd)


def _diagnostic_artifact_paths(root: Path) -> dict[str, Path]:
    return {
        "contexts": root / "brsctx1.bin",
        "records": root / "brsrec1.bin",
        "journal": root / "brsjrn1.bin",
        "sidecar": root / "brshgt1.bin",
        "replay": root / "replay_diagnostic.json",
        "counters": root / "counters.json",
    }


def _source_sidecar_row_count(fd: int) -> int:
    """Validate sidecar framing and return its physical row count."""
    file_size = os.fstat(fd).st_size
    if file_size < BRSHGT1_HEADER_STRUCT.size:
        raise AnalyzerError("DIAG-SIDECAR: source sidecar is shorter than its header")
    payload_size = file_size - BRSHGT1_HEADER_STRUCT.size
    if payload_size % DIAGNOSTIC_ROW_SIZE != 0:
        raise AnalyzerError(
            f"DIAG-SIDECAR: source has {payload_size % DIAGNOSTIC_ROW_SIZE} "
            "bytes after its last complete row"
        )
    row_count = payload_size // DIAGNOSTIC_ROW_SIZE
    if row_count < 1:
        raise AnalyzerError("DIAG-SIDECAR: source sidecar has no rows")
    header = os.pread(fd, BRSHGT1_HEADER_STRUCT.size, 0)
    magic, declared_count = BRSHGT1_HEADER_STRUCT.unpack(header)
    if magic != DIAGNOSTIC_MAGIC:
        raise AnalyzerError(f"DIAG-SIDECAR: wrong source magic {magic!r}")
    if declared_count not in (0, row_count):
        raise AnalyzerError(
            f"DIAG-SIDECAR: source declares {declared_count} rows, "
            f"but contains {row_count}"
        )
    return row_count


def _reconstruct_diagnostic_from_fds(
    row_count: int,
    source_fds: dict[str, int],
) -> DiagnosticReconstruction:
    """Recompute aggregates and source hashes through one descriptor set."""
    cumulative_counts = {name: 0 for name in CONTEXT_COUNTER_NAMES}
    first_heights: dict[str, int] = {}
    previous: DiagnosticCheckpoint | None = None
    final: DiagnosticCheckpoint | None = None
    stream_file_sizes = {
        "contexts": os.fstat(source_fds["contexts"]).st_size,
        "records": os.fstat(source_fds["records"]).st_size,
        "journal": os.fstat(source_fds["journal"]).st_size,
    }
    checkpoint_file_sizes = {
        "context": stream_file_sizes["contexts"],
        "record": stream_file_sizes["records"],
        "journal": stream_file_sizes["journal"],
    }
    stream_hashers = {name: hashlib.sha256() for name in stream_file_sizes}
    stream_body_hashers = {name: hashlib.sha256() for name in stream_file_sizes}
    hashed_bytes = {name: HEADER_SIZE for name in stream_file_sizes}
    declared_counts: dict[str, int] = {}
    stream_magics = {
        "contexts": CONTEXT_MAGIC,
        "records": RECORD_MAGIC,
        "journal": JOURNAL_MAGIC,
    }
    for name, magic in stream_magics.items():
        header = os.pread(source_fds[name], HEADER_SIZE, 0)
        if len(header) != HEADER_SIZE:
            raise AnalyzerError(f"DIAG-SALVAGE: short source {name} header")
        actual_magic, declared_counts[name] = HEADER_STRUCT.unpack(header)
        if actual_magic != magic:
            raise AnalyzerError(
                f"DIAG-SALVAGE: wrong source {name} magic {actual_magic!r}"
            )
        stream_hashers[name].update(header)

    def observe_context(data: bytes) -> None:
        stream_hashers["contexts"].update(data)
        stream_body_hashers["contexts"].update(data)
        hashed_bytes["contexts"] += len(data)

    def observe_records(data: bytes) -> None:
        stream_hashers["records"].update(data)
        stream_body_hashers["records"].update(data)
        hashed_bytes["records"] += len(data)

    def observe_journal(data: bytes) -> None:
        stream_hashers["journal"].update(data)
        stream_body_hashers["journal"].update(data)
        hashed_bytes["journal"] += len(data)

    sidecar_full_hasher = hashlib.sha256()
    sidecar_body_hasher = hashlib.sha256()
    sidecar_header = os.pread(source_fds["sidecar"], BRSHGT1_HEADER_STRUCT.size, 0)
    if len(sidecar_header) != BRSHGT1_HEADER_STRUCT.size:
        raise AnalyzerError("DIAG-SALVAGE: short source sidecar header")
    sidecar_magic, _ = BRSHGT1_HEADER_STRUCT.unpack(sidecar_header)
    if sidecar_magic != DIAGNOSTIC_MAGIC:
        raise AnalyzerError(f"DIAG-SALVAGE: wrong source sidecar magic {sidecar_magic!r}")
    sidecar_full_hasher.update(sidecar_header)

    for row_number in range(1, row_count + 1):
        row_offset = BRSHGT1_HEADER_STRUCT.size + (row_number - 1) * DIAGNOSTIC_ROW_SIZE
        row_raw = os.pread(source_fds["sidecar"], DIAGNOSTIC_ROW_SIZE, row_offset)
        if len(row_raw) != DIAGNOSTIC_ROW_SIZE:
            raise AnalyzerError(f"DIAG-SIDECAR: short row {row_number}")
        sidecar_full_hasher.update(row_raw)
        sidecar_body_hasher.update(row_raw)
        row = BRSHGT1_ROW_STRUCT.unpack(row_raw)
        row = DiagnosticCheckpoint(*row)
        _validate_checkpoint_bounds(row, previous, checkpoint_file_sizes)
        classified, records, journal, context_map, record_counts = (
            _read_diagnostic_streams_from_fds(
                row,
                previous,
                source_fds["contexts"],
                source_fds["records"],
                source_fds["journal"],
                observe_context,
                observe_records,
                observe_journal,
            )
        )
        block_counts = {
            **_diagnostic_spend_counts(classified),
            **record_counts,
        }
        _accumulate_block_counts(
            block_counts,
            row.height,
            cumulative_counts,
            first_heights,
        )
        previous = row
        final = row

    if final is None:
        raise AnalyzerError("DIAG-SALVAGE: source contains no terminal row")
    _validate_sidecar_terminal_fd(source_fds["sidecar"], row_count, final)
    if len(first_heights) != len(CONTEXT_COUNTER_NAMES):
        raise AnalyzerError(
            "DIAG-SALVAGE: terminal proof does not contain all 11 contexts"
        )
    if max(first_heights.values()) != final.height:
        raise AnalyzerError(
            "DIAG-SALVAGE: terminal height is not the last first occurrence"
        )

    expected_counts = {
        "contexts": final.context_rows,
        "records": final.record_rows,
        "journal": final.journal_rows,
    }
    committed_ends = {
        "contexts": final.context_end,
        "records": final.record_end,
        "journal": final.journal_end,
    }
    source_stream_digests: dict[str, DiagnosticStreamDigests] = {}
    for name, committed_end in committed_ends.items():
        if declared_counts[name] not in (0, expected_counts[name]):
            raise AnalyzerError(
                f"DIAG-SALVAGE: source {name} declares {declared_counts[name]} "
                f"rows, expected 0 or {expected_counts[name]}"
            )
        if hashed_bytes[name] != committed_end:
            raise AnalyzerError(
                f"DIAG-SALVAGE: hashed {hashed_bytes[name]} committed {name} "
                f"bytes, expected {committed_end}"
            )
        committed_sha256 = stream_hashers[name].copy().hexdigest()
        committed_body_sha256 = stream_body_hashers[name].hexdigest()
        offset = committed_end
        while offset < stream_file_sizes[name]:
            chunk = os.pread(
                source_fds[name],
                min(8 * 1024 * 1024, stream_file_sizes[name] - offset),
                offset,
            )
            if not chunk:
                raise AnalyzerError(
                    f"DIAG-SALVAGE: source {name} ended at {offset}, "
                    f"expected {stream_file_sizes[name]}"
                )
            stream_hashers[name].update(chunk)
            offset += len(chunk)
        source_stream_digests[name] = DiagnosticStreamDigests(
            stream_hashers[name].hexdigest(),
            committed_sha256,
            committed_body_sha256,
        )

    # Sidecar body is the committed rows after the header.
    sidecar_size = os.fstat(source_fds["sidecar"]).st_size
    # Prefix hash is the state after header + committed rows, before tail.
    sidecar_prefix_hasher = sidecar_full_hasher.copy()
    tail_offset = BRSHGT1_HEADER_STRUCT.size + row_count * DIAGNOSTIC_ROW_SIZE
    while tail_offset < sidecar_size:
        chunk = os.pread(
            source_fds["sidecar"],
            min(8 * 1024 * 1024, sidecar_size - tail_offset),
            tail_offset,
        )
        if not chunk:
            raise AnalyzerError(
                f"DIAG-SALVAGE: sidecar ended at {tail_offset}, expected {sidecar_size}"
            )
        sidecar_full_hasher.update(chunk)
        tail_offset += len(chunk)
    source_stream_digests["sidecar"] = DiagnosticStreamDigests(
        sidecar_full_hasher.hexdigest(),
        sidecar_prefix_hasher.hexdigest(),
        sidecar_body_hasher.hexdigest(),
    )

    return DiagnosticReconstruction(
        row_count,
        final,
        cumulative_counts,
        first_heights,
        source_stream_digests,
    )




def _write_all(fd: int, data: bytes | memoryview) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise AnalyzerError("DIAG-SALVAGE: short recovery write")
        view = view[written:]


FICLONE = 0x40049409
CLONE_EXACT_FULL_FILE = "EXACT_FULL_FILE"
CLONE_DIFFERS_FROM_SOURCE = "DIFFERS_FROM_SOURCE"


def _fd_signature(fd: int) -> tuple[int, int, int, int, int]:
    stat_result = os.fstat(fd)
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    )
def _sha256_fd(fd: int) -> str:
    """Hash one retained descriptor without changing its file position."""
    digest = hashlib.sha256()
    size = os.fstat(fd).st_size
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(8 * 1024 * 1024, size - offset), offset)
        if not chunk:
            raise AnalyzerError(
                f"DIAG-SALVAGE: source ended at {offset}, expected {size}"
            )
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()




def _path_signature(path: Path) -> tuple[int, int, int, int, int]:
    stat_result = path.stat()
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    )


def _copy_fd_fallback(source_fd: int, destination_fd: int, size: int) -> None:
    """Copy one file when the filesystem cannot clone extents."""
    offset = 0
    while offset < size:
        chunk = os.pread(source_fd, min(8 * 1024 * 1024, size - offset), offset)
        if not chunk:
            raise AnalyzerError(
                f"DIAG-SALVAGE: source ended at {offset}, expected {size}"
            )
        _write_all(destination_fd, chunk)
        offset += len(chunk)


def _clone_committed_source(
    source_fd: int,
    source: Path,
    destination: Path,
    committed_size: int,
    *,
    replacement_header: bytes | None = None,
    source_sha256: str | None = None,
    source_committed_prefix_sha256: str | None = None,
    source_committed_body_sha256: str | None = None,
) -> dict[str, object]:
    """Clone one retained source file, then normalize and cut the clone."""
    before = os.fstat(source_fd)
    if not (0 <= committed_size <= before.st_size):
        raise AnalyzerError(
            f"DIAG-SALVAGE: committed size {committed_size} exceeds "
            f"{source} size {before.st_size}"
        )
    source_header: bytes | None = None
    if replacement_header is not None:
        if len(replacement_header) > committed_size:
            raise AnalyzerError(
                "DIAG-SALVAGE: replacement header exceeds committed source"
            )
        source_header = os.pread(source_fd, len(replacement_header), 0)
        if len(source_header) != len(replacement_header):
            raise AnalyzerError(f"DIAG-SALVAGE: short source header: {source}")

    source_digest = (
        source_sha256 if source_sha256 is not None else _sha256_fd(source_fd)
    )
    if committed_size == before.st_size and source_committed_prefix_sha256 is not None:
        if source_committed_prefix_sha256 != source_digest:
            raise AnalyzerError(
                f"DIAG-SALVAGE: source committed-prefix digest mismatch: {source}"
            )
    if _fd_signature(source_fd) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ):
        raise AnalyzerError(f"DIAG-SALVAGE: source changed before cloning: {source}")

    identity: dict[str, object] = {
        "path": str(source),
        "device": before.st_dev,
        "inode": before.st_ino,
        "bytes": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": source_digest,
        "clone_provenance": (
            CLONE_EXACT_FULL_FILE
            if committed_size == before.st_size
            and (replacement_header is None or replacement_header == source_header)
            else CLONE_DIFFERS_FROM_SOURCE
        ),
    }
    if source_committed_prefix_sha256 is not None:
        identity["committed_prefix_sha256"] = source_committed_prefix_sha256
    if source_committed_body_sha256 is not None:
        identity["committed_body_sha256"] = source_committed_body_sha256
    if replacement_header is not None:
        assert source_header is not None
        identity["source_header_hex"] = source_header.hex()
        identity["recovery_header_hex"] = replacement_header.hex()

    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o644,
    )
    try:
        try:
            fcntl.ioctl(destination_fd, FICLONE, source_fd)
        except OSError as exc:
            if exc.errno not in (
                errno.EXDEV,
                errno.EINVAL,
                errno.ENOTTY,
                errno.EOPNOTSUPP,
            ):
                raise
            _copy_fd_fallback(source_fd, destination_fd, committed_size)
        os.ftruncate(destination_fd, committed_size)
        if replacement_header is not None:
            if os.pwrite(destination_fd, replacement_header, 0) != len(
                replacement_header
            ):
                raise AnalyzerError("DIAG-SALVAGE: short recovery header write")
        os.fsync(destination_fd)
        if _fd_signature(source_fd) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise AnalyzerError(
                f"DIAG-SALVAGE: source changed while cloning: {source}"
            )
        return identity
    finally:
        os.close(destination_fd)


def _verify_retained_files(
    paths: dict[str, Path],
    descriptors: dict[str, int],
    signatures: dict[str, tuple[int, int, int, int, int]],
    phase: str,
) -> None:
    for name, descriptor in descriptors.items():
        if (
            _fd_signature(descriptor) != signatures[name]
            or _path_signature(paths[name]) != signatures[name]
        ):
            raise AnalyzerError(f"DIAG-SALVAGE: {phase}: {paths[name]}")


def _mkdir_exclusive_durable(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    if not cursor.is_dir():
        raise AnalyzerError(
            f"DIAG-SETUP: recovery ancestor is not a directory: {cursor}"
        )
    for directory in reversed(missing):
        directory.mkdir()
        parent_fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


def _materialize_recovery_dir(
    source_paths: dict[str, Path],
    source_fds: dict[str, int],
    recovery_dir: Path,
    reconstruction: DiagnosticReconstruction,
) -> tuple[
    dict[str, Path],
    dict[str, dict[str, object]],
    dict[str, tuple[int, int, int, int, int]],
]:
    """Clone only checkpoint-committed evidence into a new directory."""
    _mkdir_exclusive_durable(recovery_dir)
    recovery_paths = _diagnostic_artifact_paths(recovery_dir)
    final = reconstruction.final
    source_custody: dict[str, dict[str, object]] = {}
    copy_specs = (
        ("contexts", final.context_end, HEADER_STRUCT.pack(CONTEXT_MAGIC, final.context_rows)),
        ("records", final.record_end, HEADER_STRUCT.pack(RECORD_MAGIC, final.record_rows)),
        ("journal", final.journal_end, HEADER_STRUCT.pack(JOURNAL_MAGIC, final.journal_rows)),
        (
            "sidecar",
            BRSHGT1_HEADER_STRUCT.size
            + reconstruction.row_count * DIAGNOSTIC_ROW_SIZE,
            BRSHGT1_HEADER_STRUCT.pack(DIAGNOSTIC_MAGIC, reconstruction.row_count),
        ),
    )
    recovery_signatures: dict[str, tuple[int, int, int, int, int]] = {}
    for name, committed_size, replacement_header in copy_specs:
        stream_digests = reconstruction.source_stream_digests.get(name)
        identity = _clone_committed_source(
            source_fds[name],
            source_paths[name],
            recovery_paths[name],
            committed_size,
            replacement_header=replacement_header,
            source_sha256=(
                stream_digests.full_file_sha256
                if stream_digests is not None
                else None
            ),
            source_committed_prefix_sha256=(
                stream_digests.committed_prefix_sha256
                if stream_digests is not None
                else None
            ),
            source_committed_body_sha256=(
                stream_digests.committed_body_sha256
                if stream_digests is not None
                else None
            ),
        )
        source_custody[name] = identity
        recovery_signatures[name] = _path_signature(recovery_paths[name])
    for name in ("replay", "counters"):
        source_custody[name] = _clone_committed_source(
            source_fds[name],
            source_paths[name],
            recovery_paths[name],
            os.fstat(source_fds[name]).st_size,
        )
        recovery_signatures[name] = _path_signature(recovery_paths[name])
    dir_fd = os.open(recovery_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return recovery_paths, source_custody, recovery_signatures


def _salvage_diagnostic_scan(
    source_dir: Path,
    recovery_dir: Path,
    output_path: Path,
    rest_url: str,
    ceiling: int,
    data_dir: str,
    storage_backend: str = "fjall",
    txindex: bool = False,
) -> None:
    """Recover terminal proof without changing the failed source directory."""
    source_dir = source_dir.resolve()
    recovery_dir = recovery_dir.resolve()
    output_path = output_path.resolve()
    # Preserve the operator's exact provenance string for replay comparison.
    if not source_dir.is_dir():
        raise AnalyzerError(f"DIAG-SETUP: source directory not found: {source_dir}")
    if recovery_dir.exists():
        raise AnalyzerError(
            f"DIAG-SETUP: recovery directory already exists: {recovery_dir}"
        )
    if output_path.exists():
        raise AnalyzerError(f"DIAG-SETUP: output already exists: {output_path}")
    if source_dir == recovery_dir or source_dir in recovery_dir.parents:
        raise AnalyzerError("DIAG-SETUP: recovery directory must be outside source")
    if source_dir == output_path.parent or source_dir in output_path.parents:
        raise AnalyzerError("DIAG-SETUP: output must be outside source")

    source_paths = _diagnostic_artifact_paths(source_dir)
    source_fds: dict[str, int] = {}
    source_signatures: dict[str, tuple[int, int, int, int, int]] = {}
    recovery_fds: dict[str, int] = {}
    succeeded = False
    try:
        for name, path in source_paths.items():
            source_fds[name] = os.open(path, os.O_RDONLY)
            source_signatures[name] = _fd_signature(source_fds[name])
        row_count = _source_sidecar_row_count(source_fds["sidecar"])
        source_reconstruction = _reconstruct_diagnostic_from_fds(
            row_count,
            source_fds,
        )
        _verify_retained_files(
            source_paths,
            source_fds,
            source_signatures,
            "source changed during reconstruction",
        )
        recovery_paths, source_custody, recovery_signatures = (
            _materialize_recovery_dir(
                source_paths,
                source_fds,
                recovery_dir,
                source_reconstruction,
            )
        )
        _verify_retained_files(
            source_paths,
            source_fds,
            source_signatures,
            "source changed during materialization",
        )
        for name, path in recovery_paths.items():
            recovery_fds[name] = os.open(path, os.O_RDONLY)
        _verify_retained_files(
            recovery_paths,
            recovery_fds,
            recovery_signatures,
            "recovery changed during materialization",
        )
        teardown = DiagnosticTeardown(
            None,
            "unobserved",
            str(source_dir),
            source_custody,
        )
        _finalize_candidate(
            recovery_paths,
            source_reconstruction.row_count,
            source_reconstruction.final,
            source_reconstruction.cumulative_counts,
            source_reconstruction.first_heights,
            rest_url,
            ceiling,
            output_path,
            storage_backend,
            txindex,
            data_dir,
            teardown,
            recovery_signatures,
        )
        try:
            _verify_retained_files(
                source_paths,
                source_fds,
                source_signatures,
                "source changed after candidate publication",
            )
            _verify_retained_files(
                recovery_paths,
                recovery_fds,
                recovery_signatures,
                "recovery changed after candidate publication",
            )
        except BaseException as custody_error:
            try:
                try:
                    output_path.unlink()
                except FileNotFoundError:
                    # The candidate is already absent; fsync its parent below.
                    pass
                parent_fd = os.open(
                    output_path.parent, os.O_RDONLY | os.O_DIRECTORY
                )
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            except OSError as rollback_error:
                raise rollback_error from custody_error
            raise
        succeeded = True
    finally:
        for fd in recovery_fds.values():
            os.close(fd)
        for fd in source_fds.values():
            os.close(fd)
        if recovery_dir.exists() and not succeeded:
            shutil.rmtree(recovery_dir)


def cmd_salvage_cmodern_height(args: argparse.Namespace) -> int:
    _salvage_diagnostic_scan(
        Path(args.source_dir),
        Path(args.recovery_dir),
        Path(args.output),
        args.rest_url,
        args.stop_height,
        args.data_dir,
        storage_backend=args.storage_backend,
        txindex=args.txindex,
    )
    return 0


def cmd_find_cmodern_height(args: argparse.Namespace) -> int:
    binary = Path(args.binary)
    work_dir = Path(args.work_dir)
    output = Path(args.output)
    if not binary.is_file():
        raise AnalyzerError(f"DIAG-SETUP: binary not found: {binary}")
    if not args.rest_url or ":" not in args.rest_url:
        raise AnalyzerError(
            f"DIAG-SETUP: invalid rest_url {args.rest_url!r}; expected host:port"
        )
    if not (0 <= args.stop_height <= 0xFFFFFFFF):
        raise AnalyzerError(
            f"DIAG-SETUP: stop-height must be a u32, got {args.stop_height}"
        )
    if work_dir.exists():
        raise AnalyzerError(f"DIAG-SETUP: work directory already exists: {work_dir}")
    if output.exists():
        raise AnalyzerError(f"DIAG-SETUP: output already exists: {output}")
    work_dir.mkdir(parents=True, exist_ok=False)
    _run_diagnostic_scan(
        binary,
        args.rest_url,
        args.stop_height,
        work_dir,
        output,
        storage_backend=args.storage_backend,
        txindex=args.txindex,
    )
    return 0

# ── Binary parsing ──────────────────────────────────────────────────────────


def read_raw_entries(
    path: Path, magic: bytes, entry_size: int, name: str
) -> list[bytes]:
    """Read a binary file with magic + u64 count header, return raw entry bytes."""
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise AnalyzerError(
            f"{path}: file too short ({len(data)} bytes < {HEADER_SIZE} header)"
        )
    file_magic, count = HEADER_STRUCT.unpack_from(data, 0)
    if file_magic != magic:
        raise AnalyzerError(f"{path}: bad magic {file_magic!r}, expected {magic!r}")
    expected = HEADER_SIZE + count * entry_size
    if len(data) != expected:
        raise AnalyzerError(
            f"{path}: size mismatch (got {len(data)}, expected {expected} "
            f"= {HEADER_SIZE} + {count} × {entry_size} {name})"
        )
    return [
        data[HEADER_SIZE + i * entry_size : HEADER_SIZE + (i + 1) * entry_size]
        for i in range(count)
    ]


def parse_records(path: Path) -> list[Record]:
    raws = read_raw_entries(path, RECORD_MAGIC, RECORD_SIZE, "records")
    return [Record(r) for r in raws]


def parse_journal(path: Path) -> list[JournalEntry]:
    raws = read_raw_entries(path, JOURNAL_MAGIC, JOURNAL_SIZE, "journal entries")
    return [JournalEntry(r) for r in raws]


def _iter_binary_entries(
    path: Path, magic: bytes, entry_size: int, name: str
) -> Iterator[tuple[int, bytes]]:
    """Stream fixed-size entries from a magic+u64-count binary file.

    Yields ``(index, raw_bytes)`` pairs without loading the whole file.
    Raises ``AnalyzerError`` on short reads, bad magic, or size mismatch.
    """
    file_size = path.stat().st_size
    if file_size < HEADER_SIZE:
        raise AnalyzerError(
            f"{name}: file too short ({file_size} bytes < {HEADER_SIZE} header)"
        )
    with path.open("rb") as stream:
        header = _read_exact_bytes(stream, HEADER_SIZE, f"{name} header")
        file_magic, count = HEADER_STRUCT.unpack(header)
        if file_magic != magic:
            raise AnalyzerError(
                f"{name}: bad magic {file_magic!r}, expected {magic!r}"
            )
        expected_payload = count * entry_size
        available = file_size - HEADER_SIZE
        if available < expected_payload:
            raise AnalyzerError(
                f"{name}: declared {count} entries need {expected_payload} bytes "
                f"but only {available} remain after header"
            )
        for index in range(count):
            raw = _read_exact_bytes(stream, entry_size, f"{name} entry {index}")
            yield index, raw
        trailing = stream.read(1)
        if trailing:
            raise AnalyzerError(
                f"{name}: {len(trailing)} trailing byte(s) after declared entries"
            )


def _read_exact_bytes(stream: BinaryIO, length: int, field: str, scope: str = "") -> bytes:
    """Read exactly *length* bytes from *stream* or raise AnalyzerError."""
    data = stream.read(length)
    if data is None or len(data) < length:
        prefix = f"{scope}: " if scope else ""
        raise AnalyzerError(f"{prefix}{field}: short read (expected {length} bytes)")
    return data


def iter_records(path: Path) -> Iterator[Record]:
    """Stream BRSREC1 records one at a time without materializing the file."""
    for _index, raw in _iter_binary_entries(
        path, RECORD_MAGIC, RECORD_SIZE, "records"
    ):
        yield Record(raw)


def _iter_binary_entries_with_custody(
    path: Path, magic: bytes, entry_size: int, name: str
) -> tuple[Iterator[tuple[int, bytes]], dict[str, int]]:
    """Stream fixed-size entries and compute custody (size + sha256) on the
    exact single open used for parsing.  Returns ``(iterator, custody)``
    where *custody* is populated once the iterator is fully consumed.
    """
    file_size = path.stat().st_size
    if file_size < HEADER_SIZE:
        raise AnalyzerError(
            f"{name}: file too short ({file_size} bytes < {HEADER_SIZE} header)"
        )
    custody: dict[str, int] = {"bytes": 0, "sha256": 0, "body_sha256": 0}
    stream = path.open("rb")
    running_hash = hashlib.sha256()
    body_hash = hashlib.sha256()
    try:
        header = _read_exact_bytes(stream, HEADER_SIZE, f"{name} header")
        running_hash.update(header)
        file_magic, count = HEADER_STRUCT.unpack(header)
        if file_magic != magic:
            raise AnalyzerError(
                f"{name}: bad magic {file_magic!r}, expected {magic!r}"
            )
        expected_payload = count * entry_size
        available = file_size - HEADER_SIZE
        if available < expected_payload:
            raise AnalyzerError(
                f"{name}: declared {count} entries need {expected_payload} bytes "
                f"but only {available} remain after header"
            )

        def _gen() -> Iterator[tuple[int, bytes]]:
            try:
                for index in range(count):
                    raw = _read_exact_bytes(stream, entry_size, f"{name} entry {index}")
                    running_hash.update(raw)
                    body_hash.update(raw)
                    yield index, raw
                trailing = stream.read(1)
                if trailing:
                    raise AnalyzerError(
                        f"{name}: {len(trailing)} trailing byte(s) after declared entries"
                    )
                custody["bytes"] = file_size
                custody["sha256"] = int(running_hash.hexdigest(), 16)
                custody["body_sha256"] = int(body_hash.hexdigest(), 16)
            finally:
                stream.close()

        return _gen(), custody
    except BaseException:
        stream.close()
        raise


def iter_records_with_custody(
    path: Path
) -> tuple[Iterator[Record], dict[str, int]]:
    """Stream BRSREC1 records and compute custody on the single open."""
    gen, custody = _iter_binary_entries_with_custody(
        path, RECORD_MAGIC, RECORD_SIZE, "records"
    )
    return ((Record(raw) for _idx, raw in gen), custody)


def iter_journal_with_custody(
    path: Path
) -> tuple[Iterator[JournalEntry], dict[str, int]]:
    """Stream BRSJRN1 journal entries and compute custody on the single open."""
    gen, custody = _iter_binary_entries_with_custody(
        path, JOURNAL_MAGIC, JOURNAL_SIZE, "journal entries"
    )
    return ((JournalEntry(raw) for _idx, raw in gen), custody)

def iter_journal(path: Path) -> Iterator[JournalEntry]:
    """Stream BRSJRN1 journal entries one at a time without materializing the file."""
    for _index, raw in _iter_binary_entries(
        path, JOURNAL_MAGIC, JOURNAL_SIZE, "journal entries"
    ):
        yield JournalEntry(raw)
def parse_counters(path: Path) -> tuple[Counters, dict[str, int]]:
    """Parse counters JSON and return (Counters, custody) from the single read."""
    counters_bytes = path.read_bytes()
    raw = json.loads(counters_bytes)
    if not isinstance(raw, dict):
        raise AnalyzerError(f"{path}: JSON root is not an object")
    if raw.get("schema") != 1:
        raise AnalyzerError(f"{path}: schema is {raw.get('schema')}, expected 1")
    custody = {
        "bytes": len(counters_bytes),
        "sha256": int(hashlib.sha256(counters_bytes).hexdigest(), 16),
    }
    return Counters(raw), custody


# ── Sorting and hashing ─────────────────────────────────────────────────────


def sort_records_raw(raw_entries: list[bytes]) -> bytes:
    """Sort raw record bytes by (spend_txid, input_index, op_seq), concatenate."""

    def key(raw: bytes) -> tuple[bytes, int, int]:
        txid = raw[0:32]
        input_index = struct.unpack_from("<I", raw, 32)[0]
        op_seq = struct.unpack_from("<I", raw, 36)[0]
        return (txid, input_index, op_seq)

    return b"".join(sorted(raw_entries, key=key))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> tuple[int, str]:
    """Return (size in bytes, lowercase hex sha256) for a file."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


# ── Invariant checks ────────────────────────────────────────────────────────


def check_counter_arithmetic(c: Counters) -> list[dict[str, object]]:
    """INV-1 through INV-7."""
    results: list[dict[str, object]] = []

    def inv(inv_id: str, passed: bool, statement: str, **extra: object) -> None:
        entry: dict[str, object] = {"id": inv_id, "passed": passed, "statement": statement}
        entry.update(extra)
        results.append(entry)

    inv(
        "INV-1",
        c.verify_script_calls == c.ffi_verify_entries,
        "C_VERIFY_SCRIPT_CALLS == C_FFI_VERIFY_ENTRIES",
        expected=c.ffi_verify_entries,
        actual=c.verify_script_calls,
    )
    inv(
        "INV-2",
        c.ffi_verify_true == c.ffi_verify_entries,
        "C_FFI_VERIFY_TRUE == C_FFI_VERIFY_ENTRIES",
        expected=c.ffi_verify_entries,
        actual=c.ffi_verify_true,
    )
    inv(
        "INV-3",
        c.checkecdsa_entries == c.ecdsa_from_checksig + c.ecdsa_from_checkmultisig,
        "C_CHECKECDSA_ENTRIES == C_ECDSA_FROM_CHECKSIG + C_ECDSA_FROM_CHECKMULTISIG",
        expected=c.ecdsa_from_checksig + c.ecdsa_from_checkmultisig,
        actual=c.checkecdsa_entries,
    )
    rejects = (
        c.checkecdsa_reject_pubkey
        + c.checkecdsa_reject_empty_sig
        + c.checkecdsa_reject_missing_data
    )
    inv(
        "INV-4",
        c.checkecdsa_entries == c.ecdsa_verify_calls + rejects,
        "C_CHECKECDSA_ENTRIES == C_ECDSA_VERIFY_CALLS + rejects",
        expected=c.ecdsa_verify_calls + rejects,
        actual=c.checkecdsa_entries,
    )
    inv(
        "INV-5",
        c.ecdsa_verify_calls == c.ecdsa_verify_ok + c.ecdsa_verify_fail
        and c.ecdsa_verify_calls == c.sighash_computed,
        "C_ECDSA_VERIFY_CALLS == C_ECDSA_VERIFY_OK + C_ECDSA_VERIFY_FAIL and == C_SIGHASH_COMPUTED",
        ok_plus_fail=c.ecdsa_verify_ok + c.ecdsa_verify_fail,
        sighash_computed=c.sighash_computed,
        ecdsa_verify_calls=c.ecdsa_verify_calls,
    )
    inv(
        "INV-6",
        c.ecdsa_from_checksig <= c.op_checksig + c.op_checksigverify
        and c.ecdsa_from_checkmultisig
        <= 20 * (c.op_checkmultisig + c.op_checkmultisigverify),
        "C_ECDSA_FROM_CHECKSIG <= C_OP_CHECKSIG + C_OP_CHECKSIGVERIFY; "
        "C_ECDSA_FROM_CHECKMULTISIG <= 20 * (C_OP_CHECKMULTISIG + C_OP_CHECKMULTISIGVERIFY)",
        from_checksig=c.ecdsa_from_checksig,
        checksig_plus_verify=c.op_checksig + c.op_checksigverify,
        from_checkmultisig=c.ecdsa_from_checkmultisig,
        twenty_multisig=20 * (c.op_checkmultisig + c.op_checkmultisigverify),
    )
    inv(
        "INV-7",
        c.checkschnorr_entries >= c.schnorr_verify_calls
        and c.schnorr_verify_calls == c.schnorr_verify_ok + c.schnorr_verify_fail,
        "C_CHECKSCHNORR_ENTRIES >= C_SCHNORR_VERIFY_CALLS and "
        "C_SCHNORR_VERIFY_CALLS == C_SCHNORR_VERIFY_OK + C_SCHNORR_VERIFY_FAIL",
        checkschnorr_entries=c.checkschnorr_entries,
        schnorr_verify_calls=c.schnorr_verify_calls,
        schnorr_ok_plus_fail=c.schnorr_verify_ok + c.schnorr_verify_fail,
    )
    return results


def _check_pre_taproot_schnorr_absence(c: Counters) -> dict[str, object]:
    """Keep the legacy KSPIKE1 capture contract pre-Taproot."""
    counters = {
        "op_checksigadd": c.op_checksigadd,
        "checkschnorr_entries": c.checkschnorr_entries,
        "schnorr_verify_calls": c.schnorr_verify_calls,
        "schnorr_verify_ok": c.schnorr_verify_ok,
        "schnorr_verify_fail": c.schnorr_verify_fail,
    }
    return {
        "id": "INV-KSPIKE-SCHNORR-0",
        "passed": all(value == 0 for value in counters.values()),
        "statement": "legacy KSPIKE1 Schnorr and OP_CHECKSIGADD counters are zero",
        **counters,
    }


def check_record_counts(records: list[Record], c: Counters) -> dict[str, object]:
    """INV-9: record count reconciliation."""
    outcome_01 = sum(1 for r in records if r.outcome in (0, 1))
    total = len(records)
    return {
        "id": "INV-9",
        "passed": outcome_01 == c.ecdsa_verify_calls and total == c.checkecdsa_entries,
        "statement": "count(outcome in {0,1}) == C_ECDSA_VERIFY_CALLS and count(all) == C_CHECKECDSA_ENTRIES",
        "outcome_01_count": outcome_01,
        "total_records": total,
        "ecdsa_verify_calls": c.ecdsa_verify_calls,
        "checkecdsa_entries": c.checkecdsa_entries,
    }


def check_journal_sums(journal: list[JournalEntry], c: Counters) -> dict[str, object]:
    """INV-10: journal sums reconcile with counters."""
    s_checksig = sum(e.checksig_ops for e in journal)
    s_checkmultisig = sum(e.checkmultisig_ops for e in journal)
    s_ecdsa_calls = sum(e.ecdsa_verify_calls for e in journal)
    s_ecdsa_ok = sum(e.ecdsa_verify_ok for e in journal)
    return {
        "id": "INV-10",
        "passed": (
            s_ecdsa_calls == c.ecdsa_verify_calls
            and s_checksig == c.op_checksig + c.op_checksigverify
            and s_checkmultisig == c.op_checkmultisig + c.op_checkmultisigverify
            and s_ecdsa_ok == c.ecdsa_verify_ok
        ),
        "statement": "sum(journal fields) == counter values",
        "journal_sum_checksig_ops": s_checksig,
        "journal_sum_checkmultisig_ops": s_checkmultisig,
        "journal_sum_ecdsa_verify_calls": s_ecdsa_calls,
        "journal_sum_ecdsa_verify_ok": s_ecdsa_ok,
        "counter_op_checksig_plus_verify": c.op_checksig + c.op_checksigverify,
        "counter_op_checkmultisig_plus_verify": c.op_checkmultisig
        + c.op_checkmultisigverify,
        "counter_ecdsa_verify_calls": c.ecdsa_verify_calls,
        "counter_ecdsa_verify_ok": c.ecdsa_verify_ok,
    }


def check_duplicate_keys(records: list[Record]) -> dict[str, object]:
    """INV-11: no duplicate (spend_txid, input_index, op_seq) after sorting."""
    seen: set[tuple[bytes, int, int]] = set()
    duplicates = 0
    for r in records:
        key = r.sort_key
        if key in seen:
            duplicates += 1
        seen.add(key)
    return {
        "id": "INV-11",
        "passed": duplicates == 0,
        "statement": "No duplicate (spend_txid, input_index, op_seq) after sorting",
        "duplicate_count": duplicates,
    }


def check_all_verdicts_true(journal: list[JournalEntry]) -> dict[str, object]:
    """INV-2 for census: all journal verdicts are true (1)."""
    false_count = sum(1 for e in journal if e.verdict != 1)
    return {
        "id": "INV-2",
        "passed": false_count == 0,
        "statement": "All journal verdicts are true (valid chain)",
        "total_entries": len(journal),
        "false_verdicts": false_count,
    }


def check_count_repeat(
    c1: Counters, c2: Counters, sha1: str, sha2: str
) -> dict[str, object]:
    """INV-13: two Run-B executions produce identical counters and sorted records SHA256."""
    counters_identical = (
        all(getattr(c1, name) == getattr(c2, name) for name in COUNTER_NAMES)
        and c1.record_count == c2.record_count
        and c1.journal_count == c2.journal_count
    )
    sha_match = sha1 == sha2
    return {
        "id": "INV-13",
        "passed": counters_identical and sha_match,
        "statement": "Two Run-B executions produce byte-identical counters and identical sha256(records.sorted.bin)",
        "counters_identical": counters_identical,
        "sorted_records_sha256_match": sha_match,
        "sha256_run1": sha1,
        "sha256_run2": sha2,
    }


def check_census_capture_agreement(
    census_journal: list[JournalEntry],
    capture_journal: list[JournalEntry],
) -> dict[str, object]:
    """INV-12: census ∩ capture journal agreement (anti-triple-count)."""
    census_map: dict[tuple[bytes, int], JournalEntry] = {}
    for e in census_journal:
        if e.key in census_map:
            raise AnalyzerError(
                f"INV-12: duplicate key in census journal (input_index={e.input_index})"
            )
        census_map[e.key] = e

    capture_map: dict[tuple[bytes, int], JournalEntry] = {}
    for e in capture_journal:
        if e.key in capture_map:
            raise AnalyzerError(
                f"INV-12: duplicate key in capture journal (input_index={e.input_index})"
            )
        capture_map[e.key] = e

    intersection = set(census_map.keys()) & set(capture_map.keys())
    discrepancies: list[dict[str, object]] = []
    max_ratio = 1.0

    for key in sorted(intersection):
        c = census_map[key]
        b = capture_map[key]
        for field_name in (
            "checksig_ops",
            "checkmultisig_ops",
            "ecdsa_verify_calls",
            "ecdsa_verify_ok",
        ):
            cv = int(getattr(c, field_name))
            bv = int(getattr(b, field_name))
            if cv != bv:
                discrepancies.append(
                    {
                        "input_index": key[1],
                        "field": field_name,
                        "census_value": cv,
                        "capture_value": bv,
                    }
                )
                if field_name == "ecdsa_verify_calls" and bv > 0:
                    ratio = cv / bv
                    max_ratio = max(max_ratio, ratio)

    width_multiplier: int | None = None
    if max_ratio > 2.5 and max_ratio < 3.5:
        width_multiplier = 3
    elif max_ratio > 1.5:
        width_multiplier = round(max_ratio)

    return {
        "id": "INV-12",
        "passed": len(discrepancies) == 0,
        "statement": "Census ∩ capture journals agree exactly on every field",
        "intersection_size": len(intersection),
        "census_size": len(census_map),
        "capture_size": len(capture_map),
        "discrepancy_count": len(discrepancies),
        "discrepancies": discrepancies[:50],
        "width_multiplier": width_multiplier,
    }


# ── Bare JSON extraction ────────────────────────────────────────────────────


def extract_bare_mode0(bare: dict[str, object]) -> dict[str, object]:
    """Extract mode-0 results from bare-secp JSON per the binding contract.

    Requires top-level ``native_mode0`` with all exact fields:
    inputs_per_round, rounds, attempts_total, round_ns,
    median_ns_per_attempt, min_ns_per_attempt, max_ns_per_attempt,
    mismatches, first_mismatch, ok_count.

    Per-attempt round cost is ``round_ns[i] / inputs_per_round``, never
    divided by ``attempts_total`` across all rounds.  The median of those
    per-round costs is the authoritative Y.  Reported median/min/max must
    agree with the independently recomputed values within floating tolerance.
    """
    _REQUIRED_FIELDS = (
        "inputs_per_round",
        "rounds",
        "attempts_total",
        "round_ns",
        "median_ns_per_attempt",
        "min_ns_per_attempt",
        "max_ns_per_attempt",
        "mismatches",
        "first_mismatch",
        "ok_count",
    )

    mode0 = bare.get("native_mode0")
    if not isinstance(mode0, dict):
        raise AnalyzerError(
            "bare JSON: missing top-level native_mode0 object "
            "(old schema without inputs_per_round/rounds/attempts_total)"
        )

    missing = [f for f in _REQUIRED_FIELDS if f not in mode0]
    if missing:
        raise AnalyzerError(
            "bare JSON: native_mode0 missing required fields: " + ", ".join(missing)
        )

    inputs_per_round = _require_non_bool_int(
        mode0["inputs_per_round"], "bare JSON: native_mode0.inputs_per_round"
    )
    rounds = _require_non_bool_int(mode0["rounds"], "bare JSON: native_mode0.rounds")
    attempts_total = _require_non_bool_int(
        mode0["attempts_total"], "bare JSON: native_mode0.attempts_total"
    )
    mismatches = _require_non_bool_int(
        mode0["mismatches"], "bare JSON: native_mode0.mismatches"
    )
    ok_count = _require_non_bool_int(
        mode0["ok_count"], "bare JSON: native_mode0.ok_count"
    )
    first_mismatch = mode0["first_mismatch"]

    # Validate positive / non-negative values
    if inputs_per_round <= 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.inputs_per_round = {inputs_per_round} "
            "(must be positive)"
        )
    if rounds <= 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.rounds = {rounds} (must be positive)"
        )
    if attempts_total <= 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.attempts_total = {attempts_total} "
            "(must be positive)"
        )
    if ok_count < 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.ok_count = {ok_count} (must be non-negative)"
        )
    if mismatches < 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.mismatches = {mismatches} (must be non-negative)"
        )

    # Require attempts_total == inputs_per_round * rounds
    if attempts_total != inputs_per_round * rounds:
        raise AnalyzerError(
            f"bare JSON: attempts_total ({attempts_total}) != "
            f"inputs_per_round ({inputs_per_round}) * rounds ({rounds})"
        )

    # round_ns must be a list of positive ints with length == rounds
    round_ns_raw = mode0["round_ns"]
    if not isinstance(round_ns_raw, list):
        raise AnalyzerError("bare JSON: native_mode0.round_ns is not a list")
    if len(round_ns_raw) != rounds:
        raise AnalyzerError(
            f"bare JSON: round_ns length ({len(round_ns_raw)}) != rounds ({rounds})"
        )

    round_ns: list[int] = []
    for i, ns in enumerate(round_ns_raw):
        if isinstance(ns, bool) or not isinstance(ns, int):
            raise AnalyzerError(
                f"bare JSON: round_ns[{i}] = {ns!r} (must be a positive non-boolean integer)"
            )
        if ns <= 0:
            raise AnalyzerError(f"bare JSON: round_ns[{i}] = {ns} (must be positive)")
        round_ns.append(ns)

    # Independently recompute per-round ns/attempt as round_ns / inputs_per_round.
    # Never divide by attempts_total for a single round.
    per_attempt: list[float] = [float(ns) / float(inputs_per_round) for ns in round_ns]

    # Median is the authoritative Y (not mean).
    recomputed_median = statistics.median(per_attempt)
    recomputed_min = min(per_attempt)
    recomputed_max = max(per_attempt)

    reported_median = _require_positive_finite_float(
        mode0["median_ns_per_attempt"], "bare JSON: median_ns_per_attempt"
    )
    reported_min = _require_positive_finite_float(
        mode0["min_ns_per_attempt"], "bare JSON: min_ns_per_attempt"
    )
    reported_max = _require_positive_finite_float(
        mode0["max_ns_per_attempt"], "bare JSON: max_ns_per_attempt"
    )

    # Require reported median/min/max agree within floating tolerance.
    _REL_TOL = 1e-6

    def _approx(a: float, b: float) -> bool:
        if a == b:
            return True
        return abs(a - b) <= _REL_TOL * max(abs(a), abs(b), 1.0)

    if not _approx(reported_median, recomputed_median):
        raise AnalyzerError(
            f"bare JSON: median_ns_per_attempt ({reported_median}) != "
            f"recomputed round-median ({recomputed_median})"
        )
    if not _approx(reported_min, recomputed_min):
        raise AnalyzerError(
            f"bare JSON: min_ns_per_attempt ({reported_min}) != "
            f"recomputed round-min ({recomputed_min})"
        )
    if not _approx(reported_max, recomputed_max):
        raise AnalyzerError(
            f"bare JSON: max_ns_per_attempt ({reported_max}) != "
            f"recomputed round-max ({recomputed_max})"
        )

    spread_ns = recomputed_max - recomputed_min

    return {
        "median_ns_per_attempt": recomputed_median,
        "min_ns_per_attempt": recomputed_min,
        "max_ns_per_attempt": recomputed_max,
        "spread_ns": spread_ns,
        "inputs_per_round": inputs_per_round,
        "rounds": rounds,
        "attempts_total": attempts_total,
        "mismatches": mismatches,
        "first_mismatch": first_mismatch,
        "ok_count": ok_count,
        "per_attempt_ns": per_attempt,
    }


def extract_spike_width1(spike: dict[str, object]) -> float:
    """Extract width-1 us_per_input from a spike run JSON."""
    if "runs" in spike and isinstance(spike["runs"], list):
        for run in spike["runs"]:
            if not isinstance(run, dict):
                raise AnalyzerError("spike JSON: runs entry is not an object")
            threads = run.get("threads")
            if isinstance(threads, bool) or not isinstance(threads, int):
                raise AnalyzerError(
                    "spike JSON: run.threads must be a non-boolean integer"
                )
            if threads != 1:
                continue
            us = run.get("us_per_input")
            if us is None:
                raise AnalyzerError(
                    "spike JSON: run with threads == 1 missing us_per_input"
                )
            return _require_positive_finite_float(us, "spike JSON: run.us_per_input")
        raise AnalyzerError("spike JSON: no run with threads == 1")
    if "us_per_input" in spike:
        threads = spike.get("threads")
        if isinstance(threads, bool) or not isinstance(threads, int):
            raise AnalyzerError(
                "spike JSON: top-level us_per_input requires threads to be a non-boolean integer"
            )
        if threads != 1:
            raise AnalyzerError(
                "spike JSON: top-level us_per_input requires threads == 1"
            )
        return _require_positive_finite_float(
            spike["us_per_input"], "spike JSON: top-level us_per_input"
        )
    raise AnalyzerError("spike JSON: no us_per_input found")


# ── Subcommand: validate-capture ────────────────────────────────────────────


def cmd_validate_capture(args: argparse.Namespace) -> int:
    counters, _ = parse_counters(Path(args.counters))
    records = parse_records(Path(args.records))
    journal = parse_journal(Path(args.journal))

    repeat_counters, _ = parse_counters(Path(args.repeat_counters))
    parse_records(Path(args.repeat_records))
    parse_journal(Path(args.repeat_journal))

    # Sort records and compute SHA256 for both runs
    raw1 = read_raw_entries(Path(args.records), RECORD_MAGIC, RECORD_SIZE, "records")
    raw2 = read_raw_entries(
        Path(args.repeat_records), RECORD_MAGIC, RECORD_SIZE, "records"
    )
    sorted1 = sort_records_raw(raw1)
    sorted2 = sort_records_raw(raw2)
    sha1 = sha256_hex(sorted1)
    sha2 = sha256_hex(sorted2)

    if args.sorted_records_output:
        out = Path(args.sorted_records_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(HEADER_STRUCT.pack(RECORD_MAGIC, len(raw1)) + sorted1)

    inv_results: list[dict[str, object]] = []
    inv_results.extend(check_counter_arithmetic(counters))
    inv_results.append(_check_pre_taproot_schnorr_absence(counters))
    inv_results.append(check_record_counts(records, counters))
    inv_results.append(check_journal_sums(journal, counters))
    inv_results.append(check_duplicate_keys(records))
    inv_results.append(check_count_repeat(counters, repeat_counters, sha1, sha2))

    all_passed = (
        all(r["passed"] for r in inv_results)
        and counters.ffi_verify_entries == EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1
    )

    report: dict[str, object] = {
        "schema": "census-capture-v2",
        "counters_label": counters.label,
        "record_count": len(records),
        "journal_count": len(journal),
        "sorted_records_sha256": sha1,
        "repeat_sorted_records_sha256": sha2,
        "invariants": inv_results,
        "all_passed": all_passed,
    }

    context_inputs = getattr(args, "context_inputs", None)
    if context_inputs:
        corpus_size, corpus_sha256 = _sha256_file(Path(context_inputs))
        report["corpus_size"] = corpus_size
        report["corpus_sha256"] = corpus_sha256

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    failed = [r["id"] for r in inv_results if not r["passed"]]
    if counters.ffi_verify_entries != EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1:
        failed.append("EXP-KSPIKE1")
    if failed:
        print(f"validate-capture: FAILED — {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"validate-capture: PASSED — {len(records)} records, sha256={sha1[:16]}…")
    return 0


# ── Subcommand: validate-census ─────────────────────────────────────────────


def cmd_validate_census(args: argparse.Namespace) -> int:
    counters, _ = parse_counters(Path(args.counters))
    journal = parse_journal(Path(args.journal))
    capture_journal = parse_journal(Path(args.capture_journal))

    inv_results: list[dict[str, object]] = []
    inv_results.extend(check_counter_arithmetic(counters))
    inv_results.append(_check_pre_taproot_schnorr_absence(counters))
    inv_results.append(check_all_verdicts_true(journal))
    inv_results.append(check_journal_sums(journal, counters))
    inv_results.append(check_census_capture_agreement(journal, capture_journal))

    # EXP-1: expected input count
    exp1_passed = counters.ffi_verify_entries == EXPECTED_FFI_VERIFY_ENTRIES_FULL
    exp1: dict[str, object] = {
        "id": "EXP-1",
        "passed": exp1_passed,
        "statement": f"C_FFI_VERIFY_ENTRIES == {EXPECTED_FFI_VERIFY_ENTRIES_FULL}",
        "expected": EXPECTED_FFI_VERIFY_ENTRIES_FULL,
        "actual": counters.ffi_verify_entries,
    }
    if not exp1_passed:
        exp1["warning"] = (
            "Value differs from published anchor — window, corpus, or published figure may have moved."
        )

    # EXP-4: attempts-per-check comparison (census vs capture)
    census_a = (
        counters.ecdsa_verify_calls / counters.ffi_verify_entries
        if counters.ffi_verify_entries
        else 0.0
    )
    capture_ecdsa_sum = sum(e.ecdsa_verify_calls for e in capture_journal)
    capture_count = len(capture_journal)
    capture_a = capture_ecdsa_sum / capture_count if capture_count else 0.0
    if census_a > 0 and capture_a > 0:
        ratio = census_a / capture_a
        exp4_passed = abs(ratio - 1.0) <= 0.10
    else:
        ratio = 0.0
        exp4_passed = False
    exp4: dict[str, object] = {
        "id": "EXP-4",
        "passed": exp4_passed,
        "statement": "attempts-per-check on KSPIKE1 vs 0..150k differ by <= 10%",
        "census_attempts_per_check": census_a,
        "capture_attempts_per_check": capture_a,
        "ratio": ratio,
    }
    if not exp4_passed and ratio > 0:
        exp4["warning"] = (
            "Corpus over-represents multisig; report both ratios and extrapolate with the whole-window ratio."
        )

    all_passed = (
        all(r["passed"] for r in inv_results) and exp1["passed"] and exp4["passed"]
    )

    report = {
        "schema": "validate-census-v1",
        "counters_label": counters.label,
        "journal_count": len(journal),
        "invariants": inv_results,
        "expected_anchors": [exp1, exp4],
        "all_passed": all_passed,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    failed = [r["id"] for r in inv_results if not r["passed"]]
    if not exp1["passed"]:
        failed.append("EXP-1")
    if not exp4["passed"]:
        failed.append("EXP-4")
    if failed:
        print(f"validate-census: FAILED — {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"validate-census: PASSED — {len(journal)} journal entries")
    return 0


# ── Subcommand: verdict ─────────────────────────────────────────────────────


def cmd_verdict(args: argparse.Namespace) -> int:
    if len(args.bare_runs) != 3:
        raise AnalyzerError(
            f"verdict requires exactly three bare-runs, got {len(args.bare_runs)}"
        )
    if len(args.spike_runs) != 3:
        raise AnalyzerError(
            f"verdict requires exactly three spike-runs, got {len(args.spike_runs)}"
        )
    capture_counters, _ = parse_counters(Path(args.capture_counters))
    k_entries = capture_counters.ffi_verify_entries
    if k_entries == 0:
        raise AnalyzerError("capture counters: ffi_verify_entries == 0")

    # Extract spike width-1 values across runs
    spike_values: list[float] = []
    for spike_path in args.spike_runs:
        spike_raw = json.loads(Path(spike_path).read_text())
        if not isinstance(spike_raw, dict):
            raise AnalyzerError(f"{spike_path}: JSON root is not an object")
        spike_values.append(extract_spike_width1(spike_raw))

    if not spike_values:
        raise AnalyzerError("no spike run files provided")

    x_us = statistics.median(spike_values)
    spike_spread_us = (
        (max(spike_values) - min(spike_values)) if len(spike_values) > 1 else 0.0
    )

    # Extract and validate every bare timing run.
    run_records: list[dict[str, object]] = []
    run_medians: list[float] = []
    all_per_attempt_ns: list[float] = []
    for bare_path in args.bare_runs:
        bare_raw = json.loads(Path(bare_path).read_text())
        if not isinstance(bare_raw, dict):
            raise AnalyzerError(f"{bare_path}: JSON root is not an object")

        mode0 = extract_bare_mode0(bare_raw)
        run_medians.append(mode0["median_ns_per_attempt"])
        all_per_attempt_ns.extend(mode0["per_attempt_ns"])

        # INV-8: native correctness, recomputed rather than trusting emitted passed.
        inv8_raw = bare_raw.get("inv_8")
        if not isinstance(inv8_raw, dict):
            raise AnalyzerError(f"{bare_path}: missing inv_8")
        for field in (
            "passed",
            "mismatches",
            "ok_count",
            "expected_true_count",
            "ok_equals_count_outcome_1",
        ):
            if field not in inv8_raw:
                raise AnalyzerError(f"{bare_path}: inv_8 missing {field}")
        inv8_mismatches = _require_non_bool_int(
            inv8_raw["mismatches"], f"{bare_path}: inv_8 mismatches"
        )
        inv8_ok_count = _require_non_bool_int(
            inv8_raw["ok_count"], f"{bare_path}: inv_8 ok_count"
        )
        inv8_expected = _require_non_bool_int(
            inv8_raw["expected_true_count"],
            f"{bare_path}: inv_8 expected_true_count",
        )
        inv8_ok_eq = inv8_raw["ok_equals_count_outcome_1"]
        if not isinstance(inv8_ok_eq, bool):
            raise AnalyzerError(
                f"{bare_path}: inv_8 ok_equals_count_outcome_1 is not a boolean"
            )
        inv8_emitted_passed = inv8_raw["passed"]
        if not isinstance(inv8_emitted_passed, bool):
            raise AnalyzerError(f"{bare_path}: inv_8 passed is not a boolean")
        inv8_run_passed = (
            inv8_mismatches == 0
            and inv8_ok_count == inv8_expected
            and inv8_expected == k_entries
            and inv8_ok_eq
            and inv8_emitted_passed
            and mode0["mismatches"] == inv8_mismatches
            and mode0["ok_count"] == inv8_ok_count
        )

        # INV-15: every run must contain exactly the 22 COUNTER_NAMES with
        # integer zero values, plus explicit true all_counters_zero and passed.
        inv15_raw = bare_raw.get("inv_15")
        if not isinstance(inv15_raw, dict):
            raise AnalyzerError(f"{bare_path}: missing inv_15")
        for field in ("counters", "all_counters_zero", "passed"):
            if field not in inv15_raw:
                raise AnalyzerError(f"{bare_path}: inv_15 missing {field}")
        inv15_all_zero = inv15_raw["all_counters_zero"]
        inv15_passed_emitted = inv15_raw["passed"]
        if not isinstance(inv15_all_zero, bool):
            raise AnalyzerError(
                f"{bare_path}: inv_15 all_counters_zero is not a boolean"
            )
        if not isinstance(inv15_passed_emitted, bool):
            raise AnalyzerError(f"{bare_path}: inv_15 passed is not a boolean")
        inv15_counters = inv15_raw["counters"]
        if not isinstance(inv15_counters, dict):
            raise AnalyzerError(f"{bare_path}: inv_15 counters is not a dict")
        inv15_counter_keys = set(inv15_counters.keys())
        expected_counter_keys = set(COUNTER_NAMES)
        if inv15_counter_keys != expected_counter_keys:
            missing = sorted(expected_counter_keys - inv15_counter_keys)
            extra = sorted(inv15_counter_keys - expected_counter_keys)
            raise AnalyzerError(
                f"{bare_path}: inv_15 counters keys mismatch "
                f"(missing={missing}, extra={extra})"
            )
        computed_all_zero = True
        for name in COUNTER_NAMES:
            value = inv15_counters[name]
            if not isinstance(value, int) or isinstance(value, bool):
                raise AnalyzerError(
                    f"{bare_path}: inv_15 counter {name} is not an integer: {value!r}"
                )
            if value != 0:
                computed_all_zero = False
        # Recompute rather than trust the emitted summaries.
        inv15_run_passed = (
            computed_all_zero
            and inv15_all_zero is True
            and inv15_passed_emitted is True
        )

        run_records.append(
            {
                "path": str(bare_path),
                "native_mode0": {
                    "inputs_per_round": mode0["inputs_per_round"],
                    "rounds": mode0["rounds"],
                    "attempts_total": mode0["attempts_total"],
                    "round_ns": bare_raw["native_mode0"]["round_ns"],
                    "mismatches": mode0["mismatches"],
                    "first_mismatch": mode0["first_mismatch"],
                    "ok_count": mode0["ok_count"],
                    "median_ns_per_attempt": mode0["median_ns_per_attempt"],
                    "min_ns_per_attempt": mode0["min_ns_per_attempt"],
                    "max_ns_per_attempt": mode0["max_ns_per_attempt"],
                    "per_attempt_ns": mode0["per_attempt_ns"],
                },
                "inv_8": {
                    "passed": inv8_run_passed,
                    "mismatches": inv8_mismatches,
                    "ok_count": inv8_ok_count,
                    "expected_true_count": inv8_expected,
                    "ok_equals_count_outcome_1": inv8_ok_eq,
                    "emitted_passed": inv8_emitted_passed,
                },
                "inv_15": {
                    "passed": inv15_run_passed,
                    "all_counters_zero": inv15_all_zero,
                    "passed_emitted": inv15_passed_emitted,
                    "computed_all_zero": computed_all_zero,
                    "counters": {
                        name: int(inv15_counters[name]) for name in COUNTER_NAMES
                    },
                },
                "rust_secp_diagnostic": bare_raw.get("rust_secp_diagnostic"),
            }
        )

    if not run_medians:
        raise AnalyzerError("no bare run files provided")

    # Authoritative Y is the median of each run's validated per-round median.
    y_ns = statistics.median(run_medians)
    y_us = y_ns / 1000.0

    if not all_per_attempt_ns:
        raise AnalyzerError("no bare per-round timing values")
    bare_spread_ns = max(all_per_attempt_ns) - min(all_per_attempt_ns)
    bare_spread_us = bare_spread_ns / 1000.0

    inv8_passed = all(r["inv_8"]["passed"] for r in run_records)
    inv15_passed = all(r["inv_15"]["passed"] for r in run_records)

    # Rust secp diagnostic is a per-run non-gating observation; report first present.
    rust_secp_diagnostic = next(
        (
            r["rust_secp_diagnostic"]
            for r in run_records
            if r["rust_secp_diagnostic"] is not None
        ),
        None,
    )

    # INV-14: reproducible source-identity proof from integrity JSON.
    # Object-byte identity is deliberately not required because RelWithDebInfo
    # embeds absolute source paths; the build has no LTO/IPO.
    integrity_raw = json.loads(Path(args.integrity).read_text())
    if not isinstance(integrity_raw, dict):
        raise AnalyzerError(f"{args.integrity}: JSON root is not an object")
    for field in (
        "pristine_source_hash",
        "patched_source_hash",
        "pristine_secp_tree_hash",
        "patched_secp_tree_hash",
    ):
        if field not in integrity_raw:
            raise AnalyzerError(f"{args.integrity}: missing {field}")
        value = integrity_raw[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or not re.fullmatch(r"[0-9a-f]{64}", value)
        ):
            raise AnalyzerError(
                f"{args.integrity}: {field} is not a 64-character lowercase hex string"
            )
    pristine_pubkey = integrity_raw["pristine_source_hash"]
    patched_pubkey = integrity_raw["patched_source_hash"]
    pristine_secp = integrity_raw["pristine_secp_tree_hash"]
    patched_secp = integrity_raw["patched_secp_tree_hash"]
    recompute_pubkey_identical = pristine_pubkey == patched_pubkey
    recompute_secp_identical = pristine_secp == patched_secp
    inv14_pubkey_identical = integrity_raw.get("pubkey_source_identical")
    inv14_secp_identical = integrity_raw.get("secp_tree_identical")
    if not isinstance(inv14_pubkey_identical, bool):
        raise AnalyzerError(
            "integrity JSON: missing or non-boolean pubkey_source_identical"
        )
    if not isinstance(inv14_secp_identical, bool):
        raise AnalyzerError(
            "integrity JSON: missing or non-boolean secp_tree_identical"
        )
    # Gate on recomputed equality and require the emitted booleans to agree.
    inv14_passed = (
        recompute_pubkey_identical
        and recompute_secp_identical
        and inv14_pubkey_identical is recompute_pubkey_identical
        and inv14_secp_identical is recompute_secp_identical
    )

    # Census data
    a_calls = capture_counters.ecdsa_verify_calls
    a_ratio = a_calls / k_entries

    # Floor and residual (all in µs)
    f_us = a_ratio * y_us
    r_us = x_us - f_us
    r_frac = r_us / x_us if x_us != 0 else 0.0

    # Threshold: 5% of total wall, expressed as fraction of script wall
    current_wall = _require_positive_finite_float(
        args.current_wall_seconds, "current_wall_seconds"
    )
    current_script_wall = _require_positive_finite_float(
        args.current_script_wall_seconds, "current_script_wall_seconds"
    )
    threshold = 0.05 * current_wall / current_script_wall

    # Noise estimate
    noise_us = spike_spread_us + abs(a_ratio * bare_spread_us)

    # EXP-3: a in (0, 2]
    exp3_passed = 0.0 < a_ratio <= 2.0

    # Determine verdict
    if not inv8_passed or not inv14_passed or not inv15_passed:
        verdict = "INVALID"
        rationale = "Bare arm integrity check failed (INV-8/14/15)"
    elif r_us < -noise_us:
        verdict = "INVALID"
        rationale = (
            f"R = {r_us:.4f} µs < -noise = {-noise_us:.4f} µs; "
            "capture or comparator is wrong"
        )
    elif r_frac >= threshold:
        verdict = "OPEN"
        rationale = f"r = {r_frac:.4f} >= threshold = {threshold:.4f}"
    else:
        verdict = "CLOSED"
        rationale = f"r = {r_frac:.4f} < threshold = {threshold:.4f}"

    report = {
        "schema": "verdict-v1",
        "verdict": verdict,
        "rationale": rationale,
        "X_us_per_check": x_us,
        "Y_ns_per_attempt": y_ns,
        "Y_us_per_attempt": y_us,
        "A_ecdsa_verify_calls": a_calls,
        "K_ffi_verify_entries": k_entries,
        "a_attempts_per_check": a_ratio,
        "F_us_per_check": f_us,
        "R_us_per_check": r_us,
        "r_residual_fraction": r_frac,
        "threshold": threshold,
        "current_wall_seconds": current_wall,
        "current_script_wall_seconds": current_script_wall,
        "spike_run_values": spike_values,
        "spike_spread_us": spike_spread_us,
        "bare_spread_ns": bare_spread_ns,
        "bare_spread_us": bare_spread_us,
        "noise_us": noise_us,
        "bare_runs": run_records,
        "run_medians_ns_per_attempt": run_medians,
        "inv_8": {"passed": inv8_passed},
        "rust_secp_diagnostic": rust_secp_diagnostic,
        "inv_14": {
            "passed": inv14_passed,
            "pubkey_source_identical": inv14_pubkey_identical,
            "secp_tree_identical": inv14_secp_identical,
            "pubkey_source_identical_recomputed": recompute_pubkey_identical,
            "secp_tree_identical_recomputed": recompute_secp_identical,
            "pristine_source_hash": pristine_pubkey,
            "patched_source_hash": patched_pubkey,
            "pristine_secp_tree_hash": pristine_secp,
            "patched_secp_tree_hash": patched_secp,
            "note": integrity_raw.get("note"),
        },
        "inv_15": {"passed": inv15_passed},
        "EXP-3": {
            "passed": exp3_passed,
            "a_attempts_per_check": a_ratio,
            "statement": "a in (0, 2]",
        },
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    print(f"verdict: {verdict} — {rationale}")
    return 0 if verdict != "INVALID" else 2



# ── Subcommand: classify-corpus ──────────────────────────────────────────────


def _op_kind_name(op_kind: int) -> str:
    return {
        1: "CHECKSIG",
        2: "CHECKSIGVERIFY",
        3: "CHECKMULTISIG",
        4: "CHECKMULTISIGVERIFY",
        5: "CHECKSIGADD",
    }.get(op_kind, f"UNKNOWN({op_kind})")


def _sig_version_name(sig_version: int) -> str:
    return {
        0: "BASE",
        1: "WITNESS_V0",
        2: "TAPSCRIPT",
        3: "TAPROOT",
    }.get(sig_version, f"UNKNOWN({sig_version})")


def _require_hex_str(value: object, field: str, length: int) -> str:
    """Validate that *value* is a lowercase hex string of exactly *length* chars."""
    if not isinstance(value, str) or len(value) != length:
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be a {length}-character hex string"
        )
    if not re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value):
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be lowercase hex, got {value!r}"
        )
    return value


def _require_int_field(value: object, field: str) -> int:
    """Validate that *value* is a non-bool int."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be an integer, got {type(value).__name__}"
        )
    return value


def _validate_replay_artifact(path: Path) -> dict[str, object]:
    """Validate a mainnet-prefix-replay-v3 JSON artifact and return flat fields.

    Required root keys (exactly): schema, network, network_magic, genesis_hash,
    start_height, start_hash, stop_height, stop_hash, block_count, window,
    assume_valid_height, window_verify_success_total, corpus_manifest, archive.
    Raises ``AnalyzerError`` with CTX-CUSTODY or CTX-WINDOW prefix on any
    schema, field, or invariant violation.
    """
    replay_bytes = path.read_bytes()
    raw = json.loads(replay_bytes)
    if not isinstance(raw, dict):
        raise AnalyzerError("CTX-CUSTODY: replay artifact root is not an object")

    _REPLAY_KEYS = {
        "schema", "network", "network_magic", "genesis_hash",
        "start_height", "start_hash", "stop_height", "stop_hash",
        "block_count", "window", "assume_valid_height",
        "window_verify_success_total", "corpus_manifest", "archive",
        "block_bytes", "block_source",
        "blocks_per_second", "checkpoint_generation", "data_dir",
        "decode_seconds", "elapsed_seconds", "fetch_seconds",
        "git_head", "measurement_target", "rss_high_water_bytes",
        "stage_seconds", "storage_backend", "tx_count", "txindex",
        "txindex_worker_catchup_seconds", "txindex_total_elapsed_seconds",
    }
    _require_exact_keys(raw, _REPLAY_KEYS, "replay artifact root")

    if raw["schema"] != "mainnet-prefix-replay-v3":
        raise AnalyzerError(
            f"CTX-CUSTODY: replay schema is {raw['schema']!r}, "
            f"expected 'mainnet-prefix-replay-v3'"
        )

    network = raw["network"]
    if network != "mainnet":
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.network must be 'mainnet', got {network!r}"
        )

    network_magic = _require_hex_str(raw["network_magic"], "replay.network_magic", 8)
    if network_magic != MAINNET_MAGIC:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.network_magic must be {MAINNET_MAGIC!r}, "
            f"got {network_magic!r}"
        )

    genesis_hash = _require_hex_str(raw["genesis_hash"], "replay.genesis_hash", 64)
    if genesis_hash != MAINNET_GENESIS_HASH:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.genesis_hash must be the canonical mainnet "
            f"genesis {MAINNET_GENESIS_HASH!r}, got {genesis_hash!r}"
        )

    start_height = _require_int_field(raw["start_height"], "replay.start_height")
    if start_height != 0:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.start_height must be 0, got {start_height}"
        )
    start_hash = _require_hex_str(raw["start_hash"], "replay.start_hash", 64)
    if start_hash != genesis_hash:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.start_hash must equal genesis_hash, "
            f"got {start_hash!r}"
        )

    stop_height = _require_int_field(raw["stop_height"], "replay.stop_height")
    stop_hash = _require_hex_str(raw["stop_hash"], "replay.stop_hash", 64)
    block_count = _require_int_field(raw["block_count"], "replay.block_count")
    if block_count != stop_height + 1:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.block_count must equal stop_height+1 "
            f"({stop_height + 1}), got {block_count}"
        )

    window = _require_int_field(raw["window"], "replay.window")
    if window <= 1:
        raise AnalyzerError(
            f"CTX-WINDOW: replay.window must be > 1, got {window}"
        )

    assume_valid_height = _require_int_field(
        raw["assume_valid_height"], "replay.assume_valid_height"
    )
    if assume_valid_height != 0:
        raise AnalyzerError(
            f"CTX-WINDOW: replay.assume_valid_height must be 0, "
            f"got {assume_valid_height}"
        )

    window_verify_success_total = _require_int_field(
        raw["window_verify_success_total"], "replay.window_verify_success_total"
    )
    if window_verify_success_total < 1:
        raise AnalyzerError(
            f"CTX-WINDOW: replay.window_verify_success_total must be >= 1, "
            f"got {window_verify_success_total}"
        )

    corpus_manifest = _require_custody_ref(
        raw["corpus_manifest"], "replay.corpus_manifest", with_schema=True
    )
    archive = _require_custody_ref(
        raw["archive"], "replay.archive", with_schema=False
    )

    # ── Optional timing/metadata fields emitted by the Rust replay binary.
    # These are not load-bearing for the contract, but the schema is frozen,
    # so we validate type and canonical range for each.
    def _require_float(value: object, field: str, *, ge: float | None = None) -> float:
        if isinstance(value, bool) or not isinstance(value, float):
            raise AnalyzerError(f"CTX-CUSTODY: {field} must be a float")
        if ge is not None and value < ge:
            raise AnalyzerError(f"CTX-CUSTODY: {field} must be >= {ge}, got {value}")
        return value

    block_bytes = _require_non_bool_int(raw["block_bytes"], "replay.block_bytes")
    if block_bytes < 0:
        raise AnalyzerError(f"CTX-CUSTODY: replay.block_bytes must be >= 0, got {block_bytes}")

    block_source = raw["block_source"]
    if block_source != "file":
        raise AnalyzerError(
            "CTX-CUSTODY: replay.block_source must be 'file', "
            f"got {block_source!r}"
        )

    if not isinstance(raw["txindex"], bool):
        raise AnalyzerError("CTX-CUSTODY: replay.txindex must be a boolean")

    blocks_per_second = _require_float(raw["blocks_per_second"], "replay.blocks_per_second", ge=0.0)
    checkpoint_generation = _require_non_bool_int(
        raw["checkpoint_generation"], "replay.checkpoint_generation"
    )
    if checkpoint_generation < 1:
        raise AnalyzerError(f"CTX-CUSTODY: replay.checkpoint_generation must be >= 1, got {checkpoint_generation}")

    data_dir = raw["data_dir"]
    if not isinstance(data_dir, str) or len(data_dir) == 0:
        raise AnalyzerError("CTX-CUSTODY: replay.data_dir must be a nonempty string")

    decode_seconds = _require_float(raw["decode_seconds"], "replay.decode_seconds", ge=0.0)
    elapsed_seconds = _require_float(raw["elapsed_seconds"], "replay.elapsed_seconds", ge=0.0)
    fetch_seconds = _require_float(raw["fetch_seconds"], "replay.fetch_seconds", ge=0.0)

    def _require_optional_float(value: object, field: str) -> None:
        if value is not None:
            _require_float(value, field, ge=0.0)

    _require_optional_float(
        raw["txindex_worker_catchup_seconds"],
        "replay.txindex_worker_catchup_seconds",
    )
    _require_optional_float(
        raw["txindex_total_elapsed_seconds"],
        "replay.txindex_total_elapsed_seconds",
    )

    git_head = _require_hex_str(raw["git_head"], "replay.git_head", 40)

    measurement_target = raw["measurement_target"]
    if not isinstance(measurement_target, str) or len(measurement_target) == 0:
        raise AnalyzerError("CTX-CUSTODY: replay.measurement_target must be a nonempty string")

    rss_high_water_bytes = _require_non_bool_int(
        raw["rss_high_water_bytes"], "replay.rss_high_water_bytes"
    )
    if rss_high_water_bytes < 0:
        raise AnalyzerError(f"CTX-CUSTODY: replay.rss_high_water_bytes must be >= 0, got {rss_high_water_bytes}")

    stage_seconds = raw["stage_seconds"]
    if not isinstance(stage_seconds, list):
        raise AnalyzerError("CTX-CUSTODY: replay.stage_seconds must be a list")
    _STAGE_ENTRY_KEYS = {"count", "stage", "sum_seconds"}
    for _stage_entry in stage_seconds:
        if not isinstance(_stage_entry, dict):
            raise AnalyzerError(
                "CTX-CUSTODY: replay.stage_seconds entries must be objects with "
                "count, stage, and sum_seconds"
            )
        _require_exact_keys(_stage_entry, _STAGE_ENTRY_KEYS, "replay.stage_seconds entry")
        _stage_count = _stage_entry["count"]
        if isinstance(_stage_count, bool) or not isinstance(_stage_count, int):
            raise AnalyzerError(
                "CTX-CUSTODY: replay.stage_seconds count must be a non-bool integer"
            )
        if _stage_count < 0:
            raise AnalyzerError(
                f"CTX-CUSTODY: replay.stage_seconds count must be >= 0, got {_stage_count}"
            )
        _stage_name = _stage_entry["stage"]
        if not isinstance(_stage_name, str):
            raise AnalyzerError("CTX-CUSTODY: replay.stage_seconds stage must be a string")
        _stage_sum = _stage_entry["sum_seconds"]
        if isinstance(_stage_sum, bool) or not isinstance(_stage_sum, float):
            raise AnalyzerError(
                "CTX-CUSTODY: replay.stage_seconds sum_seconds must be a float"
            )
        if not math.isfinite(_stage_sum) or _stage_sum < 0.0:
            raise AnalyzerError(
                "CTX-CUSTODY: replay.stage_seconds sum_seconds must be finite and "
                f">= 0, got {_stage_sum}"
            )

    storage_backend = raw["storage_backend"]
    if not isinstance(storage_backend, str) or len(storage_backend) == 0:
        raise AnalyzerError("CTX-CUSTODY: replay.storage_backend must be a nonempty string")

    tx_count = _require_non_bool_int(raw["tx_count"], "replay.tx_count")
    if tx_count < 0:
        raise AnalyzerError(f"CTX-CUSTODY: replay.tx_count must be >= 0, got {tx_count}")

    return {
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
        "corpus_manifest": corpus_manifest,
        "archive": archive,
        "block_bytes": block_bytes,
        "block_source": block_source,
        "blocks_per_second": blocks_per_second,
        "checkpoint_generation": checkpoint_generation,
        "data_dir": data_dir,
        "decode_seconds": decode_seconds,
        "elapsed_seconds": elapsed_seconds,
        "fetch_seconds": fetch_seconds,
        "git_head": git_head,
        "measurement_target": measurement_target,
        "rss_high_water_bytes": rss_high_water_bytes,
        "stage_seconds": stage_seconds,
        "storage_backend": storage_backend,
        "tx_count": tx_count,
        "txindex": raw["txindex"],
        "txindex_worker_catchup_seconds": raw["txindex_worker_catchup_seconds"],
        "txindex_total_elapsed_seconds": raw["txindex_total_elapsed_seconds"],
        "custody": {
            "bytes": len(replay_bytes),
            "sha256": hashlib.sha256(replay_bytes).hexdigest(),
        },
    }


def _validate_corpus_manifest(
    manifest_path: Path, archive_path: Path, replay: dict[str, object]
) -> dict[str, object]:
    """Validate corpus manifest JSON, cross-check against replay, and
    stream-validate every Core-frame in the archive in a single open pass.

    The archive is opened exactly once.  A running SHA-256 is updated
    incrementally with every byte read (magic + length + payload), replacing
    the separate ``_sha256_file`` call.  The computed hash and byte count
    must match the manifest's declared archive size and sha256.

    Returns the manifest summary **without** ``entries``.  Raises
    ``AnalyzerError`` with CTX-CUSTODY prefix on any mismatch.
    """
    # ── Load and validate manifest JSON ──
    manifest_bytes = manifest_path.read_bytes()
    raw = json.loads(manifest_bytes)
    if not isinstance(raw, dict):
        raise AnalyzerError("CTX-CUSTODY: corpus manifest root is not an object")

    _MANIFEST_KEYS = {
        "schema", "version", "network", "network_magic", "genesis_hash",
        "range", "archive", "entries",
    }
    _require_exact_keys(raw, _MANIFEST_KEYS, "corpus manifest root")

    if raw["schema"] != "bitcoin-rs-corpus-manifest":
        raise AnalyzerError(
            f"CTX-CUSTODY: corpus manifest schema is {raw['schema']!r}, "
            f"expected 'bitcoin-rs-corpus-manifest'"
        )
    version = _require_int_field(raw["version"], "manifest.version")
    if version != 1:
        raise AnalyzerError(
            f"CTX-CUSTODY: corpus manifest version must be 1, got {version}"
        )

    network = raw["network"]
    if network != "mainnet":
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.network must be 'mainnet', got {network!r}"
        )
    network_magic = _require_hex_str(raw["network_magic"], "manifest.network_magic", 8)
    if network_magic != MAINNET_MAGIC:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.network_magic must be {MAINNET_MAGIC!r}, "
            f"got {network_magic!r}"
        )
    genesis_hash = _require_hex_str(raw["genesis_hash"], "manifest.genesis_hash", 64)
    if genesis_hash != MAINNET_GENESIS_HASH:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.genesis_hash must be the canonical mainnet "
            f"genesis {MAINNET_GENESIS_HASH!r}, got {genesis_hash!r}"
        )

    # ── range ──
    range_obj = raw["range"]
    if not isinstance(range_obj, dict):
        raise AnalyzerError("CTX-CUSTODY: manifest.range must be an object")
    _require_exact_keys(range_obj, {"start_height", "stop_height"}, "manifest.range")
    range_start = _require_u32(range_obj["start_height"], "manifest.range.start_height")
    range_stop = _require_u32(range_obj["stop_height"], "manifest.range.stop_height")
    if range_start != 0:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.range.start_height must be 0, got {range_start}"
        )

    # ── archive ──
    archive_obj = raw["archive"]
    if not isinstance(archive_obj, dict):
        raise AnalyzerError("CTX-CUSTODY: manifest.archive must be an object")
    _require_exact_keys(archive_obj, {"size", "sha256"}, "manifest.archive")
    archive_size = _require_u64(archive_obj["size"], "manifest.archive.size")
    archive_sha256 = _require_hex_str(
        archive_obj["sha256"], "manifest.archive.sha256", 64
    )

    # ── entries ──
    entries = raw["entries"]
    if not isinstance(entries, list) or len(entries) == 0:
        raise AnalyzerError(
            "CTX-CUSTODY: manifest.entries must be a non-empty array"
        )

    # ── Cross-check manifest file bytes/SHA-256 against replay ──
    replay_cm = replay["corpus_manifest"]
    replay_cm_bytes = replay_cm["bytes"]
    replay_cm_sha256 = replay_cm["sha256"]
    actual_cm_size = len(manifest_bytes)
    actual_cm_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if actual_cm_size != replay_cm_bytes:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest file size mismatch: replay={replay_cm_bytes}, "
            f"actual={actual_cm_size}"
        )
    if actual_cm_sha != replay_cm_sha256:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest file sha256 mismatch: replay={replay_cm_sha256}, "
            f"actual={actual_cm_sha}"
        )

    # ── Cross-check manifest fields against replay ──
    replay_network = replay["network"]
    replay_magic = replay["network_magic"]
    replay_genesis = replay["genesis_hash"]
    replay_start = replay["start_height"]
    replay_stop = replay["stop_height"]
    replay_stop_hash = replay["stop_hash"]
    replay_arch_bytes = replay["archive"]["bytes"]
    replay_arch_sha256 = replay["archive"]["sha256"]

    if network != replay_network:
        raise AnalyzerError(
            f"CTX-CUSTODY: network mismatch: manifest={network!r}, "
            f"replay={replay_network!r}"
        )
    if network_magic != replay_magic:
        raise AnalyzerError(
            f"CTX-CUSTODY: network_magic mismatch: manifest={network_magic!r}, "
            f"replay={replay_magic!r}"
        )
    if genesis_hash != replay_genesis:
        raise AnalyzerError(
            f"CTX-CUSTODY: genesis_hash mismatch: manifest={genesis_hash!r}, "
            f"replay={replay_genesis!r}"
        )
    if range_start != replay_start:
        raise AnalyzerError(
            f"CTX-CUSTODY: start_height mismatch: manifest={range_start}, "
            f"replay={replay_start}"
        )
    if range_stop != replay_stop:
        raise AnalyzerError(
            f"CTX-CUSTODY: stop_height mismatch: manifest={range_stop}, "
            f"replay={replay_stop}"
        )
    if archive_size != replay_arch_bytes:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive size mismatch: manifest={archive_size}, "
            f"replay={replay_arch_bytes}"
        )
    if archive_sha256 != replay_arch_sha256:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive sha256 mismatch: manifest={archive_sha256}, "
            f"replay={replay_arch_sha256!r}"
        )

    # ── Validate manifest entries: exact keys, types, duplicates, contiguity ──
    expected_entry_count = range_stop + 1
    if len(entries) != expected_entry_count:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest entries count {len(entries)} != "
            f"stop_height+1 ({expected_entry_count})"
        )

    _ENTRY_KEYS = {"height", "hash", "offset", "payload_length"}
    seen_heights: set[int] = set()
    seen_hashes: set[str] = set()
    expected_offset = 0
    last_index = len(entries) - 1
    magic_bytes = bytes.fromhex(network_magic)

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}] is not an object"
            )
        _require_exact_keys(entry, _ENTRY_KEYS, f"manifest.entries[{index}]")
        entry_height = _require_u32(
            entry["height"], f"manifest.entries[{index}].height"
        )
        entry_hash = _require_hex_str(
            entry["hash"], f"manifest.entries[{index}].hash", 64
        )
        entry_offset = _require_u64(
            entry["offset"], f"manifest.entries[{index}].offset"
        )
        entry_payload_length = _require_u32(
            entry["payload_length"], f"manifest.entries[{index}].payload_length"
        )
        if entry_payload_length < 80 or entry_payload_length > 4_000_000:
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}].payload_length "
                f"{entry_payload_length} out of range [80, 4000000]"
            )

        if entry_height in seen_heights:
            raise AnalyzerError(
                f"CTX-CUSTODY: duplicate height {entry_height} in manifest entries"
            )
        if entry_hash in seen_hashes:
            raise AnalyzerError(
                f"CTX-CUSTODY: duplicate hash {entry_hash} in manifest entries"
            )
        seen_heights.add(entry_height)
        seen_hashes.add(entry_hash)

        if entry_height != range_start + index:
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}].height {entry_height} "
                f"!= expected {range_start + index} (gapped heights)"
            )
        if entry_offset != expected_offset:
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}].offset {entry_offset} "
                f"!= expected {expected_offset} (inconsistent offset)"
            )
        expected_offset = entry_offset + 8 + entry_payload_length
        if index == last_index and expected_offset != archive_size:
            raise AnalyzerError(
                f"CTX-CUSTODY: final frame end {expected_offset} != "
                f"archive.size {archive_size}"
            )

    # ── Single-open archive pass: stream frames, hash incrementally ──
    prev_block_hash_raw: bytes | None = None
    running_hash = hashlib.sha256()
    bytes_consumed = 0

    with archive_path.open("rb") as stream:
        for index, entry in enumerate(entries):
            assert isinstance(entry, dict)
            entry_payload_length = int(entry["payload_length"])
            entry_hash = str(entry["hash"])

            # Read frame header: 4-byte magic + 4-byte LE u32 length.
            frame_header = _read_exact_bytes(
                stream, 8, f"archive frame {index} header", scope="CTX-CUSTODY"
            )
            running_hash.update(frame_header)
            bytes_consumed += 8
            frame_magic = frame_header[0:4]
            frame_length = struct.unpack_from("<I", frame_header, 4)[0]

            if frame_magic != magic_bytes:
                raise AnalyzerError(
                    f"CTX-CUSTODY: archive frame {index} magic "
                    f"{frame_magic.hex()} != manifest network_magic "
                    f"{magic_bytes.hex()} (frame magic mismatch)"
                )
            if frame_length != entry_payload_length:
                raise AnalyzerError(
                    f"CTX-CUSTODY: archive frame {index} length {frame_length} "
                    f"!= manifest payload_length {entry_payload_length} "
                    f"(payload_length mismatch)"
                )

            # Read the 80-byte block header first.
            header_bytes = _read_exact_bytes(
                stream, 80, f"archive frame {index} block header", scope="CTX-CUSTODY"
            )
            running_hash.update(header_bytes)
            bytes_consumed += 80

            # Double-SHA256 of the 80-byte header → internal LE hash.
            hash_raw = hashlib.sha256(
                hashlib.sha256(header_bytes).digest()
            ).digest()
            hash_display = hash_raw[::-1].hex()

            if hash_display != entry_hash:
                raise AnalyzerError(
                    f"CTX-CUSTODY: archive frame {index} header double-SHA256 "
                    f"{hash_display} != manifest hash {entry_hash} "
                    f"(header hash mismatch)"
                )

            # prev_blockhash is bytes 4..36 of the header (internal LE order).
            prev_blockhash = header_bytes[4:36]

            if index == 0:
                if entry_hash != genesis_hash:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: first block hash {entry_hash} != "
                        f"manifest genesis_hash {genesis_hash}"
                    )
                if prev_blockhash != b"\x00" * 32:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: genesis block prev_blockhash is not "
                        f"all-zero (genesis prev_blockhash nonzero: "
                        f"got {prev_blockhash[::-1].hex()})"
                    )
            else:
                if prev_block_hash_raw is None:
                    raise AnalyzerError(
                        "CTX-CUSTODY: internal error: prev_block_hash_raw is None"
                    )
                if prev_blockhash != prev_block_hash_raw:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: block {index} prev_blockhash "
                        f"{prev_blockhash[::-1].hex()} != previous block hash "
                        f"{prev_block_hash_raw[::-1].hex()} (chain break)"
                    )

            # Last block hash must equal replay stop_hash.
            if index == last_index:
                if entry_hash != replay_stop_hash:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: last block hash {entry_hash} != "
                        f"replay stop_hash {replay_stop_hash}"
                    )

            prev_block_hash_raw = hash_raw

            # Consume the remainder of the payload in 64 KiB chunks.
            remaining = entry_payload_length - 80
            chunk_size = 65536
            while remaining > 0:
                to_read = min(remaining, chunk_size)
                chunk = _read_exact_bytes(
                    stream, to_read, f"archive frame {index} payload chunk", scope="CTX-CUSTODY"
                )
                running_hash.update(chunk)
                bytes_consumed += to_read
                remaining -= to_read

        # Archive must be exhausted exactly at archive.size.
        trailing = stream.read(1)
        if trailing:
            raise AnalyzerError(
                f"CTX-CUSTODY: archive has {len(trailing)} trailing byte(s) "
                f"after final frame (trailing bytes)"
            )

    if bytes_consumed != archive_size:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive bytes consumed {bytes_consumed} != "
            f"archive.size {archive_size}"
        )
    computed_sha256 = running_hash.hexdigest()
    if computed_sha256 != archive_sha256:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive streaming sha256 {computed_sha256} != "
            f"manifest archive sha256 {archive_sha256}"
        )

    return {
        "schema": "bitcoin-rs-corpus-manifest",
        "version": version,
        "network": network,
        "network_magic": network_magic,
        "genesis_hash": genesis_hash,
        "range": {"start_height": range_start, "stop_height": range_stop},
        "archive": {"size": archive_size, "sha256": archive_sha256},
        "custody": {
            "bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
    }


def _count_context_records_disk(
    contexts_path: Path,
    records_path: Path,
    journal_path: Path,
    counters: Counters,
    scratch_dir: Path | None = None,
) -> tuple[dict[str, int], int, dict[str, dict[str, int]]]:
    """Join the three native streams using bounded SQLite bulk loading.

    Each evidence stream is parsed and hashed from one open. Rows are inserted
    lazily, so memory is bounded by SQLite's executemany machinery rather than
    the evidence size, and an already-seen duplicate is reported before a later
    malformed row is requested from the iterator.
    """
    counts: dict[str, int] = {name: 0 for name in CONTEXT_COUNTER_NAMES}
    chunk_size = 4096

    if scratch_dir is not None:
        scratch_dir = Path(scratch_dir)
        if not scratch_dir.is_dir():
            raise AnalyzerError(
                f"CTX-EXECUTION: scratch-dir is not a writable directory: {scratch_dir}"
            )
        try:
            with tempfile.NamedTemporaryFile(
                prefix="classify-corpus-write-test-", dir=scratch_dir
            ):
                pass
        except OSError as exc:
            raise AnalyzerError(
                f"CTX-EXECUTION: scratch-dir is not a writable directory: "
                f"{scratch_dir}: {exc}"
            ) from exc

    saved_sqlite_tmpdir = os.environ.get("SQLITE_TMPDIR")
    saved_tmpdir = os.environ.get("TMPDIR")
    if scratch_dir is not None:
        os.environ["SQLITE_TMPDIR"] = str(scratch_dir)
        os.environ["TMPDIR"] = str(scratch_dir)

    conn: sqlite3.Connection | None = None

    def insert_bounded(
        sql: str, rows: Iterator[tuple[object, ...]]
    ) -> int:
        inserted = 0
        exhausted = False
        while not exhausted:
            def next_chunk() -> Iterator[tuple[object, ...]]:
                nonlocal exhausted, inserted
                for _ in range(chunk_size):
                    try:
                        row = next(rows)
                    except StopIteration:
                        exhausted = True
                        return
                    inserted += 1
                    yield row

            conn.executemany(sql, next_chunk())
        return inserted

    try:
        with tempfile.TemporaryDirectory(
            prefix="classify-corpus-", dir=scratch_dir
        ) as tmpdir:
            db_path = Path(tmpdir) / "contexts.db"
            conn = sqlite3.connect(str(db_path))
            try:
                if scratch_dir is not None:
                    conn.execute("PRAGMA temp_store = FILE")
                conn.execute(
                    "CREATE TABLE contexts ("
                    "txid_le BLOB NOT NULL, input_index INTEGER NOT NULL, "
                    "spend_context TEXT NOT NULL, "
                    "PRIMARY KEY(txid_le, input_index)"
                    ") WITHOUT ROWID"
                )
                conn.execute(
                    "CREATE TABLE journal ("
                    "txid_le BLOB NOT NULL, input_index INTEGER NOT NULL, "
                    "checksig_ops INTEGER NOT NULL, checkmultisig_ops INTEGER NOT NULL, "
                    "ecdsa_verify_calls INTEGER NOT NULL, ecdsa_verify_ok INTEGER NOT NULL, "
                    "PRIMARY KEY(txid_le, input_index)"
                    ") WITHOUT ROWID"
                )
                conn.execute(
                    "CREATE TABLE records ("
                    "txid_le BLOB NOT NULL, input_index INTEGER NOT NULL, "
                    "op_seq INTEGER NOT NULL, stream_pos INTEGER NOT NULL, "
                    "op_kind INTEGER NOT NULL, sig_version INTEGER NOT NULL, "
                    "outcome INTEGER NOT NULL, reject_reason INTEGER NOT NULL, "
                    "PRIMARY KEY(txid_le, input_index, op_seq)"
                    ") WITHOUT ROWID"
                )
                conn.execute("CREATE INDEX records_stream_pos ON records(stream_pos)")

                context_iter = iter_context_inputs(contexts_path, dedup=False)

                def context_rows() -> Iterator[tuple[object, ...]]:
                    for evidence in context_iter:
                        classified = classify_input(evidence)
                        yield (
                            evidence.identity.txid_le,
                            evidence.identity.input_index,
                            classified.spend_context.value,
                        )

                try:
                    context_count = insert_bounded(
                        "INSERT INTO contexts VALUES (?, ?, ?)", context_rows()
                    )
                    contexts_custody = context_iter.custody()
                except ContextError as exc:
                    raise AnalyzerError(f"CTX-RAW: BRSCTX1 stream failed: {exc}") from exc
                except sqlite3.IntegrityError as exc:
                    raise AnalyzerError(
                        f"CTX-EXECUTION: duplicate context execution identity in BRSCTX1: {exc}"
                    ) from exc

                journal_iter, journal_custody = iter_journal_with_custody(journal_path)

                def journal_rows() -> Iterator[tuple[object, ...]]:
                    for entry in journal_iter:
                        if entry.verdict != 1:
                            display_txid = entry.spend_txid[::-1].hex()
                            raise AnalyzerError(
                                f"CTX-EXECUTION: journal verdict {entry.verdict} != 1 "
                                f"for txid={display_txid}, input_index={entry.input_index}"
                            )
                        yield (
                            entry.spend_txid,
                            entry.input_index,
                            entry.checksig_ops,
                            entry.checkmultisig_ops,
                            entry.ecdsa_verify_calls,
                            entry.ecdsa_verify_ok,
                        )

                try:
                    journal_count = insert_bounded(
                        "INSERT INTO journal VALUES (?, ?, ?, ?, ?, ?)", journal_rows()
                    )
                except sqlite3.IntegrityError as exc:
                    raise AnalyzerError(
                        f"CTX-EXECUTION: duplicate journal key in BRSJRN1: {exc}"
                    ) from exc

                if context_count != journal_count:
                    raise AnalyzerError(
                        f"CTX-EXECUTION: context count {context_count} != "
                        f"journal count {journal_count}"
                    )
                if context_count != counters.ffi_verify_entries:
                    raise AnalyzerError(
                        f"CTX-EXECUTION: context count {context_count} != "
                        f"counters.ffi_verify_entries {counters.ffi_verify_entries}"
                    )
                if journal_count != counters.ffi_verify_entries:
                    raise AnalyzerError(
                        f"CTX-EXECUTION: journal count {journal_count} != "
                        f"counters.ffi_verify_entries {counters.ffi_verify_entries}"
                    )
                if context_count != counters.context_count:
                    raise AnalyzerError(
                        f"CTX-EXECUTION: context count {context_count} != "
                        f"counters.context_count {counters.context_count}"
                    )
                if journal_count != counters.journal_count:
                    raise AnalyzerError(
                        f"CTX-EXECUTION: journal count {journal_count} != "
                        f"counters.journal_count {counters.journal_count}"
                    )

                missing_journal = conn.execute(
                    "SELECT COUNT(*) FROM ("
                    " SELECT txid_le, input_index FROM contexts"
                    " EXCEPT SELECT txid_le, input_index FROM journal"
                    ")"
                ).fetchone()[0]
                if missing_journal:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: {missing_journal} context key(s) not present in journal"
                    )
                missing_context = conn.execute(
                    "SELECT COUNT(*) FROM ("
                    " SELECT txid_le, input_index FROM journal"
                    " EXCEPT SELECT txid_le, input_index FROM contexts"
                    ")"
                ).fetchone()[0]
                if missing_context:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: {missing_context} journal key(s) not present in contexts"
                    )

                spend_counts = dict(
                    conn.execute(
                        "SELECT spend_context, COUNT(*) FROM contexts GROUP BY spend_context"
                    ).fetchall()
                )
                counts["p2sh_redeem_spends"] = spend_counts.get(SpendContext.P2SH.value, 0)
                counts["native_witness_v0_spends"] = spend_counts.get(
                    SpendContext.NATIVE_WITNESS_V0.value, 0
                )
                counts["p2sh_wrapped_witness_v0_spends"] = spend_counts.get(
                    SpendContext.P2SH_WRAPPED_WITNESS_V0.value, 0
                )
                counts["taproot_key_path_spends"] = spend_counts.get(
                    SpendContext.TAPROOT_KEY_PATH.value, 0
                )
                counts["tapscript_spends"] = spend_counts.get(
                    SpendContext.TAPSCRIPT.value, 0
                )

                record_iter, record_custody = iter_records_with_custody(records_path)

                def record_rows() -> Iterator[tuple[object, ...]]:
                    for stream_pos, record in enumerate(record_iter):
                        yield (
                            record.spend_txid,
                            record.input_index,
                            record.op_seq,
                            stream_pos,
                            record.op_kind,
                            record.sig_version,
                            record.outcome,
                            record.reject_reason,
                        )

                try:
                    record_count = insert_bounded(
                        "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        record_rows(),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: duplicate record key in BRSREC1: {exc}"
                    ) from exc

                # ── Set-based discovery of the earliest per-record semantic failure.
                #    The old streaming loop checked each record in stream order, then
                #    within a record in this priority: orphan, then op_seq sequence,
                #    then op/sig/context legality.  We preserve the same ordering by
                #    selecting the globally earliest (stream_pos, category_priority)
                #    candidate from three bounded LIMIT 1 queries.
                record_failures: list[tuple[int, int, tuple[object, ...], str]] = []

                orphan = conn.execute(
                    "SELECT r.txid_le, r.input_index, r.stream_pos FROM records r "
                    "LEFT JOIN contexts c ON c.txid_le=r.txid_le AND c.input_index=r.input_index "
                    "WHERE c.txid_le IS NULL ORDER BY r.stream_pos LIMIT 1"
                ).fetchone()
                if orphan is not None:
                    record_failures.append((orphan[2], 0, orphan[:2], "orphan"))

                sequence_error = conn.execute(
                    "WITH ordered AS ("
                    " SELECT txid_le, input_index, op_seq, stream_pos,"
                    " ROW_NUMBER() OVER (PARTITION BY txid_le, input_index ORDER BY stream_pos)-1 expected"
                    " FROM records"
                    ") SELECT txid_le, input_index, expected, op_seq, stream_pos FROM ordered"
                    " WHERE op_seq != expected ORDER BY stream_pos LIMIT 1"
                ).fetchone()
                if sequence_error is not None:
                    record_failures.append((sequence_error[4], 1, sequence_error[:4], "sequence"))

                invalid = conn.execute(
                    "WITH classified AS ("
                    " SELECT r.*, c.spend_context, CASE"
                    " WHEN op_kind IN (3,4) AND sig_version NOT IN (0,1) THEN 'multisig_sig'"
                    " WHEN op_kind IN (3,4) AND spend_context='bare' AND sig_version!=0 THEN 'bare_multisig'"
                    " WHEN op_kind IN (3,4) AND spend_context='p2sh' AND sig_version!=0 THEN 'p2sh_multisig'"
                    " WHEN op_kind IN (3,4) AND spend_context='native_witness_v0' AND sig_version!=1 THEN 'native_multisig'"
                    " WHEN op_kind IN (3,4) AND spend_context='p2sh_wrapped_witness_v0' AND sig_version!=1 THEN 'wrapped_multisig'"
                    " WHEN op_kind IN (3,4) AND spend_context IN ('taproot_key_path','tapscript') THEN 'taproot_multisig'"
                    " WHEN op_kind=5 AND sig_version!=2 THEN 'checksigadd_sig'"
                    " WHEN op_kind=5 AND spend_context!='tapscript' THEN 'checksigadd_context'"
                    " WHEN op_kind=0 AND sig_version!=3 THEN 'keypath_sig'"
                    " WHEN op_kind=0 AND spend_context!='taproot_key_path' THEN 'keypath_context'"
                    " WHEN op_kind IN (1,2) AND sig_version=2 AND spend_context!='tapscript' THEN 'tapscript_checksig'"
                    " WHEN op_kind IN (1,2) AND sig_version=1 AND spend_context NOT IN ('native_witness_v0','p2sh_wrapped_witness_v0') THEN 'witness_checksig'"
                    " WHEN op_kind IN (1,2) AND sig_version=0 AND spend_context NOT IN ('bare','p2sh') THEN 'base_checksig'"
                    " WHEN op_kind IN (1,2) AND sig_version NOT IN (0,1,2) THEN 'unknown_checksig'"
                    " WHEN op_kind NOT IN (0,1,2,3,4,5) THEN 'unknown_op' END error_code"
                    " FROM records r JOIN contexts c"
                    " ON c.txid_le=r.txid_le AND c.input_index=r.input_index"
                    ") SELECT txid_le,input_index,op_kind,sig_version,spend_context,error_code,stream_pos"
                    " FROM classified WHERE error_code IS NOT NULL"
                    " ORDER BY stream_pos LIMIT 1"
                ).fetchone()
                if invalid is not None:
                    record_failures.append((invalid[6], 2, invalid[:6], "invalid"))

                if record_failures:
                    record_failures.sort(key=lambda row: (row[0], row[1]))
                    _, _, row, kind = record_failures[0]
                    if kind == "orphan":
                        txid_le, input_index = row
                        raise AnalyzerError(
                            "CTX-OPERATIONS: BRSREC1 record has no matching "
                            f"context identity: txid={txid_le[::-1].hex()}, "
                            f"input_index={input_index}"
                        )
                    if kind == "sequence":
                        txid_le, input_index, expected, actual = row
                        raise AnalyzerError(
                            "CTX-OPERATIONS: op_seq contiguity violation for "
                            f"txid={txid_le[::-1].hex()}, input_index={input_index}: "
                            f"expected {expected}, got {actual}"
                        )
                    # kind == "invalid"
                    txid_le, input_index, op, sig, ctx_name, error_code = row
                    identity = f"txid={txid_le[::-1].hex()}, input_index={input_index}"
                    sig_name = _sig_version_name(sig)
                    if error_code == "multisig_sig":
                        message = f"multisig record must have sig_version BASE or WITNESS_V0, got {sig_name} for {identity}"
                    elif error_code == "bare_multisig":
                        message = f"bare multisig record has sig_version {sig_name}, expected BASE for {identity}"
                    elif error_code == "p2sh_multisig":
                        message = f"P2SH multisig record has sig_version {sig_name}, expected BASE for {identity}"
                    elif error_code == "native_multisig":
                        message = f"native witness-v0 multisig record has sig_version {sig_name}, expected WITNESS_V0 for {identity}"
                    elif error_code == "wrapped_multisig":
                        message = f"P2SH-wrapped witness-v0 multisig record has sig_version {sig_name}, expected WITNESS_V0 for {identity}"
                    elif error_code == "taproot_multisig":
                        message = f"multisig record joined to a Taproot input {identity}"
                    elif error_code == "checksigadd_sig":
                        message = f"CHECKSIGADD record must have sig_version TAPSCRIPT, got {sig_name} for {identity}"
                    elif error_code == "checksigadd_context":
                        message = f"CHECKSIGADD record joined to a non-Tapscript input {identity}"
                    elif error_code == "keypath_sig":
                        message = f"key-path record must have sig_version TAPROOT, got {sig_name} for {identity}"
                    elif error_code == "keypath_context":
                        message = f"key-path record joined to a non-key-path input {identity}"
                    elif error_code == "tapscript_checksig":
                        message = f"Tapscript CHECKSIG record joined to a non-Tapscript input {identity}"
                    elif error_code == "witness_checksig":
                        message = f"WITNESS_V0 CHECKSIG record joined to a non-witness-v0 input {identity}"
                    elif error_code == "base_checksig":
                        message = f"BASE CHECKSIG record joined to a non-legacy input {identity}"
                    elif error_code == "unknown_checksig":
                        message = f"CHECKSIG record has unknown sig_version {sig} for {identity}"
                    else:
                        message = f"unknown op_kind {op} for {identity}"
                    raise AnalyzerError(f"CTX-OPERATIONS: {message}")

                if record_count != counters.record_count:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: BRSREC1 record count {record_count} != "
                        f"counters.record_count {counters.record_count}"
                    )

                gap_count = conn.execute(
                    "SELECT COUNT(*) FROM ("
                    " SELECT txid_le, input_index FROM records"
                    " GROUP BY txid_le, input_index"
                    " HAVING COUNT(*) != MAX(op_seq)+1 OR MIN(op_seq) != 0"
                    ")"
                ).fetchone()[0]
                if gap_count:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: op_seq contiguity proof failed: "
                        f"{gap_count} key(s) with non-contiguous op_seq"
                    )

                record_tallies = conn.execute(
                    "SELECT"
                    " SUM(op_kind IN (3,4) AND spend_context='bare'),"
                    " SUM(op_kind IN (3,4) AND spend_context='p2sh'),"
                    " SUM(op_kind IN (3,4) AND spend_context='native_witness_v0'),"
                    " SUM(op_kind IN (3,4) AND spend_context='p2sh_wrapped_witness_v0'),"
                    " SUM((op_kind=5 OR (op_kind IN (1,2) AND sig_version=2)) AND spend_context='tapscript'),"
                    " SUM(op_kind=5 AND spend_context='tapscript')"
                    " FROM records JOIN contexts USING(txid_le,input_index)"
                ).fetchone()
                for name, value in zip(
                    (
                        "bare_multisig_checks", "p2sh_multisig_checks",
                        "native_witness_v0_multisig_checks",
                        "p2sh_wrapped_witness_v0_multisig_checks",
                        "tapscript_schnorr_checks", "tapscript_checksigadd_checks",
                    ),
                    record_tallies,
                ):
                    counts[name] = value or 0

                aggregate = conn.execute(
                    "SELECT"
                    " SUM(op_kind IN (1,2,3,4) AND sig_version IN (0,1) AND outcome!=2),"
                    " SUM(op_kind IN (1,2,3,4) AND sig_version IN (0,1) AND outcome=1),"
                    " SUM(op_kind IN (1,2,3,4) AND sig_version IN (0,1) AND outcome=0),"
                    " SUM(((op_kind IN (1,2,5) AND sig_version=2) OR (op_kind=0 AND sig_version=3)) AND outcome!=2),"
                    " SUM(((op_kind IN (1,2,5) AND sig_version=2) OR (op_kind=0 AND sig_version=3)) AND outcome=1),"
                    " SUM(((op_kind IN (1,2,5) AND sig_version=2) OR (op_kind=0 AND sig_version=3)) AND outcome=0),"
                    " SUM(op_kind IN (1,2,3,4) AND sig_version IN (0,1)),"
                    " SUM(((op_kind IN (1,2,5) AND sig_version=2) OR (op_kind=0 AND sig_version=3)) AND reject_reason!=8),"
                    " SUM(reject_reason=1), SUM(reject_reason=2), SUM(reject_reason=3)"
                    " FROM records"
                ).fetchone()
                (
                    agg_ecdsa_calls, agg_ecdsa_ok, agg_ecdsa_fail,
                    agg_schnorr_calls, agg_schnorr_ok, agg_schnorr_fail,
                    agg_checkecdsa_entries, agg_checkschnorr_entries,
                    reject_pubkey, reject_empty_sig, reject_missing_data,
                ) = (value or 0 for value in aggregate)

                ecdsa_mismatch = conn.execute(
                    "WITH e AS ("
                    " SELECT txid_le,input_index,"
                    " SUM(outcome!=2) calls,SUM(outcome=1) ok FROM records"
                    " WHERE op_kind IN (1,2,3,4) AND sig_version IN (0,1)"
                    " GROUP BY txid_le,input_index"
                    ") SELECT e.txid_le,e.input_index,e.calls,e.ok,j.ecdsa_verify_calls,j.ecdsa_verify_ok"
                    " FROM e JOIN journal j USING(txid_le,input_index)"
                    " WHERE e.calls!=j.ecdsa_verify_calls OR e.ok!=j.ecdsa_verify_ok LIMIT 1"
                ).fetchone()
                if ecdsa_mismatch is not None:
                    txid_le, input_index, r_calls, r_ok, j_calls, j_ok = ecdsa_mismatch
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: ECDSA mismatch for txid={txid_le[::-1].hex()}, "
                        f"input_index={input_index}: records calls={r_calls} ok={r_ok}, "
                        f"journal calls={j_calls} ok={j_ok}"
                    )
                journal_only_ecdsa = conn.execute(
                    "WITH e AS ("
                    " SELECT txid_le,input_index FROM records"
                    " WHERE op_kind IN (1,2,3,4) AND sig_version IN (0,1)"
                    " GROUP BY txid_le,input_index"
                    ") SELECT j.txid_le,j.input_index,j.ecdsa_verify_calls,j.ecdsa_verify_ok"
                    " FROM journal j LEFT JOIN e USING(txid_le,input_index)"
                    " WHERE (j.ecdsa_verify_calls>0 OR j.ecdsa_verify_ok>0) AND e.txid_le IS NULL"
                    " LIMIT 1"
                ).fetchone()
                if journal_only_ecdsa is not None:
                    txid_le, input_index, _calls, _ok = journal_only_ecdsa
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: journal has ECDSA calls for "
                        f"txid={txid_le[::-1].hex()}, input_index={input_index} "
                        "but no ECDSA records found"
                    )

                sum_checksig, sum_checkmultisig = conn.execute(
                    "SELECT COALESCE(SUM(checksig_ops),0),"
                    " COALESCE(SUM(checkmultisig_ops),0) FROM journal"
                ).fetchone()
                if sum_checksig != counters.op_checksig + counters.op_checksigverify:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: SUM(checksig_ops) {sum_checksig} != "
                        f"op_checksig + op_checksigverify "
                        f"{counters.op_checksig + counters.op_checksigverify}"
                    )
                if sum_checkmultisig != counters.op_checkmultisig + counters.op_checkmultisigverify:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: SUM(checkmultisig_ops) {sum_checkmultisig} != "
                        f"op_checkmultisig + op_checkmultisigverify "
                        f"{counters.op_checkmultisig + counters.op_checkmultisigverify}"
                    )

                reconciliations = (
                    ("ecdsa_verify_calls", agg_ecdsa_calls, counters.ecdsa_verify_calls),
                    ("ecdsa_verify_ok", agg_ecdsa_ok, counters.ecdsa_verify_ok),
                    ("ecdsa_verify_fail", agg_ecdsa_fail, counters.ecdsa_verify_fail),
                    ("schnorr_verify_calls", agg_schnorr_calls, counters.schnorr_verify_calls),
                    ("schnorr_verify_ok", agg_schnorr_ok, counters.schnorr_verify_ok),
                    ("schnorr_verify_fail", agg_schnorr_fail, counters.schnorr_verify_fail),
                    ("checkecdsa_entries", agg_checkecdsa_entries, counters.checkecdsa_entries),
                    ("checkschnorr_entries", agg_checkschnorr_entries, counters.checkschnorr_entries),
                    ("op_checksigadd", counts["tapscript_checksigadd_checks"], counters.op_checksigadd),
                )
                for name, actual, expected in reconciliations:
                    if actual != expected:
                        raise AnalyzerError(
                            f"CTX-OPERATIONS: {name} mismatch: records={actual}, counters={expected}"
                        )
                for name, actual in zip(
                    (
                        "checkecdsa_reject_pubkey",
                        "checkecdsa_reject_empty_sig",
                        "checkecdsa_reject_missing_data",
                    ),
                    (reject_pubkey, reject_empty_sig, reject_missing_data),
                ):
                    expected = getattr(counters, name)
                    if actual != expected:
                        raise AnalyzerError(
                            f"CTX-OPERATIONS: {name} mismatch: records={actual}, counters={expected}"
                        )
                conn.commit()
            finally:
                if conn is not None:
                    conn.close()

    finally:
        if saved_sqlite_tmpdir is not None:
            os.environ["SQLITE_TMPDIR"] = saved_sqlite_tmpdir
        else:
            os.environ.pop("SQLITE_TMPDIR", None)
        if saved_tmpdir is not None:
            os.environ["TMPDIR"] = saved_tmpdir
        else:
            os.environ.pop("TMPDIR", None)

    return counts, context_count, {
        "contexts": contexts_custody,
        "records": record_custody,
        "journal": journal_custody,
    }


def _c150_passed(counts: dict[str, int], counters: Counters) -> bool:
    """Exact C150 product predicate.

    All 11 CONTEXT_COUNTER_NAMES are zero; the six ordinary equality-chain
    counters all equal EXPECTED_FFI_VERIFY_ENTRIES_FULL (2_868_199); all
    complementary counters are zero.

    ``eval_script_entries`` is checked separately and must equal exactly twice
    the canonical total (2 * 2_868_199 == 5_736_398), not the one-times total.
    Every ordinary C150 spend is a bare P2PKH whose VerifyScript runs two
    EvalScript passes -- one over the scriptSig and one over the scriptPubKey --
    so the instrumented kernel emits two EvalScript entries per VerifyScript
    call. It is therefore deliberately excluded from the one-times equality
    tuple and pinned to ``2 * expected`` on its own line.
    """
    # All 11 context counters must be zero
    if any(counts[name] != 0 for name in CONTEXT_COUNTER_NAMES):
        return False
    # Equality chain: all must equal 2_868_199
    expected = EXPECTED_FFI_VERIFY_ENTRIES_FULL
    equality_chain = (
        counters.ffi_verify_entries,
        counters.op_checksig,
        counters.ecdsa_from_checksig,
        counters.checkecdsa_entries,
        counters.ecdsa_verify_calls,
        counters.ecdsa_verify_ok,
    )
    if any(v != expected for v in equality_chain):
        return False
    # eval_script_entries is exactly twice the ordinary total: two EvalScript
    # passes (scriptSig + scriptPubKey) per ordinary P2PKH VerifyScript call.
    if counters.eval_script_entries != 2 * expected:
        return False
    # Complementary counters must be zero
    complementary_zero = (
        counters.op_checksigverify,
        counters.op_checkmultisig,
        counters.op_checkmultisigverify,
        counters.op_checksigadd,
        counters.ecdsa_from_checkmultisig,
        counters.checkecdsa_reject_pubkey,
        counters.checkecdsa_reject_empty_sig,
        counters.checkecdsa_reject_missing_data,
        counters.ecdsa_verify_fail,
        counters.checkschnorr_entries,
        counters.schnorr_verify_calls,
        counters.schnorr_verify_ok,
        counters.schnorr_verify_fail,
    )
    if any(v != 0 for v in complementary_zero):
        return False
    return True


def _cmodern_passed(counts: dict[str, int]) -> bool:
    """Require every context that defines Cmodern to occur at least once."""
    return all(counts[name] > 0 for name in CONTEXT_COUNTER_NAMES)


def cmd_classify_corpus(args: argparse.Namespace) -> int:
    counters_path = Path(args.counters)
    contexts_path = Path(args.contexts)
    records_path = Path(args.records)
    journal_path = Path(args.journal)
    replay_path = Path(args.replay)
    manifest_path = Path(args.corpus_manifest)
    archive_path = Path(args.archive)
    output_path = Path(args.output)

    # ── Parse counters (single read, custody from same buffer) ──
    counters, counters_custody = parse_counters(counters_path)

    # ── Validate replay artifact and corpus manifest/archive ──
    # Each parser computes custody (size + sha256) from the exact buffer it
    # parses, eliminating TOCTOU from a separate prehash pass.
    replay = _validate_replay_artifact(replay_path)
    manifest = _validate_corpus_manifest(manifest_path, archive_path, replay)

    # ── Run disk-backed counter computation (returns custody for ctx/rec/jrn) ──
    counts, context_count, bin_custody = _count_context_records_disk(
        contexts_path, records_path, journal_path, counters,
        Path(args.scratch_dir) if getattr(args, "scratch_dir", None) else None,
    )

    # ── Assemble custody from parser-returned metadata ──
    custody: dict[str, dict[str, object]] = {
        "counters": {
            "path": str(counters_path),
            "bytes": counters_custody["bytes"],
            "sha256": format(counters_custody["sha256"], "064x"),
        },
        "contexts": {
            "path": str(contexts_path),
            "bytes": bin_custody["contexts"]["bytes"],
            "sha256": format(bin_custody["contexts"]["sha256"], "064x"),
        },
        "records": {
            "path": str(records_path),
            "bytes": bin_custody["records"]["bytes"],
            "sha256": format(bin_custody["records"]["sha256"], "064x"),
        },
        "journal": {
            "path": str(journal_path),
            "bytes": bin_custody["journal"]["bytes"],
            "sha256": format(bin_custody["journal"]["sha256"], "064x"),
        },
        "replay": {
            "path": str(replay_path),
            "bytes": replay["custody"]["bytes"],
            "sha256": replay["custody"]["sha256"],
        },
        "corpus_manifest": {
            "path": str(manifest_path),
            "bytes": manifest["custody"]["bytes"],
            "sha256": manifest["custody"]["sha256"],
        },
        "archive": {
            "path": str(archive_path),
            "bytes": manifest["archive"]["size"],
            "sha256": manifest["archive"]["sha256"],
        },
    }

    # ── Counter arithmetic invariants (INV-1 through INV-7) ──
    inv_results = check_counter_arithmetic(counters)
    inv_all_passed = all(r["passed"] for r in inv_results)

    # ── Zero-input evidence precedence: validate counts > 0 before contract logic ──
    if counters.context_count == 0 or counters.journal_count == 0 or counters.record_count == 0:
        raise AnalyzerError(
            "CTX-EXECUTION: zero-input evidence rejected: "
            f"context_count={counters.context_count}, "
            f"journal_count={counters.journal_count}, "
            f"record_count={counters.record_count}"
        )

    # ── Apply c150 / cmodern contract logic ──
    if args.contract == "cmodern":
        if replay["stop_height"] != CMODERN_STOP_HEIGHT:
            raise AnalyzerError(
                f"CTX-CUSTODY: cmodern requires stop_height {CMODERN_STOP_HEIGHT}, "
                f"got {replay['stop_height']}"
            )
        if replay["stop_hash"] != CMODERN_STOP_HASH:
            raise AnalyzerError(
                f"CTX-CUSTODY: cmodern requires stop_hash {CMODERN_STOP_HASH!r}, "
                f"got {replay['stop_hash']!r}"
            )
        all_passed = _cmodern_passed(counts) and inv_all_passed
        contract_result: dict[str, object] = {
            "cmodern_frozen": True,
            "cmodern_passed": all_passed,
        }
    elif args.contract == "c150":
        # c150 pin: stop_height must be exactly 150000 and stop_hash must match.
        if replay["stop_height"] != C150_STOP_HEIGHT:
            raise AnalyzerError(
                f"CTX-CUSTODY: c150 requires stop_height {C150_STOP_HEIGHT}, "
                f"got {replay['stop_height']}"
            )
        if replay["stop_hash"] != C150_STOP_HASH:
            raise AnalyzerError(
                f"CTX-CUSTODY: c150 requires stop_hash {C150_STOP_HASH!r}, "
                f"got {replay['stop_hash']!r}"
            )
        all_passed = _c150_passed(counts, counters) and inv_all_passed
        contract_result = {"c150_passed": all_passed}
    else:
        raise AnalyzerError(
            f"contract must be 'c150' or 'cmodern', got {args.contract!r}"
        )

    # ── Build report ──
    report: dict[str, object] = {
        "schema": "classify-corpus-v2",
        "contract": args.contract,
        "input_count": context_count,
        "context_counts": counts,
        "definitions": CONTEXT_COUNTER_DEFINITIONS,
        "all_passed": all_passed,
        "custody": custody,
        "replay": replay,
        "corpus_manifest": manifest,
        "counter_arithmetic": inv_results,
        **contract_result,
    }

    # Optional cross-check: --input-count if provided.
    input_count_opt = getattr(args, "input_count", None)
    if input_count_opt is not None:
        if input_count_opt != context_count:
            raise AnalyzerError(
                f"CTX-SOURCE: --input-count {input_count_opt} != "
                f"BRSCTX1 context count {context_count}"
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")

    if all_passed:
        print(f"classify-corpus: PASSED — {args.contract}")
        return 0
    print(f"classify-corpus: FAILED — {args.contract}", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description="CHECKSIG census analyzer",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    vc = sub.add_parser("validate-capture", help="validate Run B capture artifacts")
    vc.add_argument("--counters", required=True, help="Run B counters JSON (first run)")
    vc.add_argument("--records", required=True, help="Run B records binary (first run)")
    vc.add_argument("--journal", required=True, help="Run B journal binary (first run)")
    vc.add_argument(
        "--repeat-counters", required=True, help="Run B counters JSON (second run)"
    )
    vc.add_argument(
        "--repeat-records", required=True, help="Run B records binary (second run)"
    )
    vc.add_argument(
        "--repeat-journal", required=True, help="Run B journal binary (second run)"
    )
    vc.add_argument("--output", required=True, help="output validation report JSON")
    vc.add_argument(
        "--sorted-records-output",
        default=None,
        help="optional: write sorted records binary here",
    )
    vc.add_argument(
        "--context-inputs",
        default=None,
        help="optional: census-context-input-v1 JSONL to bind corpus_size and corpus_sha256",
    )
    vc.set_defaults(func=cmd_validate_capture)

    vs = sub.add_parser(
        "validate-census", help="validate Run A census + cross-check with Run B"
    )
    vs.add_argument("--counters", required=True, help="Run A census counters JSON")
    vs.add_argument("--journal", required=True, help="Run A census journal binary")
    vs.add_argument(
        "--capture-journal", required=True, help="Run B capture journal binary"
    )
    vs.add_argument("--output", required=True, help="output validation report JSON")
    vs.set_defaults(func=cmd_validate_census)

    vd = sub.add_parser("verdict", help="compute OPEN/CLOSED/INVALID verdict")
    vd.add_argument(
        "--capture-counters", required=True, help="Run B capture counters JSON"
    )
    vd.add_argument(
        "--bare-runs",
        required=True,
        nargs="+",
        help="exactly three bare-secp timing JSON files (Run C)",
    )
    vd.add_argument(
        "--spike-runs",
        required=True,
        nargs="+",
        help="exactly three spike run JSON files (Run D)",
    )
    vd.add_argument(
        "--current-wall-seconds",
        required=True,
        type=float,
        help="current total replay wall time in seconds",
    )
    vd.add_argument(
        "--current-script-wall-seconds",
        required=True,
        type=float,
        help="current script verification wall time in seconds",
    )
    vd.add_argument("--output", required=True, help="output verdict JSON")
    vd.add_argument(
        "--integrity",
        required=True,
        help="integrity JSON (INV-14 source-identity proof: pubkey.cpp and secp256k1 tree hashes)",
    )
    vd.set_defaults(func=cmd_verdict)

    cc = sub.add_parser(
        "classify-corpus",
        help="classify verified inputs by spend context and join BRSREC1 records (v2)",
    )
    cc.add_argument(
        "--counters",
        required=True,
        help="counters JSON (schema 1) with ffi_verify_entries and record_count",
    )
    cc.add_argument(
        "--contexts",
        required=True,
        help="BRSCTX1 binary context evidence file (one row per verified non-coinbase input)",
    )
    cc.add_argument(
        "--records",
        required=True,
        help="BRSREC1 executed-operation records binary",
    )
    cc.add_argument(
        "--journal",
        required=True,
        help="BRSJRN1 journal binary",
    )
    cc.add_argument(
        "--replay",
        required=True,
        help="mainnet-prefix-replay-v3 JSON artifact",
    )
    cc.add_argument(
        "--corpus-manifest",
        required=True,
        help="bitcoin-rs-corpus-manifest v1 JSON",
    )
    cc.add_argument(
        "--archive",
        required=True,
        help="Core-framed corpus archive binary",
    )
    cc.add_argument(
        "--output",
        required=True,
        help="output classification report JSON",
    )
    cc.add_argument(
        "--contract",
        required=True,
        choices=("c150", "cmodern"),
        help="classification contract: c150 (C150 bare-multisig only) or cmodern (all context counters nonzero)",
    )
    cc.add_argument(
        "--input-count",
        default=None,
        type=int,
        help="optional cross-check: expected BRSCTX1 row count (BRSCTX1 file is authoritative)",
    )
    cc.add_argument(
        "--scratch-dir",
        default=None,
        help="optional writable directory for the classifier database and SQLite temporary files",
    )
    cc.set_defaults(func=cmd_classify_corpus)

    fc = sub.add_parser(
        "find-cmodern-height",
        help="launch a diagnostic replay to find the first mainnet height with all 11 special contexts",
    )
    fc.add_argument("--binary", required=True, help="feature-built mainnet_prefix_replay binary")
    fc.add_argument("--rest-url", required=True, help="frozen REST URL (host:port)")
    fc.add_argument("--stop-height", required=True, type=int, help="safety ceiling (inclusive u32)")
    fc.add_argument("--work-dir", required=True, help="new work directory for BRS streams and scratch state")
    fc.add_argument("--output", required=True, help="candidate output JSON path")
    fc.add_argument("--storage-backend", default="fjall", help="storage backend for replay state")
    fc.add_argument("--txindex", action="store_true", default=False, help="enable txindex")
    fc.set_defaults(func=cmd_find_cmodern_height)
    sc = sub.add_parser(
        "salvage-cmodern-height",
        help="recover terminal Cmodern evidence without changing the failed run",
    )
    sc.add_argument("--source-dir", required=True, help="read-only failed work directory")
    sc.add_argument("--recovery-dir", required=True, help="new directory for committed evidence")
    sc.add_argument("--rest-url", required=True, help="original frozen REST URL (host:port)")
    sc.add_argument("--stop-height", required=True, type=int, help="original safety ceiling")
    sc.add_argument(
        "--data-dir",
        required=True,
        help="exact original data_dir recorded by replay_diagnostic.json",
    )
    sc.add_argument("--output", required=True, help="new candidate output JSON path")
    sc.add_argument("--storage-backend", default="fjall", help="original storage backend")
    sc.add_argument("--txindex", action="store_true", default=False, help="original txindex setting")
    sc.set_defaults(func=cmd_salvage_cmodern_height)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except AnalyzerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyError, ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
