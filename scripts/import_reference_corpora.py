#!/usr/bin/env python3
"""Reference-corpora seed transforms used by import-reference-corpora.sh.

The shell owns acquisition, the byte budget, minimization, and provenance.
This module owns the per-source data extraction and seed framing. Framing
constants are re-read from the fuzz harness and the script crate at run
time, so a contract change fails closed instead of emitting malformed
seeds. Publication is not a transaction over the corpus and does not claim
crash durability.

Sources (pins live in the shell driver and in fuzz/CORPUS_PROVENANCE.md):

- btcsuite/btcd: txscript/data vectors (script_tests.json, tx_valid.json,
  tx_invalid.json, sighash.json, many_inputs_tx.hex, taproot-ref/*),
  blockchain/testdata blk*.dat chains and 277647.utxostore.bz2,
  wire/testdata payloads.
- bitcoin/bitcoin: src/test/data vectors (script_tests.json, tx_valid.json,
  tx_invalid.json, sighash.json, bip341_wallet_vectors.json,
  blockfilters.json).
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import json
from pathlib import Path
import re
import sys
from collections.abc import Iterator, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import import_qa_assets as qa


# --- Harness contract -------------------------------------------------------


def _harness_const(text: str, name: str) -> int:
    masked = qa._mask_rust_raw_strings(qa._strip_rust_comments(text))
    match = re.search(
        rf"const\s+{name}\s*:\s*(?:usize|u8|u32)\s*=\s*(0x[0-9a-fA-F]+|[0-9_]+)\s*;",
        masked,
    )
    if match is None:
        raise ValueError(f"Cannot find script_eval {name}")
    return int(match.group(1).replace("_", ""), 0)


def script_contract(harness: Path) -> tuple[int, int, int]:
    """(ELEMENT_LEN_MAX, WITNESS_ELEMENTS_MAX, EXPLICIT_FLAGS) from the target."""
    text = harness.read_text()
    return (
        _harness_const(text, "ELEMENT_LEN_MAX"),
        _harness_const(text, "WITNESS_ELEMENTS_MAX"),
        _harness_const(text, "EXPLICIT_FLAGS"),
    )


def flag_bits(script_src: Path) -> dict[str, int]:
    """Core flag name -> bit, mirroring VerifyFlags::from_core_names."""
    text = qa._mask_rust_raw_strings(qa._strip_rust_comments(script_src.read_text()))
    consts: dict[str, int] = {}
    for match in re.finditer(
        r"const\s+([A-Z0-9_]+)\s*:\s*Self\s*=\s*Self\(\s*1\s*<<\s*([0-9]+)\s*\)", text
    ):
        consts[match.group(1)] = 1 << int(match.group(2))
    consts["NONE"] = 0
    start = text.find("fn from_core_names")
    end = text.find("Ok(flags)", start)
    if start < 0 or end < 0:
        raise ValueError("Cannot find VerifyFlags::from_core_names")
    bits: dict[str, int] = {}
    arm = re.compile(r'"([A-Z0-9_]+)"\s*=>\s*\{?\s*Self::([A-Z0-9_]+)')
    for match in arm.finditer(text[start:end]):
        name, const = match.group(1), match.group(2)
        if const not in consts:
            raise ValueError(f"Cannot resolve VerifyFlags::{const} bit")
        bits[name] = consts[const]
    if len(bits) != len(consts):
        raise ValueError("VerifyFlags::from_core_names arm set differs from constants")
    return bits


# Names upstream vectors use that are not VerifyFlags bits. btcd writes
# BADTX on tx_invalid rows where the tx itself is expected to fail, so the
# flag column carries no script semantics; the seed keeps the flag bits at 0
# while the malformed tx is the payload.
PSEUDO_FLAGS = {"BADTX": 0}


# --- Core script assembly (src/test/script_tests.cpp ParseScript) ------------

# Canonical opcode names as mapOpNames resolves them: bare name and its
# OP_-prefixed alias both land here. Generated from Core's opcode table;
# CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY keep the NOP2/NOP3 aliases.
OPCODES: dict[str, int] = {}


def _opcode(byte: int, *names: str) -> None:
    for name in names:
        OPCODES[name] = byte
        OPCODES["OP_" + name] = byte


_opcode(0x61, "NOP")
_opcode(0x62, "VER")
_opcode(0x63, "IF")
_opcode(0x64, "NOTIF")
_opcode(0x65, "VERIF")
_opcode(0x66, "VERNOTIF")
_opcode(0x67, "ELSE")
_opcode(0x68, "ENDIF")
_opcode(0x69, "VERIFY")
_opcode(0x6A, "RETURN")
_opcode(0x6B, "TOALTSTACK")
_opcode(0x6C, "FROMALTSTACK")
_opcode(0x6D, "2DROP")
_opcode(0x6E, "2DUP")
_opcode(0x6F, "3DUP")
_opcode(0x70, "2OVER")
_opcode(0x71, "2ROT")
_opcode(0x72, "2SWAP")
_opcode(0x73, "IFDUP")
_opcode(0x74, "DEPTH")
_opcode(0x75, "DROP")
_opcode(0x76, "DUP")
_opcode(0x77, "NIP")
_opcode(0x78, "OVER")
_opcode(0x79, "PICK")
_opcode(0x7A, "ROLL")
_opcode(0x7B, "ROT")
_opcode(0x7C, "SWAP")
_opcode(0x7D, "TUCK")
_opcode(0x7E, "CAT")
_opcode(0x7F, "SUBSTR")
_opcode(0x80, "LEFT")
_opcode(0x81, "RIGHT")
_opcode(0x82, "SIZE")
_opcode(0x83, "INVERT")
_opcode(0x84, "AND")
_opcode(0x85, "OR")
_opcode(0x86, "XOR")
_opcode(0x87, "EQUAL")
_opcode(0x88, "EQUALVERIFY")
_opcode(0x89, "RESERVED1")
_opcode(0x8A, "RESERVED2")
_opcode(0x8B, "1ADD")
_opcode(0x8C, "1SUB")
_opcode(0x8D, "2MUL")
_opcode(0x8E, "2DIV")
_opcode(0x8F, "NEGATE")
_opcode(0x90, "ABS")
_opcode(0x91, "NOT")
_opcode(0x92, "0NOTEQUAL")
_opcode(0x93, "ADD")
_opcode(0x94, "SUB")
_opcode(0x95, "MUL")
_opcode(0x96, "DIV")
_opcode(0x97, "MOD")
_opcode(0x98, "LSHIFT")
_opcode(0x99, "RSHIFT")
_opcode(0x9A, "BOOLAND")
_opcode(0x9B, "BOOLOR")
_opcode(0x9C, "NUMEQUAL")
_opcode(0x9D, "NUMEQUALVERIFY")
_opcode(0x9E, "NUMNOTEQUAL")
_opcode(0x9F, "LESSTHAN")
_opcode(0xA0, "GREATERTHAN")
_opcode(0xA1, "LESSTHANOREQUAL")
_opcode(0xA2, "GREATERTHANOREQUAL")
_opcode(0xA3, "MIN")
_opcode(0xA4, "MAX")
_opcode(0xA5, "WITHIN")
_opcode(0xA6, "RIPEMD160")
_opcode(0xA7, "SHA1")
_opcode(0xA8, "SHA256")
_opcode(0xA9, "HASH160")
_opcode(0xAA, "HASH256")
_opcode(0xAB, "CODESEPARATOR")
_opcode(0xAC, "CHECKSIG")
_opcode(0xAD, "CHECKSIGVERIFY")
_opcode(0xAE, "CHECKMULTISIG")
_opcode(0xAF, "CHECKMULTISIGVERIFY")
_opcode(0xB0, "NOP1")
_opcode(0xB1, "CHECKLOCKTIMEVERIFY", "NOP2")
_opcode(0xB2, "CHECKSEQUENCEVERIFY", "NOP3")
for _nop in range(0xB3, 0xBA):
    _opcode(_nop, f"NOP{_nop - 0xAF}")
_opcode(0xBA, "CHECKSIGADD")
_opcode(0x50, "RESERVED")
OPCODES["TRUE"] = OPCODES["OP_TRUE"] = 0x51
OPCODES["FALSE"] = OPCODES["OP_FALSE"] = 0x00
OPCODES["INVALIDOPCODE"] = OPCODES["OP_INVALIDOPCODE"] = 0xFF


class AssemblyError(ValueError):
    pass


def _push(data: bytes) -> bytes:
    length = len(data)
    if length < 0x4C:
        return bytes([length]) + data
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + data
    if length <= 0xFFFF:
        return b"\x4d" + length.to_bytes(2, "little") + data
    return b"\x4e" + length.to_bytes(4, "little") + data


def _script_num(number: int) -> bytes:
    """CScriptNum minimal push: OP_0/OP_1NEGATE/OP_N for -1..16 else a push."""
    if number == -1:
        return b"\x4f"
    if number == 0:
        return b"\x00"
    if 1 <= number <= 16:
        return bytes([0x50 + number])
    value = abs(number)
    encoded = bytearray()
    while value:
        encoded.append(value & 0xFF)
        value >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0x80 if number < 0 else 0)
    elif number < 0:
        encoded[-1] |= 0x80
    return _push(bytes(encoded))


# --- BIP341 math for Core's autogenerated taproot rows -----------------------
# script_tests.cpp marks "#TAPROOTOUTPUT#" / "#CONTROLBLOCK#" / "#SCRIPT#".
# The internal key is key0 = scalar 1, i.e. the secp256k1 generator point.

_FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_GROUP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_TAPSCRIPT_LEAF = 0xC0


def _tagged_hash(tag: str, message: bytes) -> bytes:
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + message).digest()


def _point_add(p: tuple[int, int] | None, q: tuple[int, int] | None):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _FIELD_P == 0:
        return None
    if p == q:
        slope = (3 * p[0] * p[0]) * pow(2 * p[1], _FIELD_P - 2, _FIELD_P) % _FIELD_P
    else:
        slope = (q[1] - p[1]) * pow(q[0] - p[0], _FIELD_P - 2, _FIELD_P) % _FIELD_P
    x = (slope * slope - p[0] - q[0]) % _FIELD_P
    return x, (slope * (p[0] - x) - p[1]) % _FIELD_P


def _point_mul(k: int, p: tuple[int, int] | None):
    result = None
    addend = p
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _lift_x(x: int) -> tuple[int, int]:
    """x-only BIP340 key: the point with even Y."""
    y2 = (pow(x, 3, _FIELD_P) + 7) % _FIELD_P
    y = pow(y2, (_FIELD_P + 1) // 4, _FIELD_P)
    if pow(y, 2, _FIELD_P) != y2:
        raise AssemblyError("x-only key is not on secp256k1")
    return x, y if y % 2 == 0 else _FIELD_P - y


def _taproot_key(script: bytes) -> tuple[bytes, int]:
    """P2TR output key for Core's autogenerated rows, plus its parity.

    Single-leaf tree: root = TapLeaf(TAPSCRIPT_LEAF, script), key0 = G.
    """
    leaf = _tagged_hash(
        "TapLeaf", bytes([_TAPSCRIPT_LEAF]) + _compact_size(len(script)) + script
    )
    tweak = int.from_bytes(
        _tagged_hash("TapTweak", _G_X.to_bytes(32, "big") + leaf), "big"
    )
    if tweak >= _GROUP_N:
        raise AssemblyError("TapTweak out of range")
    internal = _lift_x(_G_X)
    output = _point_add(internal, _point_mul(tweak, internal))
    if output is None:
        raise AssemblyError("TapTweak yielded infinity")
    return output[0].to_bytes(32, "big"), output[1] & 1


def _compact_size(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    return b"\xfe" + value.to_bytes(4, "little")


def _compact_read(blob: bytes, pos: int) -> tuple[int, int] | None:
    if pos >= len(blob):
        return None
    prefix = blob[pos]
    if prefix < 0xFD:
        return prefix, pos + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[prefix]
    if pos + 1 + width > len(blob):
        return None
    return int.from_bytes(blob[pos + 1 : pos + 1 + width], "little"), pos + 1 + width


def tx_inputs(tx: bytes) -> list[tuple[bytes, list[bytes]]] | None:
    """Consensus tx bytes -> [(scriptSig, witness stack)] per input, or None
    when the blob does not parse. Witness-less inputs get an empty stack."""
    if len(tx) < 10:
        return None
    pos = 4
    segwit = tx[pos : pos + 2] == b"\x00\x01"
    if segwit:
        pos += 2
    read = _compact_read(tx, pos)
    if read is None:
        return None
    vin_count, pos = read
    inputs: list[tuple[bytes, list[bytes]]] = []
    for _ in range(vin_count):
        pos += 36
        read = _compact_read(tx, pos)
        if read is None:
            return None
        sig_len, pos = read
        if pos + sig_len + 4 > len(tx):
            return None
        inputs.append((tx[pos : pos + sig_len], []))
        pos += sig_len + 4
    read = _compact_read(tx, pos)
    if read is None:
        return None
    vout_count, pos = read
    for _ in range(vout_count):
        pos += 8
        read = _compact_read(tx, pos)
        if read is None:
            return None
        spk_len, pos = read
        pos += spk_len
        if pos > len(tx):
            return None
    if segwit:
        for index in range(vin_count):
            read = _compact_read(tx, pos)
            if read is None:
                return None
            count, pos = read
            elements: list[bytes] = []
            for _ in range(count):
                read = _compact_read(tx, pos)
                if read is None:
                    return None
                length, pos = read
                if pos + length > len(tx):
                    return None
                elements.append(tx[pos : pos + length])
                pos += length
            inputs[index] = (inputs[index][0], elements)
    if pos + 4 > len(tx):
        return None
    return inputs


def assemble(asm: str, taproot_script: bytes | None = None) -> bytes:
    """Core's ParseScript dialect: ints -> CScriptNum pushes, 0x.. -> raw
    bytes, 'x' -> pushed bytes, opcode names -> one opcode byte. The
    "#TAPROOTOUTPUT#" scriptPubKey marker resolves through the caller's
    taproot_script (the last #SCRIPT# witness element)."""
    out = bytearray()
    for word in asm.split():
        if re.fullmatch(r"-?[0-9]+", word):
            out += _script_num(int(word))
        elif word.startswith(("0x", "0X")) and len(word) > 2:
            try:
                out += bytes.fromhex(word[2:])
            except ValueError as error:
                raise AssemblyError(f"invalid hex literal {word!r}") from error
        elif len(word) >= 2 and word.startswith("'") and word.endswith("'"):
            out += _push(word[1:-1].encode())
        elif word == "#TAPROOTOUTPUT#":
            if taproot_script is None:
                raise AssemblyError("#TAPROOTOUTPUT# without #SCRIPT# witness")
            key, _parity = _taproot_key(taproot_script)
            out += key
        else:
            opcode = OPCODES.get(word)
            if opcode is None:
                raise AssemblyError(f"unknown opcode {word!r}")
            out.append(opcode)
    return bytes(out)


# --- Shared row readers ------------------------------------------------------


def _hex(text: object) -> bytes | None:
    if not isinstance(text, str):
        return None
    try:
        return bytes.fromhex(text.strip())
    except ValueError:
        return None


def _load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _load_json_prefix(path: Path) -> object | None:
    """btcd taproot-ref files hold one JSON object with a stray trailing
    delimiter; decode only the leading value."""
    decoder = json.JSONDecoder()
    try:
        value, _end = decoder.raw_decode(path.read_text().lstrip())
    except (OSError, json.JSONDecodeError):
        return None
    return value


def script_rows(path: Path) -> Iterator[tuple[str, str, str, list[str], int | None]]:
    """script_tests.json rows -> (scriptSig asm, scriptPubKey asm, flags,
    witness elements, prevout amount in satoshis or None). Comment rows and
    malformed rows are skipped."""
    for row in _load_json(path):
        if not isinstance(row, list) or len(row) < 4:
            continue
        pos = 0
        witness: list[str] = []
        amount: int | None = None
        if isinstance(row[0], list):
            # Last inner element is the prevout amount in BTC (a float); the
            # rest are hex witness elements or #SCRIPT#/#CONTROLBLOCK# markers.
            witness = [element for element in row[0][:-1] if isinstance(element, str)]
            btc = row[0][-1]
            if isinstance(btc, (int, float)):
                amount = round(btc * 100_000_000)
            pos = 1
        fields = row[pos:]
        if len(fields) < 3 or not all(isinstance(field, str) for field in fields[:3]):
            continue
        yield fields[0], fields[1], fields[2], witness, amount


def tx_rows(path: Path) -> Iterator[tuple[list[tuple[str, int | None]], bytes, str]]:
    """tx_valid/tx_invalid rows -> ((prevout scriptPubKey asm, amount sat or
    None) per input, serialized tx bytes, flag csv)."""
    for row in _load_json(path):
        if (
            isinstance(row, list)
            and len(row) >= 3
            and isinstance(row[0], list)
            and isinstance(row[1], str)
            and isinstance(row[2], str)
        ):
            blob = _hex(row[1])
            prevouts = [
                (
                    entry[2],
                    entry[3] if len(entry) >= 4 and isinstance(entry[3], int) else None,
                )
                for entry in row[0]
                if isinstance(entry, list) and len(entry) >= 3 and isinstance(entry[2], str)
            ]
            if blob is not None:
                yield prevouts, blob, row[2]


def sighash_txs(path: Path) -> Iterator[bytes]:
    """sighash.json rows -> serialized tx bytes."""
    for row in _load_json(path):
        if (
            isinstance(row, list)
            and len(row) >= 5
            and isinstance(row[0], str)
            and isinstance(row[2], int)
        ):
            blob = _hex(row[0])
            if blob is not None:
                yield blob


def bip341_vectors(path: Path) -> tuple[Iterator[bytes], Iterator[bytes]]:
    """(unsigned tx bytes, expected taproot scriptPubKey bytes)."""

    def txs() -> Iterator[bytes]:
        data = _load_json(path)
        for entry in data.get("keyPathSpending", []):
            blob = _hex(entry.get("given", {}).get("rawUnsignedTx"))
            if blob is not None:
                yield blob

    def spks() -> Iterator[bytes]:
        data = _load_json(path)
        for entry in data.get("scriptPubKey", []):
            blob = _hex(entry.get("expected", {}).get("scriptPubKey"))
            if blob is not None:
                yield blob

    return txs(), spks()


def taproot_ref_rows(directory: Path) -> Iterator[dict]:
    for entry in sorted(qa._seed_paths(directory)):
        row = _load_json_prefix(entry)
        if isinstance(row, dict):
            yield row


def _txout_script(txout: bytes) -> bytes | None:
    """TxOut consensus bytes -> scriptPubKey (8-byte value, varint, script)."""
    if len(txout) < 9:
        return None
    prefix = txout[8]
    if prefix < 0xFD:
        length, start = prefix, 9
    elif prefix == 0xFD and len(txout) >= 11:
        length, start = int.from_bytes(txout[9:11], "little"), 11
    elif prefix == 0xFE and len(txout) >= 13:
        length, start = int.from_bytes(txout[9:13], "little"), 13
    else:
        return None
    script = txout[start : start + length]
    return script if len(script) == length else None


def taproot_ref_spend(row: dict) -> tuple[bytes, bytes, list[bytes], str, int] | None:
    """A taproot-ref row -> (scriptPubKey, scriptSig, witness, flags, prevout
    amount in satoshis from the spent TxOut)."""
    index = row.get("index")
    prevouts = row.get("prevouts")
    if not isinstance(index, int) or not isinstance(prevouts, list):
        return None
    if index < 0 or index >= len(prevouts):
        return None
    txout = _hex(prevouts[index])
    if txout is None:
        return None
    script_pubkey = _txout_script(txout)
    flags = row.get("flags")
    spend = row.get("success") or row.get("failure")
    if script_pubkey is None or not isinstance(flags, str) or not isinstance(spend, dict):
        return None
    script_sig = _hex(spend.get("scriptSig", ""))
    witness = spend.get("witness")
    if script_sig is None or not isinstance(witness, list):
        return None
    elements = [_hex(element) for element in witness]
    if any(element is None for element in elements):
        return None
    amount = int.from_bytes(txout[:8], "little")
    return script_pubkey, script_sig, elements, flags, amount  # type: ignore[misc]


def blk_dat_blocks(blob: bytes) -> Iterator[bytes]:
    """Core blk*.dat records -> block bytes. Stops at the first record whose
    leading magic is not the mainnet message start, so trailing zero padding
    is never emitted."""
    pos = 0
    while pos + 8 <= len(blob):
        if blob[pos : pos + 4] != b"\xf9\xbe\xb4\xd9":
            break
        length = int.from_bytes(blob[pos + 4 : pos + 8], "little")
        block = blob[pos + 8 : pos + 8 + length]
        if len(block) != length:
            break
        pos += 8 + length
        yield block


def blockfilter_blocks(path: Path) -> Iterator[bytes]:
    for row in _load_json(path):
        if isinstance(row, list) and len(row) >= 3 and isinstance(row[2], str):
            blob = _hex(row[2])
            if blob is not None:
                yield blob


# --- Seed emitters -----------------------------------------------------------


class Emitted:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def bump(self, reason: str, by: int = 1) -> None:
        self.counts[reason] = self.counts.get(reason, 0) + by

    def report(self, name: str) -> None:
        detail = " ".join(f"{key}={self.counts[key]}" for key in sorted(self.counts))
        print(f"[import-reference] {name}: {detail}")


def _script_seed(
    out: Path,
    flags_bits_map: dict[str, int],
    explicit: int,
    element_limit: int,
    witness_max: int,
    flags: str,
    script_sig: bytes,
    script_pubkey: bytes,
    witness: Sequence[bytes],
    amount_sat: int | None,
    max_bytes: int,
    emitted: Emitted,
) -> None:
    try:
        bits = 0
        for name in flags.split(","):
            name = name.strip()
            if not name or name == "NONE":
                continue
            bit = flags_bits_map.get(name, PSEUDO_FLAGS.get(name))
            if bit is None:
                raise AssemblyError(name)
            bits |= bit
    except AssemblyError as error:
        emitted.bump(f"skip_unknown_flag_{error}")
        return
    cap = min(element_limit, 0xFFFF)
    if len(witness) > witness_max:
        # Truncating would drop the taproot script/control block tail, so the
        # row is skipped rather than reframed into a different spend.
        emitted.bump("skip_witness_overflow")
        return
    # Cutting an oversized script or witness element mid-push would reframe
    # the row into a different spend, so the row is skipped rather than
    # truncated; the u16 wire bound covers every upstream element today.
    if (
        len(script_sig) > cap
        or len(script_pubkey) > cap
        or any(len(element) > cap for element in witness)
    ):
        emitted.bump("skip_element_overflow")
        return
    frame = bytearray([explicit])
    frame += bits.to_bytes(4, "little")
    frame += len(script_sig).to_bytes(2, "little") + script_sig
    frame += len(script_pubkey).to_bytes(2, "little") + script_pubkey
    frame.append(len(witness))
    for element in witness:
        frame += len(element).to_bytes(2, "little") + element
    if amount_sat is not None:
        frame += amount_sat.to_bytes(8, "little")
    if len(frame) > max_bytes:
        emitted.bump("skip_oversize")
        return
    qa._emit(out, bytes(frame))
    emitted.bump("imported")


def _object_seed(out: Path, blob: bytes, max_bytes: int, emitted: Emitted, truncate: bool) -> None:
    if len(blob) > max_bytes:
        if truncate:
            blob = blob[:max_bytes]
        else:
            emitted.bump("skip_oversize")
            return
    qa._emit(out, blob)
    emitted.bump("imported")


# --- Source mappers ----------------------------------------------------------


def map_script_tests(
    path: Path,
    out: Path,
    flags_bits_map: dict[str, int],
    contract: tuple[int, int, int],
    max_bytes: int,
    emitted: Emitted,
) -> None:
    element_limit, witness_max, explicit = contract
    for script_sig_asm, script_pubkey_asm, flags, witness_raw, amount in script_rows(path):
        witness: list[bytes] = []
        last_script: bytes | None = None
        try:
            for element in witness_raw:
                if element.startswith("#SCRIPT#"):
                    last_script = assemble(element[len("#SCRIPT#"):])
                    witness.append(last_script)
                elif element == "#CONTROLBLOCK#":
                    if last_script is None:
                        raise AssemblyError("#CONTROLBLOCK# without #SCRIPT#")
                    _key, parity = _taproot_key(last_script)
                    witness.append(
                        bytes([_TAPSCRIPT_LEAF | parity]) + _G_X.to_bytes(32, "big")
                    )
                else:
                    blob = _hex(element)
                    if blob is None:
                        raise AssemblyError(f"bad witness element {element!r}")
                    witness.append(blob)
            script_sig = assemble(script_sig_asm)
            script_pubkey = assemble(script_pubkey_asm, last_script)
        except AssemblyError as error:
            emitted.bump(f"skip_asm_{str(error)[:24]}")
            continue
        _script_seed(
            out, flags_bits_map, explicit, element_limit, witness_max,
            flags, script_sig, script_pubkey, witness, amount, max_bytes, emitted,
        )


def map_taproot_ref(
    directory: Path,
    tx_out: Path,
    script_out: Path,
    flags_bits_map: dict[str, int],
    contract: tuple[int, int, int],
    max_bytes: int,
    tx_emitted: Emitted,
    script_emitted: Emitted,
) -> None:
    element_limit, witness_max, explicit = contract
    for row in taproot_ref_rows(directory):
        blob = _hex(row.get("tx"))
        if blob is not None:
            _object_seed(tx_out, blob, max_bytes, tx_emitted, truncate=False)
        spend = taproot_ref_spend(row)
        if spend is None:
            script_emitted.bump("skip_malformed_spend")
            continue
        script_pubkey, script_sig, witness, flags, amount = spend
        _script_seed(
            script_out, flags_bits_map, explicit, element_limit, witness_max,
            flags, script_sig, script_pubkey, witness, amount, max_bytes, script_emitted,
        )


def map_tx_rows(
    path: Path,
    tx_out: Path,
    script_out: Path,
    flags_bits_map: dict[str, int],
    contract: tuple[int, int, int],
    max_bytes: int,
    tx_emitted: Emitted,
    script_emitted: Emitted,
) -> None:
    """Each row seeds tx_validate with the tx bytes and script_eval with one
    frame per parseable input: its scriptSig, the matching prevout
    scriptPubKey, and the input's witness stack."""
    element_limit, witness_max, explicit = contract
    for prevouts, blob, flags in tx_rows(path):
        _object_seed(tx_out, blob, max_bytes, tx_emitted, truncate=False)
        parsed = tx_inputs(blob)
        if parsed is None:
            script_emitted.bump("skip_unparsed_tx")
            continue
        for (script_sig, witness), (prevout, amount) in zip(parsed, prevouts):
            try:
                script_pubkey = assemble(prevout)
            except AssemblyError as error:
                script_emitted.bump(f"skip_asm_{str(error)[:24]}")
                continue
            _script_seed(
                script_out, flags_bits_map, explicit, element_limit, witness_max,
                flags, script_sig, script_pubkey, witness, amount, max_bytes, script_emitted,
            )


def map_hex_tx_file(path: Path, out: Path, max_bytes: int, emitted: Emitted) -> None:
    blob = _hex(path.read_text())
    if blob is None:
        emitted.bump("skip_bad_hex")
        return
    _object_seed(out, blob, max_bytes, emitted, truncate=False)


def map_bip341(
    path: Path,
    tx_out: Path,
    script_out: Path,
    flags_bits_map: dict[str, int],
    contract: tuple[int, int, int],
    max_bytes: int,
    tx_emitted: Emitted,
    script_emitted: Emitted,
) -> None:
    txs, spks = bip341_vectors(path)
    for blob in txs:
        _object_seed(tx_out, blob, max_bytes, tx_emitted, truncate=False)
    element_limit, witness_max, explicit = contract
    for spk in spks:
        _script_seed(
            script_out, flags_bits_map, explicit, element_limit, witness_max,
            "TAPROOT", b"", spk, [], None, max_bytes, script_emitted,
        )


def map_dat(blob: bytes, out: Path, max_bytes: int, emitted: Emitted) -> None:
    for block in blk_dat_blocks(blob):
        _object_seed(out, block, max_bytes, emitted, truncate=False)


def map_payload(
    blob: bytes, command: str, selectors: dict[str, bytes], out: Path, max_bytes: int, emitted: Emitted
) -> None:
    selector = selectors.get(command)
    if selector is None:
        emitted.bump(f"no_command_{command}")
        return
    _object_seed(out, selector + blob[: max_bytes - 1], max_bytes, emitted, truncate=False)


def _bz2(path: Path) -> bytes:
    with path.open("rb") as stream:
        return bz2.decompress(stream.read())


# --- Driver ------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--btcd", required=True, type=Path)
    parser.add_argument("--bitcoin", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--out-base", required=True, type=Path)
    parser.add_argument("--max-seed-bytes", required=True, type=int)
    args = parser.parse_args(argv)
    max_bytes = args.max_seed_bytes

    try:
        contract = script_contract(
            args.repo_root / "fuzz/fuzz_targets/script_eval.rs"
        )
        flags_bits_map = flag_bits(
            args.repo_root / "crates/script/src/interpreter.rs"
        )
        selectors = qa._commands(args.repo_root / "crates/p2p/src/compat.rs")
    except (OSError, ValueError) as error:
        print(f"[import-reference] contract: {error}", file=sys.stderr)
        return 1

    tx_out = args.out_base / "tx_validate"
    block_out = args.out_base / "block_validate"
    script_out = args.out_base / "script_eval"
    p2p_out = args.out_base / "p2p_message"
    snapshot_out = args.out_base / "utxo_snapshot"
    for out in (tx_out, block_out, script_out, p2p_out, snapshot_out):
        out.mkdir(parents=True, exist_ok=True)

    btcd_data = args.btcd / "txscript/data"
    btcd_blocks = args.btcd / "blockchain/testdata"
    btcd_wire = args.btcd / "wire/testdata"
    core_data = args.bitcoin / "src/test/data"
    for required in (btcd_data, btcd_blocks, btcd_wire, core_data):
        if not required.is_dir():
            print(f"[import-reference] missing source dir: {required}", file=sys.stderr)
            return 1

    emitted_tx = Emitted()
    emitted_block = Emitted()
    emitted_script = Emitted()
    emitted_p2p = Emitted()
    emitted_snapshot = Emitted()

    for name in ("tx_valid.json", "tx_invalid.json"):
        map_tx_rows(
            core_data / name,
            tx_out, script_out, flags_bits_map, contract, max_bytes,
            emitted_tx, emitted_script,
        )
        map_tx_rows(
            btcd_data / name,
            tx_out, script_out, flags_bits_map, contract, max_bytes,
            emitted_tx, emitted_script,
        )
    for name in ("sighash.json",):
        for blob in sighash_txs(core_data / name):
            _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)
        for blob in sighash_txs(btcd_data / name):
            _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)
    map_hex_tx_file(btcd_data / "many_inputs_tx.hex", tx_out, max_bytes, emitted_tx)
    map_bip341(
        core_data / "bip341_wallet_vectors.json",
        tx_out, script_out, flags_bits_map, contract, max_bytes,
        emitted_tx, emitted_script,
    )

    map_taproot_ref(
        btcd_data / "taproot-ref",
        tx_out, script_out, flags_bits_map, contract, max_bytes,
        emitted_tx, emitted_script,
    )
    map_script_tests(
        core_data / "script_tests.json",
        script_out, flags_bits_map, contract, max_bytes, emitted_script,
    )
    map_script_tests(
        btcd_data / "script_tests.json",
        script_out, flags_bits_map, contract, max_bytes, emitted_script,
    )

    map_dat((btcd_blocks / "blk_0_to_14131.dat").read_bytes(), block_out, max_bytes, emitted_block)
    for name in ("blk_0_to_4.dat.bz2", "blk_3A.dat.bz2", "blk_4A.dat.bz2", "blk_5A.dat.bz2"):
        map_dat(_bz2(btcd_blocks / name), block_out, max_bytes, emitted_block)
    # A single 149 KiB mainnet block: over the seed bound, kept as a p2p payload below.
    map_dat(_bz2(btcd_blocks / "277647.dat.bz2"), block_out, max_bytes, emitted_block)
    for blob in blockfilter_blocks(core_data / "blockfilters.json"):
        _object_seed(block_out, blob, max_bytes, emitted_block, truncate=False)

    # btcd wire testdata is all over the seed bound; payloads are truncated to
    # the bound because a p2p decoder must accept arbitrary prefixes.
    map_payload(_bz2(btcd_wire / "megatx.bin.bz2"), "tx", selectors, p2p_out, max_bytes, emitted_p2p)
    for path in sorted(btcd_wire.glob("*.blk")):
        map_payload(path.read_bytes(), "block", selectors, p2p_out, max_bytes, emitted_p2p)
    for block in blk_dat_blocks(_bz2(btcd_blocks / "277647.dat.bz2")):
        map_payload(block, "block", selectors, p2p_out, max_bytes, emitted_p2p)

    # btcd's serialized utxo store is a foreign-format negative seed for the
    # strict v4 snapshot decoder.
    _object_seed(snapshot_out, _bz2(btcd_blocks / "277647.utxostore.bz2"), max_bytes, emitted_snapshot, truncate=True)

    emitted_tx.report("tx_validate")
    emitted_block.report("block_validate")
    emitted_script.report("script_eval")
    emitted_p2p.report("p2p_message")
    emitted_snapshot.report("utxo_snapshot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
