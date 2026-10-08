#!/usr/bin/env python3
"""Reference-corpora seed transforms used by import-reference-corpora.sh.

The shell owns acquisition, the byte budget, minimization, and provenance.
This module owns the per-source data extraction and seed emission; every
seed is an upstream byte stream reused directly (decoded hex, a blk.dat
record, a payload body) with no re-framing into harness semantics.

Publication is not a transaction over the corpus and does not claim crash
durability. A refresh inventory removes seeds emitted by the previous run
before importing, so seeds from stale pins cannot survive to be
misattributed to the current pins in generated provenance.

Sources (pins live in the shell driver and in fuzz/CORPUS_PROVENANCE.md):

- btcsuite/btcd: txscript/data vectors (tx_valid.json, tx_invalid.json,
  sighash.json, many_inputs_tx.hex, taproot-ref/* tx fields),
  blockchain/testdata blk*.dat chains and 277647.utxostore.bz2,
  wire/testdata payloads.
- bitcoin/bitcoin: src/test/data vectors (tx_valid.json, tx_invalid.json,
  sighash.json, bip341_wallet_vectors.json, blockfilters.json).
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import json
from pathlib import Path
import sys
from collections.abc import Iterator, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import import_qa_assets as qa


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


def tx_blobs(path: Path) -> Iterator[bytes]:
    """tx_valid/tx_invalid rows -> serialized tx bytes (row[1] hex)."""
    for row in _load_json(path):
        if (
            isinstance(row, list)
            and len(row) >= 2
            and isinstance(row[1], str)
        ):
            blob = _hex(row[1])
            if blob is not None:
                yield blob


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


def bip341_txs(path: Path) -> Iterator[bytes]:
    """bip341_wallet_vectors.json -> unsigned tx bytes."""
    data = _load_json(path)
    for entry in data.get("keyPathSpending", []):
        blob = _hex(entry.get("given", {}).get("rawUnsignedTx"))
        if blob is not None:
            yield blob


def taproot_ref_txs(directory: Path) -> Iterator[bytes]:
    """taproot-ref/*.json -> the `tx` field's serialized tx bytes."""
    for entry in sorted(qa._seed_paths(directory)):
        row = _load_json_prefix(entry)
        if isinstance(row, dict):
            blob = _hex(row.get("tx"))
            if blob is not None:
                yield blob


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
        # sha1 of each emitted seed: the name libFuzzer's merge gives the
        # file if cmin retains it, so the refresh inventory names match the
        # post-minimization basenames on disk.
        self.names: set[str] = set()

    def bump(self, reason: str, by: int = 1) -> None:
        self.counts[reason] = self.counts.get(reason, 0) + by

    def report(self, name: str) -> None:
        detail = " ".join(f"{key}={self.counts[key]}" for key in sorted(self.counts))
        print(f"[import-reference] {name}: {detail}")


def _emit(out: Path, seed: bytes, emitted: Emitted) -> None:
    """Publish the seed and record its content-addressed name."""
    emitted.names.add(hashlib.sha1(seed).hexdigest())
    qa._emit(out, seed)


def _object_seed(out: Path, blob: bytes, max_bytes: int, emitted: Emitted, truncate: bool) -> None:
    if len(blob) > max_bytes:
        if truncate:
            blob = blob[:max_bytes]
        else:
            emitted.bump("skip_oversize")
            return
    _emit(out, blob, emitted)
    emitted.bump("imported")


def map_hex_tx_file(path: Path, out: Path, max_bytes: int, emitted: Emitted) -> None:
    blob = _hex(path.read_text())
    if blob is None:
        emitted.bump("skip_bad_hex")
        return
    _object_seed(out, blob, max_bytes, emitted, truncate=False)


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
        selectors = qa._commands(args.repo_root / "crates/p2p/src/compat.rs")
    except (OSError, ValueError) as error:
        print(f"[import-reference] contract: {error}", file=sys.stderr)
        return 1

    tx_out = args.out_base / "tx_validate"
    block_out = args.out_base / "block_validate"
    p2p_out = args.out_base / "p2p_message"
    snapshot_out = args.out_base / "utxo_snapshot"
    for out in (tx_out, block_out, p2p_out, snapshot_out):
        out.mkdir(parents=True, exist_ok=True)

    # Seeds a previous run imported from earlier pins must not survive a
    # refresh: one that still earns coverage in cmin would be attributed to
    # the new pins in the generated provenance. The inventory tracks only
    # importer-emitted names; fuzzer-discovered and qa-assets seeds are never
    # listed and never removed.
    inventory_path = args.out_base.parent / ".reference-inventory.json"
    prior: dict[str, object] = {}
    if inventory_path.is_file():
        try:
            loaded = json.loads(inventory_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                prior = loaded
        except (OSError, json.JSONDecodeError):
            pass
    for out in (tx_out, block_out, p2p_out, snapshot_out):
        names = prior.get(out.name)
        if not isinstance(names, list):
            continue
        for name in names:
            if isinstance(name, str) and Path(name).name == name:
                (out / name).unlink(missing_ok=True)

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
    emitted_p2p = Emitted()
    emitted_snapshot = Emitted()

    for name in ("tx_valid.json", "tx_invalid.json"):
        for blob in tx_blobs(core_data / name):
            _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)
        for blob in tx_blobs(btcd_data / name):
            _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)
    for blob in sighash_txs(core_data / "sighash.json"):
        _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)
    for blob in sighash_txs(btcd_data / "sighash.json"):
        _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)
    map_hex_tx_file(btcd_data / "many_inputs_tx.hex", tx_out, max_bytes, emitted_tx)
    for blob in bip341_txs(core_data / "bip341_wallet_vectors.json"):
        _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)
    for blob in taproot_ref_txs(btcd_data / "taproot-ref"):
        _object_seed(tx_out, blob, max_bytes, emitted_tx, truncate=False)

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
    emitted_p2p.report("p2p_message")
    emitted_snapshot.report("utxo_snapshot")

    inventory = {
        out.name: sorted(emitted.names)
        for out, emitted in (
            (tx_out, emitted_tx),
            (block_out, emitted_block),
            (p2p_out, emitted_p2p),
            (snapshot_out, emitted_snapshot),
        )
    }
    inventory_path.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
