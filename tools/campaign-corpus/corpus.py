#!/usr/bin/env python3
"""Deterministic Core-framed campaign corpus exporter, manifest, and census."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
PRODUCTS_PATH = HERE / "products.json"

MANIFEST_SCHEMA = "bitcoin-rs-corpus-manifest"
MANIFEST_VERSION = 1
MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
HEADER_LEN = 8
MAX_PAYLOAD = 4_000_000
MIN_HEADER = 80
ZERO_SHA256 = "0" * 64

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


def load_freeze(path: Path = PRODUCTS_PATH) -> Freeze:
    raw = _load_json(path)
    if raw.get("schema") != "bitcoin-rs-campaign-corpora-v1":
        raise ContractError("products.json schema is not bitcoin-rs-campaign-corpora-v1")
    magic = bytes.fromhex(_text(raw["network_magic"], "network_magic"))
    specials = tuple(
        _text(item, "census_specials[]") for item in _array(raw["census_specials"], "census_specials")
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
        assume_valid_height=_u32(validation["assume_valid_height"], "assume_valid_height"),
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


def write_frame(payload: bytes, magic: bytes = MAINNET_MAGIC) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ContractError("payload exceeds the 4,000,000-byte consensus maximum")
    return magic + struct.pack("<I", len(payload)) + payload


def read_frames(archive: bytes, magic: bytes = MAINNET_MAGIC) -> list[tuple[FrameMeta, bytes]]:
    records: list[tuple[FrameMeta, bytes]] = []
    offset = 0
    while offset < len(archive):
        remaining = len(archive) - offset
        if remaining < HEADER_LEN:
            raise ContractError("truncated Core frame header")
        got_magic = archive[offset : offset + 4]
        if got_magic != magic:
            raise ContractError("Core frame magic mismatch")
        length = struct.unpack_from("<I", archive, offset + 4)[0]
        if length > MAX_PAYLOAD:
            raise ContractError("Core frame payload exceeds the consensus maximum")
        start = offset + HEADER_LEN
        end = start + length
        if end > len(archive):
            raise ContractError("truncated Core frame payload")
        records.append((FrameMeta(offset=offset, payload_length=length), archive[start:end]))
        offset = end
    return records


def length_prefixed_payloads(blob: bytes) -> list[bytes]:
    payloads: list[bytes] = []
    offset = 0
    while offset < len(blob):
        remaining = len(blob) - offset
        if remaining < 4:
            raise ContractError("truncated length-prefixed header")
        length = struct.unpack_from("<I", blob, offset)[0]
        start = offset + 4
        end = start + length
        if end > len(blob):
            raise ContractError("truncated length-prefixed payload")
        payloads.append(blob[start:end])
        offset = end
    return payloads


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def manifest_digest(document: Mapping[str, object]) -> str:
    preimage = dict(document)
    preimage["manifest_sha256"] = ZERO_SHA256
    return hashlib.sha256(canonical_json(preimage)).hexdigest()


def build_manifest(
    freeze: Freeze,
    corpus_id: str,
    archive: bytes,
    payloads: Sequence[bytes],
) -> dict[str, object]:
    chosen = product(freeze, corpus_id)
    if len(payloads) != chosen.block_count:
        raise ContractError(
            f"{corpus_id} archive has {len(payloads)} blocks, expected {chosen.block_count}"
        )
    entries: list[dict[str, object]] = []
    offset = 0
    for height, payload in enumerate(payloads):
        block_hash = header_block_hash(payload)
        entries.append(
            {
                "height": height,
                "hash": block_hash,
                "offset": offset,
                "payload_length": len(payload),
            }
        )
        offset += HEADER_LEN + len(payload)
    if entries[0]["hash"] != freeze.genesis_hash:
        raise ContractError("archive genesis hash is not mainnet genesis")
    if entries[-1]["hash"] != chosen.stop_hash:
        raise ContractError(f"{corpus_id} stop hash does not match the frozen tip")
    if offset != len(archive):
        raise ContractError("archive size does not match framed payloads")
    document: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "version": MANIFEST_VERSION,
        "corpus_id": corpus_id,
        "network": freeze.network,
        "network_magic": freeze.network_magic.hex(),
        "genesis_hash": freeze.genesis_hash,
        "range": {"start_height": 0, "stop_height": chosen.stop_height},
        "source_tip_hash": chosen.stop_hash,
        "archive": {
            "size": len(archive),
            "sha256": hashlib.sha256(archive).hexdigest(),
        },
        "entries": entries,
        "manifest_sha256": ZERO_SHA256,
    }
    document["manifest_sha256"] = manifest_digest(document)
    return document


def verify_archive(freeze: Freeze, archive: bytes, manifest: Mapping[str, object]) -> Product:
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ContractError("manifest schema is not bitcoin-rs-corpus-manifest")
    if manifest.get("version") != MANIFEST_VERSION:
        raise ContractError("manifest version is not 1")
    if manifest_digest(manifest) != _hash(_text(manifest["manifest_sha256"], "manifest_sha256")):
        raise ContractError("manifest_sha256 does not match the canonical preimage")
    corpus_id = _text(manifest["corpus_id"], "corpus_id")
    chosen = product(freeze, corpus_id)
    if _text(manifest["network"], "network") != freeze.network:
        raise ContractError("manifest network is not mainnet")
    if bytes.fromhex(_text(manifest["network_magic"], "network_magic")) != freeze.network_magic:
        raise ContractError("manifest network magic is not mainnet")
    if _hash(_text(manifest["genesis_hash"], "genesis_hash")) != freeze.genesis_hash:
        raise ContractError("manifest genesis hash is not mainnet genesis")
    range_obj = _object(manifest["range"], "range")
    if range_obj.get("start_height") != 0 or range_obj.get("stop_height") != chosen.stop_height:
        raise ContractError(f"{corpus_id} height range is not genesis through the frozen tip")
    if _hash(_text(manifest["source_tip_hash"], "source_tip_hash")) != chosen.stop_hash:
        raise ContractError(f"{corpus_id} source tip is not the frozen stop hash")
    archive_info = _object(manifest["archive"], "archive")
    if archive_info.get("size") != len(archive):
        raise ContractError("manifest archive size does not match the file")
    if _hash(_text(archive_info["sha256"], "archive.sha256")) != hashlib.sha256(archive).hexdigest():
        raise ContractError("manifest archive sha256 does not match the file")
    frames = read_frames(archive, freeze.network_magic)
    entries = _array(manifest["entries"], "entries")
    if len(frames) != chosen.block_count or len(entries) != chosen.block_count:
        raise ContractError(f"{corpus_id} entry count is not the frozen block count")
    for height, ((meta, payload), entry_raw) in enumerate(zip(frames, entries, strict=True)):
        entry = _object(entry_raw, f"entries[{height}]")
        if entry.get("height") != height:
            raise ContractError("manifest heights are not contiguous from genesis")
        if entry.get("offset") != meta.offset or entry.get("payload_length") != meta.payload_length:
            raise ContractError("manifest offsets do not match the archive frames")
        actual_hash = header_block_hash(payload)
        if _hash(_text(entry["hash"], f"entries[{height}].hash")) != actual_hash:
            raise ContractError("manifest block hash does not match the framed header")
        if height == 0 and actual_hash != freeze.genesis_hash:
            raise ContractError("framed genesis is not mainnet genesis")
        if height == chosen.stop_height and actual_hash != chosen.stop_hash:
            raise ContractError(f"{corpus_id} framed tip is not the frozen stop hash")
    return chosen


def classify_census(freeze: Freeze, corpus_id: str, counters: Mapping[str, object]) -> dict[str, object]:
    chosen = product(freeze, corpus_id)
    specials = {name: _u64(counters.get(name, 0), name) for name in freeze.census_specials}
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
            raise ContractError("Cmodern census requires a positive count for every special context")
        schnorr_entries = _u64(counters.get("checkschnorr_entries", 0), "checkschnorr_entries")
        schnorr_calls = _u64(counters.get("schnorr_verify_calls", 0), "schnorr_verify_calls")
        schnorr_ok = _u64(counters.get("schnorr_verify_ok", 0), "schnorr_verify_ok")
        schnorr_fail = _u64(counters.get("schnorr_verify_fail", 0), "schnorr_verify_fail")
        if schnorr_entries < schnorr_calls:
            raise ContractError("Cmodern Schnorr entries are below verify calls")
        if schnorr_calls != schnorr_ok + schnorr_fail:
            raise ContractError("Cmodern Schnorr verify calls do not equal ok plus fail")
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


def export_payloads(freeze: Freeze, corpus_id: str, payloads: Sequence[bytes]) -> tuple[bytes, dict[str, object]]:
    archive = b"".join(write_frame(payload, freeze.network_magic) for payload in payloads)
    return archive, build_manifest(freeze, corpus_id, archive, payloads)


def export_length_prefixed(freeze: Freeze, corpus_id: str, blob: bytes) -> tuple[bytes, dict[str, object]]:
    return export_payloads(freeze, corpus_id, length_prefixed_payloads(blob))


def rest_fetch(hostport: str, path: str, timeout: float = 30.0) -> bytes:
    host, port = _hostport(hostport)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise ContractError(f"REST {path} returned HTTP {response.status}")
        return body
    finally:
        connection.close()


def export_from_rest(
    freeze: Freeze,
    corpus_id: str,
    hostport: str,
    fetch: Fetch | None = None,
) -> tuple[bytes, dict[str, object]]:
    chosen = product(freeze, corpus_id)
    getter = fetch or (lambda path: rest_fetch(hostport, path))
    payloads: list[bytes] = []
    for height in range(chosen.block_count):
        hash_body = getter(f"/rest/blockhashbyheight/{height}.hex").strip()
        block_hash = _hash(hash_body.decode("ascii"))
        payload = getter(f"/rest/block/{block_hash}.bin")
        if header_block_hash(payload) != block_hash:
            raise ContractError(f"REST block {height} header hash does not match blockhashbyheight")
        payloads.append(payload)
    return export_payloads(freeze, corpus_id, payloads)


def publish(path: Path, data: bytes) -> None:
    if path.exists():
        raise ContractError(f"refusing to replace existing {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_name(path.name + ".tmp")
    if scratch.exists():
        scratch.unlink()
    scratch.write_bytes(data)
    scratch.replace(path)


def c150_state(freeze: Freeze) -> Mapping[str, object]:
    return product(freeze, "C150").state


def core_oracle_params(freeze: Freeze, corpus_id: str) -> list[object]:
    chosen = product(freeze, corpus_id)
    oracle = freeze.core_oracle
    return [oracle["hash_type"], chosen.stop_height, oracle["use_index"]]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    export_cmd = sub.add_parser("export", help="export a frozen corpus from Core REST")
    export_cmd.add_argument("--rest-url", required=True)
    export_cmd.add_argument("--corpus-id", required=True, choices=("C150", "Cmodern"))
    export_cmd.add_argument("--archive", type=Path, required=True)
    export_cmd.add_argument("--manifest", type=Path, required=True)

    convert_cmd = sub.add_parser("convert", help="convert a length-prefixed archive to Core frames")
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

    args = parser.parse_args(argv)
    freeze = load_freeze()
    if args.command == "export":
        archive, manifest = export_from_rest(freeze, args.corpus_id, args.rest_url)
        _write_pair(args.archive, args.manifest, archive, manifest)
    elif args.command == "convert":
        archive, manifest = export_length_prefixed(
            freeze, args.corpus_id, args.length_prefixed.read_bytes()
        )
        _write_pair(args.archive, args.manifest, archive, manifest)
    elif args.command == "verify":
        verify_archive(freeze, args.archive.read_bytes(), _load_json(args.manifest))
        print(f"verified {args.manifest}")
    elif args.command == "classify":
        result = classify_census(freeze, args.contract, _load_json(args.counters))
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


def _write_pair(archive_path: Path, manifest_path: Path, archive: bytes, manifest: Mapping[str, object]) -> None:
    publish(archive_path, archive)
    publish(manifest_path, canonical_json(manifest) + b"\n")
    print(f"wrote {archive_path} ({len(archive)} bytes)")
    print(f"wrote {manifest_path}")
    print(f"archive sha256 {manifest['archive']['sha256']}")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)


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
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 0xFFFFFFFF:
        raise ContractError(f"{label} must be a u32")
    return value


def _u64(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
