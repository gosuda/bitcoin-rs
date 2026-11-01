#!/usr/bin/env python3
"""Emit comparator config documents from staged campaign custody.

One command per comparator kind reads a staged custody directory, hashes
the artifacts through the comparators' own no-follow streaming reader,
and writes the exact config document that comparator parses:

- ``offline`` writes ``offline-full-validation-config-v1`` and validates
  it with ``offline_full_validation.parse_config``.
- ``p2p`` projects the custody archive records into Bitcoin network
  ``block`` frames, writes ``p2p-loopback-config-v1``, and validates it
  with ``p2p_loopback.parse_config``. The comparator's 16 MiB corpus and
  4,096-step bounds apply, so a large corpus refuses here exactly as it
  would at campaign time.
- ``muhash`` writes ``muhash-rpc-campaign-config-v2`` plus one frozen
  state document beside it, and validates the config with
  ``muhash_rpc._parse_campaign_config``.

Custody layout::

    <custody-root>/products.json
    <custody-root>/corpora/<corpus-id>.archive.bin
    <custody-root>/corpora/<corpus-id>.manifest.json
    <custody-root>/corpora/acquisition-record.json
    <custody-root>/rpc.cookie                       (muhash only)

``products.json`` is the producer registry parsed by ``corpus.load_freeze``.
The acquisition record is the custody pin document; the digest pins are
file SHA-256 identities, and every pin below is required::

    {"schema": "bitcoin-rs-custody-acquisition-record-v1",
     "oracle": {"implementation": "Bitcoin Core 31.1",
                "sha256": "<64 hex>"},
     "campaign": {"affinity": "<cpu list>"},
     "corpora": {"<corpus-id>": {
         "archive_sha256": "<64 hex>",
         "manifest_sha256": "<64 hex>",
         "certified_state": {"utxo_hash_serialized_3": "<64 hex>",
                             "bodies_available": true,
                             "disconnect_ready": true},
         "frozen_rpc_state": {"transactions": <n>, "bogosize": <n>,
                              "disk_size": <n>}}}}

A missing input identity is ``BLOCKED``: the emitter prints
``BLOCKED: <identity>`` on stderr, exits 2, and writes nothing. Missing
covers a absent file, an unknown corpus id, and a digest pin that the
record does not carry. A present but incoherent input (digest mismatch,
symlink or non-regular artifact, unknown schema, registry disagreement)
raises ``ContractError``, exits 2, and writes nothing.

Publication reuses the sibling atomic ``O_TMPFILE`` plus ``linkat``
helpers. Each emitted document is accepted by the owning comparator
parser before any byte is published, and existing output paths refuse.

Constants this emitter owns: the offline arm timeout is the comparator
ceiling and the offline posture is the one certified cache policy with
every auxiliary index off; the loopback peer speaks protocol 70016 with
services ``NETWORK | WITNESS`` at the comparator connect and I/O
ceilings; the muhash campaign uses the ``process-cold/
page-cache-unspecified`` policy with no eviction procedure at the
300-second ceiling, and the bitcoin-rs arm declares the ``fjall``
backend. The arm command templates follow the placeholder contracts the
comparators enforce; the offline template uses the documented harness
argument family (``--data-dir/--corpus/--manifest/--state`` with
assume-valid off), so a Bitcoin Core arm needs the state-writing wrapper
that the certified-state gate already requires of both arms.
"""

import argparse
import hashlib
import os
import struct
import sys
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAMPAIGN_TOOLS = HERE.parent / "benchmark-campaign"
if str(CAMPAIGN_TOOLS) not in sys.path:
    sys.path.insert(0, str(CAMPAIGN_TOOLS))

import corpus
import muhash_rpc
import offline_full_validation as offline
import p2p_loopback
from evidence import ContractError, JsonObject, canonical_bytes, publish_result

CONTRACT_ERRORS = (
    ContractError,
    corpus.ContractError,
    muhash_rpc.ContractError,
)

PRODUCTS_NAME = "products.json"
CORPORA_DIRNAME = "corpora"
ACQUISITION_RECORD_NAME = "acquisition-record.json"
CREDENTIAL_NAME = "rpc.cookie"
ARCHIVE_SUFFIX = ".archive.bin"
MANIFEST_SUFFIX = ".manifest.json"
FROZEN_STATE_SUFFIX = ".frozen-state.json"
ACQUISITION_SCHEMA = "bitcoin-rs-custody-acquisition-record-v1"
ACQUISITION_RECORD_LIMIT = offline.MAX_CONFIG_BYTES
CERTIFIED_STATE_KEYS = (
    "utxo_hash_serialized_3",
    "bodies_available",
    "disconnect_ready",
)
FROZEN_RPC_STATE_KEYS = ("transactions", "bogosize", "disk_size")
SATOSHI_PER_COIN = 100_000_000
OFFLINE_CACHE_POLICY = sorted(offline.CACHE_POLICIES)[0]
P2P_PROTOCOL_VERSION = 70016
P2P_SERVICES_NETWORK_WITNESS = 5
P2P_SOCKET_BUFFER_BYTES = 262_144
P2P_BLOCK_COMMAND = b"block"
MUHASH_POLICY = "process-cold/page-cache-unspecified"
MUHASH_CANDIDATE_BACKEND = "fjall"
MUHASH_TIMEOUT_SECONDS = 300
OFFLINE_COMMAND: tuple[str, ...] = (
    "{binary}",
    "--data-dir",
    "{data_dir}",
    "--corpus",
    "{corpus_path}",
    "--manifest",
    "{manifest_path}",
    "--state",
    "{state_path}",
    "--assume-valid-height=0",
)
P2P_COMMAND: tuple[str, ...] = (
    "{binary}",
    "--data-dir",
    "{data_dir}",
    "--peer-host",
    "{peer_host}",
    "--peer-port",
    "{peer_port}",
    "--state-path",
    "{state_path}",
)
MUHASH_COMMAND: tuple[str, ...] = (
    "{binary}",
    "--bind",
    "{rpc_bind}",
    "--port",
    "{rpc_port}",
    "--cookie",
    "{cookie}",
    "--config",
    "{config}",
    "--data-dir",
    "{data_dir}",
)


class EmitterBlocked(Exception):
    """A required custody identity is missing, so the cell is BLOCKED."""

    def __init__(self, identity: str) -> None:
        super().__init__(identity)
        self.identity = identity


@dataclass(frozen=True)
class RegistryState:
    """The certified tip identity the producer registry carries."""

    height: int
    bestblock: str
    txouts: int
    total_amount_sat: int
    muhash: str


@dataclass(frozen=True)
class ManifestEntry:
    """One validated producer manifest entry in archive order."""

    height: int
    block_hash: str
    offset: int
    payload_length: int


@dataclass(frozen=True)
class Custody:
    """Verified custody paths, fresh artifact identities, and documents."""

    root: Path
    freeze: corpus.Freeze
    product: corpus.Product
    archive_path: Path
    manifest_path: Path
    archive_info: os.stat_result
    archive_sha256: str
    manifest_info: os.stat_result
    manifest_sha256: str
    manifest: JsonObject
    record: JsonObject


@dataclass(frozen=True)
class Arms:
    """Fresh no-follow identities of the two pinned arm binaries."""

    oracle_path: Path
    oracle_sha256: str
    candidate_path: Path
    candidate_sha256: str


def _mapping(value: object, field: str) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ContractError(f"{field} must be a JSON object")
    return value


def _require(value: JsonObject, keys: tuple[str, ...], field: str) -> None:
    for key in keys:
        if key not in value:
            raise ContractError(f"{field} is incomplete")


def _load_custody(args: argparse.Namespace) -> Custody:
    root = args.custody_root.absolute()
    products = root / PRODUCTS_NAME
    if not products.is_file():
        raise EmitterBlocked("products registry")
    freeze = corpus.load_freeze(products)
    try:
        product = corpus.product(freeze, args.corpus_id)
    except CONTRACT_ERRORS:
        raise EmitterBlocked(f"corpus {args.corpus_id}") from None
    corpora = root / CORPORA_DIRNAME
    archive_path = corpora / f"{args.corpus_id}{ARCHIVE_SUFFIX}"
    manifest_path = corpora / f"{args.corpus_id}{MANIFEST_SUFFIX}"
    record_path = corpora / ACQUISITION_RECORD_NAME
    if not archive_path.is_file():
        raise EmitterBlocked("corpus archive")
    if not manifest_path.is_file():
        raise EmitterBlocked("corpus manifest")
    if not record_path.is_file():
        raise EmitterBlocked("custody acquisition record")
    archive_info, archive_sha256 = offline._hash_regular(archive_path, "corpus archive")
    manifest_info, manifest_sha256 = offline._hash_regular(
        manifest_path, "corpus manifest"
    )
    manifest = _mapping(
        offline._load_json(manifest_path, "corpus manifest", offline.MAX_MANIFEST_BYTES),
        "corpus manifest",
    )
    record = _mapping(
        offline._load_json(record_path, "acquisition record", ACQUISITION_RECORD_LIMIT),
        "acquisition record",
    )
    if record.get("schema") != ACQUISITION_SCHEMA:
        raise ContractError(f"acquisition record schema must be {ACQUISITION_SCHEMA}")
    return Custody(
        root=root,
        freeze=freeze,
        product=product,
        archive_path=archive_path.absolute(),
        manifest_path=manifest_path.absolute(),
        archive_info=archive_info,
        archive_sha256=archive_sha256,
        manifest_info=manifest_info,
        manifest_sha256=manifest_sha256,
        manifest=manifest,
        record=record,
    )


def _check_manifest_identity(custody: Custody) -> JsonObject:
    manifest = custody.manifest
    _require(
        manifest,
        (
            "schema",
            "version",
            "corpus_id",
            "network",
            "network_magic",
            "genesis_hash",
            "range",
            "source_tip_hash",
            "archive",
            "manifest_sha256",
            "entries",
        ),
        "corpus manifest",
    )
    if (
        offline._text(manifest["schema"], "corpus manifest.schema")
        != corpus.MANIFEST_SCHEMA
        or offline._uint(manifest["version"], "corpus manifest.version")
        != corpus.MANIFEST_VERSION
    ):
        raise ContractError(
            f"corpus manifest schema must be {corpus.MANIFEST_SCHEMA} "
            f"at version {corpus.MANIFEST_VERSION}"
        )
    if (
        offline._text(manifest["corpus_id"], "corpus manifest.corpus_id")
        != custody.product.corpus_id
    ):
        raise ContractError("corpus manifest corpus_id does not match the request")
    if offline._text(manifest["network"], "corpus manifest.network") != custody.freeze.network:
        raise ContractError("corpus manifest network does not match the registry")
    if (
        offline._magic(manifest["network_magic"], "corpus manifest.network_magic")
        != custody.freeze.network_magic
    ):
        raise ContractError("corpus manifest network magic does not match the registry")
    if (
        offline._hash(manifest["genesis_hash"], "corpus manifest.genesis_hash")
        != custody.freeze.genesis_hash
    ):
        raise ContractError("corpus manifest genesis hash does not match the registry")
    range_value = _mapping(manifest["range"], "corpus manifest.range")
    _require(range_value, ("start_height", "stop_height"), "corpus manifest.range")
    start = offline._uint(range_value["start_height"], "corpus manifest.range.start_height")
    stop = offline._uint(range_value["stop_height"], "corpus manifest.range.stop_height")
    if stop != custody.product.stop_height or stop - start + 1 != custody.product.block_count:
        raise ContractError("corpus manifest range does not match the registry")
    if (
        offline._hash(manifest["source_tip_hash"], "corpus manifest.source_tip_hash")
        != custody.product.stop_hash
    ):
        raise ContractError("corpus manifest stop hash does not match the registry")
    archive_value = _mapping(manifest["archive"], "corpus manifest.archive")
    _require(archive_value, ("sha256", "size"), "corpus manifest.archive")
    manifest_archive_sha256 = offline._hash(
        archive_value["sha256"], "corpus manifest.archive.sha256"
    )
    manifest_archive_size = offline._uint(
        archive_value["size"],
        "corpus manifest.archive.size",
        offline.MAX_ARCHIVE_BYTES,
    )
    if (
        manifest_archive_sha256 != custody.archive_sha256
        or manifest_archive_size != custody.archive_info.st_size
    ):
        raise ContractError("archive digest does not match the custody manifest")
    return manifest


def _manifest_entries(custody: Custody) -> list[ManifestEntry]:
    raw = custody.manifest["entries"]
    if not isinstance(raw, list):
        raise ContractError("corpus manifest.entries must be an array")
    if len(raw) != custody.product.block_count:
        raise ContractError("corpus manifest entry count does not match the registry")
    entries: list[ManifestEntry] = []
    cursor = 0
    for index, item in enumerate(raw):
        field = f"corpus manifest.entries[{index}]"
        entry = _mapping(item, field)
        _require(entry, ("hash", "height", "offset", "payload_length"), field)
        height = offline._uint(entry["height"], f"{field}.height")
        if height != index:
            raise ContractError("corpus manifest heights are not contiguous from zero")
        offset = offline._uint(entry["offset"], f"{field}.offset", offline.MAX_ARCHIVE_BYTES)
        payload_length = offline._uint(
            entry["payload_length"], f"{field}.payload_length", offline.MAX_PAYLOAD_BYTES
        )
        if payload_length < offline.HEADER_BYTES:
            raise ContractError(f"{field} payload is shorter than a header")
        if offset != cursor:
            raise ContractError(f"{field} offset is not packed")
        cursor += 8 + payload_length
        entries.append(
            ManifestEntry(
                height,
                offline._hash(entry["hash"], f"{field}.hash"),
                offset,
                payload_length,
            )
        )
    if cursor != custody.archive_info.st_size:
        raise ContractError("corpus manifest does not consume the archive exactly")
    return entries


def _record_corpus(record: JsonObject, corpus_id: str) -> JsonObject:
    corpora = record.get("corpora")
    if not isinstance(corpora, dict) or not all(isinstance(key, str) for key in corpora):
        raise ContractError("acquisition record.corpora must be a JSON object")
    body = corpora.get(corpus_id)
    if not isinstance(body, dict) or not all(isinstance(key, str) for key in body):
        raise EmitterBlocked(f"custody record corpus {corpus_id}")
    return body


def _digest_pin(body: JsonObject, key: str, identity: str) -> str:
    if key not in body:
        raise EmitterBlocked(identity)
    return offline._hash(body[key], f"acquisition record.{key}")


def _oracle_identity(record: JsonObject) -> tuple[str, str]:
    raw = record.get("oracle")
    if not isinstance(raw, dict) or "sha256" not in raw:
        raise EmitterBlocked("oracle digest pin")
    oracle = _mapping(raw, "acquisition record.oracle")
    _require(oracle, ("implementation",), "acquisition record.oracle")
    digest = offline._hash(oracle["sha256"], "acquisition record.oracle.sha256")
    implementation = offline._text(
        oracle["implementation"], "acquisition record.oracle.implementation"
    )
    return implementation, digest


def _check_pins(custody: Custody, record_corpus: JsonObject) -> str:
    archive_pin = _digest_pin(record_corpus, "archive_sha256", "archive digest pin")
    manifest_pin = _digest_pin(record_corpus, "manifest_sha256", "manifest digest pin")
    if archive_pin != custody.archive_sha256:
        raise ContractError("archive digest does not match the acquisition record")
    if manifest_pin != custody.manifest_sha256:
        raise ContractError("manifest digest does not match the acquisition record")
    implementation, oracle_sha256 = _oracle_identity(custody.record)
    if custody.freeze.core_oracle.get("implementation") != implementation:
        raise ContractError("acquisition record oracle does not match the registry")
    return oracle_sha256


def _registry_state(product: corpus.Product) -> RegistryState:
    state = product.state
    _require(
        dict(state),
        ("height", "bestblock", "txouts", "total_amount_sat", "muhash"),
        "products registry state",
    )
    return RegistryState(
        height=offline._uint(state["height"], "products.state.height"),
        bestblock=offline._hash(state["bestblock"], "products.state.bestblock"),
        txouts=offline._uint(state["txouts"], "products.state.txouts"),
        total_amount_sat=offline._uint(
            state["total_amount_sat"], "products.state.total_amount_sat"
        ),
        muhash=offline._hash(state["muhash"], "products.state.muhash"),
    )


def _certified_state(custody: Custody, record_corpus: JsonObject) -> JsonObject:
    raw = record_corpus.get("certified_state")
    if not isinstance(raw, dict) or not all(key in raw for key in CERTIFIED_STATE_KEYS):
        raise EmitterBlocked("certified state pin")
    certified = _mapping(raw, "acquisition record.certified_state")
    registry = _registry_state(custody.product)
    return {
        "height": registry.height,
        "bestblock": registry.bestblock,
        "txouts": registry.txouts,
        "total_amount_sat": registry.total_amount_sat,
        "muhash": registry.muhash,
        "utxo_hash_serialized_3": offline._hash(
            certified["utxo_hash_serialized_3"],
            "acquisition record.certified_state.utxo_hash_serialized_3",
        ),
        "bodies_available": offline._boolean(
            certified["bodies_available"],
            "acquisition record.certified_state.bodies_available",
        ),
        "disconnect_ready": offline._boolean(
            certified["disconnect_ready"],
            "acquisition record.certified_state.disconnect_ready",
        ),
    }


def _campaign_affinity(record: JsonObject) -> str:
    raw = record.get("campaign")
    if not isinstance(raw, dict) or "affinity" not in raw:
        raise EmitterBlocked("campaign affinity pin")
    campaign = _mapping(raw, "acquisition record.campaign")
    return offline._text(campaign["affinity"], "acquisition record.campaign.affinity")


def _binary_identity(path: Path, identity: str) -> tuple[Path, str]:
    absolute = path.absolute()
    try:
        _info, digest = offline._hash_regular(absolute, identity)
    except ContractError as error:
        if isinstance(error.__cause__, FileNotFoundError):
            raise EmitterBlocked(identity) from None
        raise
    return absolute, digest


def _hash_arms(args: argparse.Namespace) -> Arms:
    oracle_path, oracle_sha256 = _binary_identity(args.oracle_binary, "oracle binary")
    candidate_path, candidate_sha256 = _binary_identity(
        args.candidate_binary, "candidate binary"
    )
    return Arms(oracle_path, oracle_sha256, candidate_path, candidate_sha256)


def _file_ref(path: Path, info: os.stat_result, digest: str) -> JsonObject:
    return {"path": str(path), "sha256": digest, "bytes": info.st_size}


def _program(
    path: Path, digest: str, command: tuple[str, ...], restart_field: str
) -> JsonObject:
    return {
        "binary": str(path),
        "binary_sha256": digest,
        "command": list(command),
        restart_field: None,
    }


def _offline_document(
    custody: Custody, record_corpus: JsonObject, arms: Arms
) -> JsonObject:
    document: JsonObject = {
        "schema": offline.CONFIG_SCHEMA,
        "network_magic": custody.freeze.network_magic.hex(),
        "arm_timeout_ns": offline.MAX_ARM_TIMEOUT_NS,
        "posture": {
            "assume_valid": False,
            "txindex": False,
            "blockfilterindex": False,
            "coinstatsindex": False,
            "cache_policy": OFFLINE_CACHE_POLICY,
        },
        "corpus": {
            "archive": _file_ref(
                custody.archive_path, custody.archive_info, custody.archive_sha256
            ),
            "manifest": _file_ref(
                custody.manifest_path, custody.manifest_info, custody.manifest_sha256
            ),
        },
        "expected_state": _certified_state(custody, record_corpus),
        "lifecycle": {"mode": "fresh", "expected_reopen_state": None},
        "core": _program(
            arms.oracle_path, arms.oracle_sha256, OFFLINE_COMMAND, "reopen_command"
        ),
        "candidate": _program(
            arms.candidate_path, arms.candidate_sha256, OFFLINE_COMMAND, "reopen_command"
        ),
    }
    offline.parse_config(document)
    return document


def _project_frames(custody: Custody, entries: list[ManifestEntry]) -> list[bytes]:
    if len(entries) + 1 > p2p_loopback.MAX_STEPS:
        raise ContractError("projected loopback schedule exceeds the step bound")
    descriptor = offline._open_regular(custody.archive_path, "corpus archive")
    frames: list[bytes] = []
    total = 0
    try:
        for index, entry in enumerate(entries):
            header = os.read(descriptor, 8)
            if len(header) != 8:
                raise ContractError("archive ended inside a record header")
            if header[:4] != custody.freeze.network_magic:
                raise ContractError(f"archive record {index} has the wrong network magic")
            if int.from_bytes(header[4:], "little") != entry.payload_length:
                raise ContractError(
                    f"archive record {index} length does not match the custody manifest"
                )
            payload = os.read(descriptor, entry.payload_length)
            if len(payload) != entry.payload_length:
                raise ContractError("archive ended inside a block payload")
            checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            wire = (
                custody.freeze.network_magic
                + P2P_BLOCK_COMMAND.ljust(12, b"\x00")
                + struct.pack("<I", entry.payload_length)
                + checksum
                + payload
            )
            total += len(wire)
            if total > p2p_loopback.MAX_CORPUS_BYTES:
                raise ContractError(
                    "projected loopback corpus exceeds the 16 MiB byte bound"
                )
            frames.append(wire)
    finally:
        os.close(descriptor)
    return frames


def _p2p_document(
    custody: Custody,
    record_corpus: JsonObject,
    entries: list[ManifestEntry],
    arms: Arms,
) -> JsonObject:
    frames = _project_frames(custody, entries)
    schedule: list[JsonObject] = [
        {
            "kind": "send",
            "frame": index,
            "delay_ns": 0,
            "bandwidth_bytes_per_second": None,
            "duration_ns": 0,
            "after_bytes": None,
        }
        for index in range(len(frames))
    ]
    schedule.append(
        {
            "kind": "disconnect",
            "frame": None,
            "delay_ns": 0,
            "bandwidth_bytes_per_second": None,
            "duration_ns": 0,
            "after_bytes": None,
        }
    )
    document: JsonObject = {
        "schema": p2p_loopback.CONFIG_SCHEMA,
        "peer": {
            "network_magic": custody.freeze.network_magic.hex(),
            "protocol_version": P2P_PROTOCOL_VERSION,
            "services": P2P_SERVICES_NETWORK_WITNESS,
            "connect_timeout_ns": p2p_loopback.MAX_CONNECT_TIMEOUT_NS,
            "io_timeout_ns": p2p_loopback.MAX_IO_TIMEOUT_NS,
            "socket_buffer_bytes": P2P_SOCKET_BUFFER_BYTES,
            "expected_inbound_sha256": None,
        },
        "lifecycle": {
            "mode": "fresh",
            "generation": 0,
            "initial_state": {},
            "expected_final_state": _certified_state(custody, record_corpus),
            "expected_restart_state": None,
        },
        "corpus": [frame.hex() for frame in frames],
        "schedule": schedule,
        "core": _program(
            arms.oracle_path, arms.oracle_sha256, P2P_COMMAND, "restart_command"
        ),
        "candidate": _program(
            arms.candidate_path, arms.candidate_sha256, P2P_COMMAND, "restart_command"
        ),
    }
    p2p_loopback.parse_config(document)
    return document


def _muhash_document(
    custody: Custody,
    record_corpus: JsonObject,
    arms: Arms,
    output: Path,
) -> tuple[JsonObject, tuple[Path, JsonObject]]:
    credential = custody.root / CREDENTIAL_NAME
    if not credential.is_file():
        raise EmitterBlocked("rpc credential file")
    credential_info, credential_sha256 = offline._hash_regular(
        credential, "rpc credential file"
    )
    raw = record_corpus.get("frozen_rpc_state")
    if not isinstance(raw, dict) or not all(key in raw for key in FROZEN_RPC_STATE_KEYS):
        raise EmitterBlocked("frozen rpc state pin")
    frozen_values = _mapping(raw, "acquisition record.frozen_rpc_state")
    registry = _registry_state(custody.product)
    frozen: JsonObject = {
        "height": registry.height,
        "bestblock": registry.bestblock,
        "transactions": offline._uint(
            frozen_values["transactions"], "acquisition record.frozen_rpc_state.transactions"
        ),
        "txouts": registry.txouts,
        "bogosize": offline._uint(
            frozen_values["bogosize"], "acquisition record.frozen_rpc_state.bogosize"
        ),
        "disk_size": offline._uint(
            frozen_values["disk_size"], "acquisition record.frozen_rpc_state.disk_size"
        ),
        "total_amount": Decimal(registry.total_amount_sat) / Decimal(SATOSHI_PER_COIN),
        "muhash": registry.muhash,
    }
    frozen_bytes = canonical_bytes(frozen) + b"\n"
    side = output.with_suffix(FROZEN_STATE_SUFFIX)
    arm_config_ref = {
        "path": str(side),
        "sha256": hashlib.sha256(frozen_bytes).hexdigest(),
        "bytes": len(frozen_bytes),
    }
    corpus_id = custody.product.corpus_id
    core = {
        "arm_id": f"{corpus_id}-core",
        "binary": str(arms.oracle_path),
        "binary_sha256": arms.oracle_sha256,
        "command": list(MUHASH_COMMAND),
        "backend": muhash_rpc.CORE_BACKEND,
        "config": arm_config_ref,
        "datadir": str(output.with_suffix(".core-data")),
    }
    candidate = {
        "arm_id": f"{corpus_id}-bitcoin-rs",
        "binary": str(arms.candidate_path),
        "binary_sha256": arms.candidate_sha256,
        "command": list(MUHASH_COMMAND),
        "backend": MUHASH_CANDIDATE_BACKEND,
        "config": arm_config_ref,
        "datadir": str(output.with_suffix(".candidate-data")),
    }
    document: JsonObject = {
        "schema": muhash_rpc.CAMPAIGN_CONFIG_SCHEMA,
        "campaign_id": f"{corpus_id}-muhash-rpc",
        "policy": MUHASH_POLICY,
        "corpus": {
            "identity": corpus_id,
            "file": _file_ref(
                custody.manifest_path, custody.manifest_info, custody.manifest_sha256
            ),
            "height": registry.height,
            "bestblock": registry.bestblock,
        },
        "expected": {"height": registry.height, "bestblock": registry.bestblock},
        "timeout_seconds": MUHASH_TIMEOUT_SECONDS,
        "max_response_bytes": muhash_rpc.MAX_RESPONSE_BYTES,
        "credential_file": _file_ref(
            credential, credential_info, credential_sha256
        ),
        "affinity": _campaign_affinity(custody.record),
        "core": core,
        "candidate": candidate,
        "eviction_procedure": None,
    }
    muhash_rpc._parse_campaign_config(document)
    return document, (side, frozen)


def _unlink_linked(parent: Path, name: str, published: os.stat_result) -> None:
    try:
        directory = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
    except OSError:
        return
    try:
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
    finally:
        os.close(directory)


def _publish(
    output: Path, document: JsonObject, side: tuple[Path, JsonObject] | None
) -> None:
    if output.exists():
        raise ContractError(f"output already exists: {output}")
    if side is not None and side[0].exists():
        raise ContractError(f"output already exists: {side[0]}")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    published: os.stat_result | None = None
    if side is not None:
        publish_result(side[1], side[0])
        try:
            published = os.stat(side[0], follow_symlinks=False)
        except OSError:
            published = None
    try:
        publish_result(document, output)
    except BaseException:
        if side is not None and published is not None:
            _unlink_linked(side[0].parent, side[0].name, published)
        raise


def _run(args: argparse.Namespace) -> None:
    custody = _load_custody(args)
    _check_manifest_identity(custody)
    entries = _manifest_entries(custody)
    record_corpus = _record_corpus(custody.record, custody.product.corpus_id)
    oracle_sha256 = _check_pins(custody, record_corpus)
    arms = _hash_arms(args)
    if arms.oracle_sha256 != oracle_sha256:
        raise ContractError("oracle binary digest does not match the acquisition record")
    output = args.output.absolute()
    if args.kind == "offline":
        document = _offline_document(custody, record_corpus, arms)
        side = None
    elif args.kind == "p2p":
        document = _p2p_document(custody, record_corpus, entries, arms)
        side = None
    else:
        document, side = _muhash_document(custody, record_corpus, arms, output)
    _publish(output, document, side)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("offline", "p2p", "muhash"))
    parser.add_argument("--custody-root", required=True, type=Path)
    parser.add_argument("--corpus-id", required=True)
    parser.add_argument("--candidate-binary", required=True, type=Path)
    parser.add_argument("--oracle-binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _run(args)
    except EmitterBlocked as blocked:
        print(f"BLOCKED: {blocked.identity}", file=sys.stderr)
        return 2
    except CONTRACT_ERRORS as error:
        print(f"emit-comparator-config: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
