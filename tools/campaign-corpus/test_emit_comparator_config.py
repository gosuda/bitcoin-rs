#!/usr/bin/env python3
"""Contract tests for the custody-driven comparator config emitter.

Every expected digest is computed here with hashlib over the documented
framing: double-SHA256 header hashes, double-SHA256 frame checksums, and
SHA-256 file identities. Schema acceptance is proven by running the
owning comparator parser over the published bytes. Refusal paths must
exit 2, name the missing identity or the refused artifact on stderr,
and leave no output document behind. All fixtures are synthetic custody
built inside a TemporaryDirectory; the reference corpus is never read.
"""

import contextlib
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAMPAIGN_TOOLS = HERE.parent / "benchmark-campaign"
for entry in (str(HERE), str(CAMPAIGN_TOOLS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import corpus
import emit_comparator_config as emitter
import muhash_rpc
import offline_full_validation as offline
import p2p_loopback

MAGIC = bytes.fromhex("f9beb4d9")
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
CORPUS_ID = "Cfix"
MUHASH = "cd" * 32
UTXO_HASH_3 = "ef" * 32
STOP_HEIGHT = 1
TXOUTS = 2
TOTAL_AMOUNT_SAT = 12_500_000_000
CANDIDATE_BYTES = b"#!/bin/candidate-fixture\n"
ORACLE_BYTES = b"#!/bin/oracle-fixture\n"
COOKIE_BYTES = b"bench-user:fixture-secret"
AFFINITY = "0-1"
TRANSACTIONS = 1
BOGOSIZE = 300
DISK_SIZE = 400


def _dsha(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _display(payload: bytes) -> str:
    return _dsha(payload[:80])[::-1].hex()


def _header(index: int, prev_digest: bytes) -> bytes:
    return (
        struct.pack("<I", 1)
        + prev_digest
        + bytes([index]) * 32
        + struct.pack("<III", 1231006505 + index, 0x207FFFFF, index)
    )


def _record(payload: bytes) -> bytes:
    return MAGIC + struct.pack("<I", len(payload)) + payload


def _network_frame(payload: bytes) -> bytes:
    return (
        MAGIC
        + b"block".ljust(12, b"\x00")
        + struct.pack("<I", len(payload))
        + _dsha(payload)[:4]
        + payload
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CustodyFixture:
    """Synthetic staged custody with independently established identity."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.corpora = root / "corpora"
        self.corpora.mkdir()
        header0 = _header(0, bytes(32))
        header1 = _header(1, _dsha(header0))
        self.payloads = (header0 + b"\x01" * 16, header1 + b"\x02" * 16)
        self.hashes = tuple(_display(payload) for payload in self.payloads)
        self.records = tuple(_record(payload) for payload in self.payloads)
        self.archive_bytes = b"".join(self.records)
        self.archive = self.corpora / f"{CORPUS_ID}.archive.bin"
        self.archive.write_bytes(self.archive_bytes)
        self.archive_sha256 = _sha256(self.archive_bytes)
        self.archive_size = len(self.archive_bytes)
        self.frames = tuple(_network_frame(payload) for payload in self.payloads)
        self.manifest = self._write_manifest()
        self.manifest_file_sha256 = _sha256(self.manifest.read_bytes())
        self.products = root / "products.json"
        self.products.write_bytes(_canonical(self._products_value()) + b"\n")
        self.candidate = root / "candidate-node"
        self.candidate.write_bytes(CANDIDATE_BYTES)
        self.candidate_sha256 = _sha256(CANDIDATE_BYTES)
        self.oracle = root / "oracle-bitcoind"
        self.oracle.write_bytes(ORACLE_BYTES)
        self.oracle_sha256 = _sha256(ORACLE_BYTES)
        self.record = self.corpora / "acquisition-record.json"
        self.record.write_bytes(_canonical(self._record_value()) + b"\n")
        self.cookie = root / "rpc.cookie"
        self.cookie.write_bytes(COOKIE_BYTES)
        self.cookie.chmod(0o600)
        self.cookie_sha256 = _sha256(COOKIE_BYTES)

    def _write_manifest(self) -> Path:
        entries = []
        offset = 0
        for height, (payload, record, digest) in enumerate(
            zip(self.payloads, self.records, self.hashes, strict=True)
        ):
            entries.append(
                {
                    "hash": digest,
                    "height": height,
                    "offset": offset,
                    "payload_length": len(payload),
                }
            )
            offset += len(record)
        body: dict[str, object] = {
            "schema": corpus.MANIFEST_SCHEMA,
            "version": corpus.MANIFEST_VERSION,
            "corpus_id": CORPUS_ID,
            "network": "mainnet",
            "network_magic": MAGIC.hex(),
            "genesis_hash": GENESIS_HASH,
            "range": {"start_height": 0, "stop_height": STOP_HEIGHT},
            "source_tip_hash": self.hashes[-1],
            "archive": {"size": self.archive_size, "sha256": self.archive_sha256},
            "entries": entries,
        }
        body["manifest_sha256"] = _sha256(_canonical(body))
        path = self.corpora / f"{CORPUS_ID}.manifest.json"
        path.write_bytes(_canonical(body) + b"\n")
        return path

    def _products_value(self) -> dict[str, object]:
        return {
            "schema": "bitcoin-rs-campaign-corpora-v1",
            "network": "mainnet",
            "network_magic": MAGIC.hex(),
            "genesis_hash": GENESIS_HASH,
            "core_oracle": {
                "implementation": "Bitcoin Core 31.1",
                "rpc_method": "gettxoutsetinfo",
                "hash_type": "muhash",
                "use_index": True,
            },
            "validation": {"assume_valid_height": 0},
            "census_specials": ["p2sh_redeem_spends"],
            "products": {
                CORPUS_ID: {
                    "stop_height": STOP_HEIGHT,
                    "stop_hash": self.hashes[-1],
                    "block_count": len(self.payloads),
                    "census": {"specials": "all_zero"},
                    "state": {
                        "height": STOP_HEIGHT,
                        "bestblock": self.hashes[-1],
                        "txouts": TXOUTS,
                        "total_amount_sat": TOTAL_AMOUNT_SAT,
                        "muhash": MUHASH,
                    },
                }
            },
        }

    def _record_value(self) -> dict[str, object]:
        return {
            "schema": emitter.ACQUISITION_SCHEMA,
            "oracle": {"implementation": "Bitcoin Core 31.1", "sha256": self.oracle_sha256},
            "campaign": {"affinity": AFFINITY},
            "corpora": {
                CORPUS_ID: {
                    "archive_sha256": self.archive_sha256,
                    "manifest_sha256": self.manifest_file_sha256,
                    "certified_state": {
                        "utxo_hash_serialized_3": UTXO_HASH_3,
                        "bodies_available": True,
                        "disconnect_ready": True,
                    },
                    "frozen_rpc_state": {
                        "transactions": TRANSACTIONS,
                        "bogosize": BOGOSIZE,
                        "disk_size": DISK_SIZE,
                    },
                }
            },
        }

    def emit(self, kind: str, output: Path, corpus_id: str = CORPUS_ID) -> tuple[int, str]:
        stderr = io.StringIO()
        argv = [
            kind,
            "--custody-root",
            str(self.root),
            "--corpus-id",
            corpus_id,
            "--candidate-binary",
            str(self.candidate),
            "--oracle-binary",
            str(self.oracle),
            "--output",
            str(output),
        ]
        with contextlib.redirect_stderr(stderr):
            code = emitter.main(argv)
        return code, stderr.getvalue()


class EmitterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="emit-comparator-config-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.fixture = CustodyFixture(self.root)
        self.output = self.root / "out" / "config.json"


class OfflineEmissionTests(EmitterTestCase):
    def test_emits_config_that_the_offline_validator_accepts(self) -> None:
        code, stderr = self.fixture.emit("offline", self.output)
        self.assertEqual((code, stderr), (0, ""))
        document = json.loads(self.output.read_bytes())
        self.assertEqual(document["schema"], offline.CONFIG_SCHEMA)
        self.assertEqual(document["network_magic"], MAGIC.hex())
        self.assertEqual(document["arm_timeout_ns"], offline.MAX_ARM_TIMEOUT_NS)
        self.assertEqual(
            document["corpus"]["archive"],
            {
                "path": str(self.fixture.archive),
                "sha256": self.fixture.archive_sha256,
                "bytes": self.fixture.archive_size,
            },
        )
        self.assertEqual(
            document["corpus"]["manifest"]["sha256"],
            self.fixture.manifest_file_sha256,
        )
        self.assertEqual(
            document["expected_state"],
            {
                "height": STOP_HEIGHT,
                "bestblock": self.fixture.hashes[-1],
                "txouts": TXOUTS,
                "total_amount_sat": TOTAL_AMOUNT_SAT,
                "muhash": MUHASH,
                "utxo_hash_serialized_3": UTXO_HASH_3,
                "bodies_available": True,
                "disconnect_ready": True,
            },
        )
        self.assertEqual(
            document["lifecycle"],
            {"mode": "fresh", "expected_reopen_state": None},
        )
        self.assertEqual(document["core"]["binary_sha256"], self.fixture.oracle_sha256)
        self.assertEqual(
            document["candidate"]["binary_sha256"], self.fixture.candidate_sha256
        )
        self.assertIn("--assume-valid-height=0", document["candidate"]["command"])
        self.assertIsNone(document["candidate"]["reopen_command"])
        config = offline.load_config(self.output)
        self.assertEqual(config.network_magic, MAGIC)
        self.assertEqual(config.expected_state.height, STOP_HEIGHT)
        self.assertEqual(config.candidate.binary_sha256, self.fixture.candidate_sha256)


class P2pEmissionTests(EmitterTestCase):
    def test_emits_config_that_the_p2p_validator_accepts(self) -> None:
        code, stderr = self.fixture.emit("p2p", self.output)
        self.assertEqual((code, stderr), (0, ""))
        document = json.loads(self.output.read_bytes())
        self.assertEqual(document["schema"], p2p_loopback.CONFIG_SCHEMA)
        self.assertEqual(
            document["corpus"], [frame.hex() for frame in self.fixture.frames]
        )
        wire = bytes.fromhex(document["corpus"][0])
        self.assertEqual(wire[:4], MAGIC)
        self.assertEqual(wire[4:16], b"block".ljust(12, b"\x00"))
        self.assertEqual(wire[20:24], _dsha(self.fixture.payloads[0])[:4])
        self.assertEqual(
            [step["kind"] for step in document["schedule"]],
            ["send", "send", "disconnect"],
        )
        self.assertEqual(
            [step["frame"] for step in document["schedule"][:2]], [0, 1]
        )
        self.assertEqual(
            document["peer"]["services"], emitter.P2P_SERVICES_NETWORK_WITNESS
        )
        self.assertEqual(
            document["lifecycle"]["expected_final_state"]["muhash"], MUHASH
        )
        config = p2p_loopback.load_config(self.output)
        self.assertEqual(config.corpus[0].sha256, _sha256(self.fixture.frames[0]))
        self.assertEqual(
            config.lifecycle.expected_final_state["muhash"], MUHASH
        )


class MuhashEmissionTests(EmitterTestCase):
    def test_emits_config_that_the_muhash_validator_accepts(self) -> None:
        code, stderr = self.fixture.emit("muhash", self.output)
        self.assertEqual((code, stderr), (0, ""))
        document = json.loads(self.output.read_bytes())
        self.assertEqual(document["schema"], muhash_rpc.CAMPAIGN_CONFIG_SCHEMA)
        self.assertEqual(document["corpus"]["identity"], CORPUS_ID)
        self.assertEqual(document["corpus"]["height"], STOP_HEIGHT)
        self.assertEqual(document["corpus"]["bestblock"], self.fixture.hashes[-1])
        self.assertEqual(
            document["corpus"]["file"]["sha256"], self.fixture.manifest_file_sha256
        )
        self.assertEqual(
            document["credential_file"]["sha256"], self.fixture.cookie_sha256
        )
        self.assertEqual(document["core"]["backend"], "coinsdb")
        self.assertEqual(document["candidate"]["backend"], "fjall")
        self.assertNotEqual(document["core"]["arm_id"], document["candidate"]["arm_id"])
        side = self.output.with_suffix(".frozen-state.json")
        self.assertTrue(side.is_file())
        frozen = json.loads(side.read_bytes(), parse_float=Decimal)
        self.assertEqual(Decimal(str(frozen["total_amount"])), Decimal("125"))
        self.assertEqual(frozen["muhash"], MUHASH)
        self.assertEqual(frozen["transactions"], TRANSACTIONS)
        self.assertEqual(frozen["txouts"], TXOUTS)
        config = muhash_rpc._parse_campaign_config(document)
        self.assertEqual(config.campaign_id, f"{CORPUS_ID}-muhash-rpc")
        self.assertEqual(config.policy, "process-cold/page-cache-unspecified")
        self.assertEqual(config.core.config.sha256, _sha256(side.read_bytes()))


class CustodyRefusalTests(EmitterTestCase):
    def test_missing_candidate_binary_is_blocked(self) -> None:
        self.fixture.candidate.unlink()
        code, stderr = self.fixture.emit("offline", self.output)
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED: candidate binary", stderr)
        self.assertFalse(self.output.exists())

    def test_symlink_archive_is_refused(self) -> None:
        target = self.root / "archive-target.bin"
        target.write_bytes(self.fixture.archive_bytes)
        self.fixture.archive.unlink()
        os.symlink(target, self.fixture.archive)
        code, stderr = self.fixture.emit("muhash", self.output)
        self.assertEqual(code, 2)
        self.assertNotIn("BLOCKED:", stderr)
        self.assertNotEqual(stderr, "")
        self.assertFalse(self.output.exists())

    def test_archive_digest_mismatch_with_manifest_is_refused(self) -> None:
        data = bytearray(self.fixture.archive_bytes)
        data[-1] ^= 0xFF
        self.fixture.archive.write_bytes(bytes(data))
        code, stderr = self.fixture.emit("muhash", self.output)
        self.assertEqual(code, 2)
        self.assertNotIn("BLOCKED:", stderr)
        self.assertIn("archive digest does not match the custody manifest", stderr)
        self.assertFalse(self.output.exists())

    def test_unknown_corpus_id_is_blocked(self) -> None:
        code, stderr = self.fixture.emit("offline", self.output, corpus_id="Cmissing")
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED: corpus Cmissing", stderr)
        self.assertFalse(self.output.exists())

    def test_missing_products_registry_is_blocked(self) -> None:
        self.fixture.products.unlink()
        code, stderr = self.fixture.emit("offline", self.output)
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED: products registry", stderr)
        self.assertFalse(self.output.exists())

    def test_missing_acquisition_record_is_blocked(self) -> None:
        self.fixture.record.unlink()
        code, stderr = self.fixture.emit("p2p", self.output)
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED: custody acquisition record", stderr)
        self.assertFalse(self.output.exists())

    def test_existing_output_refuses_without_writes(self) -> None:
        os.mkdir(self.output.parent, 0o700)
        self.output.write_bytes(b"sentinel")
        side = self.output.with_suffix(".frozen-state.json")
        code, stderr = self.fixture.emit("muhash", self.output)
        self.assertEqual(code, 2)
        self.assertIn("output already exists", stderr)
        self.assertEqual(self.output.read_bytes(), b"sentinel")
        self.assertFalse(side.exists())


if __name__ == "__main__":
    unittest.main()
