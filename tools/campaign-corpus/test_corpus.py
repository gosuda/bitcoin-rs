#!/usr/bin/env python3
"""Contract tests for the C150 / Cmodern campaign corpus freeze."""

from __future__ import annotations

import hashlib
import io
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import corpus
from corpus import ContractError


C150_HASH = "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"
CMODERN_HASH = "00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f"
GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
MUHASH = "383a0b41ac28ddf6ac91723b41527fa64c0b54451cee5f2c4b3823ef92117116"


def _genesis_header() -> bytes:
    merkle = bytes.fromhex("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a")
    return (
        struct.pack("<I", 1)
        + bytes(32)
        + merkle
        + struct.pack("<I", 1231006505)
        + struct.pack("<I", 0x1D00FFFF)
        + struct.pack("<I", 2083236893)
    )


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
        self.assertEqual(self.freeze.network_magic, bytes.fromhex("f9beb4d9"))
        self.assertEqual(self.freeze.core_oracle["implementation"], "Bitcoin Core 31.1")
        self.assertEqual(corpus.core_oracle_params(self.freeze, "C150"), ["muhash", 150_000, True])
        self.assertEqual(corpus.core_oracle_params(self.freeze, "Cmodern"), ["muhash", 709_635, True])

    def test_eleven_named_special_contexts(self) -> None:
        self.assertEqual(len(self.freeze.census_specials), 11)
        self.assertIn("taproot_key_path_spends", self.freeze.census_specials)
        self.assertIn("tapscript_checksigadd_checks", self.freeze.census_specials)
        self.assertIn("p2sh_redeem_spends", self.freeze.census_specials)

    def test_contract_page_cites_the_frozen_tips(self) -> None:
        page = Path(__file__).resolve().parents[2] / "docs/contracts/campaign-corpora.md"
        text = page.read_text(encoding="utf-8")
        self.assertIn(C150_HASH, text)
        self.assertIn(CMODERN_HASH, text)
        self.assertIn(MUHASH, text)
        self.assertIn("assume_valid_height` is `0`", text)


class Framing(unittest.TestCase):
    def test_genesis_header_hash(self) -> None:
        self.assertEqual(corpus.header_block_hash(_genesis_header()), GENESIS_HASH)

    def test_round_trip_and_offsets(self) -> None:
        payloads = [b"a" * 80, b"b" * 90]
        archive = b"".join(corpus.write_frame(item) for item in payloads)
        frames = corpus.read_frames(archive)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0][0].offset, 0)
        self.assertEqual(frames[1][0].offset, 8 + 80)
        self.assertEqual(frames[0][1], payloads[0])
        self.assertEqual(frames[1][1], payloads[1])

    def test_wrong_magic_is_refused(self) -> None:
        archive = corpus.write_frame(b"x" * 80, magic=b"TEST")
        with self.assertRaises(ContractError):
            corpus.read_frames(archive)

    def test_truncated_header_is_refused(self) -> None:
        with self.assertRaises(ContractError):
            corpus.read_frames(b"f9be")

    def test_truncated_payload_is_refused(self) -> None:
        header = bytes.fromhex("f9beb4d9") + struct.pack("<I", 80)
        with self.assertRaises(ContractError):
            corpus.read_frames(header + b"short")

    def test_length_prefixed_convert_preserves_payloads(self) -> None:
        payloads = [_genesis_header(), b"q" * 80]
        blob = b"".join(struct.pack("<I", len(item)) + item for item in payloads)
        recovered = corpus.length_prefixed_payloads(blob)
        self.assertEqual(recovered, payloads)


class ManifestBinding(unittest.TestCase):
    def test_wrong_block_count_is_not_c150(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(ContractError):
            corpus.export_payloads(freeze, "C150", [_genesis_header()])

    def test_unknown_corpus_is_refused(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(ContractError):
            corpus.product(freeze, "CFIXTURE")

    def test_manifest_digest_tamper_is_caught(self) -> None:
        freeze = corpus.load_freeze()
        payloads = [_genesis_header()]
        archive = corpus.write_frame(payloads[0])
        # Bypass product block-count by forging a one-entry document, then
        # checking that digest verification still fails closed on tamper.
        document = {
            "schema": corpus.MANIFEST_SCHEMA,
            "version": corpus.MANIFEST_VERSION,
            "corpus_id": "C150",
            "network": freeze.network,
            "network_magic": freeze.network_magic.hex(),
            "genesis_hash": freeze.genesis_hash,
            "range": {"start_height": 0, "stop_height": 150_000},
            "source_tip_hash": C150_HASH,
            "archive": {"size": len(archive), "sha256": hashlib.sha256(archive).hexdigest()},
            "entries": [
                {
                    "height": 0,
                    "hash": GENESIS_HASH,
                    "offset": 0,
                    "payload_length": len(payloads[0]),
                }
            ],
            "manifest_sha256": corpus.ZERO_SHA256,
        }
        document["manifest_sha256"] = corpus.manifest_digest(document)
        document["source_tip_hash"] = "ff" * 32
        with self.assertRaises(ContractError):
            corpus.verify_archive(freeze, archive, document)

    def test_duplicate_json_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dup.json"
            path.write_text('{"schema":"x","schema":"y"}\n', encoding="utf-8")
            with self.assertRaises(ContractError):
                corpus._load_json(path)

    def test_publish_refuses_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.bin"
            corpus.publish(path, b"one")
            with self.assertRaises(ContractError):
                corpus.publish(path, b"two")


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


class RestExport(unittest.TestCase):
    def test_rest_hash_mismatch_is_refused(self) -> None:
        freeze = corpus.load_freeze()
        blocks = {0: _genesis_header()}

        def fetch(path: str) -> bytes:
            if path.startswith("/rest/blockhashbyheight/"):
                return b"ff" * 32
            return blocks[0]

        with self.assertRaises(ContractError):
            # Still fails closed even before completing 150,001 fetches.
            corpus.export_from_rest(freeze, "C150", "127.0.0.1:8332", fetch=fetch)

    def test_hostport_rejects_a_path(self) -> None:
        with self.assertRaises(ContractError):
            corpus._hostport("127.0.0.1:8332/rest")


class NonVacuity(unittest.TestCase):
    def test_red_wrong_c150_hash_is_caught(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(AssertionError):
            self.assertEqual(freeze.products["C150"].stop_hash, CMODERN_HASH)

    def test_red_wrong_special_count_is_caught(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(AssertionError):
            self.assertEqual(len(freeze.census_specials), 4)

    def test_red_assumevalid_shortcut_is_caught(self) -> None:
        freeze = corpus.load_freeze()
        with self.assertRaises(AssertionError):
            self.assertNotEqual(freeze.assume_valid_height, 0)


if __name__ == "__main__":
    unittest.main()
