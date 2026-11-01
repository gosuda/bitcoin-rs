# pyright: strict
"""Contract tests for shared evidence encoding, publication, and custody."""

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from evidence import (
    ContractError,
    _parse_start_time,
    canonical_bytes,
    copy_pinned,
    hash_regular_file,
    nearest_rank,
    process_start_time,
    publish_result,
)


class CanonicalBytesTests(unittest.TestCase):
    def test_matches_json_oracle_for_documents_without_decimal(self) -> None:
        document: dict[str, object] = {
            "schema": "p2p-loopback-result-v2",
            "pairs": [{"index": 0, "ratio": 1.5, "labels": ["a", "\u00e9"]}],
            "empty": [],
            "max": None,
            "ok": True,
        }
        oracle = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(canonical_bytes(document), oracle)

    def test_decimal_values_encode_as_normalized_numbers(self) -> None:
        value: dict[str, object] = {
            "a": Decimal("12.50000000"),
            "b": Decimal("0.0100"),
        }
        self.assertEqual(canonical_bytes(value), b'{"a":12.5,"b":0.01}')


class NearestRankTests(unittest.TestCase):
    def test_hand_computed_nearest_ranks(self) -> None:
        self.assertEqual(nearest_rank([9], 0.50), 9)
        self.assertEqual(nearest_rank([9], 1.0), 9)
        self.assertEqual(nearest_rank([20, 10], 0.50), 10)
        self.assertEqual(nearest_rank([20, 10], 0.95), 20)
        samples = [70, 10, 60, 20, 50, 30, 40]
        self.assertEqual(nearest_rank(samples, 0.50), 40)
        self.assertEqual(nearest_rank(samples, 0.95), 70)
        self.assertEqual(nearest_rank(samples, 0.99), 70)
        hundred = list(range(100, 0, -1))
        self.assertEqual(nearest_rank(hundred, 0.50), 50)
        self.assertEqual(nearest_rank(hundred, 0.95), 95)
        self.assertEqual(nearest_rank(hundred, 1.0), 100)

    def test_empty_and_out_of_range_percentiles_are_refused(self) -> None:
        with self.assertRaises(ContractError):
            nearest_rank([], 0.50)
        with self.assertRaises(ContractError):
            nearest_rank([1], 0.0)
        with self.assertRaises(ContractError):
            nearest_rank([1], 1.01)


class ProcessStartTimeTests(unittest.TestCase):
    def test_start_time_survives_spaces_and_parentheses_in_comm(self) -> None:
        trailing = ["S", *(str(index) for index in range(4, 22)), "987654321"]
        stat_text = "4242 (a) b (c) " + " ".join(trailing)
        self.assertEqual(_parse_start_time(stat_text), 987654321)

    def test_start_time_reads_the_live_process(self) -> None:
        start = process_start_time(os.getpid())
        self.assertGreater(start, 0)
        self.assertEqual(process_start_time(os.getpid()), start)


class CopyPinnedTests(unittest.TestCase):
    def test_copy_hashes_bytes_and_sets_the_mode(self) -> None:
        payload = b"pinned-config"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(payload)
            destination = root / "copy"
            self.assertEqual(
                copy_pinned(source, destination, digest, 0o400), destination
            )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)

    def test_digest_mismatch_leaves_no_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"pinned-config")
            destination = root / "copy"
            with self.assertRaises(ContractError):
                copy_pinned(source, destination, "0" * 64)
            self.assertFalse(destination.exists())

    def test_symlink_source_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_bytes(b"pinned-config")
            link = root / "link"
            link.symlink_to(real)
            with self.assertRaises(ContractError):
                copy_pinned(
                    link, root / "copy", hashlib.sha256(b"pinned-config").hexdigest()
                )
            self.assertFalse((root / "copy").exists())

    def test_existing_destination_is_refused(self) -> None:
        payload = b"pinned-config"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(payload)
            destination = root / "copy"
            destination.write_bytes(b"existing")
            with self.assertRaises(ContractError):
                copy_pinned(source, destination, hashlib.sha256(payload).hexdigest())
            self.assertEqual(destination.read_bytes(), b"existing")


class HashRegularFileTests(unittest.TestCase):
    def test_matches_an_independent_digest(self) -> None:
        payload = b"pinned-config"
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.write_bytes(payload)
            self.assertEqual(
                hash_regular_file(source), hashlib.sha256(payload).hexdigest()
            )

    def test_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_bytes(b"pinned-config")
            link = root / "link"
            link.symlink_to(real)
            with self.assertRaises(ContractError):
                hash_regular_file(link)

    def test_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ContractError):
                hash_regular_file(Path(temporary))


class PublishResultTests(unittest.TestCase):
    def test_shallow_result_publishes_atomically(self) -> None:
        result: dict[str, object] = {"schema": "test-v1", "samples": 3}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "out.json"
            publish_result(result, output)
            self.assertEqual(output.read_bytes(), canonical_bytes(result) + b"\n")

    def test_existing_output_is_never_overwritten(self) -> None:
        result: dict[str, object] = {"schema": "test-v1"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "out.json"
            output.write_bytes(b"existing\n")
            with self.assertRaises(ContractError) as raised:
                publish_result(result, output)
            self.assertIn("already exists", str(raised.exception))
            self.assertEqual(output.read_bytes(), b"existing\n")
            self.assertEqual(list(root.glob(".*out.json*")), [])

    def test_symlink_parent_is_refused(self) -> None:
        result: dict[str, object] = {"schema": "test-v1"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ContractError):
                publish_result(result, link / "out.json")
            self.assertFalse((real / "out.json").exists())

    def test_over_deep_result_is_rejected(self) -> None:
        nested: object = {"leaf": 1}
        for _ in range(40):
            nested = [nested]
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaises(ContractError),
        ):
            publish_result({"result": nested}, Path(temporary) / "out.json")


if __name__ == "__main__":
    unittest.main()
