# pyright: strict
"""Contract tests for evidence publication validation."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from evidence import ContractError, _publish_result, canonical_bytes


class PublishDepthTests(unittest.TestCase):
    def test_over_deep_result_is_rejected(self) -> None:
        nested: object = {"leaf": 1}
        for _ in range(40):
            nested = [nested]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ContractError):
                _publish_result({"result": nested}, Path(tmp) / "out.json")

    def test_shallow_result_publishes_atomically(self) -> None:
        result: dict[str, object] = {"schema": "test-v1", "samples": 3}
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.json"
            _publish_result(result, output)
            self.assertEqual(output.read_bytes(), canonical_bytes(result) + b"\n")


if __name__ == "__main__":
    unittest.main()
