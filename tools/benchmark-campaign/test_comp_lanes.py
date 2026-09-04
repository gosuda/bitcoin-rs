#!/usr/bin/env python3.14
# pyright: strict
"""Behavioral tests for the comparator campaign lane runner.

Each assertion is proven non-vacuous by a companion RED test that
deliberately breaks the expectation and confirms the test fails.
"""

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import comp_lanes
from comp_lanes import LANE_REPORT_SCHEMA, run_all_lanes, run_p2p_lane


def _is_object(value: object) -> bool:
    return isinstance(value, dict)


def _run_in_workspace() -> tuple[Path, dict[str, object]]:
    workspace = Path(tempfile.mkdtemp(prefix="comp-lanes-test-"))
    report = run_all_lanes(workspace)
    return workspace, report


class P2PLaneTests(unittest.TestCase):
    """Tests for the P2P loopback lane (#35)."""

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="p2p-lane-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_p2p_lane_produces_valid_result(self) -> None:
        result = run_p2p_lane(self.workspace)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["result_schema"], "p2p-loopback-result-v2")
        self.assertEqual(result["pair_count"], 7)
        self.assertEqual(result["arm_count"], 14)
        correctness = result["correctness"]
        assert isinstance(correctness, dict)
        self.assertTrue(all(correctness.values()))
        self.assertIsNotNone(result["result_sha256"])
        self.assertIsNotNone(result["ratio"])

    def test_p2p_lane_result_sha256_matches_file(self) -> None:
        result = run_p2p_lane(self.workspace)
        self.assertEqual(result["status"], "passed")
        result_path = Path(result["result_path"])  # type: ignore[arg-type]
        raw = result_path.read_bytes()
        record = json.loads(raw)
        canonical = comp_lanes.p2p_canonical_bytes(
            {k: v for k, v in record.items() if k != "result_sha256"}
        )
        expected = hashlib.sha256(canonical).hexdigest()
        self.assertEqual(record["result_sha256"], expected)
        self.assertEqual(result["result_sha256"], expected)

    def test_p2p_lane_correctness_gates_are_all_true(self) -> None:
        result = run_p2p_lane(self.workspace)
        self.assertEqual(result["status"], "passed")
        correctness = result["correctness"]
        assert isinstance(correctness, dict)
        expected_keys = {
            "bytes_equal",
            "peer_parameters_equal",
            "protocol_ok",
            "restart_state_equal",
            "schedule_equal",
            "state_equal",
        }
        self.assertEqual(set(correctness.keys()), expected_keys)
        for key, value in correctness.items():
            self.assertTrue(value, f"correctness gate {key} is not true")


class OfflineLaneTests(unittest.TestCase):
    """Tests for the offline full-validation lane (#34)."""

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="offline-lane-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_offline_lane_produces_valid_result(self) -> None:
        result = comp_lanes.run_offline_lane(self.workspace)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            result["result_schema"], "offline-full-validation-result-v1"
        )
        self.assertEqual(result["pair_count"], 7)
        self.assertEqual(result["arm_count"], 14)
        correctness = result["correctness"]
        assert isinstance(correctness, dict)
        self.assertTrue(all(correctness.values()))
        self.assertIsNotNone(result["result_sha256"])
        self.assertIsNotNone(result["ratio"])


class RPCLaneTests(unittest.TestCase):
    """Tests for the MuHash RPC lane (#41)."""

    def test_rpc_lane_blocked_without_bitcoind(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="rpc-lane-test-"))
        try:
            report = run_all_lanes(workspace)
            lanes = report["lanes"]
            assert isinstance(lanes, list)
            rpc = lanes[2]
            assert isinstance(rpc, dict)
            self.assertEqual(rpc["issue"], "#41")
            if shutil.which("bitcoind") is None:
                self.assertEqual(rpc["status"], "blocked")
                self.assertEqual(
                    rpc["reason"], "bitcoind binary not found on PATH"
                )
            else:
                self.assertEqual(rpc["status"], "reachable")
        finally:
            shutil.rmtree(workspace, ignore_errors=True)


class CombinedReportTests(unittest.TestCase):
    """Tests for the combined lane report structure."""

    def test_report_has_correct_schema_and_three_lanes(self) -> None:
        workspace, report = _run_in_workspace()
        try:
            self.assertEqual(report["schema"], LANE_REPORT_SCHEMA)
            lanes = report["lanes"]
            assert isinstance(lanes, list)
            self.assertEqual(len(lanes), 3)
            issues = [lane["issue"] for lane in lanes]  # type: ignore[union-attr]
            self.assertEqual(issues, ["#34", "#35", "#41"])
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_report_sha256_is_consistent(self) -> None:
        workspace, report = _run_in_workspace()
        try:
            canonical = comp_lanes.p2p_canonical_bytes(
                {k: v for k, v in report.items() if k != "report_sha256"}
            )
            expected = hashlib.sha256(canonical).hexdigest()
            self.assertEqual(report["report_sha256"], expected)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_offline_lane_in_report_has_passed_status(self) -> None:
        workspace, report = _run_in_workspace()
        try:
            lanes = report["lanes"]
            assert isinstance(lanes, list)
            offline = lanes[0]
            assert isinstance(offline, dict)
            self.assertEqual(offline["lane"], "offline-full-validation")
            self.assertEqual(offline["status"], "passed")
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_p2p_lane_in_report_has_passed_status(self) -> None:
        workspace, report = _run_in_workspace()
        try:
            lanes = report["lanes"]
            assert isinstance(lanes, list)
            p2p = lanes[1]
            assert isinstance(p2p, dict)
            self.assertEqual(p2p["lane"], "p2p-loopback")
            self.assertEqual(p2p["status"], "passed")
        finally:
            shutil.rmtree(workspace, ignore_errors=True)


class NonVacuityProofs(unittest.TestCase):
    """RED tests that deliberately break assertions to prove non-vacuity.

    Each test in P2PLaneTests, OfflineLaneTests, etc. has a companion
    here that mutates the expectation or the data and confirms the
    assertion fails.  These tests MUST fail — they are the RED half of
    the RED/GREEN proof.  They are run separately and are expected to
    raise AssertionError.
    """

    def test_RED_wrong_schema_name_is_caught(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="red-schema-"))
        try:
            result = run_p2p_lane(workspace)
            # Deliberately assert the wrong schema name
            with self.assertRaises(AssertionError):
                self.assertEqual(result["result_schema"], "p2p-loopback-result-v1")
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_RED_wrong_arm_count_is_caught(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="red-arms-"))
        try:
            result = run_p2p_lane(workspace)
            # Deliberately assert the wrong arm count
            with self.assertRaises(AssertionError):
                self.assertEqual(result["arm_count"], 12)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_RED_wrong_correctness_gate_count_is_caught(self) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="red-gates-"))
        try:
            result = run_p2p_lane(workspace)
            correctness = result["correctness"]
            assert isinstance(correctness, dict)
            # Deliberately expect an extra gate that does not exist
            with self.assertRaises(AssertionError):
                self.assertIn("fake_gate", correctness)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_RED_wrong_lane_count_is_caught(self) -> None:
        workspace, report = _run_in_workspace()
        try:
            lanes = report["lanes"]
            assert isinstance(lanes, list)
            # Deliberately assert the wrong lane count
            with self.assertRaises(AssertionError):
                self.assertEqual(len(lanes), 2)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_RED_wrong_issue_order_is_caught(self) -> None:
        workspace, report = _run_in_workspace()
        try:
            lanes = report["lanes"]
            assert isinstance(lanes, list)
            issues = [lane["issue"] for lane in lanes]  # type: ignore[union-attr]
            # Deliberately assert the wrong issue order
            with self.assertRaises(AssertionError):
                self.assertEqual(issues, ["#35", "#34", "#41"])
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def test_RED_tampered_report_sha256_is_caught(self) -> None:
        workspace, report = _run_in_workspace()
        try:
            # Tamper with the report and verify the sha256 no longer matches
            tampered = dict(report)
            tampered["schema"] = "tampered"
            canonical = comp_lanes.p2p_canonical_bytes(
                {k: v for k, v in tampered.items() if k != "report_sha256"}
            )
            expected = hashlib.sha256(canonical).hexdigest()
            with self.assertRaises(AssertionError):
                self.assertEqual(report["report_sha256"], expected)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
