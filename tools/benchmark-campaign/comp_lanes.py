#!/usr/bin/env python3.14
# pyright: strict
"""Campaign lane runner for comparator issues #34, #35, #41.

Runs each comparator in its offline-reachable mode and produces a combined
lane report.  The P2P loopback lane (#35) and the offline full-validation lane (#34)
are fully reachable offline using deterministic fixture nodes.  The
MuHash RPC lane (#41) requires a ``bitcoind`` binary; when it is absent
the lane records the blocking fact and the exact command that failed.

This is a thin orchestrator over the existing comparators — it does not
re-implement any comparison logic.
"""

import argparse
import hashlib
import json
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import offline_full_validation  # noqa: E402
import p2p_loopback  # noqa: E402
from offline_full_validation import (  # noqa: E402
    CONFIG_SCHEMA as OFFLINE_CONFIG_SCHEMA,
    MANIFEST_SCHEMA as OFFLINE_MANIFEST_SCHEMA,
    CertifiedState as OfflineState,
    canonical_bytes as offline_canonical_bytes,
    header_hash as offline_header_hash,
    main as offline_main,
    state_json as offline_state_json,
)
from p2p_loopback import (  # noqa: E402
    CONFIG_SCHEMA as P2P_CONFIG_SCHEMA,
    canonical_bytes as p2p_canonical_bytes,
    canonical_sha256 as p2p_canonical_sha256,
    main as p2p_main,
)

LANE_REPORT_SCHEMA = "comp-lanes-report-v1"
MAGIC = "f9beb4d9"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _node_source(expect_bytes: int, echo: bytes, final_state: dict[str, object]) -> str:
    return f"""#!{sys.executable}
import json, socket, sys
from pathlib import Path
paired = [a for a in sys.argv[1:] if a != "--restart"]
args = dict(zip(paired[::2], paired[1::2], strict=True))
conn = socket.create_connection((args['--peer-host'], int(args['--peer-port'])), timeout=5.0)
if {echo.hex()!r}:
    conn.send(bytes.fromhex({echo.hex()!r}))
remaining = {expect_bytes!r}
while remaining:
    chunk = conn.recv(min(65536, remaining))
    if not chunk:
        raise SystemExit(9)
    remaining -= len(chunk)
with open(args['--state-path'], 'w') as f:
    json.dump({final_state!r}, f, sort_keys=True)
conn.close()
raise SystemExit(0)
"""


def _frame(index: int, command: str, payload: bytes, magic: str = MAGIC) -> bytes:
    wire_payload = bytes([index]) * 8 + payload
    checksum = hashlib.sha256(hashlib.sha256(wire_payload).digest()).digest()[:4]
    head = (
        bytes.fromhex(magic)
        + command.encode("ascii").ljust(12, b"\x00")
        + len(wire_payload).to_bytes(4, "little")
        + checksum
    )
    return head + wire_payload


def _step(
    kind: str,
    *,
    frame: int | None = None,
    delay_ns: int = 0,
    bandwidth: int | None = None,
    duration_ns: int = 0,
    after_bytes: int | None = None,
) -> dict[str, object]:
    return {
        "kind": kind,
        "frame": frame,
        "delay_ns": delay_ns,
        "bandwidth_bytes_per_second": bandwidth,
        "duration_ns": duration_ns,
        "after_bytes": after_bytes,
    }


def _default_schedule(echo: bytes) -> list[dict[str, object]]:
    return [
        _step("send", frame=0, delay_ns=1_000_000),
        _step("stall", duration_ns=2_000_000),
        _step("send", frame=1, bandwidth=33_554_432),
        _step("send", frame=2),
        _step("disconnect", after_bytes=len(echo) or None),
    ]


def _build_p2p_fixture(workspace: Path) -> Path:
    """Create a deterministic P2P loopback config with fixture nodes."""
    echo = bytes.fromhex(MAGIC) + b"\x11version"
    frames = [
        _frame(i, ("tx", "block", "tx")[i], bytes([0x45 + i]) * (100 + i))
        for i in range(3)
    ]
    final_state: dict[str, object] = {"phase": "final", "rows": 3, "tip": "f" * 64}
    expect_bytes = sum(len(f) for f in frames)
    command = [
        "{binary}",
        "--peer-host",
        "{peer_host}",
        "--peer-port",
        "{peer_port}",
        "--state-path",
        "{state_path}",
    ]
    node_src = _node_source(expect_bytes, echo, final_state)
    core_binary = _write_executable(workspace / "core-node.py", node_src)
    cand_binary = _write_executable(workspace / "candidate-node.py", node_src)

    def _program(binary: Path) -> dict[str, object]:
        return {
            "binary": str(binary),
            "binary_sha256": _sha256_file(binary),
            "command": command,
            "restart_command": None,
        }

    config = {
        "schema": P2P_CONFIG_SCHEMA,
        "peer": {
            "network_magic": MAGIC,
            "protocol_version": 70016,
            "services": 1,
            "connect_timeout_ns": 5_000_000_000,
            "io_timeout_ns": 5_000_000_000,
            "socket_buffer_bytes": 262_144,
            "expected_inbound_sha256": hashlib.sha256(echo).hexdigest(),
        },
        "lifecycle": {
            "mode": "fresh",
            "generation": 4,
            "initial_state": {"generation": 3, "tip": "e" * 64},
            "expected_final_state": final_state,
            "expected_restart_state": None,
        },
        "corpus": [f.hex() for f in frames],
        "schedule": _default_schedule(echo),
        "core": _program(core_binary),
        "candidate": _program(cand_binary),
    }
    config_path = workspace / "p2p-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return config_path


def run_p2p_lane(workspace: Path) -> dict[str, object]:
    """Run the P2P loopback comparator (#35) with fixture nodes.

    Returns a lane result dict with either the result artifact path or
    a blocking error.
    """
    config_path = _build_p2p_fixture(workspace)
    output_path = workspace / "p2p-result.json"
    started = time.monotonic_ns()
    try:
        code = p2p_main(["--config", str(config_path), "--output", str(output_path)])
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
    elapsed_ns = time.monotonic_ns() - started
    if code != 0 or not output_path.is_file():
        return {
            "issue": "#35",
            "lane": "p2p-loopback",
            "status": "blocked",
            "reason": f"p2p_loopback exited with code {code}",
            "elapsed_ns": elapsed_ns,
        }
    result = json.loads(output_path.read_bytes())
    return {
        "issue": "#35",
        "lane": "p2p-loopback",
        "status": "passed",
        "result_path": str(output_path),
        "result_schema": result.get("schema"),
        "pair_count": result.get("pair_count"),
        "arm_count": len(result.get("arms", [])),
        "correctness": result.get("correctness"),
        "ratio": result.get("candidate_over_core_p50_ratio"),
        "result_sha256": result.get("result_sha256"),
        "elapsed_ns": elapsed_ns,
    }


def _offline_payload(marker: int) -> bytes:
    return bytes([marker]) * 80 + bytes([marker])


def _offline_record(payload: bytes) -> bytes:
    return bytes.fromhex(MAGIC) + len(payload).to_bytes(4, "little") + payload


def _offline_node_source(expected: OfflineState) -> str:
    payload = json.dumps(offline_state_json(expected), sort_keys=True)
    return f"""#!{sys.executable}
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--data-dir', required=True)
parser.add_argument('--corpus', required=True)
parser.add_argument('--manifest', required=True)
parser.add_argument('--state', required=True)
args = parser.parse_args()
corpus = Path(args.corpus).read_bytes()
if not corpus:
    raise SystemExit(3)
Path(args.data_dir, 'imported').write_bytes(corpus)
Path(args.state).write_text({payload!r} + '\\n', encoding='utf-8')
raise SystemExit(0)
"""


def _build_offline_fixture(workspace: Path) -> Path:
    """Create a two-block Core-framed archive and fixture importer nodes."""
    payloads = (_offline_payload(1), _offline_payload(2))
    records = [_offline_record(payload) for payload in payloads]
    archive_bytes = b"".join(records)
    archive_path = workspace / "blocks.dat"
    archive_path.write_bytes(archive_bytes)
    hashes = [offline_header_hash(payload) for payload in payloads]
    offset = 0
    entries: list[dict[str, object]] = []
    for height, (payload, digest, record) in enumerate(
        zip(payloads, hashes, records, strict=True)
    ):
        entries.append(
            {
                "height": height,
                "hash": digest,
                "offset": offset,
                "payload_length": len(payload),
            }
        )
        offset += len(record)
    manifest = {
        "schema": OFFLINE_MANIFEST_SCHEMA,
        "network": "mainnet",
        "network_magic": MAGIC,
        "start_height": 0,
        "stop_height": 1,
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "archive_bytes": len(archive_bytes),
        "blocks": entries,
    }
    manifest_path = workspace / "offline-manifest.json"
    manifest_bytes = offline_canonical_bytes(manifest) + b"\n"
    manifest_path.write_bytes(manifest_bytes)
    expected = OfflineState(
        1,
        hashes[-1],
        2,
        5_000_000_000,
        "cd" * 32,
        "ef" * 32,
        True,
        True,
    )
    node = _write_executable(
        workspace / "offline-node.py", _offline_node_source(expected)
    )
    digest = _sha256_file(node)
    command = [
        "{binary}",
        "--data-dir",
        "{data_dir}",
        "--corpus",
        "{corpus_path}",
        "--manifest",
        "{manifest_path}",
        "--state",
        "{state_path}",
    ]

    def _program() -> dict[str, object]:
        return {
            "binary": str(node),
            "binary_sha256": digest,
            "command": command,
            "reopen_command": None,
        }

    config = {
        "schema": OFFLINE_CONFIG_SCHEMA,
        "network_magic": MAGIC,
        "arm_timeout_ns": 10_000_000_000,
        "posture": {
            "assume_valid": False,
            "txindex": False,
            "blockfilterindex": False,
            "coinstatsindex": False,
            "cache_policy": "process-cold/page-cache-unspecified",
        },
        "corpus": {
            "archive": {
                "path": str(archive_path),
                "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                "bytes": len(archive_bytes),
            },
            "manifest": {
                "path": str(manifest_path),
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "bytes": len(manifest_bytes),
            },
        },
        "expected_state": offline_state_json(expected),
        "core": _program(),
        "candidate": _program(),
        "lifecycle": {"mode": "fresh", "expected_reopen_state": None},
    }
    config_path = workspace / "offline-config.json"
    config_path.write_bytes(offline_canonical_bytes(config) + b"\n")
    return config_path


def run_offline_lane(workspace: Path) -> dict[str, object]:
    """Run the offline full-validation comparator (#34) with fixture nodes."""
    config_path = _build_offline_fixture(workspace)
    output_path = workspace / "offline-result.json"
    started = time.monotonic_ns()
    try:
        code = offline_main(["--config", str(config_path), "--output", str(output_path)])
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
    except offline_full_validation.ContractError as exc:
        return {
            "issue": "#34",
            "lane": "offline-full-validation",
            "status": "blocked",
            "reason": str(exc),
            "elapsed_ns": time.monotonic_ns() - started,
        }
    elapsed_ns = time.monotonic_ns() - started
    if code != 0 or not output_path.is_file():
        return {
            "issue": "#34",
            "lane": "offline-full-validation",
            "status": "blocked",
            "reason": f"offline_full_validation exited with code {code}",
            "elapsed_ns": elapsed_ns,
        }
    result = json.loads(output_path.read_bytes())
    return {
        "issue": "#34",
        "lane": "offline-full-validation",
        "status": "passed",
        "result_path": str(output_path),
        "result_schema": result.get("schema"),
        "pair_count": result.get("pair_count"),
        "arm_count": len(result.get("arms", [])),
        "correctness": result.get("correctness"),
        "ratio": result.get("candidate_over_core_p50_ratio"),
        "result_sha256": result.get("result_sha256"),
        "elapsed_ns": elapsed_ns,
    }


def _find_bitcoind() -> str | None:
    """Return the path to bitcoind if found on PATH, else None."""
    return shutil.which("bitcoind")


def run_rpc_lane(workspace: Path) -> dict[str, object]:
    """Check whether the MuHash RPC comparator (#41) can run.

    The comparator in ``muhash_rpc.py`` requires a running ``bitcoind``
    daemon with RPC enabled.  When ``bitcoind`` is absent the lane
    records the blocking fact.
    """
    bitcoind = _find_bitcoind()
    if bitcoind is None:
        return {
            "issue": "#41",
            "lane": "muhash-rpc",
            "status": "blocked",
            "reason": "bitcoind binary not found on PATH",
            "command_run": "shutil.which('bitcoind')",
            "command_result": None,
        }
    return {
        "issue": "#41",
        "lane": "muhash-rpc",
        "status": "reachable",
        "reason": None,
        "bitcoind_path": bitcoind,
    }


def run_all_lanes(workspace: Path) -> dict[str, object]:
    """Run all three comparator lanes and produce a combined report."""
    p2p = run_p2p_lane(workspace)
    offline = run_offline_lane(workspace)
    rpc = run_rpc_lane(workspace)
    report: dict[str, object] = {
        "schema": LANE_REPORT_SCHEMA,
        "timestamp_ns": time.time_ns(),
        "lanes": [offline, p2p, rpc],
    }
    report["report_sha256"] = p2p_canonical_sha256(
        {k: v for k, v in report.items() if k != "report_sha256"}
    )
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path for the combined lane report JSON",
    )
    parser.add_argument(
    "--workspace",
        type=Path,
        default=None,
        help="Working directory for fixture files (default: temp dir)",
    )
    args = parser.parse_args(argv)

    if args.workspace is not None:
        workspace = args.workspace
        workspace.mkdir(parents=True, exist_ok=True)
        cleanup: tempfile.TemporaryDirectory[str] | None = None
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="comp-lanes-")
        workspace = Path(cleanup.name)

    try:
        report = run_all_lanes(workspace)
        output = args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(p2p_canonical_bytes(report) + b"\n")
        print(f"comp-lanes: report written to {output}")
        for lane in report["lanes"]:  # type: ignore[union-attr]
            assert isinstance(lane, dict)
            print(
                f"  {lane['issue']} {lane['lane']}: {lane['status']}"
                + (f" — {lane['reason']}" if lane.get("reason") else "")
            )
        return 0
    finally:
        if cleanup is not None:
            cleanup.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
