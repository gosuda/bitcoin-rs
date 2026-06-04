#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: produce-g14-ibd-manifest.sh --output <evidence.json> --ibd-start-height <height> --ibd-stop-height <height> --bitcoin-rs-command <command> --bitcoin-core-command <command> [--criterion-bitcoin-rs-elapsed-seconds <seconds> --criterion-bitcoin-core-elapsed-seconds <seconds> --criterion-bitcoin-rs-benchmark-id <id> --criterion-bitcoin-core-benchmark-id <id>] --bitcoin-rs-config <path> --bitcoin-core-config <path> --bitcoin-core-version <version> --bitcoin-core-commit <40-hex> --benchmark-artifact <path> --utxo-commit-p95-ms <ms> --electrum-get-history-p95-ms <ms> --rss-bytes <bytes>' \
    '' \
    'Runs one bitcoin-rs IBD command and one Bitcoin Core IBD command for the same mainnet height window unless both Criterion elapsed-second arguments are provided.' \
    'If both Criterion elapsed values are supplied, command strings are recorded as provenance and are not run.' \
    'Writes a wall-clock command-wrapper JSON manifest. collect-g14-perf-evidence.sh intentionally rejects this manifest for G14 unless elapsed seconds are replaced with Criterion-sourced evidence.' \
    'The manifest intentionally excludes Core block hashes and chain metadata; collect-g14-perf-evidence.sh must resolve those with live bitcoin-cli.'
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

python3 - "$@" <<'PY'
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def non_empty_text(value: str, name: str) -> str:
    if not value.strip():
        die(f"{name} must not be empty")
    return value


def non_negative_height(value: str, name: str) -> int:
    try:
        height = int(value)
    except ValueError as error:
        die(f"{name} must be a non-negative integer: {error}")
    if height < 0:
        die(f"{name} must be non-negative")
    return height


def positive_float(value: str, name: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        die(f"{name} must be a finite positive number: {error}")
    if not math.isfinite(number) or number <= 0.0:
        die(f"{name} must be finite and positive")
    return number


def positive_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        die(f"{name} must be a positive integer: {error}")
    if number <= 0:
        die(f"{name} must be positive")
    return number


def require_file(path: str, name: str) -> Path:
    resolved = Path(path)
    if not resolved.is_file():
        die(f"{name} is not a readable file: {path}")
    return resolved


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path: Path, name: str) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        die(f"{name} must be UTF-8: {error}")
    return non_empty_text(value, name)


def run_timed(command: str, name: str) -> float:
    started = time.monotonic()
    result = subprocess.run(command, shell=True, text=True, check=False)
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        die(f"{name} command exited with status {result.returncode}")
    if elapsed <= 0.0:
        die(f"{name} elapsed time was not positive")
    return elapsed


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-h", "--help", action="store_true")
parser.add_argument("--output")
parser.add_argument("--ibd-start-height")
parser.add_argument("--ibd-stop-height")
parser.add_argument("--bitcoin-rs-command")
parser.add_argument("--bitcoin-core-command")
parser.add_argument("--bitcoin-rs-config")
parser.add_argument("--bitcoin-core-config")
parser.add_argument("--bitcoin-core-version")
parser.add_argument("--bitcoin-core-commit")
parser.add_argument("--benchmark-artifact")
parser.add_argument("--utxo-commit-p95-ms")
parser.add_argument("--electrum-get-history-p95-ms")
parser.add_argument("--rss-bytes")
parser.add_argument("--criterion-bitcoin-rs-elapsed-seconds")
parser.add_argument("--criterion-bitcoin-core-elapsed-seconds")
parser.add_argument("--criterion-bitcoin-rs-benchmark-id")
parser.add_argument("--criterion-bitcoin-core-benchmark-id")
args = parser.parse_args()

if args.help:
    print(
        "usage: produce-g14-ibd-manifest.sh --output <evidence.json> "
        "--ibd-start-height <height> --ibd-stop-height <height> "
        "--bitcoin-rs-command <command> --bitcoin-core-command <command> "
        "[--criterion-bitcoin-rs-elapsed-seconds <seconds> "
        "--criterion-bitcoin-core-elapsed-seconds <seconds> "
        "--criterion-bitcoin-rs-benchmark-id <id> "
        "--criterion-bitcoin-core-benchmark-id <id>] "
        "--bitcoin-rs-config <path> --bitcoin-core-config <path> "
        "--bitcoin-core-version <version> --bitcoin-core-commit <40-hex> "
        "--benchmark-artifact <path> --utxo-commit-p95-ms <ms> "
        "--electrum-get-history-p95-ms <ms> --rss-bytes <bytes>"
    )
    raise SystemExit(0)

required = {
    "--output": args.output,
    "--ibd-start-height": args.ibd_start_height,
    "--ibd-stop-height": args.ibd_stop_height,
    "--bitcoin-rs-command": args.bitcoin_rs_command,
    "--bitcoin-core-command": args.bitcoin_core_command,
    "--bitcoin-rs-config": args.bitcoin_rs_config,
    "--bitcoin-core-config": args.bitcoin_core_config,
    "--bitcoin-core-version": args.bitcoin_core_version,
    "--bitcoin-core-commit": args.bitcoin_core_commit,
    "--benchmark-artifact": args.benchmark_artifact,
    "--utxo-commit-p95-ms": args.utxo_commit_p95_ms,
    "--electrum-get-history-p95-ms": args.electrum_get_history_p95_ms,
    "--rss-bytes": args.rss_bytes,
}
missing = [name for name, value in required.items() if value is None]
if missing:
    die("missing " + ", ".join(missing))

output = Path(args.output)
if output.exists() and output.is_dir():
    die(f"--output must be a file path, got directory: {output}")
if output.parent and not output.parent.exists():
    die(f"--output parent does not exist: {output.parent}")

start_height = non_negative_height(args.ibd_start_height, "--ibd-start-height")
stop_height = non_negative_height(args.ibd_stop_height, "--ibd-stop-height")
if stop_height < start_height:
    die("--ibd-stop-height must be greater than or equal to --ibd-start-height")

bitcoin_rs_command = non_empty_text(args.bitcoin_rs_command, "--bitcoin-rs-command")
bitcoin_core_command = non_empty_text(args.bitcoin_core_command, "--bitcoin-core-command")
bitcoin_rs_config = read_text(require_file(args.bitcoin_rs_config, "--bitcoin-rs-config"), "--bitcoin-rs-config")
bitcoin_core_config = read_text(require_file(args.bitcoin_core_config, "--bitcoin-core-config"), "--bitcoin-core-config")
bitcoin_core_version = non_empty_text(args.bitcoin_core_version, "--bitcoin-core-version")
bitcoin_core_commit = non_empty_text(args.bitcoin_core_commit, "--bitcoin-core-commit")
if not re.fullmatch(r"[0-9a-f]{40}", bitcoin_core_commit):
    die("--bitcoin-core-commit must be 40 lowercase hex characters")
benchmark_artifact = require_file(args.benchmark_artifact, "--benchmark-artifact")
utxo_commit_p95_ms = positive_float(args.utxo_commit_p95_ms, "--utxo-commit-p95-ms")
electrum_get_history_p95_ms = positive_float(
    args.electrum_get_history_p95_ms,
    "--electrum-get-history-p95-ms",
)
rss_bytes = positive_int(args.rss_bytes, "--rss-bytes")

criterion_elapsed_args = (
    args.criterion_bitcoin_rs_elapsed_seconds,
    args.criterion_bitcoin_core_elapsed_seconds,
)
criterion_elapsed_supplied = [value is not None for value in criterion_elapsed_args]
if any(criterion_elapsed_supplied) and not all(criterion_elapsed_supplied):
    die(
        "--criterion-bitcoin-rs-elapsed-seconds and "
        "--criterion-bitcoin-core-elapsed-seconds must be supplied together"
    )
if all(criterion_elapsed_supplied):
    bench_tool = "criterion"
    elapsed_seconds_source = "criterion"
    bitcoin_rs_benchmark_id = non_empty_text(
        args.criterion_bitcoin_rs_benchmark_id or "",
        "--criterion-bitcoin-rs-benchmark-id",
    )
    bitcoin_core_benchmark_id = non_empty_text(
        args.criterion_bitcoin_core_benchmark_id or "",
        "--criterion-bitcoin-core-benchmark-id",
    )
    bitcoin_rs_elapsed_seconds = positive_float(
        args.criterion_bitcoin_rs_elapsed_seconds,
        "--criterion-bitcoin-rs-elapsed-seconds",
    )
    bitcoin_core_elapsed_seconds = positive_float(
        args.criterion_bitcoin_core_elapsed_seconds,
        "--criterion-bitcoin-core-elapsed-seconds",
    )
else:
    if args.criterion_bitcoin_rs_benchmark_id is not None:
        die("--criterion-bitcoin-rs-benchmark-id requires Criterion elapsed-second arguments")
    if args.criterion_bitcoin_core_benchmark_id is not None:
        die("--criterion-bitcoin-core-benchmark-id requires Criterion elapsed-second arguments")
    bench_tool = "wall-clock-command-wrapper"
    elapsed_seconds_source = "wall-clock-command-wrapper"
    bitcoin_rs_benchmark_id = None
    bitcoin_core_benchmark_id = None
    bitcoin_rs_elapsed_seconds = run_timed(bitcoin_rs_command, "--bitcoin-rs-command")
    bitcoin_core_elapsed_seconds = run_timed(bitcoin_core_command, "--bitcoin-core-command")

manifest = {
    "ibd_start_height": start_height,
    "ibd_stop_height": stop_height,
    "bench_tool": bench_tool,
    "elapsed_seconds_source": elapsed_seconds_source,
    "bitcoin_rs_elapsed_seconds": bitcoin_rs_elapsed_seconds,
    "bitcoin_core_elapsed_seconds": bitcoin_core_elapsed_seconds,
    "bitcoin_core_version": bitcoin_core_version,
    "bitcoin_core_commit": bitcoin_core_commit,
    "bitcoin_rs_command": bitcoin_rs_command,
    "bitcoin_core_command": bitcoin_core_command,
    "bitcoin_rs_config": bitcoin_rs_config,
    "bitcoin_core_config": bitcoin_core_config,
    "benchmark_artifact_sha256": sha256_file(benchmark_artifact),
    "utxo_commit_p95_ms": utxo_commit_p95_ms,
    "electrum_get_history_p95_ms": electrum_get_history_p95_ms,
    "rss_bytes": rss_bytes,
}
if all(criterion_elapsed_supplied):
    manifest["criterion_bitcoin_rs_benchmark_id"] = bitcoin_rs_benchmark_id
    manifest["criterion_bitcoin_core_benchmark_id"] = bitcoin_core_benchmark_id

output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(output)
PY
