#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: measure-g14-utxo-commit-p95.sh --output <measurement.json> --samples <path> --ibd-start-height <height> --ibd-start-hash <64-hex> --ibd-stop-height <height> --ibd-stop-hash <64-hex> [--block-size-threshold-bytes <n>] [--measurement-kind evidence|smoke]' \
    '' \
    'Reads local UTXO commit timing samples and writes a hash-bound G14 measurement artifact.' \
    'Each qualifying sample must include height, block_hash, block_size_bytes, and utxo_commit_ms or utxo_commit_us.' \
    'Only samples with block_size_bytes >= the threshold (default 4 MiB) and height inside the IBD window are used.' \
    '' \
    'Defaults: --block-size-threshold-bytes 4194304 --measurement-kind evidence'
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
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "g14-utxo-commit-measurement-v1"
SMOKE_SCHEMA = "g14-utxo-commit-smoke-v1"
DEFAULT_BLOCK_SIZE_THRESHOLD_BYTES = 4 * 1024 * 1024


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def require_hex(value: str, length: int, name: str) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        die(f"{name} must be {length} lowercase hex characters")
    return value


def non_negative_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        die(f"{name} must be a non-negative integer: {error}")
    if number < 0:
        die(f"{name} must be non-negative")
    return number


def positive_int(value: str, name: str) -> int:
    number = non_negative_int(value, name)
    if number <= 0:
        die(f"{name} must be positive")
    return number


def positive_float(value) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        die("sample timing must be a finite positive number")
    number = float(value)
    if not math.isfinite(number) or number <= 0.0:
        die("sample timing must be finite and positive")
    return number


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_head() -> str:
    output = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], text=True)
    return require_hex(output.strip(), 40, "git HEAD")


def percentile_ms(samples_ms: list[float], numerator: int, denominator: int) -> float:
    if not samples_ms:
        die("cannot calculate percentile for an empty sample")
    ordered = sorted(samples_ms)
    index = math.ceil(len(ordered) * numerator / denominator) - 1
    index = max(0, min(index, len(ordered) - 1))
    return ordered[index]


def read_samples(path: Path) -> list:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        die(f"--samples must be UTF-8 JSON: {error}")
    except json.JSONDecodeError as error:
        die(f"--samples must be JSON: {error}")
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        samples = payload.get("samples")
        if isinstance(samples, list):
            return samples
    die("--samples must be a JSON array or an object with a samples array")


def sample_commit_ms(sample: dict, index: int) -> float:
    if "utxo_commit_ms" in sample and "utxo_commit_us" in sample:
        die(f"samples[{index}] must not include both utxo_commit_ms and utxo_commit_us")
    if "utxo_commit_ms" in sample:
        return positive_float(sample["utxo_commit_ms"])
    if "utxo_commit_us" in sample:
        return positive_float(sample["utxo_commit_us"]) / 1000.0
    die(f"samples[{index}] must include utxo_commit_ms or utxo_commit_us")


def parse_sample(sample, index: int, start_height: int, stop_height: int, threshold_bytes: int) -> float | None:
    if not isinstance(sample, dict):
        die(f"samples[{index}] must be an object")
    height = sample.get("height")
    if not isinstance(height, int) or isinstance(height, bool):
        die(f"samples[{index}].height must be an integer")
    if height < start_height or height > stop_height:
        die(f"samples[{index}].height must be within the IBD window")
    require_hex(str(sample.get("block_hash", "")), 64, f"samples[{index}].block_hash")
    block_size = sample.get("block_size_bytes")
    if not isinstance(block_size, int) or isinstance(block_size, bool):
        die(f"samples[{index}].block_size_bytes must be an integer")
    if block_size < threshold_bytes:
        return None
    return sample_commit_ms(sample, index)


def write_json(path: str, data: dict) -> None:
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if path == "-":
        sys.stdout.write(encoded)
        return
    Path(path).write_text(encoded, encoding="utf-8")


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--help", action="store_true")
parser.add_argument("--output")
parser.add_argument("--samples")
parser.add_argument("--ibd-start-height")
parser.add_argument("--ibd-start-hash")
parser.add_argument("--ibd-stop-height")
parser.add_argument("--ibd-stop-hash")
parser.add_argument("--block-size-threshold-bytes", default=str(DEFAULT_BLOCK_SIZE_THRESHOLD_BYTES))
parser.add_argument("--measurement-kind", default="evidence", choices=["evidence", "smoke"])
args = parser.parse_args(sys.argv[1:])

if args.help:
    print("usage: measure-g14-utxo-commit-p95.sh --output <measurement.json> --samples <path> --ibd-start-height <height> --ibd-start-hash <64-hex> --ibd-stop-height <height> --ibd-stop-hash <64-hex> [--block-size-threshold-bytes <n>] [--measurement-kind evidence|smoke]")
    raise SystemExit(0)

for key in ("output", "samples", "ibd_start_height", "ibd_start_hash", "ibd_stop_height", "ibd_stop_hash"):
    if getattr(args, key) is None:
        die(f"--{key.replace('_', '-')} is required")

start_height = non_negative_int(args.ibd_start_height, "--ibd-start-height")
stop_height = non_negative_int(args.ibd_stop_height, "--ibd-stop-height")
if stop_height < start_height:
    die("--ibd-stop-height must be greater than or equal to --ibd-start-height")
start_hash = require_hex(args.ibd_start_hash, 64, "--ibd-start-hash")
stop_hash = require_hex(args.ibd_stop_hash, 64, "--ibd-stop-hash")
threshold_bytes = positive_int(args.block_size_threshold_bytes, "--block-size-threshold-bytes")
samples_path = Path(args.samples)
if not samples_path.is_file():
    die(f"--samples is not a readable file: {samples_path}")

qualifying_ms: list[float] = []
for index, sample in enumerate(read_samples(samples_path)):
    parsed = parse_sample(sample, index, start_height, stop_height, threshold_bytes)
    if parsed is not None:
        qualifying_ms.append(parsed)

if not qualifying_ms and args.measurement_kind == "evidence":
    die("no qualifying UTXO commit samples at or above the block size threshold")

if args.measurement_kind == "smoke" and not qualifying_ms:
    qualifying_ms = [1.0]

data = {
    "schema": SMOKE_SCHEMA if args.measurement_kind == "smoke" else SCHEMA,
    "measurement_kind": args.measurement_kind,
    "bitcoin_rs_commit": current_head(),
    "ibd_start_height": start_height,
    "ibd_start_hash": start_hash,
    "ibd_stop_height": stop_height,
    "ibd_stop_hash": stop_hash,
    "block_size_threshold_bytes": threshold_bytes,
    "sample_source_path": str(samples_path.resolve()),
    "sample_source_sha256": sha256_file(samples_path),
    "sample_count": len(qualifying_ms),
    "utxo_commit_p50_ms": percentile_ms(qualifying_ms, 50, 100),
    "utxo_commit_p95_ms": percentile_ms(qualifying_ms, 95, 100),
    "utxo_commit_p99_ms": percentile_ms(qualifying_ms, 99, 100),
    "utxo_commit_max_ms": max(qualifying_ms),
}
write_json(args.output, data)
PY
