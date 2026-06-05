#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: run-g14-mainnet-ibd-criterion.sh --output <artifact.json> --benchmark-run-id <id> --benchmark-host-id <id> --ibd-start-height <height> --ibd-stop-height <height> --bitcoin-rs-command <command> --bitcoin-core-command <command> --bitcoin-rs-config <path> --bitcoin-core-config <path> [--criterion-bitcoin-rs-raw-output <path>] [--criterion-bitcoin-core-raw-output <path>] [--force] [-- <bitcoin-cli-arg>...]' \
    '' \
    'Runs one bitcoin-rs Criterion command and one Bitcoin Core Criterion command, captures their raw output, extracts canonical mainnet IBD elapsed seconds, then delegates artifact validation to produce-g14-criterion-artifact.sh.' \
    'Set BITCOIN_CLI=/path/to/bitcoin-cli to override the binary used by the artifact producer.'
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR

python3 - "$@" <<'PY'
import argparse
import math
import os
from pathlib import Path
import re
import subprocess
import sys

BITCOIN_RS_CRITERION_BENCHMARK_ID = "bitcoin-rs/mainnet-ibd"
BITCOIN_CORE_CRITERION_BENCHMARK_ID = "bitcoin-core/mainnet-ibd"
CRITERION_NUMBER_PATTERN = r"[0-9]+(?:\.[0-9]+)?"
CRITERION_UNIT_PATTERN = "(?:ns|us|\u00b5s|ms|s)"
CRITERION_INTERVAL_RE = re.compile(
    rf"time:\s*\[\s*({CRITERION_NUMBER_PATTERN})\s*({CRITERION_UNIT_PATTERN})\s+"
    rf"({CRITERION_NUMBER_PATTERN})\s*({CRITERION_UNIT_PATTERN})\s+"
    rf"({CRITERION_NUMBER_PATTERN})\s*({CRITERION_UNIT_PATTERN})\s*\]"
)
CRITERION_SINGLE_RE = re.compile(
    rf"time:\s*({CRITERION_NUMBER_PATTERN})\s*({CRITERION_UNIT_PATTERN})"
)
CRITERION_UNIT_SECONDS = {
    "ns": 0.000_000_001,
    "us": 0.000_001,
    "\u00b5s": 0.000_001,
    "ms": 0.001,
    "s": 1.0,
}


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def non_empty_text(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        die(f"{name} must not be empty")
    return value


def non_negative_height(value: str | None, name: str) -> int:
    raw = non_empty_text(value, name)
    try:
        height = int(raw)
    except ValueError as error:
        die(f"{name} must be a non-negative integer: {error}")
    if height < 0:
        die(f"{name} must be non-negative")
    return height


def require_file(path: str | None, name: str) -> Path:
    raw = non_empty_text(path, name)
    resolved = Path(raw)
    if not resolved.is_file():
        die(f"{name} is not a readable file: {raw}")
    return resolved


def read_text(path: Path, name: str) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        die(f"{name} must be UTF-8: {error}")
    return non_empty_text(value, name)


def ensure_output_path(path: str | None, name: str, force: bool) -> Path:
    raw = non_empty_text(path, name)
    resolved = Path(raw)
    if resolved.exists() and resolved.is_dir():
        die(f"{name} must be a file path, got directory: {resolved}")
    if resolved.exists() and not force:
        die(f"{name} already exists; pass --force to replace it: {resolved}")
    if resolved.parent and not resolved.parent.exists():
        die(f"{name} parent does not exist: {resolved.parent}")
    return resolved


def criterion_seconds(value: str, unit: str) -> float:
    return float(value) * CRITERION_UNIT_SECONDS[unit]


def criterion_label_matches(line: str, benchmark_id: str) -> bool:
    stripped = line.strip()
    return stripped == benchmark_id or stripped == f"Benchmarking {benchmark_id}"


def criterion_phase_matches(line: str, benchmark_id: str) -> bool:
    return line.strip().startswith(f"Benchmarking {benchmark_id}:")


def criterion_label_like(line: str) -> bool:
    stripped = line.strip()
    if stripped.startswith("Benchmarking "):
        stripped = stripped.removeprefix("Benchmarking ").split(":", 1)[0].strip()
    return re.fullmatch(r"[^\s:]+(?:/[^\s:]+)+", stripped) is not None


def criterion_time_prefix_matches(line: str, benchmark_id: str) -> bool:
    prefix = line.split("time:", 1)[0].strip()
    return prefix == benchmark_id


def criterion_elapsed_seconds(raw_output: str, benchmark_id: str, name: str) -> float:
    lines = raw_output.splitlines()
    for index, line in enumerate(lines):
        if not criterion_label_matches(line, benchmark_id):
            continue
        for offset, candidate in enumerate(lines[index : min(len(lines), index + 16)]):
            if offset > 0 and criterion_phase_matches(candidate, benchmark_id):
                continue
            if offset > 0 and criterion_label_like(candidate) and not criterion_label_matches(candidate, benchmark_id):
                break
            if "time:" in candidate and not criterion_time_prefix_matches(candidate, benchmark_id):
                break
            interval = CRITERION_INTERVAL_RE.search(candidate)
            if interval:
                return criterion_seconds(interval.group(3), interval.group(4))
            single = CRITERION_SINGLE_RE.search(candidate)
            if single:
                return criterion_seconds(single.group(1), single.group(2))
    die(f"{name} must contain Criterion time output for benchmark {benchmark_id!r}")


def run_criterion_command(command: str, raw_output: Path, benchmark_id: str, name: str) -> str:
    with raw_output.open("w", encoding="utf-8") as handle:
        result = subprocess.run(command, shell=True, stdout=handle, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        die(f"{name} failed with status {result.returncode}")
    elapsed = criterion_elapsed_seconds(read_text(raw_output, name), benchmark_id, name)
    if not math.isfinite(elapsed) or elapsed <= 0.0:
        die(f"{name} elapsed time must be positive")
    return f"{elapsed:.12g}"


def script_dir() -> Path:
    return Path(os.environ["SCRIPT_DIR"])


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-h", "--help", action="store_true")
parser.add_argument("--output")
parser.add_argument("--benchmark-run-id")
parser.add_argument("--benchmark-host-id")
parser.add_argument("--ibd-start-height")
parser.add_argument("--ibd-stop-height")
parser.add_argument("--bitcoin-rs-command")
parser.add_argument("--bitcoin-core-command")
parser.add_argument("--bitcoin-rs-config")
parser.add_argument("--bitcoin-core-config")
parser.add_argument("--criterion-bitcoin-rs-raw-output")
parser.add_argument("--criterion-bitcoin-core-raw-output")
parser.add_argument("--force", action="store_true")
parser.add_argument("bitcoin_cli_args", nargs=argparse.REMAINDER)
args = parser.parse_args()

if args.help:
    usage = (
        "usage: run-g14-mainnet-ibd-criterion.sh --output <artifact.json> "
        "--benchmark-run-id <id> --benchmark-host-id <id> --ibd-start-height <height> "
        "--ibd-stop-height <height> --bitcoin-rs-command <command> --bitcoin-core-command <command> "
        "--bitcoin-rs-config <path> --bitcoin-core-config <path> "
        "[--criterion-bitcoin-rs-raw-output <path>] [--criterion-bitcoin-core-raw-output <path>] "
        "[--force] [-- <bitcoin-cli-arg>...]"
    )
    print(usage)
    raise SystemExit(0)

required = {
    "--output": args.output,
    "--benchmark-run-id": args.benchmark_run_id,
    "--benchmark-host-id": args.benchmark_host_id,
    "--ibd-start-height": args.ibd_start_height,
    "--ibd-stop-height": args.ibd_stop_height,
    "--bitcoin-rs-command": args.bitcoin_rs_command,
    "--bitcoin-core-command": args.bitcoin_core_command,
    "--bitcoin-rs-config": args.bitcoin_rs_config,
    "--bitcoin-core-config": args.bitcoin_core_config,
}
missing = [name for name, value in required.items() if value is None]
if missing:
    die("missing " + ", ".join(missing))

output = ensure_output_path(args.output, "--output", args.force)
start_height = non_negative_height(args.ibd_start_height, "--ibd-start-height")
stop_height = non_negative_height(args.ibd_stop_height, "--ibd-stop-height")
if stop_height < start_height:
    die("--ibd-stop-height must be greater than or equal to --ibd-start-height")

benchmark_run_id = non_empty_text(args.benchmark_run_id, "--benchmark-run-id")
benchmark_host_id = non_empty_text(args.benchmark_host_id, "--benchmark-host-id")
bitcoin_rs_command = non_empty_text(args.bitcoin_rs_command, "--bitcoin-rs-command")
bitcoin_core_command = non_empty_text(args.bitcoin_core_command, "--bitcoin-core-command")
bitcoin_rs_config = require_file(args.bitcoin_rs_config, "--bitcoin-rs-config")
bitcoin_core_config = require_file(args.bitcoin_core_config, "--bitcoin-core-config")

bitcoin_rs_raw_output = ensure_output_path(
    args.criterion_bitcoin_rs_raw_output
    or str(output.with_suffix(".bitcoin-rs-criterion-raw-output.txt")),
    "--criterion-bitcoin-rs-raw-output",
    args.force,
)
bitcoin_core_raw_output = ensure_output_path(
    args.criterion_bitcoin_core_raw_output
    or str(output.with_suffix(".bitcoin-core-criterion-raw-output.txt")),
    "--criterion-bitcoin-core-raw-output",
    args.force,
)
created_paths = [output, bitcoin_rs_raw_output, bitcoin_core_raw_output]

try:
    for path in created_paths:
        if path.exists():
            path.unlink()
    bitcoin_rs_elapsed_seconds = run_criterion_command(
        bitcoin_rs_command,
        bitcoin_rs_raw_output,
        BITCOIN_RS_CRITERION_BENCHMARK_ID,
        "--bitcoin-rs-command",
    )
    bitcoin_core_elapsed_seconds = run_criterion_command(
        bitcoin_core_command,
        bitcoin_core_raw_output,
        BITCOIN_CORE_CRITERION_BENCHMARK_ID,
        "--bitcoin-core-command",
    )

    bitcoin_cli_args = args.bitcoin_cli_args
    if bitcoin_cli_args and bitcoin_cli_args[0] == "--":
        bitcoin_cli_args = bitcoin_cli_args[1:]
    producer = script_dir() / "produce-g14-criterion-artifact.sh"
    command = [
        str(producer),
        "--output",
        str(output),
        "--benchmark-run-id",
        benchmark_run_id,
        "--benchmark-host-id",
        benchmark_host_id,
        "--ibd-start-height",
        str(start_height),
        "--ibd-stop-height",
        str(stop_height),
        "--criterion-bitcoin-rs-elapsed-seconds",
        bitcoin_rs_elapsed_seconds,
        "--criterion-bitcoin-core-elapsed-seconds",
        bitcoin_core_elapsed_seconds,
        "--criterion-bitcoin-rs-raw-output",
        str(bitcoin_rs_raw_output),
        "--criterion-bitcoin-core-raw-output",
        str(bitcoin_core_raw_output),
        "--bitcoin-rs-command",
        bitcoin_rs_command,
        "--bitcoin-core-command",
        bitcoin_core_command,
        "--bitcoin-rs-config",
        str(bitcoin_rs_config),
        "--bitcoin-core-config",
        str(bitcoin_core_config),
        "--force",
    ]
    if bitcoin_cli_args:
        command.extend(["--", *bitcoin_cli_args])
    env = dict(os.environ)
    subprocess.run(command, check=True, env=env)
except (subprocess.CalledProcessError, SystemExit):
    for path in created_paths:
        if path.exists():
            path.unlink()
    raise

print(output)
PY
