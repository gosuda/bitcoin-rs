#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: produce-g14-criterion-artifact.sh --output <artifact.json> --benchmark-run-id <id> --benchmark-host-id <id> --ibd-start-height <height> --ibd-stop-height <height> --criterion-bitcoin-rs-elapsed-seconds <seconds> --criterion-bitcoin-core-elapsed-seconds <seconds> --criterion-bitcoin-rs-raw-output <path> --criterion-bitcoin-core-raw-output <path> --bitcoin-rs-command <command> --bitcoin-core-command <command> --bitcoin-rs-config <path> --bitcoin-core-config <path> [--force] [-- <bitcoin-cli-arg>...]' \
    '' \
    'Packages externally measured Criterion elapsed seconds for one bitcoin-rs IBD run and one Bitcoin Core IBD run over a live mainnet height window.' \
    'Writes a fail-closed g14-criterion-artifact-v1 JSON artifact consumable by produce-g14-ibd-manifest.sh; this helper does not time commands itself.' \
    'The artifact binds live bitcoin-cli start/stop hashes, canonical benchmark IDs, one shared benchmark_run_id, one shared benchmark_host_id, command/config SHA-256 fields, and raw Criterion output SHA-256 fields.' \
    '' \
    'Set BITCOIN_CLI=/path/to/bitcoin-cli to override the binary.'
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
import os
from pathlib import Path
import re
import subprocess

CRITERION_ARTIFACT_SCHEMA = "g14-criterion-artifact-v1"
BITCOIN_RS_CRITERION_BENCHMARK_ID = "bitcoin-rs/mainnet-ibd"
BITCOIN_CORE_CRITERION_BENCHMARK_ID = "bitcoin-core/mainnet-ibd"


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


def positive_float(value: str | None, name: str) -> float:
    raw = non_empty_text(value, name)
    try:
        number = float(raw)
    except ValueError as error:
        die(f"{name} must be a finite positive number: {error}")
    if not math.isfinite(number) or number <= 0.0:
        die(f"{name} must be finite and positive")
    return number


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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_bitcoin_cli(bitcoin_cli: str, bitcoin_cli_args: list[str], command: str, *args: str) -> str:
    try:
        output = subprocess.check_output(
            [bitcoin_cli, *bitcoin_cli_args, command, *args],
            text=True,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        die(f"BITCOIN_CLI is not executable: {error}")
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        die(f"bitcoin-cli {command} failed with status {error.returncode}{detail}")
    return output.strip()


def require_live_hash(value: str, name: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        die(f"{name} must be 64 lowercase hex characters")
    return value


def require_chain_height(data: dict, key: str, stop_height: int) -> None:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"bitcoin-cli getblockchaininfo {key} must be an integer")
    if value < stop_height:
        die(
            f"bitcoin-cli getblockchaininfo {key}={value} is below "
            f"ibd_stop_height={stop_height}"
        )


def require_mainnet_chain_info(raw: str, stop_height: int) -> None:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        die(f"bitcoin-cli getblockchaininfo must return JSON: {error}")
    if not isinstance(data, dict):
        die("bitcoin-cli getblockchaininfo must return a JSON object")
    if data.get("chain") != "main":
        die(f"bitcoin-cli must be connected to mainnet, got chain={data.get('chain')!r}")
    require_chain_height(data, "blocks", stop_height)
    require_chain_height(data, "headers", stop_height)


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-h", "--help", action="store_true")
parser.add_argument("--output")
parser.add_argument("--benchmark-run-id")
parser.add_argument("--benchmark-host-id")
parser.add_argument("--ibd-start-height")
parser.add_argument("--ibd-stop-height")
parser.add_argument("--criterion-bitcoin-rs-elapsed-seconds")
parser.add_argument("--criterion-bitcoin-core-elapsed-seconds")
parser.add_argument("--criterion-bitcoin-rs-raw-output")
parser.add_argument("--criterion-bitcoin-core-raw-output")
parser.add_argument("--bitcoin-rs-command")
parser.add_argument("--bitcoin-core-command")
parser.add_argument("--bitcoin-rs-config")
parser.add_argument("--bitcoin-core-config")
parser.add_argument("--force", action="store_true")
parser.add_argument("bitcoin_cli_args", nargs=argparse.REMAINDER)
args = parser.parse_args()

if args.help:
    usage = (
        "usage: produce-g14-criterion-artifact.sh --output <artifact.json> "
        "--benchmark-run-id <id> --benchmark-host-id <id> --ibd-start-height <height> "
        "--ibd-stop-height <height> --criterion-bitcoin-rs-elapsed-seconds <seconds> "
        "--criterion-bitcoin-core-elapsed-seconds <seconds> "
        "--criterion-bitcoin-rs-raw-output <path> --criterion-bitcoin-core-raw-output <path> "
        "--bitcoin-rs-command <command> --bitcoin-core-command <command> --bitcoin-rs-config <path> "
        "--bitcoin-core-config <path> [--force] [-- <bitcoin-cli-arg>...]"
    )
    print(usage)
    raise SystemExit(0)

required = {
    "--output": args.output,
    "--benchmark-run-id": args.benchmark_run_id,
    "--benchmark-host-id": args.benchmark_host_id,
    "--ibd-start-height": args.ibd_start_height,
    "--ibd-stop-height": args.ibd_stop_height,
    "--criterion-bitcoin-rs-elapsed-seconds": args.criterion_bitcoin_rs_elapsed_seconds,
    "--criterion-bitcoin-core-elapsed-seconds": args.criterion_bitcoin_core_elapsed_seconds,
    "--criterion-bitcoin-rs-raw-output": args.criterion_bitcoin_rs_raw_output,
    "--criterion-bitcoin-core-raw-output": args.criterion_bitcoin_core_raw_output,
    "--bitcoin-rs-command": args.bitcoin_rs_command,
    "--bitcoin-core-command": args.bitcoin_core_command,
    "--bitcoin-rs-config": args.bitcoin_rs_config,
    "--bitcoin-core-config": args.bitcoin_core_config,
}
missing = [name for name, value in required.items() if value is None]
if missing:
    die("missing " + ", ".join(missing))

output = Path(args.output)
if output.exists() and output.is_dir():
    die(f"--output must be a file path, got directory: {output}")
if output.exists() and not args.force:
    die(f"--output already exists; pass --force to replace it: {output}")
if output.parent and not output.parent.exists():
    die(f"--output parent does not exist: {output.parent}")
if output.exists():
    output.unlink()

benchmark_run_id = non_empty_text(args.benchmark_run_id, "--benchmark-run-id")
benchmark_host_id = non_empty_text(args.benchmark_host_id, "--benchmark-host-id")
start_height = non_negative_height(args.ibd_start_height, "--ibd-start-height")
stop_height = non_negative_height(args.ibd_stop_height, "--ibd-stop-height")
if stop_height < start_height:
    die("--ibd-stop-height must be greater than or equal to --ibd-start-height")

bitcoin_rs_elapsed_seconds = positive_float(
    args.criterion_bitcoin_rs_elapsed_seconds,
    "--criterion-bitcoin-rs-elapsed-seconds",
)
bitcoin_core_elapsed_seconds = positive_float(
    args.criterion_bitcoin_core_elapsed_seconds,
    "--criterion-bitcoin-core-elapsed-seconds",
)
bitcoin_rs_raw_output = require_file(args.criterion_bitcoin_rs_raw_output, "--criterion-bitcoin-rs-raw-output")
bitcoin_core_raw_output = require_file(args.criterion_bitcoin_core_raw_output, "--criterion-bitcoin-core-raw-output")
bitcoin_rs_command = non_empty_text(args.bitcoin_rs_command, "--bitcoin-rs-command")
bitcoin_core_command = non_empty_text(args.bitcoin_core_command, "--bitcoin-core-command")
bitcoin_rs_config = read_text(require_file(args.bitcoin_rs_config, "--bitcoin-rs-config"), "--bitcoin-rs-config")
bitcoin_core_config = read_text(require_file(args.bitcoin_core_config, "--bitcoin-core-config"), "--bitcoin-core-config")

bitcoin_cli_args = args.bitcoin_cli_args
if bitcoin_cli_args and bitcoin_cli_args[0] == "--":
    bitcoin_cli_args = bitcoin_cli_args[1:]
bitcoin_cli = os.environ.get("BITCOIN_CLI", "bitcoin-cli")
start_hash = require_live_hash(
    run_bitcoin_cli(bitcoin_cli, bitcoin_cli_args, "getblockhash", str(start_height)),
    "bitcoin-cli start hash",
)
stop_hash = require_live_hash(
    run_bitcoin_cli(bitcoin_cli, bitcoin_cli_args, "getblockhash", str(stop_height)),
    "bitcoin-cli stop hash",
)
require_mainnet_chain_info(
    run_bitcoin_cli(bitcoin_cli, bitcoin_cli_args, "getblockchaininfo"),
    stop_height,
)

artifact = {
    "schema": CRITERION_ARTIFACT_SCHEMA,
    "benchmark_run_id": benchmark_run_id,
    "benchmark_host_id": benchmark_host_id,
    "ibd_start_height": start_height,
    "ibd_start_hash": start_hash,
    "ibd_stop_height": stop_height,
    "ibd_stop_hash": stop_hash,
    "bitcoin_rs_command_sha256": sha256_text(bitcoin_rs_command),
    "bitcoin_core_command_sha256": sha256_text(bitcoin_core_command),
    "bitcoin_rs_config_sha256": sha256_text(bitcoin_rs_config),
    "bitcoin_core_config_sha256": sha256_text(bitcoin_core_config),
    "benchmarks": [
        {
            "benchmark_id": BITCOIN_RS_CRITERION_BENCHMARK_ID,
            "benchmark_run_id": benchmark_run_id,
            "elapsed_seconds": bitcoin_rs_elapsed_seconds,
            "raw_output_sha256": sha256_file(bitcoin_rs_raw_output),
        },
        {
            "benchmark_id": BITCOIN_CORE_CRITERION_BENCHMARK_ID,
            "benchmark_run_id": benchmark_run_id,
            "elapsed_seconds": bitcoin_core_elapsed_seconds,
            "raw_output_sha256": sha256_file(bitcoin_core_raw_output),
        },
    ],
}
output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(output)
PY
