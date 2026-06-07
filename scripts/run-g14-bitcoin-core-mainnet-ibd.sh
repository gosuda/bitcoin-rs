#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: run-g14-bitcoin-core-mainnet-ibd.sh --ibd-start-height <height> --ibd-stop-height <height> --ibd-start-hash <hash> --ibd-stop-hash <hash> --datadir <path> --bitcoin-core-config <path> [--bitcoind-command <command>] [--bitcoin-cli-command <command>] [--command-output <path>] [--poll-interval-seconds <seconds>] [--startup-timeout-seconds <seconds>] [--force] [-- <bitcoind-arg>...]' \
    '' \
    'Runs a Bitcoin Core mainnet IBD command, validates the measured Core node reaches the requested window, then emits canonical Criterion-style bitcoin-core/mainnet-ibd timing for G14 evidence capture.'
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

python3 - "$@" <<'PY'
import argparse
import json
import math
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time

BENCHMARK_ID = "bitcoin-core/mainnet-ibd"
RESERVED_BITCOIND_ARGS = (
    "-conf",
    "-datadir",
    "-chain",
    "-daemon",
    "-regtest",
    "-signet",
    "-testnet",
    "-testnet4",
)


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def non_empty(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        die(f"{name} must not be empty")
    return value


def height(value: str | None, name: str) -> int:
    raw = non_empty(value, name)
    try:
        number = int(raw)
    except ValueError as error:
        die(f"{name} must be a non-negative integer: {error}")
    if number < 0:
        die(f"{name} must be non-negative")
    return number


def positive_float(value: str | None, name: str) -> float:
    raw = non_empty(value, name)
    try:
        number = float(raw)
    except ValueError as error:
        die(f"{name} must be a finite positive number: {error}")
    if not math.isfinite(number) or number <= 0.0:
        die(f"{name} must be finite and positive")
    return number


def block_hash(value: str | None, name: str) -> str:
    raw = non_empty(value, name)
    if not re.fullmatch(r"[0-9a-f]{64}", raw):
        die(f"{name} must be a 64-character lowercase block hash")
    return raw


def file_path(value: str | None, name: str) -> Path:
    path = Path(non_empty(value, name))
    if not path.is_file():
        die(f"{name} is not a readable file: {path}")
    return path


def output_path(value: str | None, force: bool) -> tuple[Path, bool]:
    if value is None:
        handle = tempfile.NamedTemporaryFile(
            prefix="bitcoin-core-mainnet-ibd-",
            suffix=".log",
            delete=False,
        )
        handle.close()
        return Path(handle.name), True
    path = Path(value)
    if path.exists() and path.is_dir():
        die(f"--command-output must be a file path, got directory: {path}")
    if path.exists() and not force:
        die(f"--command-output already exists; pass --force to replace it: {path}")
    if path.parent and not path.parent.exists():
        die(f"--command-output parent does not exist: {path.parent}")
    return path, False


def reject_reserved_bitcoind_args(args: list[str]) -> None:
    for arg in args:
        key = arg.split("=", 1)[0]
        if key in RESERVED_BITCOIND_ARGS:
            die(f"pass {key} through G14 Core adapter options, not bitcoind args")


def cli_command(command: str, datadir: Path, config: Path, args: list[str]) -> list[str]:
    return shlex.split(command) + [f"-datadir={datadir}", f"-conf={config}", "-chain=main", *args]


def run_cli(command: str, datadir: Path, config: Path, args: list[str]) -> str:
    result = subprocess.run(
        cli_command(command, datadir, config, args),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        die(
            f"bitcoin-cli {' '.join(args)} failed with status "
            f"{result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def try_run_cli(command: str, datadir: Path, config: Path, args: list[str]) -> str | None:
    result = subprocess.run(
        cli_command(command, datadir, config, args),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def read_chain_info(command: str, datadir: Path, config: Path) -> dict:
    raw = run_cli(command, datadir, config, ["getblockchaininfo"])
    return parse_chain_info(raw)


def try_read_chain_info(command: str, datadir: Path, config: Path) -> dict | None:
    raw = try_run_cli(command, datadir, config, ["getblockchaininfo"])
    if raw is None:
        return None
    return parse_chain_info(raw)


def parse_chain_info(raw: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        die(f"bitcoin-cli getblockchaininfo must return JSON: {error}")
    if not isinstance(data, dict):
        die("bitcoin-cli getblockchaininfo must return a JSON object")
    return data


def chain_blocks_headers(data: dict) -> tuple[int, int]:
    chain = data.get("chain")
    if chain != "main":
        die("measured Bitcoin Core node must be on mainnet")
    blocks = data.get("blocks")
    headers = data.get("headers")
    if not isinstance(blocks, int) or isinstance(blocks, bool):
        die("bitcoin-cli getblockchaininfo blocks must be an integer")
    if not isinstance(headers, int) or isinstance(headers, bool):
        die("bitcoin-cli getblockchaininfo headers must be an integer")
    return blocks, headers


def require_chain_start(data: dict, start_height: int) -> None:
    blocks, _headers = chain_blocks_headers(data)
    if blocks > start_height:
        die(
            "measured Bitcoin Core node starts past requested IBD start height "
            f"{start_height}: blocks={blocks}"
        )


def require_chain_tip(data: dict, stop_height: int) -> bool:
    blocks, headers = chain_blocks_headers(data)
    return blocks >= stop_height and headers >= stop_height


def require_hash(
    command: str,
    datadir: Path,
    config: Path,
    height: int,
    expected_hash: str,
    name: str,
) -> None:
    actual_hash = run_cli(command, datadir, config, ["getblockhash", str(height)])
    if not re.fullmatch(r"[0-9a-f]{64}", actual_hash):
        die(f"measured Bitcoin Core {name} hash must be a 64-character lowercase block hash")
    if actual_hash != expected_hash:
        die(f"measured Bitcoin Core {name} hash must be {expected_hash!r}")


def wait_for_stop(process: subprocess.Popen, timeout_seconds: float) -> None:
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        die("bitcoind did not exit after bitcoin-cli stop")
    if process.returncode not in (0, None):
        die(f"bitcoind exited with status {process.returncode}")


def cleanup_after_failure(
    process: subprocess.Popen,
    bitcoin_cli_command: str,
    datadir: Path,
    config: Path,
) -> None:
    if process.poll() is not None:
        return
    try:
        run_cli(bitcoin_cli_command, datadir, config, ["stop"])
    except SystemExit:
        process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-h", "--help", action="store_true")
parser.add_argument("--ibd-start-height")
parser.add_argument("--ibd-stop-height")
parser.add_argument("--ibd-start-hash")
parser.add_argument("--ibd-stop-hash")
parser.add_argument("--datadir")
parser.add_argument("--bitcoin-core-config")
parser.add_argument("--bitcoind-command", default="bitcoind")
parser.add_argument("--bitcoin-cli-command", default="bitcoin-cli")
parser.add_argument("--command-output")
parser.add_argument("--poll-interval-seconds", default="1.0")
parser.add_argument("--startup-timeout-seconds", default="900.0")
parser.add_argument("--force", action="store_true")
parser.add_argument("bitcoind_args", nargs=argparse.REMAINDER)
args = parser.parse_args()

if args.help:
    usage = (
        "usage: run-g14-bitcoin-core-mainnet-ibd.sh --ibd-start-height <height> "
        "--ibd-stop-height <height> --ibd-start-hash <hash> --ibd-stop-hash <hash> "
        "--datadir <path> --bitcoin-core-config <path> "
        "[--bitcoind-command <command>] [--bitcoin-cli-command <command>] "
        "[--command-output <path>] [--poll-interval-seconds <seconds>] "
        "[--startup-timeout-seconds <seconds>] [--force] [-- <bitcoind-arg>...]"
    )
    print(usage)
    raise SystemExit(0)

start_height = height(args.ibd_start_height, "--ibd-start-height")
stop_height = height(args.ibd_stop_height, "--ibd-stop-height")
if stop_height < start_height:
    die("--ibd-stop-height must be greater than or equal to --ibd-start-height")
start_hash = block_hash(args.ibd_start_hash, "--ibd-start-hash")
stop_hash = block_hash(args.ibd_stop_hash, "--ibd-stop-hash")
datadir = Path(non_empty(args.datadir, "--datadir"))
config = file_path(args.bitcoin_core_config, "--bitcoin-core-config")
bitcoind_command = non_empty(args.bitcoind_command, "--bitcoind-command")
bitcoin_cli_command = non_empty(args.bitcoin_cli_command, "--bitcoin-cli-command")
poll_interval = positive_float(args.poll_interval_seconds, "--poll-interval-seconds")
startup_timeout = positive_float(args.startup_timeout_seconds, "--startup-timeout-seconds")
bitcoind_args = args.bitcoind_args
if bitcoind_args and bitcoind_args[0] == "--":
    bitcoind_args = bitcoind_args[1:]
reject_reserved_bitcoind_args(bitcoind_args)

command_output, remove_command_output = output_path(args.command_output, args.force)
if command_output.exists():
    command_output.unlink()

command = (
    shlex.split(bitcoind_command)
    + [
        f"-datadir={datadir}",
        f"-conf={config}",
        "-chain=main",
        "-daemon=0",
        *bitcoind_args,
    ]
)
started = time.monotonic()
with command_output.open("w", encoding="utf-8") as output:
    process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)

stopped = False
try:
    deadline = started + startup_timeout
    observed_start = False
    while True:
        if process.poll() is not None:
            die(f"bitcoind exited before reaching stop height with status {process.returncode}")
        info = try_read_chain_info(bitcoin_cli_command, datadir, config)
        if info is None:
            if time.monotonic() >= deadline:
                die("timed out waiting for measured Bitcoin Core RPC startup")
            time.sleep(poll_interval)
            continue
        if not observed_start:
            require_chain_start(info, start_height)
            observed_start = True
        if require_chain_tip(info, stop_height):
            break
        if time.monotonic() >= deadline:
            die("timed out waiting for measured Bitcoin Core node to reach stop height")
        time.sleep(poll_interval)

    require_hash(bitcoin_cli_command, datadir, config, start_height, start_hash, "start")
    require_hash(bitcoin_cli_command, datadir, config, stop_height, stop_hash, "stop")
    elapsed = time.monotonic() - started
    run_cli(bitcoin_cli_command, datadir, config, ["stop"])
    stopped = True
    wait_for_stop(process, startup_timeout)
finally:
    if not stopped and process.poll() is None:
        cleanup_after_failure(process, bitcoin_cli_command, datadir, config)
    if remove_command_output:
        command_output.unlink(missing_ok=True)

print(f"Benchmarking {BENCHMARK_ID}")
print(f"Benchmarking {BENCHMARK_ID}: Collecting 1 sample from bitcoind")
print(f"Benchmarking {BENCHMARK_ID}: Analyzing")
print(f"{BENCHMARK_ID}   time:   [{elapsed:.12g} s {elapsed:.12g} s {elapsed:.12g} s]")
PY
