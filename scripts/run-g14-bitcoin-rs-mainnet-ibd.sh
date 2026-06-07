#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: run-g14-bitcoin-rs-mainnet-ibd.sh --ibd-start-height <height> --ibd-stop-height <height> --ibd-start-hash <hash> --ibd-stop-hash <hash> [--replay-command <command>] [--replay-output <path>] [--force] -- <mainnet-prefix-replay-arg>...' \
    '' \
    'Runs the repo-native mainnet_prefix_replay command and emits a canonical Criterion-style bitcoin-rs/mainnet-ibd timing section for G14 evidence capture.' \
    'The default replay command is: cargo run -p bitcoin-rs-node --example mainnet_prefix_replay --no-default-features --features fjall --'
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

BENCHMARK_ID = "bitcoin-rs/mainnet-ibd"
REPLAY_SCHEMA = "mainnet-prefix-replay-v1"
DEFAULT_REPLAY_COMMAND = (
    "cargo run -p bitcoin-rs-node --example mainnet_prefix_replay "
    "--no-default-features --features fjall --"
)


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def height(value: str | None, name: str) -> int:
    if value is None or not value.strip():
        die(f"{name} must not be empty")
    try:
        number = int(value)
    except ValueError as error:
        die(f"{name} must be a non-negative integer: {error}")
    if number < 0:
        die(f"{name} must be non-negative")
    return number


def block_hash(value: str | None, name: str) -> str:
    if value is None or not value.strip():
        die(f"{name} must not be empty")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        die(f"{name} must be a 64-character lowercase block hash")
    return value


def output_path(value: str | None, force: bool) -> tuple[Path, bool]:
    if value is None:
        handle = tempfile.NamedTemporaryFile(
            prefix="bitcoin-rs-mainnet-ibd-",
            suffix=".json",
            delete=False,
        )
        handle.close()
        return Path(handle.name), True
    path = Path(value)
    if path.exists() and path.is_dir():
        die(f"--replay-output must be a file path, got directory: {path}")
    if path.exists() and not force:
        die(f"--replay-output already exists; pass --force to replace it: {path}")
    if path.parent and not path.parent.exists():
        die(f"--replay-output parent does not exist: {path.parent}")
    return path, False


def require_replay_int(data: dict, key: str, expected: int) -> None:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"replay artifact {key} must be an integer")
    if value != expected:
        die(f"replay artifact {key} must be {expected}")


def require_replay_text(data: dict, key: str, expected: str) -> None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        die(f"replay artifact {key} must be a non-empty string")
    if value != expected:
        die(f"replay artifact {key} must be {expected!r}")


def read_replay_elapsed(
    path: Path,
    start_height: int,
    stop_height: int,
    start_hash: str,
    stop_hash: str,
) -> float:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        die(f"replay artifact must be UTF-8: {error}")
    except json.JSONDecodeError as error:
        die(f"replay artifact must be JSON: {error}")
    if data.get("schema") != REPLAY_SCHEMA:
        die(f"replay artifact schema must be {REPLAY_SCHEMA!r}")
    require_replay_int(data, "start_height", start_height)
    require_replay_int(data, "stop_height", stop_height)
    require_replay_int(data, "block_count", stop_height - start_height + 1)
    require_replay_text(data, "start_hash", start_hash)
    require_replay_text(data, "stop_hash", stop_hash)
    elapsed = data.get("elapsed_seconds")
    if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool):
        die("replay artifact elapsed_seconds must be a number")
    elapsed = float(elapsed)
    if not math.isfinite(elapsed) or elapsed <= 0.0:
        die("replay artifact elapsed_seconds must be finite and positive")
    return elapsed


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-h", "--help", action="store_true")
parser.add_argument("--ibd-start-height")
parser.add_argument("--ibd-stop-height")
parser.add_argument("--ibd-start-hash")
parser.add_argument("--ibd-stop-hash")
parser.add_argument("--replay-command", default=DEFAULT_REPLAY_COMMAND)
parser.add_argument("--replay-output")
parser.add_argument("--force", action="store_true")
parser.add_argument("replay_args", nargs=argparse.REMAINDER)
args = parser.parse_args()

if args.help:
    print(
        "usage: run-g14-bitcoin-rs-mainnet-ibd.sh --ibd-start-height <height> "
        "--ibd-stop-height <height> --ibd-start-hash <hash> --ibd-stop-hash <hash> "
        "[--replay-command <command>] "
        "[--replay-output <path>] [--force] -- <mainnet-prefix-replay-arg>..."
    )
    raise SystemExit(0)

start_height = height(args.ibd_start_height, "--ibd-start-height")
stop_height = height(args.ibd_stop_height, "--ibd-stop-height")
if stop_height < start_height:
    die("--ibd-stop-height must be greater than or equal to --ibd-start-height")
start_hash = block_hash(args.ibd_start_hash, "--ibd-start-hash")
stop_hash = block_hash(args.ibd_stop_hash, "--ibd-stop-hash")

replay_args = args.replay_args
if replay_args and replay_args[0] == "--":
    replay_args = replay_args[1:]
for reserved in ("--output", "--start-height", "--stop-height"):
    if reserved in replay_args:
        die(f"pass replay {reserved} through G14 IBD adapter options, not replay args")

replay_output, remove_replay_output = output_path(args.replay_output, args.force)
command = (
    shlex.split(args.replay_command)
    + replay_args
    + [
        "--start-height",
        str(start_height),
        "--stop-height",
        str(stop_height),
        "--output",
        str(replay_output),
    ]
)

try:
    subprocess.run(command, check=True)
    elapsed = read_replay_elapsed(
        replay_output,
        start_height,
        stop_height,
        start_hash,
        stop_hash,
    )
finally:
    if remove_replay_output:
        replay_output.unlink(missing_ok=True)

print(f"Benchmarking {BENCHMARK_ID}")
print(f"Benchmarking {BENCHMARK_ID}: Collecting 1 sample from mainnet_prefix_replay")
print(f"Benchmarking {BENCHMARK_ID}: Analyzing")
print(f"{BENCHMARK_ID}   time:   [{elapsed:.12g} s {elapsed:.12g} s {elapsed:.12g} s]")
PY
