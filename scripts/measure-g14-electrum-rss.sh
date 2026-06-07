#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: measure-g14-electrum-rss.sh --output <measurement.json> --host <host> --port <port> --pid <bitcoin-rs-pid> --tip-height <height> --tip-hash <64-hex> --scripthashes <path> [--sample-size <n>] [--seed <seed>] [--timeout-seconds <seconds>]' \
    '' \
    'Measures the G14 Electrum get_history p95 and bitcoin-rs RSS budget inputs against a running mainnet-tip bitcoin-rs Electrum endpoint.' \
    'The helper does not start bitcoin-rs and does not mutate node state.' \
    'The scripthash corpus must contain real 64-hex Electrum scripthashes, one per line.' \
    'It writes a JSON fragment with electrum_get_history_p95_ms and rss_bytes keys consumable by the G14 evidence manifest flow.' \
    '' \
    'Defaults: --sample-size 10000 --seed g14-electrum-rss-v1 --timeout-seconds 30'
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
import socket
import sys
import time

SCHEMA = "g14-electrum-rss-measurement-v1"
SMOKE_SCHEMA = "g14-electrum-rss-smoke-v1"
METHOD = "blockchain.scripthash.get_history"


def die(message: str) -> None:
    raise SystemExit(f"error: {message}")


def positive_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        die(f"{name} must be a positive integer: {error}")
    if number <= 0:
        die(f"{name} must be positive")
    return number


def non_negative_int(value: str, name: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        die(f"{name} must be a non-negative integer: {error}")
    if number < 0:
        die(f"{name} must be non-negative")
    return number


def positive_float(value: str, name: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        die(f"{name} must be a finite positive number: {error}")
    if not math.isfinite(number) or number <= 0.0:
        die(f"{name} must be finite and positive")
    return number


def require_hex(value: str, length: int, name: str) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        die(f"{name} must be {length} lowercase hex characters")
    return value


def rss_bytes(pid: int) -> int:
    status_path = Path(f"/proc/{pid}/status")
    try:
        lines = status_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        die(f"--pid does not expose {status_path}")
    except UnicodeDecodeError as error:
        die(f"{status_path} must be UTF-8: {error}")
    for line in lines:
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) < 2:
                die(f"{status_path} VmRSS line is malformed")
            return positive_int(parts[1], f"{status_path} VmRSS KiB") * 1024
    die(f"{status_path} does not contain VmRSS")


def process_basename(value: str) -> str:
    return Path(value).name


def process_identity(pid: int) -> dict[str, str | bool]:
    exe_path = Path(f"/proc/{pid}/exe")
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    exe_name = ""
    argv0_name = ""
    try:
        exe_name = process_basename(str(exe_path.readlink()))
    except OSError:
        pass
    try:
        cmdline = cmdline_path.read_bytes().split(b"\0")
    except OSError:
        cmdline = []
    if cmdline and cmdline[0]:
        try:
            argv0_name = process_basename(cmdline[0].decode("utf-8"))
        except UnicodeDecodeError:
            argv0_name = "<non-utf8>"
    return {
        "matches_bitcoin_rs": exe_name == "bitcoin-rs" or argv0_name == "bitcoin-rs",
        "exe_basename": exe_name,
        "argv0_basename": argv0_name,
    }


def percentile_ms(samples_ns: list[int], numerator: int, denominator: int) -> float:
    if not samples_ns:
        die("cannot calculate percentile for an empty sample")
    index = math.ceil(len(samples_ns) * numerator / denominator) - 1
    index = max(0, min(index, len(samples_ns) - 1))
    return samples_ns[index] / 1_000_000.0


def sampled_scripthash(seed: str, index: int) -> str:
    return hashlib.sha256(f"{seed}:{index}".encode("utf-8")).hexdigest()


def select_scripthash_sample(values: list[str], seed: str, sample_size: int) -> list[str]:
    keyed = sorted(
        values,
        key=lambda value: (
            hashlib.sha256(f"{seed}:{value}".encode("utf-8")).digest(),
            value,
        ),
    )
    return keyed[:sample_size]


def read_scripthash_corpus(path: str) -> list[str]:
    values = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        die(f"--scripthashes is not readable: {path}")
    except UnicodeDecodeError as error:
        die(f"--scripthashes must be UTF-8: {error}")
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        values.append(require_hex(stripped, 64, f"--scripthashes line {line_number}"))
    if not values:
        die("--scripthashes must contain at least one 64-hex scripthash")
    return values


def write_json(path: str, data: dict) -> None:
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if path == "-":
        sys.stdout.write(encoded)
        return
    Path(path).write_text(encoded, encoding="utf-8")


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--help", action="store_true")
parser.add_argument("--output")
parser.add_argument("--host")
parser.add_argument("--port")
parser.add_argument("--pid")
parser.add_argument("--tip-height")
parser.add_argument("--tip-hash")
parser.add_argument("--scripthashes")
parser.add_argument("--sample-size", default="10000")
parser.add_argument("--seed", default="g14-electrum-rss-v1")
parser.add_argument("--timeout-seconds", default="30")
parser.add_argument("--generate-empty-scripthashes-for-smoke-test", action="store_true")
args = parser.parse_args(sys.argv[1:])

if args.help:
    print("""usage: measure-g14-electrum-rss.sh --output <measurement.json> --host <host> --port <port> --pid <bitcoin-rs-pid> --tip-height <height> --tip-hash <64-hex> --scripthashes <path> [--sample-size <n>] [--seed <seed>] [--timeout-seconds <seconds>]""")
    raise SystemExit(0)

for key in ("output", "host", "port", "pid", "tip_height", "tip_hash"):
    if getattr(args, key) is None:
        die(f"--{key.replace('_', '-')} is required")

port = positive_int(args.port, "--port")
if port > 65535:
    die("--port must be <= 65535")
pid = positive_int(args.pid, "--pid")
tip_height = non_negative_int(args.tip_height, "--tip-height")
tip_hash = require_hex(args.tip_hash, 64, "--tip-hash")
sample_size = positive_int(args.sample_size, "--sample-size")
timeout_seconds = positive_float(args.timeout_seconds, "--timeout-seconds")
if not args.seed.strip():
    die("--seed must not be empty")
if args.generate_empty_scripthashes_for_smoke_test:
    if args.scripthashes is not None:
        die("--scripthashes cannot be combined with --generate-empty-scripthashes-for-smoke-test")
    scripthashes = [sampled_scripthash(args.seed, index) for index in range(sample_size)]
    corpus_source = "generated-empty-scripthashes-for-smoke-test"
elif args.scripthashes is not None:
    scripthashes = read_scripthash_corpus(args.scripthashes)
    if len(scripthashes) < sample_size:
        die("--scripthashes contains fewer entries than --sample-size")
    scripthashes = select_scripthash_sample(scripthashes, args.seed, sample_size)
    corpus_source = args.scripthashes
else:
    die("--scripthashes is required unless --generate-empty-scripthashes-for-smoke-test is set")
identity = process_identity(pid)
if not args.generate_empty_scripthashes_for_smoke_test and not identity["matches_bitcoin_rs"]:
    observed = f"exe={identity['exe_basename']!r}, argv0={identity['argv0_basename']!r}"
    die(f"--pid must refer to a bitcoin-rs process for production evidence ({observed})")

latencies_ns: list[int] = []
non_empty_history_count = 0
rss_high_water = rss_bytes(pid)
started_ns = time.monotonic_ns()

with socket.create_connection((args.host, port), timeout=timeout_seconds) as sock:
    sock.settimeout(timeout_seconds)
    reader = sock.makefile("rb")
    writer = sock.makefile("wb")
    for index in range(sample_size):
        request_id = index + 1
        request = {
            "id": request_id,
            "method": METHOD,
            "params": [scripthashes[index]],
        }
        encoded = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
        before_ns = time.perf_counter_ns()
        writer.write(encoded)
        writer.flush()
        line = reader.readline()
        elapsed_ns = time.perf_counter_ns() - before_ns
        if not line:
            die(f"Electrum server closed the connection after {index} samples")
        try:
            response = json.loads(line.decode("utf-8"))
        except UnicodeDecodeError as error:
            die(f"Electrum response {request_id} is not UTF-8: {error}")
        except json.JSONDecodeError as error:
            die(f"Electrum response {request_id} is not JSON: {error}")
        if response.get("id") != request_id:
            die(f"Electrum response id mismatch for sample {request_id}")
        if "error" in response and response["error"] is not None:
            die(f"Electrum response {request_id} returned error: {response['error']!r}")
        result = response.get("result")
        if not isinstance(result, list):
            die(f"Electrum response {request_id} result must be an array")
        if result:
            non_empty_history_count += 1
        elif not args.generate_empty_scripthashes_for_smoke_test:
            die(
                f"Electrum response {request_id} returned empty history for a caller-supplied "
                "scripthash corpus"
            )
        latencies_ns.append(elapsed_ns)
        rss_high_water = max(rss_high_water, rss_bytes(pid))

finished_ns = time.monotonic_ns()
latencies_ns.sort()
rss_final = rss_bytes(pid)
rss_high_water = max(rss_high_water, rss_final)
data = {
    "schema": SMOKE_SCHEMA if args.generate_empty_scripthashes_for_smoke_test else SCHEMA,
    "measurement_kind": "smoke" if args.generate_empty_scripthashes_for_smoke_test else "evidence",
    "method": METHOD,
    "electrum_host": args.host,
    "electrum_port": port,
    "electrum_tip_height": tip_height,
    "electrum_tip_hash": tip_hash,
    "electrum_sample_size": sample_size,
    "electrum_sample_seed": args.seed,
    "electrum_non_empty_history_count": non_empty_history_count,
    "electrum_scripthash_corpus": corpus_source,
    "electrum_scripthash_corpus_sha256": hashlib.sha256(
        ("\n".join(scripthashes[:sample_size]) + "\n").encode("utf-8")
    ).hexdigest(),
    "electrum_get_history_p50_ms": percentile_ms(latencies_ns, 50, 100),
    "electrum_get_history_p95_ms": percentile_ms(latencies_ns, 95, 100),
    "electrum_get_history_p99_ms": percentile_ms(latencies_ns, 99, 100),
    "electrum_get_history_min_ms": latencies_ns[0] / 1_000_000.0,
    "electrum_get_history_max_ms": latencies_ns[-1] / 1_000_000.0,
    "electrum_measurement_elapsed_seconds": (finished_ns - started_ns) / 1_000_000_000.0,
    "rss_bytes": rss_high_water,
    "rss_final_bytes": rss_final,
    "rss_pid": pid,
    "rss_pid_argv0_basename": identity["argv0_basename"],
    "rss_pid_exe_basename": identity["exe_basename"],
    "rss_source": f"/proc/{pid}/status VmRSS",
}
write_json(args.output, data)
PY
