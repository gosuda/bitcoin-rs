#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: run-g14-bitcoin-rs-daemon-mainnet-ibd.sh --ibd-start-height <height> --ibd-stop-height <height> --ibd-start-hash <hash> --ibd-stop-hash <hash> --datadir <path> --bitcoin-rs-config <path> --rpc-url <url> --rpc-user <user> --rpc-password <password> [--bitcoin-rs-command <command>] [--command-output <path>] [--poll-interval-seconds <seconds>] [--startup-timeout-seconds <seconds>] [--force] [-- <bitcoin-rs-arg>...]' \
    '' \
    'Runs a bitcoin-rs mainnet daemon, polls JSON-RPC until applied blocks reach the requested window, validates start/stop block hashes, then emits canonical Criterion-style bitcoin-rs/mainnet-ibd timing for G14 evidence capture.'
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

python3 - "$@" <<'PY'
import argparse
import base64
import ipaddress
import json
import math
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

BENCHMARK_ID = "bitcoin-rs/mainnet-ibd"
RESERVED_BITCOIN_RS_ARGS = (
    "--config",
    "--bitcoin-conf",
    "--data-dir",
    "--network",
    "--rpc-bind",
    "--rpc-user",
    "--rpc-password",
    "--rpc-cookie",
)
UNSUPPORTED_BITCOIN_RS_ARGS = ("--addnode",)


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
            prefix="bitcoin-rs-daemon-mainnet-ibd-",
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


def reject_reserved_bitcoin_rs_args(args: list[str]) -> None:
    for arg in args:
        key = arg.split("=", 1)[0]
        if key in RESERVED_BITCOIN_RS_ARGS:
            die(f"pass {key} through G14 bitcoin-rs adapter options, not bitcoin-rs args")


def reject_unsupported_bitcoin_rs_args(args: list[str]) -> None:
    for arg in args:
        key = arg.split("=", 1)[0]
        if key in UNSUPPORTED_BITCOIN_RS_ARGS:
            die(f"bitcoin-rs daemon CLI does not support {key}")


def parse_rpc_url(value: str) -> tuple[str, str]:
    parsed = urlparse(non_empty(value, "--rpc-url"))
    if parsed.scheme not in ("http", "https"):
        die("--rpc-url must be an http or https URL")
    if not parsed.hostname:
        die("--rpc-url must include a host")
    if parsed.path not in ("", "/"):
        die("--rpc-url must not include a path")
    if parsed.query or parsed.fragment:
        die("--rpc-url must not include query or fragment parameters")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    host = parsed.hostname
    if host == "localhost":
        bind_host = "127.0.0.1"
        url_host = "127.0.0.1"
    else:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            die("--rpc-url host must be an IP literal or localhost")
        if isinstance(ip, ipaddress.IPv6Address):
            bind_host = f"[{host}]"
            url_host = f"[{host}]"
        else:
            bind_host = host
            url_host = host
    rpc_bind = f"{bind_host}:{port}"
    rpc_url = f"{parsed.scheme}://{url_host}:{port}/"
    return rpc_url, rpc_bind


def rpc_payload(method: str, params: list) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode("utf-8")


def rpc_headers(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {
        "Content-Type": "application/json",
        "Authorization": f"Basic {token}",
    }


def parse_rpc_result(raw: str, method: str) -> object:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        die(f"JSON-RPC {method} must return JSON: {error}")
    if not isinstance(payload, dict):
        die(f"JSON-RPC {method} must return a JSON object")
    if payload.get("error") is not None:
        die(f"JSON-RPC {method} failed: {payload['error']}")
    if "result" not in payload:
        die(f"JSON-RPC {method} must include a result field")
    return payload["result"]


def rpc_call(url: str, user: str, password: str, method: str, params: list) -> object:
    request = urllib.request.Request(
        url,
        data=rpc_payload(method, params),
        headers=rpc_headers(user, password),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30.0) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace").strip()
        die(f"JSON-RPC {method} failed with HTTP {error.code}: {body}")
    except urllib.error.URLError as error:
        die(f"JSON-RPC {method} failed: {error.reason}")
    return parse_rpc_result(raw, method)


def try_rpc_call(
    url: str, user: str, password: str, method: str, params: list
) -> object | None:
    request = urllib.request.Request(
        url,
        data=rpc_payload(method, params),
        headers=rpc_headers(user, password),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30.0) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return None
    try:
        return parse_rpc_result(raw, method)
    except SystemExit:
        return None


def parse_chain_info(result: object) -> dict:
    if not isinstance(result, dict):
        die("JSON-RPC getblockchaininfo must return a JSON object")
    return result


def chain_blocks(data: dict) -> int:
    chain = data.get("chain")
    if chain != "main":
        die("measured bitcoin-rs node must be on mainnet")
    blocks = data.get("blocks")
    if not isinstance(blocks, int) or isinstance(blocks, bool):
        die("JSON-RPC getblockchaininfo blocks must be an integer")
    return blocks


def require_chain_start(data: dict, start_height: int) -> None:
    blocks = chain_blocks(data)
    if blocks > start_height:
        die(
            "measured bitcoin-rs node starts past requested IBD start height "
            f"{start_height}: blocks={blocks}"
        )


def require_chain_tip(data: dict, stop_height: int) -> bool:
    return chain_blocks(data) >= stop_height


def require_hash(
    url: str,
    user: str,
    password: str,
    height: int,
    expected_hash: str,
    name: str,
) -> None:
    result = rpc_call(url, user, password, "getblockhash", [height])
    if not isinstance(result, str):
        die(f"JSON-RPC getblockhash must return a string for measured bitcoin-rs {name} hash")
    actual_hash = result.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", actual_hash):
        die(f"measured bitcoin-rs {name} hash must be a 64-character lowercase block hash")
    if actual_hash != expected_hash:
        die(f"measured bitcoin-rs {name} hash must be {expected_hash!r}")


SHUTDOWN_GRACE_SECONDS = 30.0


def signal_process_group(pgid: int, signum: signal.Signals) -> None:
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass


def reap_direct_child(process: subprocess.Popen, timeout_seconds: float) -> None:
    if process.poll() is not None:
        return
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        signal_process_group(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def reap_lingering_process_group(pgid: int, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    signal_process_group(pgid, signal.SIGKILL)
    deadline = time.monotonic() + min(timeout_seconds, 10.0)
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)


def shutdown_daemon_process(process: subprocess.Popen, pgid: int) -> None:
    signal_process_group(pgid, signal.SIGTERM)
    reap_direct_child(process, SHUTDOWN_GRACE_SECONDS)
    reap_lingering_process_group(pgid, SHUTDOWN_GRACE_SECONDS)


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-h", "--help", action="store_true")
parser.add_argument("--ibd-start-height")
parser.add_argument("--ibd-stop-height")
parser.add_argument("--ibd-start-hash")
parser.add_argument("--ibd-stop-hash")
parser.add_argument("--datadir")
parser.add_argument("--bitcoin-rs-config")
parser.add_argument("--bitcoin-rs-command", default="bitcoin-rs")
parser.add_argument("--rpc-url")
parser.add_argument("--rpc-user")
parser.add_argument("--rpc-password")
parser.add_argument("--command-output")
parser.add_argument("--poll-interval-seconds", default="1.0")
parser.add_argument("--startup-timeout-seconds", default="900.0")
parser.add_argument("--force", action="store_true")
parser.add_argument("bitcoin_rs_args", nargs=argparse.REMAINDER)
args = parser.parse_args()

if args.help:
    print(
        "usage: run-g14-bitcoin-rs-daemon-mainnet-ibd.sh --ibd-start-height <height> "
        "--ibd-stop-height <height> --ibd-start-hash <hash> --ibd-stop-hash <hash> "
        "--datadir <path> --bitcoin-rs-config <path> --rpc-url <url> --rpc-user <user> "
        "--rpc-password <password> [--bitcoin-rs-command <command>] "
        "[--command-output <path>] [--poll-interval-seconds <seconds>] "
        "[--startup-timeout-seconds <seconds>] [--force] "
        "[-- <bitcoin-rs-arg>...]"
    )
    raise SystemExit(0)

start_height = height(args.ibd_start_height, "--ibd-start-height")
stop_height = height(args.ibd_stop_height, "--ibd-stop-height")
if stop_height < start_height:
    die("--ibd-stop-height must be greater than or equal to --ibd-start-height")
start_hash = block_hash(args.ibd_start_hash, "--ibd-start-hash")
stop_hash = block_hash(args.ibd_stop_hash, "--ibd-stop-hash")
datadir = Path(non_empty(args.datadir, "--datadir"))
config = file_path(args.bitcoin_rs_config, "--bitcoin-rs-config")
bitcoin_rs_command = non_empty(args.bitcoin_rs_command, "--bitcoin-rs-command")
rpc_url, rpc_bind = parse_rpc_url(args.rpc_url)
rpc_user = non_empty(args.rpc_user, "--rpc-user")
rpc_password = non_empty(args.rpc_password, "--rpc-password")
poll_interval = positive_float(args.poll_interval_seconds, "--poll-interval-seconds")
startup_timeout = positive_float(args.startup_timeout_seconds, "--startup-timeout-seconds")

bitcoin_rs_args = args.bitcoin_rs_args
if bitcoin_rs_args and bitcoin_rs_args[0] == "--":
    bitcoin_rs_args = bitcoin_rs_args[1:]
reject_reserved_bitcoin_rs_args(bitcoin_rs_args)
reject_unsupported_bitcoin_rs_args(bitcoin_rs_args)

command_output, remove_command_output = output_path(args.command_output, args.force)
if command_output.exists():
    command_output.unlink()

command = (
    shlex.split(bitcoin_rs_command)
    + [
        f"--config={config}",
        f"--data-dir={datadir}",
        "--network=mainnet",
        f"--rpc-bind={rpc_bind}",
        f"--rpc-user={rpc_user}",
        f"--rpc-password={rpc_password}",
        *bitcoin_rs_args,
    ]
)

process: subprocess.Popen | None = None
pgid: int | None = None
started = time.monotonic()
try:
    with command_output.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            command,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    pgid = process.pid
    deadline = started + startup_timeout
    observed_start = False
    while True:
        if process.poll() is not None:
            die(
                "bitcoin-rs exited before reaching stop height with status "
                f"{process.returncode}"
            )
        info_result = try_rpc_call(rpc_url, rpc_user, rpc_password, "getblockchaininfo", [])
        if info_result is None:
            if time.monotonic() >= deadline:
                die("timed out waiting for measured bitcoin-rs RPC startup")
            time.sleep(poll_interval)
            continue
        info = parse_chain_info(info_result)
        if not observed_start:
            require_chain_start(info, start_height)
            observed_start = True
        if require_chain_tip(info, stop_height):
            break
        if time.monotonic() >= deadline:
            die("timed out waiting for measured bitcoin-rs node to reach stop height")
        time.sleep(poll_interval)

    require_hash(rpc_url, rpc_user, rpc_password, start_height, start_hash, "start")
    require_hash(rpc_url, rpc_user, rpc_password, stop_height, stop_hash, "stop")
    elapsed = time.monotonic() - started
finally:
    if process is not None and pgid is not None:
        shutdown_daemon_process(process, pgid)
    if remove_command_output:
        command_output.unlink(missing_ok=True)

print(f"Benchmarking {BENCHMARK_ID}")
print(f"Benchmarking {BENCHMARK_ID}: Collecting 1 sample from bitcoin-rs")
print(f"Benchmarking {BENCHMARK_ID}: Analyzing")
print(f"{BENCHMARK_ID}   time:   [{elapsed:.12g} s {elapsed:.12g} s {elapsed:.12g} s]")
PY
