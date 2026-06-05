#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: produce-g14-ibd-manifest.sh --output <evidence.json> --ibd-start-height <height> --ibd-stop-height <height> --bitcoin-rs-command <command> --bitcoin-core-command <command> [--criterion-bitcoin-rs-benchmark-id <id> --criterion-bitcoin-core-benchmark-id <id> [--criterion-bitcoin-rs-elapsed-seconds <seconds> --criterion-bitcoin-core-elapsed-seconds <seconds>]] --bitcoin-rs-config <path> --bitcoin-core-config <path> --bitcoin-core-version <version> --bitcoin-core-commit <40-hex> --benchmark-artifact <path> --utxo-commit-p95-ms <ms> (--electrum-rss-measurement <json> | --electrum-get-history-p95-ms <ms> --rss-bytes <bytes>)' \
    '' \
    'Runs one bitcoin-rs IBD command and one Bitcoin Core IBD command for the same mainnet height window unless both Criterion benchmark IDs are provided.' \
    'If both Criterion benchmark IDs are supplied, elapsed seconds are read from a fail-closed g14-criterion-artifact-v1 JSON artifact with matching IBD window metadata, one shared benchmark_run_id, one shared benchmark_host_id, plus bitcoin-rs/Core command/config SHA-256 bindings.' \
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

CRITERION_ARTIFACT_SCHEMA = "g14-criterion-artifact-v1"
ELECTRUM_RSS_MEASUREMENT_SCHEMA = "g14-electrum-rss-measurement-v1"
ELECTRUM_HISTORY_METHOD = "blockchain.scripthash.get_history"
ELECTRUM_SAMPLE_SIZE = 10_000
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


def non_empty_text(value: str, name: str) -> str:
    if not value.strip():
        die(f"{name} must not be empty")
    return value


def required_literal(value: str, expected: str, name: str) -> str:
    value = non_empty_text(value, name)
    if value != expected:
        die(f"{name} must be {expected!r}")
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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def current_head() -> str:
    output = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], text=True)
    head = output.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        die("git HEAD must be 40 lowercase hex characters")
    return head


def read_text(path: Path, name: str) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        die(f"{name} must be UTF-8: {error}")
    return non_empty_text(value, name)


def read_json_file(path: Path, name: str):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except UnicodeDecodeError as error:
        die(f"{name} must be UTF-8 JSON: {error}")
    except json.JSONDecodeError as error:
        die(f"{name} must be JSON: {error}")


def require_int_field(data: dict, key: str, expected: int, source: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"{source} {key} must be an integer")
    if value != expected:
        die(f"{source} {key} must match manifest {key}={expected}")
    return value


def require_hex_field(data: dict, key: str, length: int, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        die(f"{source} {key} must be {length} lowercase hex characters")
    return value


def require_matching_hash_field(data: dict, key: str, expected: str, source: str) -> None:
    value = require_hex_field(data, key, 64, source)
    if value != expected:
        die(f"{source} {key} must match the provided command/config")


def require_literal_field(data: dict, key: str, expected: str, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        die(f"{source} {key} must be a string")
    if value != expected:
        die(f"{source} {key} must be {expected!r}")
    return value


def require_int_value(data: dict, key: str, source: str, *, positive: bool = False) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"{source} {key} must be an integer")
    if positive and value <= 0:
        die(f"{source} {key} must be positive")
    if not positive and value < 0:
        die(f"{source} {key} must be non-negative")
    return value


def require_number_value(data: dict, key: str, source: str) -> float:
    value = data.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        die(f"{source} {key} must be a number")
    value = float(value)
    if not math.isfinite(value) or value <= 0.0:
        die(f"{source} {key} must be finite and positive")
    return value


def require_benchmark_run_id(data: dict, key: str, expected: str | None, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        die(f"{source} {key} must be a non-empty string")
    if expected is not None and value != expected:
        die(f"{source} {key} must match the artifact benchmark_run_id")
    return value


def require_text_field(data: dict, key: str, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        die(f"{source} {key} must be a non-empty string")
    return value


def require_raw_output_sha256(data: dict, source: str) -> str:
    value = data.get("raw_output_sha256")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        die(f"{source} raw_output_sha256 must be 64 lowercase hex characters")
    return value


def require_raw_output_path(data: dict, source: str) -> Path:
    value = data.get("raw_output_path")
    if not isinstance(value, str) or not value.strip():
        die(f"{source} raw_output_path must be a non-empty string")
    path = Path(value)
    if not path.is_file():
        die(f"{source} raw_output_path is not a readable file: {path}")
    return path


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


def criterion_elapsed_seconds(raw_output: str, benchmark_id: str, source: str) -> float:
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
    die(f"{source} must contain Criterion time output for benchmark {benchmark_id!r}")


def read_raw_output(path: Path, source: str) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        die(f"{source} raw_output_path must be UTF-8: {error}")
    return non_empty_text(value, f"{source} raw_output_path")


def require_raw_output_binding(
    entry: dict,
    benchmark_id: str,
    elapsed_seconds: float,
    source: str,
) -> tuple[str, str]:
    raw_output_path = require_raw_output_path(entry, source)
    raw_output_sha256 = require_raw_output_sha256(entry, source)
    if sha256_file(raw_output_path) != raw_output_sha256:
        die(f"{source} raw_output_sha256 must match raw_output_path")
    parsed_seconds = criterion_elapsed_seconds(
        read_raw_output(raw_output_path, source),
        benchmark_id,
        source,
    )
    if not math.isclose(elapsed_seconds, parsed_seconds, rel_tol=0.0, abs_tol=1e-12):
        die(f"{source} elapsed_seconds must match raw_output_path Criterion output")
    return str(raw_output_path.resolve()), raw_output_sha256


def criterion_artifact_elapsed_seconds(
    path: Path,
    rs_id: str,
    core_id: str,
    start_height: int,
    stop_height: int,
    command_config_hashes: dict[str, str],
) -> tuple[str, str, float, float, dict[str, str], dict[str, str]]:
    data = read_json_file(path, "--benchmark-artifact")
    if not isinstance(data, dict):
        die("--benchmark-artifact Criterion evidence must be a JSON object")
    if data.get("schema") != CRITERION_ARTIFACT_SCHEMA:
        die(f"--benchmark-artifact schema must be {CRITERION_ARTIFACT_SCHEMA!r}")
    require_int_field(data, "ibd_start_height", start_height, "--benchmark-artifact")
    require_int_field(data, "ibd_stop_height", stop_height, "--benchmark-artifact")
    require_hex_field(data, "ibd_start_hash", 64, "--benchmark-artifact")
    require_hex_field(data, "ibd_stop_hash", 64, "--benchmark-artifact")
    benchmark_run_id = require_benchmark_run_id(
        data,
        "benchmark_run_id",
        None,
        "--benchmark-artifact",
    )
    benchmark_host_id = require_text_field(data, "benchmark_host_id", "--benchmark-artifact")
    for key, expected in command_config_hashes.items():
        require_matching_hash_field(data, key, expected, "--benchmark-artifact")
    benchmarks = data.get("benchmarks")
    if not isinstance(benchmarks, list):
        die("--benchmark-artifact benchmarks must be an array")
    elapsed_by_id = {}
    raw_output_path_by_id = {}
    raw_output_sha256_by_id = {}
    for index, entry in enumerate(benchmarks):
        if not isinstance(entry, dict):
            die(f"--benchmark-artifact benchmarks[{index}] must be an object")
        benchmark_id = entry.get("benchmark_id")
        if not isinstance(benchmark_id, str) or not benchmark_id.strip():
            die(f"--benchmark-artifact benchmarks[{index}].benchmark_id must be a non-empty string")
        require_benchmark_run_id(
            entry,
            "benchmark_run_id",
            benchmark_run_id,
            f"--benchmark-artifact benchmarks[{index}]",
        )
        if benchmark_id in elapsed_by_id:
            die(f"--benchmark-artifact contains duplicate benchmark_id {benchmark_id!r}")
        if "elapsed_seconds" not in entry:
            die(f"--benchmark-artifact benchmark {benchmark_id!r} is missing elapsed_seconds")
        elapsed = positive_float(
            str(entry["elapsed_seconds"]),
            f"--benchmark-artifact benchmark {benchmark_id!r} elapsed_seconds",
        )
        raw_path, raw_sha256 = require_raw_output_binding(
            entry,
            benchmark_id,
            elapsed,
            f"--benchmark-artifact benchmarks[{index}]",
        )
        elapsed_by_id[benchmark_id] = elapsed
        raw_output_path_by_id[benchmark_id] = raw_path
        raw_output_sha256_by_id[benchmark_id] = raw_sha256
    missing = [benchmark_id for benchmark_id in (rs_id, core_id) if benchmark_id not in elapsed_by_id]
    if missing:
        die("--benchmark-artifact is missing benchmark_id " + ", ".join(repr(value) for value in missing))
    return (
        benchmark_run_id,
        benchmark_host_id,
        elapsed_by_id[rs_id],
        elapsed_by_id[core_id],
        raw_output_path_by_id,
        raw_output_sha256_by_id,
    )


def require_optional_elapsed_matches_artifact(
    supplied: str | None,
    artifact_elapsed: float,
    name: str,
) -> float:
    if supplied is None:
        return artifact_elapsed
    supplied_elapsed = positive_float(supplied, name)
    if not math.isclose(supplied_elapsed, artifact_elapsed, rel_tol=0.0, abs_tol=1e-12):
        die(f"{name} must match the hashed Criterion artifact elapsed_seconds")
    return supplied_elapsed


def read_electrum_rss_measurement(path: Path, stop_height: int) -> dict:
    data = read_json_file(path, "--electrum-rss-measurement")
    if not isinstance(data, dict):
        die("--electrum-rss-measurement must be a JSON object")
    require_literal_field(data, "schema", ELECTRUM_RSS_MEASUREMENT_SCHEMA, "--electrum-rss-measurement")
    require_literal_field(data, "measurement_kind", "evidence", "--electrum-rss-measurement")
    require_literal_field(data, "method", ELECTRUM_HISTORY_METHOD, "--electrum-rss-measurement")
    sample_size = require_int_value(data, "electrum_sample_size", "--electrum-rss-measurement", positive=True)
    if sample_size != ELECTRUM_SAMPLE_SIZE:
        die(f"--electrum-rss-measurement electrum_sample_size must be {ELECTRUM_SAMPLE_SIZE}")
    non_empty = require_int_value(
        data,
        "electrum_non_empty_history_count",
        "--electrum-rss-measurement",
        positive=True,
    )
    if non_empty != sample_size:
        die("--electrum-rss-measurement electrum_non_empty_history_count must equal electrum_sample_size")
    tip_height = require_int_value(data, "electrum_tip_height", "--electrum-rss-measurement")
    if tip_height != stop_height:
        die("--electrum-rss-measurement electrum_tip_height must match --ibd-stop-height")
    tip_hash = require_hex_field(data, "electrum_tip_hash", 64, "--electrum-rss-measurement")
    corpus_hash = require_hex_field(
        data,
        "electrum_scripthash_corpus_sha256",
        64,
        "--electrum-rss-measurement",
    )
    corpus = data.get("electrum_scripthash_corpus")
    if not isinstance(corpus, str) or not corpus.strip():
        die("--electrum-rss-measurement electrum_scripthash_corpus must be a non-empty string")
    if corpus == "generated-empty-scripthashes-for-smoke-test":
        die("--electrum-rss-measurement must not be a smoke corpus")
    return {
        "electrum_get_history_p95_ms": require_number_value(
            data,
            "electrum_get_history_p95_ms",
            "--electrum-rss-measurement",
        ),
        "rss_bytes": require_int_value(data, "rss_bytes", "--electrum-rss-measurement", positive=True),
        "electrum_rss_measurement_schema": ELECTRUM_RSS_MEASUREMENT_SCHEMA,
        "electrum_rss_measurement_tip_height": tip_height,
        "electrum_rss_measurement_tip_hash": tip_hash,
        "electrum_rss_measurement_sample_size": sample_size,
        "electrum_rss_measurement_non_empty_history_count": non_empty,
        "electrum_scripthash_corpus": corpus,
        "electrum_scripthash_corpus_sha256": corpus_hash,
    }


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
parser.add_argument("--electrum-rss-measurement")
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
        "[--criterion-bitcoin-rs-benchmark-id <id> "
        "--criterion-bitcoin-core-benchmark-id <id> "
        "[--criterion-bitcoin-rs-elapsed-seconds <seconds> "
        "--criterion-bitcoin-core-elapsed-seconds <seconds>]] "
        "--bitcoin-rs-config <path> --bitcoin-core-config <path> "
        "--bitcoin-core-version <version> --bitcoin-core-commit <40-hex> "
        "--benchmark-artifact <path> --utxo-commit-p95-ms <ms> "
        "(--electrum-rss-measurement <json> | "
        "--electrum-get-history-p95-ms <ms> --rss-bytes <bytes>)"
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
command_config_hashes = {
    "bitcoin_rs_command_sha256": sha256_text(bitcoin_rs_command),
    "bitcoin_core_command_sha256": sha256_text(bitcoin_core_command),
    "bitcoin_rs_config_sha256": sha256_text(bitcoin_rs_config),
    "bitcoin_core_config_sha256": sha256_text(bitcoin_core_config),
}
bitcoin_core_version = non_empty_text(args.bitcoin_core_version, "--bitcoin-core-version")
bitcoin_core_commit = non_empty_text(args.bitcoin_core_commit, "--bitcoin-core-commit")
if not re.fullmatch(r"[0-9a-f]{40}", bitcoin_core_commit):
    die("--bitcoin-core-commit must be 40 lowercase hex characters")
benchmark_artifact = require_file(args.benchmark_artifact, "--benchmark-artifact")
benchmark_artifact_path = str(benchmark_artifact.resolve())
utxo_commit_p95_ms = positive_float(args.utxo_commit_p95_ms, "--utxo-commit-p95-ms")
if args.electrum_rss_measurement is not None:
    electrum_rss_measurement = require_file(
        args.electrum_rss_measurement,
        "--electrum-rss-measurement",
    )
    electrum_rss_measurement_path = str(electrum_rss_measurement.resolve())
    electrum_rss = read_electrum_rss_measurement(electrum_rss_measurement, stop_height)
    if args.electrum_get_history_p95_ms is not None:
        supplied = positive_float(args.electrum_get_history_p95_ms, "--electrum-get-history-p95-ms")
        if not math.isclose(supplied, electrum_rss["electrum_get_history_p95_ms"], rel_tol=0.0, abs_tol=1e-12):
            die("--electrum-get-history-p95-ms must match --electrum-rss-measurement")
    if args.rss_bytes is not None:
        supplied = positive_int(args.rss_bytes, "--rss-bytes")
        if supplied != electrum_rss["rss_bytes"]:
            die("--rss-bytes must match --electrum-rss-measurement")
    electrum_rss["electrum_rss_measurement_path"] = electrum_rss_measurement_path
    electrum_rss["electrum_rss_measurement_sha256"] = sha256_file(electrum_rss_measurement)
else:
    if args.electrum_get_history_p95_ms is None or args.rss_bytes is None:
        die("--electrum-rss-measurement or both --electrum-get-history-p95-ms and --rss-bytes are required")
    electrum_rss = {
        "electrum_get_history_p95_ms": positive_float(
            args.electrum_get_history_p95_ms,
            "--electrum-get-history-p95-ms",
        ),
        "rss_bytes": positive_int(args.rss_bytes, "--rss-bytes"),
    }

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
criterion_benchmark_id_args = (
    args.criterion_bitcoin_rs_benchmark_id,
    args.criterion_bitcoin_core_benchmark_id,
)
criterion_benchmark_ids_supplied = [value is not None for value in criterion_benchmark_id_args]
if any(criterion_benchmark_ids_supplied) and not all(criterion_benchmark_ids_supplied):
    die(
        "--criterion-bitcoin-rs-benchmark-id and "
        "--criterion-bitcoin-core-benchmark-id must be supplied together"
    )
if any(criterion_elapsed_supplied) and not all(criterion_benchmark_ids_supplied):
    die("Criterion elapsed-second arguments require Criterion benchmark IDs")
if all(criterion_benchmark_ids_supplied):
    bench_tool = "criterion"
    elapsed_seconds_source = "criterion"
    bitcoin_rs_benchmark_id = non_empty_text(
        args.criterion_bitcoin_rs_benchmark_id,
        "--criterion-bitcoin-rs-benchmark-id",
    )
    required_literal(
        bitcoin_rs_benchmark_id,
        BITCOIN_RS_CRITERION_BENCHMARK_ID,
        "--criterion-bitcoin-rs-benchmark-id",
    )
    bitcoin_core_benchmark_id = non_empty_text(
        args.criterion_bitcoin_core_benchmark_id,
        "--criterion-bitcoin-core-benchmark-id",
    )
    required_literal(
        bitcoin_core_benchmark_id,
        BITCOIN_CORE_CRITERION_BENCHMARK_ID,
        "--criterion-bitcoin-core-benchmark-id",
    )
    (
        benchmark_run_id,
        benchmark_host_id,
        artifact_rs_elapsed_seconds,
        artifact_core_elapsed_seconds,
        raw_output_path_by_id,
        raw_output_sha256_by_id,
    ) = criterion_artifact_elapsed_seconds(
        benchmark_artifact,
        bitcoin_rs_benchmark_id,
        bitcoin_core_benchmark_id,
        start_height,
        stop_height,
        command_config_hashes,
    )
    bitcoin_rs_elapsed_seconds = require_optional_elapsed_matches_artifact(
        args.criterion_bitcoin_rs_elapsed_seconds,
        artifact_rs_elapsed_seconds,
        "--criterion-bitcoin-rs-elapsed-seconds",
    )
    bitcoin_core_elapsed_seconds = require_optional_elapsed_matches_artifact(
        args.criterion_bitcoin_core_elapsed_seconds,
        artifact_core_elapsed_seconds,
        "--criterion-bitcoin-core-elapsed-seconds",
    )
else:
    bench_tool = "wall-clock-command-wrapper"
    elapsed_seconds_source = "wall-clock-command-wrapper"
    benchmark_run_id = None
    benchmark_host_id = None
    bitcoin_rs_benchmark_id = None
    bitcoin_core_benchmark_id = None
    bitcoin_rs_elapsed_seconds = run_timed(bitcoin_rs_command, "--bitcoin-rs-command")
    bitcoin_core_elapsed_seconds = run_timed(bitcoin_core_command, "--bitcoin-core-command")

if bench_tool == "criterion" and args.electrum_rss_measurement is None:
    die("Criterion G14 manifests require --electrum-rss-measurement")

manifest = {
    "ibd_start_height": start_height,
    "ibd_stop_height": stop_height,
    "bench_tool": bench_tool,
    "elapsed_seconds_source": elapsed_seconds_source,
    "bitcoin_rs_elapsed_seconds": bitcoin_rs_elapsed_seconds,
    "bitcoin_core_elapsed_seconds": bitcoin_core_elapsed_seconds,
    "bitcoin_core_version": bitcoin_core_version,
    "bitcoin_rs_commit": current_head(),
    "storage_backend": "fjall",
    "indexes": "all",
    "bitcoin_core_commit": bitcoin_core_commit,
    "bitcoin_rs_command": bitcoin_rs_command,
    "bitcoin_core_command": bitcoin_core_command,
    "bitcoin_rs_config": bitcoin_rs_config,
    "bitcoin_core_config": bitcoin_core_config,
    "benchmark_artifact_path": benchmark_artifact_path,
    "benchmark_artifact_sha256": sha256_file(benchmark_artifact),
    **command_config_hashes,
    "utxo_commit_p95_ms": utxo_commit_p95_ms,
    **electrum_rss,
}
if all(criterion_benchmark_ids_supplied):
    manifest["criterion_artifact_schema"] = CRITERION_ARTIFACT_SCHEMA
    manifest["benchmark_run_id"] = benchmark_run_id
    manifest["benchmark_host_id"] = benchmark_host_id
    manifest["criterion_bitcoin_rs_benchmark_id"] = bitcoin_rs_benchmark_id
    manifest["criterion_bitcoin_core_benchmark_id"] = bitcoin_core_benchmark_id
    manifest["criterion_bitcoin_rs_raw_output_path"] = raw_output_path_by_id[bitcoin_rs_benchmark_id]
    manifest["criterion_bitcoin_rs_raw_output_sha256"] = raw_output_sha256_by_id[bitcoin_rs_benchmark_id]
    manifest["criterion_bitcoin_core_raw_output_path"] = raw_output_path_by_id[bitcoin_core_benchmark_id]
    manifest["criterion_bitcoin_core_raw_output_sha256"] = raw_output_sha256_by_id[bitcoin_core_benchmark_id]

output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(output)
PY
