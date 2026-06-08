#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: produce-g14-ibd-manifest.sh --output <evidence.json> --ibd-start-height <height> --ibd-stop-height <height> --bitcoin-rs-command <command> --bitcoin-core-command <command> [--criterion-bitcoin-rs-benchmark-id <id> --criterion-bitcoin-core-benchmark-id <id> [--criterion-bitcoin-rs-elapsed-seconds <seconds> --criterion-bitcoin-core-elapsed-seconds <seconds>]] --bitcoin-rs-config <path> --bitcoin-core-config <path> --bitcoin-core-version <version> --bitcoin-core-commit <40-hex> --benchmark-artifact <path> (--utxo-commit-measurement <json> | --utxo-commit-p95-ms <ms>) (--electrum-rss-measurement <json> | --electrum-get-history-p95-ms <ms> --rss-bytes <bytes>)' \
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
import shlex
import subprocess
import sys
import time

CRITERION_ARTIFACT_SCHEMA = "g14-criterion-artifact-v1"
IBD_COMPLETION_PROOF_SCHEMA = "g14-ibd-completion-proof-v1"
IBD_COMPLETION_PROOF_PREFIX = "G14_IBD_COMPLETION_PROOF "
ELECTRUM_RSS_MEASUREMENT_SCHEMA = "g14-electrum-rss-measurement-v1"
ELECTRUM_HISTORY_METHOD = "blockchain.scripthash.get_history"
ELECTRUM_SAMPLE_SIZE = 10_000
UTXO_COMMIT_MEASUREMENT_SCHEMA = "g14-utxo-commit-measurement-v1"
UTXO_COMMIT_SMOKE_SCHEMA = "g14-utxo-commit-smoke-v1"
UTXO_BLOCK_SIZE_THRESHOLD_BYTES = 4 * 1024 * 1024
BITCOIN_RS_CRITERION_BENCHMARK_ID = "bitcoin-rs/mainnet-ibd"
BITCOIN_CORE_CRITERION_BENCHMARK_ID = "bitcoin-core/mainnet-ibd"
BITCOIN_RS_IBD_ADAPTER = "bitcoin-rs-daemon-mainnet-ibd-v1"
BITCOIN_RS_DAEMON_ADAPTER_BASENAME = "run-g14-bitcoin-rs-daemon-mainnet-ibd.sh"
BITCOIN_RS_REPLAY_ADAPTER_BASENAME = "run-g14-bitcoin-rs-mainnet-ibd.sh"
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


def bitcoin_rs_command_argv(command: str, name: str) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as error:
        die(f"{name} must be shell-parseable: {error}")
    if not tokens:
        die(f"{name} must not be empty")
    return tokens


def validate_bitcoin_rs_ibd_command(command: str, name: str = "--bitcoin-rs-command") -> None:
    tokens = bitcoin_rs_command_argv(command, name)
    basenames = [Path(token).name for token in tokens]
    if BITCOIN_RS_REPLAY_ADAPTER_BASENAME in basenames:
        die(
            f"{name} must not invoke the mainnet prefix replay wrapper "
            f"{BITCOIN_RS_REPLAY_ADAPTER_BASENAME!r}"
        )
    if basenames[0] != BITCOIN_RS_DAEMON_ADAPTER_BASENAME:
        die(
            f"{name} must start with the bitcoin-rs daemon IBD adapter "
            f"{BITCOIN_RS_DAEMON_ADAPTER_BASENAME!r}, got {basenames[0]!r}"
        )
def parse_cli_flag_values(tokens: list[str], flag: str, name: str) -> list[str]:
    values: list[str] = []
    index = 0
    equals_prefix = f"{flag}="
    while index < len(tokens):
        token = tokens[index]
        if token == flag:
            if index + 1 >= len(tokens):
                die(f"{name} has {flag} without a value")
            values.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith(equals_prefix):
            values.append(token[len(equals_prefix) :])
            index += 1
            continue
        index += 1
    return values


def require_single_cli_flag_value(tokens: list[str], flag: str, name: str) -> str:
    values = parse_cli_flag_values(tokens, flag, name)
    if not values:
        die(f"{name} must include {flag}")
    if len(values) > 1:
        die(f"{name} must not repeat {flag}")
    return values[0]


def require_cli_height_flag(tokens: list[str], flag: str, name: str) -> int:
    raw = require_single_cli_flag_value(tokens, flag, name)
    try:
        height = int(raw)
    except ValueError as error:
        die(f"{name} {flag} must be a non-negative integer: {error}")
    if height < 0:
        die(f"{name} {flag} must be non-negative")
    return height


def require_cli_hash_flag(tokens: list[str], flag: str, name: str) -> str:
    raw = require_single_cli_flag_value(tokens, flag, name)
    block_hash = raw.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", block_hash):
        die(f"{name} {flag} must be 64 lowercase hex characters")
    return block_hash


def validate_bitcoin_rs_ibd_window_binding(
    command: str,
    name: str,
    start_height: int,
    stop_height: int,
    start_hash: str,
    stop_hash: str,
) -> None:
    validate_bitcoin_rs_ibd_command(command, name)
    tokens = bitcoin_rs_command_argv(command, name)
    command_start_height = require_cli_height_flag(tokens, "--ibd-start-height", name)
    command_stop_height = require_cli_height_flag(tokens, "--ibd-stop-height", name)
    command_start_hash = require_cli_hash_flag(tokens, "--ibd-start-hash", name)
    command_stop_hash = require_cli_hash_flag(tokens, "--ibd-stop-hash", name)
    if command_start_height != start_height:
        die(
            f"{name} --ibd-start-height must match outer G14 window "
            f"({command_start_height} != {start_height})"
        )
    if command_stop_height != stop_height:
        die(
            f"{name} --ibd-stop-height must match outer G14 window "
            f"({command_stop_height} != {stop_height})"
        )
    if command_start_hash != start_hash:
        die(f"{name} --ibd-start-hash must match outer G14 window")
    if command_stop_hash != stop_hash:
        die(f"{name} --ibd-stop-hash must match outer G14 window")



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


def require_proof_text(data: dict, key: str, expected: str, source: str) -> None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        die(f"{source} {key} must be a non-empty string")
    if value != expected:
        die(f"{source} {key} must be {expected!r}")


def require_proof_int(data: dict, key: str, expected: int, source: str) -> None:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"{source} {key} must be an integer")
    if value != expected:
        die(f"{source} {key} must be {expected}")


def require_ibd_completion_proof(
    raw_output: str,
    benchmark_id: str,
    benchmark_run_id: str,
    benchmark_host_id: str,
    start_height: int,
    start_hash: str,
    stop_height: int,
    stop_hash: str,
    command_sha256: str,
    config_sha256: str,
    source: str,
    expected_ibd_adapter: str | None = None,
) -> None:
    payloads = [
        line.removeprefix(IBD_COMPLETION_PROOF_PREFIX).strip()
        for line in raw_output.splitlines()
        if line.startswith(IBD_COMPLETION_PROOF_PREFIX)
    ]
    if len(payloads) != 1:
        die(f"{source} must contain exactly one {IBD_COMPLETION_PROOF_PREFIX.strip()} line")
    try:
        proof = json.loads(payloads[0])
    except json.JSONDecodeError as error:
        die(f"{source} IBD completion proof must be JSON: {error}")
    if not isinstance(proof, dict):
        die(f"{source} IBD completion proof must be a JSON object")
    require_proof_text(proof, "schema", IBD_COMPLETION_PROOF_SCHEMA, source)
    require_proof_text(proof, "benchmark_id", benchmark_id, source)
    require_proof_text(proof, "benchmark_run_id", benchmark_run_id, source)
    require_proof_text(proof, "benchmark_host_id", benchmark_host_id, source)
    require_proof_int(proof, "ibd_start_height", start_height, source)
    require_proof_text(proof, "ibd_start_hash", start_hash, source)
    require_proof_int(proof, "ibd_stop_height", stop_height, source)
    require_proof_text(proof, "ibd_stop_hash", stop_hash, source)
    require_proof_int(proof, "ibd_blocks", stop_height - start_height + 1, source)
    require_proof_text(proof, "command_sha256", command_sha256, source)
    require_proof_text(proof, "config_sha256", config_sha256, source)

    if expected_ibd_adapter is not None:
        require_proof_text(proof, "ibd_adapter", expected_ibd_adapter, source)
    elif proof.get("ibd_adapter") is not None:
        die(f"{source} IBD completion proof must not include ibd_adapter for {benchmark_id!r}")


def require_raw_output_binding(
    entry: dict,
    benchmark_id: str,
    elapsed_seconds: float,
    benchmark_run_id: str,
    benchmark_host_id: str,
    start_height: int,
    start_hash: str,
    stop_height: int,
    stop_hash: str,
    command_sha256: str,
    config_sha256: str,
    source: str,
) -> tuple[str, str]:
    raw_output_path = require_raw_output_path(entry, source)
    raw_output_sha256 = require_raw_output_sha256(entry, source)
    if sha256_file(raw_output_path) != raw_output_sha256:
        die(f"{source} raw_output_sha256 must match raw_output_path")
    raw_output = read_raw_output(raw_output_path, source)
    parsed_seconds = criterion_elapsed_seconds(
        raw_output,
        benchmark_id,
        source,
    )
    if not math.isclose(elapsed_seconds, parsed_seconds, rel_tol=0.0, abs_tol=1e-12):
        die(f"{source} elapsed_seconds must match raw_output_path Criterion output")
    require_ibd_completion_proof(
        raw_output,
        benchmark_id,
        benchmark_run_id,
        benchmark_host_id,
        start_height,
        start_hash,
        stop_height,
        stop_hash,
        command_sha256,
        config_sha256,
        source,
        BITCOIN_RS_IBD_ADAPTER if benchmark_id == BITCOIN_RS_CRITERION_BENCHMARK_ID else None,
    )
    return str(raw_output_path.resolve()), raw_output_sha256


def criterion_artifact_elapsed_seconds(
    path: Path,
    rs_id: str,
    core_id: str,
    start_height: int,
    stop_height: int,
    command_config_hashes: dict[str, str],
    bitcoin_rs_command: str,
) -> tuple[str, str, float, float, dict[str, str], dict[str, str], str]:
    data = read_json_file(path, "--benchmark-artifact")
    if not isinstance(data, dict):
        die("--benchmark-artifact Criterion evidence must be a JSON object")
    if data.get("schema") != CRITERION_ARTIFACT_SCHEMA:
        die(f"--benchmark-artifact schema must be {CRITERION_ARTIFACT_SCHEMA!r}")
    require_int_field(data, "ibd_start_height", start_height, "--benchmark-artifact")
    require_int_field(data, "ibd_stop_height", stop_height, "--benchmark-artifact")
    start_hash = require_hex_field(data, "ibd_start_hash", 64, "--benchmark-artifact")
    stop_hash = require_hex_field(data, "ibd_stop_hash", 64, "--benchmark-artifact")
    validate_bitcoin_rs_ibd_window_binding(
        bitcoin_rs_command,
        "--bitcoin-rs-command",
        start_height,
        stop_height,
        start_hash,
        stop_hash,
    )
    benchmark_run_id = require_benchmark_run_id(
        data,
        "benchmark_run_id",
        None,
        "--benchmark-artifact",
    )
    benchmark_host_id = require_text_field(data, "benchmark_host_id", "--benchmark-artifact")
    for key, expected in command_config_hashes.items():
        require_matching_hash_field(data, key, expected, "--benchmark-artifact")
    require_literal_field(
        data,
        "bitcoin_rs_ibd_adapter",
        BITCOIN_RS_IBD_ADAPTER,
        "--benchmark-artifact",
    )
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
            benchmark_run_id,
            benchmark_host_id,
            start_height,
            start_hash,
            stop_height,
            stop_hash,
            command_config_hashes["bitcoin_rs_command_sha256"]
            if benchmark_id == rs_id
            else command_config_hashes["bitcoin_core_command_sha256"],
            command_config_hashes["bitcoin_rs_config_sha256"]
            if benchmark_id == rs_id
            else command_config_hashes["bitcoin_core_config_sha256"],
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
        BITCOIN_RS_IBD_ADAPTER,
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

def percentile_ms(samples_ms: list[float], numerator: int, denominator: int) -> float:
    if not samples_ms:
        die("cannot calculate percentile for an empty sample")
    ordered = sorted(samples_ms)
    index = math.ceil(len(ordered) * numerator / denominator) - 1
    index = max(0, min(index, len(ordered) - 1))
    return ordered[index]


def positive_sample_float(value, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        die(f"{name} must be a finite positive number")
    number = float(value)
    if not math.isfinite(number) or number <= 0.0:
        die(f"{name} must be finite and positive")
    return number


def read_utxo_samples(path: Path) -> list:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        die(f"sample source must be UTF-8 JSON: {error}")
    except json.JSONDecodeError as error:
        die(f"sample source must be JSON: {error}")
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        samples = payload.get("samples")
        if isinstance(samples, list):
            return samples
    die("sample source must be a JSON array or an object with a samples array")


def utxo_sample_commit_ms(sample: dict, index: int) -> float:
    if "utxo_commit_ms" in sample and "utxo_commit_us" in sample:
        die(f"sample[{index}] must not include both utxo_commit_ms and utxo_commit_us")
    if "utxo_commit_ms" in sample:
        return positive_sample_float(sample["utxo_commit_ms"], f"sample[{index}].utxo_commit_ms")
    if "utxo_commit_us" in sample:
        return positive_sample_float(sample["utxo_commit_us"], f"sample[{index}].utxo_commit_us") / 1000.0
    die(f"sample[{index}] must include utxo_commit_ms or utxo_commit_us")


def parse_utxo_sample(
    sample,
    index: int,
    start_height: int,
    stop_height: int,
    threshold_bytes: int,
) -> float | None:
    if not isinstance(sample, dict):
        die(f"sample[{index}] must be an object")
    height = sample.get("height")
    if not isinstance(height, int) or isinstance(height, bool):
        die(f"sample[{index}].height must be an integer")
    if height < start_height or height > stop_height:
        die(f"sample[{index}].height must be within the IBD window")
    block_hash = sample.get("block_hash")
    if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
        die(f"sample[{index}].block_hash must be 64 lowercase hex characters")
    block_size = sample.get("block_size_bytes")
    if not isinstance(block_size, int) or isinstance(block_size, bool):
        die(f"sample[{index}].block_size_bytes must be an integer")
    if block_size < threshold_bytes:
        return None
    return utxo_sample_commit_ms(sample, index)


def qualifying_utxo_commit_samples_ms(
    samples_path: Path,
    start_height: int,
    stop_height: int,
    threshold_bytes: int,
) -> list[float]:
    qualifying_ms: list[float] = []
    for index, sample in enumerate(read_utxo_samples(samples_path)):
        parsed = parse_utxo_sample(sample, index, start_height, stop_height, threshold_bytes)
        if parsed is not None:
            qualifying_ms.append(parsed)
    return qualifying_ms



def utxo_sample_hash_at_height(samples: list, height: int, source: str) -> str:
    matched: str | None = None
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            die(f"{source}[{index}] must be an object")
        sample_height = sample.get("height")
        if not isinstance(sample_height, int) or isinstance(sample_height, bool):
            die(f"{source}[{index}].height must be an integer")
        if sample_height != height:
            continue
        block_hash = sample.get("block_hash")
        if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
            die(f"{source}[{index}].block_hash must be 64 lowercase hex characters")
        if matched is not None and matched != block_hash:
            die(f"{source} contains conflicting block_hash values for height {height}")
        matched = block_hash
    if matched is None:
        die(f"{source} must include a sample at height {height}")
    return matched


def verify_utxo_boundary_sample_hashes(
    samples_path: Path,
    start_height: int,
    start_hash: str,
    stop_height: int,
    stop_hash: str,
) -> None:
    samples = read_utxo_samples(samples_path)
    start_sample_hash = utxo_sample_hash_at_height(samples, start_height, "sample source")
    if start_sample_hash != start_hash:
        die("sample source block_hash at ibd_start_height must match --ibd-start-hash")
    stop_sample_hash = utxo_sample_hash_at_height(samples, stop_height, "sample source")
    if stop_sample_hash != stop_hash:
        die("sample source block_hash at ibd_stop_height must match --ibd-stop-hash")

def verify_utxo_commit_sample_custody(
    data: dict,
    source: str,
    start_height: int,
    start_hash: str,
    stop_height: int,
    stop_hash: str,
    threshold_bytes: int,
) -> None:
    sample_source_path_value = data.get("sample_source_path")
    if not isinstance(sample_source_path_value, str) or not sample_source_path_value.strip():
        die(f"{source} sample_source_path must be a non-empty string")
    sample_source_path = Path(sample_source_path_value)
    if not sample_source_path.is_file():
        die(f"{source} sample_source_path is not a readable file: {sample_source_path}")
    expected_sample_sha = require_hex_field(data, "sample_source_sha256", 64, source)
    if sha256_file(sample_source_path) != expected_sample_sha:
        die(f"{source} sample_source_sha256 must match sample_source_path")
    verify_utxo_boundary_sample_hashes(
        sample_source_path,
        start_height,
        start_hash,
        stop_height,
        stop_hash,
    )
    expected_sample_count = require_int_value(data, "sample_count", source, positive=True)
    expected_p95_ms = require_number_value(data, "utxo_commit_p95_ms", source)
    qualifying_ms = qualifying_utxo_commit_samples_ms(
        sample_source_path,
        start_height,
        stop_height,
        threshold_bytes,
    )
    if len(qualifying_ms) != expected_sample_count:
        die(f"{source} sample_count must match qualifying samples from sample_source_path")
    recomputed_p95_ms = percentile_ms(qualifying_ms, 95, 100)
    if not math.isclose(recomputed_p95_ms, expected_p95_ms, rel_tol=0.0, abs_tol=1e-12):
        die(f"{source} utxo_commit_p95_ms must match sample_source_path")




def read_utxo_commit_measurement(
    path: Path,
    start_height: int,
    stop_height: int,
) -> dict:
    data = read_json_file(path, "--utxo-commit-measurement")
    if not isinstance(data, dict):
        die("--utxo-commit-measurement must be a JSON object")
    require_literal_field(data, "schema", UTXO_COMMIT_MEASUREMENT_SCHEMA, "--utxo-commit-measurement")
    require_literal_field(data, "measurement_kind", "evidence", "--utxo-commit-measurement")
    head = current_head()
    require_literal_field(data, "bitcoin_rs_commit", head, "--utxo-commit-measurement")
    require_exact_int(data, "ibd_start_height", start_height, "--utxo-commit-measurement")
    require_exact_int(data, "ibd_stop_height", stop_height, "--utxo-commit-measurement")
    start_hash = require_hex_field(data, "ibd_start_hash", 64, "--utxo-commit-measurement")
    stop_hash = require_hex_field(data, "ibd_stop_hash", 64, "--utxo-commit-measurement")
    threshold = require_int_value(
        data,
        "block_size_threshold_bytes",
        "--utxo-commit-measurement",
        positive=True,
    )
    if threshold != UTXO_BLOCK_SIZE_THRESHOLD_BYTES:
        die("--utxo-commit-measurement block_size_threshold_bytes must be 4194304")
    verify_utxo_commit_sample_custody(
        data,
        "--utxo-commit-measurement",
        start_height,
        start_hash,
        stop_height,
        stop_hash,
        threshold,
    )
    sample_count = require_int_value(data, "sample_count", "--utxo-commit-measurement", positive=True)
    return {
        "utxo_commit_p95_ms": require_number_value(data, "utxo_commit_p95_ms", "--utxo-commit-measurement"),
        "utxo_commit_measurement_schema": UTXO_COMMIT_MEASUREMENT_SCHEMA,
        "utxo_commit_measurement_sample_count": sample_count,
        "utxo_commit_measurement_start_height": start_height,
        "utxo_commit_measurement_start_hash": require_hex_field(
            data,
            "ibd_start_hash",
            64,
            "--utxo-commit-measurement",
        ),
        "utxo_commit_measurement_stop_height": stop_height,
        "utxo_commit_measurement_stop_hash": require_hex_field(
            data,
            "ibd_stop_hash",
            64,
            "--utxo-commit-measurement",
        ),
        "utxo_commit_block_size_threshold_bytes": threshold,
    }



def require_exact_int(data: dict, key: str, expected: int, source: str) -> int:
    value = require_int_value(data, key, source)
    if value != expected:
        die(f"{source} {key} must be {expected}")
    return value


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
parser.add_argument("--utxo-commit-measurement")
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
        "--benchmark-artifact <path> "
        "(--utxo-commit-measurement <json> | --utxo-commit-p95-ms <ms>) "
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
if args.utxo_commit_measurement is not None:
    utxo_commit_measurement = require_file(
        args.utxo_commit_measurement,
        "--utxo-commit-measurement",
    )
    utxo_commit_measurement_path = str(utxo_commit_measurement.resolve())
    utxo = read_utxo_commit_measurement(utxo_commit_measurement, start_height, stop_height)
    if args.utxo_commit_p95_ms is not None:
        supplied = positive_float(args.utxo_commit_p95_ms, "--utxo-commit-p95-ms")
        if not math.isclose(supplied, utxo["utxo_commit_p95_ms"], rel_tol=0.0, abs_tol=1e-12):
            die("--utxo-commit-p95-ms must match --utxo-commit-measurement")
    utxo["utxo_commit_measurement_path"] = utxo_commit_measurement_path
    utxo["utxo_commit_measurement_sha256"] = sha256_file(utxo_commit_measurement)
    utxo_commit_p95_ms = utxo["utxo_commit_p95_ms"]
elif args.utxo_commit_p95_ms is not None:
    utxo_commit_p95_ms = positive_float(args.utxo_commit_p95_ms, "--utxo-commit-p95-ms")
    utxo = {"utxo_commit_p95_ms": utxo_commit_p95_ms}
else:
    die("--utxo-commit-measurement or --utxo-commit-p95-ms is required")
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
        bitcoin_rs_ibd_adapter,
    ) = criterion_artifact_elapsed_seconds(
        benchmark_artifact,
        bitcoin_rs_benchmark_id,
        bitcoin_core_benchmark_id,
        start_height,
        stop_height,
        command_config_hashes,
        bitcoin_rs_command,
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
if bench_tool == "criterion" and args.utxo_commit_measurement is None:
    die("Criterion G14 manifests require --utxo-commit-measurement")

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
    **utxo,
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
    manifest["bitcoin_rs_ibd_adapter"] = bitcoin_rs_ibd_adapter

output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(output)
PY
