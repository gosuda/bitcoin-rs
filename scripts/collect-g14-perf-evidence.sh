#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: collect-g14-perf-evidence.sh <evidence.json> [-- <bitcoin-cli-arg>...]' \
    '' \
    'Normalizes externally measured G14 mainnet IBD evidence into shell exports.' \
    'The helper does not start or manage bitcoin-rs, bitcoind, or Electrum.' \
    'It verifies Bitcoin Core mainnet metadata and resolves measured block hashes.' \
    '' \
    'Required JSON keys:' \
    '  ibd_start_height, ibd_stop_height,' \
    '  bitcoin_rs_elapsed_seconds, bitcoin_core_elapsed_seconds,' \
    '  criterion_bitcoin_rs_benchmark_id, criterion_bitcoin_core_benchmark_id,' \
    '  bench_tool=criterion, elapsed_seconds_source=criterion,' \
    '  bitcoin_rs_commit, storage_backend=fjall, indexes=all,' \
    '  bitcoin_core_version, bitcoin_core_commit,' \
    '  bitcoin_rs_command, bitcoin_core_command,' \
    '  bitcoin_rs_config, bitcoin_core_config,' \
    '  benchmark_artifact_path, benchmark_artifact_sha256, criterion_artifact_schema=g14-criterion-artifact-v1,' \
    '  benchmark_run_id shared by both Criterion benchmark entries,' \
    '  benchmark_host_id shared by both Criterion benchmark entries,' \
    '  criterion_bitcoin_rs_raw_output_path, criterion_bitcoin_rs_raw_output_sha256,' \
    '  criterion_bitcoin_core_raw_output_path, criterion_bitcoin_core_raw_output_sha256,' \
    '  Criterion artifact ibd_start_height/hash and ibd_stop_height/hash matching the live Core window,' \
    '  Criterion artifact bitcoin_rs/core command/config sha256 fields matching the evidence JSON,' \
    '  utxo_commit_p95_ms, electrum_get_history_p95_ms, rss_bytes' \
    '  required Electrum/RSS binding: electrum_rss_measurement_path, electrum_rss_measurement_sha256,' \
    '  electrum_rss_measurement_schema=g14-electrum-rss-measurement-v1, electrum_rss_measurement_sample_size=10000,' \
    '  electrum_rss_measurement_tip_height/hash matching the live stop height/hash' \
    '' \
    'Set BITCOIN_CLI=/path/to/bitcoin-cli to override the binary.' \
    '' \
    'Example:' \
    '  eval "$(bash scripts/collect-g14-perf-evidence.sh /tmp/g14.json -- -datadir=/srv/bitcoin-mainnet)"' \
    '  cargo test -p bitcoin-rs --test g14_perf_budgets -- --ignored --nocapture'
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 2
}

evidence_path=
while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      [[ -z "$evidence_path" ]] || die "unexpected argument: $1"
      evidence_path="$1"
      shift
      ;;
  esac
done

[[ -n "$evidence_path" ]] || die 'evidence JSON path is required'
[[ -r "$evidence_path" ]] || die "evidence JSON is not readable: $evidence_path"

bitcoin_cli="${BITCOIN_CLI:-bitcoin-cli}"
bitcoin_cli_args=("$@")

start_height="$(python3 - "$evidence_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
print(data["ibd_start_height"])
PY
)"
stop_height="$(python3 - "$evidence_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
print(data["ibd_stop_height"])
PY
)"

python3 - "$evidence_path" <<'PY'
import json
import sys

OFFLINE_KEYS = ("ibd_start_hash", "ibd_stop_hash", "bitcoin_core_chain_info")

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
present = [key for key in OFFLINE_KEYS if key in data]
if present:
    raise SystemExit(
        "error: offline Bitcoin Core metadata is not accepted; "
        "remove "
        + ", ".join(present)
        + " and provide BITCOIN_CLI for live getblockhash/getblockchaininfo queries"
    )
PY

start_hash="$("$bitcoin_cli" "${bitcoin_cli_args[@]}" getblockhash "$start_height")"
stop_hash="$("$bitcoin_cli" "${bitcoin_cli_args[@]}" getblockhash "$stop_height")"
chain_info="$("$bitcoin_cli" "${bitcoin_cli_args[@]}" getblockchaininfo)"
chain_info_source="bitcoin-cli"

G14_START_HASH="$start_hash" G14_STOP_HASH="$stop_hash" G14_CHAIN_INFO="$chain_info" G14_CHAIN_INFO_SOURCE="$chain_info_source" python3 - "$evidence_path" <<'PY'
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

EVIDENCE_HELP = "collect-g14-perf-evidence.sh requires the JSON keys listed in --help"
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


def require_key(data: dict, key: str):
    if key not in data:
        die(f"missing {key}; {EVIDENCE_HELP}")
    return data[key]


def require_int(data: dict, key: str, *, positive: bool) -> int:
    value = require_key(data, key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"{key} must be an integer")
    if positive and value <= 0:
        die(f"{key} must be positive")
    if not positive and value < 0:
        die(f"{key} must be non-negative")
    return value


def require_number(data: dict, key: str) -> str:
    value = require_key(data, key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        die(f"{key} must be a positive number")
    numeric = float(value)
    if not numeric > 0.0 or numeric == float("inf"):
        die(f"{key} must be finite and positive")
    return str(value)


def require_number_value(data: dict, key: str, source: str) -> float:
    value = data.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        die(f"{source} {key} must be a positive number")
    numeric = float(value)
    if not numeric > 0.0 or numeric == float("inf"):
        die(f"{source} {key} must be finite and positive")
    return numeric


def require_text(data: dict, key: str) -> str:
    value = require_key(data, key)
    if not isinstance(value, str) or not value.strip():
        die(f"{key} must be a non-empty string")
    return value


def require_literal_value(data: dict, key: str, expected: str) -> str:
    value = require_text(data, key)
    if value != expected:
        die(f"{key} must be {expected!r}, got {value!r}")
    return value


def require_literal_field(data: dict, key: str, expected: str, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        die(f"{source} {key} must be a string")
    if value != expected:
        die(f"{source} {key} must be {expected!r}")
    return value


def require_hex(value: str, length: int, name: str) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        die(f"{name} must be {length} lowercase hex characters")
    return value


def require_hex_field(data: dict, key: str, length: int, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        die(f"{source} {key} must be {length} lowercase hex characters")
    return value


def require_chain_height(data: dict, key: str, stop_height: int, source: str) -> None:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"{source} {key} must be an integer")
    if value < stop_height:
        die(
            f"{source} {key}={value} is below "
            f"ibd_stop_height={stop_height}"
        )


def require_artifact_height(data: dict, key: str, expected: int) -> None:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"benchmark_artifact_path {key} must be an integer")
    if value != expected:
        die(f"benchmark_artifact_path {key} must match evidence {key}={expected}")


def require_artifact_hash(data: dict, key: str, expected: str) -> None:
    value = data.get(key)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        die(f"benchmark_artifact_path {key} must be 64 lowercase hex characters")
    if value != expected:
        die(f"benchmark_artifact_path {key} must match live bitcoin-cli {key}")


def require_artifact_binding(data: dict, key: str, expected: str) -> None:
    value = data.get(key)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        die(f"benchmark_artifact_path {key} must be 64 lowercase hex characters")
    if value != expected:
        die(f"benchmark_artifact_path {key} must match evidence {key}")


def require_benchmark_run_id(data: dict, key: str, expected: str | None, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        die(f"{source} {key} must be a non-empty string")
    if expected is not None and value != expected:
        die(f"{source} {key} must match benchmark_artifact_path benchmark_run_id")
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
    if not value.strip():
        die(f"{source} raw_output_path must not be empty")
    return value


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


def require_exact_int(data: dict, key: str, expected: int, source: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        die(f"{source} {key} must be an integer")
    if value != expected:
        die(f"{source} {key} must be {expected}")
    return value


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_criterion_artifact(
    path: Path,
    start_height: int,
    stop_height: int,
    start_hash: str,
    stop_hash: str,
    command_config_hashes: dict[str, str],
) -> tuple[str, str, dict[str, float], dict[str, str], dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except UnicodeDecodeError as error:
        die(f"benchmark_artifact_path must point to UTF-8 JSON: {error}")
    except json.JSONDecodeError as error:
        die(f"benchmark_artifact_path must point to JSON: {error}")
    if not isinstance(data, dict):
        die("benchmark_artifact_path Criterion evidence must be a JSON object")
    if data.get("schema") != CRITERION_ARTIFACT_SCHEMA:
        die(f"benchmark_artifact_path schema must be {CRITERION_ARTIFACT_SCHEMA!r}")
    benchmark_run_id = require_benchmark_run_id(
        data,
        "benchmark_run_id",
        None,
        "benchmark_artifact_path",
    )
    benchmark_host_id = require_text(data, "benchmark_host_id")
    require_artifact_height(data, "ibd_start_height", start_height)
    require_artifact_height(data, "ibd_stop_height", stop_height)
    require_artifact_hash(data, "ibd_start_hash", start_hash)
    require_artifact_hash(data, "ibd_stop_hash", stop_hash)
    for key, expected in command_config_hashes.items():
        require_artifact_binding(data, key, expected)
    benchmarks = data.get("benchmarks")
    if not isinstance(benchmarks, list):
        die("benchmark_artifact_path benchmarks must be an array")
    elapsed_by_id = {}
    raw_output_path_by_id = {}
    raw_output_sha256_by_id = {}
    for index, entry in enumerate(benchmarks):
        if not isinstance(entry, dict):
            die(f"benchmark_artifact_path benchmarks[{index}] must be an object")
        benchmark_id = entry.get("benchmark_id")
        if not isinstance(benchmark_id, str) or not benchmark_id.strip():
            die(f"benchmark_artifact_path benchmarks[{index}].benchmark_id must be a non-empty string")
        require_benchmark_run_id(
            entry,
            "benchmark_run_id",
            benchmark_run_id,
            f"benchmark_artifact_path benchmarks[{index}]",
        )
        if benchmark_id in elapsed_by_id:
            die(f"benchmark_artifact_path contains duplicate benchmark_id {benchmark_id!r}")
        elapsed = entry.get("elapsed_seconds")
        if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool):
            die(f"benchmark_artifact_path benchmark {benchmark_id!r} elapsed_seconds must be a number")
        elapsed = float(elapsed)
        if not elapsed > 0.0 or elapsed == float("inf"):
            die(f"benchmark_artifact_path benchmark {benchmark_id!r} elapsed_seconds must be finite and positive")
        raw_path, raw_sha256 = require_raw_output_binding(
            entry,
            benchmark_id,
            elapsed,
            f"benchmark_artifact_path benchmarks[{index}]",
        )
        elapsed_by_id[benchmark_id] = elapsed
        raw_output_path_by_id[benchmark_id] = raw_path
        raw_output_sha256_by_id[benchmark_id] = raw_sha256
    return benchmark_run_id, benchmark_host_id, elapsed_by_id, raw_output_path_by_id, raw_output_sha256_by_id


def read_json_file(path: Path, source: str):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except UnicodeDecodeError as error:
        die(f"{source} must point to UTF-8 JSON: {error}")
    except json.JSONDecodeError as error:
        die(f"{source} must point to JSON: {error}")


def validate_electrum_rss_measurement(
    evidence: dict,
    stop_height: int,
    stop_hash: str,
) -> None:
    if "electrum_rss_measurement_path" not in evidence:
        die("electrum_rss_measurement_path is required for G14 evidence")
    path = Path(require_text(evidence, "electrum_rss_measurement_path"))
    expected_sha = require_hex(
        require_text(evidence, "electrum_rss_measurement_sha256"),
        64,
        "electrum_rss_measurement_sha256",
    )
    if not path.is_file():
        die(f"electrum_rss_measurement_path is not a readable file: {path}")
    if sha256_file(path) != expected_sha:
        die("electrum_rss_measurement_sha256 must match electrum_rss_measurement_path")
    data = read_json_file(path, "electrum_rss_measurement_path")
    if not isinstance(data, dict):
        die("electrum_rss_measurement_path must point to a JSON object")
    require_literal_value(evidence, "electrum_rss_measurement_schema", ELECTRUM_RSS_MEASUREMENT_SCHEMA)
    require_literal_field(data, "schema", ELECTRUM_RSS_MEASUREMENT_SCHEMA, "electrum_rss_measurement_path")
    require_literal_field(data, "measurement_kind", "evidence", "electrum_rss_measurement_path")
    require_literal_field(data, "method", ELECTRUM_HISTORY_METHOD, "electrum_rss_measurement_path")
    require_exact_int(evidence, "electrum_rss_measurement_sample_size", ELECTRUM_SAMPLE_SIZE, "evidence JSON")
    require_exact_int(data, "electrum_sample_size", ELECTRUM_SAMPLE_SIZE, "electrum_rss_measurement_path")
    require_exact_int(
        evidence,
        "electrum_rss_measurement_non_empty_history_count",
        ELECTRUM_SAMPLE_SIZE,
        "evidence JSON",
    )
    require_exact_int(
        data,
        "electrum_non_empty_history_count",
        ELECTRUM_SAMPLE_SIZE,
        "electrum_rss_measurement_path",
    )
    require_exact_int(evidence, "electrum_rss_measurement_tip_height", stop_height, "evidence JSON")
    require_exact_int(data, "electrum_tip_height", stop_height, "electrum_rss_measurement_path")
    manifest_tip_hash = require_hex_field(
        evidence,
        "electrum_rss_measurement_tip_hash",
        64,
        "evidence JSON",
    )
    artifact_tip_hash = require_hex_field(
        data,
        "electrum_tip_hash",
        64,
        "electrum_rss_measurement_path",
    )
    if manifest_tip_hash != stop_hash or artifact_tip_hash != stop_hash:
        die("electrum_rss_measurement tip hash must match live bitcoin-cli ibd_stop_hash")
    corpus_hash = require_hex_field(
        evidence,
        "electrum_scripthash_corpus_sha256",
        64,
        "evidence JSON",
    )
    if require_hex_field(data, "electrum_scripthash_corpus_sha256", 64, "electrum_rss_measurement_path") != corpus_hash:
        die("electrum_scripthash_corpus_sha256 must match electrum_rss_measurement_path")
    if require_text(evidence, "electrum_scripthash_corpus") != require_literal_field(
        data,
        "electrum_scripthash_corpus",
        require_text(evidence, "electrum_scripthash_corpus"),
        "electrum_rss_measurement_path",
    ):
        die("electrum_scripthash_corpus must match electrum_rss_measurement_path")
    if not math.isclose(
        float(require_number(evidence, "electrum_get_history_p95_ms")),
        require_number_value(data, "electrum_get_history_p95_ms", "electrum_rss_measurement_path"),
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        die("electrum_get_history_p95_ms must match electrum_rss_measurement_path")
    if require_int(evidence, "rss_bytes", positive=True) != require_exact_int(
        data,
        "rss_bytes",
        require_int(evidence, "rss_bytes", positive=True),
        "electrum_rss_measurement_path",
    ):
        die("rss_bytes must match electrum_rss_measurement_path")


def require_artifact_elapsed(
    elapsed_by_id: dict[str, float],
    benchmark_id: str,
    elapsed_seconds: str,
    name: str,
) -> None:
    if benchmark_id not in elapsed_by_id:
        die(f"benchmark_artifact_path is missing benchmark_id {benchmark_id!r}")
    if not math.isclose(float(elapsed_seconds), elapsed_by_id[benchmark_id], rel_tol=0.0, abs_tol=1e-12):
        die(f"{name} must match benchmark_artifact_path elapsed_seconds for {benchmark_id!r}")


def optional_manifest_binding(data: dict, key: str, expected: str) -> str:
    if key not in data:
        return expected
    value = require_text(data, key)
    if value != expected:
        die(f"{key} must match benchmark_artifact_path")
    return value


def current_head() -> str:
    output = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], text=True)
    return require_hex(output.strip(), 40, "git HEAD")


with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
if not isinstance(data, dict):
    die("evidence JSON must be an object")

start_height = require_int(data, "ibd_start_height", positive=False)
stop_height = require_int(data, "ibd_stop_height", positive=False)
if stop_height < start_height:
    die("ibd_stop_height must be greater than or equal to ibd_start_height")

start_hash = require_hex(os.environ["G14_START_HASH"].strip(), 64, "bitcoin-cli start hash")
stop_hash = require_hex(os.environ["G14_STOP_HASH"].strip(), 64, "bitcoin-cli stop hash")
chain_info_source = os.environ.get("G14_CHAIN_INFO_SOURCE", "bitcoin-cli")
try:
    chain_info = json.loads(os.environ["G14_CHAIN_INFO"])
except json.JSONDecodeError as error:
    die(f"{chain_info_source} chain info must be JSON: {error}")
if not isinstance(chain_info, dict):
    die(f"{chain_info_source} chain info must be an object")
if chain_info.get("chain") != "main":
    die(f"{chain_info_source} must be connected to mainnet, got chain={chain_info.get('chain')!r}")
require_chain_height(chain_info, "blocks", stop_height, chain_info_source)
require_chain_height(chain_info, "headers", stop_height, chain_info_source)
bitcoin_rs_commit = require_hex(require_text(data, "bitcoin_rs_commit"), 40, "bitcoin_rs_commit")
head = current_head()
if bitcoin_rs_commit != head:
    die(f"bitcoin_rs_commit must match git HEAD {head}")
storage_backend = require_literal_value(data, "storage_backend", "fjall")
indexes = require_literal_value(data, "indexes", "all")
core_commit = require_hex(require_text(data, "bitcoin_core_commit"), 40, "bitcoin_core_commit")
bench_tool = require_literal_value(data, "bench_tool", "criterion")
require_literal_value(data, "elapsed_seconds_source", "criterion")
rs_command = require_text(data, "bitcoin_rs_command")
core_command = require_text(data, "bitcoin_core_command")
rs_config = require_text(data, "bitcoin_rs_config")
core_config = require_text(data, "bitcoin_core_config")
rs_command_sha256 = sha256_text(rs_command)
core_command_sha256 = sha256_text(core_command)
rs_config_sha256 = sha256_text(rs_config)
core_config_sha256 = sha256_text(core_config)
benchmark_artifact_sha256 = require_hex(
    require_text(data, "benchmark_artifact_sha256"),
    64,
    "benchmark_artifact_sha256",
)
benchmark_artifact_path = Path(require_text(data, "benchmark_artifact_path"))
if not benchmark_artifact_path.is_file():
    die(f"benchmark_artifact_path is not a readable file: {benchmark_artifact_path}")
if sha256_file(benchmark_artifact_path) != benchmark_artifact_sha256:
    die("benchmark_artifact_sha256 must match benchmark_artifact_path")
require_literal_value(data, "criterion_artifact_schema", CRITERION_ARTIFACT_SCHEMA)
(
    artifact_benchmark_run_id,
    artifact_benchmark_host_id,
    artifact_elapsed_by_id,
    artifact_raw_output_path_by_id,
    artifact_raw_output_sha256_by_id,
) = read_criterion_artifact(
    benchmark_artifact_path,
    start_height,
    stop_height,
    start_hash,
    stop_hash,
    {
        "bitcoin_rs_command_sha256": rs_command_sha256,
        "bitcoin_core_command_sha256": core_command_sha256,
        "bitcoin_rs_config_sha256": rs_config_sha256,
        "bitcoin_core_config_sha256": core_config_sha256,
    },
)
if "benchmark_run_id" in data:
    require_benchmark_run_id(data, "benchmark_run_id", artifact_benchmark_run_id, "evidence JSON")
benchmark_host_id = require_text(data, "benchmark_host_id")
if benchmark_host_id != artifact_benchmark_host_id:
    die("benchmark_host_id must match benchmark_artifact_path benchmark_host_id")
block_count = stop_height - start_height + 1
bitcoin_rs_elapsed_seconds = require_number(data, "bitcoin_rs_elapsed_seconds")
bitcoin_core_elapsed_seconds = require_number(data, "bitcoin_core_elapsed_seconds")
criterion_bitcoin_rs_benchmark_id = require_text(data, "criterion_bitcoin_rs_benchmark_id")
criterion_bitcoin_core_benchmark_id = require_text(data, "criterion_bitcoin_core_benchmark_id")
if criterion_bitcoin_rs_benchmark_id != BITCOIN_RS_CRITERION_BENCHMARK_ID:
    die(
        "criterion_bitcoin_rs_benchmark_id must be "
        f"{BITCOIN_RS_CRITERION_BENCHMARK_ID!r}"
    )
if criterion_bitcoin_core_benchmark_id != BITCOIN_CORE_CRITERION_BENCHMARK_ID:
    die(
        "criterion_bitcoin_core_benchmark_id must be "
        f"{BITCOIN_CORE_CRITERION_BENCHMARK_ID!r}"
    )
require_artifact_elapsed(
    artifact_elapsed_by_id,
    criterion_bitcoin_rs_benchmark_id,
    bitcoin_rs_elapsed_seconds,
    "bitcoin_rs_elapsed_seconds",
)
require_artifact_elapsed(
    artifact_elapsed_by_id,
    criterion_bitcoin_core_benchmark_id,
    bitcoin_core_elapsed_seconds,
    "bitcoin_core_elapsed_seconds",
)
criterion_bitcoin_rs_raw_output_path = optional_manifest_binding(
    data,
    "criterion_bitcoin_rs_raw_output_path",
    artifact_raw_output_path_by_id[criterion_bitcoin_rs_benchmark_id],
)
criterion_bitcoin_rs_raw_output_sha256 = optional_manifest_binding(
    data,
    "criterion_bitcoin_rs_raw_output_sha256",
    artifact_raw_output_sha256_by_id[criterion_bitcoin_rs_benchmark_id],
)
require_hex(criterion_bitcoin_rs_raw_output_sha256, 64, "criterion_bitcoin_rs_raw_output_sha256")
criterion_bitcoin_core_raw_output_path = optional_manifest_binding(
    data,
    "criterion_bitcoin_core_raw_output_path",
    artifact_raw_output_path_by_id[criterion_bitcoin_core_benchmark_id],
)
criterion_bitcoin_core_raw_output_sha256 = optional_manifest_binding(
    data,
    "criterion_bitcoin_core_raw_output_sha256",
    artifact_raw_output_sha256_by_id[criterion_bitcoin_core_benchmark_id],
)
require_hex(criterion_bitcoin_core_raw_output_sha256, 64, "criterion_bitcoin_core_raw_output_sha256")
if float(bitcoin_rs_elapsed_seconds) >= float(bitcoin_core_elapsed_seconds):
    die(
        "bitcoin-rs initial sync evidence must be faster than Bitcoin Core "
        f"for the same {block_count}-block IBD window"
    )
validate_electrum_rss_measurement(data, stop_height, stop_hash)

env = {
    "G14_COMMIT_SHA": bitcoin_rs_commit,
    "G14_MEASUREMENT_TARGET": "mainnet-ibd",
    "G14_STORAGE_BACKEND": storage_backend,
    "G14_INDEXES": indexes,
    "G14_REFERENCE_IMPL": "bitcoin-core",
    "G14_BENCH_TOOL": bench_tool,
    "G14_BLOCK_SIZE_BYTES": "4194304",
    "G14_ELECTRUM_SAMPLE_SIZE": "10000",
    "G14_IBD_START_HEIGHT": str(start_height),
    "G14_IBD_START_HASH": start_hash,
    "G14_IBD_STOP_HEIGHT": str(stop_height),
    "G14_IBD_STOP_HASH": stop_hash,
    "G14_BITCOIN_RS_IBD_BLOCKS": str(block_count),
    "G14_BITCOIN_CORE_IBD_BLOCKS": str(block_count),
    "G14_BITCOIN_RS_ELAPSED_SECONDS": bitcoin_rs_elapsed_seconds,
    "G14_BITCOIN_CORE_ELAPSED_SECONDS": bitcoin_core_elapsed_seconds,
    "G14_BITCOIN_RS_CRITERION_BENCHMARK_ID": criterion_bitcoin_rs_benchmark_id,
    "G14_BITCOIN_CORE_CRITERION_BENCHMARK_ID": criterion_bitcoin_core_benchmark_id,
    "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_PATH": criterion_bitcoin_rs_raw_output_path,
    "G14_BITCOIN_RS_CRITERION_RAW_OUTPUT_SHA256": criterion_bitcoin_rs_raw_output_sha256,
    "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_PATH": criterion_bitcoin_core_raw_output_path,
    "G14_BITCOIN_CORE_CRITERION_RAW_OUTPUT_SHA256": criterion_bitcoin_core_raw_output_sha256,
    "G14_BENCHMARK_RUN_ID": artifact_benchmark_run_id,
    "G14_BENCHMARK_HOST_ID": benchmark_host_id,
    "G14_BITCOIN_CORE_VERSION": require_text(data, "bitcoin_core_version"),
    "G14_BITCOIN_CORE_COMMIT": core_commit,
    "G14_BITCOIN_RS_COMMAND_SHA256": rs_command_sha256,
    "G14_BITCOIN_CORE_COMMAND_SHA256": core_command_sha256,
    "G14_BITCOIN_RS_CONFIG_SHA256": rs_config_sha256,
    "G14_BITCOIN_CORE_CONFIG_SHA256": core_config_sha256,
    "G14_BENCHMARK_ARTIFACT_SHA256": benchmark_artifact_sha256,
    "G14_UTXO_COMMIT_P95_MS": require_number(data, "utxo_commit_p95_ms"),
    "G14_ELECTRUM_GET_HISTORY_P95_MS": require_number(data, "electrum_get_history_p95_ms"),
    "G14_RSS_BYTES": str(require_int(data, "rss_bytes", positive=True)),
    "G14_ELECTRUM_RSS_MEASUREMENT_PATH": require_text(data, "electrum_rss_measurement_path"),
    "G14_ELECTRUM_RSS_MEASUREMENT_SHA256": require_hex(
        require_text(data, "electrum_rss_measurement_sha256"),
        64,
        "electrum_rss_measurement_sha256",
    ),
    "G14_ELECTRUM_RSS_MEASUREMENT_SCHEMA": require_literal_value(
        data,
        "electrum_rss_measurement_schema",
        ELECTRUM_RSS_MEASUREMENT_SCHEMA,
    ),
    "G14_ELECTRUM_RSS_MEASUREMENT_SAMPLE_SIZE": str(
        require_exact_int(data, "electrum_rss_measurement_sample_size", ELECTRUM_SAMPLE_SIZE, "evidence JSON")
    ),
    "G14_ELECTRUM_RSS_MEASUREMENT_NON_EMPTY_HISTORY_COUNT": str(
        require_exact_int(
            data,
            "electrum_rss_measurement_non_empty_history_count",
            ELECTRUM_SAMPLE_SIZE,
            "evidence JSON",
        )
    ),
    "G14_ELECTRUM_RSS_MEASUREMENT_TIP_HEIGHT": str(
        require_exact_int(data, "electrum_rss_measurement_tip_height", stop_height, "evidence JSON")
    ),
    "G14_ELECTRUM_RSS_MEASUREMENT_TIP_HASH": require_hex_field(
        data,
        "electrum_rss_measurement_tip_hash",
        64,
        "evidence JSON",
    ),
    "G14_ELECTRUM_SCRIPTHASH_CORPUS": require_text(data, "electrum_scripthash_corpus"),
    "G14_ELECTRUM_SCRIPTHASH_CORPUS_SHA256": require_hex_field(
        data,
        "electrum_scripthash_corpus_sha256",
        64,
        "evidence JSON",
    ),
}

for key, value in env.items():
    print(f"export {key}={shlex.quote(value)}")
PY
