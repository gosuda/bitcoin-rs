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
    '  bitcoin_core_version, bitcoin_core_commit,' \
    '  bitcoin_rs_command, bitcoin_core_command,' \
    '  bitcoin_rs_config, bitcoin_core_config,' \
    '  benchmark_artifact_sha256,' \
    '  utxo_commit_p95_ms, electrum_get_history_p95_ms, rss_bytes' \
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
import os
import re
import shlex
import subprocess
import sys

EVIDENCE_HELP = "collect-g14-perf-evidence.sh requires the JSON keys listed in --help"


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


def require_text(data: dict, key: str) -> str:
    value = require_key(data, key)
    if not isinstance(value, str) or not value.strip():
        die(f"{key} must be a non-empty string")
    return value


def require_hex(value: str, length: int, name: str) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        die(f"{name} must be {length} lowercase hex characters")
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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
core_commit = require_hex(require_text(data, "bitcoin_core_commit"), 40, "bitcoin_core_commit")
rs_command = require_text(data, "bitcoin_rs_command")
core_command = require_text(data, "bitcoin_core_command")
rs_config = require_text(data, "bitcoin_rs_config")
core_config = require_text(data, "bitcoin_core_config")
benchmark_artifact_sha256 = require_hex(
    require_text(data, "benchmark_artifact_sha256"),
    64,
    "benchmark_artifact_sha256",
)
block_count = stop_height - start_height + 1
bitcoin_rs_elapsed_seconds = require_number(data, "bitcoin_rs_elapsed_seconds")
bitcoin_core_elapsed_seconds = require_number(data, "bitcoin_core_elapsed_seconds")
if float(bitcoin_rs_elapsed_seconds) >= float(bitcoin_core_elapsed_seconds):
    die(
        "bitcoin-rs initial sync evidence must be faster than Bitcoin Core "
        f"for the same {block_count}-block IBD window"
    )

env = {
    "G14_COMMIT_SHA": current_head(),
    "G14_MEASUREMENT_TARGET": "mainnet-ibd",
    "G14_STORAGE_BACKEND": "fjall",
    "G14_INDEXES": "all",
    "G14_REFERENCE_IMPL": "bitcoin-core",
    "G14_BENCH_TOOL": "criterion",
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
    "G14_BITCOIN_CORE_VERSION": require_text(data, "bitcoin_core_version"),
    "G14_BITCOIN_CORE_COMMIT": core_commit,
    "G14_BITCOIN_RS_COMMAND_SHA256": sha256_text(rs_command),
    "G14_BITCOIN_CORE_COMMAND_SHA256": sha256_text(core_command),
    "G14_BITCOIN_RS_CONFIG_SHA256": sha256_text(rs_config),
    "G14_BITCOIN_CORE_CONFIG_SHA256": sha256_text(core_config),
    "G14_BENCHMARK_ARTIFACT_SHA256": benchmark_artifact_sha256,
    "G14_UTXO_COMMIT_P95_MS": require_number(data, "utxo_commit_p95_ms"),
    "G14_ELECTRUM_GET_HISTORY_P95_MS": require_number(data, "electrum_get_history_p95_ms"),
    "G14_RSS_BYTES": str(require_int(data, "rss_bytes", positive=True)),
}

for key, value in env.items():
    print(f"export {key}={shlex.quote(value)}")
PY
