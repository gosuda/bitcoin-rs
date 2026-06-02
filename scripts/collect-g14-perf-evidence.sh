#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: collect-g14-perf-evidence.sh <evidence.json> [-- <bitcoin-cli-arg>...]' \
    '' \
    'Normalizes externally measured G14 mainnet IBD evidence into shell exports.' \
    'The helper does not start or manage bitcoin-rs, bitcoind, or Electrum.' \
    'It calls bitcoin-cli getblockhash for the measured start/stop heights.' \
    '' \
    'Required JSON keys:' \
    '  ibd_start_height, ibd_stop_height,' \
    '  bitcoin_rs_elapsed_seconds, bitcoin_core_elapsed_seconds,' \
    '  bitcoin_core_version, bitcoin_core_commit,' \
    '  bitcoin_rs_command, bitcoin_core_command,' \
    '  bitcoin_rs_config, bitcoin_core_config,' \
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

start_hash="$("$bitcoin_cli" "${bitcoin_cli_args[@]}" getblockhash "$start_height")"
stop_hash="$("$bitcoin_cli" "${bitcoin_cli_args[@]}" getblockhash "$stop_height")"

G14_START_HASH="$start_hash" G14_STOP_HASH="$stop_hash" python3 - "$evidence_path" <<'PY'
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
core_commit = require_hex(require_text(data, "bitcoin_core_commit"), 40, "bitcoin_core_commit")
rs_command = require_text(data, "bitcoin_rs_command")
core_command = require_text(data, "bitcoin_core_command")
rs_config = require_text(data, "bitcoin_rs_config")
core_config = require_text(data, "bitcoin_core_config")
block_count = stop_height - start_height + 1

env = {
    "G14_COMMIT_SHA": current_head(),
    "G14_MEASUREMENT_TARGET": "mainnet-ibd",
    "G14_STORAGE_BACKEND": "rocksdb",
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
    "G14_BITCOIN_RS_ELAPSED_SECONDS": require_number(data, "bitcoin_rs_elapsed_seconds"),
    "G14_BITCOIN_CORE_ELAPSED_SECONDS": require_number(data, "bitcoin_core_elapsed_seconds"),
    "G14_BITCOIN_CORE_VERSION": require_text(data, "bitcoin_core_version"),
    "G14_BITCOIN_CORE_COMMIT": core_commit,
    "G14_BITCOIN_RS_COMMAND_SHA256": sha256_text(rs_command),
    "G14_BITCOIN_CORE_COMMAND_SHA256": sha256_text(core_command),
    "G14_BITCOIN_RS_CONFIG_SHA256": sha256_text(rs_config),
    "G14_BITCOIN_CORE_CONFIG_SHA256": sha256_text(core_config),
    "G14_UTXO_COMMIT_P95_MS": require_number(data, "utxo_commit_p95_ms"),
    "G14_ELECTRUM_GET_HISTORY_P95_MS": require_number(data, "electrum_get_history_p95_ms"),
    "G14_RSS_BYTES": str(require_int(data, "rss_bytes", positive=True)),
}

for key, value in env.items():
    print(f"export {key}={shlex.quote(value)}")
PY
