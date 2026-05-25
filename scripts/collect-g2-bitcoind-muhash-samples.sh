#!/usr/bin/env bash
set -euo pipefail

SAMPLE_INTERVAL=10000
MAX_U32=4294967295

usage() {
  printf '%s\n' \
    'usage: collect-g2-bitcoind-muhash-samples.sh [--print-heights] <tip-height> [-- <bitcoin-cli-arg>...]' \
    '' \
    'Collect Bitcoin Core G2 MuHash samples as:' \
    '  height:64-lowerhex[,height:64-lowerhex...]' \
    '' \
    'The helper does not start or manage bitcoind. It calls:' \
    '  bitcoin-cli gettxoutsetinfo "muhash" <height> true' \
    '' \
    'Specific-height queries require a Core node with coinstatsindex available.' \
    'Set BITCOIN_CLI=/path/to/bitcoin-cli to override the binary.' \
    '' \
    'Examples:' \
    '  bash scripts/collect-g2-bitcoind-muhash-samples.sh 880000 -- -datadir=/srv/bitcoin-mainnet' \
    '  G2_BITCOIND_MUHASH_SAMPLES="$(bash scripts/collect-g2-bitcoind-muhash-samples.sh 880000)"' \
    '  bash scripts/collect-g2-bitcoind-muhash-samples.sh --print-heights 20001'
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 2
}

validate_tip_height() {
  local raw="$1"
  [[ "$raw" =~ ^[0-9]+$ ]] || die 'tip height must be an unsigned decimal integer'
  if (( ${#raw} > 10 )) || { (( ${#raw} == 10 )) && [[ "$raw" > "$MAX_U32" ]]; }; then
    die "tip height must fit u32 for the G2 verifier: ${raw}"
  fi

  local normalized=$((10#${raw}))
  (( normalized > 0 )) || die 'tip height must be greater than zero'
  printf '%s\n' "$normalized"
}

required_heights() {
  local tip_height="$1"
  local height=0

  while true; do
    printf '%s\n' "$height"
    local next=$((height + SAMPLE_INTERVAL))
    if (( next > tip_height )); then
      break
    fi
    height="$next"
  done

  if (( height != tip_height )); then
    printf '%s\n' "$tip_height"
  fi
}

parse_sample() {
  local requested_height="$1"
  REQUESTED_HEIGHT="$requested_height" python3 -c '
import json
import os
import re
import sys

requested_height = int(os.environ["REQUESTED_HEIGHT"])
try:
    data = json.load(sys.stdin)
except Exception as error:
    raise SystemExit(f"invalid gettxoutsetinfo JSON for height {requested_height}: {error}") from error

height = data.get("height")
muhash = data.get("muhash")
if height != requested_height:
    raise SystemExit(f"gettxoutsetinfo returned height {height!r}, expected {requested_height}")
if not isinstance(muhash, str) or not re.fullmatch(r"[0-9a-f]{64}", muhash):
    raise SystemExit(f"gettxoutsetinfo height {requested_height} returned invalid muhash {muhash!r}")
print(f"{requested_height}:{muhash}")
'
}

print_heights=false
tip_height="${G2_TIP_HEIGHT:-}"
while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --print-heights)
      print_heights=true
      shift
      ;;
    --)
      shift
      break
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      [[ -z "$tip_height" ]] || die "unexpected argument: $1"
      tip_height="$1"
      shift
      ;;
  esac
done

[[ -n "$tip_height" ]] || die 'tip height is required as an argument or G2_TIP_HEIGHT'
tip_height="$(validate_tip_height "$tip_height")"

if [[ "$print_heights" == true ]]; then
  required_heights "$tip_height"
  exit 0
fi

bitcoin_cli="${BITCOIN_CLI:-bitcoin-cli}"
bitcoin_cli_args=("$@")
samples=()
while IFS= read -r height; do
  json="$("$bitcoin_cli" "${bitcoin_cli_args[@]}" gettxoutsetinfo "muhash" "$height" true)"
  sample="$(parse_sample "$height" <<<"$json")"
  samples+=("$sample")
done < <(required_heights "$tip_height")

(
  IFS=,
  printf '%s\n' "${samples[*]}"
)
