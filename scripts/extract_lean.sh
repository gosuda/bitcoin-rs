#!/usr/bin/env bash
set -euo pipefail
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
cleanup() {
  while IFS= read -r pid; do
    if [ -n "$pid" ]; then
      kill -- "$pid" 2>/dev/null || true
    fi
  done < <(jobs -p 2>/dev/null || true)
  if [ -n "${OUT_TEMPORARY:-}" ] && [ -d "${OUT_TEMPORARY:-}" ]; then
    rm -rf -- "${OUT_TEMPORARY:?temporary extraction directory}"
  fi
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHARON=${CHARON_BIN:-charon}
AENEAS=${AENEAS_BIN:-aeneas}
WORK=${EXTRACT_WORKDIR:-"$ROOT/target/aeneas"}
REFERENCE=${EXTRACT_REFERENCE:-"$ROOT/docs/lean/Extracted"}
CHECK=0
for argument in "$@"; do
  case "$argument" in
    --check) CHECK=1 ;;
    *) printf 'unknown argument: %s\n' "$argument" >&2; exit 64 ;;
  esac
done

for tool in "$CHARON" "$AENEAS"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing tool: %s (set CHARON_BIN/AENEAS_BIN)\n' "$tool" >&2
    exit 71
  fi
done

if [ "$CHECK" -eq 1 ]; then
  OUT=$(mktemp -d)
  OUT_TEMPORARY=$OUT
else
  OUT="$REFERENCE"
  if [ -d "$OUT" ]; then
    rm -rf -- "${OUT:?extraction output directory}"
  fi
fi
mkdir -p "$OUT" "$WORK"

CRATES=()
declare -A TASK_ARGS=()

extract() {
  local crate=$1
  shift
  CRATES+=("$crate")
  TASK_ARGS["$crate"]="$*"
}

run_extract() {
  local crate=$1
  local starts=()
  local item
  local items_str="${TASK_ARGS["$crate"]:-}"
  local -a items=()
  if [ -n "$items_str" ]; then
    read -r -a items <<< "$items_str"
    for item in "${items[@]}"; do
      starts+=(--start-from-if-exists "$item")
    done
  fi
  local dest="$WORK/$crate"
  mkdir -p "$dest"
  rm -f -- "${dest:?work destination}/status" "${dest:?work destination}/extract.log"
  local crate_dir="$ROOT/crates/$crate"
  if [ ! -d "$crate_dir" ]; then
    crate_dir="$dest"
  fi
  local log="$dest/extract.log"
  if ! (env -C "$crate_dir" CARGO_TARGET_DIR="$dest/target" \
      "$CHARON" cargo --preset=aeneas --dest "$dest" "${starts[@]}" > "$log" 2>&1); then
    sed "s/^/[$crate] /" "$log" >&2 || true
    printf '%s charon failed\n' "$crate" > "$dest/status"
    return 0
  fi
  local llbc="$dest/$crate.llbc"
  if [ ! -f "$llbc" ]; then
    llbc=$(find "$dest" -name '*.llbc' -print -quit)
  fi
  if [ -z "${llbc:-}" ] || [ ! -f "$llbc" ]; then
    printf '%s no-llbc\n' "$crate" > "$dest/status"
    return 0
  fi
  local out="$OUT/$crate"
  mkdir -p "$out"
  if ! ("$AENEAS" -backend lean -dest "$out" "$llbc" > "$log" 2>&1); then
    sed "s/^/[$crate] /" "$log" >&2 || true
    rm -rf -- "${out:?extraction output for $crate}"
    printf '%s aeneas failed; no output kept\n' "$crate" > "$dest/status"
    return 0
  fi
  if grep -r -q -E '\b(sorry|admit)\b' "$out"; then
    rm -rf -- "${out:?extraction output for $crate}"
    printf '%s aeneas emitted sorry or admit; no output kept\n' "$crate" > "$dest/status"
    return 0
  fi
  if ! grep -r -q -E '^(noncomputable )?def ' "$out"; then
    rm -rf -- "${out:?extraction output for $crate}"
    printf '%s no translated definitions; no output kept\n' "$crate" > "$dest/status"
    return 0
  fi
  printf '%s extracted\n' "$crate" > "$dest/status"
}

if [ -n "${EXTRACT_CRATES:-}" ]; then
  read -r -a configured_crates <<< "$EXTRACT_CRATES"
  for crate in "${configured_crates[@]}"; do
    extract "$crate"
  done
else
  extract primitives layout::decode_reservation varint::encode varint::decode \
    crate::layout::decode_reservation crate::varint::encode crate::varint::decode
  extract utxo compress::compress_amount compress::decompress_amount \
    crate::compress::compress_amount crate::compress::decompress_amount
  extract mempool crate::fee_diagram::FeeWeight::rate_cmp \
    fee_diagram::FeeWeight::rate_cmp
fi

NPROC=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
CRATE_COUNT=${#CRATES[@]}
DEFAULT_JOBS=$(( NPROC < CRATE_COUNT ? NPROC : CRATE_COUNT ))
if [ "$DEFAULT_JOBS" -lt 1 ]; then
  DEFAULT_JOBS=1
fi
JOBS=${EXTRACT_JOBS:-$DEFAULT_JOBS}
if [ "$JOBS" -lt 1 ] 2>/dev/null; then
  JOBS=1
fi

for crate in "${CRATES[@]}"; do
  while [ "$(jobs -r -p | wc -l)" -ge "$JOBS" ]; do
    wait -n || true
  done
  (
    run_extract "$crate"
  ) &
done
wait

STATUS=()
for crate in "${CRATES[@]}"; do
  status_file="$WORK/$crate/status"
  if [ -f "$status_file" ]; then
    STATUS+=("$(cat "$status_file")")
  fi
done

{
  printf 'charon=%s\n' "$("$CHARON" version)"
  printf 'aeneas=%s\n' "$("$AENEAS" -version)"
  printf '%s\n' "${STATUS[@]}"
} > "$OUT/status.txt"

if [ "$CHECK" -eq 1 ]; then
  if ! diff -r "$REFERENCE" "$OUT" >/dev/null 2>&1; then
    printf 'docs/lean/Extracted is stale; rerun scripts/extract_lean.sh\n' >&2
    exit 65
  fi
  if grep -q -E 'emitted (sorry|admit)' "$OUT/status.txt" || \
     grep -r -q -E '\b(sorry|admit)\b' --exclude='status.txt' "$OUT" 2>/dev/null; then
    printf 'sorry or admit found in extraction output\n' >&2
    exit 66
  fi
  printf 'docs/lean/Extracted is current.\n'
else
  printf 'wrote %s\n' "$OUT"
fi
