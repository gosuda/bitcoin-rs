#!/usr/bin/env bash
# Extract the Rust owners of the hand-written Lean reference functions with
# Charon and Aeneas. Without --check the output replaces docs/lean/Extracted/.
# With --check the output is written to a temporary directory and compared.
#
# Tool selection: CHARON_BIN (default: charon on PATH) and AENEAS_BIN
# (default: aeneas on PATH). Both tools come from the Aeneas nightly pinned in
# docs/contracts/formal-verification.md.
set -euo pipefail
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
cleanup() {
  if [ -n "${OUT_TEMPORARY:-}" ] && [ -d "${OUT_TEMPORARY:-}" ]; then
    rm -rf -- "${OUT_TEMPORARY:?temporary extraction directory}"
  fi
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CHARON=${CHARON_BIN:-charon}
AENEAS=${AENEAS_BIN:-aeneas}
WORK=${EXTRACT_WORKDIR:-"$ROOT/target/aeneas"}
CHECK=0
for argument in "$@"; do
  case "$argument" in
    --check) CHECK=1 ;;
    *) echo "unknown argument: $argument" >&2; exit 64 ;;
  esac
done

for tool in "$CHARON" "$AENEAS"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing tool: $tool (set CHARON_BIN/AENEAS_BIN)" >&2
    exit 71
  fi
done

if [ "$CHECK" -eq 1 ]; then
  OUT=$(mktemp -d)
  OUT_TEMPORARY=$OUT
else
  OUT="$ROOT/docs/lean/Extracted"
  if [ -d "$OUT" ]; then
    rm -rf -- "${OUT:?extraction output directory}"
  fi
fi
mkdir -p "$OUT" "$WORK"

# crate directory and the item paths whose Rust definitions the Lean files
# restate. Extend this table when a new owner module gains a reference
# function.
STATUS=()

extract() {
  local crate=$1
  shift
  local starts=()
  local item
  for item in "$@"; do
    starts+=(--start-from-if-exists "$item")
  done
  local dest="$WORK/$crate"
  mkdir -p "$dest"
  if ! (env -C "$ROOT/crates/$crate" "$CHARON" cargo --preset=aeneas --dest "$dest" \
      "${starts[@]}"); then
    STATUS+=("$crate charon failed")
    return 0
  fi
  local llbc="$dest/$crate.llbc"
  if [ ! -f "$llbc" ]; then
    llbc=$(find "$dest" -name '*.llbc' -print -quit)
  fi
  if [ -z "${llbc:-}" ] || [ ! -f "$llbc" ]; then
    STATUS+=("$crate no-llbc")
    return 0
  fi
  local out="$OUT/$crate"
  mkdir -p "$out"
  if ! "$AENEAS" -backend lean -dest "$out" "$llbc"; then
    rm -rf -- "${out:?extraction output for $crate}"
    STATUS+=("$crate aeneas failed; no output kept")
    return 0
  fi
  if grep -r -q -E '\b(sorry|admit)\b' "$out"; then
    rm -rf -- "${out:?extraction output for $crate}"
    STATUS+=("$crate aeneas emitted sorry or admit; no output kept")
    return 0
  fi
  if ! grep -r -q -E '^(noncomputable )?def ' "$out"; then
    rm -rf -- "${out:?extraction output for $crate}"
    STATUS+=("$crate no translated definitions; no output kept")
    return 0
  fi
  STATUS+=("$crate extracted")
}

extract primitives layout::decode_reservation varint::encode varint::decode \
  crate::layout::decode_reservation crate::varint::encode crate::varint::decode
extract utxo compress::compress_amount compress::decompress_amount \
  crate::compress::compress_amount crate::compress::decompress_amount
extract mempool crate::fee_diagram::FeeWeight::rate_cmp \
  fee_diagram::FeeWeight::rate_cmp

{
  printf 'charon=%s\n' "$("$CHARON" version)"
  printf 'aeneas=%s\n' "$("$AENEAS" -version)"
  printf '%s\n' "${STATUS[@]}"
} > "$OUT/status.txt"

if [ "$CHECK" -eq 1 ]; then
  if ! diff -r "$ROOT/docs/lean/Extracted" "$OUT" >/dev/null 2>&1; then
    echo "docs/lean/Extracted is stale; rerun scripts/extract_lean.sh" >&2
    exit 65
  fi
  echo "docs/lean/Extracted is current."
else
  echo "wrote $OUT"
fi
