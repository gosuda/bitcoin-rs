#!/usr/bin/env bash
set -euo pipefail

heights=(0 1 170 91722 91812 91842 91880 173818 363731 481823 481824 624455 709632 800000 880000)
out_dir="crates/primitives/tests/testdata"
mkdir -p "${out_dir}"

for height in "${heights[@]}"; do
  hash="$(curl -fsSL "https://blockstream.info/api/block-height/${height}")"
  bin_path="${out_dir}/${height}.bin"
  txids_path="${out_dir}/${height}.txids.txt"

  if [[ ! -f "${bin_path}" ]]; then
    curl -fsSL "https://blockstream.info/api/block/${hash}/raw" > "${bin_path}"
  fi

  if [[ ! -f "${txids_path}" ]]; then
    curl -fsSL "https://blockstream.info/api/block/${hash}/txids" \
      | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)))' \
      > "${txids_path}"
    printf '\n' >> "${txids_path}"
  fi

done
