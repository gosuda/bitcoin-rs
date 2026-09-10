#!/usr/bin/env bash
set -euo pipefail

heights=(0 1 170 91722 91812 91842 91880 173818 363731 481823 481824 624455 709632 800000 880000)
out_dir="crates/primitives/tests/testdata"
mkdir -p "${out_dir}"

# Stage on the destination filesystem so a failed transfer cannot become a cache hit.
tmp_dir=""
trap 'if [[ -n "${tmp_dir}" ]]; then rm -rf -- "${tmp_dir}"; fi' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for height in "${heights[@]}"; do
  bin_path="${out_dir}/${height}.bin"
  txids_path="${out_dir}/${height}.txids.txt"
  wtxids_path="${out_dir}/${height}.wtxids.txt"
  for cache_path in "${bin_path}" "${txids_path}" "${wtxids_path}"; do
    if [[ -L "${cache_path}" || ( -e "${cache_path}" && ! -f "${cache_path}" ) ]]; then
      printf 'Not a regular fixture file: %s\n' "${cache_path}" >&2
      exit 1
    fi
  done
  if [[ -s "${bin_path}" && -s "${txids_path}" && -s "${wtxids_path}" ]]; then
    continue
  fi

  hash="$(curl -fsSL "https://blockstream.info/api/block-height/${height}")"
  if [[ ! "${hash}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    printf 'Invalid block hash for height %s\n' "${height}" >&2
    exit 1
  fi

  if [[ -z "${tmp_dir}" ]]; then
    tmp_dir="$(mktemp -d "${out_dir}/.fetch-golden.XXXXXX")"
  fi

  if [[ ! -s "${bin_path}" ]]; then
    curl -fsSL "https://blockstream.info/api/block/${hash}/raw" > "${tmp_dir}/block.bin"
    if [[ ! -s "${tmp_dir}/block.bin" ]]; then
      printf 'Empty block response for height %s\n' "${height}" >&2
      exit 1
    fi
    mv -- "${tmp_dir}/block.bin" "${bin_path}"
  fi

  if [[ ! -s "${txids_path}" ]]; then
    curl -fsSL "https://blockstream.info/api/block/${hash}/txids" \
      | python3 -c '
import json
import re
import sys

txids = json.load(sys.stdin)
if not isinstance(txids, list) or not txids or any(
    not isinstance(txid, str) or re.fullmatch(r"[0-9a-fA-F]{64}", txid) is None
    for txid in txids
):
    sys.exit("Expected a non-empty array of 64-character hexadecimal txids")
print("\n".join(txids))
' > "${tmp_dir}/txids.txt"
    mv -- "${tmp_dir}/txids.txt" "${txids_path}"
  fi

  if [[ ! -s "${wtxids_path}" ]]; then
    # BIP141 wtxids, derived independently of the Rust codec: the wtxid of a
    # transaction is the double SHA-256 of its complete serialization, so the
    # only parsing needed is the transaction boundary walk over the already
    # fetched raw block.
    python3 - "${bin_path}" << 'PYEOF' > "${tmp_dir}/wtxids.txt"
import hashlib
import sys

data = open(sys.argv[1], "rb").read()
pos = 80  # header


def varint(pos):
    prefix = data[pos]
    if prefix < 0xFD:
        return prefix, pos + 1
    if prefix == 0xFD:
        return int.from_bytes(data[pos + 1:pos + 3], "little"), pos + 3
    if prefix == 0xFE:
        return int.from_bytes(data[pos + 1:pos + 5], "little"), pos + 5
    return int.from_bytes(data[pos + 1:pos + 9], "little"), pos + 9


count, pos = varint(pos)
for _ in range(count):
    start = pos
    pos += 4  # version
    marker = data[pos]
    if marker == 0:
        pos += 2  # BIP144 marker || flag
    inputs, pos = varint(pos)
    for _ in range(inputs):
        pos += 36
        script_len, pos = varint(pos)
        pos += script_len + 4
    outputs, pos = varint(pos)
    for _ in range(outputs):
        pos += 8
        script_len, pos = varint(pos)
        pos += script_len
    if marker == 0:
        for _ in range(inputs):
            stack_items, pos = varint(pos)
            for _ in range(stack_items):
                item_len, pos = varint(pos)
                pos += item_len
    pos += 4  # lock time
    tx = data[start:pos]
    digest = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    # RPC display order is big-endian; sha256d is little-endian.
    print(digest[::-1].hex())
PYEOF
    if [[ ! -s "${tmp_dir}/wtxids.txt" ]]; then
      printf 'Empty wtxid derivation for height %s\n' "${height}" >&2
      exit 1
    fi
    mv -- "${tmp_dir}/wtxids.txt" "${wtxids_path}"
  fi
done
