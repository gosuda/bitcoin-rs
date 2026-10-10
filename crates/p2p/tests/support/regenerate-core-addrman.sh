#!/usr/bin/env bash
# Optional Linux reference-fixture reproduction; never run by normal CI.
set -euo pipefail
core_root=$(realpath "${1:?usage: regenerate-core-addrman.sh CORE_SOURCE OUTPUT_DIRECTORY}")
mkdir -p "${2:?supply a disposable output directory}"
oracle_output=$(realpath "$2")
support_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $(uname -s) == Linux ]] || { echo 'These recorded feature flags are Linux-specific.' >&2; exit 1; }
[[ $(git -C "$core_root" rev-parse HEAD) == 9be056a8a72b624dae9623b2f7bded92c2a21c91 ]] || { echo 'Wrong Core reference revision.' >&2; exit 1; }
git -C "$core_root" diff --exit-code HEAD -- src cmake/bitcoin-build-config.h.in
cmake -DCORE_ROOT="$core_root" -DORACLE_OUTPUT="$oracle_output" -P "$support_dir/core-addrman-configure.cmake"
common=(-std=c++20 -O1 -g0 -ffunction-sections -fdata-sections -I"$oracle_output/src" -I"$core_root/src")
base=(addrman.cpp netaddress.cpp netgroup.cpp util/asmap.cpp crypto/sha256.cpp crypto/sha3.cpp util/strencodings.cpp)
extra=(random.cpp crypto/chacha20.cpp crypto/sha512.cpp logging.cpp util/time.cpp util/check.cpp clientversion.cpp uint256.cpp util/threadnames.cpp support/cleanse.cpp crypto/siphash.cpp support/lockedpool.cpp randomenv.cpp util/fs.cpp)
args=()
for source in "${base[@]}"; do args+=("$core_root/src/$source"); done
for driver in core-addrman-driver core-addrman-health-driver core-addrman-ring-driver core-addrman-asmap-driver; do
  "${CXX:-g++}" "${common[@]}" "$support_dir/$driver.cpp" "${args[@]}" -Wl,--gc-sections -o "$oracle_output/$driver"
done
for source in "${extra[@]}"; do args+=("$core_root/src/$source"); done
"${CXX:-g++}" "${common[@]}" "$support_dir/core-addrman-addsingle-driver.cpp" "${args[@]}" -Wl,--gc-sections -o "$oracle_output/core-addrman-addsingle-driver"
"$oracle_output/core-addrman-driver" > "$oracle_output/placement.tsv"
"$oracle_output/core-addrman-health-driver" > "$oracle_output/health.jsonl"
"$oracle_output/core-addrman-ring-driver" > "$oracle_output/ring.tsv"
"$oracle_output/core-addrman-addsingle-driver" > "$oracle_output/addsingle.jsonl"
"$oracle_output/core-addrman-asmap-driver" "$core_root/src/test/data/asmap.raw" "$support_dir/../data/asmap-core-v31.1.raw" "$support_dir/../data/asmap-linked-ipv4-core-v31.1.raw" "$support_dir/../data/asmap-source-quota-core-v31.1.raw" > "$oracle_output/asmap.tsv"
sha256sum "$oracle_output"/core-addrman*-driver "$oracle_output/src/bitcoin-build-config.h"
