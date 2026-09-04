#!/usr/bin/env bash
# Import fuzz seed corpora from rust-bitcoin/qa-assets (CC0-1.0) into the
# bitcoin-rs cargo-fuzz targets, minimize them with cargo fuzz cmin, and
# record provenance in fuzz/CORPUS_PROVENANCE.md.
#
# Mapping (target <- qa-assets/fuzz_corpora):
#   p2p_message    <- p2p_deserialize_raw_net_msg  (reframed: strip the 24-byte
#                     envelope, map the command to the harness selector byte;
#                     the harness rebuilds magic/length/checksum itself)
#   block_validate <- bitcoin_deserialize_block + bitcoin_arbitrary_block
#                     (raw bytes; harness rust-bitcoin-deserializes, then runs
#                     bitcoin-rs verify_block_rules)
#   tx_validate    <- bitcoin_deserialize_transaction + bitcoin_deserialize_witness
#                     + bitcoin_arbitrary_transaction + bitcoin_arbitrary_witness
#                     (raw bytes; harness rust-bitcoin-deserializes, then runs
#                     native consensus + mempool check_acceptance)
#   script_eval    <- bitcoin_deserialize_script + bitcoin_script_bytes_to_asm_fmt
#                     (raw script bytes, wrapped into the script_eval framing:
#                     selector 0x00 = NONE, and for files >= 32 bytes a P2TR
#                     variant with selector 0x03 = TAPROOT)
#
# Do not import parser corpora into decode-only targets that only call
# rust-bitcoin. block_decode and tx_decode are gone.
#
# Disk discipline (repo AGENTS.md): the worst-case footprint of the clone is
# declared below (shallow clone ~= corpus size, assumed <= 2 GiB); free space
# is verified to cover footprint + reserve BEFORE cloning; the clone is
# deleted after cmin — only minimized corpora under fuzz/corpus/ are kept.
#
# Usage: scripts/import-qa-assets.sh   (run from the repository root)

set -euo pipefail

readonly REPO_ROOT="$(git rev-parse --show-toplevel)"
readonly QA_ASSETS_URL="https://github.com/rust-bitcoin/qa-assets.git"
readonly FOOTPRINT_ASSUME_MB=2048  # worst-case shallow-clone footprint
readonly RESERVE_MB=1024           # free-space reserve on top of the footprint
readonly MAX_SEED_BYTES=65536      # keep individual seeds bounded

# cargo env hygiene for this repo (see repo AGENTS.md); fuzzing needs nightly
# for -Zsanitizer, and an explicit host triple because cargo-fuzz 0.13
# defaults to the musl target.
readonly HOST_TRIPLE="$(rustc +nightly -vV | sed -n 's/^host: //p')"
CARGO_ENV=(env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR RUSTUP_TOOLCHAIN=nightly)

log() { printf '[import-qa-assets] %s\n' "$*"; }

# --- 1. Disk discipline: declare footprint, verify free space ---------------
# The clone lands under TMPDIR and the minimized corpora under fuzz/corpus/;
# both filesystems must cover their share of footprint + reserve.
available_mb() { df -Pm "$1" | awk 'NR == 2 { print $4 }'; }

readonly WORKDIR="$(mktemp -d /tmp/qa-assets.XXXXXX)"
readonly FREE_TMP_MB="$(available_mb "${WORKDIR}")"
readonly FREE_REPO_MB="$(available_mb "${REPO_ROOT:?repo root unset}")"
readonly NEEDED_MB=$((FOOTPRINT_ASSUME_MB + RESERVE_MB))
readonly NEEDED_REPO_MB=256
if [ "${FREE_TMP_MB:?free space unknown}" -lt "${NEEDED_MB}" ] ||
    [ "${FREE_REPO_MB:?free space unknown}" -lt "${NEEDED_REPO_MB}" ]; then
    log "ABORT: free ${FREE_TMP_MB} MiB (tmp) / ${FREE_REPO_MB} MiB (repo) < needed ${NEEDED_MB} / ${NEEDED_REPO_MB} MiB (footprint ${FOOTPRINT_ASSUME_MB} + reserve ${RESERVE_MB})"
    exit 1
fi
log "disk ok: ${FREE_TMP_MB} MiB free for the clone (>= ${NEEDED_MB} MiB), ${FREE_REPO_MB} MiB free on repo (>= ${NEEDED_REPO_MB} MiB)"

cleanup() { rm -rf -- "${WORKDIR:?workdir unset}"; }
trap cleanup EXIT

# --- 2. Clone pinned to the provenance commit ---------------------------------
# CORPUS_PROVENANCE.md records this exact commit; a rerun must reproduce that
# corpus, not silently follow the moving default branch.
readonly QA_ASSETS_PIN="ffd27e4ee51266673859e3d1314369e780e26a4e"
log "cloning ${QA_ASSETS_URL} at pin ${QA_ASSETS_PIN}"
git init --quiet "${WORKDIR}/qa-assets"
git -C "${WORKDIR}/qa-assets" remote add origin "${QA_ASSETS_URL}"
git -C "${WORKDIR}/qa-assets" fetch --depth 1 --quiet origin "${QA_ASSETS_PIN}"
git -C "${WORKDIR}/qa-assets" checkout --quiet FETCH_HEAD
readonly UPSTREAM_COMMIT="$(git -C "${WORKDIR}/qa-assets" rev-parse HEAD)"
[ "${UPSTREAM_COMMIT}" = "${QA_ASSETS_PIN}" ] || {
    log "ABORT: fetched ${UPSTREAM_COMMIT}, expected pin ${QA_ASSETS_PIN}"
    exit 1
}
readonly UPSTREAM_SIZE_MB="$(du -sm "${WORKDIR}/qa-assets" | cut -f1)"
log "clone at ${UPSTREAM_COMMIT} (${UPSTREAM_SIZE_MB} MiB actual)"

readonly CORPORA="${WORKDIR}/qa-assets/fuzz_corpora"
readonly FUZZ_DIR="${REPO_ROOT}/fuzz"
readonly OUT_BASE="${FUZZ_DIR}/corpus"

# --- 3. p2p_message: reframe raw network messages ----------------------------
# The harness input is [selector][payload]; it derives the envelope itself.
# Extract the command from the corpus file 24-byte header and map it to the
# selector index used by fuzz/fuzz_targets/p2p_message.rs COMMANDS (single
# source of truth: the array is parsed out of the target source).
map_p2p() {
    "${CARGO_ENV[@]}" python3 - "${CORPORA}/p2p_deserialize_raw_net_msg" \
        "${FUZZ_DIR}/fuzz_targets/p2p_message.rs" "${OUT_BASE}/p2p_message" \
        "${MAX_SEED_BYTES}" <<'PYEOF'
import hashlib
import re
import sys
from pathlib import Path

corpus_dir, target_src, out_dir, max_bytes = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
commands = re.findall(r'"([a-z0-9]+)"', target_src.read_text().split("COMMANDS", 1)[1].split("];", 1)[0])
selector = {name: bytes([idx]) for idx, name in enumerate(commands)}

out_dir.mkdir(parents=True, exist_ok=True)
imported = skipped_short = unknown_cmd = 0
for path in sorted(corpus_dir.iterdir()):
    blob = path.read_bytes()
    if len(blob) <= 24:
        skipped_short += 1
        continue
    command = blob[4:16].split(b"\0", 1)[0]
    sel = selector.get(command.decode("ascii", "replace"))
    if sel is None:
        unknown_cmd += 1
        continue
    payload = blob[24:][:max_bytes]
    seed = sel + payload
    (out_dir / hashlib.sha256(seed).hexdigest()[:32]).write_bytes(seed)
    imported += 1
print(f"p2p_message: imported={imported} skipped_short={skipped_short} unknown_command={unknown_cmd}")
PYEOF
}

# --- 4. script_eval: wrap raw script bytes into the harness framing ----------
map_script() {
    "${CARGO_ENV[@]}" python3 - "${CORPORA}/bitcoin_deserialize_script" \
        "${CORPORA}/bitcoin_script_bytes_to_asm_fmt" "${OUT_BASE}/script_eval" \
        "${MAX_SEED_BYTES}" <<'PYEOF'
import hashlib
import sys
from pathlib import Path

dirs = [Path(sys.argv[1]), Path(sys.argv[2])]
out_dir, max_bytes = Path(sys.argv[3]), int(sys.argv[4])
NONE, TAPROOT = b"\x00", b"\x03"  # FLAGS indices in fuzz_targets/script_eval.rs

out_dir.mkdir(parents=True, exist_ok=True)

def emit(seed: bytes) -> None:
    (out_dir / hashlib.sha256(seed).hexdigest()[:32]).write_bytes(seed)

def frame(selector: bytes, script_sig: bytes, script_pubkey: bytes, witness: list[bytes]) -> bytes:
    parts = [selector, len(script_sig).to_bytes(2, "little"), script_sig,
             len(script_pubkey).to_bytes(2, "little"), script_pubkey, bytes([len(witness)])]
    parts += [len(e).to_bytes(2, "little") + e for e in witness]
    return b"".join(parts)

imported = 0
for corpus_dir in dirs:
    for path in sorted(corpus_dir.iterdir()):
        script = path.read_bytes()[:max_bytes]
        emit(frame(NONE, b"", script, []))  # raw scriptPubKey
        if len(script) >= 32:               # P2TR key-path variant
            emit(frame(TAPROOT, b"", b"\x51\x20" + script[:32], [script[32:1024]]))
        imported += 1
print(f"script_eval: imported={imported} files (raw + P2TR variants)")
PYEOF
}

# --- 5. Direct byte-for-byte mappings into validation targets ----------------
# Seeds >= MAX_SEED_BYTES are skipped by policy (repo-size bound, matching the
# fuzz targets' own input caps) and the skip count is recorded so the mapping
# stays honest about what it left behind.
# Parser-only rust-bitcoin corpora are imported here because the harnesses
# deserialize with rust-bitcoin and then run bitcoin-rs consensus/mempool.
map_direct() {
    local src="$1" dst="$2" name="$3"
    mkdir -p "${dst:?}"
    local count=0 skipped=0
    if [ ! -d "${src:?}" ]; then
        log "${name}: skipped missing source ${src}"
        return
    fi
    while IFS= read -r -d '' file; do
        if [ "$(stat -c %s -- "${file:?}")" -ge "${MAX_SEED_BYTES}" ]; then
            skipped=$((skipped + 1))
            continue
        fi
        cp -- "${file:?}" "${dst}/$(basename -- "${file:?}")"
        count=$((count + 1))
    done < <(find "${src:?}" -maxdepth 1 -type f -print0 | sort -z)
    log "${name}: imported=${count} skipped_oversize=${skipped} (>= ${MAX_SEED_BYTES} bytes)"
}
map_p2p
map_script
map_direct "${CORPORA}/bitcoin_deserialize_block" "${OUT_BASE}/block_validate" block_validate/deserialize
map_direct "${CORPORA}/bitcoin_deserialize_transaction" "${OUT_BASE}/tx_validate" tx_validate/deserialize
map_direct "${CORPORA}/bitcoin_deserialize_witness" "${OUT_BASE}/tx_validate" tx_validate/witness

# --- 6. Minimize each target corpus with cargo fuzz cmin ---------------------
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" p2p_message
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" block_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" tx_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" script_eval

# --- 7. Provenance ------------------------------------------------------------
readonly PROVENANCE="${FUZZ_DIR}/CORPUS_PROVENANCE.md"
readonly IMPORT_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "${PROVENANCE}" <<EOF
# Fuzz corpus provenance

Seeds under fuzz/corpus/ were imported from
[rust-bitcoin/qa-assets](https://github.com/rust-bitcoin/qa-assets), license
[CC0-1.0](https://github.com/rust-bitcoin/qa-assets/blob/master/LICENSE)
(public domain; no attribution required, recorded here for provenance).

| Field | Value |
|---|---|
| Upstream commit | ${UPSTREAM_COMMIT} |
| Import date | ${IMPORT_DATE} |
| License | CC0-1.0 |
| Import tool | scripts/import-qa-assets.sh (shallow clone, then cargo fuzz cmin per target) |

## Mapping

| Target | Upstream corpus | Transformation |
|---|---|---|
| p2p_message | fuzz_corpora/p2p_deserialize_raw_net_msg | 24-byte envelope stripped; header command mapped to the harness selector byte; payload kept as-is (harness rebuilds magic/length/checksum) |
| block_validate | fuzz_corpora/bitcoin_deserialize_block, fuzz_corpora/bitcoin_arbitrary_block | raw bytes; rust-bitcoin deserializes, then bitcoin-rs `verify_block_rules` |
| tx_validate | fuzz_corpora/bitcoin_deserialize_transaction, fuzz_corpora/bitcoin_deserialize_witness, fuzz_corpora/bitcoin_arbitrary_transaction, fuzz_corpora/bitcoin_arbitrary_witness | raw bytes; rust-bitcoin deserializes, then bitcoin-rs consensus + mempool `check_acceptance` |
| script_eval | fuzz_corpora/bitcoin_deserialize_script, fuzz_corpora/bitcoin_script_bytes_to_asm_fmt | raw script bytes wrapped into the script_eval framing (selector 0x00 = NONE); files >= 32 bytes also emit a P2TR key-path variant (selector 0x03 = TAPROOT) |

Corpora were minimized with cargo fuzz cmin after import; only minimized
seeds are tracked here. Re-run the script after major decoder changes to
refresh.
EOF
log "provenance written to ${PROVENANCE}"

# --- 8. Delete the clone (only minimized corpora are kept) --------------------
log "import complete; clone removed by cleanup trap"
