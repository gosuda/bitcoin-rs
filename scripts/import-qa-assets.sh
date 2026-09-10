#!/usr/bin/env bash
# Import fuzz seed corpora from rust-bitcoin/qa-assets (CC0-1.0) into the
# bitcoin-rs cargo-fuzz targets, minimize them with cargo fuzz cmin, and
# record provenance in fuzz/CORPUS_PROVENANCE.md.
#
# Mapping (target <- qa-assets/fuzz_corpora):
#   p2p_message   <- p2p_deserialize_raw_net_msg  (reframed: strip the 24-byte
#                    envelope, map the command to the harness selector byte;
#                    the harness rebuilds magic/length/checksum itself)
#   block_decode  <- bitcoin_deserialize_block    (raw consensus bytes, direct)
#   tx_decode     <- bitcoin_deserialize_transaction (raw consensus bytes, direct)
#   script_eval   <- bitcoin_deserialize_script + bitcoin_script_bytes_to_asm_fmt
#                    (raw script bytes, wrapped into the script_eval framing:
#                    selector 0x00 = NONE, and for files >= 32 bytes a P2TR
#                    variant with selector 0x03 = TAPROOT)
#
# Disk discipline (repo AGENTS.md): the worst-case footprint of the clone is
# declared below (shallow clone ~= corpus size, assumed <= 2 GiB); free space
# is verified to cover footprint + reserve BEFORE cloning; the clone is
# deleted after cmin — only minimized corpora under fuzz/corpus/ are kept.
#
# Usage: scripts/import-qa-assets.sh   (run from the repository root)

set -euo pipefail

if ! REPO_ROOT="$(git rev-parse --show-toplevel)"; then
    exit 19
fi
readonly REPO_ROOT
readonly QA_ASSETS_URL="https://github.com/rust-bitcoin/qa-assets.git"
readonly FOOTPRINT_ASSUME_MB=2048  # worst-case shallow-clone footprint
readonly RESERVE_MB=1024           # free-space reserve on top of the footprint
readonly MAX_SEED_BYTES=65536      # keep individual seeds bounded

# cargo env hygiene for this repo (see repo AGENTS.md); fuzzing needs nightly
# for -Zsanitizer, and an explicit host triple because cargo-fuzz 0.13
# defaults to the musl target.
if ! HOST_TRIPLE="$(rustc +nightly -vV | sed -n 's/^host: //p')" || [ -z "${HOST_TRIPLE}" ]; then
    exit 17
fi
readonly HOST_TRIPLE
CARGO_ENV=(env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR RUSTUP_TOOLCHAIN=nightly)

log() { printf '[import-qa-assets] %s\n' "$*"; }

# --- 1. Disk discipline: declare footprint, verify free space ---------------
# The clone lands under TMPDIR and the minimized corpora under fuzz/corpus/;
# both filesystems must cover their share of footprint + reserve.
available_mb() { df -Pm "$1" | awk 'NR == 2 { print $4 }'; }

if ! WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/qa-assets.XXXXXX")"; then
    exit 23
fi
readonly WORKDIR
PROVENANCE_TMP=""
cleanup() {
    if [[ -n "${PROVENANCE_TMP}" ]]; then
        rm -f -- "${PROVENANCE_TMP}"
    fi
    rm -rf -- "${WORKDIR:?workdir unset}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! FREE_TMP_MB="$(available_mb "${WORKDIR}")" || [ -z "${FREE_TMP_MB}" ] ||
   ! FREE_REPO_MB="$(available_mb "${REPO_ROOT:?repo root unset}")" || [ -z "${FREE_REPO_MB}" ]; then
    exit 7
fi
readonly FREE_TMP_MB FREE_REPO_MB
readonly NEEDED_MB=$((FOOTPRINT_ASSUME_MB + RESERVE_MB))
readonly NEEDED_REPO_MB=256
if [ "${FREE_TMP_MB:?free space unknown}" -lt "${NEEDED_MB}" ] ||
    [ "${FREE_REPO_MB:?free space unknown}" -lt "${NEEDED_REPO_MB}" ]; then
    log "ABORT: free ${FREE_TMP_MB} MiB (tmp) / ${FREE_REPO_MB} MiB (repo) < needed ${NEEDED_MB} / ${NEEDED_REPO_MB} MiB (footprint ${FOOTPRINT_ASSUME_MB} + reserve ${RESERVE_MB})"
    exit 1
fi
log "disk ok: ${FREE_TMP_MB} MiB free for the clone (>= ${NEEDED_MB} MiB), ${FREE_REPO_MB} MiB free on repo (>= ${NEEDED_REPO_MB} MiB)"

# --- 2. Clone pinned to the provenance commit ---------------------------------
# CORPUS_PROVENANCE.md records this exact commit; a rerun must reproduce that
# corpus, not silently follow the moving default branch.
readonly QA_ASSETS_PIN="ffd27e4ee51266673859e3d1314369e780e26a4e"
log "cloning ${QA_ASSETS_URL} at pin ${QA_ASSETS_PIN}"
git init --quiet "${WORKDIR}/qa-assets"
git -C "${WORKDIR}/qa-assets" remote add origin "${QA_ASSETS_URL}"
git -C "${WORKDIR}/qa-assets" fetch --depth 1 --quiet origin "${QA_ASSETS_PIN}"
git -C "${WORKDIR}/qa-assets" checkout --quiet FETCH_HEAD
UPSTREAM_COMMIT="$(git -C "${WORKDIR}/qa-assets" rev-parse HEAD)"
readonly UPSTREAM_COMMIT
[ "${UPSTREAM_COMMIT}" = "${QA_ASSETS_PIN}" ] || {
    log "ABORT: fetched ${UPSTREAM_COMMIT}, expected pin ${QA_ASSETS_PIN}"
    exit 1
}
UPSTREAM_SIZE_MB="$(du -sm "${WORKDIR}/qa-assets" | cut -f1)"
readonly UPSTREAM_SIZE_MB
log "clone at ${UPSTREAM_COMMIT} (${UPSTREAM_SIZE_MB} MiB actual)"

readonly CORPORA="${WORKDIR}/qa-assets/fuzz_corpora"
readonly FUZZ_DIR="${REPO_ROOT}/fuzz"
readonly OUT_BASE="${FUZZ_DIR}/corpus"

# --- 3. Transform and publish bounded seeds ---------------------------------
# One mapper owns framing and atomic publication for all targets. Failures in
# directory enumeration, reads, or publication stop before cmin or provenance.
"${CARGO_ENV[@]}" python3 "${REPO_ROOT}/scripts/import_qa_assets.py" \
    --corpora "${CORPORA}" --repo-root "${REPO_ROOT}" \
    --out-base "${OUT_BASE}" --max-seed-bytes "${MAX_SEED_BYTES}"

# --- 4. Minimize each target corpus with cargo fuzz cmin ---------------------
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" p2p_message
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" block_decode
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" tx_decode
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" script_eval

# --- 5. Provenance ------------------------------------------------------------
readonly PROVENANCE="${FUZZ_DIR}/CORPUS_PROVENANCE.md"
IMPORT_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly IMPORT_DATE
# Stage beside the destination: failed writes leave the previous record intact.
PROVENANCE_TMP="$(mktemp "${FUZZ_DIR}/.corpus-provenance.XXXXXX")"
cat > "${PROVENANCE_TMP}" <<EOF
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
| p2p_message | fuzz_corpora/p2p_deserialize_raw_net_msg | 24-byte envelope stripped; header command mapped to the harness selector byte; payload bounded so the selector plus payload fits ${MAX_SEED_BYTES} bytes (harness rebuilds magic/length/checksum) |
| block_decode | fuzz_corpora/bitcoin_deserialize_block | direct copy (raw consensus bytes) |
| tx_decode | fuzz_corpora/bitcoin_deserialize_transaction | direct copy (raw consensus bytes) |
| script_eval | fuzz_corpora/bitcoin_deserialize_script, fuzz_corpora/bitcoin_script_bytes_to_asm_fmt | raw script bytes bounded by the harness ELEMENT_LEN_MAX and seed budget, then wrapped into the script_eval framing (selector 0x00 = NONE); files >= 32 bytes also emit a P2TR key-path variant (selector 0x03 = TAPROOT) |

Corpora were minimized with cargo fuzz cmin after import; only minimized
seeds are tracked here. Re-run the script after major decoder changes to
refresh.
EOF
chmod 0644 "${PROVENANCE_TMP}"
[[ ! -d "${PROVENANCE}" ]] || { echo "provenance destination is a directory" >&2; exit 1; }
mv "${PROVENANCE_TMP}" "${PROVENANCE}"
PROVENANCE_TMP=""
log "provenance written to ${PROVENANCE}"

# --- 6. Delete the clone (only minimized corpora are kept) --------------------
log "import complete; clone removed by cleanup trap"
