#!/usr/bin/env bash
# Import fuzz seed corpora extracted from Bitcoin Core's test vectors
# (bitcoin/bitcoin, MIT) and btcd's testdata (btcsuite/btcd, ISC) into the
# bitcoin-rs cargo-fuzz targets, minimize them with cargo fuzz cmin, and
# record provenance in fuzz/CORPUS_PROVENANCE.md.
#
# Mapping owner: fuzz/CORPUS_PROVENANCE.md (docs/contracts/qa-corpus.md,
# clause QAC-01). This script never duplicates the per-target mapping; the
# importer (import_reference_corpora.py) owns how each upstream file is
# transformed, while the provenance document owns which upstream corpora
# feed which target and why. Update that document, not this script, when
# the mapping changes.
#
# Disk discipline: sparse, blob-filtered, pinned clones land under TMPDIR;
# free space is verified to cover footprint + reserve BEFORE cloning; the
# clones are deleted after cmin — only minimized corpora under fuzz/corpus/
# are kept.
#
# Usage: scripts/import-reference-corpora.sh   (run from the repository root)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
readonly REPO_ROOT
# shellcheck source=scripts/fuzz-policy.sh
source "$(dirname "$0")/fuzz-policy.sh"
readonly BITCOIN_URL="https://github.com/bitcoin/bitcoin.git"
readonly BTCD_URL="https://github.com/btcsuite/btcd.git"
readonly FOOTPRINT_ASSUME_MB=1024  # worst-case sparse-clone footprint
readonly RESERVE_MB=1024           # free-space reserve on top of the footprint

# cargo env hygiene for this repo: fuzzing needs nightly
# for -Zsanitizer, and an explicit host triple because cargo-fuzz 0.13
# defaults to the musl target.
# The rustup shims must precede any direct toolchain bin directory on PATH
# for RUSTUP_TOOLCHAIN to select nightly.
CARGO_ENV=(env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR \
    PATH="${HOME}/.cargo/bin:${PATH}" RUSTUP_TOOLCHAIN=nightly)
HOST_TRIPLE="$("${CARGO_ENV[@]}" rustc -vV | sed -n 's/^host: //p')"
readonly HOST_TRIPLE

log() { printf '[import-reference] %s\n' "$*"; }

# --- 0. Required tools (QAC-03: verify before any staging or acquisition) ----
for tool in git python3; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        log "ABORT: required tool not found: ${tool}"
        exit 1
    fi
done
if ! "${CARGO_ENV[@]}" cargo fuzz --version >/dev/null 2>&1; then
    log "ABORT: cargo-fuzz unavailable (cargo fuzz --version failed)"
    exit 1
fi

# Seed corpora live in gosuda/bitcoin-rs-fuzz-corpus; FUZZ_CORPUS_DIR points
# at its `corpus/` directory (default: a sibling checkout named
# bitcoin-rs-fuzz-corpus, matching fuzz/README.md's local-campaign layout).
OUT_BASE="${FUZZ_CORPUS_DIR:-${REPO_ROOT}/../bitcoin-rs-fuzz-corpus/corpus}"
if [[ ! -d "${OUT_BASE}" ]]; then
    log "ERROR: corpus directory ${OUT_BASE} is missing; clone \
gosuda/bitcoin-rs-fuzz-corpus beside this checkout or set FUZZ_CORPUS_DIR"
    exit 1
fi
OUT_BASE="$(cd "${OUT_BASE}" && pwd -P)"
readonly OUT_BASE

# --- 1. Disk discipline: declare footprint, verify free space ---------------
available_mb() {
    local available
    available="$(df -Pm "$1" | awk 'NR == 2 { print $4 }')" || return
    # A failed numeric comparison is not proof that there is enough space.
    if [[ ! "${available}" =~ ^[0-9]+$ ]] || ! [ "${available}" -ge 0 ] 2>/dev/null; then
        log "ABORT: invalid available-space result for $1" >&2
        return 1
    fi
    printf '%s\n' "${available}"
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/reference-corpora.XXXXXX")"
readonly WORKDIR
PROVENANCE_TMP=""
STAGED_DIRS=()
cleanup() {
    if [[ -n "${PROVENANCE_TMP}" ]]; then
        rm -f -- "${PROVENANCE_TMP}"
    fi
    for dir in "${STAGED_DIRS[@]:-}"; do
        rm -rf -- "${dir}"
    done
    rm -rf -- "${WORKDIR:?workdir unset}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

FREE_TMP_MB="$(available_mb "${WORKDIR}")"
FREE_REPO_MB="$(available_mb "${REPO_ROOT:?repo root unset}")"
readonly FREE_TMP_MB FREE_REPO_MB
readonly NEEDED_MB=$((FOOTPRINT_ASSUME_MB + RESERVE_MB))
readonly NEEDED_REPO_MB=256
if [ "${FREE_TMP_MB:?free space unknown}" -lt "${NEEDED_MB}" ] ||
    [ "${FREE_REPO_MB:?free space unknown}" -lt "${NEEDED_REPO_MB}" ]; then
    log "ABORT: free ${FREE_TMP_MB} MiB (tmp) / ${FREE_REPO_MB} MiB (repo) < needed ${NEEDED_MB} / ${NEEDED_REPO_MB} MiB (footprint ${FOOTPRINT_ASSUME_MB} + reserve ${RESERVE_MB})"
    exit 1
fi
log "disk ok: ${FREE_TMP_MB} MiB free for the clones (>= ${NEEDED_MB} MiB), ${FREE_REPO_MB} MiB free on repo (>= ${NEEDED_REPO_MB} MiB)"
# The corpus volume may differ from the repo filesystem; a full volume must
# stop the import before publication touches prior seeds.
FREE_CORPUS_MB="$(available_mb "${OUT_BASE}")"
readonly FREE_CORPUS_MB
if [ "${FREE_CORPUS_MB:?free space unknown}" -lt "${NEEDED_REPO_MB}" ]; then
    log "ABORT: free ${FREE_CORPUS_MB} MiB on corpus volume < needed ${NEEDED_REPO_MB} MiB"
    exit 1
fi

# --- 2. Clone pinned to the provenance commits -------------------------------
# CORPUS_PROVENANCE.md records these exact commits; a rerun must reproduce
# that corpus, not silently follow the moving default branches. Sparse
# checkouts keep only the data directories the importer reads.
readonly BITCOIN_PIN="9dfde64cc3262329051fd05fffe40eecc786a99f"
readonly BTCD_PIN="b48125d0a3565b1441522ee10422f7815db03216"

clone_sparse() {
    local url="$1" pin="$2" dir="$3"
    shift 3
    log "cloning ${url} at pin ${pin}"
    git init --quiet "${dir}"
    git -C "${dir}" remote add origin "${url}"
    git -C "${dir}" sparse-checkout init --cone
    git -C "${dir}" sparse-checkout set "$@"
    git -C "${dir}" fetch --depth 1 --filter=blob:none --quiet origin "${pin}"
    git -C "${dir}" checkout --quiet FETCH_HEAD
    local fetched
    fetched="$(git -C "${dir}" rev-parse HEAD)"
    if [ "${fetched}" != "${pin}" ]; then
        log "ABORT: ${dir##*/} fetched ${fetched}, expected pin ${pin}"
        exit 1
    fi
}

clone_sparse "${BITCOIN_URL}" "${BITCOIN_PIN}" "${WORKDIR}/bitcoin" \
    src/test/data
clone_sparse "${BTCD_URL}" "${BTCD_PIN}" "${WORKDIR}/btcd" \
    txscript/data blockchain/testdata wire
BITCOIN_SIZE_MB="$(du -sm "${WORKDIR}/bitcoin" | cut -f1)"
BTCD_SIZE_MB="$(du -sm "${WORKDIR}/btcd" | cut -f1)"
readonly BITCOIN_SIZE_MB BTCD_SIZE_MB
log "clones at pins (${BITCOIN_SIZE_MB} / ${BTCD_SIZE_MB} MiB actual)"

readonly FUZZ_DIR="${REPO_ROOT}/fuzz"

# --- 3. Transform and publish bounded seeds ---------------------------------
# One mapper owns framing and atomic publication for all targets. Failures in
# file enumeration, reads, or publication stop before cmin or provenance.
"${CARGO_ENV[@]}" python3 "${REPO_ROOT}/scripts/import_reference_corpora.py" \
    --btcd "${WORKDIR}/btcd" --bitcoin "${WORKDIR}/bitcoin" \
    --repo-root "${REPO_ROOT}" \
    --out-base "${OUT_BASE}" --max-seed-bytes "${FUZZ_MAX_SEED_BYTES}"

# --- 4. Minimize each target corpus with cargo fuzz cmin ---------------------
# cargo-fuzz only operates on fuzz/corpus/<target> and replaces that path
# atomically, so the external corpus is staged as a real directory: cmin
# minimizes it, and the result publishes back to ${OUT_BASE}. A pre-existing
# entry aborts rather than clobbering a user-managed corpus.
for target in p2p_message block_validate tx_validate script_eval utxo_snapshot; do
    staged="${FUZZ_DIR}/corpus/${target}"
    if [[ -e "${staged}" ]]; then
        log "ERROR: ${staged} already exists; move it aside before running the importer"
        exit 1
    fi
    mkdir -p "${OUT_BASE}/${target}" "${staged}"
    cp -a "${OUT_BASE}/${target}/." "${staged}/"
    STAGED_DIRS+=("${staged}")
done
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" p2p_message
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" block_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" tx_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" script_eval
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" utxo_snapshot
# Publish the minimized sets back: seeds the minimizer dropped are removed
# from the external corpus (names are flat basenames).
for target in p2p_message block_validate tx_validate script_eval utxo_snapshot; do
    staged="${FUZZ_DIR}/corpus/${target}"
    for old in "${OUT_BASE}/${target}"/*; do
        [ -e "${old}" ] || continue
        [[ -e "${staged}/${old##*/}" ]] || rm -f -- "${old}"
    done
    cp -a "${staged}/." "${OUT_BASE}/${target}/"
done

# --- 5. Provenance ------------------------------------------------------------
readonly PROVENANCE="${FUZZ_DIR}/CORPUS_PROVENANCE.md"
IMPORT_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly IMPORT_DATE
# The generated section is appended after the authored Mapping section; a
# rerun refreshes only this section and carries everything above verbatim.
if [ ! -f "${PROVENANCE}" ] || ! grep -q -- '^## Reference corpora$' "${PROVENANCE}"; then
    log "ERROR: ${PROVENANCE} missing or has no '## Reference corpora' section; refusing to overwrite provenance"
    exit 1
fi
PROVENANCE_TMP="$(mktemp "${FUZZ_DIR}/.corpus-provenance.XXXXXX")"
sed -n '1,/^## Reference corpora$/p' -- "${PROVENANCE}" | sed '$d' > "${PROVENANCE_TMP}"
cat >> "${PROVENANCE_TMP}" <<EOF
## Reference corpora

Generated by scripts/import-reference-corpora.sh; refreshed on each run.
Authored content lives above this heading.

| Field | bitcoin/bitcoin | btcsuite/btcd |
|---|---|---|
| Upstream commit | @@BITCOIN_COMMIT@@ | @@BTCD_COMMIT@@ |
| Import date | @@IMPORT_DATE@@ | @@IMPORT_DATE@@ |
| License | MIT | ISC |
| Import tool | scripts/import-reference-corpora.sh + scripts/import_reference_corpora.py | (same) |
| Size policy | rows and payloads larger than ${FUZZ_MAX_SEED_BYTES} bytes are skipped or truncated and counted in the import log; witness stacks longer than the harness cap and framed elements over the u16 bound are skipped, never truncated |

EOF

python3 - "${PROVENANCE_TMP}" "${BITCOIN_PIN}" "${BTCD_PIN}" "${IMPORT_DATE}" <<'PYEOF'
import sys

path, bitcoin, btcd, date = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(path, encoding="utf-8") as f:
    text = f.read()
text = text.replace("@@BITCOIN_COMMIT@@", bitcoin)
text = text.replace("@@BTCD_COMMIT@@", btcd)
text = text.replace("@@IMPORT_DATE@@", date)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PYEOF
chmod 0644 -- "${PROVENANCE_TMP}"
mv -T -- "${PROVENANCE_TMP}" "${PROVENANCE}"
PROVENANCE_TMP=""
log "provenance written to ${PROVENANCE}"

# --- 6. Delete the clones (only minimized corpora are kept) -------------------
log "import complete; clones removed by cleanup trap"
