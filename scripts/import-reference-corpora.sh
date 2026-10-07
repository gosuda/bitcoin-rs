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
readonly OUT_BASE="${FUZZ_DIR}/corpus"

# --- 3. Transform and publish bounded seeds ---------------------------------
# One mapper owns framing and atomic publication for all targets. Failures in
# file enumeration, reads, or publication stop before cmin or provenance.
"${CARGO_ENV[@]}" python3 "${REPO_ROOT}/scripts/import_reference_corpora.py" \
    --btcd "${WORKDIR}/btcd" --bitcoin "${WORKDIR}/bitcoin" \
    --repo-root "${REPO_ROOT}" \
    --out-base "${OUT_BASE}" --max-seed-bytes "${FUZZ_MAX_SEED_BYTES}"

# --- 4. Minimize each target corpus with cargo fuzz cmin ---------------------
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" p2p_message
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" block_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" tx_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" script_eval
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" utxo_snapshot

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
| Size policy | rows and payloads larger than ${FUZZ_MAX_SEED_BYTES} bytes are skipped or truncated and counted in the import log; witness stacks longer than the harness cap are skipped |

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
