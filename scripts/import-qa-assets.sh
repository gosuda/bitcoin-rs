#!/usr/bin/env bash
# Import fuzz seed corpora from rust-bitcoin/qa-assets (CC0-1.0) into the
# bitcoin-rs cargo-fuzz targets, minimize them with cargo fuzz cmin, and
# record provenance in fuzz/CORPUS_PROVENANCE.md.
#
# Mapping owner: fuzz/CORPUS_PROVENANCE.md (docs/contracts/qa-corpus.md,
# clause QAC-01). This script never duplicates the per-target mapping; the
# importer (import_qa_assets.py) owns how each upstream corpus directory is
# transformed, while the provenance document owns which upstream corpora feed
# which target and why. Update that document, not this script, when the
# mapping changes.
#
# Disk discipline (repo AGENTS.md): the worst-case footprint of the clone is
# declared below (shallow clone ~= corpus size, assumed <= 2 GiB); free space
# is verified to cover footprint + reserve BEFORE cloning; the clone is
# deleted after cmin — only minimized corpora under fuzz/corpus/ are kept.
#
# Usage: scripts/import-qa-assets.sh   (run from the repository root)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
readonly REPO_ROOT
# shellcheck source=scripts/fuzz-policy.sh
source "$(dirname "$0")/fuzz-policy.sh"
readonly QA_ASSETS_URL="https://github.com/rust-bitcoin/qa-assets.git"
readonly FOOTPRINT_ASSUME_MB=2048  # worst-case shallow-clone footprint
readonly RESERVE_MB=1024           # free-space reserve on top of the footprint

# cargo env hygiene for this repo (see repo AGENTS.md); fuzzing needs nightly
# for -Zsanitizer, and an explicit host triple because cargo-fuzz 0.13
# defaults to the musl target.
HOST_TRIPLE="$(rustc +nightly -vV | sed -n 's/^host: //p')"
readonly HOST_TRIPLE
CARGO_ENV=(env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR RUSTUP_TOOLCHAIN=nightly)

log() { printf '[import-qa-assets] %s\n' "$*"; }

# --- 1. Disk discipline: declare footprint, verify free space ---------------
# The clone lands under TMPDIR and the minimized corpora under fuzz/corpus/;
# both filesystems must cover their share of footprint + reserve.
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

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/qa-assets.XXXXXX")"
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
# bitcoin_arbitrary_* corpora hold arbitrary::Unstructured byte streams, not
# consensus-serialized objects; every target here consumes consensus bytes, so
# upstream ships them unused. Log them to keep the exclusion explicit.
for arbitrary_dir in "${CORPORA}"/bitcoin_arbitrary_*; do
    [ -d "${arbitrary_dir}" ] || continue
    log "excluding ${arbitrary_dir##*/}: Unstructured bytes, not consensus-serialized (see fuzz/CORPUS_PROVENANCE.md)"
done
"${CARGO_ENV[@]}" python3 "${REPO_ROOT}/scripts/import_qa_assets.py" \
    --corpora "${CORPORA}" --repo-root "${REPO_ROOT}" \
    --out-base "${OUT_BASE}" --max-seed-bytes "${FUZZ_MAX_SEED_BYTES}"

# --- 4. Minimize each target corpus with cargo fuzz cmin ---------------------
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" p2p_message
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" block_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" tx_validate
"${CARGO_ENV[@]}" cargo fuzz cmin --target "${HOST_TRIPLE}" script_eval

# --- 5. Provenance ------------------------------------------------------------
readonly PROVENANCE="${FUZZ_DIR}/CORPUS_PROVENANCE.md"
IMPORT_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly IMPORT_DATE
# Stage beside the destination: failed writes leave the previous record intact.
# The Mapping section stays owned by fuzz/CORPUS_PROVENANCE.md; the generated
# record refreshes only run-dependent fields, preserving authored rows.
PROVENANCE_TMP="$(mktemp "${FUZZ_DIR}/.corpus-provenance.XXXXXX")"
cat > "${PROVENANCE_TMP}" <<EOF
# Fuzz corpus provenance

Seeds under fuzz/corpus/ were imported from
[rust-bitcoin/qa-assets](https://github.com/rust-bitcoin/qa-assets), license
[CC0-1.0](https://github.com/rust-bitcoin/qa-assets/blob/master/LICENSE)
(public domain; no attribution required, recorded here for provenance).

| Field | Value |
|---|---|
| Upstream commit | @@UPSTREAM_COMMIT@@ |
| Import date | @@IMPORT_DATE@@ |
| License | CC0-1.0 |
| Import tool | scripts/import-qa-assets.sh (clone pinned to the commit above, then cargo fuzz cmin per target) |
| Size policy | source files >= ${FUZZ_MAX_SEED_BYTES} bytes are skipped and counted in the import log (repo-size bound matching the targets' input caps) |

EOF

# Carried forward: the authored Mapping section (and the footer that follows
# it) stays owned by the checked-in CORPUS_PROVENANCE.md; a rerun refreshes
# only the run-dependent fields above.
if [ ! -f "${PROVENANCE}" ] || ! grep -q -- '^## Mapping$' "${PROVENANCE}"; then
    rm -f -- "${PROVENANCE_TMP}"
    PROVENANCE_TMP=""
    log "ERROR: ${PROVENANCE} missing or has no '## Mapping' section; refusing to overwrite provenance"
    exit 1
fi
sed -n '/^## Mapping$/,$p' -- "${PROVENANCE}" >> "${PROVENANCE_TMP}"

# Fill the run-dependent fields from this import.
python3 - "${PROVENANCE_TMP}" "${UPSTREAM_COMMIT}" "${IMPORT_DATE}" <<'PYEOF'
import sys

path, commit, date = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as f:
    text = f.read()
for field, value in (("| Upstream commit |", commit), ("| Import date |", date)):
    start = text.index(field)
    end = text.index("\n", start)
    text = text[:start] + f"{field} {value} |" + text[end:]
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PYEOF
chmod 0644 -- "${PROVENANCE_TMP}"
mv -T -- "${PROVENANCE_TMP}" "${PROVENANCE}"
PROVENANCE_TMP=""
log "provenance written to ${PROVENANCE}"

# --- 6. Delete the clone (only minimized corpora are kept) --------------------
log "import complete; clone removed by cleanup trap"
