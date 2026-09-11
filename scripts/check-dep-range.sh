#!/usr/bin/env bash
# Resolve the workspace against the declared dependency range, not the
# committed lockfile, and prove it still compiles and keeps one copy of
# each consensus-stack crate.
#
#   scripts/check-dep-range.sh minimal
#     cargo +nightly update -Zdirect-minimal-versions
#     then cargo +nightly check --workspace --all-targets
#     then G20 (+ cargo deny check bans when cargo-deny is on PATH)
#
#   scripts/check-dep-range.sh maximum
#     cargo update (newest versions still inside the declared ranges)
#     then cargo check --workspace --all-targets
#     then G20 (+ cargo deny check bans when cargo-deny is on PATH)
#
# Mutates Cargo.lock. CI checks out a throwaway tree. Locally, the original
# lockfile is restored on exit unless KEEP_LOCK=1.
#
# Optional native storage engines (rocksdb, mdbx) and the named feature
# matrix are owned by FEAT-01 / scripts/check-feature-matrix.sh, not this
# script: DEP-01 proves the default workspace graph at each range endpoint.
#
# Owner: docs/contracts/dependency-range.md (DEP-01, DEP-02).

set -euo pipefail

usage() {
  printf '%s\n' 'usage: scripts/check-dep-range.sh minimal|maximum'
}

RANGE=${1:-}
case "${RANGE}" in
  minimal|maximum) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

ROOT="$(git rev-parse --show-toplevel)"
cd "${ROOT}"

LOCK="${ROOT}/Cargo.lock"
BACKUP=""
restore_lock() {
  if [[ -n "${BACKUP}" && -f "${BACKUP}" && "${KEEP_LOCK:-0}" != "1" ]]; then
    mv -- "${BACKUP}" "${LOCK}"
  fi
}
if [[ "${KEEP_LOCK:-0}" != "1" ]]; then
  if [[ ! -f "${LOCK}" ]]; then
    printf '%s\n' "scripts/check-dep-range.sh: ${LOCK} is missing; refuse to generate a lockfile" >&2
    exit 1
  fi
  BACKUP="$(mktemp "${TMPDIR:-/tmp}/Cargo.lock.XXXXXX")"
  cp -- "${LOCK}" "${BACKUP}"
  trap restore_lock EXIT
fi

log() { printf '[dep-range %s] %s\n' "${RANGE}" "$*"; }

if [[ "${RANGE}" == "minimal" ]]; then
  CARGO=(cargo +nightly)
else
  CARGO=(cargo)
fi

# Library defaults include kernel, so --workspace --all-targets builds
# libbitcoinkernel. Callers that need that path must install cmake and
# libboost-dev first; this script does not.
case "${RANGE}" in
  minimal)
    log "resolving direct dependencies at their oldest allowed versions"
    "${CARGO[@]}" update -Zdirect-minimal-versions
    ;;
  maximum)
    log "resolving every crate to the newest version inside its declared range"
    "${CARGO[@]}" update
    ;;
esac

log "checking the resolved graph"
"${CARGO[@]}" check --workspace --all-targets

# G20 reads Cargo.lock via cargo metadata; it must run while the mutated
# lockfile is still in place.
log "G20 uniqueness on the resolved graph"
"${CARGO[@]}" test -p bitcoin-rs --test g20_unique_consensus_crates \
  --no-default-features --features fjall

if command -v cargo-deny >/dev/null 2>&1; then
  log "cargo deny check bans on the resolved graph"
  cargo deny check bans
else
  log "cargo-deny not on PATH; skip bans (CI installs it)"
fi

log "ok"
