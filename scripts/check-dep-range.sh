#!/usr/bin/env bash
# Resolve the workspace against the declared dependency range, not the
# committed lockfile, and prove it still compiles.
#
#   scripts/check-dep-range.sh minimal
#     cargo +nightly update -Zdirect-minimal-versions
#     then cargo +nightly check --workspace --all-targets --all-features
#
#   scripts/check-dep-range.sh maximum
#     cargo update (newest versions still inside the declared ranges)
#     then cargo check --workspace --all-targets
#
# Mutates Cargo.lock. CI checks out a throwaway tree. Locally, the original
# lockfile is restored on exit unless KEEP_LOCK=1.
#
# Owner: docs/contracts/dependency-range.md (DEP-01).

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
if [[ "${KEEP_LOCK:-0}" != "1" && -f "${LOCK}" ]]; then
  BACKUP="$(mktemp "${TMPDIR:-/tmp}/Cargo.lock.XXXXXX")"
  cp -- "${LOCK}" "${BACKUP}"
  trap restore_lock EXIT
fi

log() { printf '[dep-range %s] %s\n' "${RANGE}" "$*"; }

# Library defaults include kernel, so --workspace --all-targets builds
# libbitcoinkernel. Callers that need that path must install cmake and
# libboost-dev first; this script does not.
case "${RANGE}" in
  minimal)
    log "resolving direct dependencies at their oldest allowed versions"
    cargo +nightly update -Zdirect-minimal-versions
    log "checking the resolved minimal graph"
    cargo +nightly check --workspace --all-targets --all-features
    ;;
  maximum)
    log "resolving every crate to the newest version inside its declared range"
    cargo update
    log "checking the resolved maximum graph"
    cargo check --workspace --all-targets
    ;;
esac

log "ok"
