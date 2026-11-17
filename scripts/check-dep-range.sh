#!/usr/bin/env bash
# Resolve the workspace against the declared dependency range, not the
# committed lockfile, and prove it still compiles.
#
#   scripts/check-dep-range.sh minimal
#     cargo +nightly update -Zdirect-minimal-versions
#     then cargo +nightly check --workspace --all-targets --all-features
#     then cargo deny check bans (cargo-deny must be installed)
#
#   scripts/check-dep-range.sh maximum
#     cargo update (newest versions still inside the declared ranges)
#     then cargo check --workspace --all-targets
#     then cargo deny check bans (cargo-deny must be installed)
#
# Mutates Cargo.lock. CI checks out a throwaway tree. Locally, the original
# lockfile is restored on exit unless KEEP_LOCK=1.
#
# The minimal endpoint uses --all-features so the resolved oldest versions
# are also checked with every optional feature enabled. The maximum endpoint
# checks the default feature set plus one explicit kernel-enabled check so
# the optional C++ engine still sees its newest allowed versions; the named
# feature matrix is owned by FEAT-01 / scripts/check-feature-matrix.sh.
# The minimal endpoint uses --all-features and the maximum endpoint checks
# the kernel engine; kernel build dependencies need cmake and libboost-dev at build
# time. See CONTRIBUTING.md, Prerequisites.
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

# The minimal lane's --all-features and the maximum lane's explicit kernel
# check build libbitcoinkernel. Callers that need those paths must install
# cmake and libboost-dev first; this script does not.
case "${RANGE}" in
  minimal)
    log "resolving direct dependencies at their oldest allowed versions"
    "${CARGO[@]}" update -Zdirect-minimal-versions
    log "checking the resolved minimal graph with all features"
    "${CARGO[@]}" check --workspace --all-targets --all-features
    ;;
  maximum)
    log "resolving every crate to the newest version inside its declared range"
    "${CARGO[@]}" update
    log "checking the resolved maximum graph"
    "${CARGO[@]}" check --workspace --all-targets
    # The default feature set no longer compiles the kernel engine, so check
    # it explicitly against the resolved maximum graph; -p propagates the
    # feature through node's forwarding chain to consensus.
    log "checking the kernel engine against the resolved maximum graph"
    "${CARGO[@]}" check -p bitcoin-rs-node --all-targets --features kernel
    ;;
esac

# The existing cargo-deny policy owns uniqueness for the resolved graph.
log "cargo deny check bans on the resolved graph"
cargo deny check bans

log "ok"
