#!/usr/bin/env bash
# Single owner of the pull-request gate commands.
#
# The CI jobs (.github/workflows/ci.yml), the pre-commit hooks, and
# CONTRIBUTING.md invoke this script. Do not restate these commands anywhere
# else: the copies drift (the pre-commit config kept referencing the removed
# mdbx backend after its deletion).
#
# Compile and test profiles are kernel-free and need no CMake or Boost. The
# deny profile selects `kernel` only for metadata resolution; cargo-deny does
# not compile that graph.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: $0 {fmt|clippy|test|deny|all}" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage

# Profiles run independently: one failing profile must not hide the
# diagnostics of the profiles after it, matching the per-step conditions the
# workflow jobs used before the commands moved here.
failures=0

profile() {
  local label="$1"
  shift
  echo "==> ${label}"
  if "$@"; then
    echo "==> ok: ${label}"
  else
    echo "==> FAILED: ${label}" >&2
    failures=$((failures + 1))
  fi
}

finish() {
  if [[ ${failures} -gt 0 ]]; then
    echo "${failures} profile(s) failed" >&2
    exit 1
  fi
}

case "$1" in
  fmt)
    cargo fmt --all -- --check
    ;;

  clippy)
    # Three kernel-free all-target profiles; consensus and node have
    # kernel-enabled defaults, so they are checked separately without it.
    profile "clippy: workspace (kernel-free)" \
      cargo clippy --locked --workspace --all-targets \
        --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node \
        -- -D warnings
    profile "clippy: bitcoin-rs-consensus (native)" \
      cargo clippy --locked -p bitcoin-rs-consensus \
        --no-default-features --all-targets -- -D warnings
    profile "clippy: bitcoin-rs-node (fjall,zmq)" \
      cargo clippy --locked -p bitcoin-rs-node \
        --no-default-features --features fjall,zmq --all-targets -- -D warnings
    finish
    ;;

  test)
    # The node, binary, and workspace profiles expect the pinned Core and
    # Apalache fixtures: bash scripts/provision-ci-reference-fixtures.sh
    # Smaller profiles first; the long fixture-backed passes last.
    profile "test: bitcoin-rs-consensus (native)" \
      cargo test --locked -p bitcoin-rs-consensus --no-default-features --no-fail-fast
    profile "test: bitcoin-rs-node (fjall,zmq)" \
      cargo test --locked -p bitcoin-rs-node \
        --no-default-features --features fjall,zmq --no-fail-fast
    # Isolated so node's default zmq feature cannot unify this package on.
    profile "test: bitcoin-rs-rpc (no default features)" \
      cargo test --locked -p bitcoin-rs-rpc --no-default-features --no-fail-fast
    # The formal solver run lives in the operator-invoked model-check-manual
    # lane (K=128 needs ~30h+, measured); every CI lane skips it and runs
    # only the cheap pin tests.
    profile "test: bitcoin-rs binary (rocksdb,fjall,redb)" \
      cargo test --locked -p bitcoin-rs --no-fail-fast \
        --no-default-features --features "rocksdb,fjall,redb" \
        -- --exact --skip all_model_specs_check_with_apalache
    # Same skip for the workspace profile: no CI lane spends hours in the
    # model checker for unchanged inputs, properties, and bound.
    profile "test: workspace (kernel-free)" \
      cargo test --locked --workspace --no-fail-fast \
        --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node \
        -- --skip all_model_specs_check_with_apalache
    finish
    ;;

  deny)
    # Full dependency graph: every storage backend plus the kernel engine.
    # cargo-deny 0.20 takes the cargo metadata flags before the subcommand.
    cargo deny \
      --workspace --no-default-features --features "rocksdb,fjall,redb,kernel" \
      check
    ;;

  all)
    "$0" fmt || failures=$((failures + 1))
    "$0" clippy || failures=$((failures + 1))
    "$0" test || failures=$((failures + 1))
    "$0" deny || failures=$((failures + 1))
    finish
    ;;

  *)
    usage
    ;;
esac
