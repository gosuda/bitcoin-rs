#!/usr/bin/env bash
# Owner of the pull-request required gate. CI jobs and CONTRIBUTING.md invoke
# this script; do not duplicate the commands in workflow YAML.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: $0 {fmt|clippy|test|deny|all}" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage

case "$1" in
  fmt)
    cargo fmt --all -- --check
    ;;
  clippy)
    cargo clippy --workspace --all-targets \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node \
      -- -D warnings
    cargo clippy -p bitcoin-rs-consensus \
      --no-default-features --all-targets -- -D warnings
    cargo clippy -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq --all-targets -- -D warnings
    ;;
  test)
    cargo test --workspace --no-fail-fast \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node
    cargo test -p bitcoin-rs-consensus --no-default-features --no-fail-fast
    cargo test -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq --no-fail-fast
    ;;
  deny)
    cargo deny check --workspace --no-default-features \
      --features rocksdb,fjall,redb,mdbx,kernel
    ;;
  all)
    "$0" fmt
    "$0" clippy
    "$0" test
    "$0" deny
    ;;
  *)
    usage
    ;;
esac
