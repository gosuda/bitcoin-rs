#!/usr/bin/env bash
# Gate commands shared by CI, pre-commit, and CONTRIBUTING.md.
# PR lanes fail fast; deep collects every failure. Build/test lanes are
# kernel-free; deny resolves the kernel graph without compiling it.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: $0 {fmt|clippy|test-crates|test-binary|test-workspace|test|deny|deep|all}" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage

failures=0
collect_failures=false

profile() {
  local label="$1"
  shift
  echo "==> ${label}"
  if "$@"; then
    echo "==> ok: ${label}"
  else
    echo "==> FAILED: ${label}" >&2
    failures=$((failures + 1))
    [[ "$collect_failures" == true ]] || exit 1
  fi
}

finish() {
  if [[ ${failures} -gt 0 ]]; then
    echo "${failures} profile(s) failed" >&2
    exit 1
  fi
}

# CI test lanes install cargo-nextest (.github/workflows/ci.yml,
# .github/actions/test-deps): its pooled scheduler runs test binaries
# concurrently instead of serially, which removes the long tail of
# process-harness binaries on the 4-vCPU runners. There are no doctests in
# the tree, so the two runners execute the same tests. Environments without
# nextest (local, pre-commit) fall back to `cargo test --no-fail-fast`.
cargo_test() {
  if command -v cargo-nextest >/dev/null 2>&1; then
    cargo nextest run --locked --no-fail-fast "$@"
  else
    cargo test --locked --no-fail-fast "$@"
  fi
}

clippy_profiles() {
  # Four kernel-free all-target profiles. The kernel capability is opt-in and
  # never implied by a default, so these lanes exercise the plain builds. The
  # explicit `--no-default-features` spellings keep the per-crate rows'
  # feature sets pinned even if a default changes again; the workspace row
  # builds with default features by design (it is the "plain build works"
  # row).
  profile "clippy: workspace (kernel-free)" \
    cargo clippy --locked --workspace --all-targets \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-chainstate \
      --exclude bitcoin-rs-node \
      -- -D warnings
  profile "clippy: bitcoin-rs-consensus (native)" \
    cargo clippy --locked -p bitcoin-rs-consensus \
      --no-default-features --all-targets -- -D warnings
  profile "clippy: bitcoin-rs-chainstate (native,fjall)" \
    cargo clippy --locked -p bitcoin-rs-chainstate \
      --no-default-features --features fjall --all-targets -- -D warnings
  profile "clippy: bitcoin-rs-node (fjall,zmq)" \
    cargo clippy --locked -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq --all-targets -- -D warnings
}

test_crates_profiles() {
  # Fixture-free per-crate profiles; only the binary's tests read the pinned
  # Core fixture. Smallest first.
  profile "test: bitcoin-rs-consensus (native)" \
    cargo_test -p bitcoin-rs-consensus --no-default-features
  profile "test: bitcoin-rs-chainstate (native,fjall)" \
    cargo_test -p bitcoin-rs-chainstate \
      --no-default-features --features fjall
  profile "test: bitcoin-rs-node (fjall,zmq)" \
    cargo_test -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq
  # Isolated so node's default zmq feature cannot unify this package on.
  profile "test: bitcoin-rs-rpc (no default features)" \
    cargo_test -p bitcoin-rs-rpc --no-default-features
}

test_binary_profiles() {
  # Requires the pinned Core fixture. Formal checks have their own workflow.
  profile "test: bitcoin-rs binary (rocksdb,fjall,redb)" \
    cargo_test -p bitcoin-rs \
      --no-default-features --features "rocksdb,fjall,redb"
}

test_workspace_profiles() {
  # Also expects the pinned fixtures: bin/bitcoin-rs is a workspace member,
  # so this profile runs its default-feature (fjall,redb,zmq) test binaries,
  # including the process-harness suite that launches the pinned bitcoind.
  profile "test: workspace (kernel-free)" \
    cargo_test --workspace \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-chainstate \
      --exclude bitcoin-rs-node
}

case "$1" in
  fmt)
    cargo fmt --all -- --check
    ;;

  clippy)
    clippy_profiles
    ;;

  test-crates)
    test_crates_profiles
    ;;

  test-binary)
    test_binary_profiles
    ;;

  test-workspace)
    test_workspace_profiles
    ;;

  test)
    # Local composition of every test lane, smallest first. CI runs the
    # lanes as parallel jobs (.github/workflows/ci.yml); this subcommand
    # stays the full sequential gate for pre-commit and local use.
    "$0" test-crates
    "$0" test-binary
    "$0" test-workspace
    ;;

  deny)
    # Full dependency graph: every storage backend plus the kernel engine.
    # cargo-deny 0.20 takes the cargo metadata flags before the subcommand.
    cargo deny \
      --workspace --no-default-features --features "rocksdb,fjall,redb,kernel" \
      check
    ;;

  deep)
    collect_failures=true
    clippy_profiles
    test_crates_profiles
    test_binary_profiles
    test_workspace_profiles
    finish
    ;;

  all)
    "$0" fmt || failures=$((failures + 1))
    "$0" deep || failures=$((failures + 1))
    "$0" deny || failures=$((failures + 1))
    finish
    ;;

  *)
    usage
    ;;
esac
