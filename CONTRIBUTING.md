# Contributing to bitcoin-rs

Thank you for contributing to `bitcoin-rs`. This guide outlines the development
workflow, coding standards, and verification commands used across the project.

## Prerequisites

- Use the current stable Rust toolchain (Rust 2024 edition).
- Install C/C++ build tools for native dependencies such as ZeroMQ. The default
  binary excludes `libbitcoinkernel`, but this does not make every dependency
  Rust-only.
- Kernel-enabled checks additionally require CMake and Boost headers
  (`cmake` and `libboost-dev` on Debian/Ubuntu). The consensus and node library
  crates enable `kernel` by default; the binary does not. The exact defaults
  are owned by the [validation-default contract](docs/contracts/validation-default.md).
- The PR comparator tests use Python 3.13. Fuzzing and dependency/feature
  matrix checks also need the tools described in the main workflow below.

From the repository root, install and select stable:

```sh
rustup toolchain install stable --component rustfmt --component clippy
rustup override set stable
cargo install --locked cargo-deny
```

[`rust-toolchain.toml`](rust-toolchain.toml), CI, pre-commit hooks, and the
local commands above all select stable. Explicit `+nightly` commands below are
limited to checks that require nightly Rust.

Start with the affected package or test while developing, then run the
applicable CI checks before submitting. The workflow files define the complete
job set.

## Pull-request verification

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs for pull requests
against any base branch, including stacked PRs, and for pushes to `main`.
Its ordinary lint and test passes exclude the default-kernel library crates
from the workspace invocation and check them separately without kernel:

```sh
# Format check
cargo fmt --all -- --check

# Clippy on all targets, with kernel disabled
cargo clippy --workspace --all-targets \
  --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node -- -D warnings
cargo clippy -p bitcoin-rs-consensus \
  --no-default-features --all-targets -- -D warnings
cargo clippy -p bitcoin-rs-node \
  --no-default-features --features fjall,zmq --all-targets -- -D warnings

# Workspace unit and integration tests, with kernel disabled
cargo test --workspace --no-fail-fast \
  --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node
cargo test -p bitcoin-rs-consensus --no-default-features --no-fail-fast
cargo test -p bitcoin-rs-node \
  --no-default-features --features fjall,zmq --no-fail-fast

# Run separately so another package cannot enable RPC's zmq feature
cargo test -p bitcoin-rs-rpc --no-default-features --no-fail-fast

# Binary tests with all retained storage backends, without kernel
cargo test -p bitcoin-rs --no-fail-fast \
  --no-default-features --features "rocksdb,fjall,redb"

# Audit the full dependency graph, including the optional kernel
cargo deny --workspace --no-default-features \
  --features "rocksdb,fjall,redb,kernel" check
```

Plain `cargo test --workspace` and `cargo clippy --workspace` also enable the
library defaults and therefore build the C++ kernel. Use the split commands
above to reproduce the PR lint/test feature selection.

The PR workflow also runs:

- `bench-smoke`: benchmark compilation, including a full-feature binary-package
  build with kernel. This job installs CMake and Boost; PR CI as a whole is not
  kernel-free. It also compiles the UTXO benches and the node's
  `chainstate_journal` benchmark.
- `comparator-tests`: every `test_*.py` in `tools/benchmark-campaign`, followed
  by `tools/campaign-corpus/test_corpus.py`, using Python 3.13. These test the
  comparator and corpus tooling without running a full-chain benchmark.

See the corresponding jobs in `ci.yml` for their complete commands. If you
use the [pre-commit configuration](.pre-commit-config.yaml), its full-node
hooks also enable kernel and require its build dependencies.

## Deep CI lanes (main workflow)

[`.github/workflows/main.yml`](.github/workflows/main.yml) runs kernel-enabled
tests, fuzzing, and dependency/feature matrices on pushes to `main` and manual
dispatch. Pull-request-triggered checks are defined in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

### Full-node feature set

Compiles all retained storage engines (`fjall`, `redb`, `rocksdb`) and the
`libbitcoinkernel` verification oracle (requires `cmake` and `libboost-dev`):

```sh
cargo test -p bitcoin-rs --no-fail-fast \
  --no-default-features --features "rocksdb,fjall,redb,kernel"

cargo clippy -p bitcoin-rs --all-targets \
  --no-default-features --features "rocksdb,fjall,redb,kernel" -- -D warnings

cargo clippy -p bitcoin-rs-node --all-targets -- -D warnings
cargo clippy -p bitcoin-rs-consensus --all-targets -- -D warnings
```

### Consensus test vectors and parity gate

```sh
# Run deterministic consensus vectors
cargo test -p bitcoin-rs-consensus --no-fail-fast -- --include-ignored

# Run differential kernel parity verification (requires kernel feature)
cargo test -p bitcoin-rs-consensus --features kernel \
  --test kernel_block_parity --test kernel_vector_parity -- --nocapture
```

The two parity test targets are not ignored. Passing `--ignored` would skip
them rather than run the oracle checks.

### Benchmark compilation check

The main workflow compiles the retained crate-level benchmarks without kernel:

```sh
cargo bench -p bitcoin-rs-consensus --no-run --no-default-features --bench merkle
cargo bench -p bitcoin-rs-utxo --no-run \
  --no-default-features --features fjall --bench utxo_commit
cargo bench -p bitcoin-rs-node --no-run \
  --no-default-features --features fjall --bench sync_pipeline
cargo bench -p bitcoin-rs-node --no-run \
  --no-default-features --features fjall --bench chainstate_journal
```

`--no-run` checks compilation; it produces no performance measurement.

### Fuzzing

Fuzz targets live under `fuzz/` and run against imported corpora:

```sh
# Install the fuzz toolchain and runner if not present
rustup toolchain install nightly
cargo install cargo-fuzz

# Example matching the Linux CI target
cargo +nightly fuzz run block_decode --target x86_64-unknown-linux-gnu -- -runs=10000
```

CI builds and runs all five targets: `p2p_message`, `block_decode`, `tx_decode`,
`script_eval`, and `utxo_snapshot`. See [`fuzz/README.md`](fuzz/README.md) for
local fuzzing and corpus guidance.

### Minimal-versions check

This lane changes `Cargo.lock`. Run it in a disposable checkout, with nightly
and kernel build dependencies installed:

```sh
cargo +nightly update -Zdirect-minimal-versions
cargo +nightly check --workspace --all-targets
```

The main workflow also checks individual features with `cargo-hack` and repeats
the full-feature dependency audit. See its `feature-combinations` and
`deny-full` jobs for the exact package and feature selection.

## Architecture and contribution scope

Read [AGENTS.md](AGENTS.md), the relevant issue or PR, and the owning
[contract](docs/contracts/README.md) before changing a subsystem. The
[architecture contract](docs/contracts/architecture.md) owns the five-layer
crate assignments, dependency direction, storage isolation, and their
verification gate. The [validation-default contract](docs/contracts/validation-default.md)
owns script-engine selection and its promotion criteria.

Keep implementation guidance with its owner rather than introducing another
architecture or validation specification in this guide.

## Commit and PR conventions

- Commit style: capitalized imperative subject line under 72 characters (for example, `Own Bitcoin protocol primitives natively`).
- Commit body: explain what changed and why. Include relevant issue numbers in footers (`Closes #N` or `Fixes #N`).
- Atomic changes: keep commits self-contained and bisectable; the workspace should compile and pass tests at each step.
- Tests first: bug fixes should include regression tests proving the defect is resolved.

## Documentation references

- [docs/README.md](docs/README.md) — Documentation index
- [docs/contracts/](docs/contracts/) — Normative architectural and protocol contracts
- [docs/getting-started.md](docs/getting-started.md) — Node setup and configuration
- [CONCEPTS.md](CONCEPTS.md) — Domain terminology and concepts
