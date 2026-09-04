# Contributing to bitcoin-rs

Thank you for contributing to `bitcoin-rs`. This guide outlines the development
workflow, coding standards, and verification commands used across the project.

## Prerequisites

- Rust toolchain: Rust 2024 edition (MSRV 1.95.0 or newer).
- Default build: Pure Rust. No C++ compiler or system libraries required.
- Optional kernel oracle: `cmake` and `libboost-dev` (only when building with
  `--features kernel` for differential verification against `libbitcoinkernel`).

Install tools:

```sh
rustup update stable
rustup component add rustfmt clippy
cargo install --locked cargo-deny
```

## Quick verification (PR gate)

Pull requests run a fast pure-Rust gate configured in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Run these locally before
submitting:

```sh
# 1. Format check
cargo fmt --all -- --check

# 2. Clippy on all targets with default features
cargo clippy --workspace --all-targets -- -D warnings

# 3. Workspace unit and integration tests (pure-Rust defaults)
cargo test --workspace --no-fail-fast

# 4. Isolated non-default feature tests
cargo test -p bitcoin-rs-rpc --no-default-features --no-fail-fast

# 5. Dependency, license, and duplicate-version audits
cargo deny check
```

## Deep CI lanes (main workflow)

Extended verification lanes run on merges to `main` as defined in
[`.github/workflows/main.yml`](.github/workflows/main.yml):

### Full-node feature set

Compiles all storage engines (`fjall`, `redb`, `rocksdb`, `mdbx`) and the
`libbitcoinkernel` verification oracle (requires `cmake` and `libboost-dev`):

```sh
cargo test -p bitcoin-rs --no-fail-fast \
  --no-default-features --features "rocksdb,fjall,redb,mdbx,kernel"

cargo clippy -p bitcoin-rs --all-targets \
  --no-default-features --features "rocksdb,fjall,redb,mdbx,kernel" -- -D warnings

cargo clippy -p bitcoin-rs-node --all-targets -- -D warnings
```

### Consensus test vectors and parity gate

```sh
# Run deterministic consensus vectors
cargo test -p bitcoin-rs-consensus --no-fail-fast -- --include-ignored

# Run differential kernel parity verification (requires kernel feature)
cargo test -p bitcoin-rs --test g03_kernel_parity --features kernel -- --ignored --nocapture
```

### Benchmark compilation check

```sh
cargo bench -p bitcoin-rs --no-run \
  --no-default-features --features "rocksdb,fjall,redb,mdbx,kernel"
cargo bench -p bitcoin-rs-utxo --no-run
cargo bench -p bitcoin-rs-utxo --no-run --features bench-mimalloc
```

### Fuzzing

Fuzz targets live under `fuzz/` and run against imported corpora:

```sh
# Install cargo-fuzz if not present
cargo install cargo-fuzz

# Run a target (options: p2p_message, block_decode, tx_decode, script_eval, utxo_snapshot)
cargo +nightly fuzz run block_decode -- -runs=10000
```

### Minimal-versions check

```sh
cargo +nightly update -Zdirect-minimal-versions
cargo +nightly check --workspace --all-targets
```

## Architecture and crate hierarchy

The workspace follows a strict one-way layer hierarchy:

```
Surfaces:      bin/bitcoin-rs, crates/rpc
Capabilities:  crates/index, crates/mining, crates/mempool
Node services: crates/node, crates/p2p, crates/storage
Core & domain: crates/consensus, crates/script, crates/utxo, crates/chain, crates/primitives
```

Key rules:
- No reverse dependencies: lower layers never depend on higher layers.
- Storage isolation: storage backends remain behind `crates/storage`. `crates/rpc` consumes node-level capabilities, never storage engines directly.
- Consensus authority: the native Rust validation engine in `crates/consensus` is the production default. `libbitcoinkernel` serves as an opt-in differential verification oracle.

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
