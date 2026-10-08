<p align="center">
  <img src="logo.png" alt="bitcoin-rs logo" width="320">
</p>

# bitcoin-rs

## Build on Bitcoin. Inside Rust.

A Bitcoin full-node project for developers exploring typed Rust integration,
node-owned indexing, and familiar Bitcoin interfaces.

[Getting started](docs/getting-started.md) ·
[Documentation](docs/README.md) ·
[Contributing](CONTRIBUTING.md) ·
[Benchmarks and limitations](docs/benchmarks/end-to-end-sync.md)

[![CI](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

## Why bitcoin-rs

[Bitcoin Core](https://github.com/bitcoin/bitcoin) is the most successful
implementation of Bitcoin. Its conservatism, stability, and compatibility
discipline are major reasons for
that success. Over time, however, those safeguards also shape which changes are
practical: existing boundaries accumulate dependencies, and implementation
choices harden into assumptions that Bitcoin consensus does not require.

bitcoin-rs asks a simple question:

> **If a Bitcoin full node were designed again today, what would we keep, and
> what would we change?**

### Why now?

Bitcoin is unusually well suited to independent implementation because its
behavior can be checked against Bitcoin Core, `libbitcoinkernel`, historical
chain data, consensus test vectors, fuzzing, and differential tests.

However, Bitcoin Core prioritizes stability, compatibility, and minimizing
change risk. While essential for the reference implementation, these priorities
make large architectural changes difficult to explore within the same codebase.

**That is why we built `bitcoin-rs`: to preserve Bitcoin's consensus while
making architectural experimentation practical—build alternatives, verify them
against reproducible evidence, and keep iterating on the implementation.**

### What can be improved

- **Performance is a first-class requirement.** `bitcoin-rs` is not aiming for
  parity with Bitcoin Core simply by changing languages. Synchronization,
  storage, memory ownership, concurrency, caching, I/O, and indexing can all be
  reconsidered. Improvements must be demonstrated with matched whole-node
  benchmarks against Core.
- **The UTXO set is the node's authoritative coin state.** Much of the Bitcoin
  application ecosystem grew by rebuilding or duplicating wallet-, Electrum-,
  and explorer-specific views around the same chain data. `bitcoin-rs`
  simplifies that boundary: the node owns the canonical UTXO set used for
  validation and an integrated script index exposed through Esplora-compatible
  APIs. Wallet-specific keys, policies, and metadata remain outside the node.
- **Modularity keeps the core isolated and components composable.** Clear
  dependency and failure boundaries keep extensions from destabilizing
  validation or chainstate while allowing components to be reused independently.
- **Rust-native integration is a primary path.** Applications and extensions in
  the Rust Bitcoin ecosystem can attach to the node as typed, in-process
  components instead of routing through serialized RPC or separate processes.

Bitcoin is not defined by the continued preservation of one codebase. **The code
can change; consensus is what must remain.** `bitcoin-rs` aims to provide an
independently designed implementation that can be compared against Bitcoin Core
and other implementations through reproducible evidence.

## Quick start

Build and run the kernel-free default binary with the quick-start profile.
Consult [Getting started](docs/getting-started.md) for build lanes and
prerequisites before choosing features:

```sh
cargo build --profile quickstart -p bitcoin-rs
./target/quickstart/bitcoin-rs --data-dir .bitcoin-rs
```

Use the `quickstart` profile for initial exploration. For sustained IBD or
benchmarking, use `cargo build --release -p bitcoin-rs` and record the exact
profile and feature set with the result. No build-time ratio is claimed here.

This starts a mainnet node using `fjall` storage and native Rust script
verification, storing state in `.bitcoin-rs` and listening for JSON-RPC on
`127.0.0.1:8332`. The shipped Docker image instead selects kernel verification
through its default configuration.

Mainnet skips historical script verification up to the pinned assume-valid
anchor by default. Add `--assume-valid-height 0` to verify all scripts from
genesis. See [Getting started](docs/getting-started.md) for configuration,
cache, indexing, and pruning options.

Verify the node is responding and syncing:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

### Kernel oracle build

To route script verification through `libbitcoinkernel` instead of the native
interpreter, install C++ dependencies (`cmake` and `libboost-dev` on
Debian/Ubuntu), build with `--features kernel` (compiles kernel support in),
and select the engine at runtime with `--validation-engine kernel`:

```sh
cargo build --release -p bitcoin-rs --features kernel
./target/release/bitcoin-rs --data-dir .bitcoin-rs --validation-engine kernel
```

## Benchmark status

[End-to-end synchronization evidence](docs/benchmarks/end-to-end-sync.md) is the
owner of methodology, measurements, artifact custody, and limitations. It
retains historical bounded results from superseded engines, including both
faster local replays and slower daemon IBD results. Those figures are not
current end-state proof or a general speed comparison with Bitcoin Core.

The owner's end-state cells are marked `planned_not_executed`. Historical raw
JSON was retired by #224; retained digests can identify an external copy, but
are not a replacement for the raw evidence. This README makes no current
performance-superiority claim. Consult the owner document for the status of
each workload before quoting a result.

## Architecture

```
Surfaces:      bin/bitcoin-rs, crates/rpc
Capabilities:  crates/index, crates/mining, crates/mempool
Node services: crates/node, crates/p2p, crates/storage
Core & domain: crates/consensus, crates/script, crates/utxo, crates/chain, crates/primitives
```

- Validation: script execution runs in parallel across rayon workers, with
  sighash midstate reuse per transaction. The native interpreter covers every
  consensus spend class. With the `kernel` feature, `libbitcoinkernel` support
  is compiled in and `validation.engine` selects the verifier at runtime
  (`native` by default, `kernel` to route script checks through
  `libbitcoinkernel`).
- Kernel boundary: `crates/consensus/src/kernel.rs` contains all
  `libbitcoinkernel` types behind `#[cfg(feature = "kernel")]`. Kernel types
  never leak into node state or apply logic. The `kernel` feature is a
  capability; `validation.engine` is the selection.
- Storage: `crates/storage` provides backend abstraction. The active engine is
  configured at startup (`fjall`, `redb`, or `rocksdb`).
- Indexing: `txindex` runs as an independent consumer, advancing its cursor and
  rollback metadata atomically.

## Build and test

```sh
# Build default binary (kernel-free)
cargo build --release -p bitcoin-rs

# Run workspace unit and integration tests
cargo test --workspace

# Lint all targets
cargo clippy --workspace --all-targets -- -D warnings
```

## Validation and verification

bitcoin-rs verifies consensus, networking, and storage through multiple independent
evidence lanes rather than relying on in-tree unit tests alone. Evidence is
separated into real external-consumer evidence (unmodified external software
exercising the public boundary) and in-tree reference/differential suites.

For reproduction commands, prerequisites, and artifact custody for each lane, see
the [validation tooling index](docs/validation-tooling.md).

Implemented and tested lanes:

- [Core vectors](docs/validation-tooling.md#3-bitcoin-core-script-and-transaction-vectors):
  native script evaluation with pinned skips; consensus transaction tests cover
  loading and deserialization, not validity.
- [Sighash differentials](docs/validation-tooling.md#4-native-sighash-checks-against-independent-implementation):
  legacy, SegWit v0, and Taproot checks against independent implementations.
- [Kernel oracle and scoped parity](docs/validation-tooling.md#5-libbitcoinkernel-oracle-and-scoped-native-parity):
  Core script-vector verdicts and selected native/kernel fixture comparisons,
  not a full-corpus differential.
- [Contextual consensus rules](docs/validation-tooling.md#6-contextual-consensus-rule-tests):
  difficulty, activation rules, and undo persistence.
- [Fuzzing and corpus regression](docs/validation-tooling.md#7-daily-fuzz-targets-and-qa-assets-corpus-provenance):
  five targets, pinned reference seeds, and codec invariants.
- [Crash recovery and reorgs](docs/validation-tooling.md#8-chainstate-crash-recovery-and-reorg-evidence):
  durable commits, process-death boundaries, and restart consistency.

External evidence and remaining work:

- [Live Core P2P](docs/validation-tooling.md#1-live-bitcoin-core-p2p-and-chain-identity-differential):
  externally verified handshake, sync, compact blocks, and chain identity.
- [Live Core acceptance](docs/validation-tooling.md#2-live-core-block-and-transaction-acceptance-differential):
  curated block/transaction cases tested.
- [bitcoinfuzz integration](https://github.com/bitcoinfuzz/bitcoinfuzz/issues/662):
  integration effort in progress to add bitcoin-rs as a differential fuzzing module.
- [Offline full-validation comparator](docs/validation-tooling.md#9-offline-full-validation-comparator):
  harness tested; full-mainnet campaigns not yet executed.
- [Ecosystem compatibility](docs/validation-tooling.md#10-external-ecosystem-compatibility-matrix):
  P2P externally verified; other surfaces tracked separately.
- [USDT observability](docs/validation-tooling.md#11-usdt--bpftrace-observability-validation):
  probe ABI tested; live tracing remains planned.

## Independent architecture, Bitcoin compatibility

bitcoin-rs explores new architectures behind Bitcoin's established consensus,
protocol, and supported API boundaries. Internal designs are replaceable:
changes must earn their place through reproducible evidence, not resemblance
to Bitcoin Core.

We check compatibility against real ecosystem consumers and reference
implementations. See the [validation tooling index](docs/validation-tooling.md)
for tested scope and the [compatibility matrix](docs/api/ecosystem-compat.toml)
for per-interface status.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for local
verification commands, CI workflows, and crate architecture conventions.

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — Node setup and configuration
- [docs/README.md](docs/README.md) — Documentation index
- [docs/validation-tooling.md](docs/validation-tooling.md) — Validation tooling and evidence index
- [docs/contracts/](docs/contracts/) — Normative architecture and protocol contracts
- [docs/contracts/ecosystem-compatibility.md](docs/contracts/ecosystem-compatibility.md) — External ecosystem compatibility strategy
- [docs/api/ecosystem-compat.toml](docs/api/ecosystem-compat.toml) — External compatibility evidence matrix
- [CONCEPTS.md](CONCEPTS.md) — Domain terminology and concepts

## License

Licensed under [Apache-2.0](LICENSE).
