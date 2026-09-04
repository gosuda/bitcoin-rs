# Source and Toolchain Compatibility Policy

This document defines the toolchain requirements, dependency management rules, semver commitments, and deprecation policies for `bitcoin-rs`.

## 1. Scope and Authority

This policy applies to every crate in the `bitcoin-rs` workspace (`crates/*`) and the node binary (`bin/bitcoin-rs`).

## 2. Toolchain and Language Edition

Language and toolchain settings are locked centrally in `rust-toolchain.toml` and root `Cargo.toml`.

| Setting | Value | Configuration Source |
| :--- | :--- | :--- |
| Minimum Supported Rust Version (MSRV) | `1.95.0` | `rust-toolchain.toml`, `Cargo.toml` (`rust-version`) |
| Rust Language Edition | `2024` | `Cargo.toml` (`workspace.package.edition`) |
| Strict Workspace Lints | Enabled | `Cargo.toml` (`workspace.lints`) |

### 2.1 MSRV Rules
- All crates in the workspace must compile on Rust `1.95.0`.
- MSRV increases only under these conditions:
  1. A required upstream dependency bumps its MSRV floor beyond `1.95.0`.
  2. A new standard library feature or compiler capability is strictly necessary for consensus correctness or performance.
- An MSRV bump requires updating `rust-toolchain.toml`, root `Cargo.toml` (`rust-version`), and workspace documentation simultaneously.

## 3. Dependency Policy

`bitcoin-rs` maintains a minimal dependency footprint to reduce build times, security surface, and binary size.

### 3.1 Adding Dependencies
- All `[dependencies]` and `[build-dependencies]` of member crates (`crates/*`) must be defined centrally in `Cargo.toml` under `[workspace.dependencies]`.
- Member crates must inherit those using `{ workspace = true }`.
- `[dev-dependencies]` are exempt. They do not reach the shipped binary, so a version skew between two crates' test harnesses cannot produce a runtime conflict, and centralizing them buys nothing. Twelve member manifests declare `tempfile = "3"` directly under `[dev-dependencies]` and there is no workspace entry for it; that is intended, not drift.
- Centralize a dev-dependency anyway when two crates must agree on a type that crosses between them in tests.
- Do not add dependencies for functionality available in the Rust standard library or existing workspace crates.
- Prohibited dependencies: `tokio`, `async-std`, or any async runtime. The node architecture uses a synchronous crossbeam-channel event loop.

### 3.2 Major Version Bumps
- Upgrading a workspace dependency to a new major version requires:
  1. Audit of upstream security, performance, and API changes.
  2. Compilation and verification across all four storage backend features (`fjall`, `rocksdb`, `mdbx`, `redb`).
  3. Verification against the `kernel` consensus feature path.

## 4. Workspace Versioning and Semver Commitment

All crates in `bitcoin-rs` share a single workspace version managed by `[workspace.package] version` (currently `0.4.0`).

| Workspace Crate | Path | Description |
| :--- | :--- | :--- |
| `bitcoin-rs-primitives` | `crates/primitives` | Core types and byte primitives |
| `bitcoin-rs-consensus` | `crates/consensus` | Block and transaction verification |
| `bitcoin-rs-script` | `crates/script` | Script execution and evaluation |
| `bitcoin-rs-storage` | `crates/storage` | Key-value store abstraction, implementations, and block/undo pruning |
| `bitcoin-rs-utxo` | `crates/utxo` | In-memory UTXO set management, snapshots, and UTXO statistics / MuHash |
| `bitcoin-rs-chain` | `crates/chain` | Block tree and chain index tracking |
| `bitcoin-rs-index` | `crates/index` | Transaction and address indexing |
| `bitcoin-rs-mempool` | `crates/mempool` | Memory pool transaction storage |
| `bitcoin-rs-p2p` | `crates/p2p` | Peer-to-peer network protocol |
| `bitcoin-rs-mining` | `crates/mining` | Block template construction |
| `bitcoin-rs-rpc` | `crates/rpc` | JSON-RPC HTTP server |
| `bitcoin-rs-node` | `crates/node` | Full node state machine and event loop |
| `bitcoin-rs` | `bin/bitcoin-rs` | Command-line node binary |

### 4.1 Semver Rules
- During `0.x.y` releases, public API breaking changes require a minor version bump (e.g., `0.4.0` to `0.5.0`).
- Patch updates (e.g., `0.4.0` to `0.4.1`) must contain only non-breaking bug fixes, performance optimizations, or internal refactoring.

## 5. Anti-Shim Principle and Deprecation Policy

### 5.1 The Anti-Shim Principle
`bitcoin-rs` operates on a strict **clean cutover** principle. The project rejects:
- Backward-compatibility shims.
- Deprecated wrapper functions or type aliases.
- Transitional configuration flags or legacy fallback paths.

When a feature, algorithm, interface, or data layout changes, maintainers must remove the old code path completely in the same change-set.

The UTXO snapshot reader is a clean-cutover boundary: `read_snapshot_strict_v4`
accepts only complete version-4 snapshots and rejects versions 2 and 3. The
node can rebuild or resynchronize chainstate, so no legacy reader is retained
for this format. A future recovery exception would require an explicit
maintainer decision and matching migration policy before adding a reader.

### 5.2 RPC Deprecation Policy
- `bitcoin-rs-rpc` does not provide deprecation windows or compatibility shims for RPC endpoints.
- RPC methods match current Bitcoin Core JSON-RPC schemas directly (`crates/rpc/tests/core_compat.rs`).
- If an RPC endpoint or field changes upstream or internally, `bitcoin-rs` updates or removes the method immediately in a clean cutover.

### 5.3 On-Disk Format Deprecation Policy
- On-disk storage schemas do not maintain backward-compatibility translation shims.
- When key-value column families, block file encodings, or checkpoint formats change, the system does not convert old databases in place.
- Every datadir carries the current `CURRENT_SCHEMA` epoch. An unmarked
   non-empty datadir is implicitly epoch `0`: it is adopted and marked while
   epoch `0` is current, but requires removal/recreation and resync after the
   epoch advances. A mismatched marker fails before normal persistent-state
   startup and requires the operator to remove/recreate the datadir and resync.
   Network/backend datadir ownership and multi-process locking are separate
   configuration and lifecycle concerns, not persistent schema compatibility
   ([issue #242](https://github.com/gosuda/bitcoin-rs/issues/242)).
   A checkpoint `CURRENT` is its sole commit point, so unpublished generation
   residue yields `Cold` and a referenced invalid generation is current-state
   corruption. There is no `HeadersOnly` compatibility fallback.
