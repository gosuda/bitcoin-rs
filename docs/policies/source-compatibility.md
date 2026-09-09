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
- MSRV increases only when a required dependency raises its floor or a newer compiler capability is necessary for correctness or measured performance.
- An MSRV bump updates `rust-toolchain.toml`, root `Cargo.toml` (`rust-version`), and workspace documentation together.

## 3. Dependency Policy

`bitcoin-rs` maintains a minimal dependency footprint to reduce build times, security surface, and binary size.

### 3.1 Adding Dependencies

- All `[dependencies]` and `[build-dependencies]` of member crates (`crates/*`) must be defined centrally in `Cargo.toml` under `[workspace.dependencies]`.
- Member crates inherit those dependencies using `{ workspace = true }`.
- `[dev-dependencies]` are exempt unless tests exchange a dependency-owned type across crate boundaries and therefore require one version.
- Do not add dependencies for functionality already available in the Rust standard library or existing workspace crates.
- `tokio`, `async-std`, and other async runtime dependencies are prohibited. The node uses a synchronous event-loop architecture. The embedding API may expose `async fn` signatures without creating or retaining an executor; the embedder owns execution (`docs/contracts/embedding.md`, `EMB-02`).

### 3.2 Major Version Bumps

Upgrading a workspace dependency to a new major version requires:

1. Audit of upstream security, performance, and API changes.
2. Compilation and verification across all four storage backend features (`fjall`, `rocksdb`, `mdbx`, `redb`).
3. Verification of the `kernel` consensus feature path when the change can affect validation.

### 3.3 Consensus and P2P Dependency Posture

- `bitcoinkernel` is the optional consensus-oracle dependency behind the `kernel` feature. Whether that feature is in a crate's current default set is owned by `docs/contracts/validation-default.md`; do not describe it as universally opt-in or universally defaulted in other documents.
- The current workspace has no `bip324` dependency or `bip324` Cargo feature. P2P transport is v1-only as recorded in `docs/policies/p2p-compatibility.md`. Future BIP324 work must land its dependency, feature wiring, transport implementation, and documentation in the same reviewed change instead of documenting an invocation before it exists.

### 3.4 Lockfile, Audit, and TLS Rules

- `Cargo.lock` changes land in the same reviewed change as the manifest change that requires them. CI and release checks use the pinned lockfile; do not use `--offline` or `--frozen` to disguise a missing or stale dependency resolution.
- `deny.toml` stays aligned with the resolved graph. Security-sensitive Bitcoin dependencies such as `bitcoin`, `secp256k1`, and `secp256k1-sys` are not exempted merely to make an audit pass.
- TLS, where a dependency requires it, uses the Rustls family only. `openssl`, `openssl-sys`, and `native-tls` are prohibited.

## 4. Workspace Versioning and Semver Commitment

All crates in `bitcoin-rs` share a single workspace version managed by `[workspace.package] version` (currently `0.5.0`). Member crates inherit the workspace version, and internal workspace dependency versions move with it.

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

- During `0.x.y` releases, public API breaking changes require a minor version bump.
- Patch updates must contain only non-breaking bug fixes, performance optimizations, or internal refactoring.

## 5. Anti-Shim Principle and Deprecation Policy

### 5.1 The Anti-Shim Principle

`bitcoin-rs` operates on a strict **clean cutover** principle. The project rejects:

- Backward-compatibility shims.
- Deprecated wrapper functions or type aliases.
- Transitional configuration flags or legacy fallback paths.

When a feature, algorithm, interface, or data layout changes, maintainers remove the old code path in the same change-set.

The UTXO snapshot reader is a clean-cutover boundary: `read_snapshot_strict_v4` accepts only complete version-4 snapshots and rejects versions 2 and 3. The node can rebuild or resynchronize chainstate, so no legacy reader is retained for this format. A future recovery exception requires an explicit maintainer decision and matching migration policy before adding a reader.

### 5.2 RPC Deprecation Policy

- `bitcoin-rs-rpc` does not provide deprecation windows or compatibility shims for RPC endpoints.
- RPC methods match current Bitcoin Core JSON-RPC schemas directly; the RPC compatibility tests are the proof surface.
- If an RPC endpoint or field changes upstream or internally, `bitcoin-rs` updates or removes the method in a clean cutover.

### 5.3 On-Disk Format Deprecation Policy

- On-disk storage schemas do not maintain backward-compatibility translation shims.
- When key-value column families, block file encodings, or checkpoint formats change, the system does not convert old databases in place.
- Datadir schema markers, resync requirements, and checkpoint commit/recovery semantics are defined by the canonical [datadir migration policy](db-migration.md). This policy does not duplicate those on-disk rules.
