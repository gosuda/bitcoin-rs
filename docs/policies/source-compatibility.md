# Source and Toolchain Compatibility Policy

This document defines the toolchain requirements, dependency management rules, semver commitments, and deprecation policies for `bitcoin-rs`.

## 1. Scope and Authority

This policy applies to every crate in the `bitcoin-rs` workspace (`crates/*`) and the node binary (`bin/bitcoin-rs`).

## 2. Toolchain and Language Edition

Language and toolchain settings are locked centrally in `rust-toolchain.toml` and root `Cargo.toml`.

| Setting | Value | Configuration Source |
| :--- | :--- | :--- |
| Pinned Rust toolchain (MSRV) | `1.95.0` | `rust-toolchain.toml` (`channel`), `Cargo.toml` (`rust-version`) |
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
- `[dev-dependencies]` are exempt. They do not reach the shipped binary, so a version skew between two crates' test harnesses cannot produce a runtime conflict, and centralizing them buys nothing. Eight member manifests declare `tempfile = ">=3.20.0, <4"` directly under `[dev-dependencies]` and there is no workspace entry for it; that is intended, not drift.
- Centralize a dev-dependency anyway when two crates must agree on a type that crosses between them in tests.
- Do not add dependencies for functionality available in the Rust standard library or existing workspace crates.
- Prohibited dependencies: `tokio`, `async-std`, or any async runtime. The node architecture uses a synchronous crossbeam-channel event loop. The embedding API (`crates/node/src/embed.rs`) exposes `async fn` signatures whose bodies are synchronous; the node never creates, enters, or retains a runtime, and the embedder supplies its own executor (`docs/contracts/embedding.md`, EMB-02). That contract does not add a runtime dependency and is not an exception to this rule.

### 3.2 Major Version Bumps
- Upgrading a workspace dependency to a new major version requires:
  1. Audit of upstream security, performance, and API changes.
  2. Compilation and verification across all four storage backend features (`fjall`, `rocksdb`, `mdbx`, `redb`).
  3. Verification against the `kernel` oracle feature path (opt-in only; see §3.3).

### 3.3 Pinned Optional Dependencies and the Strict-Rust Lane
- Strict-Rust validation is mandatory for release. The promoted binary, library, and image must validate without native consensus code. `bitcoinkernel` stays pinned at `0.2.1` (kernel tree 31.99.0) as the opt-in differential oracle only. It is never a silent fallback for a native failure, and it is never a policy pin.
- `k256` is pinned at `0.14.0` as the strict-Rust arithmetic and ECDSA lane. Its high-level Schnorr `Signature` type is withdrawn from use: it stores a `NonZeroScalar` and cannot represent the whole BIP340 input domain. BIP340 verification uses one general protocol operation over the library's maintained arithmetic primitives. The workspace adds no custom field or group arithmetic. An overflowing TapTweak is canonically rejected, never reduced.
- `bip324` is pinned at `=0.11.0` in `[workspace.dependencies]` with `default-features = false` and `features = ["std"]`. Its `tokio` feature stays off; the §3.1 runtime ban applies. Member crates inherit it with `{ workspace = true, optional = true }`. The optional feature `bip324` is off by default and forwards `p2p` to `node` to `binary`. Only the sans-I/O `Handshake` and `CipherSession` types are used, inside the existing `crates/p2p/src/connection.rs` owner. No socket or runtime integration and no custom ECDH, ElligatorSwift, or ChaCha20Poly1305 code is permitted.

### 3.4 Lockfile, Audit, and TLS Rules
- Every Cargo invocation uses `--locked`. A `Cargo.lock` change lands in the same reviewed atomic commit as its manifest or workspace change. Never use `--offline` to hide a missing crate, and never use `--frozen` as a substitute for `--locked`.
- `deny.toml` keeps exactly one `bitcoin_hashes` skip: the exact resolved newer version pulled in by `bip324 0.11.0`, recorded as an exact version and never a range, with `bip324` as its sole reverse dependency. The consensus `bitcoin_hashes` copy stays unskipped. `bitcoin`, `secp256k1`, and `secp256k1-sys` keep their no-skip status. All TLS bans stay in force.
- TLS, where a dependency requires it, uses the Rustls family only. `openssl`, `openssl-sys`, and `native-tls` are prohibited.

## 4. Workspace Versioning and Semver Commitment

All crates in `bitcoin-rs` share a single workspace version managed by `[workspace.package] version`. The current target is `0.5.0`. The `0.4.0` to `0.5.0` bump is staged at the boundary-freeze change (task T03) and lands in one atomic commit together with the `Cargo.lock` update. Member crates inherit the workspace version. A version bump and its lockfile update never split across commits.

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
- During `0.x.y` releases, public API breaking changes require a minor version bump (the `0.4.0` to `0.5.0` bump staged at T03 covers the approved boundary cuts).
- Patch updates (e.g., `0.5.0` to `0.5.1`) must contain only non-breaking bug fixes, performance optimizations, or internal refactoring.

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
- RPC methods match current Bitcoin Core JSON-RPC schemas directly. `crates/rpc/tests/core_compat.rs` is the schema-proof surface: every dispatched response covered by a `corepc_types` structured type must deserialize into that exact upstream type.
- If an RPC endpoint or field changes upstream or internally, `bitcoin-rs` updates or removes the method immediately in a clean cutover.

### 5.3 On-Disk Format Deprecation Policy
- On-disk storage schemas do not maintain backward-compatibility translation shims.
- When key-value column families, block file encodings, or checkpoint formats change, the system does not convert old databases in place.
- Datadir schema markers, resync requirements, and checkpoint commit/recovery semantics are defined by the canonical [datadir migration policy](db-migration.md). This policy does not duplicate those on-disk rules.
