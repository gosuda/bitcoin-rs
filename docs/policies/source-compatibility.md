# Source and Toolchain Compatibility Policy

This document defines the toolchain requirements, dependency management rules, semver commitments, and deprecation policies for `bitcoin-rs`.

## 1. Scope and Authority

This policy applies to every crate in the `bitcoin-rs` workspace (`crates/*`) and the node binary (`bin/bitcoin-rs`).

## 2. Toolchain and Language Edition

The repository development toolchain is selected by `rust-toolchain.toml`.
Language edition and the compatibility floor are owned by the root `Cargo.toml`,
with Clippy's compatibility behavior mirrored in `clippy.toml`.

| Setting | Value | Configuration Source |
| :--- | :--- | :--- |
| Development Rust toolchain | `stable` | `rust-toolchain.toml` |
| Minimum Supported Rust Version (MSRV) | `1.95.0` | `Cargo.toml` (`rust-version`), `clippy.toml` (`msrv`) |
| Rust Language Edition | `2024` | `Cargo.toml` (`workspace.package.edition`) |
| Strict Workspace Lints | Enabled | `Cargo.toml` (`workspace.lints`) |

### 2.1 MSRV Rules
- All crates in the workspace must compile on Rust `1.95.0`.
- MSRV increases only under these conditions:
  1. A required upstream dependency bumps its MSRV floor beyond `1.95.0`.
  2. A new standard library feature or compiler capability is strictly necessary for consensus correctness or performance.
- An MSRV bump requires updating root `Cargo.toml` (`rust-version`), `clippy.toml` (`msrv`), and workspace documentation simultaneously. The repository development toolchain remains `stable`.

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
  3. Verification against the `kernel` consensus feature path.

### 3.3 Lockfile and CI Reproducibility
- `Cargo.lock` is committed and is part of the build identity. Normal CI lint, test, benchmark, and feature checks use `--locked`; a stale lockfile fails the job instead of being rewritten only inside the runner checkout.
- Dependency-update changes may intentionally edit `Cargo.lock`, but validation after that edit still uses `--locked`.
- The `minimal-versions` lane in `.github/workflows/main.yml` is the one intentional mutation lane: `cargo +nightly update -Zdirect-minimal-versions` rewrites the lockfile in its disposable checkout. Its subsequent compile uses `--locked` against that rewritten result.
- Cargo subcommand wrappers with their own resolution behavior (`cargo fuzz`) are audited separately rather than treated as ordinary root-workspace Cargo invocations.

### 3.4 TLS Provider and Transport Rules
- If a TLS transport is added, use Rustls with default features disabled and a reviewed non-C crypto provider. Do not rely on adapter defaults to select the provider.
- `deny.toml` enforces the dependency boundary. Keep the native-TLS/OpenSSL/platform-TLS families and disallowed Rustls provider/adaptor families complete so a transitive feature cannot reintroduce AWS-LC, ring, OpenSSL, or platform TLS.
- Review both dependency features and transport configuration when changing a TLS path. A dependency ban alone does not establish correct certificate, protocol, timeout, or endpoint behavior.

## 4. Workspace Versioning and Semver Commitment

All crates in `bitcoin-rs` share a single workspace version managed by `[workspace.package] version` (currently `0.5.0`).

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
- Datadir schema markers, resync requirements, and checkpoint commit/recovery semantics are defined by the canonical [datadir migration policy](db-migration.md). This policy does not duplicate those on-disk rules.
