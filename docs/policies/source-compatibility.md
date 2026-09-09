# Source and toolchain compatibility policy

This policy covers workspace toolchains, dependencies, versioning, and compatibility cutovers.

## 1. Scope and authority

It applies to all workspace crates and `bin/bitcoin-rs`. Root configuration files are authoritative where named below.

## 2. Toolchain and language edition

| Setting | Value | Source |
| :--- | :--- | :--- |
| Development toolchain | `stable` | `rust-toolchain.toml` |
| MSRV | `1.95.0` | `Cargo.toml`, `clippy.toml` |
| Rust edition | `2024` | `Cargo.toml` |
| Workspace lints | enabled | `Cargo.toml` |

### 2.1 MSRV rules

- Workspace crates must compile on Rust `1.95.0`.
- Raise MSRV only for a required dependency, correctness capability, or measured performance need.
- Update `Cargo.toml`, `clippy.toml`, and relevant documentation together.
- Nightly is limited to checks that require unstable Cargo or compiler features.

## 3. Dependency policy

Prefer the standard library and existing workspace crates over new dependencies.

### 3.1 Adding dependencies

- Member `[dependencies]` and `[build-dependencies]` belong in root `[workspace.dependencies]` and are inherited with `{ workspace = true }`.
- `[dev-dependencies]` may stay local unless tests exchange dependency-owned types across crate boundaries.
- Do not add an async runtime. The node uses a synchronous event loop; embedding may expose `async fn` while execution remains embedder-owned (`docs/contracts/embedding.md`, `EMB-02`).

### 3.2 Major version bumps

A dependency major-version bump requires upstream API/security review and verification of affected storage backends. Changes that can affect validation also verify the `kernel` feature path.

### 3.3 Consensus and P2P dependency posture

- `bitcoinkernel` is an optional oracle dependency behind `kernel`; `docs/contracts/validation-default.md` owns its default-status claim.
- The workspace currently has no `bip324` dependency or Cargo feature. Transport is v1-only per `docs/policies/p2p-compatibility.md`. BIP324 documentation must land with working dependency and feature wiring.

### 3.4 Lockfile, audit, and TLS rules

- Update `Cargo.lock` in the same change as the manifest change that requires it.
- Ordinary CI commands may run Cargo without `--locked`, and the direct-minimal-version lane intentionally rewrites dependency resolution. A normal CI pass therefore does not by itself prove lockfile freshness; use an explicit locked Cargo check when that proof is required.
- `deny.toml` must match the resolved graph. Do not exempt security-sensitive Bitcoin dependencies merely to pass an audit.
- Dependency TLS uses Rustls only. `openssl`, `openssl-sys`, and `native-tls` are prohibited.
- Do not use `--offline` or `--frozen` to hide unresolved dependency changes.

## 4. Workspace versioning and semver

All workspace crates inherit the root `[workspace.package]` version, currently `0.5.0`. `Cargo.toml` is the crate-list source of truth.

- During `0.x.y`, public API breaks require a minor-version bump.
- Patch releases contain only compatible fixes, optimizations, and internal refactors.

## 5. Compatibility cutovers

The default is a clean cutover: remove superseded wrappers, aliases, flags, fallback paths, and old representations with their replacement. Keep a compatibility path only when a current public or migration contract explicitly requires one.

### 5.1 UTXO snapshots

`read_snapshot_strict_v4` accepts only complete v4 snapshots and rejects v2/v3. A legacy reader requires an explicit migration-policy change.

### 5.2 RPC

`bitcoin-rs-rpc` does not keep deprecation shims. RPC compatibility tests define the current Bitcoin Core schema target; incompatible endpoints or fields are updated or removed in one cutover.

### 5.3 On-disk formats

On-disk schemas are not translated in place by default. Datadir markers, replay/resync requirements, and checkpoint recovery are owned by [the datadir migration policy](db-migration.md).
