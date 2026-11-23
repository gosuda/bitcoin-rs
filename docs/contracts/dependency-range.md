# Dependency range contract

Declared Cargo ranges are the versions that this workspace claims to support.
The committed `Cargo.lock` is one point inside that range, not the contract.

## Clauses

### `DEP-01`: Minimum and maximum resolvable versions compile
- **Owner**: `scripts/check-dep-range.sh`.
- **Scope**: every direct workspace dependency declared in the root `Cargo.toml` `[workspace.dependencies]` table.
- `minimal` resolves each direct dependency at its oldest allowed version via `cargo +nightly update -Zdirect-minimal-versions`.
- `minimal` checks the workspace graph with all targets and all features enabled via `--all-targets --all-features`.
- `maximum` resolves every crate to the newest version inside its declared range via `cargo update`.
- `maximum` checks the default-feature workspace graph with all targets via `--all-targets`.
- `maximum` runs one explicit kernel-enabled check via `-p bitcoin-rs-node --all-targets --features kernel`.
- This check ensures that the optional C++ engine sees its newest allowed versions.
- Both lanes run `cargo deny check bans` against the mutated lockfile.
- The `minimal` lane enables every feature.
- Therefore, `minimal` compiles optional native storage engines at the oldest resolve.
- `FEAT-01` owns the named combinations.
- Both lanes mutate `Cargo.lock`.
- The script copies `Cargo.lock` aside and restores it on exit unless `KEEP_LOCK=1`.
- Local runs do not require a disposable checkout.
- The scheduled compatibility workflow uses a disposable runner.
- These lanes are not pull-request merge gates.

### `DEP-02`: One copy of each consensus-stack crate except listed exact-version splits
- **Owner**: `deny.toml` `[bans]`.
- **Scope**: the resolved graph of each DEP-01 lane.
- Check both lanes under `deny.toml` `[graph]` with `all-features = true`, not each lane's own feature set.
- Scope covers `bitcoin`, `bitcoin_hashes`, `secp256k1`, and `secp256k1-sys`.
- Each of those crates MUST resolve to exactly one version per graph, except the exact-version splits listed here.
- The Bitcoin 0.32.102 reference dependency retains `bitcoin_hashes 0.14.101` alongside direct `bitcoin_hashes 1.2.0`.
- The direct `secp256k1 0.33.1` line coexists with Bitcoin's exact `secp256k1 0.29.100` and `secp256k1-sys 0.10.1` reference line; versioned native links keep the two libraries distinct.
- The pool-only exception below remains approved.
- The pinned SRI release family is `noise_sv2 2.1.0`.
- The `pool-sv2` feature in `crates/wire/Cargo.toml` reaches this family.
- This family carries its own audited `secp256k1 0.28.2` and `secp256k1-sys 0.9.2` authority-key line.
- This family also carries its own `bitcoin_hashes 0.13.1` transport line.
- `deny.toml` `[bans].skip` pins those exact versions with the `noise_sv2 2.1.0` reason.
- `multiple-versions = "deny"` fails any split not covered by the listed exact-version skips.
- No further skip is approved for these four names beyond the listed exact-version splits.
- The skip entries are audited splits.
- Each entry leaves one unskipped anchor, so a new version of a skipped crate fails.
- Package-id cardinality beyond the listed exact-version splits is not checked mechanically.
- Lockfile review pins that cardinality.
- For `base64`, only direct `0.23.1`, the Bitcoin dependency chain's `0.21.7`, and the metrics exporter's `0.22.1` may coexist.
- These exact-version splits do not approve other `base64` versions.
- The Noise-family dependencies in `crates/wire/Cargo.toml` are optional normal dependencies.
- The `pool-sv2` feature enables these dependencies.
- Cargo forbids `optional` dev-dependencies.
- Cargo does not honor `cfg(feature)` in target dev tables.
- Cargo resolves optional dependencies into the lockfile as if all workspace features were enabled. Its later compile pass selects the requested features, as documented by the [Cargo resolver](https://doc.rust-lang.org/cargo/reference/resolver.html#features).
- The default-feature maximum compile does not build the Noise chain. The minimal all-features compile does.
- Both lanes check bans with all features. The exact-version skips above therefore apply to both ban checks.
- Only the `pool-sv2`-gated SV2 module and its tests use these dependencies.
- Range-endpoint graphs are in scope.
- `cargo deny check bans` runs after each DEP-01 resolve.
- Missing cargo-deny is a failed prerequisite, not a skip.

Proof: `scripts/check-dep-range.sh minimal` resolves the lower endpoint and checks all targets with all features. `scripts/check-dep-range.sh maximum` resolves the upper endpoint and checks default targets plus the explicit kernel build. Both execute `cargo deny check bans` using the all-features graph in `deny.toml` against their resolved lockfile. A checked-in lockfile alone does not establish either endpoint result.

### `DEP-03`: One JSON stack and one time stack
- **Owner**: `deny.toml` `[bans]`.
- First-party code MUST serialize JSON with `sonic-rs`.
- `serde_json` is denied with exactly four third-party `wrappers`.
- The wrappers are `corepc-types` for Bitcoin Core v31 RPC result models.
- The wrappers include `tracing-subscriber` for the node JSON log format.
- The wrappers include `usdt-impl` with `dof` for the optional USDT probe path.
- A direct dependent outside that list fails `cargo deny check bans` with `error[banned]`.
- This restriction applies to all workspace crates.
- A new third-party path to `serde_json` requires an explicit edit to this list.
- The root workspace graph is the ban scope.
- The spike workspaces under `tools/ldk` and `tools/stratum-sv2/template-provider` are separate cargo workspaces with their own lockfiles.
- `deny.toml` does not cover those spike workspaces.
- Their only `serde_json` edges are third-party: `corepc-types`, `tracing-subscriber`, and `config` in the template provider.
- No first-party crate in those workspaces names `serde_json`.
- Wall-clock time MUST come from `std::time`.
- Monotonic timing MUST come from `quanta`.
- Calendar types MUST come from `jiff`.
- `chrono`, `chrono-tz`, and `time` are denied.
- All three crates are absent from the resolved graph today.
- These entries are forward guards against accidental transitive dependencies.
- `sonic-rs` enables `sort_keys` in the root `Cargo.toml`.
- This setting keeps serialized output of constructed values in sorted key order.
- Therefore, a digest over serialized value bytes is stable across runs.
- Durable formats MUST come from typed structs, never from a mutated value tree.

## License and source rules
- Licenses are allow-listed in `deny.toml` `[licenses]` (MIT, Apache-2.0 including the LLVM exception, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Unicode-DFS-2016, Zlib, CC0-1.0, 0BSD, MPL-2.0).
- Two version-scoped exceptions are approved: `hex_lit@0.1.1` (MITNFA) and `xxhash-rust@0.8.19` (BSL-1.0).
- Sources for the root workspace lockfile are restricted to the crates.io registry by `deny.toml` `[sources]`.
- Unknown registries and git sources are denied.
- The `deny` job in `ci.yml` owns the full `cargo deny check` (advisories, bans, licenses, sources).
- The DEP-01 lanes run `check bans` only.

## Selected range prerequisites
- `bytes` is bounded at `>=1.11.1, <2`. SurrealKV requires `bytes 1.11.1` or later.
- `smallvec` is bounded at `>=1.15.2, <2`. `parking_lot_core 0.10.0` requires `smallvec 1.15.2` or later.
- The root lock uses `lz4_flex 0.12.3` through SurrealKV. `deny.toml` `[bans].skip` exempts that exact version; `lz4_flex 0.13.1` through Fjall and `lsm-tree` remains unskipped. Neither version is a direct workspace dependency.
- `windows-link 0.100.0` comes from `generator 0.8.12` through `windows-core 0.100.0`. `deny.toml` `[bans].skip` exempts `0.100.0`; `0.2.1` remains unskipped.
- `bitcoin_hashes 1.2.0` requires `bitcoin-internals 0.6.0` directly and `bitcoin-internals 0.7.0` through `bitcoin-consensus-encoding 1.3`; only that exact-version split is approved, with `deny.toml` `[bans].skip` pinning `bitcoin-internals@0.6.0`.
- `base64` is bounded to `>=0.23.1, <0.24` with defaults disabled and `std` (including `alloc`) enabled.
- `simd-unsafe` remains disabled.
- `secp256k1` is bounded to `>=0.33.1, <0.34` with `std`, `alloc`, `recovery`, `rand`, and `global-context` enabled. Bitcoin's exact `secp256k1 0.29.100` and `secp256k1-sys 0.10.1` reference line is an approved split, pinned in `deny.toml` `[bans].skip`; it approves no other version.
- The root, fuzz, LDK, and SV2 template-provider lockfiles use the same `secp256k1 0.29.100` reference line. BIP324 key exchange uses its `Party` API.
- The metrics exporter's `base64 0.22.1` is an approved exact-version duplicate, not approval for other versions.
- `proptest` is bounded at `>=1.12, <1.13` and `proptest-state-machine` is pinned at `=0.9.0` in the root `Cargo.toml` `[workspace.dependencies]`.
- Version `1.12` moves to the `rand_core 0.10` and `rand_xorshift 0.5` family, so the lock carries `rand_core@0.10.1` beside `rand_core@0.9.5` from the selected `rand 0.9` family.
- That `rand_core` pair is an approved exact-version split. It approves no other `rand` family change.
- `parking_lot` is bounded at `>=0.13.0, <0.14`. Transitive crates on the `0.12` line (`rust-rocksdb`, `signet-libmdbx`, `surrealkv`, `quick_cache`, `affinitypool`) keep `parking_lot@0.12.5`, with its `parking_lot_core@0.9.12` and `lock_api@0.4.14`.
- That `parking_lot`/`parking_lot_core`/`lock_api` pair with the `0.13`/`0.10`/`0.5` lines is an approved exact-version split. It approves no other `parking_lot` family change.
- The `syn@3.0.10` exception in `deny.toml` `[bans]` is an exact-version pin for the proc-macro chain.
- When the `syn 3.0.x` patch in the root or `fuzz` lock moves, update the exception to that exact version in the same change.
- The entry describes this `syn` pin only.
- It does not approve other splits.
- The minimal lane resolves `bitcoin` 0.32.9, which retains `bitcoin-internals` 0.3.0 beside 0.6.0 and 0.7.0; only that exact-version split is approved, with `deny.toml` `[bans].skip` pinning `bitcoin-internals@0.3.0`.
- The minimal all-features lane resolves `object` 0.39.1 through `ar_archive_writer` in the USDT probe chain and `object` 0.40.0 through `backtrace` in minimized `tokio`. `deny.toml` `[bans].skip` exempts only `0.39.1`; `0.40.0` remains the unskipped anchor.
- The `secp256k1@0.28.2`, `secp256k1-sys@0.9.2`, and `bitcoin_hashes@0.13.1` exceptions in `deny.toml` `[bans]` are exact-version pins for the `noise_sv2 2.1.0` SV2 chain.
- This policy matches the `syn` pin above, including their RustCrypto transport companions.
- When the pinned SRI release family moves, update those exceptions to the exact resolved versions in the same change.
- The entries approve no other split.

## Verification boundaries

Cargo manifests, lockfiles, cargo-deny, the workspace dependency-direction gate, and capability-compile fixtures exercise dependency and feature policy.
Separate tool workspaces retain their own checks.
The listed lockfile versions and dependency owners describe the checked-in graph. They do not establish a passing range endpoint. Each new minimum or maximum resolution requires the complete DEP-01 compile and bans result for that revision.
Compilation does not establish runtime or interoperability behavior.

## Feature matrix

Named supported combinations only, not the powerset.
Empty backend markers on non-storage crates are not combinations.

### `FEAT-01`: Named supported combinations
- Owner: `scripts/feature-matrix.tsv`.
- Scope: operator `bitcoin-rs` and `bitcoin-rs-node` backend and kernel flags plus reached storage and consensus crates.
- Each row is one combination CI MUST `cargo check` independently.
- The `pure` lane covers engine-free crates such as `bitcoin-rs-consensus` (`--no-default-features`, and `--features usdt`).
- These consensus rows check only the library target. Their test dependencies require the RocksDB native prerequisites.
- Proof: `scripts/check-feature-matrix.sh pure` executes the `consensus-native` and `consensus-usdt` rows in `scripts/feature-matrix.tsv` with `--lib`; the `feature-combinations` pure job in `.github/workflows/compatibility-campaign.yml` skips `.github/actions/native-deps`.
- The `native` lane checks all consensus targets for both combinations and runs the feature-off and feature-on `sdt_notes` tests.
- Proof: `scripts/check-feature-matrix.sh native` executes the `consensus-native-tests` and `consensus-usdt-tests` rows after native prerequisites, and `.github/workflows/compatibility-campaign.yml` runs `crates/consensus/sdt_notes_tests.rs::embedded_sdt_notes_match_core_layout` for both feature-off and feature-on builds.
- `lane=native` requires cmake, libboost (kernel), or C storage engines.
- Kernel rows (`portable-kernel`, `full-node`, `consensus-kernel`) are capability builds with `kernel` compiled in.
- Engine selection stays runtime via `validation.engine`.
- The `bitcoin-rs-node` crate default (`zmq`) is a native row.
- The checker selects the repository-root workspace from nested workspaces such as `fuzz/`.
- Adding a Cargo feature is not enough.
- Add a row here in the same commit, or do not add the feature.

### `FEAT-02`: Backend forwarding follows `ARCH-03`
- Ownership and forwarding are governed by `ARCH-03` ([architecture.md](architecture.md)).
- Layer 0 and RPC, `mempool` and `mining` MUST NOT define backend feature names.
- Forwarding is limited to storage, approved service adapters, and operator-facing entry points.
- G17 enforces this rule.
- Empty backend markers are not combinations.
- The matrix lists none.
- Owner: `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs` via `bin/bitcoin-rs/tests/support/dependency_graph.rs`.
- Proven by `scripts/check-feature-matrix.sh` in the `compatibility-campaign.yml` `feature-combinations` job.
- Proven by `scripts/tests/test_feature_matrix.py` for root and nested resolution and offline regression.
- Proven by `cargo test -p bitcoin-rs --test suite g17_dependency_direction::`.
