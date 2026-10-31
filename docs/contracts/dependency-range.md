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

### `DEP-02`: One copy of each consensus-stack crate
- **Owner**: `deny.toml` `[bans]`.
- **Scope**: the resolved graph of each DEP-01 lane.
- Check both lanes under `deny.toml` `[graph]` with `all-features = true`, not each lane's own feature set.
- Scope covers `bitcoin`, `bitcoin_hashes`, `secp256k1`, and `secp256k1-sys`.
- Each of those crates MUST resolve to exactly one version per graph.
- Exactly one pool-only exception is approved.
- The pinned SRI release family is `noise_sv2 2.0.0`.
- The `pool-sv2` feature in `crates/mining/Cargo.toml` reaches this family.
- This family carries its own audited `secp256k1 0.28.2` and `secp256k1-sys 0.9.2` authority-key line.
- This family also carries its own `bitcoin_hashes 0.13.1` transport line.
- `deny.toml` `[bans].skip` pins those exact versions with the `noise_sv2 2.0.0` reason.
- `multiple-versions = "deny"` fails any other second version.
- No further skip is approved for these four names.
- The skip entries are audited splits.
- Each entry leaves one unskipped anchor, so a new version of a skipped crate fails.
- Package-id cardinality beyond one version per name is not checked mechanically.
- Lockfile review pins that cardinality.
- The Noise-family dependencies in `crates/mining/Cargo.toml` are optional normal dependencies.
- The `pool-sv2` feature enables these dependencies.
- Cargo forbids `optional` dev-dependencies.
- Cargo does not honor `cfg(feature)` in target dev tables.
- Therefore, the default-feature maximum-lane graph never resolves the exception chain.
- Only the `--all-features` minimal-lane graph resolves the chain.
- The exact-version skips above apply in that lane.
- Only the `pool-sv2`-gated SV2 module and its tests use these dependencies.
- Range-endpoint graphs are in scope.
- `cargo deny check bans` runs after each DEP-01 resolve.
- Missing cargo-deny is a failed prerequisite, not a skip.

### `DEP-03`: One JSON stack and one time stack
- **Owner**: `deny.toml` `[bans]`.
- First-party code MUST serialize JSON with `sonic-rs`.
- `serde_json` is denied with exactly six third-party `wrappers`.
- The wrappers are `corepc-types` for Bitcoin Core v31 RPC result models.
- The wrappers include `tracing-subscriber` for the node JSON log format.
- The wrappers include `criterion` with `tinytemplate` for the bench harness.
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
- `proptest` is bounded at `>=1.11, <1.12` in the root `Cargo.toml` `[workspace.dependencies]`.
- Version `1.12` moves to the `rand_core 0.10` and `rand_xorshift 0.5` family.
- The bound retains the selected `rand 0.9` family used elsewhere.
- The `syn@3.0.9` exception in `deny.toml` `[bans]` is an exact-version pin for the proc-macro chain.
- When the `syn 3.0.x` patch in the root or `fuzz` lock moves, update the exception to that exact version in the same change.
- The entry describes this `syn` pin only.
- It does not approve other splits.
- The `secp256k1@0.28.2`, `secp256k1-sys@0.9.2`, and `bitcoin_hashes@0.13.1` exceptions in `deny.toml` `[bans]` are exact-version pins for the `noise_sv2 2.0.0` SV2 chain.
- This policy matches the `syn` pin above, including their RustCrypto transport companions.
- When the pinned SRI release family moves, update those exceptions to the exact resolved versions in the same change.
- The entries approve no other split.

## Verification boundaries

Cargo manifests, lockfiles, cargo-deny, the workspace dependency-direction gate, and capability-compile fixtures exercise dependency and feature policy.
Separate tool workspaces retain their own checks.
Compilation does not establish runtime or interoperability behavior.

## Feature matrix

Named supported combinations only, not the powerset.
Empty backend markers on non-storage crates are not combinations.

### `FEAT-01`: Named supported combinations
- Owner: `scripts/feature-matrix.tsv`.
- Scope: operator `bitcoin-rs` and `bitcoin-rs-node` backend and kernel flags plus reached storage and consensus crates.
- Each row is one combination CI MUST `cargo check` independently.
- `lane=pure` carries fjall, redb, zmq, and optional `silent-payments` with the native interpreter.
- `lane=native` requires cmake, libboost (kernel), or C storage engines.
- Kernel rows (`portable-kernel`, `full-node`, `consensus-kernel`) are capability builds with `kernel` compiled in.
- Engine selection stays runtime via `validation.engine`.
- The `bitcoin-rs-node` crate default (`fjall,zmq`) is a pure row.
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
