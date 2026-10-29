# Dependency range contract
Declared Cargo ranges are the versions this workspace claims to support. The committed `Cargo.lock` is one point inside that range, not the contract.
## Clauses
### `DEP-01`: Minimum and maximum resolvable versions compile
- **Owner**: `scripts/check-dep-range.sh`.
- **Scope**: every direct workspace dependency declared in the root `Cargo.toml` `[workspace.dependencies]` table.
- `minimal` resolves each direct dependency at its oldest allowed version (`cargo +nightly update -Zdirect-minimal-versions`) and checks the workspace graph with all targets and all features enabled (`--all-targets --all-features`).
- `maximum` resolves every crate to the newest version still inside its declared range (`cargo update`), checks the default-feature workspace graph with all targets (`--all-targets`), and runs one explicit kernel-enabled check (`-p bitcoin-rs-node --all-targets --features kernel`) so the optional C++ engine still sees its newest allowed versions.
- Both lanes run `cargo deny check bans` against the mutated lockfile. The `minimal` lane enables every feature, so it compiles the optional native storage engines at the oldest resolve. The named combinations themselves are owned by `FEAT-01`.
- Both lanes mutate `Cargo.lock`. The script copies it aside and restores it on exit unless `KEEP_LOCK=1`, so local runs need no disposable checkout; the scheduled compatibility workflow still uses a disposable runner. They are not pull-request merge gates.
### `DEP-02`: One copy of each consensus-stack crate
- **Owner**: `deny.toml` `[bans]`.
- **Scope**: the resolved graph of each DEP-01 lane, checked under `deny.toml` `[graph]` `all-features = true` in both lanes (not the lane's own feature set), for `bitcoin`, `bitcoin_hashes`, `secp256k1`, and `secp256k1-sys`.
- Each of those crates resolves to exactly one version per graph, with one approved pool-only exception: the pinned SRI release family (`noise_sv2 2.0.0`, reachable only through the `pool-sv2` feature in `crates/mining/Cargo.toml`) carries its own audited `secp256k1 0.28.2` / `secp256k1-sys 0.9.2` authority-key line and `bitcoin_hashes 0.13.1` transport line. Those exact versions are pinned in `deny.toml` `[bans].skip` with the `noise_sv2 2.0.0` reason; `multiple-versions = "deny"` still fails any other second version, and no further skip for these four names is approved. The skip entries are audited splits; each leaves one unskipped anchor, so a new version of a skipped crate still fails. Package-id cardinality beyond one version per name is not mechanically checked; lockfile review pins it.
- Pool-only SRI crates (the Noise-family dependencies in `crates/mining/Cargo.toml`) are optional normal dependencies enabled by the existing `pool-sv2` feature. Cargo forbids `optional` dev-dependencies and does not honor `cfg(feature)` in target dev tables, so the default-feature (maximum-lane) graph never resolves the exception chain; only the `--all-features` (minimal-lane) graph does, where the exact-version skips above apply. Only the `pool-sv2`-gated SV2 module and its tests use them.
- Range-endpoint graphs are in scope: `cargo deny check bans` runs after each DEP-01 resolve. Missing cargo-deny is a failed prerequisite, not a skip.
### `DEP-03`: One JSON stack and one time stack
- **Owner**: `deny.toml` `[bans]`.
- First-party code serializes JSON with `sonic-rs`. `serde_json` is denied with exactly six third-party `wrappers`: `corepc-types` (Bitcoin Core v31 RPC result models), `tracing-subscriber` (the node's JSON log format), `criterion` with `tinytemplate` (the bench harness), and `usdt-impl` with `dof` (the optional USDT probe path). A direct dependent outside that list, including any workspace crate, fails `cargo deny check bans` with `error[banned]`; a new third-party path to `serde_json` therefore needs an explicit edit to this list.
- The root workspace graph is the ban's scope. The spike workspaces under `tools/ldk`
  and `tools/stratum-sv2/template-provider` are separate cargo workspaces with their
  own lockfiles, so `deny.toml` does not cover them; their only `serde_json` edges are
  third-party (`corepc-types`, `tracing-subscriber`, and `config` in the template
  provider), and no first-party crate there names the crate.
- Wall-clock time comes from `std::time`, monotonic timing from `quanta`, and a calendar type would come from `jiff`. `chrono`, `chrono-tz`, and `time` are denied. All three are absent from the resolved graph today, so these entries are forward guards that make a second time stack a deliberate, reviewed change rather than a transitive accident.
- `sonic-rs` enables `sort_keys` in the root `Cargo.toml`, which keeps serialized output of constructed values in sorted key order, so a digest over serialized value bytes is stable across runs. Durable formats still come from typed structs, never from a mutated value tree.
## License and source rules
- Licenses are allow-listed in `deny.toml` `[licenses]` (MIT, Apache-2.0 including the LLVM exception, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Unicode-DFS-2016, Zlib, CC0-1.0, 0BSD, MPL-2.0), with two version-scoped exceptions: `hex_lit@0.1.1` (MITNFA) and `xxhash-rust@0.8.19` (BSL-1.0).
- Sources for the root workspace lockfile are restricted to the crates.io registry by `deny.toml` `[sources]`; unknown registries and git sources are denied.
- The full `cargo deny check` (advisories, bans, licenses, sources) is owned by the `deny` job in `ci.yml`; the DEP-01 lanes run `check bans` only.
## Selected range prerequisites
- `proptest` is bounded at `>=1.11, <1.12` in the root `Cargo.toml` `[workspace.dependencies]`. Version `1.12` moves to the `rand_core 0.10` and `rand_xorshift 0.5` family; the bound retains the selected `rand 0.9` family used elsewhere.
- The `syn@3.0.9` exception in `deny.toml` `[bans]` is an exact-version pin for the proc-macro chain. When the `syn 3.0.x` patch in the root or `fuzz` lock moves, update the exception to that exact version in the same change. The entry describes this pin only; it does not approve other splits.
- The `secp256k1@0.28.2`, `secp256k1-sys@0.9.2`, and `bitcoin_hashes@0.13.1` exceptions (with their RustCrypto transport companions) in `deny.toml` `[bans]` are exact-version pins for the `noise_sv2 2.0.0` SV2 chain, like the `syn` pin above. When the pinned SRI release family moves, update those exceptions to the exact resolved versions in the same change. The entries approve no other split.
## Proven by
- `scripts/check-dep-range.sh minimal` and `scripts/check-dep-range.sh maximum` (`compatibility-campaign.yml` `dependency-range` job).
- `cargo deny check bans` (`deny.toml` `[bans] multiple-versions = "deny"`).
