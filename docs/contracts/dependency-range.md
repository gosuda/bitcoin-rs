# Dependency range contract

Declared Cargo ranges are the versions this workspace claims to support.
The committed `Cargo.lock` is one point inside that range, not the
contract.

## Clauses

### `DEP-01`: Minimum and maximum resolvable versions compile

- **Owner**: `scripts/check-dep-range.sh`.
- **Scope**: every direct workspace dependency declared in the root
  `Cargo.toml` `[workspace.dependencies]` table.
- `minimal` resolves each direct dependency at its oldest allowed version
  (`cargo +nightly update -Zdirect-minimal-versions`) and checks the
  workspace graph with all features enabled (`--all-features`).
- `maximum` resolves every crate to the newest version still inside its
  declared range (`cargo update`) and checks the default workspace graph.
- Both lanes run `cargo deny check bans` against the mutated lockfile. The `minimal`
  lane enables every feature, so it compiles the optional native storage
  engines at the oldest resolve. The named combinations themselves are
  owned by `FEAT-01`.
- Both lanes mutate `Cargo.lock`. The scheduled compatibility workflow checks
  out `main` in a disposable runner; local/manual runs need disposable checkouts
  too. They are not pull-request merge gates.

### `DEP-02`: One copy of each consensus-stack crate

- **Owner**: `deny.toml` `[bans]`.
- **Scope**: the resolved graph of each DEP-01 lane — the minimal lane's
  `--all-features` resolve and the maximum lane's default-feature
  resolve — for `bitcoin`, `bitcoin_hashes`, `secp256k1`, and
  `secp256k1-sys`.
- Each of those crates resolves to exactly one version per graph:
  `deny.toml` `multiple-versions = "deny"` fails any second version of
  any crate, and those four names must not gain a `[bans].skip` entry,
  including `crate@version`. Package-id cardinality beyond one version
  per name is not mechanically checked; lockfile review pins it.
- Range-endpoint graphs are in scope: `cargo deny check bans` runs after
  each DEP-01 resolve. Missing cargo-deny is a failed prerequisite, not a skip.

## Selected range prerequisites

- `proptest` is bounded at `>=1.11, <1.12` in the root `Cargo.toml`
  `[workspace.dependencies]`. Version `1.12` moves to the `rand_core 0.10`
  and `rand_xorshift 0.5` family; the bound retains the selected `rand 0.9`
  family used elsewhere.
- The `syn@3.0.9` exception in `deny.toml` `[bans]` is an exact-version pin
  for the proc-macro chain. When the
  `syn 3.0.x` patch in the root or `fuzz` lock moves, update the exception
  to that exact version in the same change. The entry describes this pin
  only; it does not approve other splits.

## Proven by

- `scripts/check-dep-range.sh minimal` and
  `scripts/check-dep-range.sh maximum` (`compatibility-campaign.yml`
  `dependency-range` job).
- `cargo deny check bans` (`deny.toml` `[bans] multiple-versions = "deny"`).
