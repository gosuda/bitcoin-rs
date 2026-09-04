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
  workspace.
- `maximum` resolves every crate to the newest version still inside its
  declared range (`cargo update`) and checks the workspace.
- Both lanes mutate `Cargo.lock`. They run on `main` only, never on a
  pull-request checkout.

### `DEP-02`: One copy of each consensus-stack crate

- **Owner**: `bin/bitcoin-rs/tests/gates/g20_unique_consensus_crates.rs`.
- **Scope**: the resolved graph for `bitcoin`, `bitcoin_hashes`,
  `secp256k1`, and `secp256k1-sys`.
- Each of those crates must appear at exactly one version. `deny.toml`
  `multiple-versions = "deny"` is the graph-wide companion; those four
  names must not gain a `skip` entry.

## Proven by

- `scripts/check-dep-range.sh minimal` and
  `scripts/check-dep-range.sh maximum` (main workflow `dependency-range`
  job).
- `cargo test -p bitcoin-rs --test g20_unique_consensus_crates`.
- `cargo deny check` (`deny.toml` `[bans] multiple-versions = "deny"`).
