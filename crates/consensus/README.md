# bitcoin-rs-consensus

Owns consensus validation: transaction and block rule checks for every active soft fork.
Script verification always runs through the native Rust interpreter for every
consensus spend class. The `kernel` feature compiles bitcoinkernel — Bitcoin
Core's C++ consensus engine — as an independent oracle for differential tests.
It does not replace the apply path. See
[`docs/contracts/validation-default.md`](../../docs/contracts/validation-default.md).

Rule checks live in small per-subject modules (`bip9`, `bip30`, `bip34`, `bip65`,
`bip66`, `bip68`, `bip112`, `bip113`, `bip141`, `bip143`, `bip341`, `bip342`), surfaced
through the `verify_transaction` family (with median-time-past and borrowed variants),
`is_final_tx`, and the `verify_block_rules` family including Merkle-root verification.
`kernel::verify_tx_scripts` and `kernel::KernelBlock` are available under
`--features kernel` so tests can compare Core's parse and script verdicts
against the native path. BIP9 activation is `compute_state`
over a `DeploymentContext` with `DeploymentParams`. Consensus bounds are exported as
`MAX_SCRIPT_SIZE`, `MAX_MONEY`, and `MAX_BLOCK_SIGOPS_COST`; failures are `ConsensusError`
variants.

## Features
- `kernel`: compiles [bitcoinkernel](../../CONCEPTS.md#bitcoinkernel) as an
  independent Core oracle. Off by default.
- `rocksdb`, `fjall`, `redb`: empty in this crate, accepted so workspace-wide feature
  selection does not fail here

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
