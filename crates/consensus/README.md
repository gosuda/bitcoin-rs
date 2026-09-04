# bitcoin-rs-consensus

Owns consensus validation: transaction and block rule checks for every active soft fork.
Script verification has two backends. The native Rust interpreter executes every
consensus spend class. The `kernel` feature (the production default in this crate
and in `bitcoin-rs-node`, `VAL-01`) routes the same checks through bitcoinkernel —
Bitcoin Core's C++ consensus engine. The `bin/bitcoin-rs` binary does not enable
`kernel` by default, so `cargo build -p bitcoin-rs` uses the native interpreter.
Issue #213 keeps that split until native wins the signed-spend and full-replay
gates; see [`docs/contracts/validation-default.md`](../../docs/contracts/validation-default.md).

Rule checks live in small per-subject modules (`bip9`, `bip30`, `bip34`, `bip65`,
`bip66`, `bip68`, `bip112`, `bip113`, `bip141`, `bip143`, `bip341`, `bip342`), surfaced
through the `verify_transaction` family (with median-time-past and borrowed variants),
`is_final_tx`, and the `verify_block_rules` family including Merkle-root verification.
`compute_merkle_root` is the sole pairwise SHA-256d fold (AVX2 or spine) used by
block rules, witness-commitment checks, and mining candidate assembly.
`kernel::KernelBlock` parses a serialized block exactly once with
`bitcoinkernel::Block::new`, yielding the txids and borrowed transaction objects that
script preparation reuses, and `kernel::KernelContext::verify_tx` verifies a
transaction's inputs through bitcoinkernel over any `UtxoView`. BIP9 activation is
`compute_state`
over a `DeploymentContext` with `DeploymentParams`. Consensus bounds are exported as
`MAX_SCRIPT_SIZE`, `MAX_MONEY`, and `MAX_BLOCK_SIGOPS_COST`; failures are `ConsensusError`
variants.

## Features
- `kernel` (default): routes script verification through
  [bitcoinkernel](../../CONCEPTS.md#bitcoinkernel)
- `rocksdb`, `fjall`, `redb`: empty in this crate, accepted so workspace-wide feature
  selection does not fail here

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
