# bitcoin-rs-consensus

Owns consensus validation: transaction and block rule checks for every active soft fork.
Script verification has two backends. The native Rust interpreter executes every
consensus spend class; the `kernel` feature compiles bitcoinkernel — Bitcoin
Core's C++ consensus engine — in alongside it. `kernel` is a capability, not a
selection: which backend runs is the runtime `validation.engine` setting
(`ValidationEngine`, default `Native`, `VAL-01`). Every crate is kernel-free by
default, so `cargo build -p bitcoin-rs` needs no C++ toolchain and uses the
native interpreter; see [`docs/contracts/validation-default.md`](../../docs/contracts/validation-default.md).

Rule checks live in `verify_tx` and `verify_block` with per-subject helpers
(`bip9`, `bip30`, `bip34`, `bip68`, `bip113`), surfaced through the
`verify_transaction` family (with median-time-past and borrowed variants),
`is_final_tx`, and the `verify_block_rules` family including Merkle-root verification.
`compute_merkle_root` is the sole pairwise SHA-256d fold (AVX2 or spine) used by
block rules, witness-commitment checks, and mining candidate assembly.
`kernel::BlockParse` parses a serialized block exactly once — through the Rust
layout parse under `validation.engine = "native"`, or `bitcoinkernel::Block::new`
under `validation.engine = "kernel"` on `kernel`-feature builds — yielding the
txids and (on the kernel arm) the borrowed transaction objects that script
preparation reuses. `kernel::verify_tx_scripts` dispatches per-input script
checks to the selected backend over its resolved `(OutPoint, TxOut)`
`spent_outputs` rows. BIP9 activation is
`compute_state`
over a `DeploymentContext` with `DeploymentParams`. Consensus bounds are exported as
`MAX_SCRIPT_SIZE`, `MAX_BLOCK_SIGOPS_COST`, `MAX_BLOCK_WEIGHT`, and
`MAX_BLOCK_SERIALIZED_SIZE`; failures are `ConsensusError`
variants.

## Features
- `kernel` (off by default): compiles [bitcoinkernel](../../CONCEPTS.md#bitcoinkernel)
  support in. Selection is the runtime `validation.engine` setting (`native` by
  default); the feature alone never routes checks to the kernel.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
