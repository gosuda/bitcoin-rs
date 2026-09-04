# bitcoin-rs-primitives

The fixed-layout consensus primitives the rest of the workspace speaks in: the
256-bit hash type, transaction outpoints, the compact-size varint codec, and the
transaction, block, and header wrappers with their txid/wtxid and header-hash
computation.

This crate is self-contained with respect to Bitcoin protocol primitives. It
does not depend on `rust-bitcoin` in `[dependencies]` or `[dev-dependencies]`.
Codec, hashing, sighash, network, and identifier contracts are pinned by Core
vectors, published genesis hashes, and golden block fixtures — not by a parallel
type vocabulary.

`Tx`, `TxIn`, and `TxOut` wrap transactions and compute txid/wtxid; `Block` and
`Header` do the same at block level with block-level hashing helpers; `OutPoint` is
the fixed-layout transaction outpoint; and `Hash256` is the fixed-width 256-bit hash
type the wrappers hash into. `encode` holds the consensus encoding and hashing helpers
shared by the primitive wrappers (`Sink`, `ConsensusEncode`, analytic `consensus_size`),
`varint` the Bitcoin compact-size integer codec,
`sighash` the signature-hash mode wrappers (`Sighash`, `SighashError`), and `network`
the Bitcoin network constants re-exported as `Network`. The `version` module publishes
`PKG_VERSION` and `USER_AGENT`, the workspace release constants carried in wire and
RPC user-agent strings.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
