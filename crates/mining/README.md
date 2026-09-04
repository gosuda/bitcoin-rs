# bitcoin-rs-mining

Transport-neutral block-candidate assembly for solo mining.

`assemble_candidate` builds a [`Candidate`](crate::Candidate) from a
[`CandidateContext`](crate::CandidateContext) and a mempool mining snapshot.
The `policy` module selects dependency-closed packages by modified fee rate
within weight, serialized-size, and sigop limits. The `coinbase` module funds
the coinbase (subsidy plus actual fees) and, when `SegWit` is active, attaches the
witness commitment. [`Candidate::solve`](crate::Candidate::solve) turns that
candidate into a header that meets its compact target. Failures surface as
[`MiningError`](crate::MiningError).

The crate owns the domain `Candidate`, [`Candidate::solve`](crate::Candidate::solve),
and the node-facing mining contract ([`MiningControl`](crate::MiningControl),
[`BlockTemplate`](crate::BlockTemplate), [`MiningInfo`](crate::MiningInfo),
[`MiningControl::generate`](crate::MiningControl::generate)).
BIP22/BIP23 JSON projection lives in RPC: `submitold` after a long-poll wait,
`signet_challenge` on signet, and capabilities `proposal` plus `longpoll`.
Long-poll waiting, generate assemble-solve-submit, block submission, and
header-only admission (`submitheader` via `accept_headers`) live in the
node-owned coordinator that implements `MiningControl`.

## Features
- `rocksdb`: forwarding marker for the rocksdb storage backend; gates no code in
  this crate.
- `fjall`: forwarding marker for the fjall storage backend; gates no code in this
  crate.
- `redb`: forwarding marker for the redb storage backend; gates no code in this
  crate.
- `mdbx`: forwarding marker for the mdbx storage backend; gates no code in this
  crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
