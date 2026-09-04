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

The crate stops at the domain `Candidate` and the solved `Block` it produces.
BIP22/BIP23 JSON projection, long-poll waiting, and block submission live
behind the node-owned `MiningControl` surface consumed by RPC — they are not
part of this crate.

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
