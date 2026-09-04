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
BIP22/BIP23 JSON projection lives in RPC. Long-poll waiting, generate
assemble-solve-submit, and block submission live in the node-owned
coordinator that implements `MiningControl`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
