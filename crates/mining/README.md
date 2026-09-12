# bitcoin-rs-mining

Transport-neutral block-candidate assembly for solo mining.

`assemble_candidate` builds a [`Candidate`](crate::Candidate) from a
[`CandidateContext`](crate::CandidateContext) and a mempool mining snapshot.
The `policy` module selects dependency-closed packages by modified fee rate
within weight, serialized-size, and sigop limits. It consumes the snapshot's
ancestor lists and consensus `is_final_tx`; it does not re-validate the
mempool DAG. The `coinbase` module funds
the coinbase (subsidy plus actual fees) and, when `SegWit` is active, attaches the
witness commitment through consensus `compute_merkle_root` (the same AVX2/spine
fold block rules use).
[`Candidate::solve`](crate::Candidate::solve) turns that candidate into a header
that meets its compact target. Failures surface as [`MiningError`](crate::MiningError).

The crate owns the domain `Candidate`, [`Candidate::solve`](crate::Candidate::solve),
and the node-facing mining contract ([`MiningControl`](crate::MiningControl),
[`BlockTemplate`](crate::BlockTemplate), [`MiningInfo`](crate::MiningInfo),
[`MiningControl::generate`](crate::MiningControl::generate)).
BIP22/BIP23 JSON projection follows the [API-07 contract](../../docs/contracts/external-api.md#api-07-bip22bip23-template-extras).
The [`coordinator`](crate::coordinator) module owns the candidate lifecycle:
generation keys, the bounded template cache with single-flight assembly, and
long-poll publication, driven by [`MiningService`](crate::MiningService) over
node-supplied capability sources. Generate assemble-solve-submit, block
submission, and header-only admission (`submitheader` via `accept_headers`)
live in the node-owned coordinator that implements `MiningControl`.

`cargo bench -p bitcoin-rs-mining --bench candidate` times `assemble_candidate`
against pre-captured snapshots. It is a measurement seam, not a budget.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
