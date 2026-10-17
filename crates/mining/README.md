# bitcoin-rs-mining

Transport-neutral block-candidate assembly for solo mining.

`assemble_candidate` builds a [`Candidate`](crate::Candidate) from a
[`CandidateContext`](crate::CandidateContext) and the live mempool.
The `policy` module selects dependency-closed packages by modified fee rate
within weight, serialized-size, and sigop limits. It walks the pool owner's
maintained chunk index under the caller's read guard and copies only the
selected transactions; it does not re-validate the mempool DAG. The `coinbase` module funds
the coinbase (subsidy plus actual fees) and, when `SegWit` is active, attaches the
witness commitment through consensus `compute_merkle_root` (the same AVX2/spine
fold block rules use).
[`into_unsolved_block`](crate::Candidate::into_unsolved_block) turns that candidate
into a block whose header has a zero nonce, and [`solve_block`](crate::solve_block) searches
nonces until the header meets its compact target. Failures surface as
[`MiningError`](crate::MiningError).

Each non-coinbase transaction in a candidate is represented as a
[`CandidateTransaction`](crate::CandidateTransaction). During candidate
assembly, `CandidateTransaction` precomputes the canonical consensus
serialization as lowercase hex (`data_hex`) once, after releasing the pool
read lock. RPC template rendering reuses `data_hex` directly without
re-serializing transactions on cache hits, while retaining the underlying
`Arc<Tx>` for block solving and submission.

The crate owns the domain `Candidate`, [`solve_block`](crate::solve_block),
and the node-facing mining contract ([`MiningControl`](crate::MiningControl),
[`BlockTemplate`](crate::BlockTemplate), [`MiningInfo`](crate::MiningInfo),
[`MiningControl::generate`](crate::MiningControl::generate)).
BIP22/BIP23 JSON projection follows the [API-07 contract](../../docs/contracts/external-api.md#api-07-bip22bip23-template-extras).
[`MiningService`](crate::MiningService) owns the candidate lifecycle:
generation keys, the bounded template cache with single-flight assembly, and
long-poll publication over node-supplied capability sources. Generate assemble-solve-submit, block
submission, and header-only admission (`submitheader` via `accept_headers`)
live in the node-owned coordinator that implements `MiningControl`.

Generation identity includes the applied hash and both pool-owned membership
and fee-delta revisions. Capture, selection gating and post-assembly checks
compare both revisions; prioritisation leaves the public membership sequence
unchanged. After a fee change the RPC path publishes the fee-delta generation,
which invalidates the cached candidate and wakes long polls. The membership
observer still takes no pool read lock and carries no fee-only mutation event:
it invalidates the previous membership generation and the next template read
captures both live pool revisions.
Long-poll IDs retain `hash<sequence>` at fee revision zero, otherwise append
`:<fee_revision>`. Both forms are accepted; legacy IDs imply fee revision zero.

## Projected selection and template preparation

During durable block synchronization, the node stages prospective tip blocks to
[`MiningService`](crate::MiningService). The service runs a bounded worker
with at most one active preparation and one pending newest staged job:

- **Projected selection**: A single removal-plan owner
  (`plan_block_removals`) derives resident block inclusions and conflict
  descendants. Projected selection (`chunks_after`) relinearizes only the
  clusters touched by the plan on the side, without mutating pool state or
  cloning untouched entries. It borrows the mempool under a single read guard
  and runs the same package selection rules as live assembly.
- **Finishing outside the pool lock**: Candidate finishing (`finish_candidate`),
  including transaction mapping and coinbase commitment generation, executes
  outside the mempool read lock.
- **Exact receipt and generation install**: Installation into the template
  cache requires an authoritative committed receipt for the exact tip matching
  all planned transaction IDs and removal reasons, the predicted wrapping
  membership sequence advance (one count per removal), the predicted fee
  sequence, and the live generation key. Projections never advance the applied
  tip or durable head.
- **Foreground joining**: Matching foreground template requests for the staged
  tip join the running preparation rather than duplicating assembly. When the
  predicted generation matches, a foreground waiter parks on the internal
  condition variable until the committed receipt arrives.
- **Stale fallback and shutdown**: If concurrent transactions, prioritisation,
  or chain reorgs move the generation key, or if the receipt mismatches, the
  preparation is discarded and the request falls back to lazy live assembly.
  Node shutdown stops the worker, wakes waiters, and answers requests as
  unavailable without publishing speculative candidates.
- **Signalling snapshot**: Available versionbit deployments are cached in a
  single snapshot keyed by candidate tip hash and height. Cache hits serve the
  stored rules under the coordinator state lock, while misses resolve outside
  the state lock before installing, avoiding lock coupling with the chain tree
  and invalidating automatically when the tip moves.

`cargo bench -p bitcoin-rs-mining --bench candidate` times `assemble_candidate`
against live fixture pools. It is a measurement seam, not a budget.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
