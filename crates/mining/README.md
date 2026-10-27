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
BIP22/BIP23 JSON projection follows the [API-11 contract](../../docs/contracts/external-api.md#api-11-bip22bip23-template-extras).
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

## Coinbase-budgeted templates

A consumer that rebuilds the coinbase, such as a Stratum V2 pool, asks for room
instead of refusing a body that left none. [`BlockTemplateRequest::coinbase_budget`](crate::BlockTemplateRequest::coinbase_budget)
carries a [`CoinbaseBudget`](crate::CoinbaseBudget): the serialized bytes
(`additional_size`) and BIP141 sigop cost (`additional_sigops`, already in
cost units and never rescaled) of the outputs it will add. `None` is the
ordinary template: selection, identity, long-poll id, reporting, and every
existing caller are unchanged. Only template mode on the typed `MiningControl`
surface carries a budget; `generate`, proposals, and the BIP22/BIP23 JSON
surface never do.

- **One rule, derived from the owner's coinbase.** The same selector
  (`select_packages`) serves ordinary, prepared, and budgeted selection. A
  budget adds *growth* to its starting totals: `additional_size`, the scriptSig
  headroom to the 100-byte consensus limit, and the extra `CompactSize` width the
  output count may need (at least 9 bytes per output bounds how many outputs
  `additional_size` buys, so the width is derived, not assumed). Every grown
  byte is non-witness, so weight growth is four times size growth. The sigop
  allowance and worst-case input growth (80 cost units per added byte) are
  added to the coinbase's own sigop cost, which stays in the fixed
  reservation. The header, transaction count, and owner coinbase are counted
  once, and `Candidate.weight` is always the real block weight: the growth is
  held back from the limits, never included in the block. The owner payout
  output stays counted although a consumer that replaces it needs less, a
  deliberate conservative slack.
- **Empty infeasibility.** When the empty block cannot hold the growth, the
  selector fails before reading any chunk with `MiningError::CapacityExhausted`
  naming the first of weight, size, and sigops. The facade reports it as the
  existing `MiningControlError::Failed`, which is terminal for that budget.
  `Some(0, 0)` still reserves the coinbase's growth, so it is not `None`.
- **One fit rule.** [`Candidate::admits`](crate::Candidate::admits) applies the
  same check to a finished candidate from its actual weight, serialized size,
  and sigop cost (coinbase included) plus the growth derived from its own
  coinbase. A tight feasible pool therefore gets a body the selector chose to
  fit, rather than a candidate refused after selection.
- **Identity.** A cached candidate is keyed by generation and budget. A
  budgeted candidate's `template_id` appends `@cb<size>.<sigops>` to the
  generation id; ordinary ids stay byte-identical. A long-poll id may carry the
  qualifier, which parses strictly (canonical decimals, exact grammar) and is
  then dropped: waiting compares generations, and the budget of the template
  served next comes from the request.
- **Reuse is an optimisation, not a claim.** A budgeted request is answered by
  the exact cached candidate, else by the generation's ordinary candidate (the
  cached one, or a finished preparation that already holds its committed
  receipt, installed without waiting) when it `admits` the budget, else by one
  selection under the budget. The returned `template_id` says which. Nothing is
  promised about how a budgeted body relates to the ordinary one: a greedy walk
  under tighter limits may skip a large early chunk and take different later
  ones. A fresh budgeted walk never assembles an ordinary candidate. A
  budgeted request never compares a budgeted id against a preparation;
  a budgeted request that tries to reuse the generation's ordinary
  candidate from a finished preparation checks only the ordinary
  generation, and a mismatch there discards the stale preparation
  without serving it.
  A budgeted assembly that installs under the live generation reports its candidate in `last_candidate`.
- **Finite owner admission.** At most one budgeted selection walks the pool at a
  time, beside the ordinary single flight, which neither waits for it nor
  displaces it. Publication drops the old generation's cached candidates of
  every budget but never frees the slot while its assembler runs; the
  assembler's guard releases it on every exit, including unwinding, and an
  install for a generation that is no longer live is refused under the
  coordinator mutex. A caller behind the slot waits at most one second per
  attempt and at most eight attempts per call, re-running the cache and reuse
  lookups on each wake and ending at the next wake after shutdown. Exhaustion
  is `Unavailable` and classified retryable by
  [`MiningControlError::is_template_generation_race`](crate::MiningControlError::is_template_generation_race),
  like a generation race. Nothing promises progress under endless generation
  churn or contention; each call starts afresh.
- **Memory.** The cache bounds entries (eight, shared by every budget), not
  memory. A candidate owns its transactions and their hex, and the `Arc`s served
  to callers, or reused from the ordinary slot, stay alive after eviction for as
  long as their holders keep them.

Consistency: selection reads the pool under one guard (snapshot isolation);
cache publication, installs, and slot hand-off are linearizable under the
coordinator mutex. Repeated identical requests and notifications are idempotent.

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
