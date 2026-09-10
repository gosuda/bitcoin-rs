# Mempool mutations contract

The single mutation gateway in front of the mempool, the records it emits,
and the ZMQ `sequence` mapping built on them. Owners: `MempoolGateway` in
`crates/mempool/src/gateway.rs`; `MutationResult`/`MutationOutcome`/
`RemovalReason`/`MutationEnvelope`/`AdmissionOrigin` in
`crates/mempool/src/mutation.rs`; the ZMQ sequence observer
in `crates/rpc/src/zmq.rs`. The gateway also owns transaction preparation
and retries (`crates/mempool/src/admission.rs`) and its private orphan/reject
state (`crates/mempool/src/orphan.rs`).

## Clauses

### `MPL-01`: Single mutation gateway ordering invariant

- Every production mempool mutation routes through `MempoolGateway`. No
  production code outside the gateway takes the mempool write lock; lookups
  go through `MempoolGateway::read`.
- Every mutating method flows through one path, `commit` (and
  `admit_transaction`, which enqueues the same way), in this exact order:
  1. take the pool write lock,
  2. mutate and assign per-change `mempool_sequence` values, then update
     the gateway's orphan state and mark waiting children ready for parents
     that remain in the committed pool,
  3. while still holding the write lock, enqueue a non-empty
     `MutationEnvelope` on the publish FIFO and elect a drainer if none
     exists,
  4. release the write lock and the publish-state lock,
  5. the elected drainer pops batches one at a time — releasing the
     publish-state lock before every observer call — and returns the
     publish state to idle only once the queue is empty.
- Commits serialize under the write lock and step 3 enqueues under that
  same ownership, so the queue order is the commit order and the sequence
  order. An observer never sees a later-committed batch before, or
  interleaved with, an earlier one.
- Publication is eventual, not synchronous. A nested or concurrent
  mutation enqueues and returns while a drainer exists; its callback may
  run after that call has returned. A slow observer delays later
  publications, not the caller. It can never roll anything back or reorder
  the stream. Sequences were assigned in step 2, so a lagging observer
  still sees a gap-free, ordered stream.
- The observer receives a `&MutationEnvelope` — the committed
  `MutationResult` paired with the `AdmissionOrigin` that identifies how
  the transaction entered the node (`Rpc`, `Peer`, `Reorg`, or `Block`).
  The gateway clones one `MutationResult` into the envelope for each
  committed non-empty batch that has an observer attached, so it can both
  enqueue publication and return the original result to the caller.
  Publication of empty results or with an absent observer enqueues nothing,
  allocates nothing, and spawns no thread. Internal admission-state updates
  do not depend on an observer being present or making progress.
- Observers are best-effort mirrors. Observer errors and panics never
  affect the committed mutation. No gateway lock is held across an
  observer call, so an observer may re-enter the gateway: a nested call
  commits, enqueues, and returns immediately, and its publication
  completes after the in-flight callback. The accepted-mutation mining
  wake threads the last change's sequence into
  `MempoolSequenceWake::publish_generation_from`, which builds the
  generation key from `applied_tip` plus that sequence and never touches
  the mempool read lock (`crates/node/src/mining.rs`); `node` attaches that
  mining observer at gateway construction and the ZMQ sequence observer as
  an extra named leg on the gateway's `CompositeObserver`.

### `MPL-02`: Atomic mutation records and sequence assignment

- Every mutating `Mempool` method returns `MutationResult`: an ordered
  `Vec<MutationChange>`, one change per affected transaction, in commit
  order. Each change carries the txid and a `MutationOutcome`:
  `Accepted`, or `Removed(RemovalReason)`.
- `RemovalReason` is one of `BlockInclusion`, `Conflict`, `Replaced`,
  `Descendant`, `PolicyEviction`, `Expiry`, `Clear`, `Reorg`.
- `Mempool::sequence_number` advances exactly once per emitted change while
  the write lock is held. A failed insert, a no-op removal, and a clear of
  an empty pool assign nothing.

### `MPL-03`: ZeroMQ sequence event payload mapping

- `SequenceEvent::Added(Txid, seq)` publishes label `A` (`0x41`);
  `SequenceEvent::Removed(Txid, seq)` publishes label `R` (`0x52`).
- Body frame for `A`/`R`: reversed txid (32 bytes) + label byte (1) +
  mempool sequence as little-endian u64 (8) = 41 bytes. The transport's own
  4-byte counter stays in its separate trailing frame.
- `BlockInclusion` emits no `R`: the block `C` event covers it. Every other
  removal reason emits `R`. Accepted changes emit `A`. One event per change,
  in commit order.

### `MPL-04`: Generation-validated admission and chain-change fencing

- `MempoolGateway` carries a `chain_generation` atomic counter. Even values
  mean the chain is stable and admission is open; odd values mean a chain
  change (connect, disconnect, or reorg) is in progress and admission is
  closed. `stable_generation()` returns `Some(even)` when stable, `None`
  when a chain change is active.
- `begin_chain_change` takes the pool write lock, stores the next odd value,
  and returns a `ChainChangeGuard` that owns the reservation. The guard has
  no `Drop` that changes generation: dropping or unwinding without an
  explicit `finish` leaves the generation odd — admission stays closed.
  Only `finish` may compare-exchange the odd value to the reserved even value,
  reopening admission. One guard covers one externally coherent chain operation.
- The reorg owner settles both sync branch switches and RPC invalidation.
  A clean refusal finishes at the fully committed disconnect/connect prefix,
  after reconsidering its disconnected transactions under the odd generation.
  Read-only planning or body-loading refusals also leave admission usable.
  `ConnectFailed` caused by `ApplyError::UtxoCommit`, fatal disconnects and
  stuck markers retain the odd generation; reorg must not reconsider
  transactions or checkpoint possibly torn state. A failed `finish` is a
  fatal invariant failure: retain the execution cause, close apply admission
  and request shutdown rather than report success or retry the chain walk.
- `submit_transaction` owns common preparation and four bounded attempts for
  RPC and peer submissions. `preview_transactions` uses the same policy and
  script evaluator, with the same retry bound. Each attempt captures an even
  chain generation and pool sequence before reading chain facts. Preparation
  copies the input outputs under a pool read, then executes scripts without
  any pool or lifecycle lock. The commit writer validates the exact generation
  and sequence, the enforced policy snapshot and all `MempoolLimits`, then the
  resident orphan claim and duplicate identity, before using that verdict.
  Policy values are compared directly because limits can change without a
  membership sequence change; there is no second policy owner or shadow counter.
  Stale approvals and stale rejections both retry with newly resolved facts.
- Preview rechecks generation, sequence and policy before returning all rows.
  It changes no membership, mutation sequence, fee-estimator history, orphan
  or reject state, or observer output. It preserves the documented independent
  row package behavior and earlier-offered output lookup; it is not atomic
  package admission. RPC supplies maximum fee and renders the returned facts.
  The maximum applies only after an admission-valid script result, matching
  Core v31.1's `BroadcastTransaction` and `testmempoolaccept` ordering.
- RPC duplicate submission remains an idempotent success, while preview
  reports `AlreadyInMempool`. Only submission may finalize peer orphan/reject
  state. The writer validates every captured token before either transition.
- Chain facts come through `AdmissionChain` as provisional inputs for a
  submission attempt. The shared borrowed `ChainAdmissionView` in
  `crates/rpc/src/context.rs` reads the existing UTXO and block-tree handles,
  using one captured applied tip for height and MTP. It takes no additional
  chain-transition lock: a stable reader holding that mutex must not spend
  admission's retry budget. Authoritative chain changes are bracketed by
  the gateway's generation fence; exact generation and pool-sequence
  revalidation discards facts read across a change before they can determine
  admission or peer lifecycle results. RPC and node's peer ingress use that
  same view, with no gateway ownership, shadow version, or copied chain-state
  model. A provider may return no snapshot to request a transient retry.
  Peer duplicate suppression uses positive live-coin evidence from
  `UtxoSet::has_live_outputs_for_txid`; no live output leaves confirmation
  status unknown. RPC transaction-body cache membership supplies no such
  evidence.
- Peer orphan/reject transitions validate the same tokens before changing
  state, under pool-then-lifecycle lock order. An accepted parent cannot
  commit between the missing-input verdict and registration of its child.
  The gateway stores orphan bodies, txid/wtxid indexes, parent indexes,
  and ready IDs as one ownership unit. FIFO retention is bounded by both
  count and aggregate BIP141 transaction weight, using `DEFAULT_ORPHAN_QUOTA`
  and `DEFAULT_MAX_ORPHAN_WEIGHT` from `orphan.rs`. Insertions, witness
  refreshes, and removals update the resident weight; FIFO eviction restores
  both bounds. Witness refresh preserves FIFO position; expiry is not
  implemented. These private defaults and indexes have one owner; RPC
  missing-input rejections do not populate peer orphan state. An out-of-range output index
  on a resident mempool parent is rejected under the same token and retry-claim
  checks, rather than retained as an orphan awaiting an impossible parent.
- Orphan retention excludes null outpoints: a zero transaction hash with
  output index `u32::MAX`, matching
  [Core 31.1's `COutPoint::IsNull`](https://github.com/bitcoin/bitcoin/blob/v31.1/src/primitives/transaction.h).
  Rust's `OutPoint::default()` is `(zero txid, index 0)`, which is non-null.
  Such unresolved inputs follow ordinary missing-parent requests and parent
  indexing instead of being silently omitted from retry tracking.
- For standard transactions, the gateway runs the consensus-owned
  `verify_transaction_input_outpoints` check before missing-input policy can
  retain a peer body. Duplicate inputs
  and null outpoints in non-coinbase transactions reject as `Consensus` and
  use transaction-scoped caching even when witness data is present or coins
  are missing. Parent arrival or a different witness cannot repair these
  failures. State and resident-claim guards still precede classification;
  RPC failures do not populate peer caches. Standardness bounds the input
  scan; nonstandard and oversized transactions keep their existing policy
  verdicts without allocating its input set. Coinbase policy remains separate.
- Recent rejects use one bounded FIFO with an identity scope for each hash.
  Witness-scoped refusals suppress only the checked wtxid; transaction-scoped
  refusals additionally suppress the txid. Legacy inventory does not consult
  witness-only refusals, including when a stripped body's wtxid equals its
  txid. A witness-scoped refusal removes only the matching resident orphan
  variant, preserving a different witness and its source. Invalid output
  indexes on known mempool parents are transaction-scoped. This distinction
  prevents a rejected witness from blocking another valid witness for the
  same transaction, as described by
  [BIP339](https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki).
- `retry_orphans` claims one bounded ready set only while generation is
  stable. Claimed bodies remain resident; transient retry exhaustion marks
  them ready for a later call, without immediately consuming the same work
  again. Ready IDs are deduplicated and retire with their resident entry.
  Parent readiness is internal commit work, not a best-effort mutation
  observer or an ingress-channel delivery.
- Node calls `chain_changed` after each committed connect/disconnect and
  before releasing the `ChainTransition`, including changes with no mempool
  mutation. It clears recent rejects and marks children of newly available
  parents ready. Generation remains odd until the transition finishes, so
  that notification cannot prematurely consume the ready work.
- `reconsider_disconnected` re-admits transactions displaced by a reorg
  through the same `commit` path with `AdmissionOrigin::Reorg`. It processes
  candidates in order and withholds descendants of a refused or
  immediately-evicted parent, so a reorg sweep cannot create orphaned
  ancestry.
  `DisconnectedCandidates` in `crates/mempool/src/reconsider.rs` owns
  candidate accounting and an index into earlier offered transaction bodies.
  It resolves full previous outputs, including scripts, from restored coins
  or those retained bodies and uses the shared fee/vsize preparation and
  consensus-owned transaction sigop accounting.
  Node supplies ordered transactions and its coin view while retaining the
  chain transition.
  The batch deliberately runs under the reserved odd generation rather
  than ordinary submission. Its existing validation scope is unchanged;
  current-chain revalidation of the reorg batch is tracked by #640.

## Proven by

- `crates/mempool/src/gateway.rs` (inline tests):
  `input_structure_checks_follow_generation_and_sequence_guards`,
  `input_structure_nonstandard_transactions_keep_policy_precedence`,
  `accepted_and_block_inclusion_events_arrive_in_commit_order`,
  `remove_for_block_publishes_removals_with_origins`,
  `remove_for_block_leaves_unmined_child_and_publishes_only_the_parent`,
  `failed_insert_and_noop_remove_publish_nothing`,
  `replacement_tags_direct_conflicts_and_descendants`,
  `observer_panic_does_not_roll_back_the_mutation`,
  `insert_reports_accepted_then_policy_evictions`,
  `sequence_base_matches_per_change_assignment`,
  `stable_generation_reads_even_values`,
  `reconsider_disconnected_admits_in_order_once_per_candidate`,
  `reconsider_disconnected_withholds_descendants_of_a_refused_parent`.
- `crates/node/src/apply.rs` (inline tests, `chain_generation_tests` module):
  `stable_generation_is_even_before_and_after_connect`,
  `stable_generation_is_even_after_disconnect`.
- `crates/node/src/sync.rs`: clean reorg retry preserves branch and download
  ownership; partial and fatal reorgs preserve generation fencing.
- `crates/node/src/apply.rs`: RPC body preflight, mid-rollback body loss and
  clean disconnect refusal permit retry from their coherent committed state.
- `crates/node/src/reorg/tests.rs`: possibly torn UTXO commits retain the
  fence and checkpoint debt; failed generation settlement preserves its
  original cause and requests shutdown.
- `crates/rpc/src/handlers/tx.rs` (inline tests):
  admission retry rebuilds context after a transient rejection.
- `crates/mempool/src/admission.rs` (inline tests):
  `input_structure_duplicate_rejection_is_shared_across_witnesses`,
  `input_structure_null_rejection_is_shared_across_witnesses`,
  `input_structure_rpc_rejection_does_not_populate_peer_caches`,
  `parent_commit_without_observers_retries_orphan_with_original_source`,
  `chain_change_with_no_pool_mutation_clears_rejects_and_preserves_odd_ready_work`,
  `exhausted_ready_retry_stays_bounded_and_is_retried_on_later_poll`,
  `parent_commit_between_resolution_and_hold_cannot_lose_the_only_wake`,
  `rpc_missing_inputs_does_not_create_peer_lifecycle_state`,
  `coinbase_and_nonstandard_missing_transactions_are_not_held`,
  `known_parent_invalid_output_is_rejected_without_orphan_retention`,
  `orphan_retry_removes_known_invalid_outpoint_after_parent_arrival`,
  `witness_rejection_preserves_valid_variant_and_legacy_inventory`,
  `fresh_invalid_witness_preserves_a_different_resident_orphan_variant`,
  `nonexistent_mempool_output_is_rejected_without_holding_or_mutating`,
  `absent_parent_is_held_but_its_nonexistent_output_is_rejected_on_retry`,
  `stale_invalid_outpoint_claim_cannot_reject_a_refreshed_orphan`,
  `rejected_witness_does_not_suppress_a_valid_body_with_the_same_txid`,
  `rejected_stripped_body_does_not_suppress_its_valid_witness_variant`,
  `zero_hash_output_zero_is_requested_and_retried_as_an_ordinary_outpoint`,
  `null_input_in_a_non_coinbase_transaction_is_not_held`.
- `crates/rpc/src/context.rs` (`admission_chain_tests`):
  `stable_chainstate_reader_does_not_block_transaction_admission`,
  `cached_unconfirmed_transaction_is_still_admitted_from_a_peer`,
  `confirmed_hint_requires_live_chain_outputs_and_survives_no_cache`,
  `admission_chain_uses_current_handles_and_one_applied_tip`.
- `crates/mempool/src/orphan.rs` (inline tests):
  `zero_quota_retains_no_body_or_index`,
  `witness_refresh_keeps_fifo_position_and_source_identity`,
  `readiness_is_deduplicated_and_removed_with_eviction`,
  `rejects_are_bounded_and_chain_reset_clears_both_indexes`,
  `aggregate_weight_evicts_fifo_even_when_count_quota_has_room`,
  `rejecting_another_witness_preserves_the_resident_body_and_ready_work`,
  `transaction_scoped_rejection_releases_the_resident_variants_weight`.
- `crates/mempool/src/reconsider.rs` (inline tests):
  `restored_coins_and_ordered_candidates_price_the_batch`,
  `unavailable_parent_never_offers_outputs_to_a_child`,
  `restored_coin_takes_precedence_over_an_offered_output`,
  `coinbase_does_not_become_a_reconsideration_candidate`,
  `bip141_sigops_are_preserved_from_restored_coins_and_offered_outputs`.
- `crates/node/src/chain_effects.rs` (inline tests):
  `connect_without_pool_mutations_resets_rejects_and_preserves_orphan_retry`,
  `disconnect_without_pool_mutations_resets_rejects_and_preserves_orphan_retry`.
- `crates/rpc/src/zmq.rs`:
  `admission_publishes_one_a_frame_with_core_payload_bytes`,
  `policy_eviction_publishes_r_frames_in_commit_order`,
  `block_inclusion_suppresses_r_frames`,
  `policy_eviction_publishes_r_frames_with_contiguous_sequences`,
  `mempool_event_payloads_carry_reversed_txid_label_and_le_sequence`,
  `sequence_event_payload_uses_core_hash_orientation_and_label`.
- `crates/node/src/mining.rs`:
  `attached_signal_forwards_sequence_wake_without_mempool_lock`,
  `sequence_wake_falls_back_when_not_attached`.
- `crates/node/tests/mining.rs`:
  `publish_generation_from_does_not_take_mempool_lock`,
  `concurrent_publish_generation_paths_do_not_deadlock`,
  `long_poll_returns_quickly_on_mempool_sequence_wake`.
- `crates/node/tests/tx_ingress_e2e.rs`:
  `accepted_peer_tx_is_admitted_and_relayed_excluding_the_source`,
  `below_min_relay_tx_is_rejected_recorded_and_never_relayed`
  (peer tx over a real socket: dispatch filter, admission through the
  observer-installed gateway, source-excluding relay), and
  `full_relay_queue_does_not_block_peer_admission_or_mining_wake`
  (actual ingress and gateway with a saturated relay queue).
