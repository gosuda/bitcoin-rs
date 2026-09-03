# Mempool mutations contract

The single mutation gateway in front of the mempool, the records it emits,
and the ZMQ `sequence` mapping built on them. Owners: `MempoolGateway` in
`crates/mempool/src/gateway.rs`; `MutationResult`/`MutationOutcome`/
`RemovalReason`/`MutationEnvelope`/`AdmissionOrigin` in
`crates/mempool/src/mutation.rs`; the node-side observer
in `crates/node/src/mempool_observer.rs`; payload encoding in
`crates/node/src/zmq_publisher.rs`.

## Clauses

### `MPL-01`: Single mutation gateway ordering invariant

- Every production mempool mutation routes through `MempoolGateway`. No
  production code outside the gateway takes the mempool write lock; lookups
  go through `MempoolGateway::read`.
- Every mutating method flows through one path, `commit` (and
  `admit_transaction`, which enqueues the same way), in this exact order:
  1. take the pool write lock,
  2. mutate and assign per-change `mempool_sequence` values,
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
  Empty results and an absent observer enqueue nothing, allocate nothing,
  and spawn no thread.
- Observers are best-effort mirrors. Observer errors and panics never
  affect the committed mutation. No gateway lock is held across an
  observer call, so an observer may re-enter the gateway: a nested call
  commits, enqueues, and returns immediately, and its publication
  completes after the in-flight callback. The accepted-mutation mining
  wake threads the last change's sequence into
  `MempoolSequenceWake::publish_generation_from`, which builds the
  generation key from `applied_tip` plus that sequence and never touches
  the mempool read lock (`crates/node/src/mining.rs`); the node observer
  routes every mutation through it (`crates/node/src/mempool_observer.rs`,
  `NodeMutationObserver::on_mutation`).

### `MPL-02`: Atomic mutation records and sequence assignment

- Every mutating `Mempool` method returns `MutationResult`: an ordered
  `Vec<MutationChange>`, one change per affected transaction, in commit
  order. Each change carries the txid and a `MutationOutcome`:
  `Accepted`, or `Removed(RemovalReason)`.
- `RemovalReason` is one of `BlockInclusion`, `Conflict`, `Replaced`,
  `Descendant`, `PolicyEviction`, `Expiry`, `Explicit`, `Clear`, `Reorg`.
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
  no `Drop` that changes generation: dropping, unwinding, or an error leaves
  the generation odd — admission stays closed. Only `finish` may
  compare-exchange the odd value to the reserved even value, reopening
  admission. One guard covers one externally coherent chain operation.
- `admit_transaction` is the one atomic admission operation for RPC
  `sendrawtransaction`. The caller captures `expected_generation` (an even
  value from `stable_generation`) and `expected_sequence` (from a read
  guard), then calls `admit_transaction` with both tokens. The gateway takes
  the write lock once and checks, in order: (1) exact chain generation
  equals the request and is even, (2) current pool sequence equals the
  request, (3) exact transaction identity. A mismatch returns a transient
  error (`GenerationChanged` or `MempoolChanged`) and the caller retries
  with fresh facts — it never re-uses a captured even generation.
- `reconsider_disconnected` re-admits transactions displaced by a reorg
  through the same `commit` path with `AdmissionOrigin::Reorg`. It processes
  candidates in order and withholds descendants of a refused or
  immediately-evicted parent, so a reorg sweep cannot create orphaned
  ancestry.

## Proven by

- `crates/mempool/src/gateway.rs` (inline tests):
  `accepted_and_removed_events_arrive_in_commit_order`,
  `remove_for_block_reports_block_inclusion_not_explicit`,
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
- `crates/rpc/src/handlers/tx.rs` (inline tests):
  admission retry rebuilds context after a transient rejection.
- `crates/node/src/mempool_observer.rs`:
  `admission_publishes_one_a_frame_with_core_payload_bytes`,
  `explicit_removal_publishes_r_frames_in_commit_order`,
  `block_inclusion_suppresses_r_frames`,
  `policy_eviction_publishes_r_frames_with_contiguous_sequences`.
- `crates/node/src/zmq_publisher.rs`:
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
  observer-installed gateway, source-excluding relay).
