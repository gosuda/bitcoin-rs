# Chain events contract

The seam between the block-apply commit path and consumers that mirror the
applied chain. The contract orders durable commit, mempool reconciliation,
stable generation publication, and best-effort observer delivery.

Owners:
- Durable commit and stable publication: `crates/chainstate/src/transition.rs`
- Mempool reconciliation and canonical lifecycle:
  `crates/mempool/src/gateway.rs`, `crates/mempool/src/mutation.rs`
- Bounded observer delivery and gap accounting:
  `crates/rpc/src/zmq.rs`, `crates/mempool/src/mutation.rs`
- Index wake and consumer reconciliation:
  `crates/index/src/runtime.rs`, `crates/node/src/reconcile.rs`

## Clauses

### `EVT-01`: Coherent snapshot cell and process epoch

- `ChainSnapshot { epoch, sequence, tip_hash, tip_height }` is a coherent,
  non-torn view of the applied tip. The single writer replaces the whole cell
  under one `RwLock`; a reader never sees a torn mix of two commit points.
- `epoch` is a persisted, strictly monotonic counter per data dir. It changes
  only across process restarts.
- `sequence` advances once per committed connect and once per committed
  disconnect. It starts at `1` on the first record of a run; `0` means no
  committed event yet this run.
- The snapshot is a live value. It is never persisted per event.
- Readers use `NodeState::active_chain_snapshot()`.

### `EVT-02`: Ordered commit and best-effort observer delivery

- The apply path runs in this order:
  1. Hold the chain transition reservation; close admission and mixed reads
     with the generation fence.
  2. Build exact forward and undo facts without mutating the public stable view.
  3. Append required body and undo frames. Sync files and required directory
     entries.
  4. Apply one atomic storage batch containing coins, metadata, and the new
     durable head. Wait for durable completion.
  5. Publish the committed chain and coin view.
  6. Feed the committed chain update into the mempool canonical lifecycle:
     remove confirmed transactions, keep valid children of confirmed parents,
     remove mined conflicts and descendants, update graph and fee-delta state,
     and update the fee estimator.
  7. Publish the stable coherent generation only after mempool alignment.
  8. Dispatch notifications, relay, and index wake hints in the declared
     observable order outside all domain locks.
- A failure before stable publication leaves the fence closed until explicit
  recovery. A guard destructor must never quietly reopen the fence after an
  error.
- Observer delivery is bounded. The publish queue has a capacity and exposes
  dropped or gap counters. A slow or blocked observer parks its own drain
  thread; it never holds the mempool writer, the chain transition reservation,
  or a storage lock.
- Canonical estimator accounting is part of the mempool lifecycle in step 6.
  It is not an observer and is never dropped.

### `EVT-03`: Consumer cursor and positional reconciliation

- `ConsumerCursor { epoch, sequence, height, hash }` names the chain state a
  consumer's rows already mirror. Durable form is `epoch` (8 LE), `sequence`
  (8 LE), `height` (4 LE), and `hash` (32 LE).
- A cursor from an older epoch keeps its rows but loses its advisory identity;
  the consumer re-plans from its row position before trusting it.
- Row mutations and the cursor commit in one consumer-owned atomic batch.
- The index runtime is the reference consumer; later index consumers copy this
  shape.

### `EVT-04`: Consumer error isolation and row retention

- Per-capability watermarks select rollback or forward legs. Optional index
  commit failure does not block ordinary chain progress.
- A consumer that cannot obtain a required body reports failure and stops; it
  never blocks the apply path. A restart re-plans from the persisted pointer.

### `EVT-05`: Durable disconnect marker and chain-change proof

- An authoritative block disconnect arms a disconnect marker in the undo store
  before the UTXO mutation, not on the error path. A process that dies during
  rollback writes no error; the marker detects the incomplete state.
- The marker carries `(height, block_hash, phase)`.
- `ChainChangeProof` binds a transition lock to the `ChainChangeGuard` that
  reserved the active odd generation. The caller-facing mutation capability is
  `ChainTransition`, which holds that proof.
- The `UndoStore` trait abstracts the durable marker over all retained
  backends.

## Startup crash recovery

On daemon start, `NodeState::open` recovers the durable root from
`crates/chainstate` and reconciles to the committed applied tip. Chain-event
consumers therefore reconcile against the durable applied tip. System-level
convergence after crash, lost write, and reorg is owned by
[recovery.md](recovery.md). The recovery path does not restore an authenticated
checkpoint or replay a journal as an authority.

## Proven by

- `crates/chainstate/src/transition.rs` (planned): owns the ordered commit
  protocol and stable publication.
- `crates/mempool/src/gateway.rs` and `crates/mempool/src/mutation.rs`
  (planned): own the canonical mempool lifecycle and bounded observer delivery.
- `crates/node/tests/overhaul_mempool_lifecycle.rs` (planned): tests that
  canonical estimator accounting stays inside the lifecycle, that slow
  observers never hold the pool writer, and that queue overflow produces gap
  counters and a reconcile signal with bounded memory.
- `crates/node/tests/overhaul_durable_head.rs` (planned): tests that a new
  durable head is published only after mempool alignment.
- `bin/bitcoin-rs/tests/gates/g20_formal_models.rs` (planned): checks the
  `ChainAdmission` TLA+ model, which covers the durable commit, mempool
  reconciliation, and stable publication ordering.
- `crates/node/src/apply.rs` existing tests:
  - `a_clean_disconnect_leaves_no_in_flight_marker`;
  - `chain_change_proof_finish_restores_even_generation`;
  - `stable_generation_is_even_before_and_after_connect`;
  - `stable_generation_is_even_after_disconnect`.

- `crates/node/tests/overhaul_fee_history.rs` (existing):
  - `reorg_reconfirm_records_exactly_one_observation` (`EVT-02` step 6).

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
ordered commit protocol, coherent view, `ReadStamp`.
