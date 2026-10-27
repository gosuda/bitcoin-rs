# Chain events contract

The seam between the block-apply commit path and consumers that mirror the
applied chain. The contract orders durable commit, mempool reconciliation,
stable generation publication, and best-effort observer delivery.

Owners:
- Durable commit and stable publication:
  `crates/chainstate/src/lib.rs` and its connect/disconnect/window modules
- Mempool reconciliation and canonical lifecycle:
  `crates/mempool/src/gateway.rs`, `crates/mempool/src/mutation.rs`
- Bounded observer delivery and gap accounting:
  `crates/rpc/src/zmq.rs`, `crates/mempool/src/mutation.rs`
- Index wake and consumer reconciliation:
  `crates/index/src/runtime.rs`, `crates/index/src/reconcile.rs`

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
- Readers use `Chainstate::chain_snapshot()` (via `NodeState::chainstate()`).

### `EVT-02`: Ordered commit and best-effort observer delivery

- Before authoritative mutation, node holds both the mempool chain-change
  generation fence and chainstate's transition reservation. Single-block,
  window, and mining paths take the chainstate reservation first and then
  reserve the mempool generation; reorg coordination reserves the mempool
  generation before entering chainstate. `begin_chain_change` releases the
  mempool writer before returning its guard, so neither ordering nests the
  two domain locks.
- With both fences held, the apply path runs in this order:
  1. Begin the authoritative chainstate mutation.
  2. Build exact forward and undo facts without mutating the public stable view.
  3. Append required body and undo frames. Sync files and required directory
     entries.
  4. Apply one atomic storage batch containing coins, metadata, and the new
     durable head. Wait for durable completion.
  5. Publish the committed chain and coin view.
  6. Return the committed outcome to node and feed it into the mempool canonical lifecycle:
     remove confirmed transactions, keep valid children of confirmed parents,
     remove mined conflicts and descendants, update graph and fee-delta state,
     and update the fee estimator.
  7. Dispatch the node-owned post-commit effects in commit order while the
     chain transition still prevents a later block from overtaking them. Reorg
     also finishes disconnected-transaction reconsideration before settling the
     mempool generation.
  8. Node publishes the stable coherent mempool generation only after mempool
     alignment and reconsideration.
  9. Release the chainstate transition. Any disconnect checkpoint debt is
     published only after both the mempool generation and chain transition are
     stable, so checkpoint I/O does not extend the mutation fence.
- A failure before stable publication leaves the fence closed until explicit
  recovery. A guard destructor must never quietly reopen the fence after an
  error.
- Observer delivery is bounded. The commit path may enqueue an observer record
  while the transition is held to preserve ordering, but a slow consumer drains
  on its own thread. It never holds the mempool writer, chain transition
  reservation, or a storage lock while doing slow downstream work.
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
- `ChainTransition` is the chainstate mutation capability and owns only
  chainstate admission/transition authority. The node separately owns the
  mempool `ChainChangeGuard`; cross-domain coupling is composition, not a
  chainstate dependency.
- The `UndoStore` trait abstracts the durable marker over all retained
  backends.
- A marker that survives to startup no longer refuses it: recovery reconciles the
  certified durable-head chain with the restored state — rewinding a checkpoint
  the disconnect outran, replaying a gap that trails it — publishes a clean
  checkpoint, and retires the marker only after that publication is durable
  (`recovery.md` `RCV-15`). Divergence — durable evidence the head chain cannot
  authenticate, such as a missing body or undo row — still fails closed with the
  marker retained.

### `EVT-06`: Public settled polling and positional replay

- `Node::settled_snapshot`, `subscribe_chain`, `poll_chain` and `pin_chain`
  capture through the existing stable-read domain and require a stable mempool
  generation. A transition, shutdown or recovery-required fence is unavailable.
  No commit, durable-head, follower or lock-order protocol is changed.
- Subscription is polling, with no queue, callback, worker or durable log.
  Hints name the previous observed cursor and a pinned target. Multiple commits,
  epoch changes and non-adjacent moves signal a gap. Intermediate committed
  reorg prefixes are not guaranteed. Consumer persistence remains consumer-owned;
  a subscription cursor records observation, not successful application.
- `replay_chain(from_hash, target, limit)` reconciles positions, disconnecting
  before connecting. It copies at most 256 header steps with a shared 4096-hop
  ancestry budget per call, then releases locks before consumer work. Consumers
  advance their applied hash only after applying each step, keep the target fixed
  across batches, and poll again afterward; they may re-pin when ancestry is
  unavailable or the target has become stale.
- Opaque targets belong to the minting node run. They pin identity, not body
  retention or apply admission. After restart a persisted observation cursor
  detects an epoch gap; re-pin and reconcile from the consumer's actual hash.
  Unknown headers, unavailable ancestry and missing/pruned bodies are explicit
  errors. Fetch bodies separately with `block_by_hash`; never mark a failed
  body applied. Replay reconstructs a path, not a historical event log.
- Proof: `chain_feed::tests` (`crates/node/tests/unit/chain_feed.rs`) covers
  bounded batches, missed commits, stale targets, disconnect-before-connect,
  restart, refusal and unsettled fences.

## Startup crash recovery

On daemon start, `NodeState::open` delegates authoritative recovery to
`crates/chainstate/src/recovery.rs` and reconciles to the committed applied tip. Chain-event
consumers therefore reconcile against the durable applied tip. System-level
convergence after crash, lost write, and reorg is owned by
[recovery.md](recovery.md). The recovery path does not restore an authenticated
checkpoint or replay a journal as an authority.

## Proven by

- `crates/chainstate/src/lib.rs` and its connect/disconnect/window modules own
  the ordered commit protocol and stable publication.
- `crates/mempool/src/gateway.rs` and `crates/mempool/src/mutation.rs`: own the canonical mempool lifecycle and bounded observer delivery.
- `crates/node/tests/overhaul_mempool_lifecycle.rs` (planned): tests that
  canonical estimator accounting stays inside the lifecycle, that slow
  observers never hold the pool writer, and that queue overflow produces gap
  counters and a reconcile signal with bounded memory.
- `crates/node/tests/overhaul_durable_head.rs`: fault-injection matrix for the
  durable-head commit protocol — batch atomicity across the storage family,
  durability before publication, monotonic commit ids across restarts, and
  committed body and undo reachability.
- `scripts/check_models.py` (manual evidence lane): checks the
  `ChainAdmission` TLA+ model, which covers the durable commit, mempool
  reconciliation, and stable publication ordering.
- `crates/chainstate` checkpoint/journal tests cover durable ordering and
  disconnect recovery; node mining/sync/reorg tests cover mempool generation
  fencing and post-commit cross-domain dispatch.

- `crates/node/tests/overhaul_fee_history.rs` (existing):
  - `reorg_reconfirm_records_exactly_one_observation` (`EVT-02` step 6).

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
chain snapshot, chain-event hint, reconciliation consumer, consumer cursor, chain generation.
