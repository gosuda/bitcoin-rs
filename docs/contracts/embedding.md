# Embedded node lifecycle

The typed in-process surface over the node lifecycle: `Node::start`, typed reads (`Node::snapshot`, `Node::sync_progress`, `Node::capabilities`, `Node::tx_by_id`, `Node::block_by_hash`, `Node::block_header`, `Node::mempool_info`, `Node::fee_estimate`, `Node::chainstates_summary`, settled reads `Node::settled_snapshot`, `Node::subscribe_chain`/`Node::poll_chain`, `Node::pin_chain`/`Node::replay_chain`), gateway broadcast, consuming shutdown. The daemon runner is the first embedder: one lifecycle implementation, not two.

## Invariants

- **EMB-01: One owned lifecycle.** `run()` and `Node::start` boot through `crates/node/src/lifecycle.rs::start_node`; `StartupGuard::finish` transfers the owned `Node` only after every service started. Both stop through `NodeServices::teardown` with `TeardownMode` (`StartupAbort` vs `CleanShutdown`): teardown requests shutdown and wakes the event loop, joins the event loop and all configured RPC/HTTP listeners, stops metrics, joins P2P core, ingress, and relay workers, then joins bootstrap, checkpoint, and signal workers before publishing the clean checkpoint if eligible. A clean checkpoint publishes only after every prior stage succeeded, the first failure is remembered while later stages still run, and repeated entry is inert. The derived-index worker stops first under a bounded join, so the checkpoint publishes and chainstate closes only after the index released its stores; an abandoned join, or a worker whose backend open was abandoned while a detached open thread still touches the store, records a teardown error and the checkpoint never publishes while detached index I/O can still write.
- **EMB-02: Caller-owned runtime.** `Node::start`/`Node::shutdown` are `async fn` on the caller's Tokio runtime; the node never creates, enters, or retains a runtime, and drives its own threads synchronously. Owner: `crates/node/src/embed.rs`.
- **EMB-03: Internal composition root.** No public embedding signature names a storage backend, `NodeStorage`, index internals, or `NodeState`; `state` and `tx_ingress` wiring is private except via non-default `test-seam`, and no production feature/dependency edge may enable that seam. Embedders use operation-oriented `Node` methods only.
- **EMB-04: Typed reads mirror the RPC facts.** `snapshot()` returns the coherent `ChainSnapshot`; `sync_progress()` runs the identical `getblockchaininfo` projection via `ChainHandles::sync_progress` (`crates/rpc/src/context.rs`) over `ChainProgressReader` (`crates/chain/src/progress.rs`); `capabilities()` returns `CapabilitySnapshot` (`crates/index/src/capabilities.rs`).
- **EMB-05: Broadcast is the shared admission.** `Node::broadcast`, `sendrawtransaction` (`crates/rpc/src/handlers/tx.rs`), and Esplora broadcasts all call `MempoolGateway::submit_local_transaction` (`Node::broadcast` passes `sendrawtransaction`'s default fee-rate cap) under the node's one write-lock interval; block-connect eviction (`remove_for_block`), reorg re-admission (`reconsider_disconnected`), and `prioritisetransaction` (in-place prioritise) commit through the same gateway. No production path mutates the pool outside it; gateway invariants: [mempool-mutations.md](mempool-mutations.md).
- **EMB-06: TxLookup gating is honest.** `Node::tx_by_id` reads the mempool first (`MempoolReader::read` into `Mempool::transaction_by_txid`) then the confirmed index (`NodeState::esplora_derived_index_query` into `DerivedIndexQuery::transaction`); a disabled index is `NodeError::Unavailable`, a proven-absent transaction is `NodeError::NotFound`.
- **EMB-07: Shutdown consumes.** `Node::shutdown(self)` runs the ordered sequence exactly once and publishes the clean checkpoint, and a node reopened on the same data dir resumes from it; dropping without `shutdown` runs the same teardown in `StartupAbort` mode with no checkpoint. The data dir stays locked until the last store handle drops (each store carries the `.lock` guard); that lock reports as typed `DataDirLockError::InUse`, mapped to `NodeError::Startup`.
- **EMB-08: Mutations wake the template coordinator.** The node-constructed `MiningGenerationSignal` (`crates/mining/src/generation_signal.rs`) fires on every committed gateway mutation and every applied-tip connect/disconnect to the attached coordinator; before attach it is a no-op.
- **EMB-09: Shutdown wake cannot block teardown.** The bounded wake channel already holds the required notification; teardown sends nonblocking and continues joins whether accepted, full, or receiverless, with the authoritative shutdown flag raised first. Owner: `lifecycle.rs::NodeServices::teardown`.

## Startup failure and cancellation

`Node::activate_assumeutxo_snapshot_file` keeps its native v4 input contract and caller-relative paths; portable Core v2 files enter via `loadtxoutset`. Both share one import permit and one format-independent activation owner (no format translation), entering the node-owned activation boundary after header sync admits the pinned base, with mempool fencing and consumer alignment and without exporting `NodeState`. Refusal is `NodeError::Snapshot`; reporting-storage failure is `NodeError::Unavailable`. See `ARCH-07b`.
`start_node` records every worker, socket owner, and channel end in a startup guard at creation; any later bootstrap failure rolls back through the same ordered teardown in `StartupAbort` mode, which never publishes a clean checkpoint. Nothing is handed out via tuple or second factory.

### `EMB-10`: Independent runtime-stall evidence

Sync telemetry cadence is elapsed monotonic time, not wake count. `scripts/watch_runtime_stall.py` is an operator-owned process independent of node locks, RPC, and logging: it records one missed cadence plus bounded debugger/kernel/log evidence, then exits; it never mutates chainstate or infers deadlock from a missing log line. Requirements: [runtime-stall.md](../operations/runtime-stall.md). Proof: `event_loop::tests::telemetry_uses_elapsed_time_not_wake_count`, `scripts/tests/test_watch_runtime_stall.py`.

## Typed mining access

`Node::mining_control()` borrows the attached `MiningControl` used by RPC (never outliving the node; no coordinator, candidate cache, or chainstate authority duplicated). Template long-polls and solved-block submission stay synchronous; embedders own blocking-worker placement, drain submissions before shutdown, and join workers after the `RuntimeInputs` shutdown latch cancels outstanding waits. Proof: `tools/stratum-sv2/template-provider` `embedded_templates_preserve_wire_data_commit_and_cancel_on_shutdown` (production `Node::start`, no `test-seam`, no internal RPC client).

## Readiness

`Node::block_header(hash)` (`crates/node/src/chain_feed.rs`) copies header, height, and big-endian cumulative work without a retained body. `Node::broadcast_package` routes bounded native child-with-independent-parents CPFP through `MempoolGateway::submit_local_package` with the ordinary fee cap; RPC `submitpackage` uses the same atomic owner under [POL-02](mempool-policy.md#pol-02-one-admission-owner-and-admission-mode) / [POL-05](mempool-policy.md#pol-05-replacement-cluster-and-package-policy) (neither implements package RBF). Settled polling, opaque replay targets, positional steps, and gap/restart/work bounds are owned by `EVT-06` in [chain-events.md](chain-events.md). `Node::snapshot()` keeps live applied-tip semantics; followers needing settlement use `Node::settled_snapshot()` or `Node::pin_chain()`. `Node::start` returns after storage open, recovery, and thread spawn; `snapshot()`/`sync_progress()` then reflect the resumed applied tip: the snapshot is the readiness fact, no separate flag or sleep.

## Historical prefix reads

Three synchronous `Node` calls expose the confirmed-index prefix contract owned by [`IDX-12`](indexing.md#idx-12-historical-prefix-queries-one-shot-server-selected); consistency rules live there, calling shape here:
```rust
impl Node {
    pub fn transaction_at_prefix(&self, txid: &Txid) -> Result<AtPrefix<Option<(u32, Tx)>>, HistoricalQueryError>;
    pub fn script_history_at_prefix(&self, script: ScriptHash) -> Result<AtPrefix<ScriptIndexSnapshot>, HistoricalQueryError>;
    pub fn spender_at_prefix(&self, outpoint: OutPoint) -> Result<AtPrefix<Option<SpendingRecord>>, HistoricalQueryError>;
}
```
`AtPrefix<T>` carries `prefix.floor`, `prefix.height`, `prefix.hash` plus `answer` (`Some((height, tx))` with `floor <= height <= prefix.height`, `ScriptIndexSnapshot`, or `Some(record)`). Types are `bitcoin_rs_index::query_api` (already public, not re-exported); `Txid`/`Tx`/`OutPoint` keep `bitcoin_rs_primitives` paths, the rest keep index paths. Calls are synchronous bounded blocking reads on the calling thread (place on a blocking worker; the existing `async` reads are not a pattern). `transaction_at_prefix` needs `TxLookup` only (tx-only nodes OK); the script operations need `ScriptHistory`; each call returns its own prefix (compare prefixes, never assume one anchor). Absence is scoped to `[prefix.floor, prefix.height]` on `chain(prefix.hash)` (never global absence, unspentness, or existence; no mempool is merged in). A positive floor refuses full history with `Unavailable(Shared(HistoryUnproven { floor }))` while a standalone spend lookup may return scoped `None`. `Retry` means the chain or index moved, so reissue; `Unavailable` names the gap (`NoCoveredPrefix`, `AncestryBudgetExhausted`, `PrefixBelowFloor`, or shared budget/body/capability cause; match the variant, never the string); `Storage` reports a durable read failure. Strict `ScriptLive` reads and Core RPC behavior are unchanged.

## Error behavior

Typed lifecycle, readiness, `tx_by_id`/`block_by_hash` (EMB-06), mining, and broadcast errors are `NodeError`: `Startup` (config/storage/recovery/bind failure with rollback), `Shutdown` (join/checkpoint failure, only from consuming shutdown, never Drop), `Unavailable`, `NotFound`, `Broadcast` (policy rejection). Prefix reads return `HistoricalQueryError`, not `NodeError`. Daemon `run()` surfaces teardown failures as `anyhow`.

## Proof

- `gates/g17_dependency_direction.rs::node_composition_root_is_not_a_production_embedding_api` (isolated production consumer; rejects `NodeState`/ingress imports and production `test-seam` edges) · `crates/node/tests/embed.rs::embedded_node_lifecycle_round_trip`, `::dropped_node_releases_services_and_datadir_for_reopen`, `startup_failure_after_state_open_rolls_back_releases_state` · `unit/state/tests/data_dir_lock.rs` (lock held by retained connection/handles/stores) · `unit/lifecycle/tests.rs` (checkpoint/join failure, daemon/embedded identity, repeated teardown, rollback, queued wake) · `embed.rs::broadcast_publishes_one_ordered_a_event_through_the_shared_gateway` · `shutdown.rs::run_exits_cleanly_after_fast_shutdown_signal`.

## Vocabulary

Terms are defined in [../../CONCEPTS.md](../../CONCEPTS.md):
embedded node, node lifecycle.
