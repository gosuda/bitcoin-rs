# Embedded node lifecycle

The typed in-process surface provides `Node::start`, gateway broadcast, and consuming shutdown. Typed reads include `Node::snapshot`, `Node::sync_progress`, `Node::capabilities`, `Node::tx_by_id`, `Node::block_by_hash`, `Node::block_header`, `Node::mempool_info`, `Node::fee_estimate`, and `Node::chainstates_summary`. Settled reads include `Node::settled_snapshot`, `Node::subscribe_chain`/`Node::poll_chain`, and `Node::pin_chain`/`Node::replay_chain`. The daemon runner is the first embedder: one lifecycle implementation, not two.

## Invariants

- **EMB-01: One owned lifecycle.**
  - `run()` and `Node::start` MUST boot through `crates/node/src/lifecycle.rs::start_node`.
  - `StartupGuard::finish` transfers the owned `Node` only after every service started.
  - Both paths MUST stop through `NodeServices::teardown` with `TeardownMode` (`StartupAbort` vs `CleanShutdown`).
  - Teardown requests shutdown and wakes the event loop.
  - Teardown joins the event loop and all configured RPC/HTTP listeners.
  - Teardown stops metrics.
  - Teardown joins P2P core, ingress, and relay workers.
  - Teardown joins bootstrap, checkpoint, and signal workers before publishing the clean checkpoint if eligible.
  - A clean checkpoint publishes only after every prior stage succeeded.
  - The first failure is remembered while later stages still run.
  - Repeated entry is inert.
  - The derived-index worker stops first under a bounded join.
  - The checkpoint publishes and chainstate closes only after the index released its stores.
  - An abandoned join records a teardown error.
  - A worker whose backend open was abandoned while a detached open thread still touches the store records a teardown error.
  - The checkpoint never publishes while detached index I/O can still write.
- **EMB-02: Caller-owned runtime.**
  - `Node::start`/`Node::shutdown` are `async fn` on the caller's Tokio runtime.
  - The node never creates, enters, or retains a runtime.
  - The node drives its own threads synchronously.
  - Owner: `crates/node/src/embed.rs`.
- **EMB-03: Internal composition root.**
  - No public embedding signature names a storage backend, `NodeStorage`, index internals, or `NodeState`.
  - Wiring for `state` and `tx_ingress` is private except via non-default `test-seam`.
  - No production feature/dependency edge may enable that seam.
  - Embedders MUST use operation-oriented `Node` methods only.
- **EMB-04: Typed reads mirror the RPC facts.**
  - `snapshot()` returns the coherent `ChainSnapshot`.
  - `sync_progress()` runs the identical `getblockchaininfo` projection via `ChainHandles::sync_progress` (`crates/rpc/src/context.rs`) over `ChainProgressReader` (`crates/chain/src/progress.rs`).
  - `capabilities()` returns `CapabilitySnapshot` (`crates/index/src/capabilities.rs`).
- **EMB-05: Broadcast is the shared admission.**
  - `Node::broadcast`, `sendrawtransaction` (`crates/rpc/src/handlers/tx.rs`), and Esplora broadcasts all call `MempoolGateway::submit_local_transaction`.
  - `Node::broadcast` passes the default fee-rate cap of `sendrawtransaction`.
  - Calls run under the node's one write-lock interval.
  - Block-connect eviction (`remove_for_block`) commits through the same gateway.
  - Reorg re-admission (`reconsider_disconnected`) commits through the same gateway.
  - In-place prioritise (`prioritisetransaction`) commits through the same gateway.
  - No production path mutates the pool outside it.
  - Gateway invariants: [mempool-mutations.md](mempool-mutations.md).
- **EMB-06: TxLookup gating is honest.**
  - `Node::tx_by_id` reads the mempool first (`MempoolReader::read` into `Mempool::transaction_by_txid`).
  - Next, it reads the confirmed index (`NodeState::esplora_derived_index_query` into `DerivedIndexQuery::transaction`).
  - A disabled index is `NodeError::Unavailable`.
  - A proven-absent transaction is `NodeError::NotFound`.
- **EMB-07: Shutdown consumes.**
  - `Node::shutdown(self)` runs the ordered sequence exactly once.
  - It publishes the clean checkpoint.
  - A node reopened on the same data dir resumes from it.
  - Dropping without `shutdown` runs the same teardown in `StartupAbort` mode with no checkpoint.
  - The data dir stays locked until the last store handle drops.
  - Each store carries the `.lock` guard.
  - That lock reports as typed `DataDirLockError::InUse`, mapped to `NodeError::Startup`.
- **EMB-08: Mutations wake the template coordinator.**
  - The node-constructed `MiningGenerationSignal` (`crates/mining/src/generation_signal.rs`) fires on every committed gateway mutation.
  - It fires on every applied-tip connect/disconnect to the attached coordinator.
  - Before attach it is a no-op.
- **EMB-09: Shutdown wake cannot block teardown.**
  - The bounded wake channel already holds the required notification.
  - Teardown sends nonblocking and continues joins whether accepted, full, or receiverless.
  - Teardown raises the authoritative shutdown flag first.
  - Owner: `lifecycle.rs::NodeServices::teardown`.

## Startup failure and cancellation

`Node::activate_assumeutxo_snapshot_file` keeps its native v4 input contract and caller-relative paths. Portable Core v2 files enter via `loadtxoutset`. Both share one import permit and one format-independent activation owner (no format translation). Both enter the node-owned activation boundary after header sync admits the pinned base. The activation boundary uses mempool fencing and consumer alignment without exporting `NodeState`. Refusal is `NodeError::Snapshot`. Reporting-storage failure is `NodeError::Unavailable`. See `ARCH-07b`.

`start_node` records every worker, socket owner, and channel end in a startup guard at creation. Any later bootstrap failure rolls back through the same ordered teardown in `StartupAbort` mode. This mode never publishes a clean checkpoint. Nothing is handed out via tuple or second factory.

### `EMB-10`: Independent runtime-stall evidence

Sync telemetry cadence is elapsed monotonic time, not wake count. `scripts/watch_runtime_stall.py` is an operator-owned process independent of node locks, RPC, and logging. It records one missed cadence plus bounded debugger/kernel/log evidence, then exits. It never mutates chainstate or infers deadlock from a missing log line. Requirements: [runtime-stall.md](../operations/runtime-stall.md). Proof: `event_loop::tests::telemetry_uses_elapsed_time_not_wake_count`, `scripts/tests/test_watch_runtime_stall.py`.

## Typed mining access

`Node::mining_control()` borrows the attached `MiningControl` used by RPC. It never outlives the node. The call duplicates no coordinator, candidate cache, or chainstate authority. Template long-polls and solved-block submission stay synchronous. Embedders own blocking-worker placement. Embedders drain submissions before shutdown. Embedders join workers after the `RuntimeInputs` shutdown latch cancels outstanding waits. Proof: `tools/stratum-sv2/template-provider` `embedded_templates_preserve_wire_data_commit_and_cancel_on_shutdown` (production `Node::start`, no `test-seam`, no internal RPC client).

## Readiness

`Node::block_header(hash)` (`crates/node/src/chain_feed.rs`) copies header, height, and big-endian cumulative work without a retained body. `Node::broadcast_package` routes bounded native child-with-independent-parents CPFP through `MempoolGateway::submit_local_package` with the ordinary fee cap. RPC `submitpackage` uses the same atomic owner under [POL-02](mempool-policy.md#pol-02-one-admission-owner-and-admission-mode) / [POL-05](mempool-policy.md#pol-05-replacement-cluster-and-package-policy) (neither implements package RBF). Settled polling, opaque replay targets, positional steps, and gap/restart/work bounds are owned by `EVT-06` in [chain-events.md](chain-events.md). `Node::snapshot()` keeps live applied-tip semantics. Followers needing settlement use `Node::settled_snapshot()` or `Node::pin_chain()`. `Node::start` returns after storage open, recovery, and thread spawn. `snapshot()`/`sync_progress()` then reflect the resumed applied tip. The snapshot is the readiness fact, with no separate flag or sleep.

## Historical prefix reads

Three synchronous `Node` calls expose the confirmed-index prefix contract owned by [`IDX-12`](indexing.md#idx-12-historical-prefix-queries-one-shot-server-selected); consistency rules live there, calling shape here:
```rust
impl Node {
    pub fn transaction_at_prefix(&self, txid: &Txid) -> Result<AtPrefix<Option<(u32, Tx)>>, HistoricalQueryError>;
    pub fn script_history_at_prefix(&self, script: ScriptHash) -> Result<AtPrefix<ScriptIndexSnapshot>, HistoricalQueryError>;
    pub fn spender_at_prefix(&self, outpoint: OutPoint) -> Result<AtPrefix<Option<SpendingRecord>>, HistoricalQueryError>;
}
```
`AtPrefix<T>` carries `prefix.floor`, `prefix.height`, `prefix.hash` plus `answer` (`Some((height, tx))` with `floor <= height <= prefix.height`, `ScriptIndexSnapshot`, or `Some(record)`). Types are `bitcoin_rs_index::query_api` (already public, not re-exported). `Txid`/`Tx`/`OutPoint` keep `bitcoin_rs_primitives` paths, the rest keep index paths. Calls are synchronous bounded blocking reads on the calling thread (place on a blocking worker; the existing `async` reads are not a pattern). `transaction_at_prefix` needs `TxLookup` only (tx-only nodes OK). The script operations need `ScriptHistory`. Each call returns its own prefix (compare prefixes, never assume one anchor). Absence is scoped to `[prefix.floor, prefix.height]` on `chain(prefix.hash)` (never global absence, unspentness, or existence; no mempool is merged in). A positive floor refuses full history with `Unavailable(Shared(HistoryUnproven { floor }))` while a standalone spend lookup may return scoped `None`. `Retry` means the chain or index moved, so reissue. `Unavailable` names the gap (`NoCoveredPrefix`, `AncestryBudgetExhausted`, `PrefixBelowFloor`, or shared budget/body/capability cause; match the variant, never the string). `Storage` reports a durable read failure. Strict `ScriptLive` reads and Core RPC behavior are unchanged.

## Error behavior

Typed lifecycle, readiness, `tx_by_id`/`block_by_hash` (EMB-06), mining, and broadcast errors are `NodeError`. Specific variants include `Startup` (config/storage/recovery/bind failure with rollback). Variants also include `Shutdown` (join/checkpoint failure, only from consuming shutdown, never Drop). Remaining variants are `Unavailable`, `NotFound`, and `Broadcast` (policy rejection). Prefix reads return `HistoricalQueryError`, not `NodeError`. Daemon `run()` surfaces teardown failures as `anyhow`.

## Verification boundaries

The public node API, RPC/HTTP consumers, and process lifecycle harness own startup, cancellation, query, and shutdown evidence. Owner-local tests do not substitute for the real process boundary or certify an external embedding.

## Vocabulary

Terms are defined in [../../CONCEPTS.md](../../CONCEPTS.md):
embedded node, node lifecycle.
