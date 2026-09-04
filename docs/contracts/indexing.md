# Indexing contract

The normative contract for node-owned indexing runtimes, capability gating, and
asynchronous reconciliation across restarts, reorganizations, and selective
rebuilds.

Owners:
- `TxIndexRuntime`, `TxIndexQueryEngine`, `Worker` in `crates/node/src/txindex_worker.rs`
- `IndexWriter`, `IndexReader`, `IndexCapabilities`, `IndexCapability`, `IndexWatermarks`, `IndexWatermark` in `crates/index/src/index.rs` and `crates/index/src/types.rs`
- Capability status provider in `crates/node/src/capabilities.rs` and
  `crates/rpc/src/context.rs`

## Clauses

### `IDX-01`: Capability configuration and internal enablement

- CLI `--txindex` (env `BITCOIN_RS_TXINDEX`, configuration `txindex=1`) enables
  the `TxLookup` capability in the transaction index store. This builds
  Core-compatible transaction identifier lookup rows (`TxidRow`) and outpoint
  value positions.
- CLI `--scriptindex` / `--script-index` (env `BITCOIN_RS_SCRIPTINDEX`,
  configuration `scriptindex=1`) selects `full` and enables the
  `ScriptHistory` capability. This builds generic scripthash funding rows
  (`ScriptHashRow`), spending rows (`SpendingPrefixRow`), and outpoint spender
  records.
- `scriptindex=utxo` enables only the compact `ScriptLive` view for script
  activity; `scriptindex=full` enables both `ScriptLive` and `ScriptHistory`.
  The historical boolean spellings (`true`, `1`, `yes`) continue to mean
  `full`, and (`false`, `0`, `no`) mean disabled. There is no history-only mode.
- Enabling either `--txindex` or `--scriptindex` spawns exactly one node-owned
  `TxIndexRuntime` worker thread. Enabling both permits both capability row
  families to share a single block-body parse and atomic forward commit batch
  when their watermarks are aligned.

### `IDX-02`: Capability advertisement and Core compatibility

- Only explicit `--txindex` advertises the Core `txindex` capability in RPC
  `getindexinfo` and enables historical `getrawtransaction` verbose and raw
  lookups across all confirmed blocks.
- `--scriptindex=utxo` provides only unspent-output queries; `--scriptindex`
  with its historical boolean spelling or `full` additionally provides generic
  script history and spender queries. These modes support Esplora and RPC
  routes without advertising Core `txindex` unless `--txindex` is also set.
- `getindexinfo` reports `synced: true` if and only if the advertised
  capability watermark matches the height and block hash of the active chain tip.

`ScriptLive` is not a duplicate coin table. Its empty-valued key is
`script-hash-prefix || full-outpoint`; the prefix is only a scan accelerator.
Readers resolve each locator against the authoritative UTXO set and exact-check
the full script. Deletes are exact point deletes, so a prefix collision cannot
remove another script's output.

### `IDX-03`: Query gating and snapshot consistency

- **Ready invariant**: `ready ⇔ cursor == applied_tip on active chain`.
- `TxIndexQueryEngine::with_snapshot` and `index_info_internal` gate every read:
  1. The worker runtime must be healthy (neither `failed` nor `shutdown`).
  2. The applied tip loaded before snapshot creation must match the durable
     capability watermark (`IndexWatermark { height, hash }`) for every consumed
     capability.
  3. The runtime revision (`TxIndexRuntime::revision`) and the applied tip
     identity must remain identical before and after snapshot acquisition.
- If an index capability lags behind the tip, is rebuilding, is rolling back
  across a reorg, or experiences a concurrent tip advance during read assembly,
  the query engine refuses the request with `TxQueryError::Retry` or
  `TxQueryError::Unavailable`. Stale, unconfirmed, or torn rows are never
  returned to callers.
- `unspent_outputs` consumes the `ScriptLive` watermark only. It holds the
  chain-transition authority while taking the index snapshot and checking the
  live watermark against the applied tip. Locator resolution uses one stable
  UTXO view after that lock is released; a tip or revision change during
  resolution is `Retry`. A missing locator after an unchanged tip is
  unavailable; a compact-prefix collision is filtered by the exact script
  check.

### `IDX-04`: Selective reset preserves sibling readiness

- When one capability watermark experiences corruption, a missing block body
  during reorg rollback, or a schema/version mismatch, the worker resets only
  the degraded capability watermark to `None` and backfills it from the active
  chain.
- Surviving sibling capabilities remain ready: resetting and rebuilding
  `ScriptHistory` leaves `TxLookup` online and serving queries as long as its
  own watermark matches the applied tip, and vice versa.

### `IDX-05`: Restart reconciliation and schema version refusal

- The `data_dir/txindex` namespace maintains
  durable format versions and capability watermarks (`IndexWatermarks`,
  `ConsumerCursor`).
- A stored schema or format version foreign to this build refuses start for that
  namespace per `docs/policies/db-migration.md` (never an in-place migration).
- On node startup, index workers read their persisted watermarks and reconcile
  against `NodeState::active_chain_snapshot()`:
  - If the watermark is an ancestor of the restored tip, the worker connects
    forward.
  - If the watermark is on an abandoned branch, the worker rolls back to the
    common ancestor and connects forward to the active tip.
- `NodeState::open` restores the authenticated checkpoint and, when enabled,
  replays the journal's committed suffix (`docs/chainstate-recovery.md`) before
  `NodeState::start_index_workers()` spawns worker threads
  (`crates/node/src/run.rs`), so index workers reconcile against a restored
  active chainstate.

### `IDX-06`: Reorganization rollback and forward reconciliation

- Reorganizations reconcile asynchronously across the chain-event seam
  (`docs/contracts/chain-events.md`). `ApplyHandles` invokes
  `TxIndexRuntime::wake()` after each committed `applied_tip.store`.
- **Disconnect walk**:
  - Height-keyed rows (transaction position rows) are removed using per-block
    watermark identity records to delete exactly the rows contributed by each
    disconnected block from the tip down to the common ancestor.
  - When the rollback depth (watermark height minus common ancestor height)
    exceeds `txindex_worker::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (100 000 blocks),
    the worker routes to `reset_capabilities` and backfills forward instead of
    executing a long block-by-block rollback
    (`docs/benchmarks/index-rollback-rebuild-cutover.md`).
- **Connect walk**:
  - The worker loads bodies from `PruneBodyStore`, constructs bounded forward
    batches (`PreparedBatchLimits`), and commits row mutations and updated
    watermarks in a single atomic store batch per block or block chunk.
  - Live deletes are anchored by the block's authoritative undo scripts;
    same-block create/spend pairs cancel before the anchor is consulted.
    Live inserts use the same admission predicate as the UTXO set, including
    OP_RETURN, oversize-script, and genesis exclusions.
- If a rival reorg or tip extension occurs while a forward batch is being
  prepared, the atomic commit detects the watermark divergence, discards the
  stale prepared batch, and re-plans from the new active tip on the next pass.

### `IDX-07`: Error isolation and supervised rebuild

- If a required block body is missing during a rollback (e.g. an abandoned
  branch block pruned before rollback completed), the worker resets the
  affected capability watermark and initiates a fresh rebuild from the active
  chain.
- A missing or unreadable undo record is fatal only for `ScriptLive`. The
  worker resets that capability and reseeds from the authoritative UTXO view;
  `TxLookup` and `ScriptHistory` continue their body-only rollback.
- When `ScriptLive` has no watermark after restoration or reset, the worker
  rebuilds it by scanning one stable authoritative UTXO view. Rows are written
  before the live watermark is durably stamped; without that watermark partial
  rows are never queryable.
- Index workers execute in supervised threads under `catch_unwind`. A fatal
  storage failure or panic marks the worker as failed (`publish_failed`) and
  stops the worker. Block validation, UTXO commits, and chainstate progress
  continue unimpeded: the apply path never depends on index writes.

## Live gaps

- **Full-stack crash convergence**: The recovery model across chainstate,
  checkpoints, block bodies, and derived indexes is normative in
  [recovery.md](recovery.md) (`RCV-01`–`RCV-04`); a `kill -9` gate that
  re-applies real block bodies through it is not yet exercised.
- **Deep reorg memory bounding**: Disconnect planning preloads branch block bodies into memory; streaming bounded-memory disconnect is tracked under #206 (open).
## Proven by

- `crates/node/src/txindex_worker_recovery_tests.rs`:
  - `shallow_reorg_rewinds_to_common_ancestor_then_replays`
  - `absent_tip_rewinds_index_to_empty`
  - `missing_disconnected_body_routes_rewind_to_rebuild`
  - `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`
- `crates/node/src/txindex_worker_lifecycle_tests.rs` and
  `crates/node/src/txindex_worker_integration_tests.rs`: lifecycle
  publication, open failure/timeout, and shutdown abandonment.
- `crates/node/src/txindex_worker_query_tests.rs`: query gating, snapshot
  consistency, and revision ABA detection tests.
- `crates/node/src/apply.rs`:
  `txindex_worker_failure_makes_queries_unavailable_without_blocking_apply`.
