# Indexing contract

**Contract version: 1.1** (2025-02-14)

The normative contract for node-owned indexing runtimes, capability gating, and
asynchronous reconciliation across restarts, reorganizations, and selective
rebuilds.

This version adds the scheduling requirements in `IDX-08`; changes to those
requirements must update this clause and its executable proof together.

Owners:
- `TxIndexRuntime` and worker state in `crates/node/src/txindex_worker.rs`;
  reconciliation, cursor commits, bounded preparation, and rollback in its
  `reconciliation.rs`, `cursor.rs`, `catch_up.rs`, and `rollback.rs` modules.
- `TxIndexQueryEngine` in `crates/node/src/txindex_worker/query.rs` owns the shared
  snapshot gate and public query entrypoints. Its `query/transactions.rs`,
  `query/scripts.rs`, `query/block_source.rs`, and `query/budget.rs` modules own
  exact transaction resolution, script traversal, block identity, and aggregate
  work accounting respectively.
- Worker supervision and backend opening in `txindex_worker/lifecycle.rs` and
  `txindex_worker/startup.rs`; startup owns generation-checked publication.
- `IndexWriter`, `IndexReader`, `IndexCapabilities`, `IndexCapability`, `IndexWatermarks`, `IndexWatermark` in `crates/index/src/index.rs` and `crates/index/src/types.rs`
- Capability status: worker-owned `TxIndexLifecycle` in
  `crates/node/src/txindex_worker.rs` mapped by `TxIndexCapability` onto the
  RPC wire types in `crates/rpc/src/capabilities.rs`. There is no parallel
  status enum.

## Clauses

### `IDX-08`: Worker wake scheduling

- A wake increments the runtime revision, while wake notifications are
  coalesced: at most one notification need be queued, and a quiet wait observes
  the latest revision rather than the number of notifications.
- A shutdown request takes precedence over a quiet wait or an already-expired
  batch deadline and returns the stopped result without waiting for a wake.
- An expired batch deadline returns the deadline result without waiting for a
  wake. A queued wake interrupts a non-expired wait and returns the woken
  result without changing the deadline.

These are behavioral requirements, not timing guarantees; test durations are
only scheduling mechanics.

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
- `getcapabilities` reports one compiled txindex row. A missing worker is
  `enabled: false` / `Disabled`; an attached worker supplies the row through
  `TxIndexCapabilitySource`. Proof: `crates/rpc/src/capabilities.rs` tests
  `missing_source_is_the_disabled_txindex_row`, `attached_source_is_the_worker_row`.

`ScriptLive` is not a duplicate coin table. Its empty-valued key is
`script-hash-prefix || full-outpoint`; the prefix is only a scan accelerator.
Readers resolve each locator against the authoritative UTXO set and exact-check
the full script. Deletes are exact point deletes, so a prefix collision cannot
remove another script's output.

### `IDX-03`: Query gating and snapshot consistency

- **Ready invariant**: `ready ⇔ cursor == applied_tip on active chain`.
- `TxIndexQueryEngine::with_snapshot` and `index_info` gate every read:
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
- `unspent_outputs` consumes the `ScriptLive` watermark only. The query holds
  chain-transition authority across watermark validation, live locator scan,
  and authoritative UTXO resolution. Apply mutates the UTXO set before
  publishing the applied tip, so a before/after tip comparison cannot exclude
  that window. History and tx-lookup queries do not take the lock. A missing
  locator under an otherwise ready matching watermark is unavailable; a
  compact-prefix collision is filtered by the exact script check.
- A required capability that is not in the configured selection is
  `Unavailable` with a distinct disabled reason. A configured capability
  whose watermark lags is `Retry` (backfilling), never "disabled".

### `IDX-04`: Selective reset preserves sibling readiness

- When one capability watermark experiences corruption, a missing block body
  during reorg rollback, or a schema/version mismatch, the worker resets only
  the degraded capability watermark to `None` and backfills it from the active
  chain.
- Surviving sibling capabilities remain ready: resetting and rebuilding
  `ScriptHistory` leaves `TxLookup` and `ScriptLive` online and serving
  queries as long as their own watermarks match the applied tip, and vice versa.
- Switching `full` → `utxo`, or dropping internal `TxLookup` when explicit
  `--txindex` is off, resets only leftover persisted families. Configured
  families are not rebuilt as a side effect.

### `IDX-05`: Restart reconciliation and schema version refusal

- The `data_dir/txindex` namespace maintains
  durable format versions and capability watermarks (`IndexWatermarks`,
  `ConsumerCursor`).
- A stored schema or format version foreign to this build refuses start for that
  namespace per `docs/policies/db-migration.md` (never an in-place migration).
  `IndexWriter::open` (`crates/index/src/index.rs`) accepts the current
  version, and the one recorded predecessor (format 3, spending keys without
  positions) by resetting only `ScriptHistory` for rebuild (`IDX-04`); every
  other version is `IndexError::UnsupportedTxIndexFormatVersion`.
- On node startup, index workers read their persisted watermarks and reconcile
  against `NodeState::active_chain_snapshot()`:
  - If the watermark is an ancestor of the restored tip, the worker connects
    forward.
  - If the watermark is on an abandoned branch, the worker rolls back to the
    common ancestor and connects forward to the active tip.

### `IDX-08`: Atomic commit durability and recovery

- `IndexWriter` is the sole owner of index mutations. `commit_block` prepares
  all rows and commits them together with the capability watermark in one
  store batch; its successful return is the commit point and implies the rows
  and watermark are durable according to the store's atomic-write guarantee.
- A failed commit must be treated as ambiguous by callers: callers must not
  retry blindly or mutate index column families themselves. The index worker
  re-reads the persisted watermark and either retries from the last confirmed
  contiguous height or resets and rebuilds the affected capability. Storage
  errors are non-retriable by the indexing worker after supervision marks it
  failed; recovery/rebuild owns the reset decision.
- A crash before the atomic batch is visible leaves the previous watermark and
  rows intact; a crash after visibility leaves both the rows and watermark.
  Partial rows without the corresponding watermark are not queryable and are
  reconciled on restart.

### `IDX-09`: Canonical electrs row cardinality

- A committed block emits the canonical electrs rows: one header row, one
  transaction row per indexed transaction, and funding/spending rows for each
  applicable output/input. The golden-row test is the retained contract test
  for these cardinalities.
- `NodeState::open` restores the authenticated checkpoint and, when enabled,
  replays the journal's committed suffix (`docs/chainstate-recovery.md`) before
  `NodeState::start_index_workers()` spawns worker threads
  (`crates/node/src/run.rs`), so index workers reconcile against a restored
  active chainstate.

### `IDX-06`: Reorganization rollback and forward reconciliation

- Reorganizations reconcile asynchronously across the chain-event seam
  (`docs/contracts/chain-events.md`). `ChainFollowers` dispatch
  `ChainEffects`, which invokes `TxIndexRuntime::wake()` after each
  committed connect or disconnect.
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
  - The worker loads bodies from `BlockBodyStore`, constructs bounded forward
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
  rebuilds it by scanning one stable authoritative UTXO view. Each seed batch
  and the watermark stamp are ordinary fenced writes (reset, revision, and
  every capability watermark). The watermark is written only with the last
  batch; without that watermark partial rows are never queryable.
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

- `crates/index/tests/index_roundtrip.rs`
  `commit_golden_blocks_writes_expected_electrs_rows`: electrs family
  occupancy after one atomic `IndexWriter::commit_block` (`IDX-06`).
- `crates/node/src/txindex_worker_recovery_tests.rs`:
  - `shallow_reorg_rewinds_to_common_ancestor_then_replays`
  - `absent_tip_rewinds_index_to_empty`
  - `missing_disconnected_body_routes_rewind_to_rebuild`
  - `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`
  - `live_only_index_ahead_is_reported_and_reseeded`
- `crates/node/src/txindex_worker_lifecycle_tests.rs` and
  `crates/node/src/txindex_worker_integration_tests.rs`: lifecycle
  publication, open failure/timeout, and shutdown abandonment.
- `crates/node/src/txindex_worker_query_tests.rs`: query gating, snapshot
  consistency, and revision ABA detection tests.
- `crates/node/src/txindex_worker_block_source_tests.rs`: confirmed-body
  serving by height/hash (`IDX-03`, `RCV-01`).
- `crates/node/src/apply.rs`:
  `txindex_worker_failure_makes_queries_unavailable_without_blocking_apply`.
- `crates/rpc/src/capabilities.rs` tests `missing_source_is_the_disabled_txindex_row`,
  `attached_source_is_the_worker_row`: `getcapabilities` advertises one
  txindex row from `txindex_status` (`IDX-02`).

### Query-budget regression evidence

`crates/node/src/txindex_worker/query/budget/tests.rs` exercises the shared
historical/live byte budget, independent row/scan/body-read admission limits,
rejection of truncated scans, and non-consuming rejection of over-budget work
(`IDX-03`, `CL-14`). No query limit or persisted representation changes.

### Store-open cancellation evidence

The store-open wait polls node shutdown, runtime stop, and generation revocation
at bounded intervals. Once the helper has started, cancellation and timeout are
typed abandoned-open outcomes: startup poisons the namespace before releasing
the worker's claim. Cancellation before helper creation may release normally.
These paths do not cancel the underlying storage-engine call.

Evidence for `IDX-07` abandonment and `IDX-08` shutdown:
`crates/node/src/txindex_worker/startup/open_wait/tests.rs` covers bounded
cancellation, deadline precedence, disconnection, and backend error propagation;
`crates/node/src/txindex_worker/startup/tests.rs` covers namespace poisoning and
clean release. The query-budget limits and on-disk formats are unchanged.
