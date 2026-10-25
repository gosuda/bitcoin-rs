# Indexing contract

**Contract version: 1.4** (2026-10-25)

The normative contract for node-owned indexing runtimes, capability gating, and
asynchronous reconciliation across restarts, reorganizations, and selective
rebuilds.

Changes to capability, persistence or scheduling requirements must update the
owning clause and its executable proof together.

Owners:
- `DerivedIndexRuntime` and worker state in `crates/index/src/runtime.rs`;
  reconciliation, cursor commits, bounded preparation, and rollback in its
  `reconciliation.rs`, `cursor.rs`, `catch_up.rs`, and `rollback.rs` modules.
- `DerivedIndexQueryEngine` in `crates/index/src/runtime/query.rs` owns the shared
  snapshot gate and public query entrypoints. Its `query/transactions.rs` and
  `query/scripts.rs` modules own exact transaction resolution and script
  traversal; the engine's body source owns block body access and `query.rs`
  owns aggregate work accounting (`QueryBudget`). Active-chain block identity
  comes from the engine's block tree.
- Worker supervision and backend opening in `runtime/lifecycle.rs` and
  `runtime/startup.rs`; startup owns generation-checked publication.
- Durable mutation: `IndexWriter` in `crates/index/src/index/write.rs`;
  snapshot reads: `IndexReader` in `crates/index/src/index/snapshot.rs`;
  capability and watermark representations in
  `crates/index/src/index/capability.rs`. The private `index.rs` facade
  keeps their implementation internals within one module boundary;
  `crates/index/src/lib.rs` exports their public paths.
- Capability status: worker-owned `DerivedIndexLifecycle` in
  `crates/index/src/runtime.rs` mapped by `DerivedIndexCapability` onto the
  wire types in `crates/index/src/capabilities.rs`. There is no parallel
  status enum.
- Portable index bundles: export and restore in `crates/index/src/portable.rs`
  and its `portable/` modules, run by the worker in `runtime/startup.rs`.
  The node owns only the one-shot request: option parsing in
  `crates/node/src/options.rs`, validation in `crates/node/src/config.rs`, and
  the directive in `crates/node/src/state.rs`.

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
  `DerivedIndexRuntime` worker thread. Enabling both permits both capability row
  families to share a single block-body parse and atomic forward commit batch
  when their watermarks are aligned.
- CLI `--blockfilterindex` (env `BITCOIN_RS_BLOCKFILTERINDEX`, configuration
  `blockfilterindex=1`) enables `CompactFilters` in that same worker and store.
  It defaults to false and enables neither transaction lookup nor script indexes.
  With all indexes off, no derived worker or index namespace is opened. Filter
  generation runs only for this capability, asynchronously after validation.

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
- Compact filters appear as `basic block filter index` in `getindexinfo`.
  `NODE_COMPACT_FILTERS` is added to new P2P handshakes and `getnetworkinfo` only
  while this index is healthy and caught up. Existing connections cannot change
  their version message; every filter request still checks query readiness.
- `getcapabilities` reports one compiled txindex row. A missing worker is
  `enabled: false` / `Disabled`; an attached worker supplies the row through
  `DerivedIndexCapabilitySource`. Proof: `crates/index/src/capabilities.rs` tests
  `missing_source_is_the_disabled_txindex_row`, `attached_source_is_the_worker_row`.
  This row covers transaction/script capabilities only; filter-only operation
  leaves it disabled. Filter progress, reconciliation and local failures do not
  change that row. Filter status is reported by `getindexinfo` and service flags.
  Proof: `crates/index/src/runtime/query_tests.rs` test
  `filter_failure_refuses_filters_but_preserves_durable_progress_and_tx_queries`;
  `crates/rpc/tests/handler_smoke.rs` test
  `compact_filter_rpc_exposes_only_enabled_ready_data`;
  `crates/p2p/src/listener.rs` test
  `unbacked_filter_service_bit_is_removed_from_handshake`.

`ScriptLive` is not a duplicate coin table. Its empty-valued key is
`script-hash-prefix || full-outpoint`; the prefix is only a scan accelerator.
Readers resolve each locator against the authoritative UTXO set and exact-check
the full script. Deletes are exact point deletes, so a prefix collision cannot
remove another script's output.

`ScriptHistory` persists funding rows (`ScriptHashRow`) keyed by
`(script_hash_prefix, height)` and spending rows (`SpendingPrefixRow`) keyed by
`(outpoint_prefix, height)`. Because spending rows index the spent outpoint rather
than the original script hash, spend discovery for a script requires first
discovering all funding outpoints for that script. As a result, confirmed history
queries (`confirmed_history`) must discover all funding outputs across the script's
history before resolving spends; reverse-chronological scanning directly at the
storage level cannot be bounded to an initial page without omitting spends of
older funding outputs. However, `confirmed_history` avoids allocating or retaining
unneeded funding record lists when callers only require history records.

### `IDX-03`: Query gating and snapshot consistency

- **Ready invariant**: `ready ⇔ cursor == applied_tip on active chain`.
- `DerivedIndexQueryEngine::with_snapshot` and `index_info` gate every read:
  1. The worker runtime must be healthy (neither `failed` nor `shutdown`).
  2. The applied tip loaded before snapshot creation must match the durable
     capability watermark (`IndexWatermark { height, hash }`) for every consumed
     capability.
  3. The runtime revision (`DerivedIndexRuntime::revision`) and the applied tip
     identity must remain identical before and after snapshot acquisition.
- If an index capability lags behind the tip, is rebuilding, is rolling back
  across a reorg, or experiences a concurrent tip advance during read assembly,
  the query engine refuses the request with `TxQueryError::Retry` or
  `TxQueryError::Unavailable`. Stale, unconfirmed, or torn rows are never
  returned to callers. A body-store read failure is `TxQueryError::Storage`,
  not a missing body.
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
- A query MUST retain at most one decoded block in its memo. Consecutive
  full-block reads at the same `(height, hash)` reuse it. An identity miss
  MUST evict the retained block before fetching another one. Evicted
  identities are read and charged again.

Proof: these tests establish the memo-retention rule:
- `crates/index/src/runtime/query.rs`:
  `block_memo_retains_only_the_latest_identity` proves release on a miss
  before replacement and release when the query budget is dropped.
- `crates/index/src/runtime/query_tests.rs`:
  `confirmed_history_fetches_shared_block_once_per_query_and_refetches_next_query`
  proves same-identity reuse and isolation between queries.
- `crates/index/src/runtime/query_tests.rs`:
  `confirmed_history_with_nonmatching_script_falls_back_per_height_and_stays_empty`
  proves distinct-height reads for repeated nonmatching-script fallbacks.

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
  `IndexWriter::open` (`crates/index/src/index/write.rs`) accepts the current
  durability marker only (row-format 5: big-endian heights, 43-byte live rows,
  6-byte positions — format owned by
  `docs/benchmarks/scriptindex-format.md`); every older marker is `IndexError::UnsupportedTxIndexFormatVersion`
  and `open_writer` in `crates/index/src/runtime/startup.rs` full-resets
  the derived store for rebuild. No in-place upgrade path
  exists. (`IDX-04` selective reset still covers corrupt watermarks, not versions.)
- The dedicated redb store corrects the former 44-byte ScriptLive table
  declaration only when that table is empty. A populated incompatible table
  refuses open without changing its data; the operator must rebuild the derived
  index in a separately named directory. No live-row conversion is performed.
- On node startup, index workers read their persisted watermarks and reconcile
  against `Chainstate::chain_snapshot()` (via `NodeState::chainstate()`):
  - If the watermark is an ancestor of the restored tip, the worker connects
    forward.
  - If the watermark is on an abandoned branch, the worker rolls back to the
    common ancestor and connects forward to the active tip.

### `IDX-10`: Atomic commit durability and recovery

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
  replays the journal's committed suffix (`docs/contracts/recovery.md`) before
  `NodeState::start_index_workers()` spawns worker threads
  (`crates/node/src/run.rs`), so index workers reconcile against a restored
  active chainstate.

### `IDX-06`: Reorganization rollback and forward reconciliation

- Reorganizations reconcile asynchronously across the chain-event seam
  (`docs/contracts/chain-events.md`). `ChainFollowers` invokes
  `DerivedIndexRuntime::wake()` after each committed connect or disconnect.
- **Disconnect walk**:
  - Height-keyed rows (transaction position rows) are removed using per-block
    watermark identity records to delete exactly the rows contributed by each
    disconnected block from the tip down to the common ancestor.
  - When the rollback depth (watermark height minus common ancestor height)
    exceeds `txindex::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (100 000 blocks),
    the worker routes to `reset_capabilities` and backfills forward instead of
    executing a long block-by-block rollback
    (`docs/benchmarks/index-rollback-rebuild-cutover.md`).
  - Proof: `crates/index/src/runtime/recovery_tests.rs` tests
    `index_ahead_of_restored_tip_is_reported_once_and_rewound` and
    `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`.
- **Connect walk**:
  - The worker loads bodies from `BlockBodyStore`, constructs bounded forward
    batches (`PreparedBatchLimits`), and commits row mutations and updated
    watermarks in a single atomic store batch per block or block chunk.
  - Live deletes are anchored by the block's authoritative undo scripts;
    same-block create/spend pairs cancel before the anchor is consulted.
    Live inserts use the same admission predicate as the UTXO set, including
    OP_RETURN, oversize-script, and genesis exclusions.
  - Enabled capabilities whose next height is equal form one forward group;
    groups never mix capabilities with different next heights, and the lowest
    group runs first. A body absent from the group's next window (up to 256
    bodies) with no rows retained by that leg lets the same pass try the next
    higher start height, at most once per distinct start. The skipped leg wrote
    nothing, so the pass keeps the fence and watermarks it captured. No cursor
    or queue outlives the pass: the next pass tries the lowest group first and
    it resumes as soon as its body exists. Rows the leg already retained answer
    `Buffered` instead: they commit at their original deadline, and only a
    later pass, with nothing retained and a fresh fence and watermark capture,
    may reach another group. A stop request, a rejected or stale commit, a
    deferred or revoked history grant, a pruned-history answer, and an
    undo-anchor failure end the pass and are never skipped.
  - When every group that still needs rows waits on an absent body, the pass
    reports `Stalled`: the worker retries after one quiet period without
    needing a wake, never reports caught-up or publishes the cursor, and does
    not loop on progress. A group that reaches the tip while a lower group is
    owed rows keeps its rows and watermark; each capability's queries still
    gate on its own watermark (`IDX-03`), so full history stays not-ready until
    its watermark and coverage floor say otherwise.
  - Preparation of `ScriptLive` and `CompactFilters` decodes each block's undo
    anchor inside that block's own preparation task, before the writer's shared
    read lock, and drops it when that block's rows are prepared. Anchors alive
    at once are bounded by the preparation tasks in flight on the process-wide
    rayon pool, not by the window's block count. The pool's width is whatever
    the process installed: the node requests the smaller of host parallelism
    and four, while an embedding that initialized the global pool earlier keeps
    its own. Without those capabilities no undo record is read.
  - Before any block of a window is admitted, its outcomes are read in height
    order for an anchor failure, and the lowest-height one decides: a missing or
    unreadable record follows `IDX-07`, and any other failure, including a
    failed undo read, fails with its own error and resets nothing. Only without
    an anchor failure are preparation results consumed in height order: blocks
    before a preparation failure are admitted (and committed when the batch
    fills) and the failure then surfaces unchanged.
  - Unmeasured: peak resident memory of these stages. A window's bodies (at
    most 256, or 32 MiB plus one body), its in-flight anchors, its prepared
    rows, and the admitted batch are limited independently; this contract
    claims no total resident bound and no bound that depends on script sizes.
  - Proof (forward-group scheduling, all in
    `crates/index/src/runtime/recovery_tests.rs`):
    `absent_prefix_body_holds_back_only_its_own_group`,
    `shutdown_after_an_absent_body_does_not_run_a_higher_group`,
    `deferred_history_grant_does_not_run_a_higher_group`,
    `retained_prefix_commits_before_any_group_switch_and_never_outlives_a_fence_change`,
    and `run_loop_commits_a_retained_prefix_and_retries_an_absent_body_without_a_wake`.
  - Proof (undo anchors and admission order):
    `crates/index/src/runtime/recovery_tests.rs` tests
    `forward_script_live_follows_undo_present_missing_or_corrupt`,
    `anchor_failure_outranks_an_earlier_preparation_failure`, and
    `preparation_failure_keeps_its_height_after_committed_successes`.
- If a rival reorg or tip extension occurs while a forward batch is being
  prepared, the atomic commit detects the watermark divergence, discards the
  stale prepared batch, and re-plans from the new active tip on the next pass.

### `IDX-07`: Error isolation and supervised rebuild

- If a required block body is missing during a rollback (e.g. an abandoned
  branch block pruned before rollback completed), the worker resets the
  affected capability watermark and initiates a fresh rebuild from the active
  chain.
- A missing or unreadable undo record affects `ScriptLive` and `CompactFilters`.
  The worker resets `ScriptLive` and reseeds from the authoritative UTXO view;
  `TxLookup` and `ScriptHistory` use body-only rollback. `CompactFilters` instead
  becomes unavailable for this run: a current UTXO snapshot cannot recreate spent
  scripts for historical filters. Its durable rows and watermark are preserved,
  its queries refuse and its status is unsynced; sibling indexes and validation
  continue. Restore the required history and restart to retry filter reconciliation.
  An undo read that fails with a storage error is not an absent record: it
  fails the worker with its own error and resets nothing.
- When `ScriptLive` has no watermark after restoration or reset, the worker
  rebuilds it by scanning one stable authoritative UTXO view. Each seed batch
  and the watermark stamp are ordinary fenced writes (reset, revision, and
  every capability watermark). The watermark is written only with the last
  batch; without that watermark partial rows are never queryable.
- Index workers execute in supervised threads under `catch_unwind`. A fatal
  storage failure or panic marks the worker as failed (`publish_failed`) and
  stops the worker. Block validation, UTXO commits, and chainstate progress
  continue unimpeded: the apply path never depends on index writes.
  Proof: `crates/index/src/runtime/supervisor_tests.rs` tests
  `blocked_open_abandonment_detaches_and_poisons`,
  `shutdown_during_open_reports_abandonment_after_supervisor_exit`, and
  `open_timeout_publishes_error_not_infinite_spin`;
  `crates/index/src/runtime/query_tests.rs` test
  `unusable_worker_makes_queries_unavailable`;
  `crates/index/src/runtime/recovery_tests.rs` test
  `undo_read_failure_is_not_a_missing_undo`, which proves a storage-error
  undo read fails the worker with its own error while an absent record
  resets and reseeds.

### `IDX-11`: Portable index bundle

- **Request**: A bundle operation is an explicit one-shot request. CLI
  `--index-bundle-import <dir>` (env `BITCOIN_RS_INDEX_BUNDLE_IMPORT`,
  configuration `index_bundle_import`) requests a restore. CLI
  `--index-bundle-export <dir>` (env `BITCOIN_RS_INDEX_BUNDLE_EXPORT`,
  configuration `index_bundle_export`) requests an export. Neither has a
  default, and `bitcoin.conf` cannot set either.
- Configuration validation refuses a request that sets both options, a request
  without `--txindex`, and a blank or NUL-bearing directory. It opens no path;
  existence and permissions are checked only when the request runs.
  `NodeState` turns the resolved fields into one `IndexBundleDirective`. The
  index worker runs it once, after the store opens and before its first
  reconcile pass. The node does not exit after the request. The request is not
  stored and nothing removes the option: the operator removes it after the run,
  and a later start that still sets it runs the request again.
- **Format identity**: A bundle is a directory with `txlookup-v1.dat` and, written
  last, `manifest.json`. The manifest carries `format` =
  `bitcoin-rs-index-bundle` and `version` = 1, and it denies unknown fields.
  A manifest larger than 1 MiB is refused unread. The manifest binds the
  network, the genesis hash, the base (height, hash, chainwork, cumulative
  transaction count), the index format version, one `tx_lookup` coverage entry
  with its first covered height (`floor`), and one artifact (name, SHA-256,
  byte length, record count). The base must carry `validated: true`. Restore
  does not read `index.mode`; export sets it to `full` when its worker had
  `ScriptHistory` enabled and to `utxo` otherwise.
- The artifact has a 73-byte `BRSIXART` header that repeats the family, the
  artifact version, the index format version, the network magic, and the base.
  Each record is `txid (32 bytes) || height (4 bytes, big-endian) || count
  (1 byte) || count x 6-byte TxPosition`. Records carry full transaction ids,
  never raw key-value rows. They appear in strictly ascending
  `(txid[..8], height, txid[8..])` order. Ids that share an 8-byte prefix inside
  one block fold into one stored row on restore.
- **Coverage**: A bundle carries the `TxLookup` family only, as the
  `TxConfirmed` rows of one snapshot at the applied tip. Export never writes a
  `ScriptHistory` artifact, and restore refuses a manifest that declares one
  (`UnsupportedCapability`). `ScriptLive` is never a bundle capability and is
  reseeded from the UTXO set. `CompactFilters` is not a bundle family. A bundle
  carries no block bodies, undo records, or chainstate.
- **Export** publishes a manifest only when all of these hold:
  - `TxLookup` is enabled (`TxLookupDisabled`).
  - The destination holds no `manifest.json` (`ExistingBundle`); the artifact is
    created with create-new semantics and never overwrites a file.
  - The `TxLookup` watermark equals the applied tip exactly, a block body source
    exists, and the base block is not marked invalid (`NotReady`). The request
    runs before the first reconcile pass, so an index that lags the applied tip
    at start is refused, not caught up first.
  - The snapshot watermark equals the fenced watermark at capture, and the
    fenced watermarks are unchanged after the stream (`Stale`).
  - Every stored position resolves, through the active-chain block body at the
    row height, to a transaction whose id carries the row prefix
    (`BodyUnavailable` for an absent body, `SourceRow` for any other mismatch).
- Export fsyncs the artifact, fsyncs the directory, then publishes the manifest
  with create-new, fsync, and a directory fsync. Directory sync is a no-op off
  Unix. An export that returns an error attempts to remove the artifact it
  created, and a manifest that fails to write or fsync is removed. A failure of
  the final directory sync is a known gap (see Live gaps).
- **Restore validation** completes before any write. Faults are reported in this
  order: manifest fields, artifact length, SHA-256, artifact header, record
  framing and order, chain identity, a fresh `TxLookup`, locator mismatch.
  - Chain identity requires the same network, the same index format version as
    the compiled code, an applied tip, a base at or below that tip, the same
    genesis hash, the base hash at the base height on the applied tip's
    ancestry (the tip may be ahead of the base), and equal chainwork and
    cumulative transaction count at the base. A bundle with a different index
    format version is refused; the bundle is not a migration path
    ([db-migration.md](../policies/db-migration.md)).
  - Restore needs a fresh capability. It refuses (`NotFresh`) only when
    `TxLookup` already has a watermark, and it never resets a ready index.
    `TxConfirmed` rows without a `TxLookup` watermark are leftovers of an
    interrupted import; a reset of the `TxLookup` capability clears them
    before the import writes. Restore checks no other capability's state.
  - Record framing requires the declared record count and payload length, no
    trailing bytes, one to 255 positions per record, heights inside
    `[floor, base]`, and strictly ascending, non-overlapping, non-empty
    positions that lie inside one serialized block of at most 4,000,000 bytes.
  - Every record is resolved through the receiver's own block body at the
    recorded position, and the full 32-byte transaction id must equal the
    recorded id. A prefix match never resolves a locator. The first terminal
    locator outcome in record order decides: a mismatch found before any
    unavailable body is a refusal (`Locator`); an unavailable body found first
    withholds the bundle.
  - If the receiver has no block body source, or a body a locator needs is
    absent or pruned, the bundle is withheld, not refused: restore writes
    nothing, logs a warning, and ordinary backfill proceeds.
- **Restore apply**: The row stream writes the receiver's own 80-byte header for
  every height from 0 to the base (from its block tree, not from the bundle)
  and then the `TxConfirmed` rows. A batch commits after 65,536 rows (headers
  included) or 8 MiB, and each batch is an ordinary fenced write. The
  `TxLookup` watermark (base height and hash) and the floor are written only in
  the final commit, so the watermark appears with that commit or not at all. The
  apply pass hashes the artifact again and aborts before the final commit if
  the bytes differ from the validated bytes.
- A failed or interrupted apply leaves rows without a watermark, and queries
  refuse the capability. A failed attempt clears them at once when the
  capability still has no watermark. On every start with `TxLookup` enabled,
  `reset_interrupted_import` clears `TxConfirmed` rows that have no `TxLookup`
  watermark, before the bundle request or any derivation runs.
- After a restore, reconciliation proceeds as for any capability with a
  watermark; a forward pass starts at the watermark height plus one.
- **Failure handling**: A refused request is logged at error level and ordinary
  reconciliation proceeds. A one-shot setting left in place, a lagging export,
  or a bad bundle never keeps the index from reaching the tip. Only a
  writer or reader failure (`IndexBundleError::Index`) fails the index worker,
  and the node's validation and chainstate progress continue as in `IDX-07`.
  Shutdown during the request stops the worker (`Cancelled`). The request polls
  for cancellation every 4,096 records or heights.
- **Non-claims**:
  - No bundle carries `ScriptHistory`, `ScriptLive`, or `CompactFilters` rows.
    An operator who needs those indexes builds them through `IDX-01`.
  - The bundle carries no signature. The SHA-256 binds the artifact to the
    manifest that sits beside it. Restore binds each record to the receiver's
    chain by the locator check, not to the exporter's identity.
  - Restore proves that every record present resolves in the receiver's chain.
    It does not prove that no record is missing: no check compares the record
    count with the chain's transaction count.
  - No test compares restored rows with rows an ordinary derivation writes.
  - The clause makes no performance, interoperability with other
    implementations, or cross-version claim.
- Executable proof covers only the manifest and artifact codec and the
  configuration surface. The export, restore, apply, cleanup, and
  failure-handling rules above are stated from the code and have no executable
  proof (see Live gaps).
- Proof (codec and configuration only): the `crates/index/src/portable/manifest.rs`
  tests `manifest_round_trips_through_json_and_validates`,
  `unknown_fields_are_denied_at_every_level`,
  `script_live_is_never_a_capability_and_script_history_is_refused`, and
  `malformed_values_are_refused`; the `crates/index/src/portable/artifact.rs`
  tests `header_is_73_bytes_with_a_big_endian_height_and_round_trips`,
  `prefix_collisions_order_by_full_txid_and_fold_into_one_sorted_row`,
  `framing_refuses_each_violation`, and
  `hashing_reader_digest_equals_the_one_shot_digest`; the
  `crates/node/tests/config_layered.rs` tests
  `index_bundle_is_an_explicit_one_shot_request`,
  `index_bundle_import_and_export_never_resolve_by_precedence`,
  `index_bundle_requires_the_transaction_index_it_moves`, and
  `index_bundle_rejects_empty_and_unusable_directories_on_every_surface`; and the
  `bin/bitcoin-rs/src/config.rs` tests
  `index_bundle_directories_resolve_from_the_command_line_and_stay_exclusive`,
  `empty_index_bundle_directories_are_refused_by_clap_and_the_environment`, and
  `bitcoin_conf_cannot_request_a_bundle_or_relay_feature`.

### Compact-filter data and serving

`index/filters.rs` selects BIP158 basic-filter scripts and owns BIP157 hash/header
commitments. `bitcoin::bip158::GcsFilterWriter` owns deduplication and encoding
(P=19, M=784931), without a second block decode. Proof: its pinned Core-vector
and same-block-spend tests in `index/filters.rs`.
Inputs are distinct nonempty output scripts excluding
OP_RETURN, plus nonempty spent-prevout scripts. Same-block spends resolve from
the parsed block before consulting the existing authoritative undo record.
Genesis outputs and oversized scripts follow BIP158, not UTXO admission rules.
There is no second UTXO set or consensus-validation path.

The existing format-5 `UtxoMeta` table gains an additive namespace:
`01 46 || block_hash` stores `filter_hash || filter_header || serialized_filter`
(hashes in wire byte order); watermark key `00 46` stores the usual height/hash.
Rows, header-chain advancement, cursor and watermark commit atomically through
the existing writer fence. No storage table or schema conversion is introduced.
Selective reset deletes only this prefix and watermark; rollback removes the
disconnected block's row before reconnecting the active branch.

Activation after IBD backfills from genesis using the existing bounded batches.
All required block bodies and undo records must be retained. Pruning and
`blockfilterindex` are rejected together at configuration time. An already
pruned prefix or missing undo makes only filters unavailable; a filter watermark is never
anchored above missing history. Restore complete history before enabling it.

`getblockfilter` serves only basic filters on the applied active chain. Unlike
Core, disconnected filters are not retained for stale-block RPC lookups. A
disabled index returns RPC -1, a malformed hash returns -8, an unknown block or filter type returns -5, and
catch-up/reconciliation returns RPC -1 with a retry reason rather than a
partial filter or waiting for the index to synchronize.

The query engine captures immutable block identities and one index snapshot
without acquiring chain-transition authority. P2P resolves filter stop hashes
against the applied chain; a competing headers-only branch does not change which
filters are servable. Proof: `crates/p2p/src/chain_query.rs` test
`compact_filters_follow_applied_chain_when_competing_headers_lead`.
P2P streams at most one filter payload at a time under the send-headroom gate;
header/checkpoint replies retain
only commitments. Requests are bounded to 1,000 filters, 2,000 hashes, or 100,000
checkpoint headers (below the 4 MB envelope). If the tip changes during streaming,
already-sent filters still belong to the captured stop chain. A completed range
is not replayed. A pass that only the outbound send-headroom gate stops after a
prefix was sent parks the remainder, which starts after the last sent filter,
keeps the stop height the prefix was computed against, and resumes without
repeating a filter. Any other interrupted prefix, or a resumed range whose stop
height has moved, closes the connection instead of silently abandoning the tail.
Disabled, unavailable, unknown, non-basic and oversized requests
receive no filter answer.
For decoded non-basic types, unknown/unapplied stops, inverted ranges and
oversized ranges, bitcoin-rs deliberately keeps the connection open without
discouragement; Core 31.1 disconnects these requests. Proof:
`crates/p2p/src/chain_query.rs` test
`invalid_compact_filter_requests_are_ignored_without_querying_the_index` and
`tools/compact-filter-interop/run.py` wire checks (response bytes and connection
outcome are recorded separately).
To bridge a just-announced tip and asynchronous publication, a valid P2P request
can be deferred for up to five seconds while publication or send headroom is
pending; time the node's aggregate outbound budget refused the request is not
counted toward the five seconds, and time the index or the connection's own
queue took is counted toward the five seconds. The existing socket poll retries one pending request per connection, so inbound traffic, ping
and cancellation remain responsive. A second pending filter request or an expired
deadline closes the connection. No response is replayed after streaming a payload;
chain validation never waits and filters are never generated synchronously.

Pinned Core vectors, durable reset/reopen tests, and the opt-in public-interface
Core/Kyoto runner are described in
[`tools/compact-filter-interop/README.md`](../../tools/compact-filter-interop/README.md).

## Live gaps

- **Full-stack crash convergence**: The recovery model across chainstate,
  checkpoints, block bodies, and derived indexes is normative in
  [recovery.md](recovery.md) (`RCV-01`–`RCV-04`); a `kill -9` gate that
  re-applies real block bodies through it is not yet exercised.
- **Portable bundle end to end**: No test runs an export, a restore, a
  withheld restore, or an interrupted import against a store (`IDX-11`). The
  export, restore, and cleanup rules in that clause rest on the code paths
  `portable/export.rs`, `portable/restore.rs`, `index/write.rs`
  `import_tx_lookup_stream`, and `runtime/startup.rs` `open_and_run`, plus the
  codec and configuration tests it lists.
- **Orphan manifest after a failed export**: `publish_manifest` ends with a
  directory sync (`portable/export.rs`). If that sync fails after
  `manifest.json` exists, the export returns an error, the artifact is removed,
  and the manifest stays. Restore of that directory then fails reading the
  artifact, and a new export into it is refused as `ExistingBundle` until the
  operator clears the directory. The code does not remove the manifest on this
  path.

## Proven by

- `crates/index/tests/index_roundtrip.rs`
  `commit_golden_blocks_writes_expected_electrs_rows`: electrs family
  occupancy after one atomic `IndexWriter::commit_block` (`IDX-06`).
- `crates/index/src/runtime/recovery_tests.rs`:
  - `index_ahead_of_restored_tip_is_reported_once_and_rewound`
  - `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`
  - `pruned_history_rebuilds_from_the_frontier_and_absent_history_waits`
  - Forward group scheduling (`IDX-06`):
    `absent_prefix_body_holds_back_only_its_own_group`,
    `shutdown_after_an_absent_body_does_not_run_a_higher_group`,
    `deferred_history_grant_does_not_run_a_higher_group`,
    `retained_prefix_commits_before_any_group_switch_and_never_outlives_a_fence_change`,
    `run_loop_commits_a_retained_prefix_and_retries_an_absent_body_without_a_wake`.
  - Forward undo anchors (`IDX-06`, `IDX-07`):
    `forward_script_live_follows_undo_present_missing_or_corrupt`,
    `anchor_failure_outranks_an_earlier_preparation_failure`,
    `preparation_failure_keeps_its_height_after_committed_successes`,
    `undo_read_failure_is_not_a_missing_undo`, and the existing
    `unavailable_filter_history_preserves_sibling_indexes_and_filter_watermark`
    for the filter side.
- `crates/index/src/runtime/startup.rs` and
  `crates/index/src/runtime/supervisor_tests.rs`: lifecycle
  publication, open failure/timeout, and shutdown abandonment.
- `crates/index/src/runtime/query_tests.rs`: query gating, snapshot
  consistency, revision ABA detection, and
  `failed_worker_makes_queries_unavailable` /
  `stopped_worker_makes_queries_unavailable` worker-liveness refusal.
- `crates/index/src/index/tests.rs`: confirmed-body
  serving by height/hash (`IDX-03`, `RCV-01`).
- `crates/chainstate/src/reorg.rs` and the `RCV-08` recovery evidence prove
  bounded disconnect streaming under a retention lease; the departed branch
  is not preloaded.
- `crates/index/src/capabilities.rs` tests `missing_source_is_the_disabled_txindex_row`,
  `attached_source_is_the_worker_row`: `getcapabilities` advertises one
  txindex row from `derived_index_status` (`IDX-02`).

### Query-budget regression evidence

`crates/index/src/runtime/query.rs` tests exercise the shared
historical/live byte budget, independent row/scan/body-read admission limits,
rejection of truncated scans, and non-consuming rejection of over-budget work
(`IDX-03` and the project bounded-resources invariant). No query limit or
persisted representation changes.

### Store-open cancellation evidence

The store-open wait polls node shutdown, runtime stop, and generation revocation
at bounded intervals. Once the helper has started, cancellation and timeout are
typed abandoned-open outcomes: startup poisons the namespace before releasing
the worker's claim. Cancellation before helper creation may release normally.
These paths do not cancel the underlying storage-engine call.

Evidence for `IDX-07` abandonment and `IDX-08` shutdown:
`crates/index/src/runtime/startup.rs` tests cover bounded
cancellation, deadline precedence, disconnection, backend error propagation,
namespace poisoning, and clean release. The query-budget limits and on-disk formats are unchanged.
