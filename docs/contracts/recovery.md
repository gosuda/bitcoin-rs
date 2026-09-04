# Recovery contract

How persisted components converge after a crash, checkpoint fallback, or
reorganization. Chainstate is the single authority; every other persisted
component is derived and reconciles to it.

Owners:
- Authoritative position: `NodeState::open`, applied tip, checkpoint restore
  and `detect_checkpoint_fallback` in `crates/node/src/state.rs`,
  `crates/node/src/checkpoint.rs`, `crates/node/src/recovery_evidence.rs`
- Derived-index position and transitions: `Worker::reconcile_once`,
  `ReconcilePhase`, `TxIndexLifecycle` in `crates/node/src/txindex_worker.rs`
- Operator visibility: `NodeCapabilities` in `crates/node/src/capabilities.rs`,
  `CapabilityState` in `crates/rpc/src/context.rs`, `WarningStore` and
  `RecoveryReporter` in `crates/node/src/recovery_evidence.rs`

## Clauses

### `RCV-01`: Authority and identity

- Canonical chainstate (UTXO set plus the applied tip) is the only
  authoritative position. Checkpoints are a durable copy of it; block bodies,
  `txindex`, `scriptindex`, and undo/lookup metadata are derived.
- Every derived position is a `(height, block hash)` pair. Height alone never
  identifies a position; two components agree only when both fields match.
- A derived component never blocks, delays, or rewrites authoritative apply.
  Index workers open and reconcile on their own threads after
  `NodeState::open` returns (`TxIndexWorker::spawn_with_open`); a failed or
  wedged index publishes `Failed`/`ShutdownAbandoned` and degrades only
  index-dependent APIs (`IDX-07`).

### `RCV-02`: Behind, ahead, stale, absent

For each enabled capability the worker compares its durable watermark with the
applied tip on every pass and takes exactly one transition:

- **On the active chain below the tip** (behind): forward replay of canonical
  bodies from the watermark to the tip (`IDX-06`).
- **On the active chain above the tip** (ahead — checkpoint fallback or a
  crash between chainstate and index commits): rewind to the tip. This is an
  operator-visible event (`RCV-04`).
- **Off the active chain** (stale branch): rewind to the common ancestor, then
  forward replay.
- **Absent tip** (headers-only start): every row is rewound; the index holds
  no position the chain does not.
- **Absent watermark**: forward replay from genesis.

### `RCV-03`: Rewind versus rebuild

- `ReconcilePhase` holds one `ReconcileLeg` per capability, because
  capabilities carry independent watermarks and may be in different legs at
  once (one rebuilding while its sibling rewinds).
- A rewind removes rows block by block using exact identity-bearing rows and
  the disconnected block's body. The worker publishes
  `ReconcileLeg::RollingBack { from_height, to_height }` on the rewinding
  capabilities for its duration and returns them to `Forward` when the
  rollback loop ends.
- When the rewind depth to the common ancestor exceeds
  `rollback_rebuild_cutover`, or when a rewind cannot be performed exactly
  (missing disconnected body, missing watermark identity), the affected
  capabilities are reset and rebuilt from genesis (`IDX-04`). Their leg is
  `ReconcileLeg::Rebuilding` until every reset capability is back at the
  applied tip; a rebuild leg survives sibling rollbacks and is cleared only
  when a pass reports `CaughtUp`, which `Worker::reconcile_once` grants only
  after re-checking that no enabled capability still selects a rollback or
  forward step against the current applied tip.
- The applied tip may move while a rewind or rebuild is in flight. The worker
  never restarts the transition; the next pass reconciles the new tip from the
  current durable watermarks.

### `RCV-04`: Operator-visible rollback evidence

- Checkpoint fallback (`detect_checkpoint_fallback`) and an index watermark
  above the applied tip (`Worker::reconcile_once`) each write one
  `WarningStore` entry and one durable `chain-rollback-event.json` marker via
  the single `RecoveryReporter` created in `NodeState::open`.
- The index-ahead marker names the capability set, both block identities, and
  the gap; it is written once per reconciliation pass, not once per block.
- The warning is set before the marker write. A marker write failure fails the
  reporting index worker (`TxIndexWorkerError::RollbackEvidence`), never the
  chain.
- RPC exposes `CapabilityState::{Opening, CatchingUp, RollingBack, Rebuilding,
  Ready, Failed, Disabled, ShutdownAbandoned}` for the txindex; `RollingBack`
  and `Rebuilding` come from the worker's published `ReconcilePhase`, not from
  query results. `Rebuilding.processed_height` is the lowest watermark of the
  rebuilding capabilities only (`TxIndexQueryEngine::index_progress_for`), so
  a script-only rebuild reports script progress, not the untouched tx cursor.
  `processed_height` and `target_height` come from the same read against one
  applied tip; a read that raced a tip or revision move is retried, never
  spliced with a separately loaded tip.

## Proven by

- `crates/node/src/txindex_worker_recovery_tests.rs`:
  `shallow_reorg_rewinds_to_common_ancestor_then_replays` (`RCV-02`,
  `RCV-03`), `index_ahead_of_restored_tip_is_reported_once_and_rewound`
  (`RCV-04`), `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`
  (`RCV-03`), `tip_change_during_rebuild_converges_on_new_tip` (`RCV-03`),
  `missing_disconnected_body_routes_rewind_to_rebuild` (`RCV-03`),
  `selective_rebuild_leg_survives_sibling_rollback` (`RCV-03`),
  `absent_tip_rewinds_index_to_empty` (`RCV-02`).
- `crates/node/src/txindex_worker_lifecycle_tests.rs` and
  `crates/node/src/txindex_worker_integration_tests.rs`: open failure, open
  timeout, blocked-open abandonment, and late-publication revocation never
  gate `NodeState::open` (`RCV-01`).
- `crates/node/src/apply.rs`:
  `txindex_worker_failure_makes_queries_unavailable_without_blocking_apply`
  (`RCV-01`).
- `crates/node/src/recovery_evidence.rs`:
  `reporter_report_checkpoint_fallback_writes_marker_and_warns`,
  `reporter_report_index_ahead_writes_marker_and_warns`,
  `checkpoint_fallback_with_index_far_ahead_converges_and_warns`,
  `marker_write_failure_fails_only_the_reporting_index` (`RCV-04`).
- `crates/node/src/state.rs`:
  `stale_checkpoint_restore_surfaces_warning_not_silence` (`RCV-04`).
