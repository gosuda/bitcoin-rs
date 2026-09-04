# Chain events contract

The seam between the block-apply commit path and index consumers that mirror
the applied chain. Owners: `ChainSnapshot`, `ChainEventHint`,
`ChainEventPublisher`, `NodeState::active_chain_snapshot` in
`crates/node/src/state.rs`; `ConsumerCursor` and the reconciliation plan in
`crates/node/src/reconcile.rs`; `UndoStore`, `DisconnectMarker`,
`DisconnectPhase` in `crates/storage/src/undo.rs` and
`crates/node/src/apply.rs`; `ChainChangeProof`, `ChainChangeGuard` in
`crates/node/src/apply.rs`.

## Clauses

### `EVT-01`: Coherent snapshot cell and process epoch

- `ChainSnapshot { epoch, sequence, tip_hash, tip_height }` is a coherent,
  non-torn view of the applied tip. The single writer replaces the whole cell
  under one `RwLock`; a reader never sees a torn mix of two commit points.
- `epoch` is a persisted, strictly monotonic counter per data dir. It changes
  only across process restarts.
- `sequence` advances once per committed connect and once per committed
  disconnect. It starts at `1` on the first `record` of a run; `0` means no
  committed event yet this run.
- The snapshot is a live value. It is never persisted per-event.
- Readers use `NodeState::active_chain_snapshot()`.

### `EVT-02`: Non-blocking hint emission order

- One `ChainEventHint { kind, height, hash, epoch, sequence }` per committed
  event. `kind` is `Connected` or `Disconnected`.
- `ChainEventPublisher::record` runs in this order: advance the sequence,
  replace the snapshot cell, emit the hint. A consumer woken by a hint
  therefore reads a snapshot at least as fresh as the hint.
- Hints travel over a bounded channel (`CHAIN_HINT_CHANNEL_LIMIT`, sized from
  `INBOUND_BLOCK_CHANNEL_LIMIT`). The send is non-blocking: a full channel
  drops the hint and never blocks the commit path.
- A dropped hint is not a bug. Hints are wake-ups, not a replay log. They
  carry no payload to apply. Recovery is always positional: read a fresh
  snapshot, re-plan from the consumer's persisted cursor over the chain
  itself. Ancestry comes from `BlockTree::active_node_at_height` and
  `BlockTree::find_common_ancestor` (`crates/chain`); bodies come from
  `PruneBodyStore::load_block_body`.

### `EVT-03`: Consumer cursor and positional reconciliation

- `ConsumerCursor { epoch, sequence, height, hash }` names the chain state a
  consumer's rows already mirror. Durable form is `CURSOR_BYTE_LEN` = 52
  bytes: epoch (8 LE) + sequence (8 LE) + height (4 LE) + hash (32 LE).
- A cursor from an older epoch keeps its rows but loses its advisory
  identity: the consumer re-plans from its row position before trusting it.
- Row mutations and the cursor commit in one consumer-owned atomic batch.
  The txindex worker (`crates/node/src/txindex_worker.rs`) is the reference
  consumer; later index consumers copy this shape.

### `EVT-04`: Consumer error isolation and row retention

- The transaction index is the first consumer: per-capability watermarks
  select its rollback/forward legs, and its wake is the coalesced revision
  counter (`crates/node/src/txindex_worker.rs`).
- The txindex worker is the current consumer. Its height-keyed position rows
  delete exactly their own rows during rollback, guarded by watermark identity.
- A consumer that cannot obtain a required body reports failure and stops;
  it never blocks the apply path, and a restart re-plans from the persisted
  pointer.

### `EVT-05`: Durable disconnect marker and chain-change proof

- An authoritative block disconnect arms a `DisconnectMarker` in the
  `UndoStore` before the UTXO mutation, not on the error path. A process
  that dies during rollback writes no error, which is the case the marker
  must detect. The marker carries `(height, block_hash, phase)`.
- `DisconnectPhase` is `InFlight` or `RolledBack`. `InFlight` means the
  authoritative rollback started and did not report completion; a checkpoint
  must not clear it because that would make a torn UTXO set durable.
  `RolledBack` means the in-memory UTXO set and applied tip moved together
  and still need one clean checkpoint. Startup refuses either phase and names
  the directories to remove. Only the checkpoint that publishes the
  rolled-back authoritative state may remove the marker.
- `ChainChangeProof` binds a `ChainTransition` to the `ChainChangeGuard`
  that reserved the active odd generation. Apply-path functions accept
  `&ChainChangeProof`, not independent `&ChainTransition` and
  `&ChainChangeGuard` arguments, so a call without an active odd generation
  cannot compile. The proof's `odd_generation` returns the exact reserved
  value.
- The `UndoStore` trait (`crates/storage/src/undo.rs`) abstracts the
  durable marker over all four backends. `KvUndoStore` writes the marker
  through the `KvStore::write` path; `InMemoryUndoStore` is the test
  default. The marker lives in the `UndoData` column family.

## Live gaps

- **Cross-crate lifecycle boundary**: Slimming `crates/node` orchestration and shifting domain-owned mechanics to their respective crates is tracked under #217 (open).
- **Full-stack crash convergence**: System-level convergence rules across chainstate checkpoints, block data, and secondary indexes are normative in [recovery.md](recovery.md). Chainstate restart uses the authenticated checkpoint plus the redo-only journal contract in `docs/chainstate-recovery.md`; `crates/node/tests/crash_recovery.rs` exercises process `SIGKILL` boundaries, journal replay, reorg rewind/fallback, and upgrade compatibility. The retired recovery-meta sidecar is neither authoritative nor read, while the recovery-evidence bounded current/previous file protocol (`crates/node/src/recovery_evidence.rs`) remains proven by G11. End-to-end convergence spanning real block-body and secondary-index replay remains a live gap.

## Proven by


- `crates/node/src/state.rs`: `record_publishes_snapshot_and_hints_in_commit_order`,
  `record_drops_hints_when_channel_full`,
  `active_chain_snapshot_starts_at_genesis_on_fresh_node`,
  `active_chain_snapshot_anchors_at_restored_tip_after_restart`.
- `crates/node/src/txindex_worker_recovery_tests.rs`:
  `shallow_reorg_rewinds_to_common_ancestor_then_replays`,
  `tip_change_during_rebuild_converges_on_new_tip`,
  `missing_disconnected_body_routes_rewind_to_rebuild`.
- `crates/node/src/apply.rs`:
  `a_clean_disconnect_leaves_no_in_flight_marker`,
  `chain_change_proof_finish_restores_even_generation`,
  `stable_generation_is_even_before_and_after_connect`,
  `stable_generation_is_even_after_disconnect`.
- `crates/node/src/state.rs`:
  `checkpoint_refuses_inflight_disconnect_and_preserves_state`.
- `crates/node/src/recovery_evidence.rs` tests (G11):
  `witness_round_trips_and_falls_back_to_prev`,
  `foreign_genesis_current_cannot_displace_valid_prev`,
  `foreign_genesis_marker_current_cannot_displace_valid_prev`,
  `same_genesis_older_epoch_higher_witness_warns`,
  `equal_or_lower_witness_does_not_warn`,
  `oversized_evidence_file_is_ignored`,
  `marker_round_trips`,
  `marker_last_event_wins_preserves_prev`.
