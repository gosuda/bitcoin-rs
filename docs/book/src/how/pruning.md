# Pruning

Pruning deletes block-body locator rows and undo rows below a requested height, plus whole block files whose highest block is below that line. The deletions and three metadata keys commit in one atomic batch, so a crash leaves either the old line or the new one. Two independent bounds decide the effective line: the RPC refuses a height within 288 blocks of the applied tip, and the storage layer never prunes inside the margin of the last published checkpoint.

[`ARCH-08`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md#arch-08-durable-pruning-and-reorg-retention) owns durable pruning and reorg retention, [`SYNC-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md#sync-07-required-history-remains-available-until-consumed) owns required-history availability, and [`RCV-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-07-missing-disconnected-body-routes-to-canonical-rebuild) owns what a missing body does to recovery.

## What a prune deletes

`prune_to_height` is the only pruning entry (`crates/storage/src/pruning.rs:136`). It stages two families and a file list:

- body locator rows in `BLOCK_DATA_CF`, keyed by `(height, block_hash)`, 37 bytes per key;
- undo rows under the `UndoData` prefix, keyed by the same pair;
- block files whose `blkfile<file_no>` maximum-height row is below the line and which are not the current append file (`crates/storage/src/pruning/block_pruner.rs:72-99`).

`stage_block_and_undo_prune` returns `StagedPrune { blocks, undo, file_numbers, pruned_below }` (`crates/storage/src/pruning.rs:209-241`). `pruned_below` is the highest removed height plus one, across both families. The line is exclusive: `pruneblockchain 5` removes heights 0 through 4 and keeps height 5. The live trace below confirms that boundary.

File removal happens after the metadata commit. `reclaim_staged_flat_block_files` skips the current file, unlinks each selected file, and deletes its maximum-height row (`crates/storage/src/pruning.rs:244-268`). Because the current file is never unlinked, `size_on_disk` can stay flat after a successful prune when all bodies live in the active file. The rows are what readers consult, so a removed locator is enough to make the body unavailable.

The unit is the locator row, not the byte range. The same line prunes undo rows because a disconnect below the line cannot be served anyway. The retention registry keeps a row that an in-flight consumer still needs.

## The line is bounded twice

The RPC bound comes first. `pruneblockchain` refuses when pruning is disabled with `pruning is disabled`, refuses a height above the applied tip with `prune height cannot exceed applied tip`, and refuses a height above `applied - 288` with `prune height is within reorg safety margin` (`crates/serving/src/handlers/chain.rs`). The constant is `CORE_REORG_SAFETY_MARGIN = 288` (`crates/consensus/src/primitives.rs`).

The storage bound is separate and can be tighter. `prune_to_height` recomputes `safe_prune_height = applied_tip_height - 288` and refuses again, then builds the policy line (`crates/storage/src/pruning.rs:146-160`):

```text
pruner_tip  = pruneheight + 288
policy_line = min(pruner_tip, durable_tip_height) - retention_depth
retention_depth = max(keep_below_tip, 288)
```

`durable_tip_height` is not the applied tip. The node initializes it from the tip restored at open and updates it only when the node publishes a checkpoint (`crates/node/src/state/open.rs`, `crates/execution/src/checkpoint/publisher.rs:221-222`). The execution maintenance worker publishes a checkpoint at most once every ten minutes while the node runs, and only when the applied tip is above the checkpoint height (`crates/execution/src/maintenance.rs`). So the effective line never exceeds `checkpoint_height - 288`. A prune pass that asks for more records its request but deletes only what the checkpoint base already makes safe.

That clamp is visible in the live trace and is the reason two height keys exist. On a cold datadir with 300 blocks and no checkpoint yet, `pruneblockchain 5` returned 5 and stored `node:pruneheight = 5`, but every block was still served because `durable_tip_height` was 0 and the policy line was 0. After a clean stop published checkpoint generation 1 at height 300, a restart made the same call delete heights 0 through 4.

`retention.reserve(policy_line)` further lowers the line to the lowest active lease floor (`crates/storage/src/pruning/lease.rs:180-191`). Pruning takes the chain transition before it reads the applied tip, so a connect cannot move the tip under an in-flight prune (`crates/execution/src/lib.rs:224-250`). The history path used by block-spend reads carries a 288-block retention budget (`crates/node/src/state/storage.rs:143-149`); a request below the registry's refusal line returns `HistoryUnavailable::Pruned { below }` or `HistoryUnavailable::Reserved { below }`, never an empty success (`crates/storage/src/pruning/lease.rs:98-108`).

## The three metadata keys

```text
node:pruneheight    requested line, big-endian u32, RPC-visible
node:prune_executed first retained height, big-endian u32, authoritative
node:prune_batch    pass receipt, big-endian u64, monotonic per pass
```

`NodePruneService` loads `node:pruneheight` at open, returns it from `pruneblockchain`, and reports it as `pruneheight` in `getblockchaininfo` (`crates/node/src/state/storage.rs:304-318`, `crates/serving/src/handlers/chain.rs`). It is the request, not proof of deletion.

`node:prune_executed` is the executed frontier: the first height that the pruning authority has not removed. `ExecutedFrontier::reconstruct` reads it, falls back to `NONE` only when no prune metadata exists at all, and otherwise fails closed (`crates/storage/src/pruning.rs:95-127`). A store that has a prune height or a batch receipt but no executed frontier returns `missing executed prune frontier; preserve this store and replay into a separately named datadir`. `NodeStorage` seeds the retention registry from this value at open, so a restart never re-admits history a previous pass removed (`crates/node/src/state/storage.rs:51-53`).

`node:prune_batch` exists for one narrow case: proving whether *this* pass applied when `write_durable` returns an error after the batch may or may not have landed. The receipt is the previous value plus one, wrapping at `u64` (`crates/storage/src/pruning.rs:175-185`).

A wrong row length is corruption, not absence: `invalid persisted pruneheight length {len}`, `invalid persisted prune frontier length {len}`, or `invalid persisted prune batch length {len}`. None of these degrades to an empty frontier.

## Crash safety of a prune

A prune pass stages every deletion into a batch, calls the `before_commit` hook with `pruned_below`, puts all three metadata keys, then calls `write_durable`. The pass commits the reservation only after the batch returns. On an error, the pass reloads the three keys and decides from what is on disk (`crates/storage/src/pruning.rs:185-207`):

- If the stored frontier is at least the intended frontier, the stored prune height equals the request, and the stored receipt equals the receipt this pass wrote, the batch applied. The pass commits the reservation, reclaims the staged files, and returns success.
- If the keys are readable but do not match, the batch did not apply; the error is returned and the reservation is released.
- If the keys cannot be read, the pass calls `reservation.fail_closed()`. The failure is not assumed away.

The deletion rows and the frontier are in one batch, so a crash cannot leave rows deleted below a frontier that still admits them. A crash between the metadata commit and file unlink leaves a whole file with no locator rows and an intact `blkfile` row; the next pass selects that file again and unlinks it. Dead bytes are recoverable, deleted rows are not.

The retention reservation also blocks readers: while a prune pass holds its reservation, a history request below the reserved line returns `HistoryUnavailable::Reserved`, so a reader cannot start work on a row the pass is about to delete.

The node refuses two cases before any deletion:

- A snapshot role with a base height. `PruneAuthority::begin` checks the chainstate role and returns `ApplyError::PruneDuringHistoricalValidation { base_height }`, displayed as `cannot prune while historical validation is required through assumeutxo base height {base_height}` (`crates/execution/src/lib.rs:232-240`). Both `AssumedActive` and `Historical` carry a base height, so prefix pruning is refused while either role exists (`crates/execution/src/assumeutxo.rs:56-89`).
- A height at or above the safe line, as described above.

## What a pruned node advertises and refuses

`--prune-target-mb` greater than zero turns on pruned mode. The node advertises `WITNESS | NETWORK_LIMITED` instead of `WITNESS | NETWORK`, adding `P2P_V2` when v2 transport is on (`crates/node/src/state/open.rs`). Outside IBD, its download policy lets a `NETWORK_LIMITED` peer serve a height only when that height is within the last 288 blocks of the peer's tip (`crates/node/src/p2p/download_window/policy.rs:18-20`, `90-140`). `getblockchaininfo` reports `"pruned": true`, the stored `pruneheight`, and `prune_target_size: None` (`crates/serving/src/handlers/chain.rs`).

The node refuses reads that need a deleted body with distinct messages:

- `getblock` with verbosity 0 returns `not found: block data pruned` (`crates/serving/src/handlers/chain.rs`).
- `getblock` with verbosity 2 returns `Block not available (pruned data)` when the undo-backed spend list is requested (`crates/serving/src/handlers/chain.rs`). A pruned spend list alone degrades to no `spent` list while the block still renders.
- The embedding API returns `block body pruned for {hash}` (`crates/node/src/embed.rs:94-101`).
- Historical reads return `HistoryUnavailable::Pruned { below }`, displayed as `history below height {below} is pruned`.

Pruning is incompatible with the transaction, script, and compact-filter indexes, because each needs the history a prune deletes. Two checks enforce it: config validation and the derived-index open path (`crates/node/src/config.rs`, `crates/node/src/state.rs:410-416`). The startup refusal is one line:

```text
Error: transaction, script and compact-filter indexing are not compatible with -prune
```

[Storage and memory](../run/storage.md) shows that refusal as an operator command.

## Worked trace

The trace starts a regtest node with `--prune-target-mb 600` on a throwaway directory (`$DATA`). Each `$ rpc` line below is the authenticated JSON-RPC POST shown in [First start](../run/first-start.md), with only the method and parameters changing; the transcript shortens paths and the cookie.

```sh
$ bitcoin-rs --network regtest --data-dir $DATA --prune-target-mb 600 \
  --rpc-bind 127.0.0.1:41998 --dns-seeds-enabled=false
$ rpc generatetoaddress '[300,"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]'
{"error":null,...,"result":["...","...", ... 300 hashes ...]}
$ rpc getblockchaininfo '[]'
blocks=300 pruned=True pruneheight=None size_on_disk=89002
```

The first prune asked for a height inside the margin, and the second returned success but could not delete anything yet:

```text
$ rpc pruneblockchain '[250]'
{"error":{"code":-32602,"message":"invalid params: prune height is within reorg safety margin"},...}
$ rpc pruneblockchain '[5]'
{"error":null,"id":"1","result":5}
$ rpc getblock '["<hash at height 1>",0]'
{"error":null,"id":"1","result":"0000002006226e46..."}
```

`getblock` still served height 1 because the node had published no checkpoint yet, so `durable_tip_height` was 0 and the policy line was 0. `node:pruneheight` was 5; `node:prune_executed` stayed at 0. The two keys diverge here, which is why both exist.

A clean `SIGTERM` then published checkpoint generation 1 at height 300; after a restart on the same directory, the same request deleted the rows:

```text
$ rpc pruneblockchain '[5]'
{"error":null,"id":"1","result":5}
$ rpc getblock '["<hash at height 4>",0]'
{"error":{"code":-5,"message":"not found: block data pruned"},...}
$ rpc getblock '["<hash at height 4>",2]'
{"error":{"code":-1,"message":"Block not available (pruned data)"},...}
$ rpc getblock '["<hash at height 5>",0]'
{"error":null,"id":"1","result":"000000202b711003..."}
```

Height 4 is gone, height 5 is the first retained block, and `size_on_disk` stayed at 89002 because all 300 blocks were in the current `blk00000.dat`, which is never unlinked. A whole-file prune only reclaims space once a file is no longer the append target.

## Failure modes

- Height above the applied tip: RPC `prune height cannot exceed applied tip`; no batch is staged.
- Height inside the margin: `prune height is within reorg safety margin` from the RPC, or the same message from storage if a caller bypasses the RPC check.
- Snapshot role present: `cannot prune while historical validation is required through assumeutxo base height {base_height}`. No rows are staged.
- Ambiguous `write_durable`: the pass proves success from the three keys or fails closed. It never treats an unreadable frontier as empty.
- Missing executed frontier with other prune metadata: open fails with `missing executed prune frontier; preserve this store and replay into a separately named datadir`.
- Deep reorg whose disconnected body was pruned: planning returns `no stored body for block {hash} at height {height}`, and a boot rewind with a disconnect marker reports `a rewound block body is missing` inside `DurableHeadGapUnrecoverable`. Neither path substitutes a different block at the same height. [`RCV-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-07-missing-disconnected-body-routes-to-canonical-rebuild) routes retained history to a canonical rebuild and a pruned node to unavailable.
- Read below the line: `not found: block data pruned`, `Block not available (pruned data)`, or `history below height {below} is pruned`, depending on the surface. None returns empty success.

> **Warning** A successful `pruneblockchain` call reports the requested line, not the executed one. Compare `getblock` results, or inspect `node:prune_executed`, when the datadir has no recent checkpoint.

## Where the invariant is proven

- `ARCH-08` owns durable pruning and the executed frontier; `SYNC-07` owns required-history availability; `RCV-07` owns missing-body recovery; `ARCH-07b` owns the snapshot roles that refuse pruning.
- `crates/storage/tests/prune_then_reorg.rs::prune_to_height_deletes_rows_below_the_line_and_persists_pruneheight` proves the exclusive boundary and the stored height. It ran on this checkout:

```text
test prune_then_reorg::prune_to_height_deletes_rows_below_the_line_and_persists_pruneheight ... ok
test result: ok. 2 passed; 0 failed; 52 filtered out
```

- In the same file, `undo_pruning_keeps_records_the_durable_tip_still_needs`, `prune_to_height_respects_an_active_retention_lease`, `retention_lease_stops_the_prune_line_at_its_floor`, and `history_request_between_planning_and_commit_is_refused` prove the lease and reservation bounds.
- `ambiguous_durability_promotes_the_line_the_batch_already_persisted`, `ambiguous_durability_releases_the_claim_when_nothing_applied`, `ambiguous_durability_fails_closed_when_the_outcome_is_unprovable`, and `ambiguous_durability_does_not_confuse_a_retry_with_its_earlier_pass` prove the crash matrix.
- `executed_frontier_survives_restart_and_refuses_deleted_heights`, `executed_frontier_is_monotonic_across_passes_and_reintroduced_rows`, `missing_executed_frontier_after_prune_fails_closed`, and `corrupt_prune_metadata_never_becomes_an_empty_frontier` prove the three keys.
- `crates/node/src/state/tests/prune.rs::prune_waits_for_chain_transition_and_revalidates_applied_tip` proves the transition fence; `assumeutxo_validating_blocks_prefix_pruning_even_above_base_height` proves the snapshot-role refusal.
- `crates/node/src/state/tests/recovery.rs::prune_then_reorg_refuses_deleted_history_but_keeps_retained_reorgs` proves reorgs still work inside retained history.
- `crates/node/tests/crash_recovery.rs::pruned_frontier_survives_sigkill_and_preserves_boundary` proves a `SIGKILL` leaves the frontier intact.

## Boundaries

At HEAD, the numeric `--prune-target-mb` value does not drive a size loop. `prune_to_height` constructs `PrunePolicy { target_size_mb: 0, keep_below_tip: 288 }`, and `pruneblockchain` is its only production caller (`crates/storage/src/pruning.rs:146-160`). The flag selects pruned mode, service flags, the prune service, and the index refusal; the height decides what goes. `getblockchaininfo` reports `prune_target_size: None`. Do not expect the node to shrink itself to a target size without a prune call.

No measurement here covers reclaim under a multi-file history, pruning during IBD, or disk-usage accounting after whole-file deletion. The safety margin is a constant, not a measured reorg depth. The write order that publishes the checkpoint bounding the line is in [Checkpoints and recovery](checkpoints-and-recovery.md#the-publish-protocol).
