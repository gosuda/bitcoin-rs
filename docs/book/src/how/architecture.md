# Architecture

A block moves through six stages: the peer connection, the sync loop, the block stager, the chainstate transition, the durable-head commit, and the node followers. Chainstate owns the authoritative mutation; every other stage either feeds it or observes its committed result (`ARCH-07`, [architecture contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md#arch-07-chainstate-owns-authoritative-applied-chain-mutation)).

```text
peer read loop (crates/wire/src/listener.rs)
  |  InboundBlock { BlockImage, source, credits }
  v
bounded inbound-block channel (crates/wire/src/service.rs)
  |  wake
  v
BlockSync::tick (crates/node/src/p2p/sync.rs)
  |  drain, bind body to header, divert historical deliveries
  v
BlockStager::insert (crates/node/src/p2p/block_stager.rs)
  |  dedupe by hash, byte budgets, expected-prefix order
  v
apply_buffered_blocks (crates/node/src/p2p/sync/commit.rs)
  |  p2p::sync::chain::commit_window trait seam
  v
node commit_window (crates/node/src/sync.rs)
  |  chain transition + mempool generation fence
  v
chainstate connect_window (crates/execution/src/window.rs)
  |  per block: validate, persist undo/body, build coin delta
  |  per group: one durable-head batch (64 blocks or 8 MiB)
  v
publish_applied (crates/execution/src/lib.rs)
  |  applied-tip cell, ChainEventPublisher sequence
  v
node ChainFollowers::on_connect (crates/node/src/chain_effects.rs)
  |  block log, ZMQ, index wake, sequence, mining generation, mempool
  v
index worker (crates/projection/src/runtime) and RPC/ZMQ consumers
```

## Header sync

Headers arrive before bodies and are admitted separately. `BlockSync::tick` retires timed-out requests, drains inbound headers, bootstraps genesis when needed, reconciles peer sessions, advances historical work, then drains inbound blocks.

`request_headers_from_eligible` picks a usable peer, and `send_getheaders_tracked` records the request as `AwaitingResponse` with a 5 second timeout. A response before the deadline moves it to `ResponseQueued` without granting height credit (`P2P-05`). The headers pass through `HeadersSyncState::process`, the sole admission decider, and only then reach `Chainstate::admit_headers` (`P2P-10`, `ARCH-07`).

A body request follows the header. The header embedded in an inbound body also reaches header admission, so a body cannot arrive without its header (`P2P-06`).

## Staging

The peer thread never applies a block. It builds an `InboundBlock`, sends it on a bounded channel, and wakes the sync loop. If the channel is disconnected or the session was cancelled, the block is dropped rather than applied from a stale session.

`BlockStager::insert` deduplicates by hash and returns `AlreadyStaged` for a repeat. It refuses new entries at the retained-byte or received-byte budget and reports `DroppedForRetry`. `drain_expected_prefix` then yields entries in expected-hash order and stops at the first missing hash, so a later block cannot jump an earlier one.

## Apply and durable commit

`node::sync::commit_window` opens one chain transition, fences the mempool generation, calls `connect_window`, then runs followers per outcome. There is no second path that mutates the applied tip.

Inside chainstate, each block is applied with `PublishMode::Grouped`:

1. Consensus gates run before any write.
2. The block body is appended; the undo record is retained for the group commit.
3. The staged header tip advances and the window workspace accumulates the block's coin effects. Neither the published applied tip nor the engine coins advance here.
4. When the group reaches 64 blocks or 8 MiB, the appended bodies are synced and the workspace builds the final `WindowDelta`. One durable-head batch then commits through `CommitAuthority::commit_prefix`: undo rows, body locator rows, the script attestation, the coin replacements in the engine `Coins` keyspace, and the new head, with a compare-and-set on the previous head.
5. After the durable batch succeeds, `CommitAuthority::commit_prefix` calls `CoinStore::install_committed` to install the coin-cache delta and stats feed before returning its receipt. Body append and sync precede this batch; it is not the group's only write.
6. `publish_applied` stores the applied tip and advances the event sequence.

The durable receipt exists before the tip is published. Apply returns only after the batch receipt, so a reader that sees the new tip is seeing a head that survives a crash. A head that does not match the restored tip at startup is a replay gap; `matching_durable_head_requires_no_replay` in [`crates/execution/src/durable/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/execution/src/durable/tests.rs) pins that rule.

Coin writes go only through the head batch, into the engine `Coins` keyspace (`ColumnFamily::Coins`). The head batch names the undo and body rows that make those coin writes recoverable. The resident `UtxoSet` receives no coin writes; it parses snapshot input only.

## Publication and followers

`publish_applied` replaces the applied-tip cell under one gate and then records a `ChainSnapshot { epoch, sequence, tip_hash, tip_height }`. The snapshot is the coherent, non-torn view index consumers read (`EVT-01`). `resumed_snapshot_continues_sequence` in `crates/execution/src/events.rs` pins sequence continuity across restart.

`ChainFollowers::on_connect` runs while the transition is still held, in this order:

1. Push the block to the RPC block log.
2. Publish ZMQ `hashblock` and `rawblock`, plus transaction topics when enabled. Sends use `DONTWAIT`, so a slow subscriber cannot block the commit thread.
3. Wake the index worker by bumping a revision and trying a `bounded(1)` send. The wake carries no payload and coalesces.
4. Publish the mempool sequence event.
5. Publish the mining generation.
6. Apply block effects to the mempool, including confirmation eviction.

The index worker does its slow work on its own thread. Node keeps no parallel notifier model: the same live publisher answers `getzmqnotifications` (`ARCH-05`).

## Disconnect and reorg

A reorg takes the same transition lock in the other direction. `ChainTransition::disconnect` refuses a block that is not the applied tip. The disconnect arms a durable disconnect marker, builds the reverse coin delta from the block's undo record (`build_disconnect_delta`), and commits the parent head with that delta in one batch (`commit_disconnect_head`). Chainstate then publishes a `Disconnected` snapshot.

`ChainFollowers::on_disconnect` trims the RPC block log, publishes the ZMQ disconnect topics, wakes the index worker to roll back to the common ancestor, and hands the disconnected transactions to mempool reconsideration. Beyond 100,000 blocks of rollback, the index resets and rebuilds instead of rewinding (`IDX-06`).

## Worked trace

The trace below is verbatim from a regtest node started with `--log-level debug`. The block entered through `generatetoaddress`, not a peer, so the P2P stages are absent. The chainstate, publication, and follower stages are the same code path a peer-delivered block takes.

```text
{"timestamp":"2026-11-01T16:44:33.923132Z","level":"DEBUG","fields":{"message":"apply_block: profile","height":1,"input.block_hash":"5c3d99d734b492661bac6a4e3f5c8d78ad097ad42c0fa6e9814ca6692b4e5b24","tx_count":1,"block_rules_us":"8","bip30_bip34_us":"5","script_verify_us":"0","utxo_commit_us":"53","block_body_persist_us":"62","block_tree_insert_us":"16","coin_stats_us":"0","total_us":"482"},"target":"bitcoin_rs_execution::connect"}
{"timestamp":"2026-11-01T16:44:33.923168Z","level":"DEBUG","fields":{"message":"apply_block: tail begin","height":1,"outcome.hash":"5c3d99d734b492661bac6a4e3f5c8d78ad097ad42c0fa6e9814ca6692b4e5b24"},"target":"bitcoin_rs_execution::connect"}
{"timestamp":"2026-11-01T16:44:33.923258Z","level":"DEBUG","fields":{"message":"apply_block: publish profile","height":1,"outcome.hash":"5c3d99d734b492661bac6a4e3f5c8d78ad097ad42c0fa6e9814ca6692b4e5b24","durable_sync_us":"4","durable_commit_us":"67"},"target":"bitcoin_rs_execution::connect"}
{"timestamp":"2026-11-01T16:44:33.923435Z","level":"DEBUG","fields":{"message":"chain_effects: on_connect profile","height":1,"tip_hash":"5c3d99d734b492661bac6a4e3f5c8d78ad097ad42c0fa6e9814ca6692b4e5b24","on_connect_us":"59"},"target":"bitcoin_rs_node::chain_effects"}
{"timestamp":"2026-11-01T16:44:33.923453Z","level":"DEBUG","fields":{"message":"chainstate: transition held","transition_held_us":"807"},"target":"bitcoin_rs_execution"}
```

The order is the contract: apply profile, durable commit receipt, tip publication, follower dispatch, then the transition drops. The block held only a coinbase, so no input scripts ran; `script_dispatch=coinbase_only` records that, not a disabled check.

## Tests that pin the flow

| Invariant | Test | File |
| --- | --- | --- |
| Prefix drain stops at the first missing hash | `drain_expected_prefix_stops_at_first_missing_hash` | [`crates/node/src/p2p/block_stager/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/p2p/block_stager/tests.rs) |
| A matching durable head needs no replay | `matching_durable_head_requires_no_replay` | [`crates/execution/src/durable/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/execution/src/durable/tests.rs) |
| Followers emit in commit order | `connect_then_disconnect_rewinds_the_rpc_log_and_emits_in_order` | [`crates/node/src/chain_effects/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/chain_effects/tests.rs) |
| Event sequence survives restart | `resumed_snapshot_continues_sequence` | [`crates/execution/src/events.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/execution/src/events.rs) |
| Apply waits for a pending reorg | `apply_buffered_blocks_waits_for_pending_reorg` | [`crates/node/src/p2p/sync/tests/download_frontier.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/p2p/sync/tests/download_frontier.rs) |

The chain-events contract owns the fence order and the consumer cursor: [docs/contracts/chain-events.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/chain-events.md). The [state and storage](state-and-storage.md) chapter covers the durable records, and the [p2p](p2p.md) chapter covers peer policy before staging.
