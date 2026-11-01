# Startup

The binary parses the CLI, resolves config, opens the data directory under a lock, restores chainstate from checkpoint or journal, verifies the recent tip, then binds services in a fixed order: metrics, RPC, P2P, and finally the event loop. Most steps log one INFO or DEBUG line you can match against a real run; the metrics bind and ZMQ bind emit no line. This page walks that order with the owning file and function for each step. [run/first-start.md](../run/first-start.md) covers the operator procedure, [embed/lifecycle.md](../embed/lifecycle.md) covers embedding, and `EVT-02` in `docs/contracts/architecture.md` owns the event contract.

## From main to open

`main` (`bin/bitcoin-rs/src/main.rs:36`) parses `CliArgs`, resolves config through `config::resolve` (CLI flags and env merged onto optional `--config` and `--bitcoin-conf` files), and calls `bitcoin_rs_node::run` (`crates/node/src/lifecycle.rs`, exported via `run.rs`). `start_node` (`crates/node/src/lifecycle.rs:633`) is the sequence owner:

1. `config.validate()` again at the node boundary (`lifecycle.rs:638`).
2. Register consensus trace probes and cap the global rayon pool at 4 threads (`cap_global_thread_pool`, `lifecycle.rs:891`, `GLOBAL_RAYON_THREADS = 4`).
3. `NodeState::open` (`crates/node/src/state/open.rs:173`), the storage and chainstate open described next.
4. Start index workers (`lifecycle.rs:651`), then log `bitcoin-rs node booting` with the full config (`lifecycle.rs:656`).
5. Init metrics (`init_metrics_services`, `lifecycle.rs:840`) when `--metrics-bind` is set, plus the readiness sampler.
6. Install the signal handler (`ShutdownHandler::install`, `lifecycle.rs:682`) that triggers both the state shutdown latch and the chainstate shutdown request.

## Opening the state

`NodeState::open_inner` (`open.rs:194`) runs in this order:

1. `config.validate()`, create the data dir, acquire the data-dir lock (`DataDirLock::acquire`, `open.rs:212`). A second process on the same datadir fails here with a `DataDirLock` error.
2. `initialize_data_dir` (`open.rs:214`) creates the process epoch used by recovery evidence.
3. Split the dbcache budget between chainstate and txindex (`open.rs:219`), then `NodeStorage::open` (`open.rs:225`).
4. Bind ZMQ publisher sockets from `[[notifications.zmq]]` TOML endpoints (`open.rs:236`; key form in [reference/config-keys.md](../reference/config-keys.md)).
5. `require_full_script_attestation` then `prepare_initial_chainstate` (`open.rs:253`): restore from checkpoint or journal, or start cold. The chosen source logs one line from `crates/chainstate/src/recovery.rs:339`, `:354`, or `:464`:

   ```
   INFO bitcoin_rs_chainstate::recovery: chainstate restore selected restore_source="checkpoint" checkpoint_generation=2 checkpoint_height=5 height=5 hash="0ef5cd..."
   INFO bitcoin_rs_chainstate::recovery: chainstate restore selected restore_source="journal" checkpoint_generation=1 checkpoint_height=0 height=3 hash=7ae5b4e2... replayed_records=3 chain_tx_count=4 replay_seconds=0.0003619
   INFO bitcoin_rs_chainstate::recovery: chainstate restore selected restore_source="cold" reason="no_complete_checkpoint"
   ```

   The journal variant is the replay path: `replayed_records=3` journal records were re-applied on top of the checkpoint, and `replay_seconds` times that work (`recovery.rs:464`). A checkpoint fallback with a gap above `STALE_RESTORE_ERROR_THRESHOLD` logs the `stale checkpoint restore` error (`open.rs:328`).
6. Open the journal writer, mempool, script cache, and fee history; build `Chainstate::from_parts` (`open.rs:365`).
7. Construct the P2P service with resolved slots: `FAST_OUTBOUND_PEER_TARGET` under `--fast-sync`, otherwise `P2P_OUTBOUND_FULL_RELAY_SLOTS` (`open.rs:452`); services flags include `NETWORK_LIMITED` when pruning (`open.rs:484`).
8. Install the tip-staged hook for mining (`open.rs:516`), the mempool gateway, block-announce queue, and chain followers (`open.rs:533`).
9. Configure checkpointing (`open.rs:551`) and clear any disconnect marker (`open.rs:556`); an unrecoverable durable-head gap returns `UnrecoverableDurableHeadGap` naming the three on-disk paths to fix or wipe.
10. Restore the mempool snapshot (`open.rs:587`) with its `mempool snapshot revalidation finished` line, then open the assumeutxo manager and the block sync.
11. `verify_startup_window` (`open.rs:138`) re-verifies the last `STARTUP_VERIFY_DEPTH = 6` blocks (`crates/chainstate/src/verify.rs:24`) at `CheckLevel::CheckUndoAndCommitments`, logging `startup verification passed blocks=5` (`open.rs:149`). Failure returns `StartupVerification` with the four paths to inspect.

One real cold start, trimmed (timestamps and LSM-tree table recovery removed; `$DATA` is the data directory):

```
INFO bitcoin_rs_chainstate::recovery: chainstate restore selected restore_source="cold" reason="no_complete_checkpoint"
INFO bitcoin_rs_node::state::open: no mempool snapshot; starting with an empty pool status="missing"
INFO bitcoin_rs_node::state::open: opened storage backend with effective cache capacities backend="fjall" chainstate_cache_bytes=471859200 txindex_cache_bytes=0 total_cache_bytes=471859200
INFO bitcoin_rs_node::lifecycle: bitcoin-rs node booting config=NodeConfig { network: Regtest, data_dir: "$DATA", ... }
DEBUG bitcoin_rs_node::state::open: startup verification passed blocks=0
```

## Binding services

After `NodeState::open` returns, `start_node` wires the runtime pieces in dependency order (`lifecycle.rs:666` onward): P2P chain query, mining coordinator, block announcer (with the stale-tip retainer from [header-sync-and-block-download.md](header-sync-and-block-download.md)), the pow-valid announce hook, tx relay and tx ingress workers, then genesis bootstrap.

The bind order is:

1. RPC: `bind_rpc_with_pool` then `start_rpc_listeners`, one line per surface (`lifecycle.rs:866`):
   `INFO bitcoin_rs_node::lifecycle: rpc listener bound addr=127.0.0.1:46733 surface=Shared`
2. Pool (feature-gated), after RPC.
3. P2P: `P2pService::start` (`lifecycle.rs:828`) binds the listener:
   `INFO bitcoin_rs_p2p::service: p2p listener bound addr=127.0.0.1:0` (port `:0` on regtest; the log shows the requested value, the actual socket appears in `ss`/metrics).
4. Chainstate maintenance worker, then the event loop thread (`lifecycle.rs:828`).

`bind 127.0.0.1:0` in the booting config line is what was requested; use the `rpc listener bound` line for the real RPC address, or `--rpc-bind 127.0.0.1:8332` style fixed ports to make it predictable.

## The event loop

`EventLoop::spin` (`crates/node/src/event_loop.rs:31`) selects on three channels: shutdown close, a 1-second `SYNC_TICK` timer, and a sync wake that peer readiness or inbound messages send. Each tick calls `BlockSync::tick` (see [header-sync-and-block-download.md](header-sync-and-block-download.md)). Two guards sit after every iteration: `sync.apply_halted()` requests shutdown and increments `node.sync.apply_halt_shutdowns` (`event_loop.rs:78`), and every `SYNC_PROGRESS_INTERVAL = 1 minute` of elapsed time emits sync progress (`progress_due`, `event_loop.rs:95`; the test `telemetry_uses_elapsed_time_not_wake_count` pins that progress uses elapsed time, not wake count, `event_loop.rs:105`).

The stats heartbeat logs `event loop heartbeat` with iteration and tick counts every 1024 iterations at debug level (`event_loop.rs:41`, `STATS_INTERVAL` at `event_loop.rs:10`).

## Shutdown

The shutdown latch and chainstate shutdown request propagate to every service. `teardown` (`crates/node/src/lifecycle.rs:360`) joins core services in reverse order, saves the mempool snapshot, publishes a clean checkpoint when the shutdown was clean (`publish_clean_checkpoint_if_eligible`, `lifecycle.rs:563`, logging `published clean chainstate checkpoint` with a generation), and ends with `INFO bitcoin_rs_node::lifecycle: bitcoin-rs node exited cleanly` (`lifecycle.rs:404`). Signal handling, clean-checkpoint eligibility, and upgrade behavior are in [run/shutdown-and-upgrade.md](../run/shutdown-and-upgrade.md).

## Failure modes at startup

| Symptom | Owner | Error or log |
|---|---|---|
| Another process holds the datadir | `DataDirLock::acquire` (`open.rs:212`) | `DataDirLock` error from `NodeOpenError` |
| Durable head gap that replay cannot close | `recover_disconnect_marker` (`open.rs:556`) | `UnrecoverableDurableHeadGap { chainstate, checkpoints, txindex, source }` |
| Last 6 blocks fail undo/commitment checks | `verify_startup_window` (`open.rs:138`) | `StartupVerification` naming blocks, chainstate, checkpoints, txindex paths |
| Stored chain was not fully script-validated | `require_full_script_attestation` (`open.rs:253`) | warning `the stored chain was not fully script-validated; rebuilding it with full validation` (`crates/chainstate/src/recovery.rs:135`) |
| RPC port taken | `start_rpc_listeners` | `failed to bind RPC listener at {address}` (`run.rs:41`) |
| Metrics evidence identity mismatch | `init_metrics_services` | `metrics recorder already serves a different evidence identity` (`run.rs:71`) |

## Where this is proven

| Invariant | Test | Location |
|---|---|---|
| Event-loop progress uses elapsed time | `telemetry_uses_elapsed_time_not_wake_count` | `crates/node/src/event_loop.rs:105` |
| Startup window depth and level | `STARTUP_VERIFY_DEPTH = 6`, `CheckLevel::CheckUndoAndCommitments` | `crates/chainstate/src/verify.rs:24`, `open.rs:142` |
| Journal replay matches the durable head identity | `replayed_frontier_must_match_the_durable_head_identity` | `crates/chainstate/src/journal/replay_tests.rs` (also cited in [how/state-and-storage.md](state-and-storage.md)) |
| Crash recovery end to end | `crates/node/tests/crash_recovery.rs` (clause `SYNC-05` evidence) |

Commands run for this page: the regtest traces above come from `/tmp/bitcoin-rs-book-head --network regtest --data-dir $DATA --log-level debug` with `generatetoaddress` over RPC; the restart traces (checkpoint and journal restore lines) come from a second and third start on the same datadir.

Contracts named: `EVT-02`, `SYNC-05` (`docs/contracts/architecture.md`, `docs/contracts/synchronization.md`).

## Limits

- ZMQ bind lines are not shown here: the traced run configured no `[[notifications.zmq]]` endpoints (the booting line shows `zmq: []`), so no ZMQ socket was bound and no bind line was logged (`open.rs:236`).
- The traced run had `pool: None` in its config (visible in the booting line), so `pool.start()` was skipped; the pool bind step is read from source only (`lifecycle.rs:809`).
- The `stale checkpoint restore` error line was read from source (`open.rs:328`), not reproduced; producing it requires a witness gap above `STALE_RESTORE_ERROR_THRESHOLD`.
