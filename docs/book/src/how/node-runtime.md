# Node runtime internals

One boot path and one teardown path run every node: the daemon `run()` and the embedded `Node::start` both enter `crates/node/src/lifecycle.rs::start_node`, and both stop through `NodeServices::teardown` (`crates/node/src/lifecycle.rs`). Inside that frame, the event loop is the only block-sync poller, the chain feed hands out settled snapshots, transaction ingress is the single writer that moves P2P transactions into the mempool, and a small metrics server answers Prometheus scrapes. This chapter names each worker, where it starts and stops, and what the shutdown order depends on.

The operator view of startup, recovery, and shutdown is in [Shutdown and upgrades](../run/shutdown-and-upgrade.md) and [Logs, metrics, and stalls](../run/observability.md); the embedder view is [Node lifecycle](../embed/lifecycle.md). Here it is the wiring itself.

## What starts, in what order

`start_node` (`lifecycle.rs`) wires in this order; every handle is recorded in a `StartupGuard` as it is created, so any later failure unwinds through the same teardown in `StartupAbort` mode:

| Step | Spawn site | Thread or socket | Stop site |
|---|---|---|---|
| index workers | `lifecycle.rs` via `state.start_index_workers` | derived-index worker | `bounded_index_shutdown`, first in teardown (`lifecycle.rs`) |
| metrics + readiness sampler | `lifecycle.rs` (`init_metrics_services`) | `bitcoin-rs-metrics`, `bitcoin-rs-metrics-readiness` | `MetricsServer::stop_and_join` (`crates/node/src/metrics.rs:303`) |
| shutdown forwarder or signals | `lifecycle.rs` | `bitcoin-rs-shutdown-forwarder`, signal thread | joined after bootstrap workers (`lifecycle.rs`) |
| mining coordinator + generation signal | `lifecycle.rs` | none, service object | dropped with the node |
| block announce worker | `lifecycle.rs` | p2p-owned thread | `join_core_services` (`lifecycle.rs`) |
| tx relay worker | `lifecycle.rs` | p2p-owned thread | `join_core_services` (`lifecycle.rs`) |
| tx ingress consumer | `lifecycle.rs` | `bitcoin-rs-tx-ingress` | `join_core_services` (`lifecycle.rs`) |
| RPC listeners | `lifecycle.rs` | `bitcoin-rs-serving` per listener, plus `rpc-connection` per request | `serve_surface_with_shutdown` drain, then join |
| pool service, if `--pool` | `lifecycle.rs` | SV1/SV2 listeners plus `pool-reconcile` | `pool.shutdown` (`lifecycle.rs`) |
| P2P service | `lifecycle.rs` | peer workers | `state.p2p().shutdown()` then joins |
| chainstate maintenance | `lifecycle.rs` | worker thread | joined after the P2P bootstrap drain (`lifecycle.rs`) |
| event loop | `lifecycle.rs` | `bitcoin-rs-event-loop` | joined first among core services (`lifecycle.rs`) |

The listener spawns the per-connection RPC threads itself, `rpc-connection` with a 2 MiB stack (`crates/serving/src/server.rs`). The global rayon pool is capped at 4 threads at boot (`cap_global_thread_pool`, `lifecycle.rs`).

## Event loop ticks

The event loop is a `crossbeam` select over three inputs (`crates/node/src/event_loop.rs:31-58`): the shutdown latch, a 1 second tick (`SYNC_TICK`, `event_loop.rs:8`), and a bounded wake channel that P2P triggers when new headers or blocks arrive (`sync_wake`, `lifecycle.rs`; `on_peer_ready`, `lifecycle.rs`). Every tick or wake runs one `BlockSync::tick` (`crates/node/src/p2p/sync.rs:426`), measured into the `node.event_loop.tick_seconds` histogram, and every 1,024 iterations the loop emits a debug heartbeat with the iteration and tick counts (`event_loop.rs:37-39`). Two side conditions end the loop: a shutdown latch fires, or `sync.closed_for_recovery()` reports a chainstate closed for recovery, in which case the loop itself requests shutdown and the run exits (`event_loop.rs:60-65`, counter `node.sync.apply_halt_shutdowns`). The loop emits a sync progress line when 60 seconds have actually elapsed since the last one, not once per tick (`progress_due`, `event_loop.rs:82`); `telemetry_uses_elapsed_time_not_wake_count` (`event_loop.rs:92`) pins that rule.

`BlockSync::emit_sync_progress` (`crates/node/src/p2p/sync/telemetry.rs:4`) logs the applied height, header height, gap, live peers, and IBD state; it logs a `sync progress: frontier cannot advance` warning instead when the plan reports a stall reason other than being at the tip. The trace below shows both shapes of the line.

## Chain feed: stable hint and settled poll

The chain feed (`crates/node/src/chain_feed.rs`) is the library face of the chain for embedders and internal consumers that are not the sync engine. `settled_snapshot` (`chain_feed.rs:82`) is the primitive: it takes the chain transition lock with `try_lock_for(Duration::ZERO)` and answers `chain transition in progress` instead of waiting, then refuses when the node is shutting down or the mempool gateway has no stable generation (`ensure_chain_settled`, `chain_feed.rs:210-217`). A caller either gets a snapshot from a settled chain or an error; it never gets a torn read and never blocks a block connect.

On top of that primitive: `subscribe_chain` records a cursor snapshot, `poll_chain` (`chain_feed.rs:109`) answers an update with a `gap` flag whenever the new snapshot is not provably adjacent to the cursor (height step of one with a matching prev-block hash, same epoch, consecutive sequence), and `pin_chain`/`replay_chain` (`chain_feed.rs:97`, `chain_feed.rs:143`) let a consumer walk disconnected and connected steps toward a pinned target. Replay is bounded to 256 steps per call and 4,096 ancestry hops (`chain_feed.rs:58-59`), refuses targets from another node run, and answers `re-pin replay target after restart` when the pinned epoch or sequence no longer matches. The tests `settled_poll_replays_gaps_disconnects_and_pinned_targets` and `unsettled_or_failed_chain_fences_never_publish_a_stable_hint` (`crates/node/src/chain_feed/tests.rs:51,127`) pin the gap and fencing rules.

## Transaction ingress: RPC and P2P into the mempool

Every mutation enters through one gateway, `MempoolGateway`. The RPC and embedded paths call it directly: `sendrawtransaction` submits with `LocalOrigin::Rpc` (`crates/serving/src/handlers/tx.rs:501-506`) and `Node::broadcast` submits through the same call with the same default fee-rate cap (`crates/node/src/embed.rs:158-176`); [EMB-05](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md#invariants) states that no production path mutates the pool outside the gateway.

The P2P path is asynchronous. The peer listener hands each inbound transaction or package to a bounded channel (`state.inbound_tx_sender`, `crates/node/src/state.rs:229`), and one consumer thread, `bitcoin-rs-tx-ingress`, drains it (`spawn_tx_ingress_consumer`, `crates/node/src/tx_ingress.rs:17-39`). The loop (`run_consumer_loop`, `tx_ingress.rs:41-62`) alternates between draining the channel and a 100 ms retry pass that runs `maintain_orphans` and `retry_orphans` (`tx_ingress.rs:185-194`), so an orphan whose parents arrive later is retried without any peer round trip. After a commit, three things happen in order (`dispatch_common_outcome`, `tx_ingress.rs:256-291`): the relay queue announces the txid to other peers, `mining_control.publish_generation()` wakes the template coordinator, and the peer table records the response. Package relay follows the same spine with a charge-overrun counter, `node.package_charge_overrun`, when a decoded package's measured heap exceeds its planned charge (`process_package`, `tx_ingress.rs:95-129`). ZMQ publication is not wired here; it is a gateway observer leg (`MempoolSequenceObserver`, `crates/serving/src/zmq.rs:493`), so the RPC, P2P, and embedded paths all publish identically.

A worked refusal from the trace node: a well-formed transaction spending an unknown prevout is rejected at the gateway with the consensus reason string,

```console
$ curl -sS -u "$COOKIE" -H 'content-type: application/json' -d '{"method":"sendrawtransaction",
  "params":["0200000001000000...515100000000"],"id":2}' http://127.0.0.1:45553/
{"error":{"code":-25,"message":"bad-txns-inputs-missingorspent"},"id":2,"result":null}
$ curl -sS ... -d '{"method":"getrawmempool","params":[],"id":3}' ...
{"error":null,"id":3,"result":[]}
```

The accepted path, relay wake, mining wake, orphan retry, and package handling are pinned by unit tests in `crates/node/src/tx_ingress/tests.rs`: `accepted_tx_relays_and_wakes_mining` (`tests.rs:222`), `rejected_tx_does_not_relay_or_wake_mining` (`tests.rs:176`), `retry_poll_evicts_an_orphan_after_its_connection_is_gone` (`tests.rs:369`), and `consumer_processes_admitted_package_and_publishes_generation` (`tests.rs:392`).

## Metrics endpoint

With `--metrics-bind`, `MetricsServer::bind` (`crates/node/src/metrics.rs:271`) installs one Prometheus recorder for the process and spawns `bitcoin-rs-metrics` to serve scrapes. The recorder is pinned to an `EvidenceIdentity` (`metrics.rs:83`): the binary SHA-256, the config digest, backend, durability, and CPU model. A second bind with a different identity fails with `MetricsIdentityMismatch` instead of silently reporting numbers from two configurations under one name. The scrape handler reads one 1 KiB request buffer, renders `text/plain; version=0.0.4`, closes the connection, and enforces 2 second socket timeouts (`serve_scrape`, `metrics.rs:361-373`). Shutdown cannot hang the accept loop: the latch handler self-connects to the listener address so `accept` returns (`metrics.rs:340-343`). A readiness sampler thread samples the txindex capability once per second into `node.capability.txindex_readiness` with one label per state (`spawn_readiness_sampler`, `metrics.rs:386-404`).

`describe_node_metrics` (`metrics.rs:113-183`) declares the metric families. Scraped from the trace node (names as rendered, dots become underscores):

```text
node_event_loop_sync_ticks 217
node_event_loop_tick_seconds ... summary
node_capability_txindex_readiness{state="Ready"} 1
node_capability_txindex_readiness{state="Opening"} 0   (and seven other states)
node_shutdown_requested ...
node_package_charge_overrun ...
node_sync_pending_blocks_high_water ... staged_* and inbound_* queue depths
storage_writes_total{backend="rocksdb",durability="durable"} 105
storage_writes_total{backend="rocksdb",durability="default"} 204
storage_flushes_total ... storage_write_bytes ... storage_cache_capacity_bytes
index_family_planned_write_bytes ...
rpc_connections_active{surface="shared"} ...
rpc_connections_rejected_total{surface="shared"} ...
rpc_http_request_seconds{surface="shared",route="json_rpc"} ... summary
rpc_esplora_expensive_active ... rejected_total ... execution_seconds
```

The operator guide with capture procedures is [Logs, metrics, and stalls](../run/observability.md).

## Embedded node versus daemon

The daemon is `run()` (`crates/node/src/run.rs:295`): install tracing, call `start_node(config, runtime, true)`, block on the shutdown latch, then `shutdown_blocking()`. `install_signals = true` wires SIGINT and SIGTERM into `state.shutdown_writer()` plus `chainstate.request_shutdown()` (`lifecycle.rs`, `crates/node/src/signal.rs:14-27`). An embedded node passes `false` (`crates/node/src/embed.rs:47-50`), installs no signal handlers, and instead offers `RuntimeInputs::with_shutdown`: one named `bitcoin-rs-shutdown-forwarder` thread forwards the caller's receiver to the same two latches and is ended by the node's own latch so teardown never hangs on an open sender (`lifecycle.rs`; [EMB-09](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md#invariants)).

The second difference is address visibility. Both paths bind with `RpcServer::bind`, and both log the kernel-assigned address per listener (`lifecycle.rs`, `rpc listener bound addr=127.0.0.1:44895 surface=Shared`, verified in the trace). The parsed addresses are kept in `NodeServices::rpc_addresses`, but the accessor is compiled for tests only, so an embedder that binds port 0 reads the port from the log line, not from the API ([embed lifecycle chapter, Bound addresses](../embed/lifecycle.md)). The metrics listener has no log line at all; the trace below discovered its port with `ss -tlnp` filtered by PID, and an embedder binding `:0` must do the same or choose a fixed port.

The third difference is shutdown ownership: `Node::shutdown(self)` consumes and runs `CleanShutdown`, a drop without it runs the identical teardown as `StartupAbort` and publishes no checkpoint (`embed.rs:181-203`). The node latch is a child of the chainstate latch, so a recovery closure anywhere stops the whole node, not only its P2P or index users ([EMB-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md#invariants)); `recovery_closure_stops_the_node_run_loop` (`crates/node/src/lifecycle/tests.rs`) pins it, and `daemon_and_embedded_paths_share_one_teardown` (`lifecycle/tests.rs`) pins the single teardown.

## Mining and reorg glue

The mining coordinator is assembled at boot (`lifecycle.rs`): `MiningCoordinator` (`crates/node/src/mining.rs:75-103`) adapts the applied tip, the mempool reader, and the block tree into a `MiningService`, and the node's `MiningGenerationSignal` is attached to it. The signal fires on every committed gateway mutation and on every applied-tip connect or disconnect ([EMB-08](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md#invariants)), which is how `getblocktemplate` long-poll waiters and the pre-built candidate wake when the mempool changes. Template selection takes the mempool snapshot under the coordinator's expected sequence numbers so a stale template is detected and rebuilt (`MempoolAdapter::select_template`, `mining.rs:239`).

Submission goes through the chain transition, not around it: `MiningCoordinator::submit` locks the transition, opens a mempool change, and applies the block through `apply_connect_in_transition` (`mining.rs:158-190`), so a mining submit races with block sync on the same terms as any other apply. Mapping from apply failures to BIP22 reject reasons lives in `bip22_reject_reason` (`mining.rs:593`). The propagate hook on the chainstate (`set_pow_valid_block`, `lifecycle.rs`) hands a solved block to the block announcer so a `submitblock` from RPC and a P2P announcement share one path. Template and generate behavior contracts are [API-05](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-05-solo-mining-generate-path) through [API-11](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-11-bip22bip23-template-extras); the pool service that serves shares is described in [Mining and the native pool](../use/mining-and-pool.md) and [pool-ledger](pool-ledger.md).

Reorg control is glue too. `invalidateblock` reaches `crate::reorg::invalidate_block` through `RpcChainControl` (`lifecycle.rs`), which wraps `bitcoin_rs_execution::reorg::invalidate_block` with the node's mempool follower (`crates/node/src/reorg.rs:158-172`). The observer feeds every disconnect and connect to `ChainFollowers` and collects disconnected transactions for re-admission, capped at 20 MiB (`MAX_DISCONNECTED_TX_BYTES`, `reorg.rs:12`); settlement then reconsiders them, removes txs conflicted by the new branch, and trims the pool back under its size limit (`settle_node_reorg`, `reorg.rs:79-129`). After the branch switch, checkpoint debt is settled once (`settle_checkpoint_debt`, `reorg.rs:147-157`, log line `published checkpoint after branch switch`), and the sync engine is told to purge invalidated staged blocks and record the demoted tip (`lifecycle.rs`). The block-connect and reorg behavior itself is owned by [architecture](architecture.md) and [block-connect-and-reorg](block-connect-and-reorg.md).

## Index worker and pool service shutdown

The derived index worker is the one worker with an abandon path. `DerivedIndexHost::shutdown` (`crates/node/src/state/index.rs:120-139`) requests shutdown, joins with a deadline, and on expiry revokes the generation, marks the lifecycle `ShutdownAbandoned`, poisons the namespace, and detaches without joining, which records a teardown error so no checkpoint publishes while detached index I/O could still write ([EMB-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md#invariants)). Teardown calls it first with the 5 second `DRAIN_DEADLINE` (`lifecycle.rs`), before anything else stops.

The pool service, when compiled and configured, opens the ledger under its own directory lock at boot (`crates/node/src/pool.rs:93-148`), starts SV1 and SV2 listeners plus a `pool-reconcile` worker that refreshes templates and reconciles chain state every 250 ms (`pool.rs:154-217`), and stops with the same deadline discipline: listeners first, then the worker unparked to drain its outbox and block-record queue (`pool.rs:225-250`). SV2 runs one thread per connection named `pool-sv2-<ip>` and joins them under the deadline, reporting panics as teardown errors (`crates/node/src/pool/sv2.rs:77-116`). Pool accounting is owned by [pool-ledger](pool-ledger.md).

## Shutdown, end to end

`NodeServices::teardown` (`lifecycle.rs`) runs the order that the trace shows. Stage one stops the writers that own durable state: bounded index shutdown, pool shutdown, then `state.request_shutdown()` and `p2p().shutdown()` (`lifecycle.rs`). Stage two joins consumers in dependency order: event loop, RPC listeners (each answers `rpc listener exited cleanly` after its drain), metrics, readiness sampler, P2P core workers, tx ingress, package-claim release, tx relay, block announce. Stage three joins the bootstrap drain, maintenance worker, shutdown forwarder, and signal handler. Only then, in `CleanShutdown` mode with no recorded error, does it publish the clean checkpoint, save fee-estimator history, and write the mempool snapshot under a 10 second budget. The first failure anywhere is remembered while later stages still run, so teardown always completes.

The full trace from the regtest run (SIGTERM at 20:22:48, idle keep-alive RPC connection open, everything drained within 12 ms):

```text
20:22:48.521789 INFO rpc listener exited cleanly
20:22:48.522371 INFO p2p listener exited cleanly
20:22:48.522446 INFO tx ingress consumer exited cleanly
20:22:48.522480 INFO tx relay worker exited cleanly
20:22:48.522513 INFO block announce worker exited cleanly
20:22:48.522569 INFO chainstate maintenance worker exited cleanly
20:22:48.529182 INFO published clean chainstate checkpoint generation=1
20:22:48.529511 INFO saved fee-estimator history path=$DATA/fee-estimator-history.dat bytes=57965
20:22:48.530242 INFO prepared mempool snapshot transactions=0 bytes=84 elapsed_ms=0
20:22:48.533138 INFO bitcoin-rs node exited cleanly
```

The next boot replays nothing and restores from that checkpoint:

```text
chainstate restore selected restore_source=checkpoint checkpoint_generation=1
    checkpoint_height=101 replayed_records=0 replay_seconds=0.000094
restored chainstate checkpoint height=101 hash=03b05555...70ac5
restored fee-estimator history bytes=57965
mempool snapshot revalidation finished restored=0 status=restored
```

Teardown-order tests in `crates/node/src/lifecycle/tests.rs`: `clean_shutdown_publishes_checkpoint_and_returns_success`, `explicit_shutdown_joins_index_worker_before_clean_checkpoint`, `a_queued_shutdown_wake_does_not_block_teardown`, and `repeated_teardown_and_drop_join_workers_once`.

## A start-to-tip trace

From the same run, the lines that show the runtime working, with boot noise removed:

```text
20:17:06.449480 INFO chainstate restore selected restore_source=cold reason=no_complete_checkpoint
20:17:06.477694 INFO opened storage backend with effective cache capacities backend="rocksdb"
    chainstate_cache_bytes=377487360 txindex_cache_bytes=94371840
20:17:06.477874 INFO bitcoin-rs node booting config=NodeConfig { ... esplora_max_queries: 2,
    rest: true, max_connections: 128 }
20:17:15.755125 INFO rpc listener bound addr=127.0.0.1:44895 surface=Shared
20:17:15.761234 INFO p2p listener bound addr=0.0.0.0:18444
20:18:15.819201 INFO sync progress applied_height=0 header_height=0 gap=0 peers=0 ibd=true
20:19:15.856707 INFO sync progress applied_height=101 header_height=101 peers=0 ibd=false
20:20:15.890213 INFO sync progress applied_height=101 header_height=101 peers=0 ibd=false
```

The 101 blocks between the second and third progress lines came from one `generatetoaddress 101` call; the progress line carries `gap` only while in IBD, matching `emit_sync_progress` (`crates/node/src/p2p/sync/telemetry.rs:22-34`). No DNS seeds resolve in this sandbox (`DNS bootstrap unavailable`), so `peers=0` throughout; block sync itself, the window and staging machinery, is owned by [header-sync-and-block-download](header-sync-and-block-download.md).

## Where it is proven

Lifecycle clauses live in [docs/contracts/embedding.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md): `EMB-01` one owned lifecycle and the teardown order, `EMB-02` caller-owned runtime, `EMB-05` shared admission, `EMB-07` shutdown consumes, `EMB-08` mutations wake the coordinator, `EMB-09` shutdown wake cannot block teardown, `EMB-10` independent runtime-stall evidence. Broadcast identity is additionally pinned by `broadcast_publishes_one_ordered_a_event_through_the_shared_gateway` (`crates/node/src/embed.rs:338`), the event-loop timing rule by `telemetry_uses_elapsed_time_not_wake_count` (`crates/node/src/event_loop.rs:92`), and prompt latch wake by `wait_for_shutdown_wakes_promptly_on_trigger` (`crates/node/src/run.rs:335`).

Not exercised here: the P2P side of transaction ingress ran through its unit tests rather than live peers, because the trace node had no reachable peers; `apply_halted` shutdown and the index-worker abandon path are known from source and their tests, not from this run.
