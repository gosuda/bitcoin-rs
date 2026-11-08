# Node lifecycle

`Node::start` returns a running node. `Node::shutdown` stops it and publishes the clean checkpoint. Dropping the node without calling `shutdown` runs the same ordered teardown in startup-abort mode and publishes no checkpoint (`EMB-07`).

Both outcomes go through `crates/node/src/lifecycle.rs::start_node` and `NodeServices::teardown`; there is one lifecycle implementation, not two (`EMB-01`).

## Start

`Node::start(config, RuntimeInputs)` does the following before it returns:

1. `config.validate()` refuses an empty data directory and an uncompiled storage backend.
2. `NodeState::open` acquires the data-directory lock, opens the selected storage engine, restores or validates chainstate, and restores the mempool snapshot when one exists.
3. `start_index_workers` starts the derived index worker when an index is enabled.
4. Metrics, RPC listeners, P2P listeners, and the event loop start.

Every worker, socket owner, and channel end is recorded in a startup guard at creation. A later bootstrap failure rolls back through the same ordered teardown in `StartupAbort` mode and never publishes a checkpoint.

`Node::start` passes `install_signals = false` to `start_node`, so an embedded node does not install process signal handlers. The daemon's `run()` passes `true` and wires `SIGTERM` and `SIGINT` into the same shutdown path. An embedder that wants signal-driven shutdown passes its own receiver through `RuntimeInputs::with_shutdown`.

The node never creates, enters, or retains a runtime. Both `start` and `shutdown` are futures that run on the caller's executor (`EMB-02`).

## Readiness

There is no ready flag and no sleep. `Node::start` returns after storage open, recovery, and thread spawn, and the first `snapshot()` reflects the resumed applied tip. That snapshot is the readiness fact.

```rust
let node = runtime.block_on(Node::start(config, RuntimeInputs::default()))?;
let tip = node.snapshot();
assert_eq!(tip.tip_height, 0, "fresh regtest chain holds genesis only");
```

A node reopened on a cleanly shut down data directory returns the stored height. The in-process test [`embedded_node_lifecycle_round_trip`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/tests/embed.rs) seeds 100 regtest blocks, restarts, and asserts the resumed height.

## Bound addresses

RPC listeners bind, and the node records the real bound address with its surface:

```text
{"timestamp":"2026-11-01T16:44:24.418584Z","level":"INFO","fields":{"message":"rpc listener bound","addr":"127.0.0.1:44089","surface":"Shared"},"target":"bitcoin_rs_node::lifecycle"}
```

The record lives in `NodeServices::rpc_addresses` and is filled from `TcpListener::local_addr`, so binding `127.0.0.1:0` yields the kernel-assigned port. The accessor on `NodeServices` is crate-private and compiled for tests only. The public `Node` has no address accessor.

An external embedder that binds `:0` therefore cannot read the port back from the public API. Choose a known free port, or install a tracing subscriber and parse the `rpc listener bound` event. The test harness reaches the crate-private accessor because it lives inside the crate.

The P2P listener logs its configured address, not the bound one. A run with `--p2p-listen 127.0.0.1:0` prints `addr=127.0.0.1:0`, so that log line does not tell you which port the kernel chose.

## Shutdown

`Node::shutdown(self)` consumes the node and runs the ordered sequence exactly once; repeated entry is inert (`EMB-07`). The order matters because later stages depend on earlier ones having stopped:

1. The derived-index worker stops first under a bounded join. If it cannot stop, the teardown records `JoinDeadlineExceeded`, poisons the namespace, and never publishes a checkpoint while detached index I/O could still write.
2. The chainstate shutdown latch triggers. The node latch is a child of the chainstate latch (`crates/node/src/state/open.rs`), so a chainstate failure reaches every node worker.
3. The event loop, RPC listeners, P2P core, ingress, and relay workers, bootstrap and checkpoint workers, and metrics stop and join.
4. A clean checkpoint publishes only if every prior stage succeeded. The first failure is remembered while later stages still run.
5. Fee-estimator history is saved, and the mempool snapshot is saved when `persist_mempool` is on and the teardown is clean.

An injected shutdown receiver is served by one named forwarder thread. The forwarder waits on that receiver and on the node latch, so teardown ends it even when the caller keeps its sender open (`EMB-09`). No store handle outlives shutdown.

After a clean shutdown, the log ends with:

```text
INFO bitcoin_rs_node::lifecycle published clean chainstate checkpoint generation=1
INFO bitcoin_rs_node::lifecycle bitcoin-rs node exited cleanly
```

The checkpoint line comes from `publish_clean_checkpoint_if_eligible`; a dropped node skips it.

## Data directory lock

Opening a data directory takes an exclusive POSIX lock on `.lock` and records the directory identity. In-process registry state also prevents two nodes in one process from sharing a directory.

A second node on the same directory fails with:

```text
Cannot obtain a lock on directory /path/to/data. bitcoin-rs is probably already running.
```

`DataDirLockError::InUse` maps to `NodeError::Startup`. The lock is carried as a `StoreGuard` by every store handle, so the directory stays locked until the last handle drops, not merely until `shutdown()` returns.

The lock file opens without following symlinks, and a non-regular `.lock` is refused as `NotRegularFile`. Tests cover both cases: `second_open_while_first_lives_refuses_and_reopen_succeeds_after_drop` and `symlinked_lock_file_refuses_start_without_following` in [`crates/node/src/state/tests/data_dir_lock.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/state/tests/data_dir_lock.rs).

## Failure settlement

A fatal storage or apply failure stops the node closed instead of leaving it partially usable. `ChainTransition` checks every apply result, and a fatal classification calls `Chainstate::fail_closed_for_recovery` (`crates/execution/src/lib.rs:780`). That call closes admission permanently and requests chainstate shutdown. Because the node latch is a child of the chainstate latch, the whole node stops.

Fatal cases are a failed coin commit, a durable-head commit or lineage failure, block-body or undo persistence failure, and recovery publication failure. Retryable failures return to the caller and leave the node running.

Startup failures follow a different rule. `start_node` rolls back through `TeardownMode::StartupAbort`, which never publishes a clean checkpoint, so the next open runs recovery rather than trusting a half-started node.

An assumeutxo snapshot whose background validation fails is also settled closed: the manager persists `AssumeUtxoDiskStatus::Failed`, marks the active chainstate closed for recovery, and refuses later restarts to protect operator data. The [state and storage](../how/state-and-storage.md) chapter covers that path.

The daemon log for a clean regtest start and `SIGTERM` shows both ends of the lifecycle:

```text
{"timestamp":"2026-11-01T16:44:24.414833Z","level":"INFO","fields":{"message":"chainstate restore selected","restore_source":"cold","reason":"no_complete_checkpoint"},"target":"bitcoin_rs_execution::recovery"}
{"timestamp":"2026-11-01T16:44:24.418584Z","level":"INFO","fields":{"message":"rpc listener bound","addr":"127.0.0.1:44089","surface":"Shared"},"target":"bitcoin_rs_node::lifecycle"}
{"timestamp":"2026-11-01T16:44:25.821454Z","level":"INFO","fields":{"message":"published clean chainstate checkpoint","generation":1},"target":"bitcoin_rs_node::lifecycle"}
{"timestamp":"2026-11-01T16:44:25.822383Z","level":"INFO","fields":{"message":"bitcoin-rs node exited cleanly"},"target":"bitcoin_rs_node::lifecycle"}
```

Read the [embedding contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md) for the full invariant list behind `EMB-01` through `EMB-10`.
