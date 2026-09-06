# Embedded node lifecycle

The typed path that lets the daemon runner be the first embedder. There is
one lifecycle implementation, not two.

Owner: `crates/node/src/run.rs` (`start_node`)
Consumers: `crates/node/src/embed.rs`, `bin/bitcoin-rs/src/main.rs`

## Clauses

### `EMB-01`: One lifecycle

- Both `run()` and `Node::start` boot through `crates/node/src/run.rs::start_node`.
- Both reach the same shutdown path through `NodeServices::teardown`.
- There is no second lifecycle for the embedded form.

### `EMB-02`: Event loop wake

1. `run()` or `Node::start` enters the event loop.
2. P2P joins.
3. Metrics stop.
4. Outbound join.
5. Bounded subsystem drain.
6. Clean checkpoint or shutdown.

The daemon runner and the embedded path share this ordering.

### `EMB-03`: Defer result until all prior joins succeed

`Node::start` returns a deferred result that completes after every earlier
join in `EMB-02`. A failed or dropped earlier join suppresses a later stage.

### `EMB-04`: Same rollback-releases state

- Both the daemon and the embedded form use the same rollback behavior:
  - `StartupAbort`: a bootstrap step failed, or the graph was dropped
    unstarted. It never publishes a checkpoint.
  - `CleanShutdown`: publishes the durable root only after every prior join
    succeeded. The teardown rolls back releases state, second clean
    shutdown, and RPC traffic.
- `crates/node/src/run.rs` tests: `dropped_node_releases_services_and_datadir_for_reopen` and
  `startup_failure_completes_cleanup_and_suppresses_checkpoint`.
- `crates/node/tests/shutdown.rs`: `run_exits_cleanly_after_fast_shutdown_signal` and
  `daemon_and_embedded_paths_share_one_teardown`.

### `EMB-05`: No daemon subprocess

No separate daemon subprocess is spawned. RPC traffic runs in-process with
the node. `NodeServices::teardown` is the single owner of shutdown.

### `EMB-06`: Checkpoint is not a published authority

A clean shutdown publishes the durable root, not a checkpoint. The durable
root is owned by `crates/chainstate`. A checkpoint file may be written by an
operator command, but it is not a publication authority and is not read for
recovery correctness.

### `EMB-07`: Failure and identity

- `StartupAbort` and `CleanShutdown` expose the same failure and identity
  clauses (`EMB-01`/`EMB-04`).
- `crates/node/tests/shutdown.rs` tests:
  - `run_exits_cleanly_after_fast_shutdown_signal`;
  - `daemon_and_embedded_paths_share_one_teardown`;
  - `the_daemon_path_over_the_same_lifecycle_still_shuts_down_cleanly`.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
embedded node, node lifecycle.
