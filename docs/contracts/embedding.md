# Embedded node lifecycle

Owner: `crates/node/src/run.rs::start_node` and `NodeServices::teardown`.
Consumers: `crates/node/src/embed.rs` and the daemon runner.

### `EMB-01`: One lifecycle

`run()` and `Node::start` share startup and teardown. The embedded API does not
spawn a daemon subprocess or maintain a second service graph.

### `EMB-02`: Ordered teardown

Teardown requests shutdown and wakes the event loop, joins the core services,
drains bounded subsystems, joins bootstrap/signal workers, then considers clean
checkpoint publication. `join_core_services` owns the detailed order. Bootstrap
worker joins are not abandoned at the subsystem drain deadline.

### `EMB-03`: Report errors after cleanup

`Node::start` returns a running `Node` after startup, not a shutdown result.
`Node::shutdown` consumes the node and reports teardown failure; `run()` reports
it on exit. An earlier join failure does not skip later cleanup: teardown retains
the first error and continues. It suppresses clean checkpoint publication.

The async entry points currently execute synchronous startup/shutdown work.
Embedders must account for executor blocking; see `embed.rs` runtime ownership.

### `EMB-04`: Startup rollback and clean shutdown

`StartupAbort` never publishes a clean checkpoint. `CleanShutdown` publishes
only when preceding cleanup succeeded and an applied tip exists. Taking worker
handles and the teardown guard make repeated cleanup a no-op. Drop performs
best-effort cleanup; explicit shutdown is the error-reporting path.

### `EMB-05`: In-process RPC

RPC and the embedded API address the same node state and service graph.

### `EMB-06`: Checkpoint recovery remains implemented

A successful clean shutdown calls `NodeState::write_clean_checkpoint`.
Startup can restore that checkpoint. The proposed checkpoint-independent
`crates/chainstate` durable-root owner does not exist yet. Checkpoint removal is
a future recovery migration, not current behavior; see [recovery](recovery.md).

### `EMB-07`: Failure evidence

`crates/node/src/run.rs` includes
`clean_shutdown_publishes_checkpoint_and_returns_success`,
`teardown_join_failure_completes_cleanup_and_suppresses_checkpoint`, and
`teardown_joins_bootstrap_worker_beyond_former_deadline`.
`crates/node/tests/shutdown.rs` exercises the daemon and embedded paths.
These tests cover lifecycle behavior, not the proposed durable-root protocol.
