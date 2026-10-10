# Embedded node lifecycle

The typed in-process surface over the node lifecycle: `Node::start`,
typed reads, gateway broadcast, consuming shutdown. The daemon runner is
the first embedder — there is one lifecycle implementation, not two.

## Invariants

- **EMB-01 — One owned lifecycle.** `run()` and `Node::start` both boot
  through `crates/node/src/lifecycle.rs::start_node`. Startup returns
  an owned `Node`; it does not export detached state, worker handles, and
  an RPC context for a caller to assemble. `StartupGuard::finish` transfers
  ownership only after every service has started. Both callers stop through
  `lifecycle.rs::NodeServices::teardown`: request shutdown and wake
  the event loop; join the event loop and RPC listener; stop metrics; join
  P2P core, ingress, and relay workers; join bootstrap,
  checkpoint, and signal workers; then publish a clean checkpoint if eligible.
  On every stop path — including `StartupGuard` rollback — the
  derived-index worker is stopped under a bounded join as `teardown`
  begins, so the clean checkpoint publishes and chainstate closes only
  after the index released its stores. A join abandoned at the deadline
  records a teardown error, and so does a worker whose backend open was
  abandoned: its supervisor can exit while the detached open thread still
  touches the store. Either way the clean checkpoint never publishes
  while detached index I/O can still write.
  `TeardownMode` distinguishes `StartupAbort` from `CleanShutdown`.
  An aborted or dropped run never publishes a clean checkpoint. Clean
  shutdown publishes only after every prior cleanup stage succeeded. The
  first failure is remembered while every later cleanup stage still runs.
  Handles are taken once and the teardown guard makes repeated entry inert.
- **EMB-02 — Caller-owned runtime.** `Node::start`/`Node::shutdown` are
  `async fn` running on the caller's Tokio runtime; the node never
  creates, enters, or retains a runtime. Startup and shutdown drive the
  node's own threads synchronously. Owner: `crates/node/src/embed.rs`.
- **EMB-03 — Internal composition root.** No public embedding signature
  names a storage backend, `NodeStorage`, index internals, or `NodeState`.
  The `state` and `tx_ingress` worker-wiring modules are private in normal
  production builds; the non-default `test-seam` exposes them for integration
  tests and benchmarks. Deliberate downstream feature opt-in is not a security
  boundary, and production dependency/feature edges must not enable this seam.
  Embedders use operation-oriented `Node` methods instead of receiving raw
  writable locks, subsystem services, channels, or runtime handles. Owner:
  `crates/node/src/embed.rs`.
- **EMB-04 — Typed reads mirror the RPC facts.** `snapshot()` returns the
  coherent `ChainSnapshot`; `sync_progress()` returns the
  `getblockchaininfo` fields without RPC JSON through
  `ChainHandles::sync_progress` in `crates/rpc/src/context.rs`, the identical
  projection `getblockchaininfo` runs. The chain facts in it — heights, best
  hash, tip time and median time past, verification progress, the
  initial-block-download decision, and chain work — come from the
  Chainstate-minted `ChainProgressReader` (`crates/chain/src/progress.rs`).
  The projection adds the network, the rendered difficulty and chain work,
  and the storage facts; `getblockchaininfo` adds its wire-only fields
  (`bits`, `target`, warnings, recovery status) on top. `capabilities()`
  returns the node's concrete-service `CapabilitySnapshot`. Owners:
  `crates/node/src/embed.rs` and `crates/rpc/src/context.rs`; wire types:
  `crates/index/src/capabilities.rs`.
- **EMB-05 — Broadcast is the shared admission.** `Node::broadcast`,
  `sendrawtransaction` (`crates/rpc/src/handlers/tx.rs`) and Esplora
  broadcasts all call `MempoolGateway::submit_local_transaction`;
  `Node::broadcast` passes `sendrawtransaction`'s default fee-rate cap. The
  full policy stack is evaluated under the node's one
  `MempoolGateway` write-lock interval and the authorized mutation
  commits inside it, so no concurrent admission can pass stale policy.
  Block-connect eviction commits through the same gateway's
  `remove_for_block` (Core's `removeForBlock` mirror), reorg
  re-admission through `reconsider_disconnected`, and
  `prioritisetransaction` through the gateway's in-place prioritise.
  No production path mutates the pool outside the gateway. Owner:
  `crates/node/src/embed.rs`; gateway invariants:
  [mempool-mutations.md](mempool-mutations.md).
- **EMB-06 — TxLookup gating is honest.** `tx_by_id` answers from the
  mempool and the direct cache first; confirmed lookup requires the
  index: a disabled index is `NodeError::Unavailable`, a proven-absent
  transaction is `NodeError::NotFound`. Owner: `crates/node/src/embed.rs`.
- **EMB-07 — Shutdown consumes.** `Node::shutdown(self)` runs the ordered
  sequence exactly once and publishes the clean checkpoint; a node
  started on the same data dir afterwards resumes from that checkpoint.
  Dropping a node without `shutdown` runs the same teardown in
  `StartupAbort` mode — services joined, storage released, no checkpoint.
- **EMB-08 — Mutations wake the template coordinator.** The
  `bitcoin_rs_mining::MiningGenerationSignal` (crates/mining/src/generation_signal.rs),
  constructed and wired by node, fans every
  authoritative mutation out to the attached coordinator: the gateway's
  mutation observer fires it after each committed mutation, and the apply
  path fires it after each authoritative applied-tip connect/disconnect.
  The coordinator attaches at startup; before that the signal is a no-op.
- **EMB-09 — Shutdown wake cannot block teardown.** A full bounded wake
  channel already contains the required notification. Teardown attempts a
  nonblocking send and continues to the joins whether the channel accepted
  the wake, was already full, or has no receiver. The authoritative shutdown
  flag is raised first. Owner: `lifecycle.rs::NodeServices::teardown`.

## Startup failure and cancellation

`Node::activate_assumeutxo_snapshot_file` preserves its native v4 input contract
and caller-relative path interpretation. Portable Bitcoin Core v2 files are
imported through `loadtxoutset`; both entry points share the one-import resource
permit and the same format-independent activation owner. Neither translates
one input format into the other. The embedding method enters the node-owned snapshot
activation boundary after ordinary header synchronization has admitted the
pinned base. It preserves mempool fencing and consumer alignment without
exporting `NodeState` or the historical mutation handle. Like startup, this
async method performs synchronous work when polled; callers choose its runtime
placement. `Node::chainstates_summary` exposes roles and validation progress.
Import or activation refusal is `NodeError::Snapshot`; reporting-storage failure
is `NodeError::Unavailable`. See `ARCH-07b` for the durable lifecycle contract.

### `EMB-10`: Independent runtime-stall evidence

Sync telemetry cadence is elapsed monotonic time, not the number or origin of
sync wakes. `scripts/watch_runtime_stall.py` is an explicit operator-owned
process, independent of node locks, RPC and logging. It records one missed
cadence and bounded debugger/kernel/log evidence, then exits; it never changes
chainstate, retries mutation, or infers a deadlock from a missing log line.
Debugger attachment pauses the target and requires deployment-approved access.
Requirements and evidence limits are in
[../operations/runtime-stall.md](../operations/runtime-stall.md).

Proof: `event_loop::tests::telemetry_uses_elapsed_time_not_wake_count`;
`scripts/tests/test_watch_runtime_stall.py` covers log rotation, bounded reads,
monotonic expiry, process identity changes, and incomplete debugger output.
Synthetic runner checks cannot identify the historical stall's lock holder.

### Startup ownership

`start_node` records every worker, socket owner, and channel end in a
startup guard the moment it exists. A failure at any later bootstrap step
(configuration validation, storage open, crash recovery, RPC bind,
listener spawn) rolls the graph back through the same ordered teardown in
`StartupAbort` mode before the error is returned. Workers and storage are
not handed out through a tuple or reconstructed through a second factory.

## Readiness

`Node::start` returns after storage is open, recovery is done, and every
service thread is spawned; `snapshot()`/`sync_progress()` at that point
reflect the resumed applied tip. There is no separate ready flag and no
sleep-based readiness: the snapshot is the readiness fact.

## Error behavior

Errors at the typed boundary are `NodeError`: `Startup` (configuration,
storage, recovery, or service-bind failure, with rollback as described
above), `Shutdown` (join or checkpoint failure — reported only by
consuming shutdown, never by Drop), `Unavailable` (a capability cannot
answer), `NotFound` (a proven-absent object), and `Broadcast` (policy
rejection). Daemon `run()` exposes teardown failures as `anyhow` errors.

## Proof

- `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs::node_composition_root_is_not_a_production_embedding_api`
  compiles supported `Node` reads in an isolated production consumer and rejects
  imports of `state::NodeState` and the ingress worker entry point (`EMB-03`).
  The same gate's Cargo graph validator rejects production feature/dependency
  edges that enable `test-seam`, excluding legitimate dev-only fixture edges.
- `crates/node/tests/embed.rs::embedded_node_lifecycle_round_trip` exercises
  typed reads, broadcast, consuming shutdown, and reopen.
- `crates/node/tests/embed.rs::dropped_node_releases_services_and_datadir_for_reopen`
  and `startup_failure_after_state_open_rolls_back_releases_state` exercise
  abandoned-run cleanup and startup rollback.
- `crates/node/tests/unit/lifecycle/tests.rs` contains checkpoint failure,
  worker join failure, daemon/embedded identity, repeated teardown, rollback,
  queued-wake, and owned-startup-result regressions.
- `crates/node/src/embed.rs::tests::broadcast_publishes_one_ordered_a_event_through_the_shared_gateway`
  retains the gateway publication test and its direct-insertion control, and
  checks that a refused broadcast returns the gateway's policy reason and
  publishes nothing.
- `crates/node/tests/shutdown.rs::run_exits_cleanly_after_fast_shutdown_signal`
  exercises the daemon path.

## Vocabulary

Terms are defined in [../../CONCEPTS.md](../../CONCEPTS.md):
embedded node, node lifecycle.
