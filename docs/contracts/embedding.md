# Embedded node lifecycle

The typed in-process surface over the node lifecycle: `Node::start`,
typed reads, gateway broadcast, consuming shutdown. The daemon runner is
the first embedder — there is one lifecycle implementation, not two.

## Invariants

- **EMB-01 — One owned lifecycle.** `run()` and `Node::start` both boot
  through `crates/node/src/lifecycle/startup.rs::start_node`. Startup returns
  an owned `Node`; it does not export detached state, worker handles, and
  an RPC context for a caller to assemble. `StartupGuard::finish` transfers
  ownership only after every service has started. Both callers stop through
  `lifecycle/services.rs::NodeServices::teardown`: request shutdown and wake
  the event loop; join the event loop and RPC listener; stop metrics; join
  P2P core, ingress, and relay workers; drain subsystems; join bootstrap,
  checkpoint, and signal workers; then publish a clean checkpoint if eligible.
  `TeardownMode` distinguishes `StartupAbort` from `CleanShutdown`.
  An aborted or dropped run never publishes a clean checkpoint. Clean
  shutdown publishes only after every prior cleanup stage succeeded. The
  first failure is remembered while every later cleanup stage still runs.
  Handles are taken once and the teardown guard makes repeated entry inert.
- **EMB-02 — Caller-owned runtime.** `Node::start`/`Node::shutdown` are
  `async fn` running on the caller's Tokio runtime; the node never
  creates, enters, or retains a runtime. Startup and shutdown drive the
  node's own threads synchronously. Owner: `crates/node/src/embed.rs`.
- **EMB-03 — No storage in signatures.** No public embedding signature
  names a storage backend, `NodeStorage`, or index internals. Owner:
  `crates/node/src/embed.rs`.
- **EMB-04 — Typed reads mirror the RPC facts.** `snapshot()` returns the
  coherent `ChainSnapshot`; `sync_progress()` derives the
  `getblockchaininfo` fields from the same handles without RPC JSON. The
  calculation in `embed/progress.rs` remains op-for-op with the RPC
  verification-progress calculation. `capabilities()` returns the node's
  concrete-service `CapabilitySnapshot`. Owners: `crates/node/src/embed.rs`
  and `crates/node/src/embed/progress.rs`; wire types:
  `crates/rpc/src/capabilities.rs`.
- **EMB-05 — Broadcast is the shared admission.** `Node::broadcast` runs
  `Context::admit_transaction` (`crates/rpc/src/context.rs`) — the identical
  typed admission `sendrawtransaction` runs (`crates/rpc/src/handlers/tx.rs`):
  the full policy stack is evaluated under the node's one
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
- **EMB-08 — Mutations wake the template coordinator.** The node-owned
  `MiningGenerationSignal` (crates/node/src/mining.rs) fans every
  authoritative mutation out to the attached coordinator: the gateway's
  mutation observer fires it after each committed mutation, and the apply
  path fires it after each authoritative applied-tip connect/disconnect.
  The coordinator attaches at startup; before that the signal is a no-op.
- **EMB-09 — Shutdown wake cannot block teardown.** A full bounded wake
  channel already contains the required notification. Teardown attempts a
  nonblocking send and continues to the joins whether the channel accepted
  the wake, was already full, or has no receiver. The authoritative shutdown
  flag is raised first. Owner: `lifecycle/services.rs::NodeServices::teardown`.

## Startup failure and cancellation

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
above), `Shutdown` (drain, join, or checkpoint failure — reported only by
consuming shutdown, never by Drop), `Unavailable` (a capability cannot
answer), `NotFound` (a proven-absent object), and `Broadcast` (policy
rejection). Daemon `run()` exposes teardown failures as `anyhow` errors.

## Proof

- `crates/node/tests/embed.rs::embedded_node_lifecycle_round_trip` exercises
  typed reads, broadcast, consuming shutdown, and reopen.
- `crates/node/tests/embed.rs::dropped_node_releases_services_and_datadir_for_reopen`
  and `startup_failure_after_state_open_rolls_back_releases_state` exercise
  abandoned-run cleanup and startup rollback.
- `crates/node/src/lifecycle/services/tests.rs` contains checkpoint failure,
  worker join failure, daemon/embedded identity, repeated teardown, rollback,
  queued-wake, and owned-startup-result regressions.
- `crates/node/src/embed/tests.rs::broadcast_publishes_one_ordered_a_event_through_the_shared_gateway`
  retains the gateway publication test and its direct-insertion control.
- `crates/node/tests/shutdown.rs::run_exits_cleanly_after_fast_shutdown_signal`
  exercises the daemon path.

## Removed internal entry points

The lifecycle owner cut removes `run::start_node`, `run::NodeServices`,
`run::TeardownMode`, `run::DRAIN_DEADLINE`, `embed::node_from_parts`,
`NodeServices::cleanup`, and the detached-parts `StartupGuard::disarm`.
No aliases or re-exports retain these paths. Callers enter the lifecycle
owner directly; public `Node` and daemon APIs are not alternate owners.

## Vocabulary

Terms are defined in [../../CONCEPTS.md](../../CONCEPTS.md):
embedded node, node lifecycle.
