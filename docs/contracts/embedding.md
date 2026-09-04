# Embedded node lifecycle

The typed in-process surface over the node lifecycle: `Node::start`,
typed reads, gateway broadcast, consuming shutdown. The daemon runner is
the first embedder — there is one lifecycle implementation, not two.

## Invariants

- **EMB-01 — One lifecycle.** `run()` and `Node::start` both boot through
  `crates/node/src/run.rs::start_node` and both stop through
  `NodeServices::teardown`: request (shutdown flag + event-loop wake) →
  event loop join → rpc join → p2p joins → metrics stop → outbound join →
  bounded subsystem drain → clean checkpoint (deferred result) → bounded
  bootstrap join → signal-handler close and join → checkpoint result.
  Owner: `crates/node/src/run.rs`; consumed by `crates/node/src/embed.rs`.
  `TeardownMode` names the only difference between reaches:
  `StartupAbort` (a bootstrap step failed, or the graph was dropped
  unstarted) never publishes a checkpoint; `CleanShutdown` publishes one
  only after every prior join succeeded — a failed join suppresses it.
  The first failure is remembered while every later stage still runs, so
  one failure never skips later cleanup; taking each handle by value makes
  the teardown unable to run twice.
- **EMB-02 — Caller-owned runtime.** `Node::start`/`Node::shutdown` are
  `async fn` running on the caller's Tokio runtime; the node never
  creates, enters, or retains a runtime. Startup and shutdown drive the
  node's own threads synchronously. Owner: `crates/node/src/embed.rs`.
- **EMB-03 — No storage in signatures.** No public embedding signature
  names a storage backend, `NodeStorage`, or index internals. Owner:
  `crates/node/src/embed.rs`.
- **EMB-04 — Typed reads mirror the RPC facts.** `snapshot()` returns the
  coherent `ChainSnapshot`; `sync_progress()` derives the
  `getblockchaininfo` fields from the same handles without RPC JSON (the
  `GuessVerificationProgress` twin in `embed.rs` is kept op-for-op with
  `crates/rpc/src/handlers/chain.rs`); `capabilities()` returns the node
  concrete-service `CapabilitySnapshot`. Owner: `crates/node/src/embed.rs`.
- **EMB-05 — Broadcast is the shared admission.** `Node::broadcast` runs
  `Context::admit_transaction` — the identical typed admission
  `sendrawtransaction` runs (crates/rpc/src/handlers/tx_admission.rs):
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

## Startup failure and cancellation

`start_node` records every worker, socket owner, and channel end in a
startup guard the moment it exists. A failure at any later bootstrap step
(configuration validation, storage open, crash recovery, RPC bind,
listener spawn) rolls the whole graph back through the same ordered
teardown in `StartupAbort` mode before the error is returned: no worker
outlives a failed startup, no joinable handle is dropped, sockets and
storage locks are released, and no checkpoint is published for the
abandoned run. Bootstrap workers poll the shared shutdown flag through
bounded waits, so every join completes.

## Readiness

`Node::start` returns after storage is open, recovery is done, and every
service thread is spawned; `snapshot()`/`sync_progress()` at that point
reflect the resumed applied tip. There is no separate ready flag and no
sleep-based readiness: the snapshot is the readiness fact.

## Error behavior

Errors at the typed boundary are `NodeError`: `Startup` (configuration,
storage, recovery, or service-bind failure, with the rolled-back state
noted above), `Shutdown` (drain, join, or checkpoint failure — reported
only by the consuming `shutdown`, never by `Drop`), `Unavailable` (a
capability is disabled or cannot answer yet, including the TxLookup
gate), `NotFound` (a proven-absent object), and `Broadcast` (the
transaction failed policy; the message is the Core rejection string).
Errors of the daemon `run()` are the same teardown failures surfaced as
`anyhow` errors.

## Proof

- `crates/node/tests/embed.rs::embedded_node_lifecycle_round_trip` —
  start on a seeded regtest data dir, snapshot/progress/capability
  reads, block query, gateway broadcast with sequence 1, mempool
  read-back, gated confirmed lookup, consuming shutdown, reopen, second
  clean shutdown. No daemon subprocess, no RPC traffic.
- `crates/node/tests/embed.rs::dropped_node_releases_services_and_datadir_for_reopen`
  and `startup_failure_after_state_open_rolls_back_releases_state` —
  Drop cleanup without checkpoint; partial-startup rollback releasing
  storage.
- `crates/node/src/run.rs` tests
  `teardown_join_failure_completes_cleanup_and_suppresses_checkpoint`
  and `daemon_and_embedded_paths_share_one_teardown` — the failure and
  identity clauses of EMB-01/EMB-07.
- `bin/bitcoin-rs/tests/gates/g12_graceful_shutdown.rs` — the daemon
  path over the same lifecycle still shuts down cleanly.

## Vocabulary

Terms are defined in [../../CONCEPTS.md](../../CONCEPTS.md):
embedded node, node lifecycle.
