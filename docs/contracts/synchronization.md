# Synchronization contract

The Node-level, cross-crate synchronization contract. Each domain owns its
local mechanics — `p2p` the peer and download policy, `chainstate` the
applied-chain transition, `chain` the header tree and IBD latch, `index` the
derived capabilities, `storage` the durable head, `node` the composition.
This page owns only the invariants across those boundaries. Local rules stay
with their owners; they are cited, not copied.

Its purpose is regression protection for **the whole node**: a feature can
be correct in isolation and still stall or invalidate node-wide
synchronization (AssumeUTXO and historical backfill both did). New features
and refactors must preserve the guarantees here even when component-local
correctness holds.

## Top-level conditional convergence property

> **CONV-1**: Given a stable valid chain target, at least one responsive
> source of its required blocks, retained or retrievable prerequisites
> (bodies, undo records, history the target's validation and serving need),
> recoverable storage, and fair opportunities for node-owned work — the node
> eventually applies that target and durably publishes the applied tip,
> without a process restart or manual intervention.

"Fair opportunities" excludes starvation the node itself causes: a lock,
queue, or scheduler the node owns must not indefinitely deny foreground
progress. A lock hold bounded by construction or by an explicit,
evidence-backed statement satisfies this; an unbounded optional-consumer hold
over a required lock does not.

This property is the end-to-end argument the clauses below discharge. Each
clause owns one pipeline obligation; "eventually" in any clause means: the
owning mechanism retries, releases, or terminates the work item, and no
clause may consume another clause's discharge as its own proof.

## Pipeline obligations

| Stage | Obligation | Discharged by |
| :--- | :--- | :--- |
| Discovery | An unapplied required block is always discoverable from the authoritative frontier | `SYNC-02` (frontier owns the next block; transient work is a hint) |
| Scheduling/execution | Once required work is eligible, the scheduler actually sends or executes it | `SYNC-06` (each work item has a driver that ticks or wakes it; discoverability alone is insufficient) |
| Recovery closure | Cancellation, timeout, failed delivery, peer replacement, reorg, backfill, and restart cannot lose work permanently; every outstanding item completes, is retried/released, or reaches an explicit terminal/unavailable outcome | `SYNC-04` (typed outcomes); `RCV-04`–`RCV-08` own the durable mechanics |
| Non-starvation | Optional index/historical/mining/RPC activity cannot indefinitely deny foreground progress under the stated assumptions | `SYNC-03` (bounded holds; open gaps recorded, not assumed away) |
| Durable convergence | A successful apply is durably committed and correctly published and recoverable | `SYNC-05` (commit-before-publish; coherent consumer views) |

**Counterexample the pipeline rules out**: headers lead the applied tip and
the next block is correctly identified as unowned, but the request never
reaches a peer because of a recurring scheduling/gating mistake. Frontiers
stay authoritative, no false progress is published, work stays discoverable —
yet the node never synchronizes. `SYNC-06`'s driver obligation (not
`SYNC-02`'s discoverability) is the clause that must rule this out, and it
does so only with the named execution evidence.

### Ownership map

| Work item | Sole authority | Consumers/read capability | Stale when | Permissible failure/recovery | Owning clause/proof |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Header tip | Header admission inside the chainstate transition (`ARCH-07`) | `SyncChain::chain_tip` readers; P2P frontier planning | A newer admitted header supersedes it | Invalid header rejected per `P2P-10`; ancestry not admitted | `SYNC-01` / `P2P-10` |
| Applied-tip commit | Chainstate transition owning mutation and durability (`EVT-02` steps 1 to 5) | `SyncChain::applied_tip`; status RPC snapshots; generation-fenced readers | A newer durable commit publishes | Commit failure publishes nothing; crash replays via `RCV-04` | `SYNC-02`, `SYNC-05` / `EVT-02`; `crates/node/tests/crash_recovery.rs` |
| AssumeUTXO historical frontier | `AssumeUtxoManager` historical role (`ARCH-07b`) | `getchainstates` readers (`API-33`) | Historical validation advances or terminates | Terminal validation failure stops the role; never converts into success | `SYNC-01`, `SYNC-04` / `ARCH-07b` |
| Reorg | Chainstate transition branch switch (`RCV-05`, `RCV-08`) | Chain tip and applied-tip readers observe the new best only after commit | A heavier valid branch commits | Invalid branch poisons the block and descendants; transient failures hand over | `SYNC-04` / `crates/chainstate/src/reorg.rs` |
| Post-commit followers | Committed chain effects in commit order (`EVT-02` step 7) | Index worker wakes; mining/announce; mempool followers | The next commit supersedes the prior outcome | Settlement failure closes admission for recovery; the committed outcome is retained | `SYNC-06` / `crates/node/src/chain_effects.rs` |
| Index watermark/backfill | `IndexWriter` atomic commit paths (`IDX-01`–`IDX-10`) | Watermark-gated queries; RPC readiness projections | A new capability commit or rollback moves the watermark | Worker failure renders queries `Unavailable`; backfill resumes and never signals complete when disabled | `SYNC-01`, `SYNC-03`, `SYNC-05`, `SYNC-07` / `crates/index/src/runtime/recovery_tests.rs` |
| Retained history | Retention/pruning authority (`ARCH-08`) with `RCV-07` rebuild | Sync, reorg, and historical-validation consumers requiring bodies/undo records | Explicitly permitted pruning; otherwise retained until consumed | A missing prerequisite is reported `Unavailable`/recoverable, never empty success | `SYNC-07` / `RCV-07` |
| Settlement closure | Chainstate commit retains the outcome; `ConnectMutationError::CommittedButSettlementFailed` closes admission | Mining submission and admission callers observe the error, never a retry | Never stale within the process: the committed tip stands and retry is forbidden | No process-level settlement-injection scenario exists; recovery uses only the existing restart/replay lanes | `SYNC-04` / `crates/node/src/chain_effects.rs::committed_connect_settlement_failure_retains_outcome_and_forbids_retry` |

## Existing authoritative contracts

These remain authoritative. This page adds no second source of truth for
their content:

- [architecture.md](architecture.md) `ARCH-07`/`ARCH-07a`/`ARCH-07b`:
  authoritative chainstate transitions, one active chainstate, AssumeUTXO
  roles, historical validation and finalization; `ARCH-08`: pruning/retention;
  `ARCH-09`: read-only capability boundaries.
- [p2p-wire.md](p2p-wire.md) `P2P-03`/`P2P-05`/`P2P-06`/`P2P-10`: peer
  capability, download/frontier recovery, body/header admission, presync
  gating.
- [recovery.md](recovery.md) `RCV-01`–`RCV-15`: durable commit, restart,
  crash, reorg, schema-refusal guarantees; `RCV-07` owns missing-body
  recovery; `RCV-05` owns deep rollback and selective rebuild.
- [indexing.md](indexing.md) `IDX-01`–`IDX-10`: capability gating, watermark
  identity, query consistency, backfill/reorg worker behavior.
- [chain-events.md](chain-events.md) `EVT-01`–`EVT-05`: ordered post-commit
  publication and consumer cursors; `EVT-02` owns the post-durable-commit
  applied-tip publication step.
- [mempool-mutations.md](mempool-mutations.md) `MPL-01`–`MPL-04`:
  chain-change generation fencing around admission.
- [embedding.md](embedding.md) `EMB-*`: startup/shutdown/worker lifecycle and
  readiness.
- [../CONSTRAINTS.md](../../CONSTRAINTS.md): repository-wide bounded-resource
  and data-safety invariants.

## Clauses

### `SYNC-01`: Independent progress authorities

The header tip, the applied/validated tip, the AssumeUTXO historical
validation frontier, and each derived-index watermark describe different
facts. One does not prove the others. Publication and query semantics name
the owning authority:

- Header tip: published by header admission inside the chainstate transition
  (`ARCH-07`), read through `SyncChain::chain_tip`.
- Applied tip: published only by the chainstate transition, which owns mutation
  and durability through `EVT-02` steps 1 to 5 (`P2P-05` owns only selection
  of the next required body), read through `SyncChain::applied_tip`.
- Historical validation frontier: owned by the `AssumeUtxoManager` historical
  role (`ARCH-07b`), reported through `getchainstates` (`API-33`).
- Capability watermark: `IndexWriter`'s atomic commit paths own publication —
  `commit_block` for the capabilities it selects, and the prepared/streaming
  commit paths (`seed_script_live_stream` and its bounded batch commits) for
  `ScriptLive`. Serving-visible readiness projections are RPC reads of those
  watermarks, not a second publication.

No consumer may derive "fully synchronized", "validated", or "ready" from a
different frontier. `sync_progress` reports blocks and headers separately for
this reason (`crates/rpc/src/context.rs`); a `blocks == headers` projection is
not validation progress when an AssumeUTXO historical role is still replaying.

- Proof: `crates/node/tests/unit/state/tests/events.rs`
  (`record_returns_hints_in_commit_order_and_advances_the_snapshot`,
  `active_chain_snapshot_anchors_at_restored_tip_after_restart`);
  `crates/chainstate` post-commit publication tests (`EVT-02`);
  `crates/index/src/index/tests.rs` watermark identity.

### `SYNC-02`: Canonical applied progress; transient work is a hint

The selected header ancestry plus the chainstate's committed applied frontier
decide what block must be applied next. Download-window cursors, scheduled
requests, peer claims, staged bodies, and cached snapshots are transient work,
never a chain authority. `P2P-05` owns the rule that an unowned frontier
becomes discoverable again after cancellation, peer replacement, rejection,
rollback, or reorg; this clause owns the system consequence: a stalled or
cancelled scheduler run never leaves the node without a discoverable next
block, and no transient completed state is read back as chain progress.

Discoverable is necessary but not sufficient. `SYNC-06` discharges the
remaining pipeline obligation: the eligible work item must actually reach its
driver and be sent or executed.

- Proof: `crates/p2p/src/sync/tests/` (frontier recovery, peer handover,
  cold-start hedge regressions); `crates/node/tests/unit/state/tests/events.rs`
  `record_returns_hints_in_commit_order_and_advances_the_snapshot`.

### `SYNC-03`: Foreground progress, resource, and failure isolation

Cross-feature obligation: optional subsystems — historical validation,
derived-index backfill, RPC/observer work, mining — must not prevent
authoritative chain synchronization from making progress under the
assumptions of `CONV-1`.

- Optional components acquire no authority to publish active-chain
  transitions and never route historical effects through live mempool, mining,
  RPC/ZMQ, or index-event publication (the historical chainstate's events are
  detached, `ARCH-07b`).
- Resource use and backpressure have an owner and a bound (`CONSTRAINTS.md`);
  component failure stays isolated unless it compromises shared authoritative
  data or a required commit (`IDX-07`, `EVT-04`).
- A shared lock's hold time must be bounded by construction or by explicit
  evidence. Known bounded holds: apply holds both fences only around the
  mutation window (`EVT-02`).

**Seeding and replay isolation:** `ScriptLive` seeding no longer holds the
live UTXO stable-view lock. It consumes an accepted immutable snapshot
artifact or replays retained block bodies and undo records through the
existing worker. Missing history produces a scoped `ScriptLive`
`Unavailable`; it does not block the worker, other indexes, or authoritative
chain commits. This closes the former `seed_live_from_utxo` lock-hold gap.

- Proof: `EVT-02` step 1–7 fencing tests; the event-loop tick tests
  (`crates/node/src/event_loop.rs`, `EMB-10`); paused-seed apply/lease
  regressions `crates/index/src/runtime/seed_paused_tests.rs`
  `seed_paused_write_permits_apply_and_retires_generation` (concurrent
  applies land while the seed stream holds its pin, then retire to zero
  leases) and `catch_up_drops_subsumed_seed_lease_for_lower_start`
  (single-holder drain) plus
  `crates/index/src/runtime/recovery_tests.rs`
  `seed_first_leg_consumes_held_lease` (the forward leg consumes the held
  bundle pin with at most one live lease, stalled legs park it back).

### `SYNC-04`: Failure classification and recovery semantics

Distinguish, and never conflate:

- **Invalid header** — rejected by header admission (`P2P-10`); the peer's
  ancestry is not admitted.
- **Invalid body** — rejected by the chain transition with two outcomes:
  a body/header **binding** failure (`BodyMutated`) preserves the header
  branch, clears the body gate, and lets another peer serve the body
  (`P2P-05`); a consensus-**invalid** body (`Permanent`) poisons the
  failed block and every descendant, so the header branch does not
  survive for retry.
- **Transient delivery failure** — strike/retry/handover under the existing
  header-request and window rules; no chain-state change.
- **Unavailable history** — missing or pruned bodies; reported as unavailable
  or recoverable (`RCV-07` missing-body recovery owns the canonical rebuild;
  `IDX-03` `TxQueryError::Unavailable`), never as an empty successful answer.
- **Durable corruption** — fail closed with the owning recovery story
  (`RCV-01`; assumeutxo mismatch fails closed across both roles).
- **Terminal validation failure** — the historical role stops; it never
  silently converts into successful synchronization.

Every outstanding work item ends in one of these outcomes or is retried under
the owning mechanism (`RCV-08` reconnection, `RCV-07` reconstruction); this
is the recovery-closure obligation of `CONV-1`. Failed validation publishes
nothing; settlement failure closes admission for recovery and stays an error
even when the anchor committed (`API-33`).

- Proof: `crates/node/tests/crash_recovery.rs` (`RCV-04` crash points);
  `crates/node/src/chain_effects.rs::committed_connect_settlement_failure_retains_outcome_and_forbids_retry`
  and `crates/node/src/chain_effects.rs::mining_reports_a_committed_settlement_failure_as_accepted`
  (settlement behavior); `e2e/tests/assumeutxo.rs::invalid_core_snapshots_fail_without_activating`
  (malformed-import refusal with no activation and untouched input; no
  process-level settlement-injection scenario exists);
  `crates/index/src/runtime/recovery_tests.rs` (missing-body wait/resume,
  `RCV-07`); `crates/p2p/src/sync/` body-rejection regressions.

### `SYNC-05`: Validated/durable progress and coherent cross-consumer views

Received, staged, and decoded bytes are not validated or committed progress.
Only the authoritative validation plus durable commit publishes applied state
and corresponding ordered events (`EVT-02` step 4–5: durability before
publication). Historical validated progress has its own durability authority
and cannot advance the active tip (`ARCH-07b`).

Consumer views split by mechanism:

- **Status RPC** (`getblockchaininfo`, mining info, wait responses) retain
  one applied publication and answer from it; a later commit behind the
  capture is not an error, and the response stays coherent at that snapshot.
- **Generation-fenced reads** (wallet-facing/Esplora reads under `WF-02`)
  return the declared unavailable response when the chain generation moves
  between capture and read; a moved generation never produces a mixed-tip
  page.
- **Generation-fenced admission** is not a read: `MPL-04` gives
  `submit_transaction` four bounded attempts that retry with newly resolved
  facts when the captured generation or sequence moved, and answers
  `SubmitError::RetryExhausted` only once the attempts are spent
  (`crates/mempool/src/admission.rs`); a moved generation never admits
  against a stale tip. The two are distinct obligations and are proven
  separately.
- **Index queries** gate on watermark identity and runtime revision and
  refuse torn reads (`IDX-03`).

A feature must not introduce mixed-tip or mixed-generation responses, stale
admission, or false-ready projections.

- Proof: `crates/index/src/runtime/query_tests.rs`
  (`transaction_rejects_watermark_from_rival_tip`); `crates/mempool/src/gateway.rs`
  generation-fencing tests (`MPL-04`); `crates/rpc/tests/` capability and
  coherence suites; the durable-before-publication matrix
  (`crates/node/tests/overhaul_durable_head.rs`).

### `SYNC-06`: Work drivers and proof obligations

**Driver obligation**: every outstanding work item has an owning driver that
actually ticks or wakes it — discoverability alone is not progress, and this
clause, not `SYNC-02`, is what rules out the execution-gap counterexample
above.

- Download/frontier work: the event-loop sync tick drives
  `BlockSync::tick` only (`crates/node/src/event_loop.rs::on_sync_tick` →
  `sync.tick()`); it does not drive the index worker.
- Index worker work: the worker has its own wake/timeout reconciliation loop
  (`crates/index/src/runtime/reconciliation.rs` — revision-coalesced quiet
  wait, 1 s `recv_timeout` tick, `IDX-08`), and committed chain effects send
  its wakes (`crates/node/src/chain_effects.rs::wake_index`); sync tick and
  index wakes are separate drivers.
- Post-commit mining/announce: committed chain effects drive them in commit
  order (`EVT-02` step 7).

**Liveness distinction** (observability and assumptions, not a proof):

- **Safety**: invalid or uncommitted states are never promoted, and stale
  cross-domain views are refused. Unconditional.
- **Conditional liveness**: under `CONV-1`'s assumptions, bounded failed
  requests and lost work eventually permit fresh scheduling and progress.
  Not promised with unavailable block history (a `MissingBody` needs the
  fetch path, `crates/p2p/src/sync/historical.rs`), unusable peers, or
  terminal fail-closed conditions.

Progress is observable through `getchainstates`, `getindexinfo`, and
`getblockchaininfo`; no new global sync manager, mirrored cursor, persistent
verdict, or extra state machine is implied.

- Cross-crate composition proof:
  `crates/node/tests/sync_smoke.rs::tick_recovers_rejected_frontier_without_publishing_unapplied_blocks`
  feeds admitted headers and a malformed frontier body through the real
  delivery channels and asserts applied progress, the in-memory
  `ChainEventPublisher::snapshot()`, UTXO/CoinStats, the RPC block log and
  that both admitted tree nodes keep `NodeStatus != Invalid`, then
  that resending only the correct parent applies its already-staged
  successor. It proves the channel-fed, in-memory composition across
  `SYNC-01`/`SYNC-02`/`SYNC-05`; it does **not** prove live peer sockets,
  durable crash recovery, or eventual progress under real index contention
  (those keep their owning deep lanes).
- Proof: `crates/p2p/src/sync/tests/header_progress.rs::tick_fetches_new_tip_headers_from_at_tip_peers`;
  `crates/p2p/src/sync/tests/headroom_throttling.rs::cold_start_stall_hedges_front_without_reassigning_owner`;
  `crates/p2p/src/sync/tests/download_frontier.rs::tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer`;
  `crates/p2p/src/sync/tests/peer_fanout.rs::tick_retries_when_all_selected_peers_have_expired_pending`;
  `crates/index/src/runtime/recovery_tests.rs::run_loop_commits_a_retained_prefix_and_retries_an_absent_body_without_a_wake`
  and `shutdown_after_an_absent_body_does_not_run_a_higher_group`;
  `crates/node/src/event_loop.rs` telemetry test (`EMB-10`);
  observability counters (`docs/observability.md`).
- Whole-node process evidence for `CONV-1`: the existing deep lanes below.
  A declared TLA+ `ConditionalProgress` is **not** completed proof
  (`docs/contracts/formal-verification.md` records exhausted/non-completed
  temporal runs); it is a declared model, not a discharge.

### `SYNC-07`: Required history remains available until consumed

A new feature, optional index, snapshot workflow, or pruning optimization
must not remove, discard, or make unreachable block bodies, undo records,
validated historical receipts, or other history while an authoritative,
currently required synchronization/recovery operation still depends on them.

- Retained bytes alone do not certify historical validity; certification
  follows the owning durable/recovery policy (`RCV-*`, `ARCH-07b`).
- A missing prerequisite is reported as unavailable/recoverable (`RCV-07`
  owns the missing-body rule), never as successful progress or a
  proven-absent object.
- The retention/pruning authority stays in `ARCH-08`/storage; the
  index-specific consequences stay in `IDX-*`. This clause owns only the
  system-level consequence: a feature must not destroy the prerequisites of
  already-supported sync, reorg, AssumeUTXO historical validation, or
  authorized catch-up/recovery.
- Explicitly permitted pruning and a documented inability to serve pruned
  history are not violations; do not promise archival availability on a pruned
  node.

- Proof: `crates/index/src/runtime/recovery_tests.rs`
  (`pruned_history_rebuilds_from_the_frontier_and_absent_history_waits`);
  `crates/storage/src/` pruning retention tests and the `RCV-05`
  deep-rollback matrix; `crates/chainstate/src/reorg.rs` bounded disconnect
  streaming under a retention lease (`RCV-08`).

## Review guidance by change class

Use this to decide which obligations a feature PR can disturb and which
existing evidence to run. It is review guidance, not a demand to add a test
per hypothetical feature.

- **Optional read/index BIP**: its own worker, failure, stale/readiness state
  and backpressure must not block authoritative apply; a disabled or
  unavailable index must not signal complete or require a sync-state
  mutation. Relevant: `SYNC-01`, `SYNC-03`, `SYNC-05`, `SYNC-07`.
- **Relay/transport BIP**: negotiation, malformed peers, timeouts and
  fallback must not strand the body frontier or bypass header/body admission.
  Relevant: `SYNC-02`, `SYNC-04`, `SYNC-06`.
- **Performance change to download, validation, or storage**: same consensus
  and durable applied outcome, plus recovery after failure, reorg and
  restart; a benchmark delta is not proof of correctness. Relevant: the
  affected `SYNC-*` clauses and their owner contracts.

## Convergence evidence map

| `CONV-1` obligation | Observable end-to-end result | Owner / mechanism | Smallest evidence | Open condition |
| :--- | :--- | :--- | :--- | :--- |
| Discovery | A lost/cancelled frontier request becomes requestable again | P2P `BlockSync` sweeps (`P2P-05`) | `crates/p2p/src/sync/tests/` frontier/handover regressions | None recorded |
| Scheduling/execution | An eligible request is actually sent to a peer, or the tick records why not | Event-loop sync tick → `BlockSync::tick` | `crates/p2p/src/sync/tests/header_progress.rs::tick_fetches_new_tip_headers_from_at_tip_peers`, `headroom_throttling.rs::cold_start_stall_hedges_front_without_reassigning_owner`, `download_frontier.rs::tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer`, `peer_fanout.rs::tick_retries_when_all_selected_peers_have_expired_pending` | None recorded |
| Recovery closure | A peer loss/timeout/failed delivery ends in retry, handover, or terminal outcome without restart | `P2P-05` strike/expiry and peer handover; startup dialing on persisted AddrMan recovery (not `RCV-08`, which covers chainstate reorg disconnect/reconnect) | `crates/p2p/src/sync/tests/` expiry strikes; `bin/bitcoin-rs/tests/addrman_restart_e2e.rs` restart reconnection | Live reorg + expiry combined lane is main-only |
| Non-starvation | A foreground commit lands while optional work runs, on paths the fences bound | Apply fences (`EVT-02`) and immutable artifact/replay seeding | `EVT-02` fencing tests; paused-seed concurrent-apply proof | No live-UTXO seed lock; scoped `ScriptLive` unavailability is isolated from other work |
| Index delay/failure | Queries refuse honestly during index worker failure | `IDX-07` supervision + `SYNC-01` authorities | `unusable_worker_makes_queries_unavailable` (marks the worker failed, asserts `TxQueryError::Unavailable`) | **Not proven for delay or apply isolation:** no test covers queries during index delay/rebuild or applies a block while the index is unusable, so "index failure never blocks apply" is an unproven obligation resting on the `SYNC-03` fences and `EVT-02` evidence |
| Durable convergence | A successful apply survives restart at the published tip | Durable head + checkpoint (`RCV-01`–`RCV-04`) | `crates/node/tests/crash_recovery.rs` `RCV-04` matrix | Formal temporal runs are not completed proofs |

## Formal models

The `PeerLeases` and `ChainAdmission` models declare `ConditionalProgress`
(`docs/models/`), and their configurations carry explicit fairness
constants. Per the verification contract, a declared model property with an
exhausted or non-completed temporal run is **not** a convergence discharge:
`docs/contracts/formal-verification.md` owns the run status; treat declared
properties as design evidence only.
