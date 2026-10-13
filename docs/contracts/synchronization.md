# Node synchronization contract

This contract owns the guarantees that must survive changes across P2P,
chainstate, storage, node orchestration and derived consumers. It protects
end-to-end synchronization against feature regressions; it does not prescribe
a scheduler, queue layout or new synchronization authority.

Local transition, protocol, retention and query rules remain with
[ARCH-07/07b/08](architecture.md), [P2P-03/05/06/10](p2p-wire.md),
[RCV-*](recovery.md), [EVT-*](chain-events.md), [IDX-*](indexing.md),
[MPL-04](mempool-mutations.md) and [EMB-*](embedding.md).
[CONSTRAINTS.md](../../CONSTRAINTS.md) owns repository-wide data safety and
resource bounds. The clauses below own only their cross-boundary consequences.

## Clauses

### `SYNC-01`: Distinct progress authorities

Header selection, committed applied progress, AssumeUTXO historical validation
and each derived capability's watermark describe different facts. A consumer
must use the authority for the fact it reports: downloaded headers, available
bodies, an assumed active tip or a caught-up index cannot certify another
frontier's validation, completeness or readiness. Report unavailable or
incomplete evidence explicitly, including after snapshot activation and restart.

### `SYNC-02`: Canonical frontier and recoverable work ownership

The committed applied frontier and selected header ancestry determine the next
required foreground block. Download cursors, peer claims, staged bodies and
cached plans are transient work, not chain authorities. After cancellation,
peer replacement, rejected delivery, rollback or reorg, an otherwise requestable
gap must become discoverable and requestable again under `SYNC-06`'s assumptions.
Staged successors cannot conceal an unowned predecessor. P2P owns detection,
request release and peer recovery under `P2P-03` and `P2P-05`.

### `SYNC-03`: Foreground progress and bounded interference

Historical validation, index backfill, RPC/observer work, mining and future
optional features must preserve authoritative synchronization progress under
the availability and resource assumptions in `SYNC-06`. Each contender must
have an owner for admitted work, resource bounds and backpressure. Bounded
input or batch size alone does not establish bounded lock duration or fairness.
Slow downstream work must not retain shared chainstate, UTXO or storage guards for
unbounded consumption. An optional failure must stay within its capability
unless shared authoritative data or a required commit is compromised.

Only the active chainstate may drive live-chain effects; historical replay
must not publish foreground mempool, mining, RPC/ZMQ or index events. Domain
rules remain in `ARCH-07b`, `EVT-02/04` and `IDX-07/08`. This is a conditional
progress obligation, not a latency or throughput SLA under saturated CPU,
memory or storage. Unqualified interference paths stay explicit proof gaps.

### `SYNC-04`: Failure identity survives domain boundaries

Invalid headers, incorrectly bound bodies, consensus-invalid bound blocks,
transient peer/delivery failures, unavailable history, durable corruption and
terminal validation failure must retain their distinct owner outcomes.
A body/header binding failure must not invalidate an otherwise valid header branch.
Missing prerequisites must not become successful synchronization or a proven
absent object. Recoverable work must retain a defined retry/recovery route;
durable uncertainty and terminal failures fail closed. A committed outcome
whose follower settlement fails must not be retried as a refused block.
`P2P-05/06`, `RCV-*`, `ARCH-07b` and `EVT-02` own the detailed classifications.

### `SYNC-05`: Committed progress and coherent consumers

Received, decoded, staged or merely retained data is not committed progress.
Only the active chainstate's owner-validated transition and required durable
commit may publish applied state and its ordered effects. Authorized snapshot
activation retains its assumed status until historical validation completes
under `ARCH-07b`. Historical validation has separately certified progress in
the active durable head and cannot advance the active tip.

RPC, mempool, mining, index and observer consumers must use committed owner
outcomes with the generation/freshness checks required by `EVT-*`, `MPL-04`
and `IDX-03`. A feature must not introduce mixed-tip responses, stale admission
or false readiness by reconstructing success from scheduler state, stored
bytes or partial index history. Independently lagging consumers remain allowed;
their views must truthfully identify readiness or refuse the affected query.

### `SYNC-06`: Safety and conditional liveness

Safety holds through failures: state is never promoted beyond its
owner-certified validation or assumption status, or before its required
commit, and stale cross-domain views are refused. Progress additionally
requires usable capable peers or retrievable required history, available
storage/worker capacity, fair opportunities to run bounded work, and no
terminal consensus/storage failure. Under those assumptions, temporary failure
or lost request ownership must eventually permit fresh scheduling and progress.
There is no progress promise with unusable peers, permanently missing required
history or a closed terminal-failure fence.

The ownership map identifies who releases stalled work and where progress
becomes observable. Request expiry/cancellation must enable a later scheduling
opportunity; durable recovery must establish a coherent authority before
service admission; an index may advertise readiness only after its own
reconciliation. Exact deadlines and retry policy remain with those owners.
Scenario tests and bounded models support only the cases and assumptions they
exercise, not unconditional whole-node starvation freedom.

### `SYNC-07`: Preserve required history until consumption

A feature must not remove or make unreachable bodies, undo, validated history
receipts or other prerequisites still required by a supported authoritative
sync, reorg, historical-validation or recovery operation. Retention and prune
reserve/commit remain storage-owned; validation receipts remain chainstate-owned.
Retained bytes do not themselves prove validation, and missing prerequisites
must be reported according to their availability/recovery class.

`ARCH-07/07b/08`, `RCV-*` and `IDX-*` retain the detailed retention and
rebuild policy. Permitted pruning and bounded optional leases do not imply an
archival guarantee: an optional consumer may lose history and become
unavailable or rebuild only the supported retained range. Neither a surviving
suffix nor a tip-matching watermark proves complete historical coverage.

## Authority and recovery map

These are roles, not frozen types or call sequences. Read capabilities confer
no independent mutation authority. Each row links its existing domain rules;
the proof map below identifies executable evidence and its limits.

| Fact or work | Sole authority | Consumers / read capability | Staleness and permitted recovery | Contract / proof |
| --- | --- | --- | --- | --- |
| Selected header ancestry | Chainstate header admission and its chain tree | P2P and RPC via header tip/tree readers | New work or invalidation changes selection; re-read ancestry, without promoting bodies to applied state | `ARCH-07`, `P2P-06/10`; `SYNC-01/02` |
| Foreground body requests | P2P sync executor and exact peer-session ownership | Node adapter through `SyncChain`; scheduler reads applied/header frontiers | Cancellation, expiry, rejected delivery or changed ancestry releases/replans work; recover the canonical gap, not a remembered cursor | `P2P-03/05`; `SYNC-02/04/06` |
| Applied-tip commit | Active Chainstate and its durable head | Tip/chain snapshots, `StableRead`, node settlement and RPC | Connect, disconnect, snapshot activation and restart invalidate captured contexts; recover certified state or fail closed | `ARCH-07`, `RCV-*`; `SYNC-01/04/05` |
| Historical replay | AssumeUTXO manager and historical Chainstate's certified progress | P2P historical requests; lifecycle/progress readers | Snapshot target, validated archive and lifecycle govern resumption/finalization; missing bodies wait, terminal mismatch closes admission | `ARCH-07b`, `RCV-*`; `SYNC-01/03/04/07` |
| Reorg execution | Chainstate branch-switch owner | Node settles committed outcomes; P2P replans downloads | A changed branch invalidates preloaded plans; refuse before mutation or preserve the actual committed prefix and recover on failure | `ARCH-07`, `RCV-*`; `SYNC-02/04/05` |
| Post-commit follower settlement | Node orchestration of committed Chainstate outcomes | Mempool gateway, RPC log/ZMQ, mining and index wake | New commit/reorg or restart invalidates consumer context; ordered settlement and bounded observer delivery preserve the committed result | `EVT-*`, `MPL-04`; `SYNC-03/05` |
| Index backfill and query readiness | Derived-index runtime and atomically committed per-capability rows/watermarks | Index query engine, RPC/Esplora | Tip, process revision, reset, worker failure or restart invalidates reads; retry, reconcile/rebuild or report unavailable | `IDX-*`; `SYNC-01/03/05` |
| Retained-history availability | Storage retention registry and executed prune frontier | Mandatory chainstate operations and bounded optional `HistoryAccess` consumers | Prune reservation/commit, lease expiry and restart change availability; protect required operations, refuse lost history and honor supported rebuild limits | `ARCH-07/08`, `RCV-*`, `IDX-07`; `SYNC-07` |

## Behavioral proof map

Test names below locate representative evidence; equivalent replacements may
preserve the properties without preserving test or implementation shape.
[test-evidence.md](test-evidence.md) owns suite-family traceability. A listed
test is not a claim that it has run in every environment, or that every clause
is fully proved.

The node representative in `sync_smoke.rs`,
`tick_recovers_rejected_frontier_without_publishing_unapplied_blocks`, checks
header-only progress, ingress body-binding rejection and subsequent recovery
through actual Chainstate, UTXO/CoinStats and the RPC-consumed block log. The
malformed body is rejected before application; this test does not exercise
Chainstate window-failure settlement. Input is channel-fed and storage is in
memory; this does not establish transport or disk durability.

| Clause | Observable regression property / domain owners | Existing executable evidence | Scope and remaining gap |
| --- | --- | --- | --- |
| `SYNC-01` | Header-only progress cannot become applied/query progress; historical and index readiness stay independent. Chainstate, RPC, index. | [`context.rs`](../../crates/rpc/src/context.rs): `height_lookups_follow_applied_tip_when_header_fork_leads`; [`query_tests.rs`](../../crates/index/src/runtime/query_tests.rs): `transaction_rejects_watermark_from_rival_tip`; [`assumeutxo_tests.rs`](../../crates/chainstate/tests/unit/assumeutxo_tests.rs): `historical_replay_preserves_active_durable_head_and_notifications`. | Owner fixtures cover distinct frontiers. Joint snapshot activation with pre-existing indexes and complete-history reporting remains [#1512](https://github.com/gosuda/bitcoin-rs/issues/1512). |
| `SYNC-02` | An unowned frontier becomes requestable after rewind, peer loss or rejection; staged successors cannot strand it. P2P scheduling, Chainstate application. | [`frontier_recovery.rs`](../../crates/p2p/src/sync/tests/frontier_recovery.rs): `applied_rewind_with_unchanged_headers_refetches_the_missing_prefix`, `staged_successors_behind_a_rejected_frontier_still_probe`; [`witness_staging_gate.rs`](../../crates/p2p/src/sync/tests/witness_staging_gate.rs): `idle_frontier_relearns_stale_peer_credit_after_rejected_body`; [`sync_smoke.rs`](../../crates/node/tests/sync_smoke.rs). | Peer scheduling suites use `TestChain`, not durable application. The node regression crosses actual application/consumer boundaries with channel-fed input; it is not a live-socket peer-churn campaign. |
| `SYNC-03` | Optional work/failure cannot acquire active-chain authority or prevent foreground progress under stated resource assumptions. Node, P2P, Chainstate, index. | [`tx_ingress_e2e.rs`](../../crates/node/tests/tx_ingress_e2e.rs): `full_relay_queue_does_not_block_peer_admission_or_mining_wake`; [`historical.rs`](../../crates/p2p/src/sync/tests/historical.rs): bounded historical pipeline tests; [`assumeutxo.rs`](../../e2e/tests/assumeutxo.rs): `core_snapshot_import_syncs_both_roles_and_recovers`. | Relay saturation is channel-fed; historical scheduling uses `TestChain`. The real Core/snapshot process test withholds history but enables no index. Combined foreground/history/index contention and seed lock duration remain #1512; no absolute fairness or mainnet latency proof. |
| `SYNC-04` | Reject a mismatched delivery without poisoning valid ancestry; preserve committed outcomes and close terminal failures. P2P, Chainstate, node settlement. | `witness_staging_gate.rs` and `sync_smoke.rs`; [`chain_effects.rs`](../../crates/node/src/chain_effects.rs): `committed_connect_settlement_failure_retains_outcome_and_forbids_retry`; [`assumeutxo_recovery_tests.rs`](../../crates/chainstate/tests/unit/assumeutxo_recovery_tests.rs); [`crash_recovery.rs`](../../crates/node/tests/crash_recovery.rs). | Delivery/settlement fixtures and real-storage/process fault cases cover different boundaries. Their composition is not an exhaustive fault cross-product. |
| `SYNC-05` | Only committed application updates consumers; reorg/restart and rival index watermarks cannot expose false coherent success. Chainstate, node followers, RPC/index/mempool. | `sync_smoke.rs`; `chain_effects.rs`: `connect_then_disconnect_rewinds_the_rpc_log_and_emits_in_order`; [`overhaul_durable_head.rs`](../../crates/node/tests/overhaul_durable_head.rs): `durable_head_precedes_publication_and_survives_restart`; `query_tests.rs`; [`recovery_tests.rs`](../../crates/index/src/runtime/recovery_tests.rs). | Node smoke proves in-memory application/publication; durable-head test separately reopens real storage. Index recovery uses real Fjall with fixture bodies. Query revision changes during snapshot acquisition need a targeted regression; snapshot/index concurrency remains #1512. |
| `SYNC-06` | Temporary delivery failures permit renewed work; restart/reorg resume from the owned frontier under explicit assumptions. P2P, recovery and lifecycle owners. | `frontier_recovery.rs`; [`reorg.rs`](../../e2e/tests/reorg.rs): `restart_mid_chain_resumes_sync`, `core_reorg_repoints_node_tip`; [`ChainAdmission.tla`](../models/ChainAdmission.tla). | Process cases are finite regtest scenarios. The model concerns commit/admission/recovery, not P2P downloads, and assumes fairness, eventual input closure, backend availability and cessation of faults. [Formal evidence](formal-verification.md) is incomplete: no completed ChainAdmission safety/progress proof is recorded. Identity checks are not proofs. |
| `SYNC-07` | Pruning respects required recovery/history work; expired optional history is refused truthfully. Storage retention, Chainstate and index reconciliation. | [`prune_then_reorg.rs`](../../crates/storage/tests/prune_then_reorg.rs): `undo_pruning_keeps_records_the_durable_tip_still_needs`, `history_request_between_planning_and_commit_is_refused`, `optional_consumer_budget_exhaustion_unblocks_pruning`; [`prune.rs`](../../crates/node/tests/unit/state/tests/prune.rs): `assumeutxo_validating_blocks_prefix_pruning_even_above_base_height`; `recovery_tests.rs`: `pruned_history_rebuilds_from_the_frontier_and_absent_history_waits`. | Storage lease/batch and node pruning tests protect current owners. Index convergence from a retained floor does not prove coverage below it; combined snapshot/index/pruning behavior remains #1512. No archival promise is made. |

`SYNC-03`'s concrete unresolved interference path is ScriptLive seeding: its
stable UTXO read view spans the index seed writes. Bounded batches do not bound
that total guard duration. #1512 owns measurement and any necessary owner-local
fix, together with snapshot watermark and history-coverage scenarios.

## Change verification

Use the impact-based instruction in [AGENTS.md](../../AGENTS.md), selecting
the smallest behavioral proof from the map. For example, the channel-fed
application regression runs without a Core daemon:

```sh
cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --test sync_smoke
```

The new node regression and the existing P2P, Chainstate and RPC proofs are
selected by the PR lane (`scripts/ci-pr.sh test-crates`). Index and storage
owner suites retain the workspace lane, which runs for merge groups and main,
not pull requests; run the relevant owner tests explicitly when those clauses
are affected. Real-process, crash, contention, external consumer and formal
campaigns retain their existing fixture requirements and
[verification lanes](../../CONTRIBUTING.md#pull-request-verification). Add a
narrow regression only for a meaningful uncovered behavior; no new global
sync state, permanent harness or blanket full-sync gate is implied.
