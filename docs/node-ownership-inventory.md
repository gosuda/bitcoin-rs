# Node ownership inventory (#1085 Phase 1)

Status: working inventory for the [#1085](https://github.com/gosuda/bitcoin-rs/issues/1085)
architecture reset. Informative analysis, not a contract. Derived from the code
at `c0195fbf` (origin/main) — current behavior and current call graph, not from
any prior refactor plan. Supersedes the #1038/#1073/#1075 baselines, which
#1085 declares stale.

Method: every substantial `crates/node` responsibility was read against a
deletion-biased template (state owned, invariants, inbound callers, cross-domain
judgment, delete hypothesis, caller-simplification hypothesis, collapse
hypothesis, irreducible owner, minimal remaining API). Claims below carry
`file:line` evidence. Items marked **[verified]** were re-checked by direct
grep/read against the tree; items marked **[hypothesis]** are reviewer-facing
predictions that the subtraction phases must confirm before acting.

## Reading rules

- `DELETE` — behavior is obsolete, duplicated, transitional, derivable, or
  already owned elsewhere. Default hypothesis.
- `COLLAPSE` — unnecessary internal layering becomes one simpler unit.
- `KEEP` — genuinely node-owned composition/orchestration/lifecycle.
- `MOVE` — last resort; each entry states why DELETE and COLLAPSE are
  insufficient and names the **existing** owner crate.

## Measured current shape

Production LOC (test modules excluded), root file + subtree:

| Module | Root | Subtree | Total | `foo.rs + foo/` smell |
| --- | ---: | ---: | ---: | --- |
| apply | 1404 | 3536 | 4940 | Yes — root holds `Chainstate`, admission, constants, plumbing types, `cfg(test)` helpers beside a substantial subtree |
| chainstate_journal | 49 | 3209 | 3258 | No — root is a true index file |
| state | 460 | 2100 | 2560 | Yes — root is a 38-field aggregate with 35+ getters beside layered subtree |
| checkpoint | 485 | 2043 | 2528 | Yes — root holds schema/errors/dispatch beside load/publish subtrees |
| sync | 279 | 1926 | 2205 | Borderline — root conductor + p2p-mechanics subtree |
| reorg | 496 | 411 | 907 | Yes — subtree is one-caller helpers |
| metrics | 29 | 842 | 871 | Yes — mostly because of the bench-only `evidence/` subtree |
| config | 27 | 970 | 997 | No — root is a true index file |
| recovery_evidence | 454 | 240 | 694 | No |
| storage_footprint | 328 | 321 | 649 | No |
| lifecycle | 8 | 605 | 613 | No |
| mining | 245 | 334 | 579 | Mild |
| chain_effects | 558 | 0 | 558 | n/a |
| tx_ingress | 168 | 0 | 168 | n/a |
| **Total** | | | **≈22 800** | |

`bitcoin-rs-node` depends on all eleven other workspace crates — the widest
fan-in in the workspace, which is the "hidden implementation crate" risk #1085
names.

## Master classification

| Responsibility | Class | Confidence | One-line basis |
| --- | --- | --- | --- |
| `apply` core (admission, `Chainstate`, connect/disconnect/window/durable) | KEEP (+ internal COLLAPSE) | high | Only realisation of ARCH-07 transition admission in the workspace |
| `apply/contextual.rs` consensus/chain rule helpers | MOVE→consensus/chain (partly DELETE) | medium | Re-implements or misfiles domain rules; see MOVE ledger |
| `apply.rs` `cfg(test)` hash helpers, wrapper chain | DELETE | high [verified] | Duplicates consensus capability / adds indirection |
| `sync` conductor (`BlockSync::tick`) | KEEP (shrinks) | high | Cross-domain sequencing p2p→apply |
| `sync/{peers,requests,receive,headers}` p2p mechanics | DELETE/COLLAPSE into p2p owner | medium [hypothesis] | ~claims of duplication of `p2p::download_window` APIs; Phase-2/3 must confirm coverage |
| `sync/commit.rs` window application | COLLAPSE into apply | high | It is apply-window logic reached only via sync |
| `sync/branches.rs` | COLLAPSE into reorg | high | Reorg-branch policy beside the reorg owner |
| `state.rs` `NodeState` aggregate | COLLAPSE (shrink fields/getters) | high | 11 fields + several getters duplicate `Chainstate` handles; two getters test-only |
| `state/open.rs` | COLLAPSE into lifecycle startup | high | Pure wiring plus two genuinely-node concerns (epoch alloc, marker preflight) |
| `state/storage.rs` `NodeStorage` + `DeferredChainstateServices` | DELETE/MOVE seam to storage | high | Storage-domain constructors; deferral buys nothing |
| `state/restore.rs` | KEEP | high | Sole owner of checkpoint-vs-journal restore selection |
| `state/events.rs` | KEEP | high | Process-epoch allocator + commit-ordered publication |
| `state/index.rs` | COLLAPSE | high | Config→index translation + one-call worker spawn |
| `state/prune.rs` | KEEP (small) | high | rpc-facing adapter; MOVE to storage is layering-blocked (see corrections) |
| `state/maintenance.rs` | COLLAPSE into lifecycle services | high | One idle worker owning poll interval only |
| `state/checkpoint.rs` | COLLAPSE into checkpoint publisher | high | Pure delegation; duplicated constructor |
| `storage_backend.rs` | KEEP | high | Enforced sole owner of engine construction (ARCH-03) |
| `chainstate_journal` cluster | KEEP (whole) | high | No existing owner; distinct codec/replay/writer invariants |
| journal `BlockMeta` + accessor | DELETE | high [verified] | Production-dead |
| `checkpoint` load/publish core | KEEP | high | Atomic publication is lifecycle orchestration over four storage traits |
| `checkpoint/publisher.rs` + `state/checkpoint.rs` | COLLAPSE | high | Same ownership split in two files + duplicated ctor |
| `checkpoint/headers.rs` | MOVE→chain | high | Pure chain-domain codec; see MOVE ledger |
| `checkpoint/io.rs` | DELETE (inline) | medium | Test plumbing: production path injects `failpoint=None` |
| `checkpoint/format.rs` | DELETE partial | high | Hex codec belongs with the codec user; network name to primitives |
| `checkpoint/fs.rs` CURRENT_SCHEMA machinery | DELETE candidate | medium [hypothesis] | Version 0, no schema-bump contract enforced |
| `reorg` root | KEEP | high | Only cross-owner branch-switch sequencer |
| `reorg/{bodies,execution,settlement}` | COLLAPSE into reorg.rs | high | One-caller helpers; single ~430-line file result |
| `chain_effects.rs` `ChainEffects` | COLLAPSE into `ChainFollowers` | high | Thin dispatcher over handles owned elsewhere |
| `wake_tx_index` fast-wake | DELETE candidate | medium [hypothesis] | Possibly redundant with cursor-driven index worker; needs latency check |
| `recovery_evidence` witness + marker-write + `WarningStore` | KEEP | high [verified] | Live production chain into RPC-visible warnings |
| `recovery_evidence::read_marker` | DELETE | high [verified] | Production-dead read API |
| `storage_footprint` cluster | KEEP | high | FP-01..04 owner; `--measure-storage` caller |
| `metrics` prometheus + readiness | KEEP | high | Live scrape surface |
| `metrics/uptime.rs` | DELETE | high [verified] | `record_process_start` never called in production |
| `metrics/evidence/*` | DELETE (contingent on #1084) | high | Bench/gate-only once #1084 removes the gates |
| `metrics/warnings.rs` write-side | DELETE candidate (audit) | high [verified] | `set`/`unset` have no production writer; registry is permanently empty |
| `config` cluster | KEEP | high | Live layered config, ARCH-05 |
| `embed` facade | KEEP | high | Documented embedding contract (EMB-01..08) |
| `embed/testing.rs` | DELETE | high | Test-only `block_on`; inline into tests |
| `lifecycle` cluster | KEEP | high | Genuine service-graph composition/teardown |
| `mining` coordinator | KEEP | high | Owns transition-lock header admission + apply gate + wake seam |
| `tx_ingress` | KEEP | high | p2p→mempool routing consumer |
| `import.rs` | DELETE | high [verified] | Skeleton with zero production callers |
| `event_loop`, `run`, `signal`, `shutdown`, `logging` | KEEP | high | Distinct process-level roles |

## Cluster findings

### apply (4940)

State/invariants owned: `ApplyAdmission` closed/barrier pair (apply.rs:177+),
`TransitionLock` + `ChainChangeProof` + `ChainTransition` as the sole ARCH-07
admission realisation, `Chainstate` handle set (apply.rs:502-535), applied-tip
publication seqlock (`publication.rs`), disconnect-marker protocol
(`disconnect.rs`, pinned by `transitions_1` tests).

Cross-domain: reaches consensus (`verify_block_*`, BIP30/34/68), chain
(`softfork_state`, header validation), utxo (`build_block_changes`,
`persist_block_undo`, overlay), storage (`durable_head`), mempool
(`ChainChangeGuard`). Inbound production callers: sync, reorg, chain_effects,
state (open/prune/restore), mining (candidate/submission), checkpoint
publisher — i.e. genuinely cross-domain orchestration. KEEP.

Subtractions inside apply:

- `cfg(test)` `sha256d`/`merkle_root_bytes` (apply.rs:142-175) duplicate
  consensus merkle capability — the docstrings say so themselves **[verified]**.
  Same for `block_txids` (apply.rs:1144-1150) and `apply/scratch.rs`
  `is_coinbase` (duplicates `bitcoin_rs_utxo::is_coinbase_tx` imported at
  apply.rs:60).
- The 4-hop wrapper chain `apply_block_with_serialized_admitted →
  apply_block_inner → apply_committed_block_admitted → apply_block_admitted`
  collapses by inlining (~30 LOC; connect.rs:42-47 wrapper has two refs).
- `prove_window` prelude duplication with `connect.rs` (~150 LOC) **[hypothesis]**.
- `contextual.rs:24-49` `compact_to_target` re-implements
  `chain::header_sync::pow_to_target` per its own comment — DELETE the node
  copy once chain exports the function. `compute_verify_flags` belongs with
  `chain::softfork`; coinbase-maturity/BIP68/BIP30 helpers and the
  `COINBASE_MATURITY`/`BIP68_*` constants (apply.rs:131-138) belong in
  consensus next to the rules they implement. These are MOVE-ledger entries.

### sync (2205)

State owned: `BlockSync` conductor (sync.rs:85-114) with `ExpectedApplyCache`,
`PendingHeaderRequest`, `apply_halted`, `known_sessions`. Inbound production
caller: only `EventLoop::on_sync_tick` (event_loop.rs:127-134) plus bench and
tests. The conductor sequences p2p download → staged bodies →
`ChainTransition::connect_window` (apply.rs:687) → followers → reorg branch
switches (`reorg::switch_to_branch` from branches.rs). KEEP the conductor; it
is the cross-domain sequencing node must own.

The subtree is where the weight sits: `peers.rs`/`requests.rs`/`receive.rs`
(~938 LOC) re-implement peer selection, getdata/probe scheduling, and body
staging mechanics that `crates/p2p` (DownloadWindow/BlockStager/SyncPlanner)
already own or should own **[hypothesis — Phase-2 must diff each function
against the p2p API surface before deleting]**; `commit.rs` window application
is apply logic; `branches.rs` is reorg policy; `telemetry.rs` splits between
p2p metrics and one operator progress log. Estimated end state after
subtraction: conductor of roughly 125-195 LOC with the subtree gone. The
`state.rs:354-381` inbound-channel accessors exist only to wire
`BlockSync::new` and disappear with the pass.

### state + storage_backend (2775)

`NodeState` (state.rs:82-143) is a 38-field aggregate; at least 11 fields hold
the identical `Arc` already inside `apply_handles: Chainstate`
(`chain_tip`, `applied_tip`, `chain_tx_count`, `block_tree`, `utxo`,
`coin_stats`, `mempool`, `mempool_gateway`, `chain_events`,
`block_body_store`, `undo_store`/`durable_head`/`journal` via subsystem paths)
**[verified against apply.rs:502-535 field list]**. Readers could go through
`Chainstate` accessors; Phase 5 collapses the duplicate fields and ~22
pass-through getters. Two getters — `chain_event_publisher()` (state.rs:410)
and `chain_event_hints()` (state.rs:414) — have only test callers
**[verified]** and are immediate deletions (the publisher itself stays, wired
via `apply_handles.chain_events`).

Subtree: `restore.rs` KEEP (sole owner of cold/checkpoint/journal selection and
the journal→checkpoint fallback, restore.rs:128-272); `events.rs` KEEP (sole
writer of `<data_dir>/process-epoch` with flock, commit-ordered publication,
bounded hint channel); `storage_backend.rs` KEEP (enforced single construction
owner for engine opens — ARCH-03 contract test lives here); `open.rs`
COLLAPSE into lifecycle startup keeping only epoch allocation and the
disconnect-marker preflight; `index.rs` COLLAPSE (translation belongs to the
index crate, worker spawn to lifecycle); `maintenance.rs` COLLAPSE into
lifecycle services as the idle maintenance arm; `checkpoint.rs` COLLAPSE with
`checkpoint/publisher.rs` (constructor duplicated field-by-field at
open.rs:454-475); `storage.rs` — the `KvUndoStore`/`KvDurableHeadStore`/
`IndexedBlockBodyStore` construction and `StoredBlockBodySource` adapter are
storage-domain wiring; `DeferredChainstateServices` defers two one-shot
constructions and buys nothing (both called exactly once: open.rs:259,486).
DELETE the seam; the constructors complete the storage crate's existing
ownership (MOVE ledger).

### chainstate_journal (3258)

Writers: apply connect/disconnect (connect.rs:145,781; disconnect.rs:166-169),
construction at state/storage.rs:140-318, freeze/compact/resume driven by
checkpoint publisher (publisher.rs:46-55). Sole replay caller:
state/restore.rs:199. Invariants: three-step fsync ordering
(writer/durability.rs, pinned `head_never_advances_without_counted_storage_flush`),
append contiguity + fail-closed rebuild, CRC-framed codec (pinned by
`every_single_byte_corruption_is_rejected`), reorg identity + sticky
full-revalidation marker (writer/rewind.rs).

Why not DELETE: the cluster is the recovery accelerator that restores the
committed gap above a checkpoint without replay (pinned by
state/tests/recovery.rs:589-637); removing it is the separate
"checkpoint-only restore" decision with its own blast radius (bench, boot
tests, restore selection), not a Phase-1 call. Why not COLLAPSE: the
codec/replay/writer seams own distinct failure modes with contract-tagged
tests; merging them trades clarity for nothing (the writer root is policy +
struct, not a facade). Why not MOVE: storage has no append-log surface and
must not own recovery policy (Layer 1); chain/utxo would create layering
violations; no existing crate owns the composition. KEEP whole. Inside the
cluster, `BlockMeta` + `JournalRecord::block_meta` (record.rs:41,77) is the
one production-dead item **[verified]**.

### checkpoint (2528)

Three production trigger paths converge on `CheckpointPublisher::publish`
(publisher.rs:89): clean shutdown (embed.rs:231 → services.rs:240 →
state/checkpoint.rs:58 → publisher.rs:89), idle retention compaction
(startup.rs:162 → maintenance.rs:67-78), and reorg disconnect-debt settlement
(reorg/settlement.rs:12-22 → apply/entrypoints.rs:57-62 → publisher.rs:139-148).
Single load path: state/open.rs:62-74 → restore.rs selection.

KEEP the load/publish core: authenticated cross-store snapshot publication is
lifecycle orchestration consulting four storage traits (`KvStore`,
`DurableHeadStore`, `UndoStore`, `BlockBodyStore`) — the storage crate has no
overlapping primitive (`KvStore::snapshot` is a point-in-time KV view;
`durable_head` is the authoritative commit point the checkpoint consults, not
a duplicate) **[verified against storage/src]**. The journal↔checkpoint split
is already clean (different files, temporal coordination only).

Subtractions: COLLAPSE publisher.rs + state/checkpoint.rs into one publisher
(eliminates the duplicated constructor); DELETE io.rs test plumbing
(production injects `failpoint=None` — io.rs:9-15); DELETE format.rs hex
helpers with the headers.rs move, `network_name` → primitives; shrink fs.rs
CURRENT_SCHEMA machinery (~50 LOC, version 0, no bump contract)
**[hypothesis]**; MOVE headers.rs (below).

### reorg + chain_effects (1465)

`reorg.rs` root is the only place that orders utxo rollback → journal rewind →
durable-head commit → mempool re-admission → index/ZMQ/mining effects under
one `ChainTransition` proof, preserving odd/even generation
(settle_reorg_transition, pinned by three MPL-04 tests) and disconnect-marker
disarm. KEEP. The subtree (`bodies.rs`, `execution.rs` helpers,
`settlement.rs`) is one-and-two-caller mechanics: COLLAPSE into a single
~430-line `reorg.rs` with no subtree (~-185 LOC net of module boilerplate).

`chain_effects.rs::ChainEffects` (145 LOC) is a thin dispatcher over handles
owned elsewhere (`BlockLog` via `NodeState::blocks`, `ZmqPublisher` from
rpc::zmq, `DerivedIndexRuntime` already a `ChainCursorSource` via
state/events.rs:75-82); its capture policy duplicates
`handles.capture_rawtx/capture_block_bytes` (apply/connect.rs:337,409).
COLLAPSE into `ChainFollowers`, whose ~50-line dispatch ordering
(effects → mining → mempool, chain_effects.rs:346) is the irreducible part.
The `wake_tx_index` fast-wake (chain_effects.rs:144) is a semantic deletion
candidate if the cursor-driven index worker already bounds latency
**[hypothesis — needs a latency check before deletion]**.

### recovery_evidence, storage_footprint, metrics (2214)

`recovery_evidence`: KEEP — the witness path has three production consumers
(checkpoint/publisher.rs:228-238 writes; state/open.rs:194-196 reads+detects
fallback; storage_footprint/identity.rs:94-98 re-reads for stop identity), and
the rollback-marker write path is live end-to-end:
state/open.rs:182 constructs `RecoveryReporter` → state/index.rs:100,170 hands
it to the derived-index worker as `Arc<dyn IndexAheadSink>` →
crates/index/src/runtime/rollback.rs:105-118 fires `report_index_ahead` during
reconcile → reporter.rs:44-83 updates `WarningStore::add_index` (:65) and
`write_marker` (:81,:117) → RPC-visible via `getblockchaininfo.warnings`
**[verified]**. Sole deletion: `read_marker` (production-dead; the stale
`#[cfg_attr(not(test), allow(dead_code))]` on `with_index` also goes — the
production path calls it through `add_index`).

`storage_footprint`: KEEP whole (FP-01..04 owner; `bin/bitcoin-rs
--measure-storage` at main.rs:67; all 11 tests behavior-pinning). Note: the
FP-04 1-TB gate is currently unbound — the planned evidence test does not
exist (docs/contracts/storage-footprint.md:116).

`metrics`: KEEP prometheus + readiness (live wiring startup.rs:50-66).
DELETE uptime.rs (38 LOC — `record_process_start` has no production caller;
the uptime clock is never set in a real process) **[verified]**. DELETE the
`metrics/evidence/*` identity types are KEEP: startup.rs:50-53 constructs
`EvidenceIdentity::of_process`, while prometheus.rs:77-100 installs its labels
as process-global recorder labels (start_metrics/bind at :163-172). Any #1084
cleanup must first migrate this live startup and label path; only code proven
bench-only may be deleted. `warnings.rs`: the
write-side (`set`/`unset`, `WarningKind` enum) has **no production writer** —
the registry can never hold a warning today; the only reader is
`getmininginfo` (mining/control.rs:31) **[verified]**. Either the write-side
is dead scaffolding (delete, and drop the always-empty projection) or
production wiring is missing — audit before deleting, since removing the
always-empty field is observable at RPC level.

### config, embed, lifecycle, mining, tx_ingress, process singles (3416)

`config` KEEP: the user/resolved/resolve/runtime layering is the ARCH-05
surface `bin/main.rs:44` consumes; tests pin precedence behavior. `embed` KEEP
as the documented embedding contract (EMB-01..08); its facade methods have no
non-test callers today beyond the `run.rs` start/shutdown path — that is the
contract's nature, not dead code. DELETE `embed/testing.rs` (test-only helper,
inline). `lifecycle` KEEP (services owns every join handle + single ordered
teardown + clean-checkpoint gate; startup is the sole composer; rpc.rs is the
single seam building the RPC `Context` and the only bridge of
`reorg::invalidate_block` into `ChainControl`). `mining` KEEP — the
coordinator owns the transition-lock header admission
(`accept_submitted_header`, mining.rs:104-128), the submit-side apply gate
verifying the published tip (submission.rs:60-93), the BIP22 reject vocabulary
(API-18/30), and the mempool→template wake seam (mining.rs:188-197);
`bitcoin_rs_mining` provides none of these. `tx_ingress` KEEP (p2p→mempool
routing + relay/mining dispatch). `import.rs` KEEP — publicly exported block-import API (`lib.rs:28-29`) with
implemented `import_block`; the absence of in-repository production callers
 does not establish absence of downstream users. Removal requires a separately
coordinated deprecation and semver migration, not an inventory deletion. `event_loop`/`run`/`signal`/
`shutdown`/`logging` KEEP — distinct process-level roles (drain-flag pair
between event_loop and services, signal forwarding thread, TTY-aware tracing).

## Cross-module relationships the reset must preserve

1. **Recovery chain**: checkpoint load (state/open) ↔ restore selection
   (checkpoint vs journal replay vs fallback) ↔ journal writer/retention ↔
   utxo rollback markers ↔ recovery-evidence witness. Recovery sequencing
   currently spans restore.rs + journal + checkpoint + open.rs; any collapse
   must keep the single-selection-owner property of restore.rs.
2. **Publication ordering**: apply commit → durable head → applied-tip
   publication (seqlock) → ChainFollowers dispatch (effects → mining →
   mempool) → ZMQ/notifications; reorg runs the inverse ordering under the
   same transition proof.
3. **Epoch/identity**: state/events.rs process-epoch allocator is the sole
   writer of `<data_dir>/process-epoch`; witness/footprint identity and index
   reconciliation read it. Must remain single-owner.
4. **Prune/retention**: retention leases (utxo RetentionRegistry) are claimed
   by reorg + prune service + checkpoint publisher; the clamping lives in
   state/prune.rs and reorg.rs — keep one lease authority when collapsing.

## Verification corrections (recorded for #1076/#1084 coordination)

These corrections were confirmed by direct grep against `c0195fbf` and should
adjust the assumptions carried in the #1076 thread:

- **Journal re-exports are NOT dead (3 of 4).** `JournalEmit` (emit.rs:21,137;
  locked at apply/connect.rs:145,781, apply/disconnect.rs:166-169,
  state/maintenance.rs:103), `HeadMarker` (writer.rs:192-220; replay.rs:23-359
  + every writer submodule), and `JournalWriterFailpoint` (writer.rs:134,379;
  failpoints.rs gate predicates) are live. Only `BlockMeta` +
  `JournalRecord::block_meta` is production-dead.
- **The rollback-marker path is live.** An initial deletion hypothesis
  ("marker is write-only audit evidence with no runtime consumer;
  `add_index`/`with_index` unused") was refuted by tracing
  state/open.rs:182 → state/index.rs:100,170 → index runtime
  rollback.rs:105-118 → reporter.rs:44-83 → RPC warnings. Only `read_marker`
  is dead. The stale `allow(dead_code)` on `WarningSnapshot::with_index`
  should be removed, not the code.
- **`sync_tick` is live.** event_loop.rs:93-97 receives it and drives
  `on_sync_tick`; the "dead channel" claim did not survive verification.
- **`state/prune.rs` cannot move to storage.** It implements an
  `bitcoin_rs_rpc::context` trait; storage (Layer 1) must not depend on rpc
  (Layer 3). The service stays a node-level rpc-facing adapter unless the
  trait itself moves.

## Subtraction ledger (Phase 2/3 input)

Confirmed, low-risk deletions (production LOC):

- `import.rs` is retained as a public API; any removal requires coordinated deprecation and downstream migration
- `embed/testing.rs` (15)
- `metrics/uptime.rs` (38)
- journal `BlockMeta` + accessor (~40)
- `recovery_evidence::read_marker` + production suppression (~30)
- `apply.rs` `cfg(test)` hash/merkle helpers + `scratch::is_coinbase` (~60 test-LOC)
- apply wrapper-chain inlining (~30)
- `NodeState` test-only getters `chain_event_publisher`/`chain_event_hints` (~15)
- `checkpoint/io.rs` after inlining failpoint field (~90)
- `checkpoint/format.rs` hex/network helpers (~50)
- `metrics/warnings.rs` write-side, after the audit above (~60)

Collapse candidates (net-negative, no ownership change):

- reorg subtree → single reorg.rs (~-185 net)
- `ChainEffects` → `ChainFollowers` (~-145)
- publisher.rs + state/checkpoint.rs (~-60 plus one duplicated ctor)
- state/maintenance.rs → lifecycle services (~-30)
- state/index.rs translation → index crate (~-100 node-side)
- `DeferredChainstateServices` seam (~-80)
- prove_window/connect.rs prelude dedupe (~-150) **[hypothesis]**

Contingent on #1084: only bench-only portions of `metrics/evidence/*` (after
preserving production identity creation and recorder labels), plus the shape-pinning test
files named per cluster (≈6 of 14 checkpoint tests, config/status shape tests,
admission/internals tests in apply, ~30% of sync tests).

Bigger bets requiring their own verification PRs: sync subtree subtraction
into p2p (~-900 node-side) **[hypothesis]**; `wake_tx_index` removal (latency
check); fs.rs CURRENT_SCHEMA removal.

## MOVE ledger (Phase 4 candidates)

Each entry must answer why DELETE/COLLAPSE fail; all destinations already
exist.

1. `checkpoint/headers.rs` (414) → `bitcoin_rs_chain`. Why not DELETE: no
   duplicate exists — the header-checkpoint codec has one implementation.
   Why not COLLAPSE: it is chain-domain (types, pow commitments, 22-variant
   error enum over chain/primitives only, headers.rs:5-298) misfiled in node;
   collapsing keeps it in the wrong owner. Node keeps only the call sites.
   Tests travel with the codec.
2. `state/storage.rs` storage constructors (`KvUndoStore`, `KvDurableHeadStore`,
   `IndexedBlockBodyStore`, `StoredBlockBodySource`) → `bitcoin_rs_storage`,
   next to the traits they implement. Why not DELETE: construction logic is
   needed once. Why not COLLAPSE into node: these are Layer-1 mechanical
   adapters; node keeping them re-implements storage ownership (ARCH-02/03
   spirit). The node-side `DeferredChainstateServices` seam IS deleted.
3. `apply/contextual.rs` rule set (maturity/BIP68/BIP30 helpers, verify-flags
   computation, `COINBASE_MATURITY`/`BIP68_*` constants) →
   `bitcoin_rs_consensus` (with `compute_verify_flags` →
   `chain::softfork`). Why not DELETE: the rules must exist somewhere and
   consensus is their real owner; node copies exist only because consensus
   lacks the surface. Why not COLLAPSE: keeping domain rules inside the apply
   orchestrator is the exact "node as hidden implementation crate" pattern
   #1085 rejects. The one true DELETE inside this entry:
   `compact_to_target` (duplicates `chain::header_sync::pow_to_target`).

No other MOVE survives the template: sync mechanics are DELETE/COLLAPSE
candidates (capability exists in p2p), and everything else is KEEP.

## Open questions for review

1. Sync subtree: does `p2p::download_window` cover peer
   selection/eviction/probe scheduling completely enough to delete the node
   copies, or does the capability need to transfer (making it a MOVE)? Needs a
   function-by-function diff before Phase 2 acts.
2. Warnings write-side: delete the never-written registry (and the
   always-empty RPC projection), or is missing production wiring a bug to
   fix? Observable RPC change either way — maintainer call.
3. Journal wholesale deletion ("checkpoint-only restore"): rejected for this
   inventory as a separate decision; recorded so it is not lost.
4. `metrics/evidence` deletion timing: gate removal (#1084) first, then the
   subtree, keeping the bench via a local copy of the ledger types.
