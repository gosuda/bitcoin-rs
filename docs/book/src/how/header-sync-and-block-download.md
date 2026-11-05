# Header sync and block download

The node learns about new blocks in two stages. Headers flow through a peer-by-peer pipeline that refuses cheap fake chains, then bodies download through a budgeted window and get applied in order. This page covers the header pipeline (`crates/chain/src/header_sync.rs`, `crates/p2p/src/sync/headers_presync.rs`), difficulty and deployment state (`crates/chain/src/deployment.rs`, `progress.rs`), the download window and stager (`crates/p2p/src/download_window.rs`, `block_stager.rs`), stale tips and peer eviction (`crates/p2p/src/sync/stale_tips.rs`, `staletip.rs`, `eviction.rs`), historical sync for assumeutxo (`crates/p2p/src/sync/historical.rs`), and the frontier that drives all of it (`crates/p2p/src/sync/frontier.rs`). [how/p2p.md](p2p.md) covers the wire protocol; [run/sync-and-recovery.md](../run/sync-and-recovery.md) covers operator-facing behavior. Contract clauses: `P2P-10` in `docs/contracts/p2p-wire.md`, `SYNC-01`, `SYNC-02`, `SYNC-06` in `docs/contracts/synchronization.md`.

## Header admission

`accept_headers` (`crates/chain/src/header_sync.rs:74`) admits each header in wire order:

```
already known -> reuse node id; Invalid parent chain -> KnownInvalidHeader
validate_pow (header_sync.rs:245)         PoW target, zero and overflow targets
first header must be genesis              MissingParent otherwise
parent lookup, Invalid parent -> InvalidParent
validate_contextual_header (header_sync.rs:131)
insert as NodeStatus::HeaderValid
```

`validate_contextual_header` checks, in order: nbits equals `next_work_required` (`header_sync.rs:202`, `NbitsMismatch` otherwise), `header.time > median_time_past` (`TimestampTooEarly`), the BIP94 timewarp floor on retarget boundaries when the network enforces it (`minimum_candidate_time`, `header_sync.rs:196`, error `TimewarpAttack`), live-admission future time within `MAX_FUTURE_TIME_SECONDS = 7200` (`header_sync.rs:13`, `TimestampTooFarAhead`), and the version locks: BIP34 requires version >= 2, BIP66 >= 3, BIP65 >= 4, each only while active (`header_sync.rs:173`).

## The presync anti-DoS gate

A peer with no stake can announce an endless low-difficulty header chain. Before the node admits any of it, `HeadersSyncState` (`crates/p2p/src/sync/headers_presync.rs:192`) runs the same headers twice, the scheme Bitcoin Core uses in `headerssync.cpp` and clause `P2P-10` specifies:

1. **Presync.** Every header gets three cheap checks: continuity (`NonContinuous`), permitted difficulty transition (`permitted_difficulty_transition`, `DifficultyTransition`), and its own proof of work (`InvalidPow`). Nothing is stored. At every `commitment_period` heights, the state records one bit: a salted hash of the header, where the salt-derived offset (`presync.rs:227`) keeps a malicious peer from predicting commitment positions. `max_commitments` scales with time since the anchor at six commitments per hour (`presync.rs:231`), so a peer cannot stretch the pass forever (`MaxCommitments`).
2. **Redownload.** Once accumulated work crosses `minimum_work` (`presync.rs:301`), the state rewinds to the fork point and demands the headers again (`begin_redownload`, `presync.rs:341`). Now each header is re-verified and its commitment bit must match the recorded bit (`CommitmentMismatch`); headers are released from a bounded buffer only after the re-check (`pop_ready_headers`, `presync.rs:444`).
3. **Final.** The release gate opens and the remaining headers flow to `SyncChain::admit_headers`.

Errors classify into peer faults and not: `is_peer_fault` (`presync.rs:66`) is false only for `NonContinuous`, since a stale batch boundary can break continuity without lying. Every other failure finalizes the state and disconnects.

Running the phase-transition test at this tree:

```
$ cargo test --offline --locked -p bitcoin-rs-p2p \
    sufficient_work_chain_syncs_presync_then_redownload -- --nocapture
test sync::tests::headers_presync::sufficient_work_chain_syncs_presync_then_redownload ... ok
```

`minimum_chain_work` comes from the network parameters (`SyncChain::minimum_chain_work`, `crates/p2p/src/sync/chain.rs:91`). Chains below the anti-DoS work threshold are collected, not admitted. The threshold is that floor or, once a tip is applied, the applied tip's work minus 144 blocks of the tip's work, whichever is larger (`BlockSync::anti_dos_work_threshold`). This is what makes the download-twice rule cheaper than the fake chain.

## Difficulty, deployments, and progress

`next_work_required` (`header_sync.rs:202`) computes retarget bits on interval boundaries and `expected_non_retarget_bits` otherwise; the algorithm is pinned by clause `DAA-01` of `docs/contracts/validation-default.md` ("Bitcoin Core 31.1 difficulty adjustment"). Forks inherit their own retarget path, exercised by `crates/p2p/src/sync/tests/fork_retargeting.rs`.

Deployment state comes from `softfork_state` (`crates/chain/src/deployment.rs:88`): CSV and segwit are evaluated per block tree via `deployment_active`, falling back to the static network schedule when signalling data is unavailable. `signalling_deployments` (`deployment.rs:118`) reports which named deployments (`csv`, `segwit`, `deployment.rs:114`) are `Started` or `LockedIn` at a height. The connect path reads this per block to pick witness rules and version gates (`validation_contexts`, `crates/chainstate/src/connect.rs:179`).

`ChainProgressReader` (`crates/chain/src/progress.rs:24`) is what `getblockchaininfo` serves: blocks and headers heights, bits, median time, `verification_progress`, and `chain_work`. `InitialBlockDownload` (`crates/chain/src/ibd.rs:8`) latches exit from IBD: once the applied tip's chainwork reaches `network.minimum_chain_work` and its header time is within `MAX_TIP_AGE_SECONDS = 24h` (`ibd.rs:6`), the latch closes and never reopens (`ibd.rs:34`). Relayers use the latch to delay announcements; see `with_ibd` wiring at `crates/node/src/lifecycle.rs`.

## The download window and stager

`DownloadWindow` (`crates/p2p/src/download_window.rs`) owns in-flight body requests; `BlockStager` (`crates/p2p/src/block_stager.rs`) holds received blocks until their predecessors are applied. `SyncBudget` (`download_window.rs:17`) bounds the pipeline:

| Constant | Value | Meaning |
|---|---|---|
| `PENDING_BUDGET` | 256 blocks (`policy.rs:21`) | max queued requests |
| `PENDING_BLOCK_BYTE_ESTIMATE` | 2 MiB (`policy.rs:24`) | conservative size per pending block |
| `RECEIVED_BLOCK_TIMEOUT` | 1 minute (`policy.rs:22`) | a staged block older than this is dropped |
| `MAX_BLOCKS_IN_TRANSIT_PER_PEER` | 16 (`policy.rs:35`) | per-peer inflight cap |
| `MIN_PEERS_FOR_FANOUT` | 8 (`policy.rs:36`) | peers needed before requests fan out |
| `FAST_BLOCKS_IN_TRANSIT_PER_PEER` | 8, fanout at 2 (`policy.rs:40`) | `--fast-sync` profile |

Each `SyncBudget` field pairs a count with a byte budget; both must hold. The window tracks per-peer delivery speed (an EWMA of front-of-window intervals, `download_window.rs:141`) and detects stalls: when the window front stops moving, `stall_timeout` (`download_window.rs:906`) grows from `stall_timeout_initial` to `stall_timeout_max`, the stalling peer is put on `staller_cooldown`, and its heights re-request from others. Timeouts scale with peers that could serve the height (`BLOCK_DOWNLOAD_TIMEOUT_BASE = 2` plus one per peer, `policy.rs:16`).

The scheduler runs from one place: `BlockSync::tick` (`crates/p2p/src/sync.rs:426`), driven by a 1-second timer and by peer-readiness wakes (see [startup.md](startup.md)). Each tick retires timed-out header syncs, drains inbound headers and blocks, advances historical validation, builds the frontier, and sends `getdata` per `frontier.plan()`.

## The frontier

`SyncFrontier` (`crates/p2p/src/sync/frontier.rs:76`) is the per-tick reconciliation of what the chain needs and what peers can give. `ChainFrontier` (`frontier.rs:27`) carries the applied tip, the header tip, the canonical `next_required` body (height plus hash), and a `closed_for_recovery` flag. `UsablePeer` (`frontier.rs:35`) carries each peer's demonstrated tips and resolved height: a peer's capability is the larger of its claimed height and a height it actually proved by delivering a block or header (`body_capability`, `frontier.rs:57`). Claimed height alone is never trusted for scheduling.

`plan()` (`frontier.rs:123`) returns either scheduled work or a `NoProgressReason` (`frontier.rs:99`): `AtTip`, `ApplyHalted`, `ChainViewUnavailable`, `FrontierUnresolvable`, `NoUsablePeers`, or `NoCapablePeer`. The invariant the doc comment owns: when the header tip is ahead of the applied tip and `next_required` is unowned, the plan either schedules recovery work or names the reason it cannot. This is `SYNC-02` (transient work is a hint; the frontier owns the next block) and `SYNC-06` (eligible work reaches a driver) in code.

## Stale tips

When a competing tip loses, the node keeps it instead of forgetting it. `StaleTipRetainer` (`crates/p2p/src/sync/stale_tips.rs:116`) holds up to `MAX_RETAINED_STALE_TIPS = 64` tips ranked by (work, sequence), prunes entries that are no longer stale forks of the current tip (`prune`, `stale_tips.rs:54`), and only considers forks within `STALETIP_RECENT_WINDOW = 1000` blocks of the tip. Peers serving a retained tip are tracked per tip (`mark_known`), and `pending_for` (`stale_tips.rs:237`) hands out which peer should be asked for which branch.

Retained tips are also relayed. `staletip.rs` defines a compact custom message: `STALETIP_COMMAND = "staletip"` (`staletip.rs:3`), 48-byte compressed headers (`staletip.rs:5`), at most `MAX_STALETIP_HEADERS = 20` headers per announcement, and `MAX_ADVERTISED_STALETIPS = 10` tips per peer. A peer that missed a reorg can reconstruct the competing chain from one message (`reconstruct`, `staletip.rs:85`) instead of waiting for discovery. Relay is opt-in per peer (`--p2p-stale-tip-relay`, noted via `note_stale_tip_relay`, `peer_table.rs:509`).

## Eviction

When inbound slots are exhausted, `select_inbound_to_evict` (`crates/p2p/src/eviction.rs:19`) picks the victim with Core-style protection passes, each pass protecting the last k candidates by some criterion:

1. 4 by keyed netgroup diversity (`eviction.rs:23`)
2. 4 by recent transaction relay time (`eviction.rs:24`)
3. 8 by block-relay behavior, restricted to block-relay-only peers with relevant services (`eviction.rs:25`)
4. 4 by recent block service (`eviction.rs:33`)
5. half the remaining candidates, with a quota for local peers (`protect_by_ratio`, `eviction.rs:94`)
6. the newest peer in the largest netgroup evicted (`newest_in_largest_netgroup`, `eviction.rs:113`)

The peer table (`crates/p2p/src/peer_table.rs`) feeds this: `try_register_inbound` (`peer_table.rs:202`) enforces slot limits, and the `note_*` family (`peer_table.rs:555` onward) records the announcement, usefulness, and compact-relay facts the eviction criteria read.

## Historical sync for assumeutxo

After a snapshot load, the node must backfill and fully validate the block range before the snapshot base. `HistoricalDownload` (`crates/p2p/src/sync/historical.rs:17`) runs a second, smaller download window for exactly that: budgets clamp to 32 pending and received blocks, 64 MiB either side, and 16 inflight per peer (`historical.rs:26`). `BlockSync::advance_historical` (`historical.rs:48`) asks `chain.advance_historical()` for the next required height, requests it, and feeds `connect_historical` (declared on `SyncChain`, `crates/p2p/src/sync/chain.rs:67`). A validation error stops the role: `tracing::error!(%error, "historical validation stopped")` (`historical.rs:54`) and the window is cleared; the terminal state never converts into success (clause `SYNC-01` row "AssumeUTXO historical frontier" in `docs/contracts/synchronization.md`). See [how/state-and-storage.md](state-and-storage.md) for the snapshot side.

## Where this is proven

| Invariant | Test | Location |
|---|---|---|
| Presync transitions to redownload on sufficient work | `sufficient_work_chain_syncs_presync_then_redownload` | `crates/p2p/src/sync/tests/headers_presync.rs:465` |
| Low-work chains never reach the block tree | `low_work_headers_do_not_reach_block_tree` | `crates/p2p/src/sync/tests/headers_presync.rs:403` |
| A substituted redownload header disconnects | `a_substituted_redownload_header_disconnects_the_connection` | `crates/p2p/src/sync/tests/headers_presync.rs:577` |
| Continuity break spends the sync state | `a_midbatch_continuity_break_spends_the_sync` | `crates/p2p/src/sync/tests/headers_presync.rs:980` |
| Stale-tip behavior | `crates/p2p/src/sync/tests/stale_tip.rs` and `crates/p2p/src/staletip/tests.rs` |
| Eviction selection | `crates/p2p/src/eviction.rs` `tests` module |

## Limits

- The exact `minimum_chain_work` byte values per network live in `crates/primitives` network parameters; this page does not restate them.
- The `staletip` relay behavior against real Core peers is UNMEASURED; Core does not implement this message, so it only helps bitcoin-rs peers.
- Per-peer EWMA stall recovery is exercised by `crates/p2p/src/sync/tests/pending_retries.rs` and `window_recovery.rs`, not by a live multi-peer run on this page.
