# Staller arming redesign: why BLOCK_STALLING_TIMEOUT has never fired, and what to change

Status: DESIGN (no code). Author: design worker, 2026-06-12.
Scope: `crates/node/src/sync.rs` (R8 staller seam), `crates/node/src/sync/window.rs`
(stall state machine). Re-attempt precondition for the reverted w256 window (U2).

---

## 1. Problem statement

The Core `BLOCK_STALLING_TIMEOUT` port (commit `71db91d`, U7) has fired **zero** times across
every live mainnet IBD run (0→150k, w128 and w256), while the w256 run
(`/home/alpha/bench-g14/results/rs-ibd-u1u2-node.log`) shows exactly the pathology it exists
to kill: a ~65 s frontier crawl at ~1–3 blk/s (735 blk/min for the 16:05 minute, vs ~25,000
blk/min healthy) following peer churn that pulled a slow DNS replacement into the window
front. The episode cost the run +162.8 s (+38%) on a same-hour A/B and forced the w256
revert. The campaign hypothesis was that the "no request capacity" arming term almost never
holds. The diagnosis below shows that hypothesis is **incomplete**: capacity *was* closed for
most of the crawl; the detector armed (or could have armed) but the conviction clock never
reaches its threshold: deliveries reset it between gaps, and at the silent gaps — where it
*did* accumulate past the 2 s base — the threshold itself had been raised by a floor that
tracks the degraded cadence (§2.3).

## 2. Evidence

### 2.1 Code: the predicate and its five gates

The detector convicts only when **all** of the following hold continuously for
`effective_timeout` (≥ 2 s):

| # | Gate | Where |
|---|------|-------|
| G1 | apply side not busy (no-blame guard) | `sync.rs:1063-1065` → `window.rs:471-474` |
| G2 | front pending sits exactly at `next_apply_height`, owned by one peer | `window.rs:580-587` (`window_blocked_on` term 1) |
| G3 | ≥ 1 staged successor above the front | `window.rs:588-594` (term 2) |
| G4 | `!has_request_capacity()` — count/byte/staging clamps all closed | `window.rs:595-597` (term 3) → `window.rs:282-288` |
| G5 | EWMA seeded (cold-start suppression) and episode age ≥ `max(stall_timeout, 2×front_interval_ewma)` | `window.rs:499-506` |

And the episode clock is **reset to zero** by any of:

| # | Clearing rule | Where |
|---|---------------|-------|
| C1 | any gate G1–G4 momentarily false on any tick (`stall = None`) | `window.rs:471-478` |
| C2 | front hash changes (episode keyed `(peer, front_hash)`) — every frontier advance re-keys | `window.rs:479-491` |
| C3 | **any** delivery from the blamed peer (`record_delivery_progress`, the ADV-CASCADE fix) | `window.rs:960-966` |
| C4 | front advance decays `stall_timeout` ×0.85 but raises the floor to 2× the front-cadence EWMA (ADV-DRIP-1 fix) — the threshold *tracks the degraded cadence* | `window.rs:504, 549-556, 994-996` |

Tick ordering (`sync.rs:244-248`): `observe_stall` runs **after** the apply drain and
**before** request issuance. Every tick in which blocks applied therefore observes a window
whose staged slots were just freed — G4 is open at exactly the observation instant whenever
progress occurred that tick, even though requests re-close it microseconds later
(C1 via the flap).

### 2.2 Logs: reconstruction of the 16:04–16:06 crawl (w256 run)

Per-second apply counts from `apply_block: profile` height lines,
`rs-ibd-u1u2-node.log` (157,363 applies, 15:58:30→16:09:07):

- **Churn prelude:** outbound peer 109.192.141.188 died 16:02:29; DNS maintenance dialed
  159.223.52.111 (16:02:31, died 16:03:31), then 3.211.180.220 (died on handshake), then
  **27.125.151.86 connected 16:03:41** — the slow replacement that entered the fan-out set.
- **Ramp-down:** 16:04:47 → 16:04:52: 172 → 103 → 76 → 54 → 37 → 13 blk/s.
- **Crawl floor:** 16:04:52 → 16:05:56: **1–3 blk/s**, heights 130453 → 130621, advancing
  one height at a time. Longest apply gaps ≈ 2–3 s (e.g. 16:05:40 → 16:05:43).
- **Recovery:** 16:05:57 → 16:06:03: 17 → 18 → 26 → 51 → 47 → 43 → 143 blk/s, then back to
  healthy ~120–170 blk/s.
- **Zero stall lines:** `grep -ci stall` = 0 in both run logs. The fire path logs at WARN
  (`sync.rs:1080-1084`) and WARN is enabled (other WARNs present) — the detector genuinely
  never fired. There is **no** episode/arming observability at any log level; the only
  episode surface is the `node.sync.stall_seconds` metrics gauge, which was not scraped.

Two timing correlations matter:

1. **Crawl onset ≈ slow peer's stripe reaching the frontier.** 27.125.151.86 joined 16:03:41;
   the frontier hit its first assigned heights ~65 s later as the healthy peers' staged
   blocks drained — the ramp-down shape (healthy stripes interleaved with slow-peer holes).
2. **Recovery ≈ `PENDING_TIMEOUT` (60 s, `sync.rs:46`) expiry of the slow peer's stripe.**
   Crawl floor began 16:04:52–16:05:00; +60 s = 16:05:52–16:06:00; recovery ramp begins
   16:05:57. The run was un-wedged by the 60 s pending-timeout re-request fallback — the
   exact machinery the 2 s staller detector exists to beat by ~30×.

### 2.3 Window-state reasoning: which gate blocked conviction during the crawl?

During the crawl floor (apply ≈ 1–3 blk/s, healthy peers' download far faster than the
frontier):

- **G2 held**: the frontier advanced one height at a time at ~1 s cadence — each front block
  was in flight to (and eventually delivered by) the slow peer. Apply at 1–3 blk/s with an
  engine measured at ~1,228 blk/s means apply was input-starved at the frontier.
- **G3 held**: healthy peers' deliveries piled up above the front (the recovery burst at
  16:06:03+ of 143 blk/s = staged backlog draining instantly proves a deep staged set).
- **G4 held between applies** — and this is where the campaign hypothesis needs correction.
  With apply crawling and download fast, `received + pending` pins at
  `max_received_blocks` (the U5 count clamp), so capacity is *closed* almost always in the
  saturated crawl. `record_delivery_progress`'s own doc comment concedes this: "In the
  saturated fan-out steady state ('no request capacity' holds almost always)". G4 *does*
  flap open for one observation per applied block (tick ordering, §2.1), adding clearing
  noise at the crawl's 1–3 applies/s — but it is not the primary gate. Where G4 genuinely
  matters is the **ramp phase and shallow-starvation regimes**: the deeper the window, the
  longer staged+pending takes to pin at budget, so w256 widened the no-arm region exactly as
  the U2 verdict recorded.
- **What actually prevented conviction — corrected: C4 alone was binding at the deepest
  gaps; C2/C3 were *not* independently sufficient.** The crawl was not a steady drip: the
  per-second apply counts contain **silent gaps ≥ 2 s** (16:05:02 → 16:05:04, a run of such
  gaps through 16:05:16–16:05:30, and the ~3 s gap 16:05:40 → 16:05:43). During a silent
  gap there are **no deliveries and no front advances**, so C2 and C3 cannot clear — the
  episode clock runs, and episode age reached ~3 s against the 2 s base timeout. What
  prevented a fire at those moments was **only C4**: the front-cadence EWMA, fed by the
  crawl's own 1–2 s inter-front samples (every one of which passes the 50 ms batch filter),
  had been dragged to a conviction floor of roughly 3.4–4 s — the slow peer drags the
  yardstick used to judge it. **C2/C3 with a static 2 s threshold would NOT have protected
  this crawl**: they only outrun the clock *between* gaps, and the first > 2 s silence
  would have convicted.
  - C2: the front advanced every ~0.3–2 s between gaps, re-keying the episode — but
    advances stop exactly when a gap opens, so C2 clears nothing during the silence.
  - C3: each front advance *was* a delivery from the blamed peer, zeroing the clock — same
    limit: no delivery, no clear.
  - C4: the binding rule. Against a hypothetical *steady* drip cadence *g*, episode
    lifetime ≤ *g* while the floor ≥ max(2 s, 2*g*): the threshold is ≥ 2× the maximum
    achievable episode age at every cadence, and a metronomic dripper is unconvictable by
    construction until the 60 s pending timeout. But that steady-cadence model assumes a
    **converged** EWMA; the observed cadence was jittery and the EWMA lags (α = 1/4), so
    the model describes a worst-case regime that was *not* what the log shows. This crawl
    was convictable through its silent gaps; only the captured yardstick saved the peer.

### 2.4 Core comparison (verified against `bitcoin/bitcoin` `net_processing.cpp`)

- Core *arms* per starving peer: `FindNextBlocks` sets `nodeStaller` when an idle peer's
  `vBlocks` is empty **and growing the 1024 window by one block would make it non-empty** —
  "another peer wants work and the window front is why", not "global capacity closed".
- Core *clears* per delivery: `RemoveBlockRequest` sets `state.m_stalling_since = 0us` on
  any block received from the peer — our C3 is a faithful port.
- Therefore the shared-with-Core residual is the **metronomic drip only**: a true 1 blk/s
  dripper resets `m_stalling_since` every second and stays under the 2 s timeout forever.
  Per the corrected §2.3, **this crawl was not metronomic** — at its ≥ 2 s silent gaps a
  static 2 s clock accumulates past threshold, so Core's clearing semantics alone would
  *not* have shielded this crawl (whether Core's different per-starving-peer *arming* would
  have armed here is a separate question). What blocked conviction in our port is the
  rs-local C4 floor (ADV-DRIP-1), not the Core-faithful clearing. The U7 commit's
  slow-trickle disclosure ("slow-tricklers are visible, never disconnected — same exposure
  as Core") stands for the metronomic regime. What changed is the *measured price*: at our
  apply speed and with DNS-churn peer quality variance, a crawl-shaped hit is worth 160+ s
  per run. Convicting the *observed* gap-shaped crawl requires only fixing the rs-local
  floor capture (Phase 2a); closing the *metronomic* residual would require a **deliberate,
  named divergence from Core** (C3 replacement, Phase 2b).

### 2.5 Diagnosis summary

> The staller detector, as shipped, is a fast path for **total-silence wedges only** — a
> strict subset of what the 60 s pending timeout already handles. Every partial-progress
> pathology (the only kind observed live) is structurally invisible — but the clearing
> rules are not equally culpable: per-peer delivery clearing (C3) and front-hash re-keying
> (C2) zero the clock only while deliveries keep arriving, and at the observed ≥ 2 s silent
> gaps it was the cadence-tracking floor (C4) **alone** that blocked conviction, by raising
> the yardstick to the degraded cadence the pathology itself set.
> The "no request capacity" term (G4) is a secondary contributor: it delays arming during
> ramp phases and scales the blind region with window depth (the w256 mechanism), and its
> tick-ordering flap adds clearing noise — but fixing G4 alone would convict nothing,
> because the captured C4 floor still outruns the clock at the gaps, and C2/C3 clear it
> everywhere else.

The crawl **was** window-front stalling (not apply-side, not all-peers-slow): apply was
input-starved with a deep staged backlog, the frontier advanced at one slow peer's delivery
cadence, and recovery coincided with that peer's stripe expiring. Staller arming/conviction
is a real lever for this shape — requirement 5's null result does not apply. Honest sizing
caveat: it is a **tail-risk lever, not a mean-mover** — the clean 8-peer baseline (430 s,
network-saturated, zero crawls) would gain ~nothing; a churn-hit run would have saved up to
~150 s (60 s fallback latency minus ~2–8 s conviction, plus avoided re-dilution).

---

## 3. Design

Four phases (0, 1, 2a, 2b), strictly ordered. Phase 0 is observability and ships first —
§2.3 is reconstruction, not observation, and the riskiest assumption (§5) must be confirmed
live before conviction semantics change on a SYNC-CRITICAL surface. Phase 2 is decomposed:
2a fixes only the yardstick capture that §2.3 shows was binding (Core-faithful), and 2b is
the leaky-bucket Core divergence, contingent on evidence that 2a's residual regime actually
occurs.

**Phase autonomy:**

| Phase | Autonomy | Why |
|-------|----------|-----|
| 0 | Autonomous | Read-only observability; the falsifier for everything downstream. |
| 1 | Autonomous implementation, gated keep | Arming read only, conviction unchanged; keep decision gated on the A/B criteria including the healthy-arming upper bound (F1). |
| 2a | **User sign-off required** | Conviction-semantics change on the sync-critical surface — but Core-faithful: clearing semantics are untouched, and the EWMA floor it snapshots is already the rs-local ADV-DRIP-1 addition. |
| 2b | **Explicit user sign-off required** | Named Core divergence: relaxes the U7 no-blame rule, flips a user-reviewed test pin (`!` commit 71db91d), extends disconnect power on a sync-critical surface. |

### Phase 0 — Episode observability (prerequisite, near-zero risk)

**Mechanism.** (a) Rate-limited INFO log (≤ 1 line/s) whenever a stall episode survives
≥ 1 s: blamed peer, front height/hash, episode age, staged count, pending count, the four
gate booleans, `front_interval_ewma_ms`, `effective_timeout`. (b) Counters
`node.sync.stall_episodes_started` and `node.sync.stall_episodes_cleared{reason}` with
reason ∈ {apply_busy, front_moved, capacity_open, peer_delivery, fired} — instrumenting C1–C3
individually. (c) Log the G4 sub-clause that closed capacity when an episode starts.
(d) Count `episodes_started` during **healthy** minutes (≥ 5,000 blk/min) separately from
degraded minutes — the denominator for Phase 1's healthy-arming upper bound (its keep
criteria below).

**Invariant touched.** None (read-only surfaces). U5/U6/U7 untouched.

**Tests.** Existing R10 suite unchanged; one new test asserting the cleared-reason counter
taxonomy is exhaustive (every clear path tags a reason).

**Live measurement.** One instrumented live IBD run (any hour, no A/B needed — this is
diagnosis, not a perf claim). Decides: do episodes form during crawls (validates §2.3), and
which clearing rule dominates. If episodes never form (G2 fails — frontier blocks expired
and unowned), the design pivots to request-assignment policy instead of conviction, and
Phases 1, 2a, and 2b are abandoned as not-the-lever.

### Phase 1 — Arming that scales with window depth (the w256 re-attempt condition)

**Mechanism.** In `window_blocked_on`, replace term 3 (`!has_request_capacity()`) with a
**staged-backlog fraction**: arm when
`received.len() ≥ max_received_blocks / 2` (integer division; w128 → 64, w256 → 128),
keeping terms 1–2 and the apply-busy guard unchanged. Rationale:

- *Scales with depth by construction* — the arming bar is a fixed fraction of the window,
  so deepening the window no longer widens the blind region (the U2 revert's re-attempt
  condition, `rs-ibd-u1u2-w256-verdict.md`).
- *Flap-immune* — a single apply cannot drop the staged count below half the window, so the
  tick-ordering flap (C1 via G4) stops zeroing episodes during partial progress.
- *Self-discriminating* — staged blocks pile up **only** when the frontier is slow while the
  rest of the window is fast (apply is 50–250× faster than download, so healthy staged
  occupancy is near zero; the solution doc's point 1). Uniform slowness — all peers slow,
  or our apply slow — keeps staged low or trips the apply-busy guard, so this term encodes
  "asymmetric frontier blockage", which is precisely the staller signature. During the
  crawl, staged ≈ 240/256: armed with margin. **Caveat:** "near zero" holds only while the
  frontier never waits. At observed healthy throughput (~170+ blk/s), half-window (64 at
  w128) accumulates in ~400 ms of one peer's RTT jitter — so arming may be *frequent* in
  healthy runs, which is why Phase 0 counts healthy-minute episode starts and the keep
  criteria below carry an explicit healthy-arming upper bound, not just the degraded-arming
  lower bound.

`has_request_capacity` itself, the U5 clamps, and the request paths are not modified — only
the *arming read* changes.

**Invariant touched.** U7 arming predicate (term 3 swap). U5 byte/count clamps: read, not
modified — but note the recorded R+P wedge shapes (pending+staged pinned at budget) satisfy
the new term trivially (staged at budget ≥ half), so wedge conviction is preserved. U6
hysteresis: untouched.

**Tests.** Existing: the two wedge tests in `sync.rs`
(`stalled_front_stripe_wedges_into_request_backpressure_not_evict_churn`,
`wedged_window_expires_stalled_front_and_rerequests_through_count_clamp`) and the R10
collapse-reproduction must still pass (wedges satisfy the new arm). New: (a) parameterized
arming test at w128 and w256 budgets asserting the arm point is the same *fraction* of the
window; (b) below-fraction non-arming test (slow front, 40% staged → no episode); (c) the
uniform-slow zero-disconnect test re-derived: uniform slowness keeps staged < half → never
arms (stronger than today's EWMA-floor argument).
*Delivery note (implementation + adversarial audit):* clause (c)'s premise is wrong for the
existing saturated uniform-slow fixture — it pins staged at the **full** count budget, so
uniform slowness there *does* arm; the fixture keeps its armed-but-never-fires EWMA-floor
pin (the stronger safety property), and the below-half-never-arms direction is pinned
generically by the new fraction tests instead. Audit also added a compile-time
budget-pairing assertion (`RECEIVED_BLOCK_BYTE_BUDGET ≥ RECEIVED_BLOCK_BUDGET/2 ×
MAX_SERIALIZED_BLOCK_SIZE`) so a future depth bump without a byte-budget rebalance fails the
build rather than silently un-arming byte wedges.

**Live measurement.** Same-hour A/B (Phase 1 only vs head), kernel build, AV=150k, fresh
datadirs, stop-hash identity required. Keep iff: (a) no regression ≥ 15 s; (b) Phase 0
counters show episodes now *arming* during any degraded window (episodes_started > 0 with
sub-5,000 blk/min minutes present); **and (c) an explicit upper bound on healthy arming**:
healthy-minute (≥ 5,000 blk/min) episode starts stay rare and short-lived — armed episodes
during healthy minutes must clear via normal progress (front_moved/peer_delivery) without
approaching the conviction floor; a healthy-minute arming rate that puts steady-state
traffic within one EWMA floor of conviction is a revert signal regardless of wall clock.
**Clean-run default:** on a clean A/B pair with no degraded minutes, clause (b) is
unmeasurable — default **keep on** (no regression + tests green), with the arming clause
deferred to the next degraded run. Phase 1 alone is **not** expected to convict the drip
(C2–C4 still clear it) — it is measured on arming, not wall clock.

### Phase 2a — Yardstick snapshot (Core-faithful, lower risk)

**Mechanism.** One change to the episode state machine: fix the EWMA floor's **capture
problem**. The conviction floor (`effective_timeout`'s 2× front-cadence term) reads the
`front_interval_ewma_ms` value **snapshotted when the episode arms**, not the live EWMA —
the pre-pathology cadence judges the pathology, instead of the yardstick the pathology
itself drags up. The live EWMA continues sampling (with the existing 50 ms batch filter and
×0.85 threshold decay) so post-recovery state is unchanged; only the in-episode reads are
frozen. Everything else is retained: **C3's Core-faithful any-delivery full clear stays**,
the episode key stays `(peer, front_hash)` — which holds through a silent gap, because the
front does not move during silence — and doubling-on-fire, the 64 s cap, and the staller
cooldown are unchanged.

**Why this alone likely convicts the observed crawl.** Per the corrected §2.3 analysis, C4's
captured floor was the *only* rule blocking conviction at the crawl's ≥ 2 s silent gaps —
C2 and C3 cannot clear during silence, and the existing key survives it. With the floor
pinned to a pre-episode snapshot instead of the crawl-inflated ~3.4–4 s value, the first
> 2 s silence convicts.

**Divergence status.** Zero divergence from Core's *clearing* semantics. The EWMA floor
itself is already an rs-local addition (the ADV-DRIP-1 fix, not a Core port); 2a only
changes where that rs-local floor reads its input. It is still a conviction-semantics change
on a SYNC-CRITICAL surface and requires user sign-off, but it does not touch the U7
no-blame rule.

**Limitation — the snapshot-at-arm race (B-class risk, must be measured, not assumed).**
The snapshot is taken at episode *arming*, not at pathology *onset*. Arming requires
staged ≥ half-window to build; meanwhile the live EWMA — α = 1/4, moving most of the way to
a new level in ~5 samples, and never batch-filtering the crawl's 1–3 s gaps — is already
eating crawl samples. Two regimes:

- **Sharp onset** (the observed shape): healthy peers fill staged in ~1 s, so the race is
  probably won — the snapshot still reflects near-healthy cadence.
- **Gradual peer degradation**: the EWMA tracks down *with* the peer, so by arm time
  snapshot grace ≈ observed gap, accrual ≈ 0 — **drip immunity reappears**. 2a does not
  close this regime; it narrows the residual to it.

Phase 0's logged `front_interval_ewma_ms` at episode start is the named **falsifier**: the
keep/revert criteria below must check the snapshot value at arm time against the pre-crawl
cadence. The worked figure "convicts within a few blocks" anywhere in this design is
**best-case** (sharp onset, race won); and the "~100–300 ms healthy grace" figure is
**asserted, not measured** — the 50 ms batch filter biases the healthy EWMA toward its
slowest passing samples, so the true healthy floor may sit higher.

**Invariant touched.** U7 clearing semantics: untouched (any delivery still fully clears).
Cold-start suppression preserved (`front_interval_ewma_ms?` — no seeded EWMA ⇒ no snapshot ⇒
conviction suppressed, 60 s fallback owns the regime). U5/U6: untouched.

**Tests.** Existing R10 suite (26 tests) passes **unmodified**, including the slow-trickle
pin: a metronomic trickler still clears via C3 on every delivery, so 2a does not convict it
and the pinned residual stands. New: (a) snapshot isolation — in-episode EWMA pollution does
not raise the in-episode floor; (b) sharp-onset fixture asserting the arm-time snapshot ≈
pre-episode cadence; (c) gradual-degradation fixture *documenting* the non-conviction
residual (snapshot ≈ gap ⇒ no fire) — pinning the known limitation, not hiding it;
(d) silent-gap conviction — a > snapshot-floor silence with the front unmoved fires.

**Live measurement (keep/revert decision).** Same-hour A/B pairs (Phase 0+1+2a vs head),
kernel build, AV=150k, fresh datadir, stop-hash identity, ≥ 15 s attribution threshold:

- **Keep** iff: (a) no clean-run regression beyond noise (< 15 s vs paired control);
  (b) on any run exhibiting a degraded window (≥ 30 s below 5,000 blk/min), the instrumented
  build convicts within ≤ 8 s of crawl onset (2 s base + ≤ 2 doublings), the post-fire
  recovery matches the re-queue path (Phase 0 log shows fired + refill), **and the logged
  snapshot at arm time is at most ~2× the pre-crawl cadence** — a crawl-inflated snapshot
  falsifies 2a's premise (the race analysis above governs) even if a fire occurs;
  (c) cascade guard: `staller_disconnects ≤ 4` per run (the doubling ladder bound) — more is
  a cascade signal and an automatic revert.
- Because churn-induced crawls are stochastic, run paired A/Bs until either side exhibits a
  crawl (the u1u2 run shows DNS churn produces one within ~6 min when it occurs at all);
  budget cap 4 pairs before declaring the conviction clause unmeasured and keeping on
  clauses (a)+(c) only, with the tail-risk claim downgraded to test-pinned.
- **Measurement-power caveat.** Clause (b) requires the crawl to land on the **treated**
  side, but the stopping rule counts a crawl on *either* side — so the expected information
  per A/B pair about conviction is lower than the pair count suggests. The 4-pair cap and
  the downgrade-to-test-pinned path stand, but a "kept on (a)+(c)" outcome must **not** be
  read as validation of conviction behavior — it validates only non-regression and
  cascade-safety.

### Phase 2b — Leaky-bucket conviction (the named Core divergence, contingent)

**When this is needed — and when it is not.** 2b targets exactly one adversary: a
**metronomic dripper** that delivers steadily and never opens a gap longer than the
(snapshot-fixed) threshold, so C3 clears the clock on every delivery forever. That regime
has **not been observed in any live run** — the observed crawl had ≥ 2 s silent gaps, which
Phase 2a convicts. **Escalate to 2b only if Phase 0 / Phase 2a data shows a steady
sub-threshold drip actually occurring** (episodes repeatedly cleared by `peer_delivery` at
near-threshold cadence with no conviction). 2b requires **explicit user sign-off**: it
relaxes the U7 no-blame rule, flips a user-reviewed test pin (`!` commit 71db91d), and
extends disconnect power on a sync-critical surface.

**Mechanism.** Two coupled changes on top of 2a's snapshot:

1. **Peer-keyed episode (kills C2).** Key the episode on `peer_addr` alone; it survives a
   front advance when the *new* front pending is owned by the same peer. `front_hash` is
   retained in the episode for observability only. The episode still clears when the front
   moves to a different peer's pending, when arming drops (Phase 1 term), or on apply-busy.
2. **Leaky-bucket delivery credit (replaces C3's full clear).** On each delivery from the
   blamed peer, instead of `stall = None`, advance `episode.since` by
   `credit = min(now − episode.since, grace)`. A peer delivering at or faster than `grace`
   accrues nothing (bucket floors at zero, episode effectively idles); a peer delivering at
   cadence *g* > `grace` accrues `g − grace` of blame per block and convicts after
   `effective_timeout / (g − grace)` deliveries. **Best-case** worked example: a 1 blk/s
   drip against a ~100–300 ms healthy grace convicts in ~3 blocks (~3 s), inside the
   Core-shaped 2 s-doubling regime — best-case because the grace figure is asserted, not
   measured (see 2a's limitation), and because the snapshot-at-arm race applies here too:
   under gradual degradation grace ≈ *g* and accrual ≈ 0. Deliveries from *other* peers
   still never clear (unchanged discriminator).

This is a **named divergence from Core** (`RemoveBlockRequest` fully clears
`m_stalling_since`; we credit instead of clear) and must be flagged for user review like
71db91d was — it extends sync's disconnect power from "silent front owner" to "front owner
demonstrably slower than the pre-episode network cadence".

**Invariant touched.** U7 no-blame rule — relaxed from "any delivery clears" to "deliveries
credit at the demonstrated pre-episode cadence; sustained shortfall convicts". The apply-busy
guard, cold-start suppression (`front_interval_ewma_ms?` — no snapshot possible without a
seeded EWMA, so cold start still defers to the 60 s fallback), cooldown, and doubling are
preserved. U5/U6: untouched.

**The four U7 audit vectors, by name:**

- **Self-eclipse cascade** (serially false-blaming slow-but-streaming peers in saturated
  steady state): defended twice over. (a) Phase 1 arming requires staged ≥ half-window,
  which a *symmetric* saturated steady state never produces (apply outruns download; staged
  stays near zero) — the cascade's precondition no longer arms. (b) Even when armed, a front
  owner delivering at ≈ the snapshot cadence accrues ≈ 0 (credit ≈ actual gap), so rotating
  front ownership among comparable peers accumulates jitter, not blame; the doubling-on-fire
  ladder still bounds any residual to log₂(64/2) = 5 fires before the 64 s ceiling.
- **Drip-feed immunity** (steady sub-threshold cadence, never convicted): this is the vector
  2b exists to close — the leaky bucket converts the drip's per-block shortfall into
  monotone blame. The bucket's actual target is a **steady sub-threshold cadence**: e.g. one
  block every ~1.5 s against a 2 s threshold never lets the clock reach 2 s under full-clear
  C3, but accrues ~1.2–1.4 s of blame per block under the bucket and convicts within a few
  blocks. (A coarse *batch* drip — say 16 blocks per 60 s — is **not** this vector: its 60 s
  silent gap blows through the 2 s base long before the batch arrives, so it already
  convicts today unless the threshold has doubled all the way to the 64 s cap.)
- **Batch-deflation false positives** (chunk-shared timestamps deflating the EWMA into a
  hair-trigger floor): the snapshot inherits the live EWMA's 50 ms batch filter, and credits
  are granted per delivery with `credit ≤ now − since` (never negative blame, never
  over-credit from one chunk); a same-chunk burst from the blamed peer grants up to
  n×grace credit — generous to the peer, biasing toward non-conviction, the safe direction.
- **Cold-start false positives**: unchanged gate — no EWMA sample ⇒ no snapshot ⇒ conviction
  suppressed, episode observable only, 60 s fallback owns the regime (`window.rs:493-499`
  logic retained verbatim).

**Tests.** Existing R10 suite (26 tests): all pass except the slow-trickle pin, which
asserts the *old* residual ("visible, never disconnected") and is **deliberately flipped**
into a drip-conviction test (1 blk/s vs 100 ms snapshot → fires within ~3 s, blamed peer
correct) — this flip is part of the user sign-off gate. The uniform-slow zero-disconnect,
limit-cycle floor stop, cold-start deferral, no-blame, collapse-reproduction, sole-peer
liveness, and lease-race tests must pass unmodified in semantics. New: (a) peer-keyed
episode survives same-peer front advance; (b) credit-at-cadence accrues zero for a
snapshot-speed peer; (c) batch-credit cap; (d) episode hand-off when the front moves to a
different peer's pending mid-episode clears cleanly; (e) mutation tests on the credit
arithmetic (the U7 commit's mutation-verified standard). 2a's snapshot tests carry over.

**Live measurement.** Same protocol and keep/revert clauses as Phase 2a (including the
arm-time snapshot check and the measurement-power caveat), with one addition: the degraded
window in clause (b) must include the steady sub-threshold drip regime that justified
escalation — a 2b kept only on gap-shaped crawls has not demonstrated the divergence's
value and should be re-evaluated against staying at 2a.

### Explicitly out of scope

- Request-assignment changes (e.g. refusing new stripes to peers with high front-ownership
  blame) — a smaller-window-of-blast alternative, but it adds a second policy surface;
  conviction + the existing cooldown already prevents re-acquisition. Revisit only if
  Phase 2a's A/B shows conviction firing correctly but recovery still slow.
- Window deepening itself (w256 re-attempt) — gated behind Phase 1+2a landing and a fresh
  same-hour A/B, per the U2 verdict.
- Inbound/last-resort staller exposure and relay-attributed shielding — disclosed U7
  residuals, bounded by the 60 s fallback, unchanged here.

---

## 4. Recommendation

Ship Phase 0 alone first and re-run live (one run, no A/B). If it confirms episodes form,
are cleared by `peer_delivery`/`front_moved` between gaps, and the in-episode floor sits
crawl-inflated at the silent gaps (the corrected §2.3 prediction: C4 binding), ship Phase 1
and Phase 2a together behind the standard A/B protocol — Phase 1 without 2a convicts the
gap-shaped crawl only via the captured floor (i.e. not at all), and 2a without Phase 1
inherits the flap and the depth-blind arming. **Phase 2b is contingent, not default**: hold
it back unless Phase 0/2a data shows a steady sub-threshold drip that never opens a
> threshold gap, and take it through explicit user sign-off as a named Core divergence. If
Phase 0 instead shows G2 failing (frontier unowned during crawls), stop: conviction is not
the lever, and the next design is request-path (expiry/reassignment cadence), not blame.

## 5. Riskiest assumption

That during live crawls the frontier block is **continuously pending to the slow peer**
(G2 holds), i.e. episodes actually form and only the clearing rules kill them. §2.3 infers
this from apply cadence, backlog shape, and the 60 s-expiry recovery correlation — but no
log line observed window state directly (zero stall/window lines at INFO; the
`stall_seconds` gauge was unscraped). If instead the frontier spends the crawl expired and
unowned, or bouncing between owners, neither 2a's snapshot-judged episode nor 2b's
peer-keyed leaky bucket ever accumulates, and Phases 1–2a–2b are dead weight on a
SYNC-CRITICAL surface. Phase 0 exists to retire exactly this risk before any conviction
semantics change.

Secondary risks: (a) the snapshot yardstick judges a peer against a cadence set by *other*
peers' burst deliveries — a legitimately slower-but-honest front owner in an armed window
accrues blame by design; the mitigations are the staged-fraction arming precondition
(asymmetry required), the doubling ladder, and the cooldown's bounded blast radius (one
64 s exclusion, reconnectable). (b) The snapshot-at-arm race (Phase 2a's stated limitation):
under gradual peer degradation the snapshot itself is crawl-contaminated and drip immunity
reappears — Phase 0's arm-time `front_interval_ewma_ms` log is the falsifier. (c) The
flipped slow-trickle test (Phase 2b only) changes a previously user-reviewed behavior
(`!` commit 71db91d) — requires the same review gate, which is why 2b carries its own
explicit sign-off.

## 6. Source index

- Predicate/conviction: `crates/node/src/sync/window.rs:462-599` (`observe_stall`,
  `stall_decay_floor`, `window_blocked_on`), `:282-288` (`has_request_capacity`),
  `:953-998` (`record_delivery_progress`, EWMA, ×0.85 decay).
- Seam + tick order: `crates/node/src/sync.rs:235-284` (tick), `:1019-1085`
  (`disconnect_window_staller`), constants `:46` (60 s), `:92-110` (2 s/64 s/cooldown).
- History: commit `71db91d` (U7, four audit rounds: cascade/drip/deflation/cold-start);
  `docs/solutions/architecture-patterns/multi-peer-block-download-requires-core-stalling-disconnect.md`.
- Live evidence: `/home/alpha/bench-g14/results/rs-ibd-u1u2-node.log` (crawl),
  `rs-ibd-u1only-node.log` (clean control), `rs-ibd-u1u2-w256-verdict.md` (U2 revert).
- Core ground truth (verified via GitHub source, `net_processing.cpp`): `m_stalling_since`
  cleared in `RemoveBlockRequest` on any delivery; `nodeStaller` set when an idle peer's
  fetch list is empty and window+1 would be non-empty.
