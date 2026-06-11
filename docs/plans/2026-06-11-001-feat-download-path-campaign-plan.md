# PLAN: Download-path campaign + project closeout (2026-06-11) — ACTIVE DELIVERABLE

> On approval this section materializes to `docs/plans/2026-06-11-001-feat-download-path-campaign-plan.md`
> (ce-plan artifact). Everything above this line is the session's historical ledger.

## Context

The kernel + multi-peer plan (docs/plans/2026-06-10-001, completed at 70666c5) exhausted its scope with
this ledger: live vs Core **MET** (369.5s kernel full-validation < 628s, fuller posture), live vs gocoin
**UNMET** (359.5s matched-assumption vs ~277s), processing-bound vs Core UNMET (225.2s vs 67s),
compactness MET (portable 8.9MB / 739MB datadir). The decisive diagnosis: script-skip 359.5s ≈
full-validation 369.5s, and apply totals only ~103.3s of wall — **script CPU is no longer binding; the ~256s of
non-apply wall is the remaining lever for the gocoin clause** — but the diagnosis workflow (recovered
below, see "Diagnosis recovery") proved that 256s is of **disputed composition** (download-bound vs
apply-gated window stall) and that **every live number cited in this plan is peer-death-contaminated**:
5–6 of 8 outbound peers died in every measured run and fan-out never engaged. The lever cannot be sized,
and no download candidate ranked, until U1 yields a clean 8-peer baseline. Beating 277s means cutting
~80–100s out of that residual by a mechanism U3 must first *identify on trustworthy numbers* — not a
download tweak picked in advance (the obvious ones were tried and refuted; see Diagnosis recovery).

Two-profile framing (user-ratified): kernel profile carries the speed story; portable profile carries
the compactness story. The goal-checker hook reads the goal conjunctively — the gocoin clause is what
this campaign exists to close.

**Live-demonstrated finding that anchors U1:** in the tainted w256 run, 5 of 8 outbound peers died in
minutes and were never replaced — fan-out (needs 8 eligible) never engaged; the node synced on 3 peers.
Recon confirms: DNS bootstrap is a one-shot thread that exits (`crates/node/src/run.rs:249-274`); the
code itself documents "no autonomous peer rotation" (`crates/node/src/sync.rs:1066-1071`); `addr`/
`addrv2` are decoded but ignored (`crates/p2p/src/dispatch.rs:90`); `MIN_PEERS_FOR_FANOUT`'s own doc
pins 8 = the full outbound budget, "leaving zero slack" — any single peer death permanently kills
fan-out. Meanwhile `--connect` mode already has a 2s refill loop (`spawn_fixed_peer_bootstrap`,
`run.rs:336-368`) — the template to generalize.

## Hard constraints (unchanged, all inherited)

- U5/U6/U7 invariants are load-bearing (prior campaign units, docs/plans/2026-06-10-001): byte+count staging clamps (the count clamp is what prevents the
  recorded 5608279 collapse), staller no-blame rule, EWMA-adaptive floor, fan-out hysteresis, 64s
  staller cooldown. Every unit names which it touches; the shipped U5–U7 tests re-run per unit.
- Measurement discipline: binary identity verified before every run (`strings -a | rg bitcoinkernel`
  + mtime — the cargo wrapper swaps cached binaries in 0.2s); fresh datadir; stop-hash byte-identity
  at 150,000 (`0000…2884b`); node-log precise elapsed; keep-on-improvement / revert otherwise.
- Repo gates: fmt, clippy `-p bitcoin-rs` with full portable features `-D warnings`, workspace tests,
  node tests at portable AND kernel feature sets. Conventional commits, `Op:` trailers, no agent
  identity trailers. Sync-critical commits flagged for user review.
- Standing comparison numbers (do not re-derive): kernel full 369.5s, kernel assume-valid 359.5s,
  portable 810.1/801.5s, gocoin ~277s, Core 628s. Target: < 277s, kernel profile, matched assumptions.

## Implementation Units

### U1. Outbound peer-refill (DNS-mode connection maintenance) — CRITICAL PATH
**Goal:** the node maintains 8 outbound peers continuously; a died/disconnected slot is refilled within
seconds, so fan-out eligibility survives peer churn for the whole IBD.
**Files:** `crates/node/src/run.rs` (core: replace one-shot `spawn_dns_seed_bootstrap` with a
maintenance loop modeled on `spawn_fixed_peer_bootstrap` run.rs:336-368; all handles —
`p2p_outbound_sender`, `peers`, `peer_outbound`, `shutdown` — already at the run.rs:479-483 call site);
`crates/node/src/state.rs:68` (`P2P_OUTBOUND_QUEUE_LIMIT`); `crates/p2p/src/peer.rs:131-189`
(`SystemDnsResolver` reuse). Tests: `crates/node/tests/` or in-module — loop logic must be testable
without live DNS (inject resolver).
**Approach:** every ~5s while not shut down: count live outbound entries (`peer_outbound` map); if
below target 8, draw addrs (re-resolve DNS seeds; shuffle; skip addrs in `outbound_addr_available`
dedup run.rs:164-177) and `try_send` the deficit into the dial channel (bounded 8, state.rs:820 —
sized-to-deficit sends, full-channel tolerated). Add failed-addr backoff bookkeeping (never hammer a
dead addr; prefer fresh addrs over just-stalled ones — staller cooldown at sync.rs:123-130 already
makes re-dialed stallers fan-out-ineligible for 64s, which is the desired interaction). No new
addr-book; `getaddr`/addrv2 ingestion is explicitly deferred (see Deferred).
**Invariants touched:** none of U5–U7 directly; fan-out re-engages automatically via hysteresis
(`window.rs:234-239`) once eligible count returns to 8 — no sync.rs changes needed.
**Test scenarios:** (a) 3 live entries → exactly 5 dials queued, dedup respected; (b) failed addr
enters backoff, not re-queued within window; (c) full dial channel → no panic, retry next tick;
(d) shutdown flag stops the loop; (e) `--connect` mode unaffected (existing loop untouched or
behavior-identical if generalized); (f) regtest/dns-disabled → loop never spawns.
**Verification:** unit tests green at both feature sets; live smoke: kill 3 peers mid-run (or observe
natural churn), log shows refill dials within ~10s and fan-out re-engagement. Then U8-style live run.
**Commit:** `feat(node): continuous outbound peer maintenance under DNS bootstrap` — `Op: extend`,
flagged sync-critical.

### U2. Window-256 disposition (gated keep/revert of the uncommitted diff)
**Goal:** decide PENDING_BUDGET 128→256 on evidence: a clean 8-peer live run, which U1 makes
reproducible. **Depends: U1.**
**State:** diff uncommitted in `crates/node/src/sync.rs` + `sync/stage.rs` (+window tests); all 5 local
gates green; first live attempt TAINTED (3-peer; marker at ~/bench-g14/results/rs-ibd-w256-node.log).
**Diff-audit verdict (recovered from wf_c9c0ca59-d3c, see "Diagnosis recovery"): PASS — no BLOCKERs.**
The adversarial lens found the diff sound but flagged two must-fix items and one watch-item:
- **MF1 — pin the two-wave behavior with a test.** The headline "wave N+1 is requested while wave N still
  stages" is asserted by *no* test; the source comment "No runtime test can observe both waves in a
  single tick" (~sync.rs:109-110) is refutable, and the new `const _: () = assert!(PENDING_BUDGET ==
  2 * MIN_PEERS_FOR_FANOUT * MAX_BLOCKS_IN_TRANSIT_PER_PEER)` only *approximates* the relationship. Add a
  two-tick pipelining test that observes wave N+1 issuing before wave N drains.
- **MF2 — disclose the real RSS envelope.** Doubling the staging byte budget to 512 MiB counts
  *serialized* bytes, but each staged entry also holds the decoded block, so steady RSS is ~1.0–1.1 GiB
  and the adversarial transient is ~2 GiB — roughly 2× the single-wave envelope. State this in the
  commit body; it is not a blocker, it is undisclosed cost.
- **Watch-item (not blocking) — stall-arming weakens slightly.** The staller predicate's term 3 ("no
  request capacity") closes less often with a doubled window, enlarging the blind region to <256
  successors. But 0 stall episodes ever formed across 89.4 MB of live logs, the 60s pending timeout
  still covers it, and the 7 updated tests confirmed the re-pinned clamp/fallback properties hold.
**Approach:** (1) land MF1 (two-tick test) + MF2 (RSS disclosure in commit body); (2) kernel build,
binary-identity check, fresh datadir, live run **on the U1 8-peer baseline** (a sub-8 run cannot decide
this diff — the first attempt was TAINTED at 3 peers); (3) decision rule: elapsed < 359.5s AND stop-hash
identical AND no collapse/eviction churn → commit (`feat(node): two-wave download window` `Op: extend`,
sync-critical); else → revert (stash with verdict note) and record the negative result in the verdict file.
**Invariants touched:** count clamp semantics (staged+pending ≤ 256 now), staller "no request capacity"
predicate frequency (the watch-item above), RSS envelope (~2 GiB transient, disclosed per MF2).

### U3. Clean-baseline re-measurement + regime fork — REPLACES the pre-filled candidate slots
The diagnosis workflow (wf_c9c0ca59-d3c) already ran; its output was **negative and decisive** (see
"Diagnosis recovery"): 10 findings confirmed, the entire download-tweak candidate pool **refuted on
code+log evidence**, and the meta-finding that every live number is peer-death-contaminated. So U3 is
**not** "fill three ranked candidate slots" — there is no surviving candidate to rank. U3 is the
de-confounding re-measurement that U1 unblocks:
1. On the U1 continuous-8-peer baseline: clean kernel-AV IBD 0→150k (binary-identity checked, fresh
   datadir, stop-hash verified).
2. Read peer saturation and the apply-vs-fetch split from the node log (the same `apply_block` profile
   lines + handshake/hangup counts the recovery used).
3. **Fork on what the clean numbers show:**
   - **Network-saturated** (8 peers busy, fetch is the wall): download *is* the lever — but the obvious
     imports are already refuted (below), so any new candidate needs a *measured* ≥15s attribution
     before it earns a unit.
   - **Apply-floored** (peers idle, window drains faster than apply commits): the lever is parallel
     apply = the **processing-bound** campaign, explicitly out of scope here (separate lever class) —
     record the finding and stop the gocoin campaign honestly at its measured floor.
**Ruled out with evidence (do NOT re-propose without new measurement overturning the cited proof):**
- **Scheduler / request-latency tweaks** — rs already issues a getdata per arrival; the per-arrival
  `sync_wake` path exists (`event_loop.rs:28`, `listener.rs:37,52`) and the 5s `SYNC_TICK` is a fallback
  heartbeat, not the request cadence. Refuted.
- **gocoin imports** (compact blocks, deeper pipeline) — gocoin uses **no** compact blocks in bulk
  download and caps in-flight at `MaxBlockAtOnce=3` (`client/network/data.go`, `common/config.go:173`) —
  *shallower* than rs, not deeper. Refuted.
- **Storage / persist / decode off-profile costs** — 7 persist-lens findings confirmed these are ruled
  out (persist ~10s of wall; compaction + listener-thread decode off the critical path). Refuted as levers.
Any candidate that survives the U3 fork must carry: mechanism, expected gain from *verified* numbers,
invariants touched, U5–U7 test impact, and the live measurement that decides keep/revert. **Any expected
gain < ~15s is rejected at planning time** (run cost ~6 min + ~1% variance ≈ 4s ⇒ smaller deltas are
unmeasurable in single samples).

### U6. Debt: crash_recovery tests redb-hardcoded
`cargo test -p bitcoin-rs-node` fails at default features (2 integration tests hardcode redb).
Parameterize over available backends or gate behind the feature. `Op: correct`,
`Restores: test:crash_recovery default-features green`. Independent, parallel-safe.

### U7. Debt: kernel-only CI job dedup
The standalone kernel-only job is subsumed by kernel-node step 1 (fd2f315). Remove the redundant job.
`Op: compress` (CI surface shrinks, coverage identical). Independent.

### U8. Debt: node clippy test-target lints
21 pre-existing test-target lints in node (`stage.rs`/`apply.rs`/`state.rs`) invisible to the
documented CI command. Fix lints; decide whether CI gains `-p bitcoin-rs-node --all-targets` coverage
(small CI addition, surfaces the class). `Op: correct`. Independent.

## Diagnosis recovery (wf_c9c0ca59-d3c)

The download-path diagnosis workflow (5 lenses → adversarial verify → synthesize) **partially failed on
infrastructure**: the `synthesize` agent died on a 402 (billing) and one `verify:diff-audit` verdict was
usage-policy-blocked. The synthesis was **hand-recovered at zero agent spend** from the cached
`StructuredOutput` tool-call inputs in the per-agent `agent-*.jsonl` transcripts. Journal tally:
**10 confirmed, 20 refuted** findings. What survived:
- **Confirmed (10):** 7 persist-lens findings ruling **out** storage/persist/decode/compaction as levers
  (persist ~10s of wall; compaction + listener-thread decode off the critical path), plus 3 diff-audit
  corrections (two-wave behavior untested → MF1; honest RSS ~1.0–1.1 GiB steady / ~2 GiB transient →
  MF2; the 7 updated tests still catch the stripe-cap and fallback-deep-window under-fill regressions).
- **Refuted (the entire download-tweak pool):** all scheduler/request-latency findings (rs already
  issues per-arrival getdata — `event_loop.rs:28`, `listener.rs:37,52`; the 5s tick is fallback only);
  all gocoin-import findings (no compact blocks in bulk download, in-flight capped at 3 —
  `common/config.go:173`); and the log-forensics "8 peers available" premise (false — see meta-finding).
- **Decisive meta-finding:** the kernel-AV live log (`rs-ibd-u8k-node.log`) shows exactly 8 outbound
  handshakes, 3 hangups at t+2s/t+60s, no refill, ~5 live peers, 0 stall episodes — **358.9s loses to
  gocoin's 276.3s by 82.5s on a degraded peer set.** Every live number in this plan is therefore
  peer-death-contaminated, which is *why* U1 is both the lever and the de-confounder, and why U3 is a
  re-measurement rather than a candidate list.

**Do not spawn a new diagnosis workflow** until billing is restored AND a clean U1 8-peer baseline
exists — a fresh diagnosis on contaminated numbers would refute itself the same way. Confirm with the
user before any new billing-consuming workflow spend (the 402 is unresolved).

## Decision gates (user-owned — the plan surfaces, never executes)

- **G1 push:** 10 local commits e58d514..70666c5 are unpushed; campaign commits will stack on them.
- **G2 `!`-commit review:** fb2227e (kernel dispatch) and 71db91d (staller detection) per plan R13.
- **G3 OQ2:** kernel-as-default / retire bitcoinconsensus — the live results (2.2× build-attributable
  speedup, parity gates green) strengthen the case; decision changes default-feature wiring + CI.
- **G4 campaign budget:** each live validation run ≈ 6 min + setup; U2 + 2–3 candidate units ≈
  5–8 live runs total.

## Sequencing

U1 (refill — unblocks everything) → clean 8-peer kernel-AV baseline run, which U3 reads to fork the
regime → U2 (w256 A/B decided on that same clean baseline, gated by its own rule) → only a candidate
that *survives the U3 fork with a measured ≥15s attribution* earns a unit, one at a time, each
keep/revert-gated by its own live run. U6/U7/U8 interleave anytime (no sync surface). Decision gates
G1–G3 can fire whenever the user engages; nothing in the campaign blocks on them except G3 if
kernel-as-default lands mid-campaign (then measurement profile notes update).

## Exit criteria

- **Success:** kernel-profile matched-assumption live IBD 0→150k < 277s, stop-hash identical,
  no invariant regression — gocoin clause MET; goal ledger fully green except processing-bound
  (explicitly out of scope here; separate campaign if ever).
- **Honest failure:** candidates exhausted with verified diagnosis showing the residual gap is
  structural (e.g. peer-quality variance Core/gocoin also eat); record in verdict file with the
  measured floor.

## Deferred (explicitly out of scope)

- `getaddr`/`addrv2` ingestion + persistent addr-book (refill re-resolves DNS seeds instead — smaller,
  sufficient for IBD; addr-book is a follow-up if peer quality becomes the binding constraint).
- Processing-bound vs Core (225.2s vs 67s) — separate campaign, separate lever class.
- Chain reorganization feature decision (pre-existing, documented, user-owned).
