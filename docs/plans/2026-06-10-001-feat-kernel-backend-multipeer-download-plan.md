---
title: Kernel-backed script verification and Core-faithful multi-peer download
type: feat
status: active
date: 2026-06-10
---

# Kernel-backed script verification and Core-faithful multi-peer download

## Summary

Two sequenced campaigns to close the measured speed gap to Bitcoin Core and gocoin while keeping
the node compact. Campaign A swaps the apply path's script-validation backend from
`bitcoinconsensus` to `bitcoinkernel` in a feature-exclusive build, attacking the processing-bound
gap (rs 296.2 s vs Core 67 s on the 0→150k full-validation replay). Campaign B ports Core's
multi-peer block-download mechanism, attacking the live-IBD gap (rs 5,332 s vs Core 628 s vs
gocoin ~277 s on live 0→150k). Kernel first; campaigns are sequenced, not interleaved. Campaign A
opens with a zero-integration spike (U0) that can kill the campaign before any surgery.

---

## Problem Frame

The standing goal: **faster than the official C++ node or gocoin, while maintaining
compactness** (disjunctive — beating either competitor in a regime satisfies that regime's speed
clause; see Open Questions for the framing decision the user owns). Compactness is met (8.9 MB
binary, 606 MB datadir vs Core 18 MB / 1.0 GB and gocoin 16 MB / 3.3 GB). Speed fails in both
regimes at height ≤ 150k:

- **Processing-bound** (local corpus, full script verification, zero network): rs 296.2 s vs
  Core `-reindex-chainstate -assumevalid=0` 67 s. Root cause is pinned: libbitcoinconsensus's
  public API re-parses the serialized transaction into a `CTransaction` on **every per-input**
  `verify_with_flags` call. The rs caller is already clean (one cached serialization per tx,
  `crates/consensus/src/verify_tx.rs:296`); the waste is inside the C boundary, unreachable from
  Rust. Scheduling cannot fix it: per-tx rayon fan-out measured net-negative (RAYON=1 beat 128
  threads on the parallel path), and pre-resolving prevouts regressed the replay 296.2 → 353.9 s.
- **Live IBD**: single-peer block download is the bottleneck (apply is 50–250× faster than
  download). The prior naive multi-peer attempt (commit `5608279`) collapsed live and was
  reverted; the failure mechanism is documented in
  `docs/solutions/architecture-patterns/multi-peer-block-download-requires-core-stalling-disconnect.md`.

**How the campaigns compose against the goal.** Campaign A moves the live-IBD number by
approximately zero (apply is off the single-peer critical path). Campaign B is the only lever
for the regime where rs loses 8.5–19× — and the nearest satisfiable reading of the goal is
beating Core's live 628 s. But the coupling runs forward: if Campaign B reaches Core-class
download throughput, the portable build's ~296 s of apply CPU becomes co-binding, and the kernel
apply path is what keeps download — not validation — the constraint. Campaign A is therefore a
prerequisite for Campaign B's win being realizable, which is the substantive argument for the
kernel-first sequencing (user-confirmed), beyond its lower risk profile.

Baseline decomposition for the current best replay (296.2 s elapsed, artifact
`rs-replay-150k-parverify.json`): script-verify stage sums 200.7 s (serial-overlay path 105.0 s
over 23,883 blocks + parallel path 95.7 s over 44,008), leaving a non-script floor of ~95.5 s
(residual fetch stall ~33 s, persist/commit/decode/micro-stages the rest). Measurement
artifacts: `~/bench-g14/results/`; harness `crates/node/examples/mainnet_prefix_replay.rs`
(REST block source, stop-hash assertion, stage decomposition).

---

## Alternatives Considered (researched, closed)

**Rust-native consensus-grade script interpreter: none exists as of mid-2026.** A five-family
ultraresearch sweep (June 2026) returned four dead-ends and one strong candidate that is itself
the kernel route:

- **Floresta's validation component** — contains no Rust interpreter; it uses rust-bitcoinkernel
  (after migrating off rust-bitcoinconsensus), and its default build skips script validation
  entirely. The most serious independent Rust node is revealed-preference evidence *for* the
  kernel route.
- **rust-bitcoin ecosystem** — the `bitcoin` crate has no execution engine and affirmatively
  disclaims consensus use; `miniscript::interpreter` covers only descriptor-representable spends.
- **BitVM/rust-bitcoin-scriptexec** — explicit all-caps anti-consensus disclaimer,
  `OP_CHECKMULTISIG` is `unimplemented!()` (fatal for the 0→150k window), no VerifyScript
  pipeline, no flag model, v0.0.0 never published.
- **parity-bitcoin `script` crate** — frozen at ~Core v0.15 (2017), zero taproot, abandoned
  secp bindings, and GPL-3.0 (hard license blocker for this MIT/Apache-2.0 workspace).

Any future Rust-native attempt carries a permanent validation bar: full Core vector conformance,
continuous differential fuzzing vs the kernel, full mainnet replay parity per release, and
per-soft-fork re-proof. Nobody (Floresta included) has paid that cost; this plan does not either.
The in-repo Rust interpreter (`crates/script`) stays what it is: a taproot-only parallel
differential path, never the production backend.

**Full-block kernel backend (`ChainstateManager::process_block`): rejected for this plan.**
The kernel owns its chainstate — it opens and exclusively locks its own LevelDB at `data_dir`,
accepts no caller-supplied UTXOs (upstream PR #32317 closed unmerged, April 2026), and signals
tip activation asynchronously via callbacks from kernel-internal threads. Adopting it would
duplicate storage (kernel LevelDB beside the KvStore UTXO set), invert authority over the
storage-equivalence gate, conflict with the crossbeam event loop, and surrender the compactness
story. Script-level `verify()` granularity avoids all of it. If U0/U2's measurements show
script-level verification cannot close the gap, this decision is the named re-entry point.

**Kernel as the only engine (retire bitcoinconsensus): not in this plan, but the named
end-state question.** libbitcoinconsensus is deprecated upstream and was removed in Core v28;
the `bitcoinconsensus` crate is frozen at Core 26 sources and can never gain a future soft fork.
The portable default therefore has a sunset horizon independent of this plan. Whether the kernel
build eventually becomes the default (eliminating the dual-engine surface) is a user decision
deferred until U2 produces data (binary size, build-dependency cost); see Open Questions.

---

## Key Technical Decisions

- **KTD1 — Script-level kernel granularity, not `process_block`.** Campaign A calls
  `bitcoinkernel`'s per-input `verify` (already wrapped functionally in
  `crates/consensus/src/kernel.rs`: one `bitcoinkernel::Transaction` parse per tx +
  `PrecomputedTransactionData` shared across inputs) from the apply path. This removes the
  measured per-input re-parse pathology by construction while keeping the KvStore UTXO set,
  block-level Rust contextual checks (BIP30/34, PoW, DAA, maturity, BIP68), and the crossbeam
  event loop untouched. Rationale above.
- **KTD2 — Kernel-first sequencing** (user-confirmed). Campaign B starts only after Campaign A's
  measurement gates (U0, then U2) resolve. The substantive justification is the composition
  analysis in the Problem Frame: A keeps apply off the critical path once B lands; A alone does
  not move the live verdict, and the plan says so.
- **KTD3 — Measurement-gated integration, spike before surgery.** No published
  bitcoinkernel-vs-bitcoinconsensus benchmark exists; the expected improvement is architectural
  reasoning, not data. U0 tests the hypothesis (per-input cost and thread-scaling) at zero
  integration cost before U1 touches the apply path; U2 re-tests it end-to-end before U3/U4
  invest further. The bitcoinconsensus contention finding (1 rayon thread beat 128) does not
  transfer to a stateless pre-parsed verify call and is re-established at both gates.
- **KTD4 — Two-profile framing.** The portable build (`rocksdb,fjall,redb,mdbx,bitcoinconsensus`)
  remains the default and the compactness story; the kernel build (`kernel-node`) is the speed
  story. Both ship from one tree. Honesty constraints on this framing: (a) the kernel build's
  speed is delivered by Core's own C++ engine — the claim it supports is "the rs node
  architecture around Core's engine outperforms Core's node architecture", not "Rust outperforms
  C++"; (b) neither profile alone satisfies both goal clauses, which is why the framing itself
  is an Open Question the user ratifies. Mutual exclusivity of `kernel` and `bitcoinconsensus`
  is enforced at the source level: a `compile_error!` under
  `#[cfg(all(feature = "kernel", feature = "bitcoinconsensus"))]` in `bitcoin-rs-consensus`
  (Cargo cannot express it; a both-features build otherwise risks silent symbol misrouting
  between two static archives rather than a clean link failure — e.g. `cargo build --features
  kernel-node` without `--no-default-features` pulls in default `bitcoinconsensus`).
- **KTD5 — Under the kernel feature, the kernel verifies everything.** All script classes
  (legacy, P2SH, segwit v0, taproot) route through the kernel
  (`kernel_bits()` already carries P2SH/DERSIG/NULLDUMMY/CLTV/CSV/WITNESS/TAPROOT). The repo's
  consensus-authority rule ("if they disagree, kernel wins") makes any split routing
  unjustifiable. Corollary: the legacy script-executing entry in `verify_tx.rs` must not remain
  silently reachable with Rust-interpreter semantics in the kernel build (R2); the Rust taproot
  path stays compiled only for the dual-path differential.
- **KTD6 — Campaign B is a Core-faithful port keyed on window-blocked staller detection.**
  Per the solutions doc: deep in-order window, per-peer inflight cap ~16
  (`MAX_BLOCKS_IN_TRANSIT_PER_PEER`), single-peer-128 fallback below ~8 **eligible** peers,
  staller detection on the *window-front* block (not `applied_tip+1` stagnation), adaptive
  timeout 2 s → 64 s, no-blame rule when our own apply/stager is the bottleneck. **Eligible
  peer** means, per Core's `net_processing` shape: outbound, witness-serving (NODE_WITNESS
  service bit), header-chain at or above the requested height, and not currently soft-demoted
  for expired pending — exact predicate finalized at U6 against Core's criteria, but counting
  inbound or stalled peers toward fan-out is explicitly wrong (it recreates the under-fill
  regression). All knobs land in `SyncBudget` (`crates/node/src/sync/window.rs`), which the
  existing test harness injects via `install_budget`. Simulation results are inadmissible as
  validation evidence (prior sim said 82–88 % efficiency while live collapsed); only live runs
  count.
- **KTD7 — Staging-budget resize precedes fan-out; causal claim stated precisely.** The
  recorded collapse mechanism was head-of-line stall churn: a stalled frontier peer froze the
  apply frontier for the 1-minute `PENDING_TIMEOUT` while other peers overflowed the
  **count** budget (`RECEIVED_BLOCK_BUDGET` = 128) into evict/re-download churn — U7's staller
  detection is the fix for *that*. The **byte** budget (`RECEIVED_BLOCK_BYTE_BUDGET` = 32 MiB,
  256 KiB/slot) is a separate forward-looking bound that binds at high-height 1–2 MiB blocks,
  mostly above the 150k acceptance window. U5 does the cheap in-memory resize (to match
  `PENDING_BYTE_BUDGET`'s 256 MiB ceiling) so fan-out is never reasoned about under an
  inconsistent budget pair; disk-backed staging is **out of scope** (framework ahead of need at
  150k).

---

## Requirements

**Campaign A — kernel-backed script verification**

- R1. A `kernel-node` composite feature on `bin/bitcoin-rs` builds the full node with storage
  backends plus `kernel`, excluding `bitcoinconsensus`; `bitcoin-rs-consensus` carries a
  `compile_error!` rejecting any build that enables both native backends.
- R2. Under the `kernel` feature, `verify_block_transactions` (`crates/node/src/apply.rs`)
  dispatches script verification through the kernel for **both** full-script dispatch paths
  (shared-view parallel and overlay); non-script checks and `skip_scripts` /
  `assume_valid_height` behavior are unchanged; and no production code path in the kernel build
  can fall through to the Rust interpreter for script verdicts (the legacy entry either
  dispatches to the kernel internally or is `cfg`-unavailable, with a test pinning it).
- R3. The kernel build replays 0→150k against the local corpus to a **byte-identical stop hash**
  (`0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b`) with full script
  verification (`assume_valid_height = 0`); elapsed wall-clock **and** script-verify stage sums
  are recorded beside the portable baseline (296.2 s elapsed / 200.7 s script) and Core (67 s)
  under matched posture.
- R4. `script_verdict_parity` (`crates/consensus/tests/kernel_block_parity.rs`) runs un-ignored
  in the kernel CI job against a committed fixture corpus covering **all script classes**:
  legacy fixtures extracted from the local 150k datadir **plus** frozen post-activation
  fixtures (P2SH ≥ 173,805; segwit ≥ 481,824; taproot ≥ 709,632; raw tx hex + prevouts from
  public block data or a synced Core), with per-input accept/reject mutations; the
  empty-fixture guard stays red-on-empty. `block_verdict_parity` must not red the CI job (see
  U3 — `#[ignore]` does not survive `--include-ignored`).
- R5. CI gains a `kernel-node` job (libboost-dev + cmake) running the node test suite and clippy
  under the kernel profile; existing portable jobs are untouched.
- R6. Portable-build binary size and behavior are unchanged; the kernel build's stripped binary
  size is measured and recorded **as part of U2** (compactness ledger, not a gate).

**Campaign B — multi-peer block download**

- R7. Per-peer in-flight cap (~16) with automatic single-peer-deep-window fallback when
  **eligible** peers (per KTD6's definition) < ~8; the fallback threshold lands as a new
  `SyncBudget` field (`max_peer_inflight` already exists in `SyncBudget` — only the policy
  values and the fan-out threshold are new).
- R8. Window-blocked staller detection: when the window-front block stalls on one peer past an
  adaptive timeout (2 s doubling to 64 s), that peer is disconnected and its blocks re-queued
  via the existing `release_disconnected_peers` path — with a no-blame guard that suppresses
  disconnection when apply/stager backpressure is the cause.
- R9. Staged-block byte budget resized in memory to a full window of high-height blocks
  (≈ 256 MiB, matching `PENDING_BYTE_BUDGET`), landing before any fan-out change; disclosed:
  the 150k acceptance run does not exercise this bound (KTD7).
- R10. Adversarial staller-safety tests green before live validation: stalled-frontier-peer,
  staging-overflow, window-blocked-vs-tip-stagnation discrimination, no-blame, slow-trickle
  (peer delivering just under the adaptive timeout — measured, not necessarily disconnected),
  and few-peers fallback — in the existing synthetic-peer harness.
- R11. Live mainnet IBD 0→150k on the multi-peer build, measured against the recorded Core
  (628 s) and gocoin (~277 s) baselines under disclosed assumptions, judged by U8's decision
  rule; the sim is not acceptance evidence.

**Cross-cutting**

- R12. Every performance claim cites a fresh measurement on the repo-native replay or a live
  run; the superseded 56 s / 157 s small-window figures are never cited as evidence.
- R13. Commits are conventional, one concern each, with `Op:` body trailers; consensus-touching
  commits are flagged for user review.

---

## Implementation Units

### U0. Pre-integration kernel spike (zero-surgery falsification gate)

- **Goal:** Test the kernel-speedup hypothesis — per-input verify cost and thread-scaling —
  before any apply-path surgery. If the hypothesis fails here, U1's integration, CI work, and
  feature plumbing are never built.
- **Files:**
  - Create: `crates/consensus/examples/kernel_verify_spike.rs` (feature-gated `kernel`),
    reusing the fixture-extraction approach planned for U3 (sampled heavy blocks + prevouts
    from the local datadir, serialized to a small on-disk corpus the example loads).
- **Approach:** Replay the sampled blocks' script verification through
  `KernelContext::verify_tx` at thread widths 1 / 8 / 32 (rayon over txs), reporting per-input
  µs. Comparator is the **recorded** portable measurement on the same machine (~65 µs/input
  effective-serial on the bitcoinconsensus path) — the two backends cannot share a binary, so
  the comparison is cross-binary by design, same protocol as every cross-backend number in this
  plan.
- **Test scenarios:** spike accepts all pristine sampled blocks; per-input cost and scaling
  curve emitted as JSON.
- **Verification / decision rule:** (a) per-input cost materially below the bitcoinconsensus
  figure **or** near-linear thread-scaling where bitcoinconsensus had none → proceed to U1;
  (b) neither → stop Campaign A before surgery, document, surface the KTD1 full-block
  alternative and Campaign B to the user. An afternoon of work either way.

### U1. Kernel dispatch in the apply path

- **Goal:** Under `--features kernel`, block apply verifies all transaction scripts through the
  kernel; under the portable profile, nothing changes; a both-features build fails to compile.
- **Files:**
  - Modify: `crates/consensus/src/lib.rs` or `kernel.rs` (`compile_error!` guard per R1),
    `crates/node/src/apply.rs` (kernel dispatch at the two full-script call sites),
    `crates/consensus/src/verify_tx.rs` (under `kernel`: the script-executing entry dispatches
    to the kernel; the Rust-interpreter fallback becomes unreachable per R2),
    `bin/bitcoin-rs/Cargo.toml` (`kernel-node` composite feature).
  - Seam bias (from review): `bitcoinkernel::verify` is a free function and the existing
    `verify_tx` never uses `self.ctx` — prefer the zero-handle seam (dispatch inside the
    consensus crate's verify entry) over threading a `KernelContext` through `ApplyHandles`;
    only add handle plumbing if implementation shows it is actually needed.
  - Test: feature-gated unit tests in `crates/node/src/apply.rs` and
    `crates/consensus/src/verify_tx.rs`; a kernel-profile test pinning that the Rust
    interpreter is not reachable for script verdicts.
- **Patterns to follow:** `crates/consensus/src/kernel.rs` (error mapping
  `ConsensusError::Kernel`, `kernel_bits()` flag bridge, `i64::try_from` conversions),
  `crates/consensus/src/connect_block.rs` (feature-gated dual-path shape). Whether any `unsafe`
  surfaces (and thus `// SAFETY:` comments) appear is verified at implementation against the
  locked binding version — not assumed.
- **Test scenarios:**
  - Kernel build applies a known-good regtest fixture chain identically to the portable build's
    recorded outcomes — accept side.
  - A block with an invalid signature, a bad P2SH redeem, and a malformed witness is rejected
    with a script error under the kernel path — reject side, one case per script class.
  - `assume_valid_height` above the block height skips script execution on the kernel path too
    (no kernel calls observed), while value-balance violations are still rejected.
  - Overlay blocks (same-block spends) verify through the kernel against the per-tx snapshot
    view — the dispatch covers **both** full-script paths, not only the shared-view one.
  - Kernel profile cannot reach `Interpreter` for a script verdict (R2 pin).
  - Portable profile: `cargo tree -p bitcoin-rs --no-default-features --features
    "rocksdb,fjall,redb,mdbx,bitcoinconsensus"` shows no `bitcoinkernel`; behavior tests
    unchanged. Both-features build fails with the named `compile_error!`.
- **Verification:** `cargo test -p bitcoin-rs --no-fail-fast --no-default-features --features
  "rocksdb,kernel"` green in isolation; portable gates green; fmt clean; clippy clean on both
  profiles (`--features "rocksdb,fjall,redb,mdbx,bitcoinconsensus"` and
  `--features "rocksdb,kernel"`).

### U2. Replay measurement gate (the campaign's decision point)

- **Goal:** Measure the kernel build on the 0→150k full-validation replay; decide whether
  script-level kernel verification closes the processing-bound gap or the plan re-enters at the
  KTD1 alternative.
- **Files:** none beyond U1; results to `~/bench-g14/results/rs-replay-150k-kernel*.json` and
  the plan ledger; kernel-build stripped binary size recorded here (R6).
- **Approach:** Same protocol as the recorded baselines: REST block source against the local
  Core datadir, `assume_valid_height = 0`, stop-hash assertion, stage decomposition. Run at
  default rayon width and `RAYON_NUM_THREADS=1`.
- **Test scenarios:** Stop hash byte-identical (an end-to-end 150k-block differential against
  the portable backend); script-verify stage sums reported per path.
- **Verification / decision rule:** The decision binds on the **script-verify stage sums**
  (isolates the changed component from fetch variance); elapsed is recorded alongside.
  Baseline: 200.7 s script / 296.2 s elapsed; non-script floor ~95.5 s.
  - (a) script sum ≤ 100 s (≥2× script speedup; elapsed ≈ ≤ 195 s) → continue to U3, U4
    optional.
  - (b) script sum in (100, 150] s (≥25 % improvement, short of 2×) → continue to U3; U4
    becomes the lever, capped by its plateau rule.
  - (c) script sum > 150 s (<25 % improvement) → stop; document; surface the KTD1 full-block
    alternative and Campaign B as the remaining levers.
  Honest framing recorded with the result: even outcome (a) leaves elapsed ≈ 3× Core's 67 s —
  the processing-bound clause **vs Core** stays unmet at U2; what (a) buys is (i) the apply
  headroom that keeps Campaign B's live win realizable (Problem Frame composition) and (ii) the
  platform U4 tunes toward contesting Core. The thresholds derive from the recorded
  decomposition, not aspiration.

### U3. Kernel parity fixtures and CI

- **Goal:** The kernel path's accept/reject behavior is pinned by committed fixtures spanning
  all script classes and runs in CI; the `kernel-node` profile is a first-class CI citizen.
- **Files:**
  - Create: `crates/consensus/tests/vectors/blocks/` fixture corpus — legacy blocks sampled
    from the local datadir **plus** frozen post-activation fixtures (P2SH/segwit/taproot raw tx
    hex + prevouts; activation heights are all above 150k, so the datadir alone cannot cover
    them); `.github/workflows/ci.yml` `kernel-node` job.
  - Modify: `crates/consensus/tests/kernel_block_parity.rs` — tracking the scaffold,
    committing fixtures, and restructuring `block_verdict_parity` are **one atomic commit**
    (tracking alone reds the kernel job via `require_non_empty` under `--include-ignored`).
    `block_verdict_parity` cannot rely on `#[ignore]` (the CI job runs `--include-ignored` by
    design): gate it behind an env var (skip-with-message when unset or while
    `connect_block` is the stub) or delete it in favor of a tracking comment — it depends on
    the rejected `process_block` path and is out of scope per KTD1.
- **Patterns to follow:** existing `kernel-only` CI job (`.github/workflows/ci.yml:95-104`) for
  system deps; `require_non_empty` red-on-empty guard.
- **Test scenarios:** pristine fixtures accept on both backends; each mutation class (sig bit
  flip, script truncation, wrong sighash type, witness tampering — the witness mutation now has
  post-segwit fixtures to bite on) rejects identically; fixture-loading failure is loud.
- **Verification:** `cargo test -p bitcoin-rs-consensus --no-default-features --features kernel
  -- --include-ignored` green locally and in CI **including** the restructured
  `block_verdict_parity` handling; default `cargo test` stays green.

### U4. Kernel-path throughput tuning (conditional on U2 outcome b; optional under a)

- **Goal:** Close the residual gap via per-tx kernel `Transaction` reuse audit and
  rayon-granularity tuning over the stateless verify calls.
- **Files:** Modify `crates/consensus/src/kernel.rs`, `crates/node/src/apply.rs` (parallel
  iterator granularity).
- **Approach:** Strictly measurement-driven on the U2 harness; every candidate is one commit,
  kept on green replay + improved wall-clock, reverted otherwise. **Plateau rule (hard cap):**
  after two consecutive candidates each improving the replay by < 5 %, U4 ends and the standing
  number is the campaign's result. The falsified-hypotheses ledger (per-tx fan-out
  net-negative, pre-resolve regression) is binding prior art — those shapes are not retried on
  the kernel path without a measured reason.
- **Test scenarios:** stop-hash identity after every change; no new clippy/fmt drift.
- **Verification:** replay wall-clock strictly improves per landed change; plateau rule
  enforced.

### U5. Staging byte-budget resize (Campaign B prerequisite)

- **Goal:** The staged-block byte budget is consistent with a full download window of
  high-height blocks, so fan-out logic is never reasoned about under an inconsistent budget
  pair.
- **Files:** Modify `crates/node/src/sync.rs` (`RECEIVED_BLOCK_BYTE_BUDGET` and the
  `PENDING_BUDGET == RECEIVED_BLOCK_BUDGET` const-assert coupling added in `a11523f` —
  preserved or consciously reworked), `crates/node/src/sync/stage.rs` if `BlockStager` sizing
  assumptions surface.
- **Approach:** In-memory resize to ≈ 256 MiB (match `PENDING_BYTE_BUDGET`); **no disk-backed
  staging** (KTD7). Disclosed: at the 150k acceptance window the byte budget rarely binds
  (blocks far below the 256 KiB/slot estimate); the recorded collapse was count-budget HOL
  churn, fixed by U7. This unit ships consistency, not the collapse fix.
- **Test scenarios:** staging a window of max-size blocks does not evict; budget exhaustion
  degrades to backpressure (stops requesting), never evict-redownload churn; existing
  apply-cache tests stay green.
- **Verification:** `cargo test -p bitcoin-rs --no-fail-fast --no-default-features --features
  "rocksdb,fjall,redb,mdbx,bitcoinconsensus"`; sync unit tests green.

### U6. Per-peer fan-out with single-peer fallback

- **Goal:** The download window fans out across eligible peers at cap ~16, and collapses back
  to single-peer-deep-window when eligible peers are scarce.
- **Files:** Modify `crates/node/src/sync/window.rs` (`SyncBudget` gains `min_peers_for_fanout`;
  `max_peer_inflight` already exists — only its policy value changes), `crates/node/src/sync.rs`
  (peer-selection scan limit; the eligibility predicate per KTD6).
- **Patterns to follow:** the reverted commit `5608279` is the anti-pattern reference (shallow
  cap=3, no staller handling, no fallback, no eligibility filter);
  `tick_limits_inflight_per_peer` for existing cap mechanics; `install_budget` for test
  injection.
- **Test scenarios:** ≥8 eligible synthetic peers → window fans at cap 16; <8 eligible →
  single peer fills the deep window (no under-fill regression); ineligible peers (inbound /
  demoted / low header-chain) are not counted toward the fan-out threshold and receive no block
  requests; peer disconnect mid-window re-queues its blocks.
- **Verification:** sync unit tests green; no live run yet (gated on U7/U8).

### U7. Window-blocked staller detection

- **Goal:** A stalled peer holding the window-front block is detected, timed out adaptively
  (2 s → 64 s), disconnected, and its blocks re-requested — without blaming peers when our own
  apply path is the bottleneck.
- **Files:** Modify `crates/node/src/sync/window.rs` (front-block ownership + stall timer;
  timeout fields in `SyncBudget` for test injection), `crates/node/src/sync.rs` (disconnect +
  `release_disconnected_peers` invocation; no-blame guard reading apply/stager backpressure).
- **Approach:** Stall state keyed on "window full AND front block in-flight AND apply frontier
  idle" — explicitly not `applied_tip+1` age, per the solutions doc.
- **Test scenarios:** front-block peer never delivers → disconnected after adaptive timeout,
  blocks re-queued, sync proceeds; apply-side stall (stager full) → no disconnect fires;
  timeout doubles per consecutive stall, resets on progress; slow-trickle peer delivering just
  under the timeout → throughput metric exposes it even though no disconnect fires (same
  exposure as Core; observable, not silent); demoted peer remains usable when it is the only
  eligible peer (existing soft-demotion tests stay green).
- **Verification:** R10 adversarial suite complete across U6/U7; full sync test module green.

### U8. Live IBD validation

- **Goal:** The live-IBD verdict, re-measured: multi-peer rs vs the recorded Core and gocoin
  baselines.
- **Files:** none (run + results artifact `~/bench-g14/results/`, plan ledger update).
- **Approach:** Same protocol as the recorded cross-node run: fresh datadir, mainnet 0→150k,
  full script verification posture disclosed (rs validates strictly more than both
  competitors); daemonized with re-armable watchers (20-min background-task cap).
- **Verification / decision rule:**
  - (a) elapsed < 628 s → the live speed clause vs Core is met under a stricter validation
    posture; record and declare.
  - (b) elapsed in [628 s, ~2,000 s) → material progress, goal unmet; diagnose from the
    blk/min curve whether download or apply is binding; if apply is binding and Campaign A
    landed, that is the composition case the plan predicted — surface to the user with data.
  - (c) ≥ ~2,000 s or stall collapse → revert the offending unit (never patch live); the
    re-entry point is the staller-detection design itself, with the live trace as the new
    evidence artifact.
  - Beating gocoin's ~277 s is the stretch reading; it is not the acceptance bar because
    gocoin's figure was achieved with historical-script skip while rs fully validates —
    matched-assumption parity with gocoin is recorded as out of reach until an
    `assume_valid`-posture run is separately measured and disclosed.

---

## Scope Boundaries

- **Full-block kernel backend (`ChainstateManager`)**: out, per KTD1; named re-entry if U0/U2
  fail.
- **Retiring bitcoinconsensus / kernel-as-default**: out; deferred user decision (Open
  Questions).
- **Disk-backed staging**: out, per KTD7 — framework ahead of need at the acceptance window.
- **Node-level reorg implementation**: out (pre-existing documented gap, separate user-owned
  decision).
- **Promoting the Rust interpreter (`crates/script`) to a production backend**: out — the
  Alternatives section is the standing verdict.
- **`Interpreter::execute` fallback cleanup** (per-input clone+re-serialize): deferred;
  unreachable at measured heights, further shielded by R2's no-fallback pin.
- **New storage backends, async runtime, openssl**: unchanged hard constraints.

---

## Open Questions (user decisions)

1. **Goal-framing ratification — RATIFIED (user, 2026-06-10).** This plan reads the goal
   disjunctively ("faster than Core *or* gocoin", per the goal's own wording) and splits
   delivery across two profiles (KTD4: portable = compactness, kernel = speed). Consciously
   accepted: neither single profile satisfies fast-AND-compact against Core today, and the
   kernel build's speed comes from Core's own engine (the claim is about node architecture, not
   interpreter provenance).
2. **End-state engine policy.** libbitcoinconsensus is frozen at Core 26 and will never gain a
   future soft fork — the portable default has a sunset horizon regardless of this plan. After
   U2 produces binary-size and build-cost data, decide: keep dual-profile, or make kernel the
   default and retire bitcoinconsensus.

---

## Risks & Dependencies

- **Kernel C API is explicitly experimental** ("no concern for backwards compatibility");
  binding releases track it. Mitigation: workspace pin `>=0.2, <0.3` with `Cargo.lock` at
  0.2.1 (verified in-tree; the crates.io/docs.rs 0.1.1-vs-0.2.1 listing discrepancy observed in
  research is resolved by the lock); upgrades are deliberate, parity-gated events.
- **Portable default rests on a frozen upstream** (libbitcoinconsensus removed in Core v28,
  crate pinned to Core 26 sources): no future soft-fork rules can ever reach the portable
  build's script engine. This predates the plan but the plan makes it explicit (Open Question
  2).
- **Dual-engine divergence surface**: after Campaign A the project ships two profiles with
  different consensus engines. CI parity gates (R4) and the 150k stop-hash differential bound
  this at ≤150k plus fixture coverage; a field divergence between the project's own builds
  above fixture coverage remains the structural risk that Open Question 2 ultimately resolves.
- **Thread-scaling on kernel verify is unknown** until U0; the bitcoinconsensus finding may or
  may not transfer; U0 measures it before U1 invests.
- **Binary size of the kernel build** is unquantified (statically linked Core subsystem;
  multi-MB expected; plausibly near gocoin's 16 MB total). Recorded at U2 (R6); only the
  portable build carries the compactness claim.
- **Campaign B precedent risk**: the prior live collapse is the strongest evidence in this
  plan; U7's staller detection targets the recorded mechanism (count-budget HOL churn), and
  R11 forbids sim-based acceptance.
- **Fixture extraction** (U0/U3) depends on the local Core datadir (`~/bench-g14/core-datadir`)
  for legacy fixtures; post-activation fixtures come from public block data; all fixtures are
  committed so CI depends on neither.

---

## Verification

- Per change: `cargo fmt --all -- --check`; `cargo clippy -p bitcoin-rs --all-targets
  --no-default-features --features "rocksdb,fjall,redb,mdbx,bitcoinconsensus" -- -D warnings`;
  once U1 lands, additionally `cargo clippy -p bitcoin-rs --all-targets --no-default-features
  --features "rocksdb,kernel" -- -D warnings` (storage-backend set for the kernel CI job
  finalized at U3 by CI wall-clock cost); `cargo test --workspace --no-fail-fast`; kernel
  isolation suite `cargo test -p bitcoin-rs-consensus --no-default-features --features kernel
  -- --include-ignored`.
- Campaign A acceptance: U0 gate, then R3's byte-identical 150k replay with the U2 decision
  rule applied to recorded numbers.
- Campaign B acceptance: R10 adversarial suite green, then R11 live run judged by U8's decision
  rule.
- Measurement honesty: R12 — fresh numbers only, matched postures disclosed, regressions
  reported plainly.

---

## Deferred to Implementation

- Exact storage-backend composition for the `kernel-node` CI job (all four vs rocksdb-only) —
  decide by CI wall-clock cost at U3.
- Final eligible-peer predicate details (U6), aligned to Core's `net_processing` criteria.
- Whether U1 needs any handle plumbing at all (seam bias says no — `bitcoinkernel::verify` is a
  free function); decide at the first dispatch call site.
- Fixture corpus size/sampling strategy for U0/U3 (CI-time budget vs mutation coverage).
