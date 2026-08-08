---
title: Two thread-pool constants were tuned against a contended harness; fixing them cut CPU 3.5x and took Core's lead to 1.28x
date: 2026-08-07
category: docs/solutions/performance-issues
module: node apply path (crates/node/src/apply.rs, crates/consensus/src/verify_tx.rs)
problem_type: performance_issue
component: apply
severity: medium
applies_when:
  - "Measuring processing-bound 0→150k replay with full verification (assume_valid_height=0)"
  - "Optimizing txid computation or script verification preparation"
  - "Adding, removing, or tuning a rayon fan-out on the block apply path"
related_components:
  - consensus
  - utxo
tags:
  - txid
  - parallelization
  - rayon-granularity
  - processing-bound
  - replay
---

# Two thread-pool constants were tuned against a contended harness; fixing them cut CPU 3.5× and took Core's lead to 1.28×

## Context

Processing-bound replay `mainnet_prefix_replay --rest-url 127.0.0.1:18443 --assume-valid-height 0 --stop-height 150000` over local `bitcoind -rest` (fjall backend, full script verification both sides) is the correct instrument for CPU work per `small-window-benchmarks-do-not-predict-at-scale-throughput.md`. Baseline at `4700c25` was **389.7s / 385 blk/s** vs Core `67s` / 2240 blk/s (5.8×).

Commit `f76d43a` (`perf(apply): parallelize txid computation for blocks with many transactions`) parallelizes `plan_block_transactions` for `block.txdata.len() > 32` via `par_iter().map(compute_txid)`. Synthetic proxy benches (≤32 txs) do not exercise this path, so they show no signal.

## Measurement

Same machine (128 cores), serial runs, local REST blocks (fjall, full verification):

| Node | Commit | Elapsed 0→150k | blk/s | RSS high-water | Source | Notes |
|---|---|---|---|---|---|---|
| bitcoin-rs | `4700c25` | 389.7s | 385 | 2.36 GB | `processing-bound-150k-verdict.md` | baseline |
| bitcoin-rs | `f76d43a` | 178.93s | 838 | 223 MB | `~/bench-g14/results/replay-postopt-150k-f76d43a.json` (150001 blocks, 687 MB, `git_head f76d43a`) | single clean run, txid parallel |
| bitcoin-rs | `e540b91` (code-identical to `f76d43a`) | 173.1s median (166.4, 173.1, 177.8) | 867 | 223 MB | `taskset -c 0-31` 3×, no IBD contention (`/tmp/replay-taskset-*.json`) | txid parallel, 16-thread pool |
| bitcoin-rs | `0e2dda5` | 157.8s median (163.8, 155.9, 157.8) | 950 | 223 MB | `taskset -c 0-31` 3× (`/tmp/replay-t32-*.json`) | + 32-thread script-verify pool |
| bitcoin-rs | threshold change | 135.0s median (135.0, 134.0, 140.6) | 1111 | 226 MB | `taskset -c 0-31` 3× (`/tmp/rfin-*.json`) | + parallel threshold 16 → 4 |
| bitcoin-rs | serial prevout resolve | **125.4s median** (124.1, 125.4, 128.4) | **1196** | 226 MB | `taskset -c 0-31` 3× paired (`/tmp/rp2-0-*.json`) | + both UTXO resolve stages serial |
| Core 31.0 | — | ~~67s~~ **superseded** | 2240 | n/a | 2026-06-09 debug.log, unknown load | do not quote; re-derived below |
| Core 31.0 | — | **59.6s median** (59.6, 59.4, 60.2) | 2517 | n/a | `taskset -c 0-31` 3× interleaved with rs, same idle host | `-reindex-chainstate -assumevalid=0 -connect=0 -stopatheight=150000` |
| bitcoin-rs | matched pair | 132.2s median (132.2, 134.5, 131.6) | 1135 | 226 MB | same interleaved series | apply 95.3s; the rest is REST fetch |
| bitcoin-rs | one-shot kernel block parse, REST source | 121.9s median (121.9, 124.4, 120.6) | 1231 | 226 MB | `taskset -c 0-31` 3× paired against the prior binary | apply 82.0s, `script_prepare` 4.29s |
| bitcoin-rs | **local block file source** | **84.6s median** (84.2, 84.6, 86.5) | **1774** | **224 MB** | `taskset -c 0-31` 3× | apply 76.7s; block source matched to Core |

**Quote the interleaved matched pairs at the top of the pool sections: replay 77.9s vs 60.7s = 1.28×, P2P 62.8s vs 45.9s = 1.37×.** Every row in this table predates the two thread-pool fixes. Every row above it fetched blocks over REST while Core read local `blk*.dat` files, so those ratios measure the harness as much as the engine — see the harness section below. Total self-improvement over the `4700c25` baseline is **4.6×**.

### GoCoin: bitcoin-rs wins, and by more than the raw numbers show

GoCoin's default `LastTrustedBlock` is **#940000** (`client/common/config.go:22`), and `lib/chain/chain_accept.go:140` short-circuits script verification for any block marked `Trusted`. The whole 0→150k window sits below that, so **GoCoin skips script verification for every block in this comparison** by default. Quoting its wall time against a full-verification bitcoin-rs run would be comparing different work.

Both re-measured now, pinned `taskset -c 0-31`, both pulling blocks from the same local fixture node:

| Posture | GoCoin | bitcoin-rs | |
|---|---|---|---|
| matched — both skip historical script checks | 195.8s | **84.0s** (84.0, 84.5) | **2.33× faster** |
| bitcoin-rs doing strictly more work — full script verification | 195.8s | 121.9s | 1.61× faster |

GoCoin's own log line is the source (`Sync to 150000 took 3m15.76s`); it landed within 3% of a months-old run, so unlike Core's reference this figure was stable. bitcoin-rs is faster on both readings, and the honest headline is the second one: **it beats GoCoin by 1.61× while verifying every script GoCoin skips.**

**These are deliberately the socket-fetch numbers, not the local-block-file ones.** GoCoin pulls blocks over P2P from the fixture node, so the comparable bitcoin-rs figures are the REST runs (84.0s assume-valid, 121.9s full-verify) where both nodes pay a socket round-trip. Quoting the 84.6s local-file result against GoCoin would reintroduce exactly the harness mismatch corrected above for Core.

### P2P sync over the loopback fixture — Core leads here too

The processing-bound replay is not the only throughput metric the goal names, so all three nodes were also run as a P2P sync to 150k against the same local fixture peer, each at its own default posture (all three skip historical script checks by default at this height, so the postures match):

| Node | Runs | Median | |
|---|---|---|---|
| Core 31.0 | 43.1 / 42.9s | **43.0s** | 1.00× |
| bitcoin-rs | 75.7 / 76.4s | **76.0s** | 1.77× slower |
| GoCoin | 195.8s | 195.8s | bitcoin-rs 2.58× faster |

The bitcoin-rs row is **superseded by both thread-pool fixes below**: it now syncs the same window in **62.8s**, so Core leads **1.37×** and bitcoin-rs is **3.12×** faster than GoCoin. The row is kept because the rest of this section reasons from it.

**This is not the download-bound regime, despite being a P2P sync.** A loopback fixture imposes no bandwidth limit, so what this measures is validation plus P2P protocol overhead — closer to processing-bound than to real IBD. The genuine download-bound regime needs a bandwidth-constrained or real-network path, and the older full-tip figures (bitcoin-rs 27081s vs Core 42907s at 961k) were taken there and are **not** contradicted by this table. They are also months old and unverified this session; do not quote them without re-deriving.

**These two results are independent, not a decomposition — do not divide them.** An earlier revision of this note put them side by side:

| Measurement | bitcoin-rs | Core | ratio |
|---|---|---|---|
| replay, full verification | **77.9s** | 60.7s | **1.28×** |
| P2P sync, both skip historical scripts | 76.0s | 43.0s | 1.77× |

and inferred that because the second ratio is worse, stripping the tied crypto reveals "the non-crypto gap undiluted". **That inference was wrong.** The two runs do not share a common baseline: the P2P sync additionally executes header sync, net message processing, block-download scheduling, block staging, mempool bookkeeping, and an RPC server, none of which the replay runs at all. The difference between 1.42× and 1.77× therefore mixes script posture with entire subsystems, and attributing it to the apply path is unsupported.

Each result stands on its own, and each is internally matched:

* **1.28×** is a clean apply-path comparison — same window, same full-verification posture, both reading local files, interleaved. (This read 1.42× before the two thread-pool fixes.)
* **1.77×** is a clean whole-node comparison — same window, both at their own defaults, both pulling from the same fixture peer.

The apply-path decomposition below rests on the replay alone, which is why it is trustworthy. Nothing here licenses a claim about how much of the P2P gap is apply versus sync stack.

**The P2P gap is not stall — it is 4.9× the CPU.** The plumbing was never needed. Sampling `utime+stime` from `/proc/<pid>/stat` while polling `getblockcount` answers the first question directly, and both nodes were run through the same probe pinned to `taskset -c 0-31`:

| Node | wall | CPU | mean cores |
|---|---|---|---|
| Core 31.0 | 42.5s | **65.0s** | 1.53 |
| bitcoin-rs | 76.3s | **318.4s** | 4.17 |

A stalling node burns comparable CPU over more wall time. This is the opposite: bitcoin-rs spends **4.9× the CPU** to sync the same 150k blocks and hides most of it behind parallelism. Two consequences. Wall-clock tuning on a 128-core idle host is measuring the wrong thing, because it can spend cores freely; and on a 4- or 8-core machine, which is what most nodes run on, 318 CPU-seconds becomes wall time and the 1.77× gap widens sharply.

**Per-thread attribution says the waste is broad, not one hot spot.** Summing `/proc/<pid>/task/*/stat` by thread name over 60s of sync: threads named `bitcoin-rs` 128.8s (52%), the `script-verify-*` pool ~105s, `bitcoin-rs-p2p-` 11.1s. The pool burning 105s during an *assume-valid* sync that skips historical scripts looked like rayon workers spinning before sleeping, which would have been a one-constant fix.

**That hypothesis is refuted; do not go looking for the knob.** Sweeping `SCRIPT_VERIFY_POOL` width against both axes at once:

| width | wall | CPU |
|---|---|---|
| 32 (current) | 75.9s | 318.9s |
| 8 | 77.0s | 250.2s |
| 4 | 79.2s | 243.6s |
| 2 | 82.6s | 239.0s |
| 1 | 89.2s | 230.1s |

Collapsing the pool to a single thread removes only 88s of the 318s and costs 13s of wall. Even fully serial, bitcoin-rs burns **3.5×** Core's CPU. Pool spin in *this* pool is a minority of the excess.

**The wrong pool was under suspicion.** The larger bucket in the thread attribution was the 128.8s under the process name, and rayon leaves its **global** pool's workers unnamed, so they inherit it. Unlike `SCRIPT_VERIFY_POOL` that pool was never capped: it sized itself at one worker per core, on top of a 32-thread script pool and the node's own I/O threads. `RAYON_NUM_THREADS` tests it with no code change, and three interleaved pairs settle it:

| global pool | wall | CPU |
|---|---|---|
| one per core (32) | 75.6s | 314.4s |
| **4** | **64.4s** | **162.4s** |

**1.17× faster and 1.94× less CPU at once** — not a trade. Landed as `GLOBAL_RAYON_THREADS` in `cap_global_thread_pool`; the compiled binary reproduces it without the env var (64.6s wall, 160.0s CPU, three runs). The width sweep is flat from 2 to 8 (63.5–64.7s) and climbs above, so 4 sits mid-plateau. The full-verification replay is insensitive at every width (84–88s wall, 960–990s CPU) because script verification dominates there and runs in its own pool, so the cap costs that path nothing.

This is why the CPU axis was worth adding: the global pool was invisible to every wall-only sweep in this note, because on an idle 128-core host spinning workers cost almost no wall time. It only became obvious once CPU was measured, and then it turned out to cost wall time too.

**Measure CPU alongside wall from now on.** Every sweep in this note before this one optimised wall time only, on an idle 128-core host. `MIN_PARALLEL_SCRIPT_CHECKS` 16→4 is the clearest untested case: it won 1.15× of wall by pushing far more blocks through the pool, which is exactly the change that raises CPU. It has not been re-checked against CPU and should be, on hardware with a realistic core count, before it is treated as settled.

What this settles: Core still leads every figure, but by far less than this section first recorded. The final interleaved pairs are below; after the threshold fix landed on top of this cap, P2P settles at **1.37×** wall and **1.33×** CPU, not the 1.52×/2.46× measured with the cap alone. bitcoin-rs beats GoCoin on both throughput figures. Earlier bitcoin-rs runs each logged two `Disk quota exceeded` errors from checkpoint publication at shutdown, after the target height was reached; timings were consistent across runs, but re-measure on a host with headroom before treating any of these as precise.

### The parallel threshold was tuned against a contended harness

Capping the global pool exposed a second, older instance of the same mistake. `MIN_PARALLEL_SCRIPT_CHECKS` was walked down to **4** by a sweep run while the harness fetched every block over REST from a second `bitcoind` competing for the same cores. That contention inflated the serial path, so finer and finer fan-out kept looking free and the sweep ran to its floor.

Re-measured against local block files, three interleaved rounds, `taskset -c 0-31`, both axes:

| threshold | wall | CPU |
|---|---|---|
| 4 (previous) | 84.4s | 946.6s |
| 16 | 80.1s | 773.2s |
| **32** | **75.5s** | **649.6s** |
| 64 | 78.4s | 533.6s |
| 128 | 94.0s | 390.7s |

The ordering **inverts** once the harness stops stealing CPU: 4 is now the worst point tested on both axes, and the old sweep's monotonic "lower is always better" curve was an artefact of the contention. 32 is the wall minimum and also beats every smaller value on CPU, so it dominates rather than trades. CPU keeps falling above 32, but wall turns sharply at 128 and a node that finishes later has saved nothing.

Compiled binary, no env var, three runs: **75.2s wall, 643.8s CPU**, all 150001 blocks validated at `assume_valid_height=0` to the correct tip hash. Against the previous 84.6s that is **1.12× faster and 1.47× less CPU**, and it moves the standing gap against Core from 1.42× to **1.26×**.

Two rules come out of this, and they cost this note two wrong constants between them:

1. **Never tune a parallelism constant against a harness that shares CPU with the node.** The contended REST harness did not just add a constant; it changed the *shape* of the curve and reversed its optimum.
2. **Never tune one on wall alone.** Both bad constants were wall-optimal on an idle many-core host and both were far off once CPU was measured.

### Final matched pairs, both fixes in

Interleaved on an idle host, `taskset -c 0-31`, three rounds each, wall and CPU captured together. These supersede every ratio earlier in this note.

| Benchmark | | Core 31.0 | bitcoin-rs | Core leads |
|---|---|---|---|---|
| replay, full verification | wall | 60.7s | 77.9s | 1.28× |
| | CPU | 463.6s | 652.5s | 1.41× |
| P2P sync, both assume-valid | wall | 45.9s | 62.8s | 1.37× |
| | CPU | 67.8s | 90.1s | 1.33× |

What the two constants were worth, measured end to end:

| | before | after | |
|---|---|---|---|
| P2P wall | 76.0s | 62.8s | 1.21× faster |
| **P2P CPU** | **318.4s** | **90.1s** | **3.53× less** |
| replay wall | 84.6s | 77.9s | 1.09× faster |
| replay CPU | 946.6s | 652.5s | 1.45× less |

The CPU gap against Core on the P2P sync went from **4.9× to 1.33×**. Neither fix added an optimisation: both removed parallelism that a contended harness had made look free. Against GoCoin's 195.8s the P2P margin is now **3.12×**.

Core still leads every throughput and CPU figure here, so the parity goal is not met. But the remaining gaps are 1.28-1.41×, not the 2-5× this note opened with, and nothing left is a constant — see the stage decomposition below.

### The constant class is exhausted

Every parallelism constant in the hot path has now been re-measured against the matched harness with CPU alongside wall. The class is closed:

| Constant | Verdict |
|---|---|
| `MIN_PARALLEL_SCRIPT_CHECKS` 4 | **wrong** — 4 was the worst point on both axes; now 32 |
| global rayon pool, uncapped | **wrong** — 3.53× the CPU on the P2P path; now capped at 4 |
| `MAX_SCRIPT_VERIFY_THREADS` 32 | **survives** — wall falls monotonically to 32, a real trade that wall wins |
| global pool cap on the replay | **null** — 77.6s / 654.8s uncapped vs 79.4s / 658.3s at 4, inside noise |

The last row is why `cap_global_thread_pool` lives in `node::run` and not in the consensus crate: it pays on the P2P path, where the pool contends with the sync stack, and does nothing on a replay whose cost is script verification inside a separate pool.

Two of four were wrong, and both were wrong for the same two reasons — tuned against a harness sharing CPU with the node, and tuned on wall alone. Neither mistake is visible without measuring CPU on an idle many-core host. **No constant remains to tune**; what is left is per-unit work, itemised in the stage decomposition below.

Two measured facts about the remainder, and no causal claim between them. At our operating point (32 script threads) bitcoin-rs spends 652.5s CPU against Core's 463.6s and 77.9s wall against 60.7s. At 8 threads it spends 474.2s CPU — near Core's — but takes 130.6s, reaching only 3.63 mean cores against Core's 7.64.

**Do not read that second row as a per-unit-work gap.** Equal CPU with higher wall is the signature of *lower effective parallelism or idle time*, which is the opposite reading. The two rows describe different operating points and cannot be combined into a single cause. Assigning one needs a CPU profile or a stage concurrency trace, and neither has been taken.

The current apply decomposition (150001 blocks, `assume_valid_height=0`):

| stage | seconds | n |
|---|---|---|
| apply total | 69.39 | 150001 |
| script verify | 49.34 | 150001 |
| — of which parallel | 26.08 | 44008 |
| — of which serial overlay | 23.26 | 23883 |
| utxo commit | 3.65 | 150001 |
| block rules | 2.81 | 150001 |
| script prepare | 2.57 | 67891 |
| block body persist | 1.73 | 150001 |
| everything else | <1.1 each | |

Non-script apply is now about 10s total, down from roughly 20s. Script verification is 71% of apply, and **23.26s of it runs serially because those blocks need the same-block UTXO overlay**. That is the largest single identified item left and it is structural, not a constant.

### Memory is the metric bitcoin-rs wins

Peak RSS over the same window, same validation posture, both pinned:

| Node | Peak RSS | Source |
|---|---|---|
| bitcoin-rs | **232 MB** (233, 232, 232) | replay `rss_high_water_bytes` |
| Core 31.0 | **643 MB** | `/usr/bin/time -v` over the reindex run |

**bitcoin-rs holds 2.77× less resident memory.** Any summary of this work that quotes only the throughput ratio is incomplete: the two nodes trade off, Core faster per block and bitcoin-rs far leaner. Core's figure comes from the same `-reindex-chainstate` invocation timed at 60.5s wall, so it is the memory cost of the run being compared, not a different configuration.

Core's own stage decomposition over the identical window (`-debug=bench`, aggregated from its log lines), recorded so nobody re-derives it:

| Core stage | Cost |
|---|---|
| `Verify N txins` (2,868,199 inputs) | 36.07s |
| Load block from disk | 7.18s |
| Fork checks | 3.25s |
| Flush | 2.59s |
| Connect postprocess | 1.63s |
| Sanity checks | 1.41s |
| **Connect block total** | **55.80s** |

**Pool width was only half of it.** Widening the pool 16 → 32 bought 1.10×, but the pool cannot help a block that never reaches it: `MIN_PARALLEL_SCRIPT_CHECKS` sent every block with fewer than 16 input checks down the serial branch, and on mainnet 0→150k that is most of them. Lowering the threshold to 4 bought a further **1.15×** and cut `script_verify` 84.0s → 66.5s. The sweep is steep and monotonic above the optimum (`taskset -c 0-31`, 3× medians for 4/8/16 interleaved round-robin so cache warming hits each equally; single runs above):

| Threshold | 4 | 8 | 16 | 48 | 128 | 512 |
|---|---|---|---|---|---|---|
| Elapsed | **139.4s** | 145.1s | 155.8s | 185.0s | 234.6s | 297.3s |

Threshold 2 measured 143.8s, so the optimum is a genuine interior minimum at 4, not "as low as possible". The ordering 4 < 8 < 16 held in all three interleaved rounds.

## Where the 157.8s goes — clean stage decomposition

From `/tmp/replay-t32-3.json` (`0e2dda5`, `taskset -c 0-31`, uncontaminated):

```
elapsed              157.8s      fetch 22.4s   decode 3.6s   RSS 212 MB
  apply total        128.9s
    script_verify     84.9s      (66% of apply)
      script_parallel 55.2s
      script_prepare  19.4s
      script_resolution 6.1s
    utxo_commit        7.0s
    block_rules        5.2s
    (remainder <5s each)
  non-script apply    44.0s
```

Two things this reframes:

1. **~22.4s of the 157.8s is REST fetch**, a harness cost Core's `-reindex-chainstate` never pays — it reads local `blk` files. *(Historical: this was the first sighting of the harness asymmetry. Both sides of the ratio quoted here are superseded — Core's 67s by the re-derived 59.6s, and the REST fetch itself by the local-block-file source. The correct figure is 1.42×; see the harness section.)*
2. **`script_verify` at 84.9s already exceeds Core's entire 67s run**, and non-script apply (44.0s) is by itself two-thirds of Core's total. Both halves need work; neither alone closes the gap.

**Pinning is load control, not a core handicap.** The same `0e2dda5` build run *unpinned* on all 80 CPUs measures **190.7s** (188.0, 190.7, 191.5) — 21% *slower* than the pinned 157.8s — because this box is shared and carried load average 7.7–18.5 during the run. Giving the replay every CPU means contending for them; pinning 32 gives it 32 it mostly keeps. So `taskset -c 0-31` is the reproducible measurement, not an artificial handicap, and any cross-node ratio quoted from an unpinned run on a busy host is contention noise. The corollary matters for the Core comparison: **Core's 67s reference was captured at another time under unknown load**, so the 2.36×/1.92× figures carry that uncertainty on both sides and should be re-derived from a back-to-back idle-host pair before anyone treats them as final.

An earlier instrumented run (`53feecb`, 201.84s) attributed the then-uninstrumented remainder to `utxo_resolve` 25.7s and `txid_plan` 21.6s, but that run was contaminated (concurrent full-tip IBD writing `blk00817→867`) **and** inflated ~23s by the per-block histograms themselves. Treat its absolute numbers as indicative only; the clean decomposition above supersedes it.

**Levers tried and rejected on clean `taskset -c 0-31` 3× medians (all against the 173.1s serial baseline):**

| Change | Median | Speedup | Verdict |
|---|---|---|---|
| Parallel `prepare_block_input_checks` (`0302a0c`) | 173.5s (170.6/173.5/173.9) | 1.00× | rejected — reverted `6d9c3b8` |
| Thread-local serialize buffer in `prepare_kernel_tx` (avoids per-tx `encode::serialize` alloc) | 173.2s (173.2/173.9/172.4) | 1.00× | rejected — `script_prepare` 20.4s → 18.2s but total unchanged |
| Skip `kernel_txout` construction for witness-free txs (empty `spent_outputs` to `PrecomputedTransactionData`) | not benchmarked | — | **rejected by tests**: kernel returns `Script verification error: Spent outputs required for verification`. Core's `Init` computes no midstates without a witness, but `btck_script_pubkey_verify` still gates on `m_spent_outputs_ready`, so the prevout `TxOut` objects must be built even when never hashed |
| Feed kernel the block's already-serialized tx byte ranges instead of re-serializing | not implemented | ~1.01× (costed) | rejected on analysis — the replay moves 687 MB of tx bytes, so removing the Rust serialize entirely is order 1–2s of 173s, bounded empirically by the buffer result above (2.2s off the stage → 0.1s off the total) |
| Retain kernel `TxOut` objects in `PreparedKernelTx` and borrow `script_pubkey()`/`value()` per input, instead of rebuilding an FFI `ScriptPubkey` for each of ~3.3M inputs | 160.3s (164.1/160.3/159.7) vs **157.8s** | 0.98× | rejected — `script_parallel` 55.2s → 56.1s (no gain) and RSS 212 → 226 MB. Holding the prevout objects across the whole verify phase costs more in residency than the eliminated `malloc`+copy saves |

The first two cleared the tests but not the 1.05× noise floor; the third never got that far. `script_prepare` is real work inside `libbitcoinkernel`, not Rust-side overhead. Even eliminating **all** of prepare leaves ~153s against Core's 67s, so prepare is not where the gap lives. `ResolvedUtxoView::resolve` (25.69s) is likewise **already parallel** (`apply.rs:1136` `into_par_iter`), so it is not a batching target either.

The fourth result retires the "FFI boundary is the remaining lever" hypothesis for its allocation half. Per-input `ScriptPubkey::new` is a ~25-byte `malloc` plus copy; at 3.3M inputs that is real allocator traffic, and removing it entirely changed nothing measurable. What the kernel spends inside `btck_script_pubkey_verify` is secp256k1 work, not marshalling. Marshalling-side micro-optimization is now closed as a class: four separate attempts (parallel prepare, serialize buffer, witness-free skip, prevout reuse) all landed at 0.98–1.00×.

## Matching the harness moved the ratio from 2.05× to 1.42×, and the pool fixes took it to 1.26×

Every earlier number here fetched blocks over REST from a live `bitcoind`. Core's `-reindex-chainstate` reads its own `blk*.dat` files. That is not a like-for-like harness: the replay paid HTTP round-trips *and* competed for CPU with the process serving them, neither of which Core pays.

`mainnet_prefix_replay --blocks-file` now reads a length-prefixed local file, mirroring what Core does. Same window, same validation posture, pinned 3× medians:

| Source | elapsed | apply | outside apply |
|---|---|---|---|
| REST from live `bitcoind` | 121.9s | 82.0s | ~40s |
| **local block file** | **84.6s** (84.2, 84.6, 86.5) | **76.7s** | 8.0s |

Note that *apply itself* improved, 82.0s → 76.7s, purely from removing the serving node's CPU contention. The harness was distorting the engine measurement, not merely adding a constant.

| Metric | Core 31.0 | bitcoin-rs | |
|---|---|---|---|
| elapsed | 59.6s | **84.6s** | **1.42× slower** |
| apply | 55.80s | 76.7s | 1.37× slower |
| peak RSS | 643 MB | **224 MB** | **2.87× leaner** |

**Quote 1.26×.** This section's 1.42× was correct when written and is superseded by the two thread-pool fixes above, not by a harness change. The 2.05× and 2.22× figures earlier in this note measured the harness as much as the engine and are superseded. The lesson is the same one that produced the matched-pair section below: a ratio is only as good as the least-matched thing in it, and here the block source was the least-matched thing for the whole session.

## The matched pair — the only ratio worth quoting

Every earlier ratio in this note compared a bitcoin-rs median against Core's **67s** figure captured on 2026-06-09 under unknown load. That reference has now been re-derived, and the honest numbers are worse than the ones this document previously carried.

Core re-run from the same `core-datadir-reindex` that produced the original figure, same command (`-reindex-chainstate -assumevalid=0 -connect=0 -stopatheight=150000`), pinned `taskset -c 0-31`, 150,001 UpdateTip lines each time: **63.5 / 60.0 / 60.1s**. The old 67s was conservative.

Then both nodes interleaved back-to-back on the same idle host, so neither gets a quieter machine:

| Node | Runs | Median | Ratio |
|---|---|---|---|
| Core 31.0 | 59.6 / 59.4 / 60.2s | **59.6s** | 1.00× |
| bitcoin-rs *(REST source — superseded)* | 132.2 / 134.5 / 131.6s | 132.2s | 2.22× slower |
| bitcoin-rs, apply only *(superseded)* | 95.3s median | 95.3s | 1.60× slower |

> **The two bitcoin-rs rows here are superseded.** They still fetched blocks over REST while Core read local `blk*.dat`. Matching the block source drops them to **84.6s / 1.42×** — see *"Matching the harness moved the ratio"* above. The Core row (59.6s) stands; it is the same measurement used throughout.

The correction this section *does* establish, and which still holds:

1. **Never compare your best run against someone else's old run.** The 1.87× previously quoted came from a best-case bitcoin-rs median against Core's stale 67s reference. Interleave both nodes back-to-back, or do not quote a ratio at all. This is what exposed the harness problem in the first place.
2. **Harness cost was larger than the 22.4s this note originally claimed** — ~37s once measured back-to-back, because the `bitcoind` serving REST competes for the same cores. That observation is what led to the local-block-file source and the current 1.42×.

Core reaches its number with **15** script threads (`MAX_SCRIPTCHECK_THREADS`) against our 32, which makes the remaining gap a per-unit-work gap rather than a parallelism gap. That still describes the shape of the problem.

## Core's crypto is not faster — ours is surrounded by work Core never does

Core re-run with `-debug=bench` over the identical window, aggregating its own stage lines:

| Core stage | Cost |
|---|---|
| `Verify N txins` (2,868,199 inputs) | **36.07s** |
| Load block from disk | 7.18s |
| Fork checks | 3.25s |
| Flush | 2.59s |
| Connect postprocess | 1.63s |
| Sanity checks | 1.41s |
| **Connect block (total)** | **55.80s** |

Our `script_parallel` is **36.42s**. Core's `Verify txins` is **36.07s**. Within a percent of each other, on the same inputs, through the same libsecp256k1. **The crypto is a tie.**

That kills three hypotheses at once, and they should not be re-opened without new evidence:

* **Not the signature cache.** Core's `CachingTransactionSignatureChecker` and CuckooCache sigcache cannot be worth much here, because Core's measured verify time already equals ours. There is no hidden 2× being saved by cache hits.
* **Not compiler tuning.** The kernel is built `-O2 -g` with no `-march` (generic x86-64), and it still matches Core. `-C target-cpu=native` on the Rust side measured 1.016×. Build flags are not where the gap lives.
* **Not parallel width.** Core reaches this with 15 script threads against our 32, and still ties on verify.

The gap is the ~40s of apply that is **not** crypto:

| | Core | bitcoin-rs | Delta |
|---|---|---|---|
| script verify | 36.07s | 36.42s | ~0 |
| transaction marshalling (`script_prepare`) | none | 18.6s | **+18.6s** |
| txid computation | free during deserialization | 10.3s | **+10.3s** |
| remaining apply | 16.1s | 23.9s | +7.8s |
| total | 55.8s | 95.3s | +39.5s |

Core never pays the first two. It deserializes each block once into `CTransaction` objects and validates those in place; the txid falls out of deserialization, and `PrecomputedTransactionData` is built over objects it already holds. We decode raw bytes into `bitcoin::Transaction`, then `encode::serialize` every transaction back into bytes so `bitcoinkernel::Transaction::new` can parse it a **third** time.

So the marshalling class closed earlier was closed at the wrong altitude. Four micro-optimizations inside that round-trip each measured 0.98-1.00×, and that remains true: shaving allocations off a redundant round-trip cannot pay. Removing the round-trip is a different change, and it is now quantified at **~29s of the 39.5s gap**. That is the only lever left that is worth its risk.

## The marshalling refactor: first closed wrongly, then reopened by a better measurement

The obvious conclusion from the table above is "stop round-tripping transactions through Rust structs: parse the block once with `bitcoinkernel::Block::new` and validate `block.transaction(i)` in place." The API supports it — `TransactionRef<'a>` is `Send + Sync` and implements `TransactionExt` — at the cost of threading a block lifetime through `PreparedTx`, `prepare_block_input_checks`, `verify_block_input_scripts`, and `PreparedKernelTx` across three crates.

It is not worth doing. Sub-stage probes inside `prepare_kernel_tx` split the 19.2s prepare stage:

| Sub-stage | Cost | Fate under the refactor |
|---|---|---|
| `encode::serialize` (per tx) | **2.74s** | removed |
| `bitcoinkernel::Transaction::new` (1.7M calls) | **9.67s** | replaced |
| `PrecomputedTransactionData::new` | 2.61s | stays |
| other | 2.84s | stays |

The replacement is not free, and that is the whole point. Timing one `bitcoinkernel::Block::new` per block over the same bytes:

```
per-tx serialize + parse   12.42s   (removed)
whole-block Block::new     10.88s   (added, 150k calls)
                         --------
net                        +1.54s   (1.1% of a 138s run)
```

`Block::new` is more expensive per byte than the 1.7M individual `Transaction::new` calls it would replace, so on those two line items alone the refactor loses.

**That accounting was wrong, and the correction reverses the verdict.** It priced only the parse and the serialize, and ignored that `Block::new` *also* produces every txid as a side effect: Core's `CTransaction` hashes itself during deserialization, so `TransactionExt::txid()` is a getter over an already-computed hash. And it computes it with the implementation Core selects at runtime, which this host logs as:

```
Using the 'sse4(1way);sse41(4way);avx2(8way)' SHA256 implementation
```

That is a software **AVX2 8-way multi-buffer** SHA-256, already linked into this binary through `libbitcoinkernel`. Our `compute_txid` uses `bitcoin_hashes`' scalar SHA-256. The earlier note here that beating it would need "a cryptographic-library project" was wrong — the library is already a dependency.

Timing `Block::new` plus harvesting every txid from it, and checking each against the `tx_plan` txids:

```
Block::new + harvest all txids   10.93s   (150k blocks, 1.7M txids, 0 mismatches)

replaces:
  compute_txid (scalar SHA-256)  10.30s
  encode::serialize               2.74s
  Transaction::new                9.67s
                                --------
                                 22.71s
net                              -11.78s   (~1.10x on a 132s run)
```

Zero mismatches over 1.7M transactions, so the kernel txids are consensus-identical to rust-bitcoin's.

**This was the largest remaining lever, and it is now implemented.** One `Block::new` retires three separate costs at once. Measured 3× pinned and interleaved against the previous binary:

| | before | after |
|---|---|---|
| elapsed | 137.3s | **121.9s** (1.126×) |
| apply | 100.8s | **82.0s** (1.23×) |
| `script_prepare` | 18.55s | **4.29s** (4.3×) |

Every run validated all 150,001 blocks at `assume_valid_height=0`, and the kernel txids were proven byte-identical to `compute_txid` over 1.7M transactions before a line was written.

The shape that landed: `KernelBlock` owns the parse and exposes `txids()` plus borrowed transactions; `apply_block_inner` parses once and feeds those txids into `plan_block_transactions_with_txids`; `PreparedKernelTx<T: TransactionExt>` is generic so the block path holds a `TransactionRef<'block>` while the standalone `verify_tx_scripts` entry keeps an owned `Transaction`. The portable backend gets a `KernelBlock` that decodes with rust-bitcoin, so both backends share one call shape instead of a cfg-split signature.

The lesson generalizes past this case: **price a replacement by everything it subsumes, not by the line item that motivated it.** Costed against parse-and-serialize the change looks like +1.54s; costed against parse, serialize, and hash it is -11.78s.

Probe methodology, for anyone repeating this: the probes were `AtomicU64` nanosecond accumulators exported from `crates/consensus/src/kernel.rs` and printed by the replay example, all reverted afterwards. They are cheap enough to leave in during a measurement run (138.2s probed against a ~132s unprobed median, most of that ordinary drift).

## What the remaining apply time is

Two temporary probes (removed after measurement) attributed the last unmeasured slice of apply. They cost nothing detectable — the probed run measured 123.3s and 126.0s against a 124.2s unprobed median — which **retires the earlier claim that per-block histograms cost ~23s**. That figure came from a contaminated run; the apply path already carries 13 per-block histograms, so two more are free at this scale.

> **Superseded snapshot.** The table and analysis that stood here were the pre-refactor decomposition: `script_prepare` 18.6s and `plan_block_transactions` 10.3s. The one-shot kernel parse cut `script_prepare` to 4.29s and absorbed txid computation into `Block::new` entirely, so both figures are gone. The txid analysis that followed — bounding the `bitcoin_slices` idea at ~2.7s and calling AVX2 SHA-256 out of reach — was overtaken by that refactor, which obtained Core's AVX2 hashing for free.
>
> The current decomposition is the stage-by-stage table below, and the closing plan is in *"The gap is now fully accounted for"* above. Kept as a marker rather than deleted, because the reasoning error it records is instructive: it priced each candidate against the line item that motivated it instead of everything a replacement would subsume.

**`-C target-cpu=native` is real but too small to ship.** The build sets no `target-cpu`, so it is generic x86-64. Rebuilding native and pairing 3× against generic: **132.0s vs 129.9s (1.016×)**, native winning all three rounds, with apply alone 96.8s → 90.8s (~1.066×). The whole-run figure misses the gate because roughly 22s of the run is REST fetch that codegen cannot touch. It is deliberately **not** made the default: the binary would be pinned to this CPU. Use it only as a documented opt-in for a known host.

## Where the 80.7s apply stands against Core, stage by stage

Post-refactor decomposition beside Core's `-debug=bench` figures for the identical window:

| Stage | bitcoin-rs | Core | Note |
|---|---|---|---|
| script verification | 36.47s | 36.07s | **tie** — same libsecp256k1, nothing to win |
| block parsing | ~14.0s (`Block::new` + txid harvest ~10.9s, rust-bitcoin decode 3.1s) | 7.18s (`Load block from disk`) | only the 3.1s is removable — see below |
| consensus rules / merkle | 4.79s (`block_rules`) | 1.41s (`Sanity checks`) | merkle root over scalar SHA-256 vs Core's AVX2 |
| UTXO commit | 6.10s | 2.59s (`Flush`) | |
| block body persist | 4.18s | none | see the fairness note below |
| script prepare + resolve | 5.80s | folded into Connect | |
| remainder | ~9.4s | ~7.5s (`Fork checks` + postprocess) | |
| **total** | **80.7s** | **55.80s** | |

**Fairness note.** Core's `-reindex-chainstate` already holds its `blk` files and writes no block bodies; our replay persists them, so 4.18s of our apply is storage work Core does not do *in this benchmark*. It is not dead weight — a real node must store blocks, and Core pays it during IBD — but a strict engine-to-engine ratio should exclude it. On the current local-block-file measurement that is **80.4s vs 59.6s = 1.35×**, against the headline 1.42×.

### The one lever left, and why it is a separate change

**Do not start the "remove the double parse" refactor expecting a large win — it is worth about 3.1s.** The framing is tempting: we parse every block twice, once with rust-bitcoin into `bitcoin::Block` and once with the kernel, where Core parses once. But the two halves are not equally removable:

* The kernel parse (~10.9s) is **load-bearing and cannot go**. It produces the txids and the transaction objects that verification borrows; it is what replaced a 10.3s scalar-SHA `compute_txid` pass plus a 12.4s serialize-and-reparse round-trip. That figure also includes harvesting 1.7M txids across the FFI, not parsing alone.
* The rust-bitcoin decode (**3.1s**) is the only genuinely removable half, and removing it means carrying kernel types through apply, block rules, and the UTXO layer — a multi-crate change to consensus-critical code for **2.5% of a 121.9s run**, below the 1.05× noise gate.

An earlier revision of this note called the double parse "the largest remaining structural lever" at ~14.0s against Core's 7.18s. That was wrong in the same way the `Block::new` accounting was wrong earlier: it priced a replacement against a total that includes work which does not disappear. Corrected here so nobody spends a refactor on it.

That parse gap is real but also sub-gate, and the two probes already separate it. `Block::new` with the result discarded measured **10.88s**; `Block::new` plus harvesting all 1.7M txids measured **10.93s**. Harvesting is therefore **0.05s** — `TransactionExt::txid()` really is a getter over a hash the parse already computed, so there is nothing to reclaim there. The 10.88s is the deserialize itself, against Core's 7.18s for the same C++ deserializer *including real disk I/O*.

Why ours is ~1.5× slower on the same code is unexplained and worth knowing, but it is not a lever: **matching Core exactly would save 3.70s, or 3.0% of a 121.9s run (1.031×)** — under the noise gate. Attribute it for understanding, not for throughput. Two smaller targets sit behind it, both similarly bounded:

* `block_rules` 4.79s vs Core's 1.41s — the merkle root is SHA-256d over txids with a scalar implementation while Core uses its runtime-selected AVX2 one. The kernel does not expose a merkle helper, so this needs either an exposed hash primitive or a parallel merkle tree.
* `utxo_commit` 6.10s vs Core's 2.59s flush.

Do not re-open script verification: it is a measured tie, and four marshalling micro-optimizations plus a pool-width and threshold sweep are already closed above.

## The gap is now fully accounted for, and it is a program of small items

With the harness matched, the arithmetic closes for the first time. Apply is 76.7s against Core's 55.80s, a **20.9s** gap, and the identified per-stage deltas sum to **20.6s** — there is no longer a large unexplained remainder hiding in the measurement.

| Stage | bitcoin-rs | Core | delta | alone |
|---|---|---|---|---|
| script verification | 36.47s | 36.07s | ~0 | tie |
| `script_prepare` + `script_resolution` | 5.80s | folded into Connect | 5.80s | 1.074× |
| `block_body_persist` | 4.18s | none in reindex | 4.18s | 1.052× |
| block parse | 10.88s | 7.18s | 3.70s | 1.046× |
| `utxo_commit` | 6.10s | 2.59s | 3.51s | 1.043× |
| `block_rules` / merkle | 4.79s | 1.41s | 3.38s | 1.042× |
| **all together** | | | **20.6s** | **1.32×** |

Closing all of them lands at **64.0s against Core's 59.6s = 1.07×**, which is parity within a rounding of the noise band.

**One item is already tested and closed: `utxo_commit` is real work, not fan-out overhead.** `UtxoSet::commit` fans out over active shards above `PARALLEL_LISTENER_SHARD_THRESHOLD = 8`, which looked like a third instance of the unpaid-parallelism pattern. It is not. Paired 3× medians with the threshold at 8 versus effectively infinite:

| | elapsed | `utxo_commit` |
|---|---|---|
| parallel shards (threshold 8) | 84.2s | 5.5s |
| serial shards | 84.7s | 5.5s |

Identical. On blocks this small the active shard count rarely reaches 8, so the serial path is already what runs — there is no dispatch to remove. Closing the 3.51s against Core's flush needs a change to what the commit *does*, not to how it is scheduled. That drops the program to four items worth ~17s.

**A second item is closed: `block_rules` is merkle, and merkle is at its floor.** Probes split the 4.59s stage into merkle **4.34s**, `block.weight()` 0.18s, everything else 0.07s — so the stage *is* the merkle root. Three attempts, all rejected:

| Attempt | Result |
|---|---|
| hash via `sha2` (already a dependency, optimized x86_64 backends) instead of `bitcoin_hashes` + `Encodable` | 4.36s — **identical** |
| parallel fold, threshold 512 | 4.11s — 0.26s, inside run noise |
| parallel fold, threshold 32 | **6.52s** — worse; dispatch on small levels |

A calibration worth recording, because it corrected my own reasoning: raw double-SHA256 of 64 bytes on this host measures **873 ns** (`sha2`) and **907 ns** (`bitcoin_hashes`), not the ~400 ns I had assumed from theory. The fold runs at ~2586 ns/node, so the real overhead ratio is 2.9×, not the 6.4× an earlier draft claimed. The two libraries are equivalent; there is no faster-SHA lever hiding here.

Where the remaining 2.9× goes is per-node overhead in *small* levels — most blocks in this window have a handful of transactions, so each `next_merkle_level` call folds one or two nodes and amortizes its own call, bounds, and truncate over almost nothing. Parallelism cannot touch that (there is nothing to spread), and neither can a faster hash (hashing is only 1.46s of the 4.3s). Core reaches 1.41s for the whole of `Sanity checks` because its blocks come pre-parsed with the tree work batched differently, not because its SHA is faster.

**A third item is closed: `block_body_persist` is genuinely storage work, not overhead.** It looked suspicious — 687 MB in 4.18s is 164 MB/s on a tmpfs-backed data dir, an order of magnitude under what the device does. Probing the path found two KV reads wrapping the append (an idempotency lookup that is always `None` during linear replay, and a read-modify-write of a per-file max height that is monotonic and therefore cacheable). Both are real inefficiencies. Neither is worth fixing:

| Sub-stage | Cost |
|---|---|
| idempotency `index.get` | 0.36s |
| flat-file append (687 MB) | 1.44s |
| max-height `index.get` | 0.30s |
| batch write + other | 1.18s |
| total | 3.28s |

The two removable reads are **0.66s together, 0.8% of the run**. The remainder is the write itself plus the index batch. So this item is a *policy* call — include it in the ratio or exclude it as work Core's reindex does not do — and not an optimization target. Do not delete block-body persistence to improve a benchmark; a real node must store blocks.

**This changes how the remaining work should be run.** Every item is individually 1.04–1.07×, at or under the 1.05× single-candidate gate, so none of them will ever look convincing on its own — and at ±5% single-run noise on an 84.6s run, a 3.5s effect is at the edge of what a 3× median can resolve. The next session should therefore:

**Three of the five are now closed, all negative**, which retires most of the 20.6s on paper:

| Item | Verdict |
|---|---|
| `utxo_commit` 3.51s | real work; the shard fan-out is not even taken at this block size |
| `block_rules` 3.38s | merkle is at its floor; sha2 identical, parallelism neutral-to-worse |
| `block_body_persist` 4.18s | policy call; only 0.66s is removable overhead |

That leaves **block parse (3.70s)** and **`script_prepare` + `resolve` (5.80s)**, both inside the FFI boundary where four separate marshalling attempts already measured 0.98–1.00×. Closing both perfectly would reach ~75s against Core's 59.6s — **1.26×, still not parity**.

**No identified change reaches parity, including the architectural one.** An earlier draft of this section said parity "needs the architectural change". That was wrong and contradicted this note's own costing of that change at 3.1s. The arithmetic, from 84.6s against Core's 59.6s:

| Do this | Lands at | Ratio |
|---|---|---|
| the architectural change alone (remove the rust-bitcoin decode, 3.1s) | 81.5s | 1.37× |
| every still-open item (decode + block parse + prepare/resolve, 12.6s) | 72.0s | 1.21× |
| literally every item including the three proven unreachable | 61.8s | 1.04× |

Only the last row approaches parity, and it requires undoing three things that are measured as irreducible: merkle is at its hashing floor, `utxo_commit` is real work, and `block_body_persist` has 0.66s of removable overhead in 3.28s. So parity is not one refactor away. Core is modestly faster across nearly every non-crypto stage at once — 3-4s here, 3-4s there — which is what a mature C++ implementation with tuned allocation and batching looks like, not a defect with a fix.

What is genuinely true and worth carrying forward: script verification **was** a tie at 36.47s vs 36.07s, and the threshold correction deliberately gave that up — the stage now measures 49.34s of wall while costing far less CPU, and total apply fell from 76.7s to 69.39s. Judge the stage on total cost, not on its own clock. Memory is, memory is **2.9× better**, GoCoin is beaten by **2.3×**, and the total gap is **1.26×** and itemised. Anyone resuming should decide whether 1.26× on throughput is worth a broad re-engineering of the non-crypto apply path, rather than starting a multi-crate refactor expecting parity from it.

## Guidance

1. **Attribute a stage by disabling it, not by reading a profiler.** `perf` was unavailable here (`perf_event_paranoid=4`, no sudo), but the open question — is `script_parallel`'s ~0.93 ms/block genuine secp256k1 work or rayon dispatch overhead? — is binary, so forcing `MIN_PARALLEL_SCRIPT_CHECKS = usize::MAX` answered it in one run: the replay went 173.1s → **313.3s** and the stage 63s → **227.6s**. Genuine crypto. That immediately reframed the number: 227.6s → 63s is only **3.6× from a 16-thread pool**, so the pool width was the binding constraint, and widening it to 32 bought 1.10× (`0e2dda5`). Prefer this disable-the-stage technique whenever a hypothesis is binary; it needs no tooling and cannot be argued with.
2. **The prepare and marshalling phases are closed — do not reopen them.** Prepare is ~20s of the run; zeroing it entirely still leaves ~138s against Core's 67s. Five candidates are closed (table above): three by benchmark, one by tests (`btck_script_pubkey_verify` gates on `m_spent_outputs_ready`, so prevout `TxOut`s must be built even when nothing hashes them), one by cost analysis. `ResolvedUtxoView::resolve` is already `into_par_iter` (`apply.rs:1136`) and `plan_block_transactions` already `par_iter` above 32 txs (`apply.rs:985`), so neither is a target either.
3. **Pool width has a measured optimum at 32 on this host — do not raise it further.** The sweep is non-monotonic:

   | Pool | CPU set | Median | `script_parallel` |
   |---|---|---|---|
   | 16 | 32 physical (`0-31`) | 173.1s | 63-65s |
   | **32** | 32 physical (`0-31`) | **157.8s** | 55.2s |
   | 32 | 16 physical + SMT siblings (`0-15,40-55`) | 158.9s | 63.9s |
   | 64 | 64 logical (`0-63`) | 177.9s | 60.2s |

   64 threads is *worse than 16* — coordination and oversubscription on ~22-input blocks cost more than the extra width buys. A different machine needs its own sweep; the constant stays a cap rather than `available_parallelism` so verification cannot starve the rest of the pipeline. Beyond width, the often-proposed structural lever is holding kernel objects across the block (`bitcoinkernel::Block::new` once, then `block.transaction(i)`) instead of reconstructing per transaction. Treat that as unproven and probably weak: the prevout-reuse experiment above tested exactly the retain-kernel-objects-longer half of it and came back 0.98× with +14 MB RSS, because kernel object residency is itself a cost. Any future attempt must show it removes *work*, not just allocations, and must be measured before the cross-crate API change is written.

   **Width was re-swept after the threshold moved to 4 and did not move.** The two constants interact — a lower threshold sends far more blocks to the pool — so the width result was re-derived rather than assumed. On `taskset -c 0-31`: width 16 → 152.7s, width 32 → 139.6s. Values above 32 are unmeasurable under that pin, because `available_parallelism()` reports 32 and `available.min(cap)` clamps them; runs at 48/64/80 returned 141.0/147.2/144.0s, which are replicates of 32 and put single-run noise at roughly ±5%. Given a genuinely wider CPU set (`taskset -c 0-63`), width 32 and width 64 tie (159.8/162.2s vs 159.7/158.0s) and *both* lose ~15% to the 0-31 pin from host contention. So 32 is the optimum at either threshold, and the way to test a wider pool is a wider `taskset`, not a larger constant.

   **The threshold lesson does not generalize to `plan_block_transactions`.** The obvious follow-up — `apply.rs:985` parallelizes txid computation only above 32 txs, the same too-high-threshold shape — was swept and rejected: 1 → 139.8s, 4 → 138.1s, 16 → 141.9s, 32 → 136.4s, every value inside the ±5% single-run noise with the incumbent 32 nominally best. A txid is one SHA256d (order 1 µs) while a script check is order 100 µs, so per-item work decides whether a fan-out pays. Check the item cost before assuming a low threshold wins.
4. **Unnecessary parallelism is its own cost class — audit fan-outs by per-item work.** Two rayon fan-outs over UTXO lookups were pure loss, because a sharded hashmap hit is order 500 ns while a rayon dispatch is more. Removing them, each measured as pinned 3× medians with parallel and serial interleaved and serial winning every round:

   | Fan-out | Parallel | Serial | Stage effect |
   |---|---|---|---|
   | `ResolvedUtxoView::resolve` (`into_par_iter`, no threshold) | 143.8s | 134.7s | apply 116.2s → 103.6s |
   | `resolve_block_prevouts` non-overlay branch (`par_iter` per tx) | 139.4s | 125.4s | `script_resolution` 6.9s → 1.63s |

   **A stage-local win can be a global loss — always gate on elapsed, never on the stage.** Parallel prepare (`0302a0c`, reverted `6d9c3b8`) was re-tested at the current balance, because the original rejection was measured at threshold 16 with both resolve stages still parallel. It makes its own stage measurably faster and the run measurably slower:

   | | prepare stage | apply | elapsed |
   |---|---|---|---|
   | serial prepare | 17.7-18.5s | 92.3-95.3s | **124.2s** |
   | parallel prepare | 12.8-14.0s | 98.9-101.6s | 129.0s |

   It buys ~5s in `script_prepare` and gives back ~7s across the rest of apply, because its threads contend with the script-verify pool for the same cores. Reading `script_prepare_seconds` alone would have shipped a 4% regression as a 30% stage win. This re-confirms the original verdict and supplies the mechanism it lacked; prepare stays serial.

   The clearest evidence for the removal class: 5.3s of dispatch layered on 1.6s of work. This is the mirror of the threshold finding — there the fix was *more* parallelism for 100 µs script checks, here it is *none* for 500 ns lookups. Same question either way: does per-item work exceed dispatch? Distinct from the marshalling class closed above, which was about removing allocations rather than removing threads. Remaining fan-outs and their verdicts: `verify_block_input_scripts` (keep, ~100 µs per input), `UtxoSet::commit` over shards (keep, a batch write per item), `plan_block_transactions` (keep, swept flat).
5. **Per-block histograms are cheap here — the earlier warning was wrong.** `txid_plan_seconds`/`utxo_resolve_seconds` (added `68bbb2f`, reverted `e540b91`) were blamed for ~23s, but that run was contaminated by a concurrent full-tip IBD. Re-probing the same two stages on a quiet host cost nothing measurable (123.3s and 126.0s against a 124.2s unprobed median). The apply path already records 13 per-block histograms; two more do not move the number. Probe freely, but re-measure unprobed before quoting a figure.
6. **Do not re-use full-tip IBD wall-time to validate CPU changes.** IBD is download-bandwidth-bound (`multi-peer-block-download-requires-core-stalling-disconnect.md:41` apply 50–250× faster than single-peer download); the CPU win is invisible in IBD. Use the processing-bound replay (full verification) for CPU work, and the local-fixture full-tip IBD (`full-tip-rs-assumevalid.toml` 938343, `bitcoin-rs-fulltip-postopt-local3` at 463k/961k when stopped) only for the complementary bandwidth regime.

## Related

* `small-window-benchmarks-do-not-predict-at-scale-throughput.md` — correct harness; supersedes 0→1000 window
* `multi-peer-block-download-requires-core-stalling-disconnect.md` — download-bound regime analysis
* `script-verification-delegated-to-core-c-no-rust-headroom.md:66` — “UTXO caching, input preparation, storage commits” as Rust-side lever
* `processing-bound-150k-verdict.md` (bench results) — original 389.7s vs 67s baseline superseded by this measurement for the `f76d43a` line
