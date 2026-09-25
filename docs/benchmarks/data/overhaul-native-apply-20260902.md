> Superseded: the native interpreter now verifies every consensus spend class; see docs/contracts/validation-default.md VAL-02.

# Native apply-path measurement (PERF-V5)

This measurement controls the native-validation performance gate for issue #166, paired with the kernel baseline in `overhaul-kernel-baseline-20260829.md`.

## Configuration

- Git commit: `72e1149`
- Command: `cargo bench -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- sync_pipeline_apply_spend_heavy_proxy`
- Host: Intel Xeon Gold 6138 (80 cores), Linux x86-64
- Storage backend: fjall
- Transaction index: disabled
- Criterion samples per run: 100
- Independent runs: 3
- Core pinning: `taskset -c 70-79` (host under concurrent cargo build load from sibling agents)
- Env: `env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR TMPDIR=/tmp/perfv5tmp`

The controlling corpus is generated in-process by `spend_heavy_proxy_blocks()`. It contains 117 regtest blocks: 100 blocks establish coinbase maturity, then 16 blocks each exercise 64 `OP_TRUE` spends. The timed operation applies the full corpus to a fresh `NodeState`. Setup remains outside the Criterion timed closure. This is identical to the kernel baseline corpus.

## Results

| Run | Criterion interval (ms) | Median estimate (ms) |
|---:|---:|---:|
| 1 | 14.963 to 16.529 | 15.747 |
| 2 | 13.179 to 14.946 | 14.026 |
| 3 | 17.853 to 20.395 | 19.078 |

Median of run medians: **15.747 ms**.

Sample standard deviation across run medians: **2.568 ms**, or **16.31%** of the median. This is below the 20% noise ceiling.

Run 3 was elevated by a transient load spike (host load average 50.9 on 80 cores, 112 concurrent cargo/rustc processes). Even the worst run (19.078 ms) is 1.89x faster than the kernel baseline.

## Comparison against kernel baseline

| Metric | Kernel baseline | Native (this run) |
|---|---:|---:|
| Median | 36.136 ms | 15.747 ms |
| Speedup | 1.0x | 2.29x |

### Gate 1: native median lower than kernel median

15.747 ms < 36.136 ms. **PASS.**

### Gate 2: native_median * 1.05 <= 36.136 ms

15.747 * 1.05 = 16.534 ms. 16.534 <= 36.136 ms. **PASS.**

## Scope of this number

Both arms apply the same `spend_heavy_proxy_blocks()` corpus, whose spends are
bare `OP_TRUE` outputs (`crates/node/benches/sync_pipeline.rs`, `push_int(1)`).
Neither arm verifies a signature. The number therefore measures apply-path
overhead - parse, prevout resolution, state plumbing - on trivially satisfiable
scripts. It is not evidence about signature verification cost, and it says
nothing about the two engines on real spends.

## Verdict

**Gates pass, flip blocked.** Both arithmetic conditions hold, but they do not
license the #166 default flip. The portable backend cannot verify ordinary
spends: `verify_non_taproot_portable` in `crates/script/src/interpreter.rs`
accepts exactly one shape, `script_pubkey == [0x51]` with an empty scriptSig and
an empty witness, and errors on everything else; only taproot key-path is
implemented in full. `CONCEPTS.md` records the consequence - a mainnet sync
stops at the first real spend. Making `kernel` opt-in today would ship a node
that cannot validate mainnet in more build configurations, so the flip waits on
a portable interpreter, not on a faster measurement.
