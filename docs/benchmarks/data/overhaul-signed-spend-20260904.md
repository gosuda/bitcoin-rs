# Signed-spend proxy measurement (PERF-V7)

This measurement controls the signed-spend performance gate for issue #213
after the process-wide `secp256k1::SECP256K1` reuse in the native checker.

It uses the same harness as
[`overhaul-signed-spend-20260902.md`](overhaul-signed-spend-20260902.md).
Those earlier numbers were taken on a different host and are not a paired
control for this run.

## Configuration

- Git commit: `0299e6770b5a79e8a7af594ab5ef380a2807228e`
- rustc: 1.95.0 (`59807616e1fa2540724bfbac14d7976d7e4a3860`)
- Host: Intel Xeon, 4 CPUs, Linux 6.12.94+, x86-64
- Command (native): `cargo bench -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- signed_spend --sample-size 30 --warm-up-time 1 --measurement-time 8`
- Command (kernel): same with `--features fjall,kernel`; `CC=gcc CXX=g++` and `LIBRARY_PATH=/usr/lib/gcc/x86_64-linux-gnu/13`
- Env: `env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR TMPDIR=$PWD/target/tmp`
- Storage backend: fjall
- Transaction index: disabled
- Independent runs: 3 per arm
- Native bench SHA-256: `aecc038303049d1ca47660bfeb538c911de12dc67e83b7a664e89fcba30938e2`
- Kernel bench SHA-256: `a3d13c5ceead948f61b2e4b1411891b0d958be06cb5a3de6d88ecf5f5cfbec97`

## Corpus

`signed_spend_proxy_blocks()` in `crates/node/benches/sync_pipeline.rs`.
117-block skeleton: heights 1..100 fan out 64 coinbase outputs each;
heights 101..116 spend those outputs. Spend classes: P2PKH, P2WPKH, and
P2WSH 2-of-3.

Criterion times include `open_regtest_state()` inside `iter_custom`. The
manual percentile table times only the apply sweep. The gate uses the
apply-only p50.

## Results

### Native arm (`--features fjall`)

| Run | Criterion median (ms) | Apply p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | samples |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 251.88 | 49.753 | 52.788 | 56.283 | 56.608 | 67 |
| 2 | 245.07 | 50.306 | 52.393 | 54.106 | 55.870 | 67 |
| 3 | 245.60 | 50.014 | 51.840 | 54.628 | 56.412 | 67 |

Median of apply p50s: **50.014 ms**. Largest run-median deviation from that
value: 0.58%.

### Kernel arm (`--features fjall,kernel`)

| Run | Criterion median (ms) | Apply p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | samples |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 237.09 | 46.618 | 48.121 | 48.487 | 48.590 | 37 |
| 2 | 239.86 | 45.588 | 47.452 | 48.641 | 49.182 | 67 |
| 3 | 227.69 | 45.784 | 51.138 | 52.723 | 54.980 | 67 |

Median of apply p50s: **45.784 ms**. Largest run-median deviation from that
value: 1.82%.

### Peak RSS

`resource.getrusage(RUSAGE_CHILDREN)` over `--profile-time 2` on each
binary: native 14 684 KiB, kernel 15 968 KiB. Allocation count is not
reported by this harness.

## Comparison

| Metric | Native | Kernel | Native / kernel |
|---|---:|---:|---:|
| Median of apply p50s | 50.014 ms | 45.784 ms | 1.092 |
| Median of Criterion medians | 245.60 ms | 237.09 ms | 1.036 |

Both arms stay within five percent of their own independent-run median.
Native apply p50 is higher than kernel apply p50.

## Verdict

**Gate fails.** The native path is stable and much closer than the
2026-09-02 signed-spend run, after sharing `secp256k1::SECP256K1` across
signature checks. It is still slower than libbitcoinkernel on this
corpus, so `kernel` stays the default in `bitcoin-rs-consensus` and
`bitcoin-rs-node`.
