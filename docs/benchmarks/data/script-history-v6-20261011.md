# PR #1522: v5 → v6 measured trade-off

v6 restored 25-transaction pages for the 10,000-transaction histories and reduced warm successful-page latency. The cost is material: in the dense corpus, stopped index-file allocation was **2.48× after replay and 2.96× after rebuild**, with higher rebuild CPU and RSS. This is a local regtest RPC block replay/catch-up component measurement, not network or mainnet IBD.

| Arm | Source | Binary SHA-256 |
|---|---|---|
| v5 | `b4834e609c801a4013a67e5a76a0fdd44292a8af` | `d9fe554b45bbed9fb50b32b1c10f08480feb737248332da32d37102f1638fa90` |
| v6 | `361c6000fc8e74c222dc930a67618697ca31def1` | `aa6bc8b9a8ddcf933d688e3c91d620d608a74e5d4f856bb3d675ecf415b619a5` |

Both builds used release, locked dependencies, no default features, `fjall,redb`, two build jobs and release debug=0. Lockfile SHA-256: `65654a6b856e4733f19e0af9b71f24bda6ef4352b8757495d8e1e05a1947ccd3`. Runtime: native validation, Fjall chainstate and index, 64 MiB dbcache; AMD Ryzen 7 9700X (8 cores), approximately 30 GiB RAM, Linux 7.0.0-38 x86_64, same ext4-family volume with 4096-byte blocks.

Primary: 1,106 blocks / 12,209 transactions / 1,640,960 raw block bytes. Dense: 206 blocks / 211,310 transactions / 26,456,103 bytes. Both use the same 100/1,000/10,000 target history sizes with unique txids and prior-block spends. Core 31.1 validated the frozen corpora. Native final height, tip, UTXO count/amount and MuHash matched Core in all **23 runs**. All **2,160 retained v6 HTTP samples** returned HTTP 200 with the expected ordered page; comparable successful v5/v6 response bytes were identical. All v5 long-history forms consistently returned a budget 503.

The measured source remains `361c6000f`. Later code revision `87bd1862a` changes redb live-row handling and benchmark/test assertions; it was not remeasured. This campaign selected Fjall throughout.

## Formal acceptance: BLOCKED

Under [docs/benchmarks/README.md](https://github.com/gosuda/bitcoin-rs/blob/361c6000fc8e74c222dc930a67618697ca31def1/docs/benchmarks/README.md), this campaign is **diagnostic evidence only; formal performance acceptance is BLOCKED for every cell**. Functional observations remain recorded, but the campaign is not a performance-promotion or non-regression pass.

| Required identity | Recorded evidence / missing requirement |
|---|---|
| Artifact | Exact binary SHA-256 and source commit linked through each run ID: present. |
| Configuration | Build flags, features, backend, cache and native validation are recorded. CLI, input TOML, complete resolved `NodeConfig` and allocator identity are absent from the retained artifact: **BLOCKED**. |
| Corpus | Manifest digest, height range, stop height/hash and Core UTXO controls: present. Corpus block files and their per-block manifest are not bundled. |
| Durability | Fjall backend is recorded. Per-sample batch mode and explicit flush/sync posture were not captured: **BLOCKED**. |
| Toolchain | Release profile/features/lockfile are recorded. The required exact `rustc 1.99.0`/edition-2024 build attestation is not attached to these samples: **BLOCKED**. |
| Hardware | CPU/RAM/kernel/filesystem context is available. Pinned core set and storage-device identity were not recorded: **BLOCKED**. |

The ≥1.05× median-gain rule also requires ≥3 alternating pairs, each arm within ±5% of its median, and improvement beyond measured host noise. Primary has three alternating pairs, but its maximum run deviations are: off replay **56.2% / 10.1%** (v5/v6), full replay **21.9% / 73.4%**, and rebuild wall **18.0% / 10.6%**. All 12 comparable successful primary HTTP cells fail the two-arm stability condition; v6 run-median deviations span **13.2–23.7%**. No independent host-noise measurement was retained. Dense has only one pair. Thus observed request-latency reductions do not satisfy formal promotion acceptance.

Non-target guards require ≤3% median and ≤5% p99 regression with repeated-run uncertainty. They are not a pass: recorded primary full-index medians increase CPU by 11.1%, RSS by 8.6% and allocated index bytes by 42.1%; rebuilt index bytes increase 56.0%. Dense costs are larger but n=1. Three run samples cannot establish a reliable p99 guard or confidence interval. Missing identities, insufficient tails and absent uncertainty remain **BLOCKED**, not a skip. Nested/concurrent intervals have not been summed.

| Corpus | Height range / stop | Stop hash | Manifest SHA-256 |
|---|---|---|---|
| primary | 0–1105; stop 1105 | `15a33ccfcab6e729e11b9fe8df330bcc50b0f71904236f8e900c364a2b795276` | `967b030b20e5be91852894b908c2a6fb540abbbc3c8652baa24b319a92a2a78a` |
| dense | 0–205; stop 205 | `52d83de080edfbdcf4995b4714f5eaf7f436542e5d7802e560824b034fc64968` | `2a71d5f400581d3bd20a2ca2ad74a800d60f7571cd2886b026c9e05c27184577` |

## Primary: 3 alternating repetitions

Each arm/cell has n=3 run samples. Cells show p50 [min–max]; empirical nearest-rank p95=p99=max is the right-hand value of every bracket. Tail resolution at n=3 is very low. Timings vary materially, so small wall-time differences do not establish an overall replay/rebuild speedup or regression.

| Metric | v5 seconds | v6 seconds |
|---|---:|---:|
| Index-off replay | 4.501 [4.486–7.030] | 4.885 [4.689–5.377] |
| Full-index replay | 18.758 [14.646–18.973] | 19.067 [18.121–33.062] |
| Full replay: process start → index ready | 19.979 [15.170–20.099] | 20.466 [19.176–34.012] |
| Fresh rebuild: process start → index ready | 1.399 [1.268–1.650] | 1.357 [1.246–1.501] |

| Mode / metric | v5 | v6 |
|---|---:|---:|
| off: CPU seconds to ready | 0.480 [0.470–0.480] | 0.490 [0.480–0.500] |
| off: RSS HWM MiB to ready | 48.672 [48.551–50.719] | 48.820 [48.574–49.047] |
| off: Stopped index allocated file MiB | 0.000 [0.000–0.000] | 0.000 [0.000–0.000] |
| off: Process write_bytes MiB to ready | 22.086 [22.086–22.086] | 22.086 [22.086–22.086] |
| full: CPU seconds to ready | 0.810 [0.740–0.810] | 0.900 [0.830–0.930] |
| full: RSS HWM MiB to ready | 64.191 [60.887–65.195] | 69.719 [66.090–71.898] |
| full: Stopped index allocated file MiB | 3.434 [3.426–3.434] | 4.879 [4.879–4.883] |
| full: Process write_bytes MiB to ready | 26.184 [26.078–26.188] | 27.645 [27.637–27.699] |
| rebuild: CPU seconds to ready | 0.080 [0.060–0.080] | 0.080 [0.080–0.090] |
| rebuild: RSS HWM MiB to ready | 78.301 [76.230–79.875] | 80.746 [80.637–82.773] |
| rebuild: Stopped index allocated file MiB | 2.582 [2.582–2.582] | 4.027 [4.027–4.027] |
| rebuild: Process write_bytes MiB to ready | 2.699 [2.699–2.699] | 4.145 [4.145–4.145] |

## Dense control: one matched pair

Each arm/cell has n=1, so its displayed value is empirical p50=p95=p99=max. These are single-pair observations, not distribution or tail estimates. The v5 index-off seed replay was 2.053 s (CPU to ready 5.20 s); it is retained as setup/control evidence, not a paired off comparison.

| Mode / metric | v5 | v6 | Change |
|---|---:|---:|---:|
| full: Replay seconds | 2.239 | 2.393 | +6.9% |
| full: Process start → ready seconds | 2.853 | 2.977 | +4.4% |
| full: CPU seconds to ready | 6.260 | 6.610 | +5.6% |
| full: RSS HWM MiB to ready | 434.543 | 551.289 | +26.9% |
| full: Stopped index allocated file MiB | 58.090 | 143.797 | +147.5% |
| full: Process write_bytes MiB to ready | 179.895 | 265.605 | +47.6% |
| rebuild: Process start → ready seconds | 1.126 | 1.439 | +27.8% |
| rebuild: CPU seconds to ready | 0.800 | 1.200 | +50.0% |
| rebuild: RSS HWM MiB to ready | 455.703 | 749.812 | +64.5% |
| rebuild: Stopped index allocated file MiB | 44.414 | 131.633 | +196.4% |
| rebuild: Process write_bytes MiB to ready | 44.723 | 131.934 | +195.0% |

## Warm HTTP request latency

The tables are recomputed from the 30 retained raw samples per run, pooled by workload/mode/script/cursor/arm after excluding three warmups. p50 is the median; p95/p99 use nearest rank ceil(p×n); max is the literal maximum. Primary n=90 (3 runs), dense n=30 (1 run), so empirical p99 equals max. This is not a precise 99th-percentile estimate. The unchanged aggregate/earlier CSV summaries retain their median-of-run statistics; these tables expose the raw-sample distribution instead. Formal stability was evaluated separately on run medians. A 503 value is rejection latency, never a successful-page speedup.

### primary / full

| History | Cursor | n / arm | v5 status | v5 p50 / p95 / p99 / max ms | v6 status | v6 p50 / p95 / p99 / max ms |
|---:|---|---:|---|---:|---|---:|
| 100 | first | 90 | 200 | 2.629 / 2.844 / 3.096 / 3.096 | 200 | 0.831 / 0.981 / 1.362 / 1.362 |
| 100 | middle | 90 | 200 | 2.648 / 2.826 / 3.246 / 3.246 | 200 | 0.825 / 0.990 / 1.045 / 1.045 |
| 100 | unknown | 90 | 200 | 2.621 / 2.875 / 3.743 / 3.743 | 200 | 0.821 / 0.916 / 1.182 / 1.182 |
| 1,000 | first | 90 | 200 | 19.357 / 20.553 / 22.736 / 22.736 | 200 | 0.348 / 0.407 / 0.594 / 0.594 |
| 1,000 | middle | 90 | 200 | 19.743 / 21.018 / 21.941 / 21.941 | 200 | 0.697 / 0.860 / 1.000 / 1.000 |
| 1,000 | unknown | 90 | 200 | 19.228 / 20.222 / 21.598 / 21.598 | 200 | 0.304 / 0.378 / 0.497 / 0.497 |
| 10,000 | first | 90 | 503 budget | 39.343 / 39.962 / 40.421 / 40.421 | 200 | 0.273 / 0.365 / 0.456 / 0.456 |
| 10,000 | middle | 90 | 503 budget | 39.505 / 41.122 / 47.754 / 47.754 | 200 | 0.663 / 0.896 / 1.060 / 1.060 |
| 10,000 | unknown | 90 | 503 budget | 39.273 / 39.775 / 47.970 / 47.970 | 200 | 0.275 / 0.371 / 0.583 / 0.583 |

### primary / rebuild

| History | Cursor | n / arm | v5 status | v5 p50 / p95 / p99 / max ms | v6 status | v6 p50 / p95 / p99 / max ms |
|---:|---|---:|---|---:|---|---:|
| 100 | first | 90 | 200 | 2.822 / 2.974 / 3.019 / 3.019 | 200 | 0.822 / 0.922 / 1.320 / 1.320 |
| 100 | middle | 90 | 200 | 2.618 / 2.979 / 3.542 / 3.542 | 200 | 0.825 / 0.896 / 1.446 / 1.446 |
| 100 | unknown | 90 | 200 | 2.288 / 2.435 / 2.778 / 2.778 | 200 | 0.823 / 0.882 / 0.984 / 0.984 |
| 1,000 | first | 90 | 200 | 15.584 / 16.953 / 17.145 / 17.145 | 200 | 0.399 / 0.442 / 0.467 / 0.467 |
| 1,000 | middle | 90 | 200 | 15.982 / 17.424 / 17.856 / 17.856 | 200 | 0.818 / 0.888 / 1.391 / 1.391 |
| 1,000 | unknown | 90 | 200 | 15.593 / 16.983 / 17.133 / 17.133 | 200 | 0.390 / 0.452 / 0.625 / 0.625 |
| 10,000 | first | 90 | 503 budget | 31.193 / 33.044 / 35.450 / 35.450 | 200 | 0.327 / 0.396 / 0.491 / 0.491 |
| 10,000 | middle | 90 | 503 budget | 30.925 / 31.461 / 32.253 / 32.253 | 200 | 0.674 / 0.840 / 0.923 / 0.923 |
| 10,000 | unknown | 90 | 503 budget | 30.620 / 31.375 / 31.560 / 31.560 | 200 | 0.286 / 0.358 / 0.395 / 0.395 |

### dense / full

| History | Cursor | n / arm | v5 status | v5 p50 / p95 / p99 / max ms | v6 status | v6 p50 / p95 / p99 / max ms |
|---:|---|---:|---|---:|---|---:|
| 100 | first | 30 | 200 | 3.030 / 3.532 / 3.543 / 3.543 | 200 | 0.640 / 0.704 / 1.259 / 1.259 |
| 100 | middle | 30 | 200 | 3.037 / 3.463 / 3.974 / 3.974 | 200 | 0.633 / 0.681 / 0.690 / 0.690 |
| 100 | unknown | 30 | 200 | 3.100 / 3.457 / 3.610 / 3.610 | 200 | 0.608 / 0.694 / 1.358 / 1.358 |
| 1,000 | first | 30 | 200 | 19.461 / 20.234 / 20.453 / 20.453 | 200 | 0.619 / 0.656 / 0.665 / 0.665 |
| 1,000 | middle | 30 | 200 | 19.481 / 20.347 / 21.718 / 21.718 | 200 | 0.626 / 0.722 / 0.728 / 0.728 |
| 1,000 | unknown | 30 | 200 | 19.462 / 20.839 / 21.557 / 21.557 | 200 | 0.620 / 0.709 / 0.912 / 0.912 |
| 10,000 | first | 30 | 503 budget | 33.913 / 34.159 / 34.717 / 34.717 | 200 | 0.624 / 0.646 / 0.653 / 0.653 |
| 10,000 | middle | 30 | 503 budget | 33.849 / 34.198 / 37.302 / 37.302 | 200 | 0.628 / 0.633 / 0.637 / 0.637 |
| 10,000 | unknown | 30 | 503 budget | 33.972 / 36.362 / 37.048 / 37.048 | 200 | 0.622 / 0.697 / 0.716 / 0.716 |

### dense / rebuild

| History | Cursor | n / arm | v5 status | v5 p50 / p95 / p99 / max ms | v6 status | v6 p50 / p95 / p99 / max ms |
|---:|---|---:|---|---:|---|---:|
| 100 | first | 30 | 200 | 2.739 / 3.580 / 3.675 / 3.675 | 200 | 0.688 / 0.725 / 0.847 / 0.847 |
| 100 | middle | 30 | 200 | 2.777 / 3.386 / 3.478 / 3.478 | 200 | 0.708 / 0.768 / 1.263 / 1.263 |
| 100 | unknown | 30 | 200 | 2.843 / 3.237 / 3.542 / 3.542 | 200 | 0.678 / 0.720 / 0.730 / 0.730 |
| 1,000 | first | 30 | 200 | 17.890 / 18.034 / 18.059 / 18.059 | 200 | 0.684 / 0.695 / 0.698 / 0.698 |
| 1,000 | middle | 30 | 200 | 18.034 / 18.625 / 18.771 / 18.771 | 200 | 0.684 / 0.691 / 0.693 / 0.693 |
| 1,000 | unknown | 30 | 200 | 18.042 / 18.823 / 18.999 / 18.999 | 200 | 0.681 / 0.701 / 0.732 / 0.732 |
| 10,000 | first | 30 | 503 budget | 31.512 / 33.007 / 33.239 / 33.239 | 200 | 0.694 / 0.749 / 0.750 / 0.750 |
| 10,000 | middle | 30 | 503 budget | 31.483 / 32.914 / 35.475 / 35.475 | 200 | 0.699 / 0.730 / 0.740 / 0.740 |
| 10,000 | unknown | 30 | 503 budget | 31.673 / 32.409 / 32.966 / 32.966 | 200 | 0.693 / 0.748 / 0.767 / 0.767 |

## Interpretation and limits

The measured benefit is bounded page availability and much less warm-query work, purchased with larger durable index files and higher dense rebuild CPU/RSS/write cost. Rebuild wall time includes process startup and chainstate opening. Filesystem bytes are the sum of stopped files’ st_blocks × 512, excluding directory metadata; they are neither device-level amplification nor a peak allocation measurement. CPU/RSS/I/O snapshots are taken at readiness. The OS page cache was not dropped, and the synthetic scripts perform no signature verification. These measurements do not establish mainnet cost or an overall rebuild speedup.

## Retained observations

[Raw observations and aggregate](script-history-v6-20261011.json) contain all 23 run records, source/binary/corpus/raw-result hashes, metric ranges, status/response identities and all 4,320 retained HTTP nanosecond samples. The `http_raw_ns` arrays align with `aggregate.request_runs`; the JSON describes the reconstruction order and preserves every error. Exact reconstruction against all 4,320 parsed source CSV rows was verified. Pilot results are excluded; the slow initial run and every budget rejection are retained.

The original aggregate uses medians of per-run request summaries. The HTTP tables above use pooled raw observations, as described in their methodology. Both are retained without replacing or dropping samples. The JSON also records the original aggregate and HTTP CSV digests.

The full derived index was opened on fresh databases for replay. Rebuild runs cloned a completed, index-disabled database before timing and started with full indexing. Each indexed run checked first, middle-cursor and unknown-cursor requests to `/api/scripthash/{hash}/txs/chain[/<cursor>]` for histories of 100, 1,000 and 10,000 transactions. Three warmups precede 30 retained requests per case, over a persistent loopback HTTP connection. Corpus transactions use 34-byte anyone-can-spend scripts and spend prior-block outputs; they do not model signature cost or mainnet workload distribution.
