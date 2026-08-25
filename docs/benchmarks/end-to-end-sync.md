# End-to-end sync benchmarks

> **Evidence status:** This page publishes completed historical runs and their raw JSON. All numbers and artifacts below reflect historical runs performed prior to the Task 16 cutover, where `bitcoinkernel` (`libbitcoinkernel`) became the default production consensus engine across `bitcoin-rs-consensus`, `bitcoin-rs-node`, and `bitcoin-rs`.
>
> The obsolete `bitcoinconsensus` backend was removed in Task 16 after fresh mainnet IBD stopped at block 938344 (exposing missing complete prevouts and unsupported Taproot script-path verification in the portable path). Default builds now require system dependencies (`cmake` and `libboost-dev`).
>
> Historical `bitcoinconsensus` and early experimental `kernel` numbers published here serve as historical records and are non-comparable with kernel-default production builds. No full-tip (height 957,600+) live IBD run or G14 performance-gate pass has been completed under the landed kernel default. Final performance claims remain pending fresh measurements.

The machine-readable attachments preserve every recorded field and stage timer. The source artifacts do not record the exact command line, compiler flags, CPU affinity, cache state, host identity, exit code, or replication count. Those missing fields prevent a reproducible controlled claim.

## Completed machine-readable runs

| Run | Range | Validation | Block source | Commit | Elapsed | Throughput | Peak RSS | Raw artifact |
|---|---:|---|---|---|---:|---:|---:|---|
| Current-campaign control, 0–150,000 | 0–150,000 | Full (`assume_valid_height=0`) | `bitcoin-cli` | `9ce0727` | 88.667s | 1,691.726 blocks/s | 301.6 MiB | [`rs-parprep-current-control-r1.json`](data/end-to-end-sync/rs-parprep-current-control-r1.json) |
| Current-campaign candidate, 0–150,000 | 0–150,000 | Full (`assume_valid_height=0`) | `bitcoin-cli` | `9ce0727` | 96.732s | 1,550.684 blocks/s | 308.2 MiB | [`rs-parprep-current-candidate-r2.json`](data/end-to-end-sync/rs-parprep-current-candidate-r2.json) |
| Long local replay, 0–642,000 | 0–642,000 | Assume-valid through 642,000 | `legacy-fjall-chainstate` | `9ce0727` | 2h 43m 58.256s | 65.256 blocks/s | 6.827 GiB | [`rs-spendable-local-nobody-a014.json`](data/end-to-end-sync/rs-spendable-local-nobody-a014.json) |
| Inferred `parverify` full-validation replay, 0–150,000 | 0–150,000 | Full (`assume_valid_height=0`) | `rest` | `3023eb0` | 296.211s | 506.399 blocks/s | 2.210 GiB | [`rs-replay-150k-parverify.json`](data/end-to-end-sync/rs-replay-150k-parverify.json) |
| Inferred `kernel` full-validation replay, 0–150,000 | 0–150,000 | Full (`assume_valid_height=0`) | `rest` | `fb2227e` | 232.208s | 645.977 blocks/s | 2.219 GiB | [`rs-replay-150k-kernel.json`](data/end-to-end-sync/rs-replay-150k-kernel.json) |

All five artifacts pass these structural checks: schema `mainnet-prefix-replay-v1`, genesis start hash, positive elapsed time and throughput, non-empty stage list, and `block_count = stop_height - start_height + 1`.

## Same-range observations

The two current-campaign 150,000-block files share the same recorded commit, height and hash window, `bitcoin-cli` source, fjall backend, and full-validation posture. The files do not record the command or treatment that distinguishes “candidate” from “control.” Each is a single run:

- Candidate elapsed time was **9.096% higher** than control (96.732s vs 88.667s).
- Candidate throughput was **8.337% lower** (1550.684 vs 1691.726 blocks/s).
- Candidate peak RSS was **2.190% higher** (308.2 MiB vs 301.6 MiB).

These are observed differences only. They do not establish a regression, a causal treatment effect, or a population mean.

The older `parverify` and `kernel` replays share the 0–150,000 range, REST source, full-validation posture, and stop hash, but use different commits and the `kernel`/`parverify` engine labels are inferred from filenames and run notes, not recorded Cargo features. They are useful historical results, not a controlled A/B. The 642,000-block replay uses an assume-valid posture and a local legacy fjall chainstate, so it is not comparable to either 150,000-block group.

## Historical live-network results

These values were recorded in campaign verdict notes, not in the attached JSON. Their raw logs remain outside the repository, so this table is an index, not immutable evidence.

| Run | Range | Validation posture | Elapsed | Source note |
|---|---:|---|---:|---|
| gocoin live IBD | 0–150,000 | Historical scripts skipped | ~277s | `cross-node-ibd-150k-verdict.md` |
| Bitcoin Core 31.0 live IBD | 0–150,000 | Default assume-valid | 628s | `cross-node-ibd-150k-verdict.md` |
| bitcoin-rs single-peer live IBD (`8f98e42`) | 0–150,000 | Full script verification | 5,332.2s | `cross-node-ibd-150k-verdict.md` |
| bitcoin-rs multi-peer portable #1 (`71db91d`) | 0–150,000 | Full script verification | 810.1s | `rs-ibd-150k-multipeer-verdict.md` |
| bitcoin-rs multi-peer portable #2 (`71db91d`) | 0–150,000 | Full script verification | 801.5s | `rs-ibd-150k-multipeer-verdict.md` |
| bitcoin-rs kernel | 0–150,000 | Full script verification | 369.5s | `rs-ibd-150k-multipeer-verdict.md` |
| bitcoin-rs kernel | 0–150,000 | Assume-valid through 150,000 | 359.5s | `rs-ibd-150k-multipeer-verdict.md` |

The live runs were sequential single samples. Peer conditions and validation posture differ across implementations. Do not use the table as a controlled cross-node ranking.

## Excluded incomplete evidence

| Artifact | Observed range | Why it is excluded |
|---|---:|---|
| `rs-curated-current-r1.log` | Partial | The run stopped on the v3 snapshot limit at a transaction with 440 live outputs. |
| `fixed-fulltip-rss.csv` | 18,987–645,804 | RSS sampling ended before the target; peak was 14,503,188 KiB. There is no completed sync timing. |
| `rs-full-tip-20260727.log` | 0–957,600 attempt | The run rejected the height-957,600 header because its nBits did not match the locally computed retarget. |
| Bitcoin Core full-tip comparator | — | No completed, provenance-bound comparator artifact exists. |

Later code changed both failed bitcoin-rs paths, but no completed rerun is attached. This report does not infer results from those fixes.

## Historical performance evidence

| Budget | Required evidence | Status in this publication |
|---|---|---|
| IBD throughput | bitcoin-rs faster than Bitcoin Core on one identical window | Bounded 0–150,000 one-peer daemon IBD: Core median 73.459s vs bitcoin-rs 89.576s; Core delivered 1.219× bitcoin-rs throughput; gate and 2× target failed |
| UTXO commit p95 | ≤50ms for serialized blocks ≥1MB | Not captured |
| Tip RSS | ≤16GiB with fjall and txindex | Bounded txindex-only RSS: 313.1MB; completed current-tip evidence not captured |

These historical measurements do not establish a current performance claim.

## Bounded current evidence

A disk-bounded campaign at commit `de8001e83bd4e09077d4cebbbdd23d0cebade194`
used the exact mainnet range 0–150,000. Both implementations used full validation,
the same stop hash, and CPU set 0–31. Core used three byte-identical restores;
bitcoin-rs used one immutable framed archive and a fresh output directory per run.
The bitcoin-rs processing runs enforced active 16 GiB RSS and disk-reserve guards.

| Workload | bitcoin-rs median | Bitcoin Core 31.1 median | Core / bitcoin-rs | Result |
|---|---:|---:|---:|---|
| Full-validation local replay / chainstate reindex | 39.251s | 64.922s | 1.654× | Faster, below the 2× target |
| Whole benchmark process wall | 42.025s | 67.023s | 1.595× | Faster, below the 2× target |
| Historical transaction-index catch-up | 18.416s | 15.064s | 0.818× | Context only; the indexed contracts differ |

The campaign accepts the measured 1.654× production replay result rather than weakening
validation, persistence, crash recovery, or reorg-availability semantics to claim 2×.

The transaction-index comparison is not workload parity. Bitcoin Core stores
transaction lookup positions. bitcoin-rs also stores confirmed headers, funding,
spending, and script-history rows for RPC and ScriptIndex queries. A nine-run bitcoin-rs
row-limit sweep retained the 1,000,000-row limit. The 250,000-, 500,000-, 2,000,000-,
and 4,000,000-row candidates, plus the Fjall `bytes_1` feature-only and
`bytes_1`-plus-owned-value candidates, failed the required 1.05× throughput gate.
Every bitcoin-rs TxIndex run produced the same logical digest.

The full corpus, treatment, binary, timing, memory, free-space, restore, and rejected
candidate custody is in
[`bounded-performance-custody-v1.json`](data/end-to-end-sync/bounded-performance-custody-v1.json).
The campaign retained one bounded corpus root with one canonical archive per
implementation and deleted each disposable fixture before the next run. These bounded
results do not satisfy the live-IBD or current-tip RSS gates above.

## Bounded daemon IBD comparison

A bounded daemon IBD benchmark compared bitcoin-rs and Bitcoin Core over mainnet blocks 0–150,000. Both nodes ran under full validation (`assume_valid_height=0`), P2P v1 transport, and CPU set 0–31 on an Intel Xeon Gold 6138 host. One local Bitcoin Core seed at `127.0.0.1:18444` ran on CPU set 32–39, pre-warmed with 747,001,853 bytes per arm. The run executed three interleaved matched blocks with 30s cooldowns, fresh output directories, 16 GiB RSS limits, and 64 GiB disk-reserve guards.

| Implementation | Arm 1 | Arm 2 | Arm 3 | Median | Throughput vs Core | Result |
|---|---:|---:|---:|---:|---:|---|
| Bitcoin Core 31.1 | 73.456s | 73.459s | 73.463s | 73.459s | 1.000× | Baseline |
| bitcoin-rs (`9dae9e0`) | 89.696s | 89.576s | 88.465s | 89.576s | 0.820× | Core is 1.219× faster; 2× target failed |

Bitcoin Core median elapsed time was 73.458771289s. bitcoin-rs median elapsed time was 89.576018374s. Core's elapsed time was 0.820071852× bitcoin-rs's elapsed time, which means Core delivered 1.219405345× bitcoin-rs throughput. The requested twofold target is not met.

Every run reached the exact height 150,000 endpoint (block hash `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b`, chainwork `0000000000000000000000000000000000000000000000080560a73313fe59c2`) and exited with code 0. All runs passed the 16 GiB RSS guard, 64 GiB disk reserve, and fixture bounds.

### Limitations

- The range ends at height 150,000 and does not represent SegWit, Taproot, or current-tip peer conditions.
- Both nodes downloaded from one local warmed seed. The benchmark measures single-peer request and apply throughput, not Internet bandwidth aggregation across peers.
- The checked-in custody condenses external raw summaries; SHA-256 digests bind omitted arm files.
- ARM parity remains unmeasured because no OpenSSH ARM host alias was available.

### Follow-up outcomes (not landed)

- The `w256` window experiment measured 59.225400502s against a matched 89.972329151s control (1.519151046× speedup). It did not land because the temporary code lacked required safety gates and missed the pre-declared header-read threshold.
- The PGO (`w128`) candidate measured 89.266232737s (1.003470356× wall ratio vs the 89.576018374s baseline) and was rejected below the 1.05× continuation threshold.
- The eight-proxy same-seed run measured 115.429379346s (28.861922467% slower than the one-peer median) and was rejected as topology reconnaissance only.

The complete machine-readable custody is in [`daemon-ibd-custody-v1.json`](data/end-to-end-sync/daemon-ibd-custody-v1.json).

## Raw artifact integrity

| Artifact | SHA-256 |
|---|---|
| `rs-parprep-current-control-r1.json` | `9abe40cf9c9992ec82e36e4cfceef3f9839519e9437c48096fbe14b7ac91200c` |
| `rs-parprep-current-candidate-r2.json` | `2bf227a0892d7420f1d18600665fdef3e23c2502f1e7e6d0a77908e99394dc44` |
| `rs-spendable-local-nobody-a014.json` | `a464e6f6d7c29037c451720e0cbe924340ed7d85c51634c01ecfd25c3ee70339` |
| `rs-replay-150k-parverify.json` | `f1704f895a958afcf5fcce2f829954056e9864af87bf4f0483c29af36599ac29` |
| `rs-replay-150k-kernel.json` | `d722ab149c39c5f13e18c6358ab999f4c1f44ce46b37a9d0eb87bfd45e0b91a9` |
| `bounded-performance-custody-v1.json` | `ce3e561dbd2119579f359b7cf55f8b84211c4c1eec3953cf40762f07faabb3cf` |
| `daemon-ibd-custody-v1.json` | `3eb68821cb2e389be5ed5391f5671fae527212a0e2129fcb85fe9676e4d396c8` |

## Full recorded stage timers

### Current-campaign control, 0–150,000

Artifact: [`rs-parprep-current-control-r1.json`](data/end-to-end-sync/rs-parprep-current-control-r1.json). Stage timers are nested and are not additive.

| Stage | Samples | Sum (seconds) |
|---|---:|---:|
| `node.apply_block.total_seconds` | 150,001 | 84.801977 |
| `node.apply_block.script_verify_seconds` | 150,001 | 62.555284 |
| `node.apply_block.script_parallel_seconds` | 67,891 | 47.642603 |
| `node.apply_block.script_verify_serial_overlay_seconds` | 23,883 | 35.562514 |
| `node.apply_block.script_verify_parallel_seconds` | 44,008 | 26.990047 |
| `node.apply_block.script_prepare_seconds` | 67,891 | 10.599645 |
| `node.apply_block.block_body_persist_seconds` | 150,001 | 3.999155 |
| `node.apply_block.utxo_commit_seconds` | 150,001 | 3.567193 |
| `node.apply_block.block_rules_seconds` | 150,001 | 2.814207 |
| `node.apply_block.script_resolution_seconds` | 67,891 | 2.214619 |
| `node.apply_block.coinbase_maturity_seconds` | 150,001 | 1.254240 |
| `node.apply_block.bip30_bip34_seconds` | 150,001 | 0.470652 |
| `node.apply_block.block_tree_insert_seconds` | 150,001 | 0.431863 |
| `node.apply_block.utxo_changes_seconds` | 150,001 | 0.353395 |
| `node.apply_block.block_record_seconds` | 150,001 | 0.223474 |
| `node.apply_block.pow_self_consistency_seconds` | 150,001 | 0.201392 |
| `node.apply_block.pow_limit_continuity_seconds` | 150,001 | 0.011291 |
| `node.apply_block.coin_stats_finish_seconds` | 150,001 | 0.008771 |
| `node.apply_block.mempool_evict_seconds` | 150,001 | 0.007505 |
| `node.apply_block.bip68_seconds` | 150,001 | 0.003535 |
| `node.apply_block.script_verify_coinbase_only_seconds` | 82,110 | 0.002723 |
| `node.apply_block.tx_index_ingest_seconds` | 150,001 | 0.001598 |
| `node.apply_block.filter_index_seconds` | 150,001 | 0.001587 |

### Current-campaign candidate, 0–150,000

Artifact: [`rs-parprep-current-candidate-r2.json`](data/end-to-end-sync/rs-parprep-current-candidate-r2.json). Stage timers are nested and are not additive.

| Stage | Samples | Sum (seconds) |
|---|---:|---:|
| `node.apply_block.total_seconds` | 150,001 | 91.968297 |
| `node.apply_block.script_verify_seconds` | 150,001 | 63.885183 |
| `node.apply_block.script_parallel_seconds` | 67,891 | 47.510260 |
| `node.apply_block.script_verify_serial_overlay_seconds` | 23,883 | 35.028582 |
| `node.apply_block.script_verify_parallel_seconds` | 44,008 | 28.854061 |
| `node.apply_block.script_prepare_seconds` | 67,891 | 10.500164 |
| `node.apply_block.utxo_commit_seconds` | 150,001 | 4.511884 |
| `node.apply_block.block_body_persist_seconds` | 150,001 | 4.481974 |
| `node.apply_block.block_rules_seconds` | 150,001 | 3.785610 |
| `node.apply_block.script_resolution_seconds` | 67,891 | 2.643068 |
| `node.apply_block.coinbase_maturity_seconds` | 150,001 | 1.567006 |
| `node.apply_block.bip30_bip34_seconds` | 150,001 | 0.546041 |
| `node.apply_block.block_tree_insert_seconds` | 150,001 | 0.483378 |
| `node.apply_block.utxo_changes_seconds` | 150,001 | 0.431770 |
| `node.apply_block.block_record_seconds` | 150,001 | 0.257847 |
| `node.apply_block.pow_self_consistency_seconds` | 150,001 | 0.215109 |
| `node.apply_block.pow_limit_continuity_seconds` | 150,001 | 0.016594 |
| `node.apply_block.coin_stats_finish_seconds` | 150,001 | 0.008255 |
| `node.apply_block.mempool_evict_seconds` | 150,001 | 0.007421 |
| `node.apply_block.bip68_seconds` | 150,001 | 0.004973 |
| `node.apply_block.script_verify_coinbase_only_seconds` | 82,110 | 0.002540 |
| `node.apply_block.tx_index_ingest_seconds` | 150,001 | 0.001991 |
| `node.apply_block.filter_index_seconds` | 150,001 | 0.001938 |

### Long local replay, 0–642,000

Artifact: [`rs-spendable-local-nobody-a014.json`](data/end-to-end-sync/rs-spendable-local-nobody-a014.json). Stage timers are nested and are not additive.

| Stage | Samples | Sum (seconds) |
|---|---:|---:|
| `node.apply_block.total_seconds` | 642,001 | 8059.159316 |
| `node.apply_block.block_rules_seconds` | 642,001 | 2039.301487 |
| `node.apply_block.script_verify_seconds` | 642,001 | 1943.241413 |
| `node.apply_block.script_verify_serial_overlay_seconds` | 485,284 | 1928.596318 |
| `node.apply_block.coinbase_maturity_seconds` | 642,001 | 1020.566237 |
| `node.apply_block.utxo_commit_seconds` | 642,001 | 516.351932 |
| `node.apply_block.utxo_changes_seconds` | 642,001 | 153.322363 |
| `node.apply_block.bip68_seconds` | 642,001 | 60.704908 |
| `node.apply_block.script_verify_parallel_seconds` | 67,761 | 14.639742 |
| `node.apply_block.bip30_bip34_seconds` | 642,001 | 4.441685 |
| `node.apply_block.block_tree_insert_seconds` | 642,001 | 3.910462 |
| `node.apply_block.block_record_seconds` | 642,001 | 2.328662 |
| `node.apply_block.pow_self_consistency_seconds` | 642,001 | 1.034622 |
| `node.apply_block.pow_limit_continuity_seconds` | 642,001 | 0.161123 |
| `node.apply_block.coin_stats_finish_seconds` | 642,001 | 0.114629 |
| `node.apply_block.mempool_evict_seconds` | 642,001 | 0.065607 |
| `node.apply_block.block_body_persist_seconds` | 642,001 | 0.039602 |
| `node.apply_block.filter_index_seconds` | 642,001 | 0.024323 |
| `node.apply_block.tx_index_ingest_seconds` | 642,001 | 0.007908 |
| `node.apply_block.script_verify_coinbase_only_seconds` | 88,956 | 0.005354 |

### Portable full-validation replay, 0–150,000

Artifact: [`rs-replay-150k-parverify.json`](data/end-to-end-sync/rs-replay-150k-parverify.json). Stage timers are nested and are not additive.

| Stage | Samples | Sum (seconds) |
|---|---:|---:|
| `node.apply_block.total_seconds` | 150,001 | 260.021664 |
| `node.apply_block.script_verify_seconds` | 150,001 | 200.689497 |
| `node.apply_block.script_verify_serial_overlay_seconds` | 23,883 | 104.980515 |
| `node.apply_block.script_verify_parallel_seconds` | 44,008 | 95.696341 |
| `node.apply_block.block_body_persist_seconds` | 150,001 | 12.856825 |
| `node.apply_block.utxo_commit_seconds` | 150,001 | 9.405604 |
| `node.apply_block.block_rules_seconds` | 150,001 | 5.625090 |
| `node.apply_block.bip30_bip34_seconds` | 150,001 | 4.099814 |
| `node.apply_block.coinbase_maturity_seconds` | 150,001 | 2.833531 |
| `node.apply_block.block_tree_insert_seconds` | 150,001 | 1.202297 |
| `node.apply_block.block_record_seconds` | 150,001 | 0.683129 |
| `node.apply_block.pow_self_consistency_seconds` | 150,001 | 0.601723 |
| `node.apply_block.utxo_changes_seconds` | 150,001 | 0.564916 |
| `node.apply_block.pow_limit_continuity_seconds` | 150,001 | 0.039707 |
| `node.apply_block.coin_stats_finish_seconds` | 150,001 | 0.023684 |
| `node.apply_block.mempool_evict_seconds` | 150,001 | 0.023110 |
| `node.apply_block.script_verify_coinbase_only_seconds` | 82,110 | 0.012641 |
| `node.apply_block.bip68_seconds` | 150,001 | 0.009737 |
| `node.apply_block.tx_index_ingest_seconds` | 150,001 | 0.005914 |
| `node.apply_block.filter_index_seconds` | 150,001 | 0.005016 |

### Kernel full-validation replay, 0–150,000

Artifact: [`rs-replay-150k-kernel.json`](data/end-to-end-sync/rs-replay-150k-kernel.json). Stage timers are nested and are not additive.

| Stage | Samples | Sum (seconds) |
|---|---:|---:|
| `node.apply_block.total_seconds` | 150,001 | 196.261907 |
| `node.apply_block.script_verify_seconds` | 150,001 | 139.759901 |
| `node.apply_block.script_verify_serial_overlay_seconds` | 23,883 | 73.483969 |
| `node.apply_block.script_verify_parallel_seconds` | 44,008 | 66.267093 |
| `node.apply_block.block_body_persist_seconds` | 150,001 | 12.451361 |
| `node.apply_block.utxo_commit_seconds` | 150,001 | 8.972705 |
| `node.apply_block.block_rules_seconds` | 150,001 | 5.568082 |
| `node.apply_block.bip30_bip34_seconds` | 150,001 | 2.841842 |
| `node.apply_block.coinbase_maturity_seconds` | 150,001 | 2.674502 |
| `node.apply_block.block_tree_insert_seconds` | 150,001 | 1.227567 |
| `node.apply_block.block_record_seconds` | 150,001 | 0.676566 |
| `node.apply_block.utxo_changes_seconds` | 150,001 | 0.565663 |
| `node.apply_block.pow_self_consistency_seconds` | 150,001 | 0.550318 |
| `node.apply_block.pow_limit_continuity_seconds` | 150,001 | 0.036331 |
| `node.apply_block.coin_stats_finish_seconds` | 150,001 | 0.022794 |
| `node.apply_block.mempool_evict_seconds` | 150,001 | 0.019616 |
| `node.apply_block.bip68_seconds` | 150,001 | 0.010170 |
| `node.apply_block.script_verify_coinbase_only_seconds` | 82,110 | 0.008839 |
| `node.apply_block.tx_index_ingest_seconds` | 150,001 | 0.006004 |
| `node.apply_block.filter_index_seconds` | 150,001 | 0.004790 |

## Harness

The attached JSON was emitted by `crates/node/examples/mainnet_prefix_replay.rs`. The artifacts record the range, boundary hashes, backend, index flags, source kind, data directory, elapsed/fetch/decode time, block and transaction counts, peak RSS, commit, and stage timers. They do not capture enough launch or host state to reconstruct the exact original command. A future publishable G14 run must use the repository G14 daemon adapters and evidence manifest instead of reconstructing missing provenance from these files.
