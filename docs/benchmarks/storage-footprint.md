# Storage footprint evidence

This document owns the storage footprint evidence for the target node. The normative contract is [`docs/contracts/storage-footprint.md`](../contracts/storage-footprint.md) (`FP-01` through `FP-04`). The final campaign belongs to T39 and is recorded in `overhaul-full-tip-storage.md` when T39 creates it; this page states the campaign contract and retains the prior synthetic-corpus evidence. Backend comparison and compression evidence below is candidate evidence for the backend choice; it is not full-tip proof.

## Cell it owns

The default-lane physical peak of a data directory during fresh replay to the pinned mainnet stop identity, plus the per-owner logical ledger that explains it.

## Campaign contract (T39, gate G11)

| Field | Required value | Status |
|---|---|---|
| Profile | Default unpruned fjall | fixed |
| Optional indexes | `txindex` off, `scriptindex` off, `blockfilterindex` off | fixed |
| Stop identity | Pinned mainnet height and block hash, recorded before the run | `UNMEASURED` |
| Filesystem | Isolated filesystem or project quota; conservative high-water captured by the quota, not by a `du` snapshot | fixed |
| Lifecycle covered | Sync, compaction, restart, reorg, migration where applicable | fixed |
| Physical high-water budget | `<= 1_000_000_000_000` decimal bytes (`PhysicalLedger::data_directory_allocated_bytes`, `FP-04`) | required |
| Logical ledger | Separate per-owner serialized bytes (`FP-01`); never added to the physical ledger | fixed |
| Baseline | T02 captures the original candidate's physical high-water on the matched workload before the T14 authority cut; T39 compares the final integrated binary against it and must not exceed it | `UNMEASURED` |
| Verdict | pending | `planned_not_executed` |

A `du`-style snapshot is a lower bound on the peak and cannot prove the peak gate. Snapshot-only, wrong-lane, hidden-migration-file or unpinned-stop evidence cannot pass. If the physical high-water exceeds budget, rank dominant owners from the logical ledger, repair the dominant owner (duplicate retention, stale retention, oversized metadata, excess amplification), and rerun the full campaign. Never discard witness data, silently prune a supposedly unpruned profile or hide temporary files to meet the number. Hard links, sparse files and engine-reserved space are accounted per `FP-02`.

Physical categories: body segments, undo segments, chainstate files, engine WAL, journals, compaction and migration temporaries, optional indexes, logs, residuals. Logical categories: serialized keys and values and framing overhead by owner.

## Verdict machine

`bin/bitcoin-rs/tests/overhaul_storage_evidence.rs` passes only for default-lane unpruned fjall, pinned stop, isolated-filesystem peak and separate logical and physical ledgers; anything else fails closed.

```bash
cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_storage_evidence -- --nocapture
```

## Related cells

| Cell | Owner | Status |
|---|---|---|
| Backend write amplification on the synthetic ten-family corpus (retained harness `crates/storage/examples/storage_footprint.rs`) | `crates/storage` | prior evidence only, see below |
| T02 original-candidate physical high-water, matched workload | T02 collector | `UNMEASURED` |
| T14 candidate full-tip storage check before authority cutover | T14 | `planned_not_executed` |
| T39 final integrated campaign | T39 | `planned_not_executed` |

## Required identities per sample

Every sample in this cell records six identities. The T02 collector rejects a sample that lacks any of them; a rejected sample is not evidence.

| Identity | Content |
|---|---|
| Artifact | SHA-256 of the exact binary, library or image measured; source commit |
| Configuration | Resolved `NodeConfig`, feature set, allocator, validation mode |
| Corpus | Corpus digest, height range, stop height and stop hash |
| Durability | Backend, batch mode (`write`, `write_deferred`, `write_durable`), flush and sync posture |
| Toolchain | `rustc 1.95.0`, edition 2024, profile, enabled features |
| Hardware | CPU model, pinned core set, memory, storage device, OS kernel |

## Acceptance rule

- Promotion of a candidate over its control requires a median gain of at least 1.05x over at least three alternating candidate/control runs. Each arm stays within 5% of its own median. The improvement must exceed the observed host noise.
- Non-target cells guard at no more than 3% median regression and no more than 5% p99 regression, measured with repeated runs and reported uncertainty. Average-only reporting never passes.
- Report p50, p95, p99 and max with the sample count. Never sum nested intervals. Never sum concurrent intervals. Parallel worker walls and inclusive stage histograms are reported beside the process wall, not added to it.
- Retain raw samples beside every summary. A Criterion adaptive elapsed total is not a median source.
- A missing binary, corpus, hardware target or digest marks the cell `BLOCKED` with the missing identity named. `BLOCKED` is never a pass and never a skip.

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement. The section `Prior candidate evidence` below is historical and unchanged; it does not prove any end-state cell.

## Prior candidate evidence (2026-09-02 and 2026-09-04 synthetic corpus)

Retained verbatim from the pre-rewrite document. Headings are demoted one level. Nothing below is end-state proof.

The compression-fix comparison was measured on 2026-09-02 at branch
`overhaul/one-session` commit `b0e0935` against the empty-`Spending`
(`12+0`) corpus. Current-format (`Spending 12+8`) totals were remeasured on
2026-09-04 from `crates/storage/examples/storage_footprint.rs`.

### What was measured

The on-disk footprint of each storage backend after writing a fixed synthetic
corpus across all ten column families, forcing memtable flush to SST files
(fjall), and measuring the total bytes occupied on disk.

The measurement harness is `crates/storage/examples/storage_footprint.rs`:

```text
cargo run -p bitcoin-rs-storage --example storage_footprint --release --features fjall,redb,rocksdb -- [backend]
```

### Corpus

| Parameter | Value |
|---|---|
| Index rows per CF | 200,000 |
| Block-body rows | 5,000 |
| Undo rows | 5,000 |
| Block-body value size | 16,384 B (16 KiB) |
| Undo value size | 256 B |
| Index CF key/value sizes | TxConfirmed 12+8, TxMempool 5+4, BlockHeaders 80+0, Funding 12+8, Spending 12+8, Coinstats 12+8, BlockTree 37+0, UtxoMeta 16+8 |
| Block-body key size | 37 B |
| **Logical data size** | **129,570,000 B (123.57 MiB)** |

The corpus is synthetic: deterministic keys and values with a fixed pattern
(0xa5 for block bodies, 0xb3 for undo, pseudo-random for index rows). It is
designed to complete in under a minute and to trigger fjall's 64 MiB memtable
flush in the block-bodies keyspace so that SST files are produced rather than
all data remaining in the pre-allocated journal.

The historical compression-fix tables below used `Spending 12+0` and a
logical size of **127,970,000 B (122.04 MiB)**. They are kept so the LZ4
change stays matched to the corpus it was measured on.

### Results

#### Current format (`Spending 12+8`)

Remeasured 2026-09-04 with the harness above.

| Backend | Total on-disk | Logical | Write amplification |
|---|---:|---:|---:|
| **fjall (default)** | **86,728,585 B (82.71 MiB)** | 129,570,000 B (123.57 MiB) | **0.669x** |
| redb | 269,488,128 B (257.00 MiB) | 129,570,000 B (123.57 MiB) | 2.080x |

RocksDB was not remeasured here: this environment cannot compile
`rust-librocksdb-sys` (`cstdint` headers missing). Its last published total
(134,671,921 B) belongs to the empty-`Spending` corpus below.

#### Historical empty-`Spending` corpus (`12+0`, commit `b0e0935`)

##### Before compression fix

| Backend | Total on-disk | Logical | Write amplification |
|---|---:|---:|---:|
| fjall (default) | 207,497,732 B (197.89 MiB) | 127,970,000 B (122.04 MiB) | 1.621x |
| redb | 269,488,128 B (257.00 MiB) | 127,970,000 B (122.04 MiB) | 2.106x |
| rocksdb | 134,671,921 B (128.43 MiB) | 127,970,000 B (122.04 MiB) | 1.052x |

##### After compression fix

| Backend | Total on-disk | Logical | Write amplification |
|---|---:|---:|---:|
| **fjall (default)** | **85,858,577 B (81.88 MiB)** | 127,970,000 B (122.04 MiB) | **0.671x** |
| redb | 269,488,128 B (257.00 MiB) | 127,970,000 B (122.04 MiB) | 2.106x |
| rocksdb | 134,671,921 B (128.43 MiB) | 127,970,000 B (122.04 MiB) | 1.052x |

The fjall default backend dropped from **197.89 MiB to 81.88 MiB** — a **58.6%
reduction**. The amplification went from 1.621x to 0.671x because the synthetic
corpus is highly compressible (16 KiB blocks of repeated bytes).

Positioned `Spending` values add 1,600,000 logical bytes. On this hardware
that raised fjall's after-fix total from 85,858,577 B to 86,728,585 B
(0.671x → 0.669x). Redb's preallocated file did not grow.

#### Fjall per-column-family breakdown (current `Spending 12+8`)

| Column family | On-disk (bytes) | On-disk (KiB) |
|---|---:|---:|
| spending | 2,525,017 | 2,465.84 |
| undo_data | 2,362,913 | 2,307.53 |
| utxo_meta | 2,330,815 | 2,276.19 |
| tx_mempool | 2,330,811 | 2,276.18 |
| block_tree | 2,330,808 | 2,276.18 |
| coinstats | 2,330,707 | 2,276.08 |
| funding | 2,264,330 | 2,211.26 |
| block_bodies | 1,881,810 | 1,837.71 |
| block_headers | 110,138 | 107.56 |
| tx_confirmed | 18,935 | 18.49 |
| **Journal** | **67,108,864** | **65,536.00** |

The 64 MiB journal is a fixed pre-allocation; it does not grow with data.
Keyspace directories are mapped to column-family names by sorted directory
order, so per-CF attribution is a harness convenience, not a durable
identity.

### What was wrong

Fjall's default `KeyspaceCreateOptions` uses a compression policy of
`[None, None, Lz4]` — LZ4 compression only on the last level (level 2+). L0
and L1 data blocks are stored uncompressed. For a node whose working set lives
in L0 (small chain, recently written data, or data that has not yet compacted
to the final level), all on-disk data is uncompressed.

RocksDB, by contrast, applies LZ4 compression on every level
(`DBCompressionType::Lz4` set on both `db_options` and `cf_options`).

The empty-`Spending` measurement exposed this: fjall's 1.621x amplification
versus rocksdb's 1.052x was almost entirely due to the missing L0/L1
compression. The current-format per-CF breakdown shows the `spending` CF
(12-byte keys, 8-byte values) consuming 2,525,017 bytes for 200k rows.

### What was fixed

`FjallStore::open_with_cache` now creates each keyspace with
`CompressionPolicy::all(CompressionType::Lz4)`, applying LZ4 compression on
every level. This matches RocksDB's configuration and the fjall `lz4` feature
that the workspace already enables.

The fix is in `crates/storage/src/fjall_impl.rs`. No other backend was changed.

### How it was checked

- `crates/storage/tests/backend_equivalence.rs`: 2 tests, all green.
- `crates/storage/tests/backend_metrics.rs`: 2 tests, all green.
- `crates/storage/tests/prune_then_reorg.rs`: 3 tests, all green.
- `crates/storage/tests/cache_budget.rs`: 4 tests, all green.
- `cargo clippy -p bitcoin-rs-storage --features fjall -- -D warnings`: clean.
- Current-format remeasure: `storage_footprint` release, features `fjall` and
  `fjall,redb` (2026-09-04).

### What is not claimed

- The corpus is synthetic. Real block data (transactions, scripts) has
  different compressibility. The 0.669x amplification is specific to this
  corpus's repeated-byte pattern; real data will see a smaller but still
  significant reduction.
- Redb was not tuned. Redb does not expose a compression configuration in
  its current API; its 2.080x amplification is the engine's baseline on the
  current corpus.
- The 64 MiB journal pre-allocation is unchanged. It is a fixed overhead
  that does not grow with data, and is recycled as memtables flush.
- RocksDB per-CF breakdown is not available from the filesystem because
  RocksDB can use a single directory for all CFs depending on configuration.
