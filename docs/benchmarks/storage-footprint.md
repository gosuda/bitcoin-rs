# Storage backend on-disk footprint

The compression-fix comparison was measured on 2026-09-02 at branch
`overhaul/one-session` commit `b0e0935` against the empty-`Spending`
(`12+0`) corpus. Current-format (`Spending 12+8`) totals were remesured on
2026-09-04 from `crates/storage/examples/storage_footprint.rs`.

## What was measured

The on-disk footprint of each storage backend after writing a fixed synthetic
corpus across all ten column families, forcing memtable flush to SST files
(fjall), and measuring the total bytes occupied on disk.

The measurement harness is `crates/storage/examples/storage_footprint.rs`:

```text
cargo run -p bitcoin-rs-storage --example storage_footprint --release --features fjall,redb,rocksdb -- [backend]
```

## Corpus

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

## Results

### Current format (`Spending 12+8`)

Remesured 2026-09-04 with the harness above.

| Backend | Total on-disk | Logical | Write amplification |
|---|---:|---:|---:|
| **fjall (default)** | **86,728,585 B (82.71 MiB)** | 129,570,000 B (123.57 MiB) | **0.669x** |
| redb | 269,488,128 B (257.00 MiB) | 129,570,000 B (123.57 MiB) | 2.080x |

RocksDB was not remesured here: this environment cannot compile
`rust-librocksdb-sys` (`cstdint` headers missing). Its last published total
(134,671,921 B) belongs to the empty-`Spending` corpus below.

### Historical empty-`Spending` corpus (`12+0`, commit `b0e0935`)

#### Before compression fix

| Backend | Total on-disk | Logical | Write amplification |
|---|---:|---:|---:|
| fjall (default) | 207,497,732 B (197.89 MiB) | 127,970,000 B (122.04 MiB) | 1.621x |
| redb | 269,488,128 B (257.00 MiB) | 127,970,000 B (122.04 MiB) | 2.106x |
| rocksdb | 134,671,921 B (128.43 MiB) | 127,970,000 B (122.04 MiB) | 1.052x |

#### After compression fix

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

### Fjall per-column-family breakdown (current `Spending 12+8`)

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

## What was wrong

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

## What was fixed

`FjallStore::open_with_cache` now creates each keyspace with
`CompressionPolicy::all(CompressionType::Lz4)`, applying LZ4 compression on
every level. This matches RocksDB's configuration and the fjall `lz4` feature
that the workspace already enables.

The fix is in `crates/storage/src/fjall_impl.rs`. No other backend was changed.

## How it was checked

- `crates/storage/tests/backend_equivalence.rs`: 2 tests, all green.
- `crates/storage/tests/backend_metrics.rs`: 2 tests, all green.
- `crates/storage/tests/prune_then_reorg.rs`: 3 tests, all green.
- `crates/storage/tests/cache_budget.rs`: 4 tests, all green.
- `cargo clippy -p bitcoin-rs-storage --features fjall -- -D warnings`: clean.
- Current-format remesure: `storage_footprint` release, features `fjall` and
  `fjall,redb` (2026-09-04).

## What is not claimed

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
