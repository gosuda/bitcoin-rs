# Storage footprint benchmark evidence

Measure with the offline Linux tool under [the measurement boundary](../contracts/storage-footprint.md):

```sh
cargo run --locked -p bitcoin-rs-storage-footprint -- /path/to/data-dir \
  > /path/outside-data-dir/footprint.json
```

Put the output outside the measured directory. Shell redirection creates or truncates its target before the tool starts, so a file inside the input tree would change the snapshot.

Record the revision and build beside the output. Record the backend, the network, the index configuration, the pinned stop height and hash, and the workload. Compare matched runs only.

Apparent bytes are file lengths. They are not logical serialized bytes. Allocated bytes are the filesystem allocation (`st_blocks * 512`). A final snapshot measures no peak and certifies no mainnet storage budget. Capture peak use independently. Never prune data, drop witness data, or hide temporary files to reach a target. Current priorities: actual IBD time, final database size, peak disk use, compaction amplification, restart and reorg behavior, and backend comparisons.

## Classes in the report

The JSON object `classes` assigns every entry of the measured tree to one class. Each class reports apparent and allocated bytes. The three classes add up to `totals` in both units. The field set is additive to `bitcoin-rs-storage-allocation-v1`: `totals` and `namespaces` keep their earlier meaning.

The field `undo_attribution` states whether the tool separated undo bytes. `path_named_directory` means a path-named undo directory exists and its bytes are in `undo_data_named_dirs`. `unattributed_inside_kv` means no such directory exists, those bytes stay in `kv`, and the zero in `undo_data_named_dirs` is not an undo measurement. The tool never infers a family from a backend file name.

| Class | Contents |
|---|---|
| `block_files` | The `blocks` directory and everything below it. The tool walks each `blkNNNNN.dat` file as `BRSB` frames. |
| `undo_data_named_dirs` | Entries whose path holds a directory component named `undo_data`. Without such a directory, `undo_attribution` reports `unattributed_inside_kv` and the undo bytes stay in `kv`. |
| `kv` | All other entries. This class holds backend files, journals, checkpoints, loose files and directory metadata. |

`block_files` splits framed bytes into three fields. `payload_bytes` is the summed record body length. `framing_bytes` is 44 bytes for each record header. `unframed_bytes` is a tail that cannot start a complete record. The field `other_bytes` holds directory metadata and bytes outside frames, so the block-file fields add up to the class total.

The field `family_attribution` states the attribution rule: `path_named_family_directories`. The tool attributes a family only when the backend names a directory after that family. Fjall stores keyspaces in numeric directories (`keyspaces/<id>`) and keeps the name mapping inside keyspace 0. A fjall datadir therefore reports `undo_attribution: "unattributed_inside_kv"`, and the tool keeps those bytes inside `kv`. Read the undo numbers below as a separate store assessment, not as tool output.

A frame walk reads record headers and seeks over bodies. It reads no body byte. A frame counts only when its magic is `BRSB` and its claimed body fits the file. A stopped-writer tail therefore lands in `unframed_bytes`, and the storage owner truncates the same tail on open.

## Measured datadir

One datadir, one host, one run. Measured on 2026-10-31.

| Identity | Value |
|---|---|
| Revision | `59b1cff97fd802badecd5319321a3eb8fb68ef30` plus the uncommitted tool change of this step |
| Host | Linux 7.0.0-38-generic, 80 logical CPUs |
| Filesystem | ZFS, dataset `rpool/USERDATA/home_eq3uuw`, `compression=lz4`, `recordsize=128K` |
| Backend | fjall 3.1.12, LZ4-compressed data blocks |
| Network | mainnet blocks |
| Pinned stop | height 150000, hash `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b` |
| Indexes | `TX_LOOKUP` and `SCRIPT_LIVE` (`r00-p4-TX_AND_SCRIPTS`) |
| Datadir | `.outline/evidence/index-write-attr-20261025/scratch-c150-parent/iwa-20261026T145932-437673-9917f1/r00-p4-TX_AND_SCRIPTS/data` |
| Tool output | `/tmp/footprint-c150.json`, outside the datadir |
| Run wall time | 2.76 s for the final command, including cargo startup, with the binary already built |
| Tool undo state | `unattributed_inside_kv`; `undo_data_named_dirs` holds 0 bytes |

The search scanned the repository `.outline/` tree and `~/.cache/` for `CURRENT_SCHEMA` markers. It found 224 of them. It ranked the candidate directories that also hold a `blocks` directory by apparent size. This datadir is the largest candidate. Its apparent size is 1,660,866,929 bytes. The search did not cover every other tree under `/home/alpha`. A broader scan of `/home/alpha` stopped at its 700 s limit without a result.

## Class breakdown

| Class | Apparent bytes | Share of apparent | Allocated bytes | Share of allocated |
|---|---:|---:|---:|---:|
| `block_files` | 694,584,257 | 41.82% | 631,487,488 | 49.03% |
| `undo_data_named_dirs` | 0 | 0.00% | 0 | 0.00% |
| `kv` | 966,282,672 | 58.18% | 656,599,040 | 50.97% |
| Total | 1,660,866,929 | 100.00% | 1,288,086,528 | 100.00% |

ZFS `compression=lz4` writes less than the apparent length, so allocated bytes sit below apparent bytes for every class. Do not add the two totals.

Block-file split:

| Field | Bytes | Share of block files | Share of apparent total |
|---|---:|---:|---:|
| `payload_bytes` | 687,984,205 | 99.05% | 41.42% |
| `framing_bytes` | 6,600,044 | 0.95% | 0.40% |
| `unframed_bytes` | 0 | 0.00% | 0.00% |
| `other_bytes` | 8 | 0.00% | 0.00% |

The walk read 150,001 records. Each record has one 44-byte header, and the mean body is 4,587 bytes.

Per block file, as reported by the tool:

| File | Records | Payload bytes | Framing bytes | Apparent bytes |
|---|---:|---:|---:|---:|
| `blocks/blk00000.dat` | 119,210 | 128,902,880 | 5,245,240 | 134,148,120 |
| `blocks/blk00001.dat` | 11,835 | 133,676,835 | 520,740 | 134,197,575 |
| `blocks/blk00002.dat` | 5,697 | 133,945,707 | 250,668 | 134,196,375 |
| `blocks/blk00003.dat` | 5,674 | 133,954,366 | 249,656 | 134,204,022 |
| `blocks/blk00004.dat` | 6,395 | 133,913,688 | 281,380 | 134,195,068 |
| `blocks/blk00005.dat` | 1,190 | 23,590,729 | 52,360 | 23,643,089 |

Namespace breakdown from the same JSON:

| Namespace | Apparent bytes | Share of apparent | Allocated bytes | Share of allocated |
|---|---:|---:|---:|---:|
| `blocks` | 694,584,257 | 41.82% | 631,487,488 | 49.03% |
| `txindex` | 635,290,080 | 38.25% | 344,914,944 | 26.78% |
| `chainstate` | 246,604,524 | 14.85% | 243,069,952 | 18.87% |
| `chainstate-checkpoints` | 84,328,987 | 5.08% | 68,578,304 | 5.32% |
| `chainstate-journal` | 557 | 0.00% | 6,144 | 0.00% |
| Loose root files | 58,524 | 0.00% | 29,696 | 0.00% |

Two findings stand out. The index namespace is the second largest at 38.25% of apparent bytes, and the chainstate namespace is almost all undo data.

## Undo family assessment

The tool reports undo as unavailable for this backend: `undo_attribution` is `unattributed_inside_kv`, and the zero in `undo_data_named_dirs` is not an undo measurement. This assessment read the family from the store instead, on a copy of the datadir `chainstate` directory (`/tmp/fp-undo/chainstate`). It opened the copy with fjall 3.1.12 and issued reads only. The engine performs its own recovery and compaction on the copy, and the source datadir stays unchanged.

The store maps `undo_data` to keyspace 10 of 13 column families. The keyspace holds 150,001 rows. Each key is 37 bytes (`u` prefix, big-endian height, 32-byte block hash), so the key bytes total 5,550,037. The row values total 321,713,563 logical bytes.

| Quantity | Bytes |
|---|---:|
| Undo keyspace, apparent | 237,132,399 |
| Undo keyspace, allocated | 237,146,112 |
| Row values, logical | 321,713,563 |
| Row keys, logical | 5,550,037 |

At height 150,000 the undo family is 96.16% of the chainstate namespace by apparent bytes and 97.56% by allocated bytes. It is 14.28% of the datadir by apparent bytes and 18.41% by allocated bytes.

### zstd level 3 over undo records

Each row value was compressed alone with zstd level 3, through the `zstd` crate (0.13.3, bundled zstd 1.5.7). Compression ran once per value; decompression ran once per value and was checked byte for byte.

| Measurement | zstd level 3 | Uncompressed |
|---|---:|---:|
| Total bytes | 212,593,334 | 321,713,563 |
| Mean bytes per record | 1,417 | 2,145 |
| p50 bytes per record | 86 | 77 |
| p95 bytes per record | 8,317 | 13,031 |
| Maximum bytes per record | 93,189 | 468,380 |

Compression saves 109,120,229 logical bytes, or 33.92% of the row values. Both totals cover row values only. They exclude the 37-byte row keys.

The current physical undo keyspace is 237,146,112 allocated bytes for 321,713,563 logical value bytes. Fjall already compresses data blocks with LZ4, and that includes its own index and filter overhead. The 212,593,334-byte zstd figure is a logical sum of compressed values, not a filesystem result. It is therefore an upper bound on a zstd layout: the best case saving over the current keyspace is 24,552,778 bytes. That is 10.35% of the undo allocation, 1.91% of the datadir allocation, and 1.48% of the datadir apparent bytes. A like-for-like comparison needs the LZ4 payload size inside the engine, which an offline read cannot separate from the block, index and filter overhead.

Latency per undo record, measured in the same process, release build, warm cache, on a host shared with concurrent builds:

| Operation | Mean | p50 | p95 | p99 | Maximum |
|---|---:|---:|---:|---:|---:|
| Decompress | 3,364 ns | 469 ns | 16,368 ns | 30,303 ns | 4,935,255 ns |
| Compress | 30,742 ns | 12,987 ns | 123,658 ns | 244,907 ns | 4,196,356 ns |

## Smaller record header

A 12-byte header holds the magic, the body length and the height. It drops the 32-byte block hash. The 32 freed bytes for each of 150,001 records save 4,800,032 bytes.

| Basis | Saved bytes | Share |
|---|---:|---:|
| Block files, apparent | 4,800,032 | 0.69% |
| Datadir, apparent | 4,800,032 | 0.29% |
| Datadir, allocated | 4,800,032 | 0.37% |

An 8-byte header (magic and length only) frees 36 bytes per record and saves 5,400,036 bytes, or 0.78% of block-file apparent bytes. It also drops the height check.

### Body read latency

Each simulated read performs two positioned reads: the header prefix at the record start, then the body at record start plus 44. The 12-byte case reads a shorter prefix; the body read is identical. Each run covered all 150,001 records on a warm page cache, pinned to one CPU with `taskset -c 3`. Five runs of each header width, alternating.

| Run | 44-byte prefix mean | 44-byte prefix p50 | 12-byte prefix mean | 12-byte prefix p50 |
|---|---:|---:|---:|---:|
| 1 | 8,944 ns | 7,633 ns | 11,443 ns | 10,496 ns |
| 2 | 11,019 ns | 10,566 ns | 9,731 ns | 9,120 ns |
| 3 | 9,033 ns | 8,147 ns | 9,039 ns | 8,075 ns |
| 4 | 9,471 ns | 9,068 ns | 10,626 ns | 10,121 ns |
| 5 | 9,902 ns | 9,117 ns | 10,041 ns | 9,409 ns |

The paired differences change sign and range from -1,288 ns to +2,499 ns in the mean. That range matches the run-to-run spread, so the runs show no measurable read-time change from a shorter header. The case for a smaller header rests on the saved bytes alone.

## Decisions

| Layout | Decision | Reason |
|---|---|---|
| zstd level 3 over undo records | Reject | The best case saves 24,552,778 bytes, 1.91% of the datadir allocation. It needs an undo value format, a second codec beside the engine LZ4, and it adds 3,364 ns mean per undo read and 30,742 ns mean per undo write. |
| 12-byte record header | Reject | It saves 4,800,032 bytes, 0.37% of the datadir allocation. It removes the per-frame hash check that `FlatFileBlockReader` performs on every read, and it needs a block-file format migration. |

Reopen the undo compression question when the undo family passes 25% of the datadir allocation, or when the storage engine offers a codec choice that needs no per-value format. Reopen the header question only when another change already rewrites the block-file format.

The frame overhead itself is small. Framing is 0.95% of block-file apparent bytes at a mean body of 4,587 bytes. Keep the 44-byte header and its hash check.

## Evidence limits

This is a point-in-time snapshot of one datadir and a lower bound on peak allocation. The datadir stops at height 150,000 of mainnet, so it is not full-tip evidence. The run does not measure IBD time, compaction amplification, restart, or reorg cost. The undo assessment read a copy of one chainstate directory; it did not run the node. ZFS `compression=lz4` and `recordsize=128K` shape the allocated numbers, and another filesystem gives different ones. Report the filesystem with every allocated number.

Peak allocation needs independent filesystem or quota high-water evidence. Logical backend and index scans, cross-platform parity, and automated budget certification stay unimplemented. Add them only for an actual evidence consumer, outside production behavior.

## Prior backend-choice evidence

2026-09-04 synthetic corpus, 129,570,000 logical bytes (`Spending 12+8`): filesystem-length totals 86,728,585 bytes (fjall) and 269,488,128 bytes (redb), historical synthetic numbers, not mainnet evidence and not allocated-byte measurements from the current tool.

Earlier comparison at `b0e0935` on the different 127,970,000-byte corpus (`Spending 12+0`): fjall total fell from 207,497,732 to 85,858,577 bytes with LZ4 at every level (highly repetitive values; no real-block reduction claimed). Harness and detailed tables remain in Git history; compression policy is owned by `crates/storage/src/fjall_impl.rs`.

Full-tip and peak results remain unmeasured here. There is no in-tree footprint verdict machine.

## Tool checks

`tools/storage-footprint/src/frames.rs` tests the frame split against hand-built fixtures. The tests cover a complete file, an incomplete tail, a body shorter than its header claim, a foreign magic, and an empty file.

`tools/storage-footprint/src/linux.rs` tests the class accounting. The fixture holds one block file with two framed bodies, one undo row in a directory named `undo_data`, one KV file with a hard link, and known directory metadata. The test asserts the payload and framing split, the undo row attribution, one count for the hard link, and that the three classes partition both totals. It also asserts `path_named_directory` for that fixture, and `namespace_totals_match_and_measurement_leaves_files_unchanged` asserts `unattributed_inside_kv` for a fixture with no undo directory. The existing tests keep hard-link deduplication, namespace totals, unchanged file contents, depth refusal, and the refusal of symlinks and special entries.
