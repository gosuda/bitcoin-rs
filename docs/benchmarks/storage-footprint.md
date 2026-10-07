# Storage footprint benchmark evidence

Use the offline Linux tool described in
[the measurement boundary](../contracts/storage-footprint.md). Capture a
stopped-node allocation snapshot with:

```sh
cargo run --locked -p bitcoin-rs-storage-footprint -- /path/to/data-dir > footprint.json
```

Record the revision/build, backend, network, index configuration, pinned stop
height/hash, and workload beside the output. Compare matched runs. Filesystem
apparent bytes are not logical serialized data-model bytes.

Current priorities are actual IBD time, final database size, peak disk use,
compaction amplification, restart/reorg behavior, and backend comparisons.
A final allocation snapshot alone does not measure any peak or certify a
mainnet storage budget. Capture peak usage independently in the owning
benchmark workflow; do not silently prune, discard witness data, or hide
temporary files to meet a target.

## Prior backend-choice evidence

The 2026-09-04 synthetic corpus measured 129,570,000 logical bytes
(`Spending 12+8`), with filesystem-length totals of 86,728,585 bytes for fjall
and 269,488,128 bytes for redb. These are historical synthetic numbers, not
mainnet evidence and not allocated-byte measurements from the current tool.

The earlier compression comparison at `b0e0935` used the different
127,970,000-byte corpus (`Spending 12+0`): fjall's total fell from
207,497,732 to 85,858,577 bytes with LZ4 at every level. Highly repetitive
values explain the compression; no real-block reduction is claimed.
The synthetic harness and detailed tables remain in Git history.
`crates/storage/src/fjall_impl.rs` still owns the compression policy.

The following historical per-family table remains the source of the
fixture-scale comparisons in `scriptindex-format.md`; it is not a current
allocation report.

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

Full-tip/peak results remain unmeasured here. There is no in-tree footprint
verdict machine or planned harness presented as implemented evidence.
