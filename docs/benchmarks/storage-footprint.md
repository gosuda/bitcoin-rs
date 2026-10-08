# Storage footprint benchmark evidence

Use the offline Linux tool described in
[the measurement boundary](../contracts/storage-footprint.md). Capture a
stopped-node allocation snapshot with:

```sh
cargo run --locked -p bitcoin-rs-storage-footprint -- /path/to/data-dir \
  > /path/outside-data-dir/footprint.json
```

Keep the output outside the measured directory so shell redirection does not
create or truncate a file inside the snapshot before measurement starts.

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

Full-tip/peak results remain unmeasured here. There is no in-tree footprint
verdict machine or planned harness presented as implemented evidence.
