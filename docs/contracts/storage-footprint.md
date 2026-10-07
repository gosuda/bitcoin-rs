# Storage footprint evidence boundary

Storage measurement is an offline benchmark utility, not a node runtime
capability or a storage auditing subsystem. Owner:
`tools/storage-footprint` (Layer 4). It has no node, storage, or backend
dependencies and never opens a database.

## FP-01: Snapshot numbers

On Linux, the utility reports total apparent bytes and allocated bytes
(`st_blocks * 512`), with a breakdown by top-level data-directory entry.
Directory metadata and loose files are included. Hard links are counted once
by device/inode; the lexicographically first visited path owns their bytes.
In `bitcoin-rs-storage-allocation-v1`, the reserved `namespaces` key `"."`
contains only the root directory's own bytes. Each other key contains the bytes
of that top-level entry and its descendants, subject to hard-link deduplication.
Summing all namespace values, including `"."`, reproduces each total.
Apparent bytes are filesystem lengths, **not** serialized logical KV bytes;
do not add apparent and allocated totals.

## FP-02: Offline operating conditions

Stop the node and all other writers before running the tool. Use a trusted,
quiescent directory on one filesystem. The walk refuses observed symlinks,
special entries, and mount crossings, but is not descriptor-anchored,
race-resistant, or a custody/security boundary. A changing directory can
produce an inconsistent observation. No database constructor, flush,
compaction, migration, or file write is performed.

## FP-03: Separate command and platform

```sh
cargo run --locked -p bitcoin-rs-storage-footprint -- /path/to/stopped-node \
  > /path/outside-stopped-node/footprint.json
```

The output path must be outside the measured directory. Shell redirection
creates or truncates its target before the utility starts; placing that file
inside the input tree would change the snapshot being measured.

JSON uses `bitcoin-rs-storage-allocation-v1`. Linux is the only supported
measurement platform. On other platforms the package compiles and exits with
an explicit unsupported-platform error. The production binary accepts no
`--measure-storage*` or `--storage-high-water-bytes` options and performs no
measurement-specific build identity work.
`getblockchaininfo.size_on_disk` keeps its existing block-file apparent-size
meaning.

## FP-04: Evidence limits

This is a point-in-time snapshot and a lower bound on peak disk allocation.
It does not run IBD, prove a full-tip identity, measure compaction amplification,
or decide a storage budget verdict. The benchmark/release workflow must record
the measured revision, build/profile, backend, network, enabled indexes,
stop height/hash, filesystem, and workload alongside the JSON. Peak allocation
requires independently captured filesystem/quota high-water evidence.

Logical backend/index scans, cross-platform parity, forensic traversal,
and automated budget certification are not implemented. Add them only for an
actual evidence consumer, outside production behavior.

## Verification

`tools/storage-footprint/src/linux.rs` tests metadata-based allocation (including
sparse files where supported), hard-link
deduplication, namespace totals, unchanged file contents and namespace inventory,
and refusal of symlinks and special entries. The isolated-consumer g17 gate
proves the old storage measurement module is absent from the production API.
