# Storage footprint evidence boundary

Storage measurement is an offline benchmark tool.
It is not a node runtime feature or a storage audit system.
Owner: `tools/storage-footprint` (Layer 4).
The tool has no node, storage, or backend dependencies.
It never opens a database.

## FP-01: Snapshot numbers
- On Linux, the utility reports total apparent bytes and allocated bytes (`st_blocks * 512`).
- The report includes a breakdown by top-level data-directory entry.
- Directory metadata and loose files MUST be included.
- The tool counts hard links once by device/inode.
- The path visited first in lexicographical order owns the bytes.
- In `bitcoin-rs-storage-allocation-v1`, the reserved `namespaces` key `"."` contains only the root directory bytes.
- Each other key contains the bytes of that top-level entry and its child entries.
- Each other key follows hard-link deduplication.
- Summing all namespace values, including `"."`, reproduces each total.
- Apparent bytes are filesystem lengths, **not** serialized logical KV bytes.
- Operators MUST NOT add apparent and allocated totals together.

## FP-02: Offline operating conditions
- Operators MUST stop the node and all other writer processes before running the tool.
- Run the tool on a trusted, quiescent directory on one filesystem.
- The file walk refuses detected symlinks, special entries, and mount crossings.
- The walk is not descriptor-anchored.
- The walk is not race-resistant.
- The walk is not a custody or security boundary.
- A changing directory can cause an inconsistent measurement.
- The tool MUST NOT construct databases, flush data, compact data, migrate data, or write files.

## FP-03: Separate command and platform
```sh
cargo run --locked -p bitcoin-rs-storage-footprint -- /path/to/stopped-node \
  > /path/outside-stopped-node/footprint.json
```
- The output path MUST be outside the measured directory.
- Shell redirection creates or truncates the target file before the utility starts.
- An output path inside the input tree will change the measured snapshot.
- The JSON output format MUST use `bitcoin-rs-storage-allocation-v1`.
- Linux is the only supported measurement platform.
- On other platforms, the package compiles and exits with an explicit unsupported-platform error.
- The production binary accepts no `--measure-storage*` or `--storage-high-water-bytes` options.
- The production binary performs no measurement-specific build identity work.
- `getblockchaininfo.size_on_disk` retains its existing block-file apparent-size meaning.

## FP-04: Evidence limits
- This measurement is a point-in-time snapshot.
- The measurement is a lower bound on peak disk allocation.
- The tool does not execute IBD.
- The tool does not prove a full-tip identity.
- The tool does not measure compaction amplification.
- The tool does not decide a storage budget verdict.
- The benchmark or release workflow MUST record the measured revision, build/profile, backend, network, enabled indexes, stop height/hash, filesystem, and workload alongside the JSON report.
- Peak allocation requires independently captured filesystem or quota high-water evidence.
- The tool does not implement logical backend or index scans, cross-platform parity, forensic traversal, or automated budget certification.
- Add these capabilities only for an actual evidence consumer outside production behavior.

## Verification
- `tools/storage-footprint/src/linux.rs` tests metadata-based allocation, including sparse files where supported.
- `tools/storage-footprint/src/linux.rs` tests hard-link deduplication and namespace totals.
- The tests verify unchanged file contents and unchanged namespace inventory.
- The tests verify refusal of symlinks and special entries.
- The isolated-consumer g17 gate proves that the production API does not include the old storage measurement module.
