# Storage footprint contract

The normative contract for custody-grade data-directory storage evidence.
`getblockchaininfo.size_on_disk` remains the block-file apparent-length field
it already is. This collector is a separate, explicit measurement command.

Owners:
- Physical walk and logical column-family scan: `crates/storage/src/footprint.rs`
- Evidence envelope, identity, namespace inventory, and budget verdict:
  `crates/node/src/storage_footprint.rs`
- Default-lane full-tip conservative high-water evidence:
  `bin/bitcoin-rs/tests/overhaul_storage_evidence.rs`
- Command: `bin/bitcoin-rs --measure-storage`

## Clauses

### `FP-01`: Two ledgers, never summed

- The **logical owner ledger** records exact serialized key and value bytes for
  each column family and for framed flat block files. It explains data-model
  growth. It does not claim filesystem allocation.
- The **physical namespace ledger** records allocated filesystem blocks
  (`st_blocks * 512`) for each top-level data-directory namespace. Backend
  metadata, WAL or journal files, compaction residue, and migration temporaries
  are explicit categories or an unattributed residual. Root-level files live in
  `residual`.
- The two ledgers must not be added together. The physical namespace ledger is the source
  of the data-directory budget (`PhysicalLedger::data_directory_allocated_bytes`).
- Hard links, sparse files, and engine-reserved space require correct
  accounting. A final `du`-style snapshot is a lower bound on peak allocation
  and cannot prove the peak gate.

### `FP-02`: Custody-grade physical collection

- Traversal is anchored at one opened data-directory descriptor
  (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`). Child opens use `openat`
  from that descriptor (`O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`).
  Pathname re-resolution is not used after the root is open.
- Symlinks are rejected, including a data-directory path that is itself a
  symlink.
- Mount crossings (`st_dev` differs from the root) are rejected, including
  child directory opens used by logical scans after the physical walk.
- Hard links are counted once by `(device, inode)`.
- Collection walks the tree twice and rejects the observation if any path's
  identity or allocated size changed.
- A FIFO, device, or other non-file/non-directory inode is rejected
  (`UnsupportedEntry`) after `fstatat` and again after `openat`/`fstat`, so a
  replacement between those calls cannot stall the walk or be counted as data.
- Witness sidecar reads are bounded to the recovery 4 KiB evidence limit. An
  oversized current file is ignored and `.prev` is tried.
- A snapshot is a measured lower bound on peak allocation
  (`observation_kind = snapshot_lower_bound`). A create, allocate, or delete
  peak can hide between samples.
- A passing sub-1-TB result requires a pinned stop identity,
  `observation_kind = conservative_high_water` from an isolated filesystem or
  project quota (`--storage-high-water-bytes`), and that peak must be at least
  the snapshot. The conservative high-water must cover compaction, restart,
  reorg, and migration where applicable.

### `FP-03`: Explicit measurement command

- The collector is invoked with `bitcoin-rs --measure-storage`. It does not
  start P2P, RPC, or index workers. It is not an RPC method, background
  scanner, or dashboard.
- Empty `chainstate/` or index directories are not opened. Opening a backend
  creates missing column families; an empty directory is left untouched so
  measurement does not initialize storage.
- Logical key-value scans open `chainstate/` and index directories as child
  directory descriptors of the same anchor. Backends that still take a pathname
  are pointed at the already-opened descriptor (`/proc/self/fd/N` on Linux).
- `--measure-storage-stop-height` and `--measure-storage-stop-hash` must be
  supplied together. The hash is a 64-character RPC big-endian hex block hash.
  The pair pins the intended stop identity for this run; it does not itself
  prove that the data directory reached that tip.
- Each record uses format `bitcoin-rs-storage-footprint-v1` and includes the
  resolved configuration, network, stop height and hash, whether that stop was
  pinned, backend, enabled indexes, cache budget, compiled feature set,
  package version, git commit when available, rustc identity, `Cargo.lock`
  SHA-256, running binary identity, and all index watermarks.
- Local replay remains diagnostic and cannot satisfy the live full-tip
  acceptance gate.

### `FP-04`: Default unpruned peak budget

- The default configuration is unpruned fjall with `txindex`, `scriptindex`,
  and `blockfilterindex` disabled. Its live full-tip peak allocated
  data-directory bytes must remain at or below `1_000_000_000_000` decimal
  bytes.
- That gate applies only to a mainnet default-lane record with a conservative
  high-water from an isolated filesystem or project quota and a pinned stop
  identity. Verdicts are:
  - `pass`: default lane, pinned stop, conservative high-water less than or
    equal to 1 TB.
  - `fail`: default lane and budget figure greater than 1 TB.
  - `tip_unpinned`: default lane and conservative high-water less than or
    equal to 1 TB, but no pinned stop pair.
  - `snapshot_insufficient`: default lane, budget figure less than or equal to
    1 TB, but no conservative high-water.
  - `inapplicable`: any other network, backend, prune target, or index lane.
- A high-water value cannot produce `pass` on an empty or mid-sync data
  directory that has no pinned stop. The 1 TB figure is the named budget, not
  a measured IBD result. This command does not run IBD.
- Supported unpruned index combinations (`txindex`, `scriptindex=utxo`,
  `scriptindex=full`, and both together) use the same evidence format and are
  classified by `identity.index_lane`. This contract does not presume they fit
  the default 1-TB budget. `blockfilterindex` is recorded as disabled until
  that namespace exists.
- If the default configuration cannot meet the budget without changing its
  observable contract, stop and document the blocking namespace and
  conservative lower bound before proposing that contract change. Never discard
  witness data, silently prune a supposedly unpruned profile, or hide
  temporary files to meet the number.

## Proven by

- `bin/bitcoin-rs/tests/overhaul_storage_evidence.rs` (planned): full-tip
  default-lane physical budget evidence. Pass requires default unpruned fjall,
  pinned mainnet stop, conservative high-water from an isolated filesystem or
  quota, and separate logical owner and physical namespace ledgers.
- `crates/storage/tests/overhaul_atomic_durability.rs` (planned): atomic batch
  durability and compaction behavior, including engine WAL and temporary file
  accounting.
- `crates/node/tests/overhaul_streaming_reorg.rs` (planned): reorg memory and
  storage bounds, including retained undo and body extents.
- `crates/node/tests/overhaul_checkpoint_independence.rs` (planned): migration
  and fresh-replay storage footprint, including no legacy checkpoint residue.
- `crates/storage/tests/storage_footprint.rs` existing unit tests:
  - `logical_owner_bytes_are_exact_key_plus_value`;
  - `physical_ledger_uses_allocated_blocks_not_apparent_length`;
  - `hard_links_are_counted_once`;
  - `symlink_is_rejected`;
  - `high_water_below_snapshot_is_rejected`;
  - `ledgers_are_not_summed_by_the_physical_total`.
- `crates/node/src/storage_footprint/tests.rs` contract tests (see the clause map at the top of that module):
  - `default_regtest_record_is_inapplicable_to_the_mainnet_budget`;
  - `conservative_high_water_can_pass_the_default_mainnet_budget`;
  - `snapshot_of_default_mainnet_is_insufficient_for_the_peak_gate`;
  - `high_water_above_budget_fails_the_default_mainnet_gate`;
  - `empty_chainstate_directory_is_not_created_as_a_store`;
    - `unpinned_high_water_is_tip_unpinned_not_pass`;
    - `stop_height_without_hash_is_rejected`;
    - `stop_hash_without_height_is_rejected`;
    - `invalid_stop_hash_is_rejected`;
    - `oversized_current_witness_falls_back_to_prev`;
    - `identity_names_the_txindex_lane`;
    - `logical_chainstate_rows_are_named_owners`.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
conservative high-water, physical namespace ledger, logical owner ledger.
