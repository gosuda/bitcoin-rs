# Database Migration Policy

This document defines the storage versioning, schema compatibility, and migration policy for `bitcoin-rs`.

## 1. Scope and Authority

This policy applies to all persistent storage surfaces in `bitcoin-rs`:
- Key-Value database backends (`crates/storage/src/trait_.rs`, `crates/storage/src/column_families.rs`).
- Append-only flat block files (`crates/storage/src/block_file.rs`).
- Binary UTXO snapshot artifacts (`crates/utxo/src/snapshot.rs`).
- Chainstate checkpoint directories and metadata (`crates/node/src/checkpoint.rs`).

## 2. Current On-Disk Storage Architecture

`bitcoin-rs` splits persistent data across four distinct storage mechanisms:

| Storage Surface | Implementation File | On-Disk Location | Version Indicator |
| :--- | :--- | :--- | :--- |
| Key-Value Storage | `crates/storage/src/column_families.rs` | Datadir root (`fjall`, `rocksdb`, `mdbx`, `redb`) | **None** (See Gap) |
| Flat Block Files | `crates/storage/src/block_file.rs` | `blocks/blkNNNNN.dat` | Magic `BRSB` (`0x42525342`), no version field |
| UTXO Snapshot | `crates/utxo/src/snapshot.rs` | `utxo-v4.dat` inside checkpoint directory | Magic `0x5554584F`, header version `4` |
| Chainstate Checkpoint | `crates/node/src/checkpoint.rs` | `chainstate-checkpoints/CURRENT` & `gen-N/` | Manifest `1`, Headers `1`, UTXO `4`, CoinStats `1` |

### 2.1 Key-Value Store Column Families
`KvStore` (`crates/storage/src/trait_.rs`) abstracts backend storage over ten fixed column families defined in `ColumnFamily` (`crates/storage/src/column_families.rs`):
- `TxConfirmed` (`0`)
- `TxMempool` (`1`)
- `BlockHeaders` (`2`)
- `Funding` (`3`)
- `Spending` (`4`)
- `Coinstats` (`5`)
- `BlockTree` (`6`)
- `UtxoMeta` (`7`)
- `BlockBodies` (`8`)
- `UndoData` (`9`)

Storage backends (`FjallStore` in `fjall_impl.rs`, `RocksDbStore` in `rocksdb_impl.rs`, `MdbxStore` in `mdbx_impl.rs`, and `RedbStore` in `redb_impl.rs`) create or open these ten tables on startup using `ColumnFamily::ALL`.

The BIP157/158 `Filters` (`5`) and `FilterHeaders` (`6`) families were removed
with the compact-filter index (issue #143). Their removal renumbered the
surviving discriminants, which is a breaking change under section 3.1: the
engines open tables by string name and ignore unknown retired tables, so
fjall, MDBX, and redb datadirs reopen unchanged, while a RocksDB datadir
written by a binary that still created the retired families must be wiped and
resynced per section 6.2 (RocksDB refuses to open a database unless every
existing column family is in the open set).

`UndoData` holds the per-block records a reorg needs to disconnect a block, keyed by `bitcoin_rs_pruning::block_undo_key` (height and block hash). It is canonical persistent state, not a cache: without a block's undo record the node cannot disconnect that block, so any schema or resync decision that discards it costs the ability to reorganise below the point it was discarded.

> **IDENTIFIED GAP:**
> The `KvStore` interface and database backends store **no schema version metadata** in database headers or dedicated version rows. Database engines open existing keyspaces or tables by string name (`ColumnFamily::name()`) without checking schema compatibility.

### 2.2 Flat Block Files
`FlatFileBlockStore` (`crates/storage/src/block_file.rs`) writes raw block bodies to `blocks/blkNNNNN.dat`. Each record begins with a 4-byte magic (`BLOCK_FILE_MAGIC` = `*b"BRSB"`), followed by record length and metadata. Individual files cap at 128 MiB (`BLOCK_FILE_MAX_BYTES`).

> **IDENTIFIED GAP:**
> Flat block files carry a record magic header, but lack a format version field.

### 2.3 Binary UTXO Snapshots
`crates/utxo/src/snapshot.rs` serializes and deserializes the UTXO set.
- `SnapshotHeader` stores `magic` (`0x55_54_58_4f`), `version` (`4`), `tip_hash` (32 bytes), `height` (`u32`), and `record_count` (`u64`).
- Writer function `write_snapshot` emits version `4` (`SNAPSHOT_WRITE_VERSION`).
- Reader function `read_snapshot` decodes legacy versions `2`, `3`, and `4`.
- Reader function `read_snapshot_strict_v4` decodes version `4` exclusively, enforcing strict end-of-file validation and requiring a 384-byte `MuHash3072` trailer (`MUHASH_TRAILER_LEN`).

### 2.4 Chainstate Checkpoint Directory
`crates/node/src/checkpoint.rs` persists full chainstate checkpoints under `chainstate-checkpoints/`.
- `CURRENT` file contains `CurrentV1` JSON referencing an active generation directory (e.g. `gen-0000000000000001/`).
- `manifest-v1.json` (`CheckpointManifestV1`) records component versions and codec identifier strings:
  - `headers`: version `1`, codec `"bitcoin-rs-canonical-headers"`.
  - `utxo`: version `4`, codec `"bitcoin-rs-utxo-spendable-v1"`.
  - `coinstats`: version `1`, codec `"bitcoin-rs-coinstats"`.

## 3. Schema Breaking Changes

A database or artifact change is breaking when an existing binary cannot parse data written by a different version.

### 3.1 Column Family Breaking Changes
The following modifications break key-value store compatibility:
- Adding, removing, or reordering variants in `ColumnFamily`.
- Changing the string name returned by `ColumnFamily::name()`.
- Altering the binary serialization layout of keys or values within any column family.
- Changing key prefixes or integer endianness.

### 3.2 Snapshot Format Breaking Changes
The following modifications break UTXO snapshot compatibility:
- Changing fields or layout in `SnapshotHeader`, `SnapshotRecordHeaderV4`, or `SnapshotVoutHeader`.
- Changing the varint encoding or output serialization order.
- Modifying `MUHASH_TRAILER_LEN` (384 bytes) or trailer calculation rules.

## 4. Snapshot Version Bump Procedure

When changing the binary layout of the UTXO snapshot:
1. Increment `SNAPSHOT_WRITE_VERSION` in `crates/utxo/src/snapshot.rs`.
2. Increment `UTXO_VERSION` in `crates/node/src/checkpoint.rs`.
3. Update `UTXO_CODEC` in `crates/node/src/checkpoint.rs` to reflect the new layout.
4. Define a new record header struct in `crates/utxo/src/snapshot.rs` (e.g., `SnapshotRecordHeaderV5`).
5. Add a reading function for the new version in `read_snapshot_with_policy_observed`.
6. Retain older read decoders in `read_snapshot` only if backward read support is explicitly required by project maintainers; otherwise, remove legacy decoders to enforce a clean cutover.

## 5. Datadir Compatibility and Startup Behavior

`load_checkpoint_from_dir` in `crates/node/src/checkpoint.rs` inspects on-disk checkpoint metadata during node startup. Startup outcomes follow strict precedence:

| Condition | Internal Function Return | Node Action |
| :--- | :--- | :--- |
| Mismatched or unsupported `headers` or `CoinStats` version | `Err(IncompatibleCheckpoint::UnsupportedVersion)` | **Fatal Abort.** Node stops immediately with an explicit error. |
| Mismatched `utxo.version` or unexpected `utxo`/`coinstats` codec | `Ok(CheckpointLoad::HeadersOnly)` | **Fallback Resync.** Node retains validated `BlockTree` headers, drops UTXO payload, and resynchronizes chainstate. |
| Missing `CURRENT` file, invalid JSON, or missing generation directory | `Ok(CheckpointLoad::Cold)` | **Cold Start.** Node starts initial block download from genesis (height 0). |
| Valid manifest, headers, UTXO snapshot, and CoinStats | `Ok(CheckpointLoad::Complete)` | **Normal Startup.** Node loads full chainstate and resumes operation. |

For raw Key-Value database stores (`fjall`, `rocksdb`, `mdbx`, `redb`):
- Because KV stores lack on-disk schema headers, opening a datadir with incompatible KV key/value layouts causes runtime read failures or database panics.

## 6. Migration and Resync Policy

### 6.1 In-Place Migrations
**`bitcoin-rs` does not support in-place database migrations.**
The codebase contains zero schema transformation scripts, database version tables, or in-place record converters.

#### 6.1.0 Additive Manifest Fields

Every manifest struct in `checkpoint.rs` carries `#[serde(deny_unknown_fields)]`,
so an older binary refuses a manifest written by a newer one. That direction is
covered by the no-downgrade stance. The other direction — a newer binary reading
an older manifest — is where a new field decides between a silent read and a
forced resync, because a missing required field fails the parse and the node
falls all the way back to a cold start.

A field that carries **information a node can do without** must therefore be
`#[serde(default)]`, and its absent value must be distinguishable from a real
one. `CheckpointTipV1::chain_tx_count` is the worked example: it defaults to `0`,
which is Bitcoin Core's own "unset" encoding for `m_chain_tx_count`, and every
reader treats `0` as *unknown* rather than *zero transactions*. A chain applied
before the field existed cannot recover the number — nothing short of re-reading
every block body would — so it stays unknown until that node is resynced, and
nothing is migrated in place.

A field the node **cannot** do without is a different case and takes the version
bump in section 6.2.

### 6.1.1 Undo Record Encoding
Undo records in `UndoData` carry their own format version as the first byte
(`crates/utxo/src/undo_codec.rs`), and each record is keyed by height and block
hash — see [*Undo record*](../../CONCEPTS.md#undo-record) for why that binding matters.

The codec has no reader for a version other than the current one, by design:
a record it cannot decode is a record the node refuses to disconnect against,
which is the safe direction. So a change to the encoding is a breaking schema
change under section 6.2 and needs the same treatment as a column-family
change. It is not covered by the UTXO snapshot version rules, which govern a
different format.

Undo records are also the one persistent structure a resync cannot rebuild
lazily: they exist to disconnect blocks already applied. [Section 2.1](#21-key-value-store-column-families)
states the cost of discarding them.

### 6.2 Recommended Rule for Schema Modifications
When a pull request alters key-value column family key/value formats, column family enum definitions, or storage engine layouts:
1. Do not write in-place conversion code or compatibility adapters.
2. Update the component version or codec string in `crates/node/src/checkpoint.rs`
   **where the manifest covers the component**. It covers headers, the UTXO
   snapshot, and CoinStats. It does NOT cover the key-value column families,
   the flat block files, or the undo codec, and there is no schema metadata in
   the KV stores either (see the gap noted in section 2.1). For those, a bump
   records intent but detects nothing: the node will open the old keyspace by
   name and read it as if current. Step 3 is the actual safeguard, not step 2.
3. Require users to wipe the local datadir and resync from genesis or load a fresh UTXO snapshot.
4. Allow the node's native `HeadersOnly` or `Cold` fallback mechanisms to rebuild incompatible state cleanly.
