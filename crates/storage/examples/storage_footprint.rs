//! On-disk footprint measurement for the storage backends.
//!
//! Writes a fixed synthetic corpus across all column families, then measures
//! total bytes on disk and per-column-family bytes, and computes write
//! amplification versus the logical data size.
//!
//! Run:
//!
//! ```text
//! cargo run -p bitcoin-rs-storage --example storage_footprint --release -- [backend]
//! ```
//!
//! `backend` is one of `fjall` (default), `redb`, `rocksdb`. The corpus is
//! designed to complete in under a minute on a laptop.
#![allow(clippy::print_stdout)]
#![allow(clippy::expect_used)]

use hashbrown::HashMap;
use std::path::Path;

use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Number of rows per "index" column family (small keys, small values).
const INDEX_ROWS: u32 = 200_000;

/// Number of block-body rows (large keys, large values).
/// 5000 × 16 KiB = ~80 MiB, enough to trigger fjall's 64 MiB memtable flush
/// in the `block_bodies` keyspace so SST files are produced.
const BLOCK_BODY_ROWS: u32 = 5_000;

/// Number of undo rows (medium values).
const UNDO_ROWS: u32 = 5_000;

/// Block-body value size — a typical small block.
const BLOCK_BODY_VALUE_BYTES: usize = 16 * 1024;

/// Undo-data value size — a few UTXO entries per block.
const UNDO_VALUE_BYTES: usize = 256;

/// Computes the logical (raw key + value) bytes written across all CFs.
fn logical_data_size() -> u64 {
    let mut total: u64 = 0;

    // Index CFs: 12-byte key + 8-byte value per row (TxConfirmed, Funding,
    // Spending), 80-byte key + 0-byte value (BlockHeaders), 12-byte key
    // + 8-byte value (Coinstats),
    // 37-byte key + 0-byte value (BlockTree), 16-byte key + 8-byte value
    // (UtxoMeta), 5-byte key + 4-byte value (TxMempool).
    let index_cfs: &[(ColumnFamily, usize, usize)] = &[
        (ColumnFamily::TxConfirmed, 12, 8),
        (ColumnFamily::TxMempool, 5, 4),
        (ColumnFamily::BlockHeaders, 80, 0),
        (ColumnFamily::Funding, 12, 8),
        (ColumnFamily::Spending, 12, 8),
        (ColumnFamily::Coinstats, 12, 8),
        (ColumnFamily::BlockTree, 37, 0),
        (ColumnFamily::UtxoMeta, 16, 8),
    ];

    for &(_, key_len, val_len) in index_cfs {
        total += u64::from(INDEX_ROWS)
            * (u64::try_from(key_len).expect("key length fits in u64")
                + u64::try_from(val_len).expect("value length fits in u64"));
    }

    // BlockBodies: 37-byte key + BLOCK_BODY_VALUE_BYTES value.
    total += u64::from(BLOCK_BODY_ROWS)
        * (37 + u64::try_from(BLOCK_BODY_VALUE_BYTES).expect("block-body value size fits in u64"));

    // UndoData: 37-byte key + UNDO_VALUE_BYTES value.
    total += u64::from(UNDO_ROWS)
        * (37 + u64::try_from(UNDO_VALUE_BYTES).expect("undo value size fits in u64"));

    total
}

/// Writes the synthetic corpus into `store`.
fn write_corpus<S: KvStore>(store: &S) {
    // Index CFs with small key/value pairs.
    let index_cfs: &[(ColumnFamily, usize, usize)] = &[
        (ColumnFamily::TxConfirmed, 12, 8),
        (ColumnFamily::TxMempool, 5, 4),
        (ColumnFamily::BlockHeaders, 80, 0),
        (ColumnFamily::Funding, 12, 8),
        (ColumnFamily::Spending, 12, 8),
        (ColumnFamily::Coinstats, 12, 8),
        (ColumnFamily::BlockTree, 37, 0),
        (ColumnFamily::UtxoMeta, 16, 8),
    ];

    for &(cf, key_len, val_len) in index_cfs {
        let mut batch = store.new_batch();
        for i in 0..INDEX_ROWS {
            let key = synthetic_key(i, key_len);
            let val = synthetic_val(i, val_len);
            batch.put(cf, &key, &val);
        }
        store.write(batch).expect("write index batch");
    }
    store.flush().expect("flush after index");

    // BlockBodies: large values.
    let mut batch = store.new_batch();
    for i in 0..BLOCK_BODY_ROWS {
        let key = synthetic_key(i, 37);
        let val = vec![0xa5u8; BLOCK_BODY_VALUE_BYTES];
        batch.put(ColumnFamily::BlockBodies, &key, &val);
    }
    store.write(batch).expect("write block-body batch");
    store.flush().expect("flush after block bodies");

    // UndoData: medium values.
    let mut batch = store.new_batch();
    for i in 0..UNDO_ROWS {
        let key = synthetic_key(i, 37);
        let val = vec![0xb3u8; UNDO_VALUE_BYTES];
        batch.put(ColumnFamily::UndoData, &key, &val);
    }
    store.write(batch).expect("write undo batch");
    store.flush().expect("flush after undo");
}

fn synthetic_key(index: u32, len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    let bytes = index.to_le_bytes();
    let copy_len = bytes.len().min(len);
    key[..copy_len].copy_from_slice(&bytes[..copy_len]);
    // Fill the rest with a deterministic pattern.
    for (i, byte) in key.iter_mut().enumerate().skip(copy_len) {
        let idx = usize::try_from(index).expect("u32 fits usize on all Rust targets");
        *byte = u8::try_from(idx.wrapping_add(i * 31) & 0xFF).expect("masked value fits in u8");
    }
    key
}

fn synthetic_val(index: u32, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    let mut val = vec![0u8; len];
    let bytes = index.to_le_bytes();
    let copy_len = bytes.len().min(len);
    val[..copy_len].copy_from_slice(&bytes[..copy_len]);
    for (i, byte) in val.iter_mut().enumerate().skip(copy_len) {
        let idx = usize::try_from(index).expect("u32 fits usize on all Rust targets");
        *byte = u8::try_from(idx.wrapping_add(i * 37) & 0xFF).expect("masked value fits in u8");
    }
    val
}

// ---------------------------------------------------------------------------
// Disk measurement
// ---------------------------------------------------------------------------

/// Recursively sums the size of every regular file under `path`.
fn dir_size(path: &Path) -> u64 {
    fn recurse(dir: &Path) -> u64 {
        let mut total = 0;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                total += recurse(&entry.path());
            } else if file_type.is_file() {
                total += entry.metadata().map_or(0, |m| m.len());
            }
        }
        total
    }
    recurse(path)
}

/// Measures per-column-family bytes for fjall. Each keyspace is a separate
/// numbered directory under `keyspaces/`. Also reports the shared journal.
fn fjall_cf_sizes(root: &Path) -> (HashMap<String, u64>, u64) {
    let mut sizes = HashMap::new();
    let cf_names: Vec<&str> = ColumnFamily::ALL.iter().map(|cf| cf.name()).collect();
    let ks_dir = root.join("keyspaces");
    let mut dirs: Vec<(String, u64)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&ks_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path
                    .file_name()
                    .map_or(String::new(), |n| n.to_string_lossy().to_string());
                let size = dir_size(&path);
                dirs.push((name, size));
            }
        }
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    for (i, (_, size)) in dirs.iter().enumerate() {
        if i < cf_names.len() {
            sizes.insert(cf_names[i].to_string(), *size);
        }
    }
    // Journal files live at the DB root, named `N.jnl`.
    let journal_size: u64 = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let is_journal = e
                .path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jnl"));
            if is_journal {
                Some(e.metadata().map_or(0, |m| m.len()))
            } else {
                None
            }
        })
        .sum();
    (sizes, journal_size)
}

/// Measures per-column-family bytes for redb. redb uses a single file, so
/// per-CF breakdown is not available from the filesystem.
#[cfg(feature = "redb")]
fn redb_cf_sizes(_root: &Path) -> (HashMap<String, u64>, u64) {
    (HashMap::new(), 0)
}

/// Measures per-column-family bytes for rocksdb. Each CF is a separate
/// directory under the DB root.
#[cfg(feature = "rocksdb")]
fn rocksdb_cf_sizes(root: &Path) -> (HashMap<String, u64>, u64) {
    let mut sizes = HashMap::new();
    for cf in ColumnFamily::ALL {
        let cf_dir = root.join(cf.name());
        if cf_dir.is_dir() {
            sizes.insert(cf.name().to_string(), dir_size(&cf_dir));
        }
    }
    (sizes, 0)
}

// ---------------------------------------------------------------------------
// Main

/// Converts bytes to mebibytes for display. Storage footprints in this tool
/// are at most a few hundred MiB (< 2^28), well within f64's 52-bit mantissa
/// which represents integers exactly up to 2^53, so the cast is lossless.
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts < 2^28, lossless in f64"
)]
#[expect(clippy::as_conversions, reason = "byte counts < 2^28, lossless in f64")]
fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Converts bytes to kibibytes for display. Per-CF sizes are at most a few
/// MiB (< 2^24), well within f64's exact-integer range.
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts < 2^24, lossless in f64"
)]
#[expect(clippy::as_conversions, reason = "byte counts < 2^24, lossless in f64")]
fn kib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0
}

/// Computes the write-amplification ratio as a double. Both operands are at
/// most a few hundred MiB (< 2^28), so the f64 cast is lossless and the
/// division preserves full precision at these magnitudes.
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts < 2^28, lossless in f64"
)]
#[expect(clippy::as_conversions, reason = "byte counts < 2^28, lossless in f64")]
fn amplification_ratio(total: u64, logical: u64) -> f64 {
    if logical > 0 {
        total as f64 / logical as f64
    } else {
        0.0
    }
}
fn main() {
    let backend = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fjall".to_string());

    let logical = logical_data_size();
    println!("=== Storage footprint measurement ===");
    println!("Backend:     {backend}");
    println!(
        "Corpus:      {INDEX_ROWS} index rows/CF, {BLOCK_BODY_ROWS} block-body rows, {UNDO_ROWS} undo rows"
    );
    println!("Block body:  {BLOCK_BODY_VALUE_BYTES} B");
    println!("Undo value:  {UNDO_VALUE_BYTES} B");
    println!(
        "Logical data size: {logical} bytes ({:.2} MiB)",
        mib(logical)
    );
    println!();

    let temp = tempfile::TempDir::new().expect("tempdir");
    let path = temp.path();

    match backend.as_str() {
        #[cfg(feature = "fjall")]
        "fjall" => {
            let store = bitcoin_rs_storage::FjallStore::open(path).expect("open fjall");
            write_corpus(&store);
            store
                .force_flush_memtables()
                .expect("force flush memtables");
            drop(store);
            let total = dir_size(path);
            let (cf_sizes, journal) = fjall_cf_sizes(path);
            print_results(&backend, total, logical, &cf_sizes, journal);
        }
        #[cfg(feature = "redb")]
        "redb" => {
            let store = bitcoin_rs_storage::RedbStore::open(path).expect("open redb");
            write_corpus(&store);
            drop(store);
            let total = dir_size(path);
            let (cf_sizes, journal) = redb_cf_sizes(path);
            print_results(&backend, total, logical, &cf_sizes, journal);
        }
        #[cfg(feature = "rocksdb")]
        "rocksdb" => {
            let store = bitcoin_rs_storage::RocksDbStore::open(path).expect("open rocksdb");
            write_corpus(&store);
            drop(store);
            let total = dir_size(path);
            let (cf_sizes, journal) = rocksdb_cf_sizes(path);
            print_results(&backend, total, logical, &cf_sizes, journal);
        }
        other => {
            eprintln!("Unknown backend: {other}");
            eprintln!("Usage: storage_footprint [fjall|redb|rocksdb]");
            std::process::exit(1);
        }
    }
}

fn print_results(
    backend: &str,
    total: u64,
    logical: u64,
    cf_sizes: &HashMap<String, u64>,
    journal: u64,
) {
    let amplification = amplification_ratio(total, logical);
    println!("--- {backend} ---");
    println!("Total on-disk:     {total} bytes ({:.2} MiB)", mib(total));
    println!(
        "Logical data:      {logical} bytes ({:.2} MiB)",
        mib(logical)
    );
    println!("Write amplification: {amplification:.3}x");
    if journal > 0 {
        println!(
            "Journal:           {journal} bytes ({:.2} MiB)",
            mib(journal)
        );
    }
    println!();
    if cf_sizes.is_empty() {
        println!("Per-CF breakdown:  (single-file backend, not available)");
    } else {
        println!("Per-CF breakdown:");
        let mut entries: Vec<_> = cf_sizes.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1));
        for (name, size) in entries {
            println!("  {name:<20} {size:>12} bytes ({:.2} KiB)", kib(*size));
        }
    }
    println!();
}
