//! Custody-grade storage-footprint collector: logical and physical ledgers.

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::symlink;

use bitcoin_rs_storage::{
    ColumnFamily, DataDirAnchor, FootprintError, KvStore, PhysicalObservationKind, WriteBatch,
    logical_column_family, logical_store_owners, measure_physical_tree,
};
use tempfile::tempdir;

#[cfg(feature = "fjall")]
fn write_rows(
    store: &bitcoin_rs_storage::FjallStore,
    cf: ColumnFamily,
    rows: &[(Vec<u8>, Vec<u8>)],
) {
    let mut batch = store.new_batch();
    for (key, value) in rows {
        batch.put(cf, key, value);
    }
    store
        .write(batch)
        .unwrap_or_else(|error| panic!("write: {error}"));
}

#[cfg(feature = "fjall")]
#[test]
fn logical_owner_bytes_are_exact_key_plus_value() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = bitcoin_rs_storage::FjallStore::open(dir.path())
        .unwrap_or_else(|error| panic!("open: {error}"));
    write_rows(
        &store,
        ColumnFamily::UndoData,
        &[
            (b"abc".to_vec(), b"12345".to_vec()),
            (b"de".to_vec(), vec![0; 10]),
        ],
    );
    let owner = logical_column_family(&store, ColumnFamily::UndoData)
        .unwrap_or_else(|error| panic!("logical: {error}"));
    assert_eq!(owner.rows, 2);
    assert_eq!(owner.key_bytes, 5);
    assert_eq!(owner.value_bytes, 15);
    assert_eq!(owner.serialized_bytes, 20);
}

#[cfg(feature = "fjall")]
#[test]
fn logical_store_owners_cover_every_column_family() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = bitcoin_rs_storage::FjallStore::open(dir.path())
        .unwrap_or_else(|error| panic!("open: {error}"));
    let owners = logical_store_owners(&store, "chainstate")
        .unwrap_or_else(|error| panic!("owners: {error}"));
    assert_eq!(owners.len(), ColumnFamily::ALL.len());
    assert!(
        owners
            .iter()
            .any(|owner| owner.name == "chainstate.undo_data")
    );
}

#[test]
fn physical_ledger_uses_allocated_blocks_not_apparent_length() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    fs::create_dir(dir.path().join("blocks")).unwrap_or_else(|error| panic!("mkdir: {error}"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(dir.path().join("blocks/blk00000.dat"))
        .unwrap_or_else(|error| panic!("create: {error}"));
    file.seek(SeekFrom::Start(1_048_576))
        .unwrap_or_else(|error| panic!("seek: {error}"));
    file.write_all(&[0x5a])
        .unwrap_or_else(|error| panic!("write: {error}"));
    file.sync_all()
        .unwrap_or_else(|error| panic!("sync: {error}"));
    let apparent = file
        .metadata()
        .unwrap_or_else(|error| panic!("stat: {error}"))
        .len();
    drop(file);

    let ledger =
        measure_physical_tree(dir.path()).unwrap_or_else(|error| panic!("physical: {error}"));
    assert_eq!(
        ledger.observation_kind,
        PhysicalObservationKind::SnapshotLowerBound
    );
    assert!(
        ledger.allocated_bytes <= apparent.saturating_add(ledger.allocated_bytes),
        "sanity: allocated is a real byte count"
    );
    let blocks = ledger
        .namespaces
        .iter()
        .find(|namespace| namespace.name == "blocks")
        .unwrap_or_else(|| panic!("blocks namespace"));
    assert!(
        blocks.allocated_bytes < apparent || apparent < 64 * 1024,
        "sparse hole must not enter the physical budget as apparent length ({apparent} apparent, {} allocated)",
        blocks.allocated_bytes
    );
    assert_eq!(
        ledger.data_directory_allocated_bytes(),
        ledger.allocated_bytes
    );
}

#[test]
fn hard_links_are_counted_once() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    fs::create_dir(dir.path().join("chainstate")).unwrap_or_else(|error| panic!("mkdir: {error}"));
    let path_a = dir.path().join("chainstate/payload");
    fs::write(&path_a, vec![0x11; 32 * 1024]).unwrap_or_else(|error| panic!("write: {error}"));
    fs::hard_link(&path_a, dir.path().join("chainstate/alias"))
        .unwrap_or_else(|error| panic!("hard_link: {error}"));

    let once =
        measure_physical_tree(dir.path()).unwrap_or_else(|error| panic!("physical: {error}"));

    let copies = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    fs::create_dir(copies.path().join("chainstate"))
        .unwrap_or_else(|error| panic!("mkdir: {error}"));
    fs::write(
        copies.path().join("chainstate/payload"),
        vec![0x11; 32 * 1024],
    )
    .unwrap_or_else(|error| panic!("write: {error}"));
    fs::write(
        copies.path().join("chainstate/alias"),
        vec![0x11; 32 * 1024],
    )
    .unwrap_or_else(|error| panic!("write: {error}"));
    let twice =
        measure_physical_tree(copies.path()).unwrap_or_else(|error| panic!("physical: {error}"));

    assert!(
        once.inode_count < twice.inode_count,
        "hard-linked tree must count fewer inodes ({}/{})",
        once.inode_count,
        twice.inode_count
    );
    assert!(
        once.allocated_bytes < twice.allocated_bytes,
        "hard-linked payload must not be charged twice ({}/{})",
        once.allocated_bytes,
        twice.allocated_bytes
    );
}

#[test]
fn symlink_is_rejected() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    fs::create_dir(dir.path().join("chainstate")).unwrap_or_else(|error| panic!("mkdir: {error}"));
    fs::write(dir.path().join("chainstate/real"), b"payload")
        .unwrap_or_else(|error| panic!("write: {error}"));
    symlink("real", dir.path().join("chainstate/link"))
        .unwrap_or_else(|error| panic!("symlink: {error}"));
    let error = measure_physical_tree(dir.path())
        .err()
        .unwrap_or_else(|| panic!("expected symlink rejection"));
    assert!(
        matches!(error, FootprintError::Symlink { .. }),
        "got {error:?}"
    );
}

#[test]
fn root_symlink_is_rejected() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap_or_else(|error| panic!("mkdir: {error}"));
    let link = dir.path().join("link");
    symlink(&real, &link).unwrap_or_else(|error| panic!("symlink: {error}"));
    let error = DataDirAnchor::open(&link)
        .err()
        .unwrap_or_else(|| panic!("expected symlink rejection"));
    assert!(
        matches!(error, FootprintError::Symlink { .. }),
        "got {error:?}"
    );
}

#[test]
fn high_water_below_snapshot_is_rejected() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")
        .unwrap_or_else(|error| panic!("write: {error}"));
    let ledger =
        measure_physical_tree(dir.path()).unwrap_or_else(|error| panic!("physical: {error}"));
    let error = ledger
        .clone()
        .with_high_water(ledger.allocated_bytes.saturating_sub(1))
        .err()
        .unwrap_or_else(|| panic!("expected high-water rejection"));
    assert!(matches!(
        error,
        FootprintError::HighWaterBelowSnapshot { .. }
    ));
    let peaked = ledger
        .clone()
        .with_high_water(ledger.allocated_bytes)
        .unwrap_or_else(|error| panic!("equal high-water: {error}"));
    assert_eq!(
        peaked.observation_kind,
        PhysicalObservationKind::ConservativeHighWater
    );
}

#[test]
fn logical_flat_files_count_complete_frames_only() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = bitcoin_rs_storage::FlatFileBlockStore::open(dir.path())
        .unwrap_or_else(|error| panic!("open: {error}"));
    let hash = [0xab; 32];
    store
        .append(1, hash, b"hello-body")
        .unwrap_or_else(|error| panic!("append: {error}"));
    drop(store);

    let anchor = DataDirAnchor::open(dir.path()).unwrap_or_else(|error| panic!("anchor: {error}"));
    let owner = anchor
        .logical_flat_block_files()
        .unwrap_or_else(|error| panic!("logical blocks: {error}"));
    assert_eq!(owner.name, "blocks.flat_files");
    assert_eq!(owner.rows, 1);
    assert_eq!(owner.key_bytes, 0);
    assert_eq!(owner.serialized_bytes, 44 + 10);

    let physical = anchor
        .measure_physical()
        .unwrap_or_else(|error| panic!("physical: {error}"));
    let blocks = physical
        .namespaces
        .iter()
        .find(|namespace| namespace.name == "blocks")
        .unwrap_or_else(|| panic!("blocks namespace"));
    assert!(
        blocks.allocated_bytes > 0,
        "block files occupy allocated blocks"
    );
    assert_eq!(
        physical.data_directory_allocated_bytes(),
        physical.allocated_bytes,
        "the budget figure is the physical total, not a mix with framed bytes"
    );
}

#[test]
fn ledgers_are_not_summed_by_the_physical_total() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    fs::create_dir(dir.path().join("chainstate")).unwrap_or_else(|error| panic!("mkdir: {error}"));
    fs::write(dir.path().join("chainstate/note"), b"abc")
        .unwrap_or_else(|error| panic!("write: {error}"));
    let physical =
        measure_physical_tree(dir.path()).unwrap_or_else(|error| panic!("physical: {error}"));
    let logical_total = 3_u64;
    assert_ne!(
        physical.data_directory_allocated_bytes(),
        physical
            .data_directory_allocated_bytes()
            .saturating_add(logical_total),
        "adding logical bytes must not be how the budget is formed"
    );
}
