use bitcoin_rs_storage::KvStore;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn rebuild_index_subcommand_publishes_generation_format_7() {
    let dir = tempdir().expect("tempdir");
    let txindex_dir = dir.path().join("txindex");
    std::fs::create_dir_all(&txindex_dir).expect("create txindex");

    let bin_path = env!("CARGO_BIN_EXE_bitcoin-rs-storage-convert");
    let status = Command::new(bin_path)
        .arg("rebuild-index")
        .arg("--datadir")
        .arg(dir.path())
        .status()
        .expect("run binary");

    assert!(status.success());

    let store = bitcoin_rs_storage::RocksDbStore::open(&txindex_dir).expect("open txindex");
    let snapshot = store.snapshot().expect("snapshot");
    let version = snapshot
        .get(bitcoin_rs_storage::ColumnFamily::IdxMeta, &[0x00, b'V'])
        .expect("get version")
        .expect("found version");
    assert_eq!(version.as_slice(), &[0x07, 0x00, 0x00, 0x00]);
}
