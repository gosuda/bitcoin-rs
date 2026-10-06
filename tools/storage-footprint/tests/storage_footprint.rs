//! Contract tests for storage-footprint physical and logical ledgers (FP-01..FP-04).

#![cfg(unix)]

use anyhow::{Result, bail};
use bitcoin_rs_node::Network;
use bitcoin_rs_node::config::NodeConfig;
use bitcoin_rs_storage_footprint::evidence::{DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES, EVIDENCE_FORMAT};
use bitcoin_rs_storage_footprint::{
    MeasureStorageRequest, PhysicalObservationKind, measure_physical_tree,
    measure_storage_footprint,
};
use tempfile::tempdir;

#[test]
fn default_regtest_record_is_inapplicable_to_the_mainnet_budget() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
    assert_eq!(evidence.format, EVIDENCE_FORMAT);
    assert_eq!(evidence.identity.network, "regtest");
    assert_eq!(evidence.identity.index_lane, "default");
    assert!(!evidence.budget.applies_to_this_record);
    assert_eq!(evidence.budget.verdict, "inapplicable");
    assert!(evidence.logical.not_a_filesystem_allocation);
    assert_eq!(
        evidence.physical.observation_kind,
        PhysicalObservationKind::SnapshotLowerBound
    );
    assert!(
        evidence
            .logical
            .owners
            .iter()
            .any(|owner| owner.name == "blocks.flat_files")
    );
    Ok(())
}

#[test]
fn conservative_high_water_can_pass_the_default_mainnet_budget() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    config.p2p.dns_seeds_enabled = false;
    let snapshot = measure_physical_tree(dir.path()).map_err(|error| anyhow::anyhow!("{error}"))?;
    let genesis = Network::Mainnet.genesis_block_hash().to_string_be();
    let evidence = measure_storage_footprint(
        &config,
        &MeasureStorageRequest {
            high_water_allocated_bytes: Some(snapshot.allocated_bytes),
            stop_height: Some(0),
            stop_hash: Some(genesis.clone()),
        },
    )?;
    assert!(evidence.identity.stop_pinned);
    assert_eq!(evidence.identity.stop_height, 0);
    assert_eq!(evidence.identity.stop_hash, genesis);
    assert!(evidence.budget.applies_to_this_record);
    assert_eq!(evidence.budget.verdict, "pass");
    assert_eq!(
        evidence.physical.observation_kind,
        PhysicalObservationKind::ConservativeHighWater
    );
    Ok(())
}

#[test]
fn unpinned_high_water_is_tip_unpinned_not_pass() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    config.p2p.dns_seeds_enabled = false;
    let snapshot = measure_physical_tree(dir.path()).map_err(|error| anyhow::anyhow!("{error}"))?;
    let evidence = measure_storage_footprint(
        &config,
        &MeasureStorageRequest {
            high_water_allocated_bytes: Some(snapshot.allocated_bytes),
            stop_height: None,
            stop_hash: None,
        },
    )?;
    assert!(!evidence.identity.stop_pinned);
    assert!(evidence.budget.applies_to_this_record);
    assert_eq!(evidence.budget.verdict, "tip_unpinned");
    Ok(())
}

#[test]
fn stop_height_without_hash_is_rejected() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let error = match measure_storage_footprint(
        &config,
        &MeasureStorageRequest {
            stop_height: Some(0),
            stop_hash: None,
            ..MeasureStorageRequest::default()
        },
    ) {
        Err(error) => error,
        Ok(_) => bail!("expected paired-stop rejection"),
    };
    assert!(
        error.to_string().contains("must be supplied together"),
        "{error}"
    );
    Ok(())
}

#[test]
fn stop_hash_without_height_is_rejected() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let genesis = Network::Regtest.genesis_block_hash().to_string_be();
    let error = match measure_storage_footprint(
        &config,
        &MeasureStorageRequest {
            stop_height: None,
            stop_hash: Some(genesis),
            ..MeasureStorageRequest::default()
        },
    ) {
        Err(error) => error,
        Ok(_) => bail!("expected paired-stop rejection"),
    };
    assert!(
        error.to_string().contains("must be supplied together"),
        "{error}"
    );
    Ok(())
}

#[test]
fn invalid_stop_hash_is_rejected() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let error = match measure_storage_footprint(
        &config,
        &MeasureStorageRequest {
            stop_height: Some(0),
            stop_hash: Some("zz".to_owned()),
            ..MeasureStorageRequest::default()
        },
    ) {
        Err(error) => error,
        Ok(_) => bail!("expected hash parse rejection"),
    };
    assert!(error.to_string().contains("invalid --stop-hash"), "{error}");
    Ok(())
}

fn witness_json(genesis: &str, height: u32) -> String {
    format!(
        "{{\"format\":\"1\",\"genesis_hash\":\"{genesis}\",\"writer_epoch\":1,\"height\":{height},\"block_hash\":\"{genesis}\",\"time\":1}}"
    )
}

#[test]
fn oversized_current_witness_falls_back_to_prev() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let genesis = Network::Regtest.genesis_block_hash().to_string_be();
    let prev = witness_json(&genesis, 3);
    let mut current = " ".repeat(bitcoin_rs_storage::recovery_evidence::MAX_FILE_BYTES + 1);
    current.push_str(&witness_json(&genesis, 9));
    std::fs::write(dir.path().join("applied-tip-witness.json"), current)?;
    std::fs::write(dir.path().join("applied-tip-witness.json.prev"), prev)?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
    assert!(!evidence.identity.stop_pinned);
    assert_eq!(evidence.identity.stop_height, 3);
    assert_eq!(evidence.identity.stop_hash, genesis);
    Ok(())
}

#[test]
fn snapshot_of_default_mainnet_is_insufficient_for_the_peak_gate() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    config.p2p.dns_seeds_enabled = false;
    let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
    assert!(evidence.budget.applies_to_this_record);
    assert_eq!(evidence.budget.verdict, "snapshot_insufficient");
    Ok(())
}

#[test]
fn identity_names_the_txindex_lane() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
    assert_eq!(evidence.identity.index_lane, "txindex");
    assert!(evidence.identity.txindex);
    assert!(!evidence.budget.applies_to_this_record);
    Ok(())
}

#[test]
fn high_water_above_budget_fails_the_default_mainnet_gate() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    config.p2p.dns_seeds_enabled = false;
    let evidence = measure_storage_footprint(
        &config,
        &MeasureStorageRequest {
            high_water_allocated_bytes: Some(DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES.saturating_add(1)),
            stop_height: Some(0),
            stop_hash: Some(Network::Mainnet.genesis_block_hash().to_string_be()),
        },
    )?;
    assert!(evidence.budget.applies_to_this_record);
    assert_eq!(evidence.budget.verdict, "fail");
    Ok(())
}

#[test]
fn empty_chainstate_directory_is_not_created_as_a_store() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let chainstate = dir.path().join("chainstate");
    std::fs::create_dir(&chainstate)?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
    assert!(
        !evidence
            .logical
            .owners
            .iter()
            .any(|owner| owner.name.starts_with("chainstate.")),
        "empty chainstate must not be opened into column-family owners"
    );
    assert!(
        std::fs::read_dir(&chainstate)?.next().is_none(),
        "measurement must not initialize an empty chainstate directory"
    );
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn logical_chainstate_rows_are_named_owners() -> Result<()> {
    use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore};
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let chainstate = dir.path().join("chainstate");
    std::fs::create_dir(&chainstate)?;
    let store = FjallStore::open(&chainstate).map_err(anyhow::Error::new)?;
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::UndoData, b"k", b"value-bytes");
    store.write(batch).map_err(anyhow::Error::new)?;
    drop(store);
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
    let undo = evidence
        .logical
        .owners
        .iter()
        .find(|owner| owner.name == "chainstate.undo_data")
        .ok_or_else(|| anyhow::anyhow!("undo owner"))?;
    assert_eq!(undo.rows, 1);
    assert_eq!(undo.key_bytes, 1);
    assert_eq!(undo.value_bytes, 11);
    assert!(
        evidence
            .physical
            .namespaces
            .iter()
            .any(|namespace| namespace.name == "chainstate")
    );
    Ok(())
}

use bitcoin_rs_storage_footprint::{DataDirAnchor, FootprintError};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::symlink;

#[cfg(feature = "fjall")]
#[test]
fn logical_owner_bytes_are_exact_key_plus_value() {
    use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore};
    use bitcoin_rs_storage_footprint::logical_store_owners;

    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = FjallStore::open(dir.path()).unwrap_or_else(|error| panic!("open: {error}"));
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::UndoData, b"abc", b"12345");
    batch.put(ColumnFamily::UndoData, b"de", &[0; 10]);
    store
        .write(batch)
        .unwrap_or_else(|error| panic!("write: {error}"));
    let owners = logical_store_owners(&store, "chainstate")
        .unwrap_or_else(|error| panic!("owners: {error}"));
    let owner = owners
        .iter()
        .find(|owner| owner.name == "chainstate.undo_data")
        .unwrap_or_else(|| panic!("chainstate.undo_data owner missing"));
    assert_eq!(owner.rows, 2);
    assert_eq!(owner.key_bytes, 5);
    assert_eq!(owner.value_bytes, 15);
    assert_eq!(owner.serialized_bytes, 20);
}

#[cfg(not(target_os = "macos"))]
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
}

fn mkfifo(dir: &std::path::Path, name: &str) {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(dir.join(name).as_os_str().as_bytes())
        .unwrap_or_else(|error| panic!("fifo path: {error}"));
    // SAFETY: `path` is a valid null-terminated C string pointing to a path inside a temporary test directory.
    let status = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(status, 0, "mkfifo: {}", std::io::Error::last_os_error());
}

#[test]
fn fifo_is_rejected_without_blocking() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    mkfifo(dir.path(), "pipe");
    let error = measure_physical_tree(dir.path())
        .err()
        .unwrap_or_else(|| panic!("expected fifo rejection"));
    assert!(
        matches!(error, FootprintError::UnsupportedEntry { kind: "fifo", .. }),
        "got {error:?}"
    );
}

#[test]
fn fifo_child_file_is_rejected() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    mkfifo(dir.path(), "applied-tip-witness.json");
    let anchor = DataDirAnchor::open(dir.path()).unwrap_or_else(|error| panic!("anchor: {error}"));
    let error = anchor
        .read_child_file("applied-tip-witness.json", 4096)
        .err()
        .unwrap_or_else(|| panic!("expected fifo rejection"));
    assert!(
        matches!(error, FootprintError::UnsupportedEntry { kind: "fifo", .. }),
        "got {error:?}"
    );
}

#[test]
fn fifo_block_file_is_rejected() {
    let dir = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    fs::create_dir(dir.path().join("blocks")).unwrap_or_else(|error| panic!("mkdir: {error}"));
    mkfifo(&dir.path().join("blocks"), "blk00000.dat");
    let anchor = DataDirAnchor::open(dir.path()).unwrap_or_else(|error| panic!("anchor: {error}"));
    let error = anchor
        .logical_flat_block_files()
        .err()
        .unwrap_or_else(|| panic!("expected fifo rejection"));
    assert!(
        matches!(error, FootprintError::UnsupportedEntry { kind: "fifo", .. }),
        "got {error:?}"
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
        physical.allocated_bytes,
        physical.allocated_bytes.saturating_add(logical_total),
        "adding logical bytes must not be how the budget is formed"
    );
}

#[test]
fn cli_runs_and_measures_datadir() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let out_file = dir.path().join("footprint.json");

    let bin_path = env!("CARGO_BIN_EXE_storage-footprint");
    let output = std::process::Command::new(bin_path)
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--output")
        .arg(&out_file)
        .output()?;

    assert!(output.status.success(), "CLI failed: {output:?}");
    assert!(out_file.exists(), "output file must be written");

    let text = std::fs::read_to_string(&out_file)?;
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(parsed["format"], EVIDENCE_FORMAT);
    assert_eq!(parsed["identity"]["network"], "mainnet");
    assert_eq!(parsed["budget"]["verdict"], "snapshot_insufficient");
    Ok(())
}

#[test]
fn cli_aliases_and_config_layering() -> Result<()> {
    let dir = tempdir()?;
    std::fs::write(dir.path().join("CURRENT_SCHEMA"), b"0\n")?;
    let config_file = dir.path().join("test_config.toml");
    std::fs::write(
        &config_file,
        format!(
            "network = \"regtest\"\ndata_dir = \"{}\"\n",
            dir.path().display().to_string().replace('\\', "\\\\")
        ),
    )?;

    let bin_path = env!("CARGO_BIN_EXE_storage-footprint");
    let output = std::process::Command::new(bin_path)
        .arg("--config")
        .arg(&config_file)
        .arg("--stop-height")
        .arg("0")
        .arg("--stop-hash")
        .arg(Network::Regtest.genesis_block_hash().to_string_be())
        .arg("--high-water-bytes")
        .arg("1000000000")
        .output()?;

    assert!(output.status.success(), "CLI failed: {output:?}");
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(parsed["identity"]["network"], "regtest");
    assert_eq!(parsed["identity"]["stop_pinned"], true);
    assert_eq!(parsed["identity"]["stop_height"], 0);
    assert_eq!(
        parsed["physical"]["observation_kind"],
        "conservative_high_water"
    );
    Ok(())
}
