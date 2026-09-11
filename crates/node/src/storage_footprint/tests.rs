use super::*;
use crate::Network;
use bitcoin_rs_storage::measure_physical_tree;
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
        PhysicalObservationKind::SnapshotLowerBound.as_str()
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
    let snapshot = measure_physical_tree(dir.path()).map_err(|error| io_from_footprint(&error))?;
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
        PhysicalObservationKind::ConservativeHighWater.as_str()
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
    let snapshot = measure_physical_tree(dir.path()).map_err(|error| io_from_footprint(&error))?;
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
    assert!(
        error
            .to_string()
            .contains("invalid --measure-storage-stop-hash"),
        "{error}"
    );
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
    let mut current = " ".repeat(crate::recovery_evidence::MAX_FILE_BYTES + 1);
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
    use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore, WriteBatch};
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
