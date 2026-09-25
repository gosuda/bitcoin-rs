use super::*;
use crate::Network;
use bitcoin_rs_storage::footprint::evidence::DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES;
use bitcoin_rs_storage::measure_physical_tree;
use tempfile::tempdir;

// Contract coverage: docs/contracts/storage-footprint.md FP-01 (ledger and
// evidence shape), FP-02 (custody and witness handling), FP-03 (measurement
// command and stop identity), and FP-04 (default-lane budget verdicts). The
// individual assertions below are intentionally kept with this contract map:
// - default_regtest_record_is_inapplicable_to_the_mainnet_budget: FP-01, FP-03, FP-04
// - conservative_high_water_can_pass_the_default_mainnet_budget: FP-02, FP-04
// - unpinned_high_water_is_tip_unpinned_not_pass: FP-04
// - stop_height_without_hash_is_rejected, stop_hash_without_height_is_rejected,
//   invalid_stop_hash_is_rejected: FP-03
// - oversized_current_witness_falls_back_to_prev: FP-02
// - snapshot_of_default_mainnet_is_insufficient_for_the_peak_gate,
//   high_water_above_budget_fails_the_default_mainnet_gate: FP-04
// - identity_names_the_txindex_lane: FP-03, FP-04
// - empty_chainstate_directory_is_not_created_as_a_store: FP-03
// - logical_chainstate_rows_are_named_owners: FP-01, FP-03
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

#[cfg(feature = "fjall")]
#[test]
fn corrupt_txindex_watermarks_are_errors_not_missing_evidence() -> Result<()> {
    use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore};

    // Durable capability keys from index/capability.rs, not candidate-generated values.
    for key in [b"\0T", b"\0S", b"\0L"] {
        let dir = tempdir()?;
        let txindex = dir.path().join("txindex");
        std::fs::create_dir(&txindex)?;
        let store = FjallStore::open(&txindex)?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::UtxoMeta, key, b"broken");
        store.write(batch)?;
        drop(store);
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen.clear();
        let result = measure_storage_footprint(&config, &MeasureStorageRequest::default());
        let Err(error) = result else {
            anyhow::bail!("corrupt watermark {key:?} became valid storage evidence");
        };
        assert!(matches!(
            error.downcast_ref::<bitcoin_rs_index::IndexError>(),
            Some(bitcoin_rs_index::IndexError::InvalidWatermark)
        ));
    }
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn absent_and_valid_txindex_watermarks_remain_distinct() -> Result<()> {
    use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore};

    let dir = tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().to_path_buf();
    config.p2p.listen.clear();
    let txindex = dir.path().join("txindex");
    for create_empty_namespace in [false, true] {
        if create_empty_namespace {
            std::fs::create_dir(&txindex)?;
        }
        let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
        let watermarks = evidence.identity.index_watermarks;
        assert!(watermarks.tx_lookup.is_none());
        assert!(watermarks.script_history.is_none());
        assert!(watermarks.script_live.is_none());
        if create_empty_namespace {
            assert!(std::fs::read_dir(&txindex)?.next().is_none());
        } else {
            assert!(!txindex.exists());
        }
    }

    let store = FjallStore::open(&txindex)?;
    let mut batch = store.new_batch();
    for (key, height, marker) in [(b"\0T", 7_u32, 0xa1), (b"\0S", 8, 0xb2), (b"\0L", 9, 0xc3)] {
        // Independent fixture for the durable 4-byte LE height followed by 32 hash bytes.
        let mut encoded = [marker; 36];
        encoded[..4].copy_from_slice(&height.to_le_bytes());
        batch.put(ColumnFamily::UtxoMeta, key, &encoded);
    }
    store.write(batch)?;
    drop(store);
    let evidence = measure_storage_footprint(&config, &MeasureStorageRequest::default())?;
    let watermarks = evidence.identity.index_watermarks;
    for (watermark, height, hash) in [
        (watermarks.tx_lookup, 7, "a1"),
        (watermarks.script_history, 8, "b2"),
        (watermarks.script_live, 9, "c3"),
    ] {
        let watermark = watermark.ok_or_else(|| anyhow::anyhow!("missing persisted watermark"))?;
        assert_eq!(watermark.height, height);
        assert_eq!(watermark.hash, hash.repeat(32));
    }
    Ok(())
}
