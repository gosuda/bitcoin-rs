use super::*;

#[test]
fn transient_checkpoint_io_is_not_classified_as_incompatible() {
    let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "checkpoint locked");
    let classified =
        super::super::classify_checkpoint_error(super::super::CheckpointError::Io(error));
    let CheckpointLoadError::Io(error) = classified else {
        panic!("transient checkpoint I/O was classified as datadir incompatibility");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "checkpoint locked");

    let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "root locked");
    let classified = super::super::classify_open_error("open checkpoint root", error);
    let CheckpointLoadError::Io(error) = classified else {
        panic!("transient checkpoint-open I/O was classified as datadir incompatibility");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "root locked");
}

#[test]
fn first_publication_failures_leave_no_committed_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    for failpoint in [
        CheckpointFailpoint::HeadersWrite,
        CheckpointFailpoint::HeadersSync,
        CheckpointFailpoint::UtxoWrite,
        CheckpointFailpoint::UtxoSync,
        CheckpointFailpoint::CoinStatsWrite,
        CheckpointFailpoint::CoinStatsSync,
        CheckpointFailpoint::ManifestWrite,
        CheckpointFailpoint::ManifestSync,
        CheckpointFailpoint::StageSync,
        CheckpointFailpoint::GenerationRename,
        CheckpointFailpoint::GenerationRootSync,
        CheckpointFailpoint::CurrentTempWrite,
        CheckpointFailpoint::CurrentTempSync,
        CheckpointFailpoint::CurrentRename,
    ] {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let utxo = UtxoSet::new();
        let listener = CoinStatsListener::new(CoinStats::new());

        assert!(
            write_checkpoint_with_failpoint(
                dir.path(),
                config(),
                &tree,
                &utxo,
                &listener,
                Some(&applied_tip),
                failpoint,
            )
            .is_err(),
            "{failpoint:?}"
        );
        assert!(
            !dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists(),
            "pre-publication failure exposed CURRENT at {failpoint:?}"
        );
        assert!(matches!(
            load_checkpoint(dir.path(), config()),
            Ok(CheckpointLoad::Cold)
        ));
    }
    Ok(())
}

#[test]
fn checkpoint_without_current_is_cold() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    fs::remove_file(dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE))?;

    assert!(matches!(
        load_checkpoint(dir.path(), config()),
        Ok(CheckpointLoad::Cold)
    ));
    Ok(())
}

#[test]
fn unsupported_current_version_is_current_checkpoint_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
    let mut current: CurrentV1 = serde_json::from_slice(&fs::read(&current_path)?)?;
    current.version = current.version.saturating_add(1);
    fs::write(current_path, serde_json::to_vec(&current)?)?;
    let Err(CheckpointLoadError::Corrupt(CheckpointCorruption::Invalid { reason })) =
        load_checkpoint(dir.path(), config())
    else {
        return Err("unsupported CURRENT version was not reported as corruption".into());
    };
    assert!(reason.contains("CURRENT checkpoint version"));
    assert!(!reason.contains("incompatible bitcoin-rs datadir"));
    Ok(())
}

#[test]
fn checkpoint_roundtrip_preserves_record_with_440_outputs() -> Result<(), Box<dyn std::error::Error>>
{
    const OUTPUT_COUNT: u32 = 440;
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let record_txid = Txid(Hash256::from_le_bytes(&[0x44; 32]));
    let mut changes = BlockChanges::default();
    for vout in 0..OUTPUT_COUNT {
        changes.add(UtxoAdd::new(
            OutPoint::new(record_txid, vout),
            TxOut {
                value: Amount::from_sat(u64::from(vout) + 1),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            false,
            0,
        ));
    }
    let utxo = UtxoSet::new();
    utxo.commit_block(&changes, &Hash256::default())?;

    super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &utxo,
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;
    let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
        return Err("multi-output checkpoint did not restore".into());
    };

    assert_eq!(restored.utxo.len(), usize::try_from(OUTPUT_COUNT)?);
    assert!(
        restored
            .utxo
            .get(&OutPoint::new(record_txid, OUTPUT_COUNT - 1))
            .is_some()
    );
    Ok(())
}

#[test]
fn scanned_trailer_restores_independently_scanned_stats() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = populated_utxo()?;
    let expected = utxo.with_stable_view(|view| scan_coin_stats(view, 0, true))?;
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &utxo,
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;

    let root = dir.path().join(CHECKPOINT_ROOT);
    let current: CurrentV1 = serde_json::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    let generation = root.join(current.directory);
    let mut reader = std::io::BufReader::new(std::fs::File::open(generation.join(UTXO_FILE))?);
    let snapshot = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut reader)?;
    assert_ne!(snapshot.muhash_trailer, [0_u8; 384]);
    assert_eq!(snapshot.muhash_trailer, expected.muhash.finalize());

    let CheckpointLoad::Complete(mut restored) = load_checkpoint(dir.path(), config())? else {
        return Err(std::io::Error::other("scanned generation did not restore").into());
    };
    assert_eq!(restored.coin_stats, expected);

    let listener = CoinStatsListener::new(restored.coin_stats.clone());
    restored.utxo.set_listener(Box::new(listener.clone()));
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 42),
        TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: Script::from_bytes(vec![0x51, 0xac]),
        },
        false,
        restored.applied_tip.height,
    ));
    restored
        .utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xa5; 32]))?;
    let continued = restored
        .utxo
        .with_stable_view(|view| scan_coin_stats(view, restored.applied_tip.height, true))?;
    assert_eq!(listener.snapshot().to_bytes(), continued.to_bytes());
    Ok(())
}
