use super::*;

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
