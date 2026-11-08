use super::*;

#[test]
fn scanned_trailer_restores_independently_scanned_stats() -> TestResult {
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
        &CoinStatsListener::new(expected.clone()),
        Some(&applied_tip),
    )?;

    let root = dir.path().join(CHECKPOINT_ROOT);
    let current: CurrentV1 = sonic_rs::from_slice(&fs::read(root.join(CURRENT_FILE))?)?;
    let generation = root.join(current.directory);
    assert!(generation.join(HEADERS_FILE).exists());
    assert!(generation.join(COINSTATS_FILE).exists());

    let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
        return Err(std::io::Error::other("scanned generation did not restore").into());
    };
    assert_eq!(restored.coin_stats, expected);

    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 42);
    let txout = TxOut {
        value: Amount::from_sat(123_456),
        script_pubkey: Script::from_bytes(vec![0x51, 0xac]),
    };
    let mut stats = restored.coin_stats.clone();
    stats.insert_utxo(&outpoint, &txout, restored.applied_tip.height, false);
    let listener = CoinStatsListener::new(stats);
    let out = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 42,
        value: 123_456,
        script_pubkey: vec![0x51, 0xac],
        coinbase: false,
        height: restored.applied_tip.height,
    };
    let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
        Hash256::from_le_bytes(&[0x5a; 32]),
        &[out],
    )?;
    utxo.insert_parsed_record(record);
    let continued =
        utxo.with_stable_view(|view| scan_coin_stats(view, restored.applied_tip.height, true))?;
    assert_eq!(listener.snapshot().to_bytes(), continued.to_bytes());
    Ok(())
}
