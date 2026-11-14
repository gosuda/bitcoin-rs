use super::*;

#[test]
fn scanned_trailer_restores_independently_scanned_stats() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = populated_utxo()?;
    let large_txid = Hash256::from_le_bytes(&[0x39; 32]);
    let large_outputs: Vec<_> = (0_u8..9)
        .map(|index| bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: u32::from(index) * 3 + 1,
            value: 10_000 + u64::from(index) * 137,
            script_pubkey: vec![0x51, index, 0xac],
            coinbase: index % 2 == 0,
            height: 0,
        })
        .collect();
    utxo.insert_parsed_record(
        bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
            large_txid,
            &large_outputs,
        )?,
    );
    let initial_txid = Hash256::from_le_bytes(&[7_u8; 32]);
    let initial_output = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 3,
        value: 50_000,
        script_pubkey: vec![0x51, 0x21],
        coinbase: true,
        height: 0,
    };
    let fixture = || {
        std::iter::once((initial_txid, &initial_output))
            .chain(large_outputs.iter().map(|output| (large_txid, output)))
    };
    let mut expected = CoinStats::new();
    for (txid, output) in fixture() {
        expected.insert_utxo(
            &OutPoint::new(Txid(txid), output.vout),
            &TxOut {
                value: Amount::from_sat(output.value),
                script_pubkey: Script::from_bytes(output.script_pubkey.clone()),
            },
            output.height,
            output.coinbase,
        );
    }
    let scanned = utxo.with_stable_view(|view| scan_coin_stats(view, 0, true))?;
    assert_eq!(scanned, expected);
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
    drop(utxo);

    let engine = restored.engine.as_ref().ok_or(TestError::Missing(
        "the checkpoint generation carries no engine image",
    ))?;
    let restored_utxo = utxo_from_engine(engine.as_ref())?;
    restored_utxo.with_stable_view(|view| -> Result<(), TestError> {
        assert_eq!(view.record_count(), 2);
        assert_eq!(view.len(), 1 + large_outputs.len());
        for (txid, output) in fixture() {
            let outpoint = OutPoint::new(Txid(txid), output.vout);
            let coin = view.get_entry(&outpoint).ok_or(TestError::Missing(
                "the restored engine image is missing a fixture output",
            ))?;
            assert_eq!(coin.outpoint, outpoint);
            assert_eq!(coin.txout.value, Amount::from_sat(output.value));
            assert_eq!(coin.txout.script_pubkey.as_bytes(), output.script_pubkey);
            assert_eq!(coin.coinbase, output.coinbase);
            assert_eq!(coin.height, output.height);
        }
        Ok(())
    })?;
    let rescanned = restored_utxo
        .with_stable_view(|view| scan_coin_stats(view, restored.applied_tip.height, true))?;
    assert_eq!(
        rescanned.to_bytes(),
        restored.coin_stats.to_bytes(),
        "the engine image must hold exactly the coins the coinstats artifact counted"
    );

    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 42);
    let txout = TxOut {
        value: Amount::from_sat(123_456),
        script_pubkey: Script::from_bytes(vec![0x51, 0xac]),
    };
    let mut stats = expected;
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
    restored_utxo.insert_parsed_record(record);
    let continued = restored_utxo
        .with_stable_view(|view| scan_coin_stats(view, restored.applied_tip.height, true))?;
    assert_eq!(listener.snapshot().to_bytes(), continued.to_bytes());
    restored_utxo.with_stable_view(|view| {
        assert_eq!(view.record_count(), 3);
        assert_eq!(view.len(), 2 + large_outputs.len());
    });
    Ok(())
}

fn utxo_from_engine(engine: &dyn bitcoin_rs_storage::KvStore) -> Result<UtxoSet, TestError> {
    let utxo = UtxoSet::new();
    for row in engine.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
        let (_key, value) = row?;
        let record =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_encoded(value.into_boxed_slice())
                .map_err(|_| TestError::Missing("the engine image holds a corrupt coin record"))?;
        utxo.insert_parsed_record(record);
    }
    Ok(utxo)
}
