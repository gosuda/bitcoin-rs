use super::*;

use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

const COINS: [(u8, u32, u64, &[u8], bool); 13] = [
    (7, 3, 50_000, &[0x51, 0x21], true),
    (0x11, 0, 1_000, &[0x51], false),
    (0x11, 3, 2_500, &[0x51, 0x52], false),
    (0x33, 0, 7, &[0x6a; 25], false),
    (0x39, 1, 10_000, &[0x51, 0x00, 0xac], true),
    (0x39, 4, 10_137, &[0x51, 0x01, 0xac], false),
    (0x39, 7, 10_274, &[0x51, 0x02, 0xac], true),
    (0x39, 10, 10_411, &[0x51, 0x03, 0xac], false),
    (0x39, 13, 10_548, &[0x51, 0x04, 0xac], true),
    (0x39, 16, 10_685, &[0x51, 0x05, 0xac], false),
    (0x39, 19, 10_822, &[0x51, 0x06, 0xac], true),
    (0x39, 22, 10_959, &[0x51, 0x07, 0xac], false),
    (0x39, 25, 11_096, &[0x51, 0x08, 0xac], true),
];
const EXPECTED_UTXO_COUNT: u64 = 13;
const EXPECTED_TOTAL_AMOUNT: u64 = 148_439;
const EXPECTED_BOGO_SIZE: u64 = 52 + 51 + 52 + 75 + 53 * 9;

fn record(
    txid_byte: u8,
    outputs: &[(u32, u64, &[u8], bool)],
) -> Result<UtxoRecord, bitcoin_rs_storage::utxo::UtxoError> {
    let outs: Vec<OwnedUtxoOut> = outputs
        .iter()
        .map(|&(vout, value, script, coinbase)| OwnedUtxoOut {
            vout,
            value,
            script_pubkey: script.to_vec(),
            coinbase,
            height: 0,
        })
        .collect();
    UtxoRecord::from_owned_outputs(Hash256::from_le_bytes(&[txid_byte; 32]), &outs)
}

fn hand_built_utxo() -> Result<UtxoSet, bitcoin_rs_storage::utxo::UtxoError> {
    let utxo = populated_utxo()?;
    utxo.insert_parsed_record(record(
        0x11,
        &[(0, 1_000, &[0x51], false), (3, 2_500, &[0x51, 0x52], false)],
    )?);
    utxo.insert_parsed_record(record(0x33, &[(0, 7, &[0x6a; 25], false)])?);
    utxo.insert_parsed_record(record(
        0x39,
        &[
            (1, 10_000, &[0x51, 0x00, 0xac], true),
            (4, 10_137, &[0x51, 0x01, 0xac], false),
            (7, 10_274, &[0x51, 0x02, 0xac], true),
            (10, 10_411, &[0x51, 0x03, 0xac], false),
            (13, 10_548, &[0x51, 0x04, 0xac], true),
            (16, 10_685, &[0x51, 0x05, 0xac], false),
            (19, 10_822, &[0x51, 0x06, 0xac], true),
            (22, 10_959, &[0x51, 0x07, 0xac], false),
            (25, 11_096, &[0x51, 0x08, 0xac], true),
        ],
    )?);
    Ok(utxo)
}

fn rolling_stats() -> CoinStats {
    let mut stats = CoinStats::new();
    for (txid_byte, vout, value, script, coinbase) in COINS {
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[txid_byte; 32])), vout);
        let txout = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(script.to_vec()),
        };
        stats.insert_utxo(&outpoint, &txout, 0, coinbase);
    }
    stats
}

#[test]
fn scanned_trailer_restores_independently_scanned_stats() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = hand_built_utxo()?;
    let expected = rolling_stats();
    assert_eq!(expected.utxo_count, EXPECTED_UTXO_COUNT);
    assert_eq!(expected.total_amount, EXPECTED_TOTAL_AMOUNT);
    assert_eq!(expected.bogo_size, EXPECTED_BOGO_SIZE);
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
    assert_eq!(restored.coin_stats.utxo_count, EXPECTED_UTXO_COUNT);
    assert_eq!(restored.coin_stats.total_amount, EXPECTED_TOTAL_AMOUNT);
    assert_eq!(restored.coin_stats.bogo_size, EXPECTED_BOGO_SIZE);
    assert_eq!(restored.coin_stats, expected);

    let engine = restored.engine.as_ref().ok_or(TestError::Missing(
        "the checkpoint generation carries no engine image",
    ))?;
    let restored_utxo = utxo_from_engine(engine.as_ref())?;
    restored_utxo.with_stable_view(|view| -> Result<(), TestError> {
        assert_eq!(view.record_count(), 4);
        assert_eq!(view.len(), COINS.len());
        for (txid_byte, vout, value, script, coinbase) in COINS {
            let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[txid_byte; 32])), vout);
            let coin = view.get_entry(&outpoint).ok_or(TestError::Missing(
                "the restored engine image is missing a fixture output",
            ))?;
            assert_eq!(coin.outpoint, outpoint);
            assert_eq!(coin.txout.value, Amount::from_sat(value));
            assert_eq!(coin.txout.script_pubkey.as_bytes(), script);
            assert_eq!(coin.coinbase, coinbase);
            assert_eq!(coin.height, 0);
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
        assert_eq!(view.record_count(), 5);
        assert_eq!(view.len(), COINS.len() + 1);
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
