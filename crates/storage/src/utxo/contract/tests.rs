use super::*;
use crate::InMemoryUndoStore;
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime, OutPoint,
    Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};

use crate::utxo::test_support::{TestError, TestResult};

const HEIGHT: u32 = 91;
const HASH: Hash256 = Hash256::from_le_bytes(&[0x5a; 32]);
const FUNDED: OutPoint = OutPoint {
    txid: Txid(Hash256::from_le_bytes(&[0x31; 32])),
    vout: 0,
};
const CREATED: OutPoint = OutPoint {
    txid: Txid(Hash256::from_le_bytes(&[0x42; 32])),
    vout: 0,
};

fn coin(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: Script::from_bytes(vec![0x51]),
    }
}

#[test]
fn spent_output_projection_orders_inputs_and_ignores_bip30_restorations() -> TestResult {
    let mut cb = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![0x01, 0x01].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![coin(50)],
    };
    let spend = |previous_output, value| Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![coin(value)],
    };
    let parent = spend(FUNDED, 800);
    let same_block = OutPoint::new(parent.txid(), 0);
    let child = spend(same_block, 700);
    let mut undo = UndoBatch::empty();
    undo.restore(UtxoAdd::new(OutPoint::new(cb.txid(), 0), coin(60), true, 1));
    undo.restore(UtxoAdd::new(FUNDED, coin(900), true, 2));
    let block = Block {
        header: bitcoin_rs_consensus::primitives::Network::Regtest
            .genesis_block()
            .header,
        txs: vec![cb.clone(), parent, child],
    };
    let spent = block_spent_outputs(&block, HEIGHT, &undo)?;
    assert_eq!(spent[0], Vec::<UtxoCoin>::new());
    assert_eq!(
        spent[1],
        vec![UtxoCoin {
            outpoint: FUNDED,
            txout: coin(900),
            coinbase: true,
            height: 2
        }]
    );
    assert_eq!(
        spent[2],
        vec![UtxoCoin {
            outpoint: same_block,
            txout: coin(800),
            coinbase: false,
            height: HEIGHT
        }]
    );
    let missing = UndoBatch::empty();
    assert!(matches!(
        block_spent_outputs(&block, HEIGHT, &missing),
        Err(BlockSpendsError::Corrupt(_))
    ));
    cb.outputs.clear();
    let no_outputs = Block {
        header: block.header,
        txs: vec![cb],
    };
    let bytes = crate::utxo::undo_codec::encode(&undo, no_outputs.block_hash().into());
    assert!(decode_undo_record(&bytes, no_outputs.block_hash().into()).is_ok());
    assert!(matches!(
        decode_undo_record_for_block(&bytes, &no_outputs),
        Err(UndoCodecError::BlockCountLimit { .. })
    ));
    Ok(())
}

struct NoSpend;
impl SpentOutputLookup for NoSpend {
    fn entry(&self, _outpoint: &OutPoint) -> Option<&UtxoCoin> {
        None
    }
}

fn sample_undo() -> UndoBatch {
    let mut undo = UndoBatch::empty();
    undo.restore(UtxoAdd::new(FUNDED, coin(900), false, 1));
    undo.remove(CREATED);
    undo
}
#[test]
fn persisted_record_survives_reopening_the_store() -> TestResult {
    use std::sync::Arc;

    use crate::{KvUndoStore, RocksDbStore};

    let dir = tempfile::tempdir()?;
    let undo = sample_undo();
    persist_block_undo(
        &KvUndoStore::new(Arc::new(RocksDbStore::open(dir.path())?)),
        HEIGHT,
        HASH,
        &undo,
    )?;
    let reopened = KvUndoStore::new(Arc::new(RocksDbStore::open(dir.path())?));
    assert_eq!(load_block_undo(&reopened, HEIGHT, HASH)?, undo);
    Ok(())
}

#[test]
fn missing_and_foreign_records_are_refused() -> TestResult {
    let store = InMemoryUndoStore::default();
    let outcome = load_block_undo(&store, HEIGHT, HASH);
    assert!(
        matches!(outcome, Err(UndoLoadError::Missing { hash, height }) if hash == HASH && height == HEIGHT),
        "{outcome:?}"
    );

    let other = Hash256::from_le_bytes(&[0xab; 32]);
    let record = persist_block_undo(&store, HEIGHT, other, &UndoBatch::empty())?;
    store.persist_undo(HEIGHT, HASH, record.as_bytes())?;
    let outcome = load_block_undo(&store, HEIGHT, HASH);
    assert!(
        matches!(outcome, Err(UndoLoadError::Unreadable { hash, .. }) if hash == HASH),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn persisted_record_bytes_decode_back_to_the_batch() -> TestResult {
    let undo = sample_undo();
    let store = InMemoryUndoStore::default();
    let record = persist_block_undo(&store, HEIGHT, HASH, &undo)?;
    assert_eq!(decode_undo_record(record.as_bytes(), HASH)?, undo);
    assert_eq!(load_block_undo(&store, HEIGHT, HASH)?, undo);
    Ok(())
}

#[test]
fn populate_block_changes_applies_adds_and_spends_to_coin_store() -> TestResult {
    use crate::{CoinKey, CoinStore, MemoryKvStore};
    use std::sync::Arc;
    let store = Arc::new(MemoryKvStore::new());
    let coin_store = CoinStore::open(store, 64 * 1024 * 1024);

    let mut block1 = BlockChanges::default();
    block1.add(UtxoAdd::new(FUNDED, coin(900), false, 1));
    let untouched = OutPoint::new(FUNDED.txid, 3);
    block1.add(UtxoAdd::new(untouched, coin(125), true, 2));
    let spent = OutPoint::new(FUNDED.txid, 1);
    block1.add(UtxoAdd::new(spent, coin(200), false, 2));
    populate_block_changes(&coin_store, &block1)?;

    let key_funded = CoinKey(FUNDED.txid.0.to_le_bytes());
    let coin1 = coin_store
        .get(&key_funded)?
        .ok_or(TestError::Missing("funded exists"))?;
    let record1 = crate::utxo::record::UtxoRecord::from_encoded(coin1.to_vec().into_boxed_slice())?;
    assert_eq!(record1.find_output(FUNDED.vout).map(|o| o.value), Some(900));

    let mut block2 = BlockChanges::default();
    block2.remove(FUNDED);
    block2.remove(spent);
    block2.add(UtxoAdd::new(FUNDED, coin(700), false, 3));
    block2.add(UtxoAdd::new(
        FUNDED,
        TxOut {
            value: Amount::from_sat(650),
            script_pubkey: Script::from_bytes(vec![0x52, 0x53]),
        },
        true,
        4,
    ));
    block2.add(UtxoAdd::new(CREATED, coin(850), false, HEIGHT));
    populate_block_changes(&coin_store, &block2)?;

    let funded = coin_store.get(&key_funded)?.ok_or(TestError::Missing(
        "replacement and untouched outputs exist",
    ))?;
    let funded_record =
        crate::utxo::record::UtxoRecord::from_encoded(funded.to_vec().into_boxed_slice())?;
    let funded_outputs: Vec<_> = funded_record
        .outputs()
        .map(|out| {
            (
                out.vout,
                out.value,
                out.script_pubkey.to_vec(),
                out.coinbase,
                out.height,
            )
        })
        .collect();
    assert_eq!(
        funded_outputs,
        vec![
            (0, 650, vec![0x52, 0x53], true, 4),
            (3, 125, vec![0x51], true, 2),
        ]
    );
    let key_created = CoinKey(CREATED.txid.0.to_le_bytes());
    let coin2 = coin_store
        .get(&key_created)?
        .ok_or(TestError::Missing("created exists"))?;
    let record2 = crate::utxo::record::UtxoRecord::from_encoded(coin2.to_vec().into_boxed_slice())?;
    assert_eq!(
        record2.find_output(CREATED.vout).map(|o| o.value),
        Some(850)
    );

    Ok(())
}

fn block_with_short_txids() -> (Block, Vec<Txid>) {
    let make_tx = |seed: u8| Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), u32::MAX),
            script_sig: vec![0x00].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![coin(500)],
    };
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0x2100_ffff),
            nonce: 0,
        },
        txs: vec![make_tx(1), make_tx(2)],
    };
    let txids = vec![Txid(Hash256::from_le_bytes(&[0x77; 32]))];
    (block, txids)
}

#[test]
fn a_short_txid_list_is_refused_at_every_height() {
    let (block, txids) = block_with_short_txids();
    for height in [0, HEIGHT] {
        let outcome = build_block_changes(
            &BlockChangeInputs {
                block: &BlockImage::from_local(block.clone()),
                height,
                txids: &txids,
                same_block_spent: None,
                add_capacity: 4,
                remove_capacity: 4,
                max_script_size: 64,
            },
            &NoSpend,
        );
        assert!(
            matches!(
                outcome,
                Err(BlockChangeError::TxidCountMismatch {
                    transactions: 2,
                    txids: 1
                })
            ),
            "a short txid list was accepted at height {height}"
        );
    }
}

fn spending(previous_output: OutPoint, outputs: Vec<TxOut>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs,
    }
}

fn shaped_block() -> Block {
    let coinbase_tx = spending(
        OutPoint::null(),
        vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    );
    let parent = spending(FUNDED, vec![coin(90), coin(5)]);
    let child = spending(OutPoint::new(parent.txid(), 0), vec![coin(80)]);
    Block {
        header: bitcoin_rs_consensus::primitives::Network::Regtest
            .genesis_block()
            .header,
        txs: vec![coinbase_tx, parent, child],
    }
}

fn shaped_undo(block: &Block) -> UndoBatch {
    let mut undo = UndoBatch::empty();
    undo.restore(UtxoAdd::new(FUNDED, coin(90), false, HEIGHT - 1));
    undo.remove(OutPoint::new(block.txs[0].txid(), 0));
    undo.remove(OutPoint::new(block.txs[1].txid(), 1));
    undo.remove(OutPoint::new(block.txs[2].txid(), 0));
    undo
}

// RCV-08
#[test]
fn undo_validation_matches_the_block_shape() -> TestResult {
    const MAX_SCRIPT_SIZE: usize = 10_000;
    let block = shaped_block();
    let txids: Vec<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
    let check = BlockUndoCheck {
        block: &block,
        txids: &txids,
        max_script_size: MAX_SCRIPT_SIZE,
    };
    let undo = shaped_undo(&block);
    assert_eq!(validate_undo_for_block(&check, HEIGHT, &undo), Ok(()));

    let short = BlockUndoCheck {
        block: &block,
        txids: &txids[..2],
        max_script_size: MAX_SCRIPT_SIZE,
    };
    assert!(
        matches!(
            validate_undo_for_block(&short, HEIGHT, &undo),
            Err(UndoCodecError::BlockMismatch { .. })
        ),
        "a short transaction id slice must refuse instead of validating fewer transactions"
    );

    let mut extra_remove = shaped_undo(&block);
    extra_remove.remove(OutPoint::new(block.txs[1].txid(), 0));
    assert!(matches!(
        validate_undo_for_block(&check, HEIGHT, &extra_remove),
        Err(UndoCodecError::BlockMismatch { .. })
    ));

    let mut foreign_restore = shaped_undo(&block);
    foreign_restore.restore(UtxoAdd::new(CREATED, coin(1), false, HEIGHT - 1));
    assert!(matches!(
        validate_undo_for_block(&check, HEIGHT, &foreign_restore),
        Err(UndoCodecError::BlockMismatch { .. })
    ));

    let mut future_restore = shaped_undo(&block);
    future_restore.restore(UtxoAdd::new(FUNDED, coin(90), false, HEIGHT));
    assert!(matches!(
        validate_undo_for_block(&check, HEIGHT, &future_restore),
        Err(UndoCodecError::BlockMismatch { .. })
    ));

    let mut missing_restore = UndoBatch::empty();
    missing_restore.remove(OutPoint::new(block.txs[0].txid(), 0));
    missing_restore.remove(OutPoint::new(block.txs[1].txid(), 1));
    missing_restore.remove(OutPoint::new(block.txs[2].txid(), 0));
    assert!(matches!(
        validate_undo_for_block(&check, HEIGHT, &missing_restore),
        Err(UndoCodecError::BlockMismatch { .. })
    ));

    let mut overwritten = UndoBatch::empty();
    overwritten.restore(UtxoAdd::new(FUNDED, coin(90), false, HEIGHT - 1));
    overwritten.restore(UtxoAdd::new(
        OutPoint::new(block.txs[1].txid(), 1),
        coin(1),
        false,
        HEIGHT - 2,
    ));
    overwritten.remove(OutPoint::new(block.txs[0].txid(), 0));
    overwritten.remove(OutPoint::new(block.txs[2].txid(), 0));
    assert_eq!(
        validate_undo_for_block(&check, HEIGHT, &overwritten),
        Ok(()),
        "a BIP30 overwrite restores the replaced output instead of removing it"
    );
    Ok(())
}

#[test]
fn every_undo_truncation_and_flip_is_refused_or_canonical() -> TestResult {
    let hash = Hash256::from_le_bytes(&[0x5A; 32]);
    let mut batch = UndoBatch::empty();
    batch.restore(UtxoAdd::new(FUNDED, coin(50_000), true, 11));
    let second = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x32; 32])), 7);
    batch.restore(UtxoAdd::new(
        second,
        TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![0x51; 129]),
        },
        false,
        12,
    ));
    batch.remove(OutPoint::new(Txid(Hash256::from_le_bytes(&[0x33; 32])), 2));
    let bytes = crate::utxo::undo_codec::encode(&batch, hash);
    for cut in 0..bytes.len() {
        assert!(
            crate::utxo::undo_codec::decode(&bytes[..cut], hash).is_err(),
            "truncation at {cut} decoded"
        );
    }
    for (index, byte) in bytes.iter().enumerate() {
        for bit in 0..8_u8 {
            let mut mutated = bytes.clone();
            mutated[index] = *byte ^ (1 << bit);
            let Ok(decoded) = crate::utxo::undo_codec::decode(&mutated, hash) else {
                continue;
            };
            assert_eq!(
                crate::utxo::undo_codec::encode(&decoded, hash),
                mutated,
                "flip at byte {index} bit {bit} decoded to a non-canonical batch"
            );
        }
    }
    Ok(())
}

#[test]
fn coin_stats_feed_tracks_utxo_accounting_through_populate() -> TestResult {
    use crate::utxo::stats::{CoinStats, CoinStatsListener};
    use crate::{CoinStore, MemoryKvStore};
    use std::sync::Arc;
    let store = Arc::new(MemoryKvStore::new());
    let coin_store = CoinStore::open(store, 64 * 1024 * 1024);
    let listener = CoinStatsListener::new(CoinStats::new());
    coin_store.track_coin_stats(listener.clone());

    let mut block1 = BlockChanges::default();
    block1.add(UtxoAdd::new(FUNDED, coin(900), false, 1));
    block1.add(UtxoAdd::new(CREATED, coin(700), true, 1));
    populate_block_changes(&coin_store, &block1)?;
    listener.finish_block(1, 2);

    let mut expected = CoinStats::new();
    expected.insert_utxo(&FUNDED, &coin(900), 1, false);
    expected.insert_utxo(&CREATED, &coin(700), 1, true);
    expected.finish_block(1, 2);
    assert_eq!(listener.snapshot(), expected);

    let mut block2 = BlockChanges::default();
    block2.remove(CREATED);
    block2.add(UtxoAdd::new(FUNDED, coin(800), false, 2));
    populate_block_changes(&coin_store, &block2)?;
    listener.finish_block(2, 1);

    expected.remove_utxo(&CREATED, &coin(700), 1, true);
    expected.remove_utxo(&FUNDED, &coin(900), 1, false);
    expected.insert_utxo(&FUNDED, &coin(800), 2, false);
    expected.finish_block(2, 1);
    assert_eq!(listener.snapshot(), expected);
    Ok(())
}
