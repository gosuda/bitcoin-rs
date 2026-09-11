use super::*;

/// The record has to outlive the process that wrote it: a node restarted
/// mid-chain must still be able to disconnect its own tip. An in-memory
/// store cannot show that, so this one closes the backend and reopens it,
/// then checks every restored field rather than just the byte length.
#[cfg(feature = "fjall")]
#[test]
fn a_persisted_undo_record_survives_closing_and_reopening_the_store()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_utxo::UndoBatch;
    use bitcoin_rs_utxo::UtxoAdd;
    use bitcoin_rs_utxo::undo_codec;

    let dir = tempfile::tempdir()?;
    let block_hash = Hash256::from_le_bytes(&[0x5a; 32]);
    let outpoint = OutPoint::new(fixture_txid(0x2c), 7);
    let removed = OutPoint::new(fixture_txid(0x3d), 1);
    let txout = TxOut {
        value: Amount::from_sat(123_456),
        script_pubkey: Script::from_bytes(op_true_script()),
    };

    let mut batch = UndoBatch::default();
    batch.restore(UtxoAdd::new(outpoint, txout.clone(), true, 91));
    batch.remove(removed);
    let encoded = undo_codec::encode(&batch, block_hash);

    {
        let store = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
        KvUndoStore::new(store).persist_undo(91, block_hash, &encoded)?;
    }

    let reopened = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
    let loaded = KvUndoStore::new(reopened)
        .load_undo(91, block_hash)?
        .ok_or("undo record did not survive the reopen")?;

    let decoded = undo_codec::decode(&loaded, block_hash)?;
    let restored = decoded
        .restores()
        .first()
        .ok_or("restored entry missing after reopen")?;
    assert_eq!(restored.outpoint, outpoint, "outpoint must round-trip");
    assert_eq!(restored.txout, txout, "spent output must round-trip");
    assert!(restored.coinbase, "coinbase flag must round-trip");
    assert_eq!(restored.height, 91, "creating height must round-trip");
    assert_eq!(
        decoded.removes(),
        batch.removes(),
        "outputs to remove must round-trip"
    );
    Ok(())
}

/// Layer-2 acceptance: connecting a block leaves a decodable undo record
/// bound to that block, which is the prerequisite for ever disconnecting it.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn apply_block_persists_a_decodable_undo_record() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let block_hash = Hash256::from(block.block_hash());
    handles.apply_block(&block)?;

    let record = handles
        .undo_store
        .load_undo(1, block_hash)?
        .ok_or_else(|| std::io::Error::other("undo record missing after apply"))?;
    let undo = bitcoin_rs_utxo::decode_undo(&record, block_hash)?;

    // A coinbase-only block creates one output and spends nothing, so its
    // inverse removes that output and restores nothing.
    assert_eq!(undo.removes().len(), 1);
    assert!(undo.restores().is_empty());

    // The record is bound to its block: it must refuse another hash.
    let other = Hash256::from_le_bytes(&[0xAB; 32]);
    assert!(bitcoin_rs_utxo::decode_undo(&record, other).is_err());
    Ok(())
}
