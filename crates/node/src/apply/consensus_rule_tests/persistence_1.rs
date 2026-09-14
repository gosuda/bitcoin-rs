use super::*;

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
