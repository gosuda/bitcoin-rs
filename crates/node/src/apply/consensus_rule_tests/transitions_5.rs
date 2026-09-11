use super::*;

#[test]
fn precommit_persist_failure_leaves_utxo_and_tip_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let mut handles = empty_apply_handles_for_network(Network::Regtest);
    let genesis = Network::Regtest.genesis_block();
    let genesis_tip = applied_header_tip(&handles, genesis.block_hash().0, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let applied = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    handles.apply_block(&applied)?;
    let applied_hash = applied.block_hash().0;
    let utxo_len = handles.utxo.len();
    handles.undo_store = Arc::new(FailingUndoPersist {
        inner: InMemoryUndoStore::default(),
    });
    let next = mined_block_with_prev_hash_and_transactions(
        applied.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let next_hash = next.block_hash().0;

    let outcome = handles.apply_block(&next).map(|outcome| outcome.tip);
    assert!(
        matches!(outcome, Err(ApplyError::UndoPersistence(_))),
        "the injected persist failure must surface as UndoPersistence, got {outcome:?}"
    );
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_hash),
        "a precommit bookkeeping failure must not move the tip"
    );
    assert_eq!(handles.utxo.len(), utxo_len, "no outputs may commit");
    assert!(
        handles.block_tree.read().node_by_hash(next_hash).is_none(),
        "fallible tree preparation must precede the first UTXO mutation and stay absent on failure"
    );
    Ok(())
}
