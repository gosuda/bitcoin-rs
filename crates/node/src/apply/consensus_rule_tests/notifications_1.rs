use super::*;

#[test]
fn apply_block_publishes_rawtx_bytes_in_block_order() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let external_prevout = OutPoint::new(fixture_txid(0x96), 0);
    let publisher = Arc::new(RecordingRawTxPublisher::default());
    let publisher_for_handles: Arc<dyn crate::ZmqPublisher> = publisher.clone();
    let handles =
        apply_handles_without_tx_index(Network::Regtest, utxo_with_output(external_prevout, 1)?)
            .capturing(true, false);
    let followers = zmq_followers(publisher_for_handles);
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let txdata = vec![
        coinbase_transaction(0x96),
        spending_transaction_to_script(external_prevout, u32::MAX, op_true_script()),
    ];
    let expected_raw_txs = txdata.iter().map(consensus_bytes).collect::<Vec<_>>();
    let block = mined_block_with_prev_hash_and_transactions(genesis.block_hash(), txdata)?;

    apply_followed(&handles, &followers, &block)?;

    assert_eq!(*publisher.raw_txs.lock(), expected_raw_txs);
    Ok(())
}

#[test]
fn apply_block_publishes_full_rawblock_bytes_when_only_rawblock_is_requested()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let publisher = Arc::new(RecordingRawBlockPublisher::default());
    let publisher_for_handles: Arc<dyn crate::ZmqPublisher> = publisher.clone();
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
        .capturing(false, true);
    assert!(handles.block_body_store.is_none());
    let followers = zmq_followers(publisher_for_handles);
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let expected_block_bytes = consensus_bytes(&block);

    apply_followed(&handles, &followers, &block)?;

    let published = publisher
        .raw_block
        .lock()
        .clone()
        .unwrap_or_else(|| panic!("rawblock bytes should be published"));
    assert_eq!(published, expected_block_bytes);
    assert!(published.len() > consensus_bytes(&block.header).len());
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn apply_block_skips_zmq_publish_loop_when_publisher_opts_out()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let publisher: Arc<dyn crate::ZmqPublisher> = Arc::new(PanickingOptOutPublisher);
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let followers = zmq_followers(publisher);
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;

    apply_followed(&handles, &followers, &block)?;

    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn apply_block_skips_rawblock_publish_when_publisher_opts_out()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let publisher: Arc<dyn crate::ZmqPublisher> = Arc::new(PanickingNoRawblockPublisher);
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
        .capturing(false, true);
    assert!(handles.block_body_store.is_none());
    let followers = zmq_followers(publisher);
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;

    apply_followed(&handles, &followers, &block)?;

    Ok(())
}

/// A connected block always fires the fee estimator's `block_connected`,
/// even when the pool is empty and the block confirms nothing the pool
/// tracked. The estimator ages one height per call regardless, so
/// `estimator_last_decayed_height` advancing from `None` to `Some(height)`
/// on an empty pool is the proof that `remove_for_block` ran.
#[test]
fn apply_sweep_records_fee_estimator_confirmation() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    handles.chain_tx_count.store(1, Ordering::Relaxed);

    // The pool starts empty — no transaction has entered it.
    assert!(
        handles.mempool_gateway.read().is_empty(),
        "pool must start empty for the empty-pool estimator proof"
    );
    assert_eq!(
        handles
            .mempool_gateway
            .read()
            .estimator_last_decayed_height(),
        None,
        "estimator must not have aged before any block connects"
    );

    // Connect a block whose only transaction is a coinbase the pool never
    // tracked. The pool stays empty, but the estimator must still age.
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let applied = handles.apply_block(&block)?.tip;
    assert_eq!(applied.height, 1, "the block must connect first");
    assert!(
        handles.mempool_gateway.read().is_empty(),
        "pool must still be empty — the coinbase was never in it"
    );
    assert_eq!(
        handles
            .mempool_gateway
            .read()
            .estimator_last_decayed_height(),
        Some(1),
        "a connected block must fire block_connected even with an empty pool"
    );

    // A second block with no tracked transactions must age the estimator
    // again, proving the sweep is not gated on pool non-emptiness.
    let block2 = mined_block_with_prev_hash_and_transactions(
        block.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let applied2 = handles.apply_block(&block2)?.tip;
    assert_eq!(applied2.height, 2);
    assert_eq!(
        handles
            .mempool_gateway
            .read()
            .estimator_last_decayed_height(),
        Some(2),
        "every connected block must age the estimator, including empty-pool blocks"
    );
    Ok(())
}
