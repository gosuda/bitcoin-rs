use super::*;

#[test]
fn batch_drain_restores_unapplied_tail_after_mid_batch_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    let block2_hash = Hash256::from_le_bytes(block2.block_hash().as_bytes());
    let block3_hash = Hash256::from_le_bytes(block3.block_hash().as_bytes());

    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    let block2_id = tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let mut handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let fail_once_store = Arc::new(FailOnceBodyStore::new(2));
    handles.block_body_store = Some(fail_once_store.clone());
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block3))?;
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2.clone()))?;
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block1))?;
    sync.tick();

    assert_eq!(
        applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "height 1 should apply before the fail-once height 2 body persistence error"
    );
    assert_eq!(sync.block_stager.lock().received_len(), 1);
    assert_eq!(sync.download_window.lock().received_len(), 1);
    assert!(
        !sync.block_stager.lock().contains(&block2_hash),
        "failed block should be dropped for retry rather than restored"
    );
    assert!(
        sync.block_stager.lock().contains(&block3_hash),
        "tail block must be restored after the mid-batch failure"
    );
    // The mid-batch failure must hand the gateway generation back so the
    // retry can begin a new transition. Leaving it odd refused every
    // later apply at the gate with the same "clean shutdown has begun"
    // text and no log line — the silent tip wedge observed live on the
    // explorer node (issue #618 post-#657 field report). The committed
    // prefix is per-block atomic and no authoritative UTXO mutation
    // occurred for the failed block, so the even generation is safe to
    // restore.
    assert!(
        sync.handles.mempool_gateway.stable_generation().is_some(),
        "generation must be even after mid-batch failure so the retry can begin"
    );

    // The retry actually applies: the re-sent block 2 (the fail-once
    // body store succeeds on its second attempt) must advance the tip
    // past the failed height instead of being refused at the gate.
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
    sync.tick();

    let retry_height = applied_tip.load_full().map(|tip| tip.height);
    assert!(
        retry_height.is_some_and(|height| height >= 2),
        "retry must advance past the failed height, got {retry_height:?}"
    );
    assert!(
        sync.handles.mempool_gateway.stable_generation().is_some(),
        "generation must stay even after the retry"
    );
    assert!(fail_once_store.persisted_height(1));
    Ok(())
}

#[test]
fn restore_split_pins_off_by_one() {
    // Full-chunk stop: nothing refused, restore from the next chunk head.
    // The old formula (chunk_start + stopped + 1) returned 5 here.
    assert_eq!(super::super::restore_split(2, 2, 2), 4);
    // Mid-chunk stop: the refused block is dropped, tail starts after it.
    assert_eq!(super::super::restore_split(2, 1, 2), 4);
    // Empty chunk boundary.
    assert_eq!(super::super::restore_split(0, 0, 0), 0);
}
