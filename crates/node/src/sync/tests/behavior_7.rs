use super::*;

/// Done-when #629 (reorg / cancellation / stale-parent release): a window
/// that fails in the middle must return its un-applied work to the stager
/// untouched, and the staged round-trip must stay applicable once the
/// failure clears. Nothing released may be committed early, dropped, or
/// re-drained in a form that cannot re-apply on the same parent.
///
/// The failure here is operational (a body-store persistence error), the
/// class a reorg or stale-parent abort shares: nothing committed past the
/// failure, so the dependent suffix has to be releasable in one piece.
#[test]
fn mid_window_failure_releases_retained_work_to_the_stager()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    let block4 = mined_block_with_prev_hash(block3.block_hash(), 4, vec![coinbase_transaction(4)]);

    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    let block2_id = tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
    let block3_id = tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block3_id), block4.header, NodeStatus::HeaderValid)?;

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));

    let mut handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let fail_once_store = Arc::new(FailOnceBodyStore::new(2));
    handles.block_body_store = Some(fail_once_store);
    let sync = BlockSync::for_test(handles, peers, inbound_headers_rx, inbound_blocks_rx);
    sync.ensure_genesis_tip();

    let blocks = [block1, block2, block3, block4];
    for block in &blocks {
        stage_body(&sync, block);
    }
    assert_eq!(
        sync.block_stager.lock().received_len(),
        4,
        "all four bodies start staged"
    );

    // Block 2's persistence fails after block 1 committed: the retained
    // window work — blocks 2, 3, 4 — must land back on the stager untouched
    // (block 2 is the refused blocker, dropped for retry).
    let (applied, failed) = sync.apply_buffered_blocks(None);
    assert_eq!((applied, failed), (1, 1), "prefix commits, suffix releases");
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "only the committed prefix may move the applied tip"
    );
    assert_eq!(
        sync.block_stager.lock().received_len(),
        2,
        "blocks 3 and 4 must be restored to bounded staging, not held or lost"
    );
    for block in &blocks[2..] {
        assert!(
            sync.block_stager
                .lock()
                .staged_body(Hash256::from_le_bytes(block.block_hash().as_bytes()))
                .is_some(),
            "restored block must still be drainable with its original body"
        );
    }

    // The round-trip must be applicable: clear the transient failure
    // (re-stage the refused blocker, as the retry path does) and the
    // released work drains and applies on the same parent.
    stage_body(&sync, &blocks[1]);
    let (applied, failed) = sync.apply_buffered_blocks(None);
    assert_eq!(
        (applied, failed),
        (3, 0),
        "the released suffix plus retried blocker must apply once the failure clears"
    );
    assert_eq!(applied_tip.load_full().map(|tip| tip.height), Some(4));
    assert_eq!(
        sync.block_stager.lock().received_len(),
        0,
        "nothing staged may survive a completed round"
    );
    Ok(())
}
