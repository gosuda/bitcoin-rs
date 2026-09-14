use super::*;

#[test]
fn retargeting_pending_requests_drops_losing_branch_hashes()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = genesis_header();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let genesis_tip = {
        let node = tree.node(genesis_id)?;
        TipSnapshot {
            tip_id: genesis_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };

    let losing1 = test_header(genesis.compute_hash(), 1);
    let losing1_id = tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
    let losing2 = test_header(losing1.compute_hash(), 2);
    let losing2_id = tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
    let losing_tip = {
        let node = tree.node(losing2_id)?;
        TipSnapshot {
            tip_id: losing2_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    let losing_hashes = vec![losing1.compute_hash(), losing2.compute_hash()];

    let winning1 = test_header(genesis.compute_hash(), 101);
    let winning1_id = tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
    let winning2 = test_header(winning1.compute_hash(), 102);
    let winning2_id = tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
    let winning3 = test_header(winning2.compute_hash(), 103);
    let winning3_id = tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
    let winning_tip = {
        let node = tree.node(winning3_id)?;
        TipSnapshot {
            tip_id: winning3_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    let winning_hashes = vec![
        winning1.compute_hash(),
        winning2.compute_hash(),
        winning3.compute_hash(),
    ];

    let chain_tip = Arc::new(ArcSwapOption::empty());
    chain_tip.store(Some(Arc::new(losing_tip)));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(genesis_tip)));
    let block_tree = Arc::new(RwLock::new(tree));
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<crate::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let sync = BlockSync::new(
        std::sync::Arc::new(TestChain::new(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            block_tree,
        )),
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    let peer = SocketAddr::from(([127, 0, 0, 1], 18_461));
    let (tx, rx) = unbounded::<Message>();
    peers.register(peer, PeerLease::new(tx));
    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing genesis applied tip"))?;
    let initial = chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing losing chain tip"))?;

    assert!(
        sync.send_getdata_for_pending_blocks(peer, false, 100, &initial, &applied)
            .sent
    );
    assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, losing_hashes);

    chain_tip.store(Some(Arc::new(winning_tip)));
    let retargeted = chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing winning chain tip"))?;
    assert!(
        sync.send_getdata_for_pending_blocks(peer, false, 100, &retargeted, &applied)
            .sent
    );
    let requested = witness_block_inventory(next_getdata(&rx)?)?;
    assert_eq!(requested, winning_hashes);
    assert!(
        requested.iter().all(|hash| !losing_hashes.contains(hash)),
        "retargeted requests must not retain hashes from the losing branch"
    );
    assert_eq!(
        sync.download_window.lock().pending_len(),
        winning_hashes.len(),
        "retargeting must release losing-branch pending capacity"
    );
    Ok(())
}

#[test]
fn outweighed_branch_target_accepts_shorter_higher_work_branch()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::CompactTarget;
    let genesis = genesis_header();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let main1 = test_header(genesis.compute_hash(), 1);
    let main1_id = tree.insert_node(Some(genesis_id), main1, NodeStatus::HeaderValid)?;
    let main2 = test_header(main1.compute_hash(), 2);
    let main2_id = tree.insert_node(Some(main1_id), main2, NodeStatus::HeaderValid)?;
    let applied = {
        let node = tree.node(main2_id)?;
        TipSnapshot {
            tip_id: main2_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };

    let mut high_work = test_header(genesis.compute_hash(), 101);
    high_work.bits = CompactTarget::from_consensus(0x2000_ffff);
    high_work.nonce = 0;
    while !pow_met(
        high_work.bits.to_consensus(),
        Hash256::from(high_work.compute_hash()),
    ) {
        high_work.nonce = high_work.nonce.wrapping_add(1);
    }
    let high_work_id = tree.insert_node(Some(genesis_id), high_work, NodeStatus::HeaderValid)?;
    let winning = tree
        .tip()
        .ok_or_else(|| std::io::Error::other("missing higher-work tip"))?;
    assert_eq!(winning.tip_id, high_work_id);
    assert!(winning.height < applied.height);
    assert!(winning.chainwork > applied.chainwork);

    let chain_tip = tree.tip_handle();
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(applied)));
    let block_tree = Arc::new(RwLock::new(tree));
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<crate::InboundBlock>();
    let sync = BlockSync::new(
        std::sync::Arc::new(TestChain::new(chain_tip, applied_tip, block_tree)),
        Arc::new(PeerTable::new()),
        Arc::new(Mutex::new(inbound_headers_rx_raw)),
        Arc::new(Mutex::new(inbound_blocks_rx_raw)),
    );

    assert_eq!(sync.outweighed_branch_target(), Some(high_work_id));
    Ok(())
}
