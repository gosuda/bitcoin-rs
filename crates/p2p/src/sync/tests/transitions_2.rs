use super::*;

/// A two-branch retarget fixture: the header tip starts on a two-block
/// losing branch, and one peer has been sent getdata for both of its
/// blocks. Storing `winning_tip` into `chain_tip` retargets the request
/// branch to a three-block winning branch at the next request.
struct TwoBranches {
    sync: BlockSync,
    rx: crossbeam_channel::Receiver<Message>,
    source: PeerSource,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    losing_hashes: Vec<BlockHash>,
    losing_bodies: Vec<Block>,
    winning_tip: TipSnapshot,
    winning_hashes: Vec<BlockHash>,
}

fn two_branches() -> Result<TwoBranches, Box<dyn std::error::Error>> {
    let snapshot = |tree: &BlockTree, tip_id| -> Result<TipSnapshot, Box<dyn std::error::Error>> {
        let node = tree.node(tip_id)?;
        Ok(TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })
    };
    let genesis = genesis_header();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let genesis_tip = snapshot(&tree, genesis_id)?;

    let losing_body1 =
        mined_block_with_prev_hash(genesis.compute_hash(), 1, vec![coinbase_transaction(1)]);
    let losing_body2 =
        mined_block_with_prev_hash(losing_body1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let losing1_id = tree.insert_node(
        Some(genesis_id),
        losing_body1.header,
        NodeStatus::HeaderValid,
    )?;
    let losing2_id = tree.insert_node(
        Some(losing1_id),
        losing_body2.header,
        NodeStatus::HeaderValid,
    )?;
    let losing_tip = snapshot(&tree, losing2_id)?;
    let losing_hashes = vec![losing_body1.block_hash(), losing_body2.block_hash()];
    let losing_bodies = vec![losing_body1, losing_body2];

    let winning1 = test_header(genesis.compute_hash(), 101);
    let winning1_id = tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
    let winning2 = test_header(winning1.compute_hash(), 102);
    let winning2_id = tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
    let winning3 = test_header(winning2.compute_hash(), 103);
    let winning3_id = tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
    let winning_tip = snapshot(&tree, winning3_id)?;
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
        crate::sync::syncing_ibd_latch(),
    );
    let peer = SocketAddr::from(([127, 0, 0, 1], 18_461));
    let (tx, rx) = unbounded::<Message>();
    peers.register(peer, PeerLease::new(tx));
    let source = current_source(&sync.peer_table, peer);

    assert!(
        sync.send_getdata_for_pending_blocks(source, false, 100, &test_frontier(&sync))
            .sent
    );
    assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, losing_hashes);
    Ok(TwoBranches {
        sync,
        rx,
        source,
        chain_tip,
        losing_hashes,
        losing_bodies,
        winning_tip,
        winning_hashes,
    })
}

#[test]
fn retargeting_pending_requests_drops_losing_branch_hashes()
-> Result<(), Box<dyn std::error::Error>> {
    let TwoBranches {
        sync,
        rx,
        source,
        chain_tip,
        losing_hashes,
        winning_tip,
        winning_hashes,
        ..
    } = two_branches()?;

    chain_tip.store(Some(Arc::new(winning_tip)));
    assert!(
        sync.send_getdata_for_pending_blocks(source, false, 100, &test_frontier(&sync))
            .sent
    );
    let requested = witness_block_inventory(next_getdata(&rx)?)?;
    assert_eq!(requested, winning_hashes);
    assert!(
        requested.iter().all(|hash| !losing_hashes.contains(hash)),
        "retargeted requests must not retain hashes from the losing branch"
    );
    assert_eq!(
        sync.scheduler.lock().window.pending_len(),
        winning_hashes.len(),
        "retargeting must release losing-branch pending capacity"
    );
    Ok(())
}

/// BLK-08: a retarget releases losing-branch bodies from the stager as well
/// as the window, so the freed capacity is real, and a late losing-branch
/// delivery cannot re-acquire purged state.
#[test]
fn retarget_purges_staged_off_branch_bodies() -> Result<(), Box<dyn std::error::Error>> {
    let TwoBranches {
        sync,
        rx,
        source,
        chain_tip,
        losing_hashes,
        losing_bodies,
        winning_tip,
        winning_hashes,
    } = two_branches()?;
    let [losing1, losing2]: [Block; 2] = losing_bodies
        .try_into()
        .map_err(|_| "the fixture has two losing bodies")?;
    let mut delivery = vec![crate::InboundBlock::from_decoded(losing1)];
    assert_eq!(sync.buffer_received_block_chunk(&mut delivery, None), 1);
    assert_eq!(sync.scheduler.lock().stager.received_len(), 1);

    chain_tip.store(Some(Arc::new(winning_tip)));
    assert!(
        sync.send_getdata_for_pending_blocks(source, false, 100, &test_frontier(&sync))
            .sent
    );
    assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, winning_hashes);
    assert_eq!(
        sync.scheduler.lock().stager.received_len(),
        0,
        "the retarget must purge the staged losing-branch body"
    );

    let mut late = vec![crate::InboundBlock::from_decoded(losing2)];
    assert_eq!(
        sync.buffer_received_block_chunk(&mut late, None),
        0,
        "the late losing-branch delivery must be discarded, not staged"
    );
    let scheduler = sync.scheduler.lock();
    assert_eq!(
        scheduler.stager.received_len(),
        0,
        "a late losing-branch delivery must not stage"
    );
    assert!(
        losing_hashes
            .iter()
            .all(|hash| !scheduler.window.contains_pending(&Hash256::from(*hash))),
        "no losing-branch hash may be pending after the retarget"
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

    let SyncHarness {
        sync,
        applied_tip,
        inbound_headers_tx: _inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    applied_tip.store(Some(Arc::new(applied)));

    assert_eq!(sync.outweighed_branch_target(), Some(high_work_id));
    Ok(())
}
