use super::*;
use crate::download_window::default_sync_budget;

type HistoricalFixture = (SyncHarness, Arc<TestChain>, Vec<Block>);

fn fixture(count: u32) -> Result<HistoricalFixture, Box<dyn std::error::Error>> {
    let (tree, blocks) = mined_chain(count, 0)?;
    let mut harness = SyncHarness::new(tree);
    let chain = Arc::new(TestChain::new(
        harness.block_tree.write().tip_handle(),
        harness.applied_tip.clone(),
        harness.block_tree.clone(),
    ));
    chain
        .historical
        .lock()
        .extend((1..=count).zip(blocks.iter().map(|block| block.block_hash().0)));
    harness.sync.chain = chain.clone();
    Ok((harness, chain, blocks))
}

fn deliver(sync: &BlockSync, block: &Block, source: PeerSource) {
    assert!(
        sync.receive_historical(crate::InboundBlock {
            block: block.clone(),
            serialized: bytes::Bytes::from(consensus_bytes(block)),
            source: Some(source),
            forward_credit: None,
        })
        .is_none()
    );
}

#[test]
fn historical_pipeline_bounds_pending_and_staged_and_applies_in_order()
-> Result<(), Box<dyn std::error::Error>> {
    let (harness, chain, blocks) = fixture(40)?;
    let first = test_addr(28200, 0)?;
    let second = test_addr(28200, 1)?;
    let receivers = [
        connect_peer(&harness.peers, synthetic_peer(first, 40)),
        connect_peer(&harness.peers, synthetic_peer(second, 40)),
    ];
    harness.sync.advance_historical();
    for rx in &receivers {
        let Message::GetData(items) = rx.try_recv()? else {
            panic!("expected batch")
        };
        assert_eq!(items.len(), 16);
        assert!(rx.try_recv().is_err());
    }
    assert_eq!(harness.sync.historical.lock().window.pending_len(), 32);
    // All later bodies arrive before the frontier. They must neither apply
    // out of order nor free slots for an unbounded tail of downloads.
    for block in blocks[1..32].iter().rev() {
        let source = harness
            .sync
            .historical
            .lock()
            .window
            .pending_owner(&block.block_hash().0)
            .ok_or("missing owner")?;
        deliver(&harness.sync, block, source);
    }
    harness.sync.advance_historical();
    assert!(chain.historical_connected.lock().is_empty());
    {
        let historical = harness.sync.historical.lock();
        assert_eq!(historical.window.pending_len(), 1);
        assert_eq!(historical.stager.received_len(), 31);
    }
    let source = harness
        .sync
        .historical
        .lock()
        .window
        .pending_owner(&blocks[0].block_hash().0)
        .ok_or("missing front")?;
    deliver(&harness.sync, &blocks[0], source);
    harness.sync.advance_historical();
    {
        let historical = harness.sync.historical.lock();
        assert_eq!(
            historical.window.pending_len(),
            8,
            "refill while earlier bodies remain staged"
        );
        assert_eq!(historical.stager.received_len(), 24);
    }
    for _ in 0..4 {
        harness.sync.advance_historical();
    }
    assert_eq!(
        *chain.historical_connected.lock(),
        blocks[..32]
            .iter()
            .map(|block| block.block_hash().0)
            .collect::<Vec<_>>()
    );
    for block in blocks[32..].iter().rev() {
        let source = harness
            .sync
            .historical
            .lock()
            .window
            .pending_owner(&block.block_hash().0)
            .ok_or("missing tail")?;
        deliver(&harness.sync, block, source);
    }
    harness.sync.advance_historical();
    harness.sync.advance_historical();
    assert_eq!(
        *chain.historical_connected.lock(),
        blocks
            .iter()
            .map(|block| block.block_hash().0)
            .collect::<Vec<_>>()
    );
    let historical = harness.sync.historical.lock();
    assert_eq!(historical.window.pending_len(), 0);
    assert_eq!(historical.stager.received_len(), 0);
    Ok(())
}

#[test]
fn historical_archive_replay_retires_overtaken_downloads() -> Result<(), Box<dyn std::error::Error>>
{
    let (harness, chain, blocks) = fixture(6)?;
    let addr = test_addr(28204, 0)?;
    let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 6));
    harness.sync.advance_historical();
    let source = current_source(&harness.peers, addr);
    deliver(&harness.sync, &blocks[1], source);
    // Model the manager replaying a newly available archived prefix.
    for _ in 0..3 {
        chain.historical.lock().pop_front();
    }
    harness.sync.advance_historical();
    let historical = harness.sync.historical.lock();
    assert_eq!(historical.window.pending_len(), 3);
    assert_eq!(historical.stager.received_len(), 0);
    for block in &blocks[..3] {
        assert!(
            historical
                .window
                .pending_owner(&block.block_hash().0)
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn historical_pipeline_retries_expired_owner_on_another_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (harness, _, blocks) = fixture(4)?;
    harness.sync.install_budget(
        default_sync_budget(Network::Regtest).with_pending_timeout_override(Duration::from_secs(1)),
    );
    let old_addr = test_addr(28201, 0)?;
    let old_rx = connect_peer(&harness.peers, synthetic_peer(old_addr, 4));
    harness.sync.advance_historical();
    assert!(matches!(old_rx.try_recv()?, Message::GetData(_)));
    let new_addr = test_addr(28201, 1)?;
    let new_rx = connect_peer(&harness.peers, synthetic_peer(new_addr, 4));
    harness
        .sync
        .request_historical(1, Instant::now() + Duration::from_secs(2));
    assert!(matches!(new_rx.try_recv()?, Message::GetData(items) if items.len() == 4));
    let new_source = current_source(&harness.peers, new_addr);
    for block in blocks {
        assert!(
            harness
                .sync
                .owns_body_fetch(new_source, block.block_hash().0)
        );
    }
    assert!(old_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn historical_pipeline_bounds_bytes_and_keeps_front_admissible()
-> Result<(), Box<dyn std::error::Error>> {
    let (harness, chain, blocks) = fixture(6)?;
    let body_bytes = consensus_bytes(&blocks[0]).len();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.max_received_bytes = body_bytes * 2;
    harness.sync.install_budget(budget);
    let addr = test_addr(28202, 0)?;
    let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 6));
    harness.sync.advance_historical();
    let source = current_source(&harness.peers, addr);
    for block in blocks[1..].iter().rev() {
        deliver(&harness.sync, block, source);
    }
    assert!(harness.sync.historical.lock().stager.received_bytes() <= budget.max_received_bytes);
    deliver(&harness.sync, &blocks[0], source);
    assert!(
        harness.sync.historical.lock().stager.received_bytes()
            <= budget.max_received_bytes + body_bytes
    );
    harness.sync.advance_historical();
    assert_eq!(
        chain.historical_connected.lock().first(),
        Some(&blocks[0].block_hash().0)
    );
    Ok(())
}

#[test]
fn historical_pipeline_follows_snapshot_branch_instead_of_best_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (harness, chain, _) = fixture(5)?;
    let mut tree = harness.block_tree.write();
    let mut parent = tree
        .lookup(Network::Regtest.genesis_block().block_hash().0)
        .ok_or("missing genesis")?;
    let mut pinned = Vec::new();
    for height in 1..=3 {
        let prev = BlockHash(tree.node(parent)?.hash);
        let block = regtest_fixture::mined_block_with_prev_hash(
            prev,
            height,
            vec![regtest_fixture::coinbase(9_000 + height)],
        )?;
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
        pinned.push(block);
    }
    assert_ne!(
        tree.tip().ok_or("missing header tip")?.hash,
        pinned[2].block_hash().0
    );
    drop(tree);
    *chain.historical.lock() = (1..)
        .zip(pinned.iter().map(|block| block.block_hash().0))
        .collect();
    let addr = test_addr(28203, 0)?;
    let rx = connect_peer(&harness.peers, synthetic_peer(addr, 5));
    harness.sync.advance_historical();
    let Message::GetData(items) = rx.try_recv()? else {
        panic!("expected batch")
    };
    assert_eq!(
        items,
        pinned
            .iter()
            .map(
                |block| Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
                    block.block_hash().0.to_le_bytes()
                ))
            )
            .collect::<Vec<_>>()
    );
    let source = current_source(&harness.peers, addr);
    for block in pinned.iter().rev() {
        deliver(&harness.sync, block, source);
    }
    harness.sync.advance_historical();
    assert_eq!(
        *chain.historical_connected.lock(),
        pinned
            .iter()
            .map(|block| block.block_hash().0)
            .collect::<Vec<_>>()
    );
    Ok(())
}
