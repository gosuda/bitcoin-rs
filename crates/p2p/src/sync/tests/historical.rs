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
        sync.receive_historical({
            let mut inbound = crate::InboundBlock::from_local(block.clone());
            inbound.source = Some(source);
            inbound
        })
        .is_none()
    );
}

#[test]
fn local_replay_budget_does_not_send_getdata() -> TestResult {
    let (harness, chain, _blocks) = fixture(3)?;
    let addr = test_addr(28211, 0)?;
    let rx = connect_peer(&harness.peers, synthetic_peer(addr, 3));
    *chain.historical_replay_pending.lock() = true;

    harness.sync.advance_historical();
    assert!(
        rx.try_recv().is_err(),
        "local replay must not trigger getdata"
    );
    assert_eq!(harness.sync.historical.lock().window.pending_len(), 0);

    harness.sync.advance_historical();
    assert!(matches!(rx.try_recv()?, Message::GetData(_)));
    Ok(())
}

#[test]
fn anonymous_peer_serves_historical_bodies() -> TestResult {
    let (harness, chain, _blocks) = fixture(3)?;
    let addr = test_addr(28211, 0)?;
    let rx = connect_anonymous_peer(&harness.peers, synthetic_peer(addr, 3));
    *chain.historical_replay_pending.lock() = true;

    harness.sync.advance_historical();
    assert!(
        rx.try_recv().is_err(),
        "local replay must not trigger getdata"
    );
    assert_eq!(harness.sync.historical.lock().window.pending_len(), 0);

    harness.sync.advance_historical();
    assert!(
        matches!(rx.try_recv()?, Message::GetData(_)),
        "an endpoint-less session must serve historical bodies like any peer"
    );
    Ok(())
}

#[test]
fn historical_pipeline_bounds_pending_and_staged_and_applies_in_order() -> TestResult {
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
fn historical_archive_replay_retires_overtaken_downloads() -> TestResult {
    let (harness, chain, blocks) = fixture(6)?;
    let addr = test_addr(28204, 0)?;
    let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 6));
    harness.sync.advance_historical();
    let source = current_source(&harness.peers, addr);
    deliver(&harness.sync, &blocks[1], source);
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
fn late_retired_history_cannot_enter_foreground_staging() -> TestResult {
    let (harness, chain, blocks) = fixture(6)?;
    chain.bootstrap_genesis();
    let owned_payloads: Vec<BlockPayload> = blocks
        .iter()
        .cloned()
        .map(BlockPayload::from_local)
        .collect();
    let payloads: Vec<&BlockPayload> = owned_payloads.iter().collect();
    chain
        .commit_window(&payloads)
        .map_err(|error| format!("fixture commit: {error:?}"))?;
    let addr = test_addr(28205, 0)?;
    let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 7));
    harness.sync.advance_historical();
    let source = current_source(&harness.peers, addr);
    chain.historical.lock().pop_front();
    harness.sync.advance_historical();
    assert!(
        !harness
            .sync
            .owns_body_fetch(source, blocks[0].block_hash().0)
    );

    for competing_headers in [false, true] {
        if competing_headers {
            let mut tree = harness.block_tree.write();
            let mut parent = tree
                .lookup(Network::Regtest.genesis_block().block_hash().0)
                .ok_or("missing genesis")?;
            for height in 1..=7 {
                let block = regtest_fixture::mined_block_with_prev_hash(
                    BlockHash(tree.node(parent)?.hash),
                    height,
                    vec![regtest_fixture::coinbase(10_000 + height)],
                )?;
                parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
            }
            assert_ne!(
                tree.tip().ok_or("missing header tip")?.hash,
                blocks[5].block_hash().0
            );
        }
        let mut inbound = crate::InboundBlock::from_local(blocks[0].clone());
        inbound.source = Some(source);
        let inbound = harness
            .sync
            .receive_historical(inbound)
            .ok_or("retired lease must not retain ownership")?;
        let mut deliveries = vec![inbound];
        assert_eq!(
            harness
                .sync
                .buffer_received_block_chunk(&mut deliveries, None),
            0
        );
        assert_eq!(harness.sync.scheduler.lock().stager.received_len(), 0);
        assert_eq!(
            harness
                .applied_tip
                .load_full()
                .ok_or("missing foreground tip")?
                .hash,
            blocks[5].block_hash().0
        );
        assert!(chain.historical_connected.lock().is_empty());
    }
    Ok(())
}

#[test]
fn historical_pipeline_retries_expired_owner_on_another_connection() -> TestResult {
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
fn historical_pipeline_bounds_bytes_and_keeps_front_admissible() -> TestResult {
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

fn witness_inventory(block: &Block) -> Inventory {
    Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array(
        block.block_hash().0.to_le_bytes(),
    ))
}

fn historical_owner(sync: &BlockSync, block: &Block) -> Option<PeerSource> {
    sync.historical
        .lock()
        .window
        .pending_owner(&block.block_hash().0)
}

#[test]
fn historical_notfound_releases_the_exact_owner_and_the_alternate_serves_it_once() -> TestResult {
    let (harness, chain, blocks) = fixture(3)?;
    let addrs = [test_addr(28230, 0)?, test_addr(28230, 1)?];
    let receivers = [
        connect_peer(&harness.peers, synthetic_peer(addrs[0], 3)),
        connect_peer(&harness.peers, synthetic_peer(addrs[1], 3)),
    ];
    let sources = [
        current_source(&harness.peers, addrs[0]),
        current_source(&harness.peers, addrs[1]),
    ];
    let first = witness_inventory(&blocks[0]);

    harness.sync.advance_historical();
    let owner_source =
        historical_owner(&harness.sync, &blocks[0]).ok_or("the first body must be requested")?;
    let owner = usize::from(owner_source != sources[0]);
    let alternate = 1 - owner;
    let alternate_source = sources[alternate];
    let initial: Vec<Vec<Inventory>> = receivers.iter().map(drain_getdata_items).collect();
    assert_eq!(
        initial
            .iter()
            .flatten()
            .filter(|item| **item == first)
            .count(),
        1,
        "the first body is requested once, from its owner"
    );
    assert!(initial[owner].contains(&first));

    assert!(
        !harness
            .sync
            .block_not_found(alternate_source, std::slice::from_ref(&first))
    );
    assert_eq!(
        historical_owner(&harness.sync, &blocks[0]),
        Some(owner_source)
    );

    assert!(
        harness
            .sync
            .block_not_found(owner_source, std::slice::from_ref(&first))
    );
    assert_eq!(historical_owner(&harness.sync, &blocks[0]), None);
    for _ in 0..3 {
        harness.sync.advance_historical();
    }
    assert!(
        !drain_getdata_items(&receivers[owner]).contains(&first),
        "an owner that answered notfound is not asked for the body again"
    );
    assert_eq!(
        drain_getdata_items(&receivers[alternate])
            .iter()
            .filter(|item| **item == first)
            .count(),
        1,
        "the alternate is asked for the released body exactly once"
    );
    assert_eq!(
        historical_owner(&harness.sync, &blocks[0]),
        Some(alternate_source)
    );
    assert!(
        harness.peers.is_connected(addrs[owner]),
        "a peer that lacks a body is not punished"
    );

    for block in &blocks {
        let source =
            historical_owner(&harness.sync, block).ok_or("every body must still be pending")?;
        deliver(&harness.sync, block, source);
    }
    for _ in 0..4 {
        harness.sync.advance_historical();
    }
    assert_eq!(
        *chain.historical_connected.lock(),
        blocks
            .iter()
            .map(|block| block.block_hash().0)
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn historical_notfound_only_peer_is_not_polled_and_is_retried_after_the_interval() -> TestResult {
    let (harness, _chain, blocks) = fixture(3)?;
    let addr = test_addr(28231, 0)?;
    let rx = connect_peer(&harness.peers, synthetic_peer(addr, 3));
    let source = current_source(&harness.peers, addr);
    let first = witness_inventory(&blocks[0]);

    harness.sync.advance_historical();
    assert!(drain_getdata_items(&rx).contains(&first));
    assert!(
        harness
            .sync
            .block_not_found(source, std::slice::from_ref(&first))
    );
    assert_eq!(historical_owner(&harness.sync, &blocks[0]), None);

    for _ in 0..4 {
        harness.sync.advance_historical();
    }
    assert!(
        drain_getdata_items(&rx).is_empty(),
        "no wake-up-paced getdata/notfound loop against the only peer"
    );
    assert!(harness.peers.is_connected(addr));

    let aged = Instant::now()
        .checked_sub(BODY_UNAVAILABLE_RETRY + Duration::from_secs(1))
        .ok_or("monotonic clock is younger than the retry interval")?;
    harness
        .sync
        .scheduler
        .lock()
        .body_unavailable
        .note(source, blocks[0].block_hash().0, aged);
    harness.sync.advance_historical();
    assert_eq!(
        drain_getdata_items(&rx)
            .iter()
            .filter(|item| **item == first)
            .count(),
        1
    );
    harness.sync.advance_historical();
    assert_eq!(drain_getdata_items(&rx), Vec::<Inventory>::new());

    assert!(
        harness
            .sync
            .block_not_found(source, std::slice::from_ref(&first))
    );
    assert!(harness.sync.scheduler.lock().body_unavailable.refuses(
        source,
        blocks[0].block_hash().0,
        Instant::now()
    ));
    assert!(harness.peers.disconnect_source(source));
    harness.sync.reconcile_peer_sessions();
    assert!(!harness.sync.scheduler.lock().body_unavailable.refuses(
        source,
        blocks[0].block_hash().0,
        Instant::now()
    ));
    Ok(())
}

#[test]
fn historical_delivery_ends_the_notfound_record() -> TestResult {
    let (harness, _chain, blocks) = fixture(3)?;
    let addr = test_addr(28232, 0)?;
    let _rx = connect_peer(&harness.peers, synthetic_peer(addr, 3));
    let source = current_source(&harness.peers, addr);
    let hash = blocks[0].block_hash().0;

    harness.sync.advance_historical();
    assert_eq!(historical_owner(&harness.sync, &blocks[0]), Some(source));
    harness
        .sync
        .scheduler
        .lock()
        .body_unavailable
        .note(source, hash, Instant::now());
    assert!(
        harness
            .sync
            .scheduler
            .lock()
            .body_unavailable
            .refuses(source, hash, Instant::now())
    );

    deliver(&harness.sync, &blocks[0], source);
    assert!(
        !harness
            .sync
            .scheduler
            .lock()
            .body_unavailable
            .refuses(source, hash, Instant::now()),
        "a delivered historical body ends the record"
    );
    Ok(())
}

#[test]
fn historical_pipeline_follows_snapshot_branch_instead_of_best_header() -> TestResult {
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
