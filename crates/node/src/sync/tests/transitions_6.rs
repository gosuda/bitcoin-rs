use super::*;

#[test]
fn apply_cache_invalidated_on_chain_tip_move() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = apply_cache_fixture(4, 0)?;
    install_budget(
        &fixture.sync,
        super::super::SyncBudget {
            max_pending_blocks: 4,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 64,
            max_received_bytes: usize::MAX,
            ..super::super::default_sync_budget()
        },
    );

    // Round 1: stage one body, miss populates the cache, advance retains it
    // with the original chain-tip hash as a validity key.
    stage_body(&fixture.sync, &fixture.blocks[0]);
    let (applied, _failed) = fixture.sync.apply_buffered_blocks(None);
    assert_eq!(applied, 1);
    let cache = cache_snapshot(&fixture.sync)
        .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
    let original_chain_tip_hash = cache.chain_tip_hash;
    assert_eq!(cache.offset, 1);

    // Move the chain tip: publish a snapshot whose hash differs from the one
    // the cache was keyed against (a reorg replaces the active-chain tip).
    let moved_tip = {
        let current = fixture
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
        let mut hash_bytes = current.hash.to_le_bytes();
        hash_bytes[0] ^= 0xff;
        TipSnapshot {
            tip_id: current.tip_id,
            height: current.height,
            chainwork: current.chainwork,
            hash: Hash256::from_le_bytes(&hash_bytes),
        }
    };
    fixture.chain_tip.store(Some(Arc::new(moved_tip)));
    assert_ne!(
        fixture
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing chain tip"))?
            .hash,
        original_chain_tip_hash,
        "chain tip must move for this test to be meaningful"
    );

    // The decisive probe: with the tip moved, the stale entry must be
    // rejected by its validity keys BEFORE any repopulation can mask a
    // broken eviction (a later apply round always rekeys the cache, so
    // asserting on the post-apply snapshot alone is vacuous).
    assert!(
        fixture.sync.drain_cached_expected_blocks(1).is_none(),
        "stale cache keyed to the old chain tip must not serve a drain"
    );

    // Round 2: stage the next body. The miss recomputes the run against the
    // new tip and repopulates the cache keyed to the moved tip's hash.
    stage_body(&fixture.sync, &fixture.blocks[1]);
    let _ = fixture.sync.apply_buffered_blocks(None);
    let after = cache_snapshot(&fixture.sync)
        .ok_or_else(|| std::io::Error::other("miss did not repopulate apply cache"))?;
    assert_ne!(
        after.chain_tip_hash, original_chain_tip_hash,
        "repopulated cache must be keyed to the moved tip"
    );
    Ok(())
}

#[test]
fn window_failure_applies_prefix_and_restores_suffix() -> Result<(), Box<dyn std::error::Error>> {
    // Blocks now apply in windows, so a mid-window failure has to split the
    // chunk three ways: the prefix committed, the one block that failed, and
    // an untouched suffix that must go back on the stager. Getting that
    // split wrong is invisible to the (applied, failed) counts alone, so
    // this asserts the stager contents too.
    let fixture = apply_cache_fixture(4, 0)?;

    // Corrupt the second body without touching its header: the stager keys
    // on the header hash, so this still drains as the expected block, and
    // apply rejects it on the merkle root. A body that changed its own hash
    // would never be drained and the window would never see it.
    let mut corrupted = fixture.blocks[1].clone();
    corrupted.txs.push(coinbase_transaction(99));
    assert_eq!(
        corrupted.block_hash(),
        fixture.blocks[1].block_hash(),
        "corruption must not move the header hash or the drain never sees it"
    );

    stage_body(&fixture.sync, &fixture.blocks[0]);
    stage_body(&fixture.sync, &corrupted);
    stage_body(&fixture.sync, &fixture.blocks[2]);
    stage_body(&fixture.sync, &fixture.blocks[3]);

    let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
    assert_eq!(
        (applied, failed),
        (1, 1),
        "only the block before the corrupt one commits"
    );
    assert_eq!(
        fixture.applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "the chain stops at the last good block"
    );

    // The merkle-root rejection is a permanent consensus failure, so the
    // window invalidated the corrupted block and its (never-attempted)
    // descendants while the transition was held. They can never become
    // applicable, so instead of returning to the stager they are purged
    // from it: the frontier must not cycle on invalidated blocks.
    let restored = fixture.sync.block_stager.lock().received_len();
    assert_eq!(
        restored, 0,
        "invalidated blocks and their descendants are purged, not restored"
    );
    Ok(())
}

#[test]
fn peer_disconnect_mid_window_requeues_blocks_to_remaining_peers()
-> Result<(), Box<dyn std::error::Error>> {
    const PEER_COUNT: usize = 9;
    const SELECTED_PEERS: usize = super::super::MIN_PEERS_FOR_FANOUT;
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    install_budget(&sync, super::super::default_sync_budget());
    let mut receivers = Vec::new();
    let mut addrs = Vec::new();
    for idx in 0..PEER_COUNT {
        let addr = test_addr(9506, idx)?;
        addrs.push(addr);
        receivers.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    // Nine live peers at the first tick: the window divides nine ways
    // (mirrors `effective_peer_inflight`).
    let cap = super::super::PENDING_BUDGET.div_ceil(PEER_COUNT).clamp(
        super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
        super::super::PEER_INFLIGHT_BUDGET,
    );
    for (idx, receiver) in receivers[..SELECTED_PEERS].iter().enumerate() {
        let Message::GetData(inventory) = receiver.try_recv()? else {
            return Err(std::io::Error::other("expected initial stripe").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * cap..(idx + 1) * cap]
        );
    }
    let _ = receivers[0].try_recv()?;
    // The spare takes the window remainder past the eight full stripes;
    // drain it now so the next read sees only the requeued stripe.
    let Message::GetData(remainder) = receivers[SELECTED_PEERS].try_recv()? else {
        return Err(std::io::Error::other("expected remainder getdata for spare peer").into());
    };
    assert_eq!(
        witness_block_inventory(remainder)?,
        expected[SELECTED_PEERS * cap..]
    );
    let dropped = addrs[1];
    peers.disconnect(dropped);
    sync.tick();
    let Message::GetData(inventory) = receivers[SELECTED_PEERS].try_recv()? else {
        return Err(std::io::Error::other("expected requeued getdata").into());
    };
    // The freed stripe spreads across remaining capacity (the spare tops
    // up its remainder share while the other peers absorb the rest), so
    // prove the union over every remaining peer is exactly the freed
    // stripe: every freed block re-requested, nothing else.
    let mut requeued = witness_block_inventory(inventory)?;
    for (idx, rx) in receivers.iter().enumerate() {
        if idx == 1 || idx == SELECTED_PEERS {
            continue; // disconnected peer; spare drained above
        }
        requeued.extend(witness_block_inventory(next_getdata(rx)?)?);
    }
    requeued.sort();
    let mut freed = expected[cap..2 * cap].to_vec();
    freed.sort();
    assert_eq!(requeued, freed, "every freed block must be re-requested");
    assert_eq!(
        sync.download_window.lock().pending_len(),
        super::super::PENDING_BUDGET
    );
    Ok(())
}

#[test]
fn reconnecting_staller_held_out_of_window_front_by_cooldown()
-> Result<(), Box<dyn std::error::Error>> {
    stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued()
}

#[test]
fn sole_peer_staller_disconnected_and_usable_again_as_last_resort()
-> Result<(), Box<dyn std::error::Error>> {
    tick_allows_demoted_peer_when_it_is_the_only_eligible_peer()
}

#[test]
fn same_address_registration_after_window_eviction_keeps_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain(3)?;
    let addr = test_addr(9508, 0)?;
    let (old_tx, old_rx) = unbounded::<Message>();
    let old = PeerLease::new(old_tx);
    peers.register(addr, old.clone());
    peers.publish_info(addr, &old, synthetic_peer(addr, 100));
    sync.tick();
    let _ = old_rx.try_recv()?;
    let _ = old_rx.try_recv()?;
    let (new_tx, new_rx) = unbounded::<Message>();
    let new = PeerLease::new(new_tx);
    peers.register(addr, new.clone());
    peers.publish_info(addr, &new, synthetic_peer(addr, 100));
    sync.tick();
    assert!(peers.is_current(new.source(addr)));
    assert!(old.is_cancelled());
    assert!(peers.is_connected(addr));
    assert!(new_rx.try_recv().is_ok());
    Ok(())
}

#[test]
fn reconcile_forgets_window_state_only_when_connection_identity_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture { sync, peers, .. } = header_sync_with_genesis()?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget()
        },
    );
    let addr = test_addr(9509, 0)?;
    let (tx, _rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peers.register(addr, lease.clone());
    peers.publish_info(addr, &lease, synthetic_peer(addr, 8));
    sync.tick();
    assert!(sync.pending_getheaders.lock().is_some());

    assert!(!peers.register(addr, lease));
    sync.reconcile_peer_sessions();
    assert!(sync.pending_getheaders.lock().is_some());

    let (new_tx, _new_rx) = unbounded::<Message>();
    let replacement = PeerLease::new(new_tx);
    peers.register(addr, replacement.clone());
    peers.publish_info(addr, &replacement, synthetic_peer(addr, 8));
    sync.reconcile_peer_sessions();
    assert!(sync.pending_getheaders.lock().is_none());
    Ok(())
}

#[test]
fn partial_reorg_readmits_only_still_disconnected_transactions()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (handles, main, mut bodies) = matured_chain(101)?;
    let tip = main
        .last()
        .ok_or_else(|| std::io::Error::other("empty chain"))?;
    let spend_txid = tip.txs[1].txid();
    // A competing branch rooted at block 50 with four more blocks of
    // work: switching to it disconnects the 51-block suffix (including
    // the matured spend) while the spent coin itself stays live below
    // the fork point, and the 105th fork body contradicts its own
    // header merkle root, so the connect dies permanently mid-walk.
    let fork_root_hash = main[49].block_hash();
    let mut tree = handles.block_tree.write();
    let mut fork_parent = tree
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork_blocks = Vec::new();
    for height in 51..=105_u32 {
        let mut coinbase = coinbase_transaction(height);
        // Distinguish the branch: same-height coinbases on both chains
        // must not carry identical txids, or the fork headers collide.
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
        fork_prev = block.block_hash();
        fork_blocks.push(block);
    }
    let fork_target = fork_parent;
    drop(tree);
    let mut corrupt = fork_blocks[fork_blocks.len() - 1].clone();
    corrupt.txs[0].outputs[0].value = Amount::from_sat(2);
    let last = fork_blocks.len() - 1;
    fork_blocks[last] = corrupt;
    for block in &fork_blocks {
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
        );
    }
    let connected_count = std::rc::Rc::new(std::cell::Cell::new(0_usize));
    let counter = std::rc::Rc::clone(&connected_count);

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |hash| bodies.get(&hash).cloned(),
        move |_hash| counter.set(counter.get() + 1),
    );

    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::ConnectFailed {
                disconnected: 51,
                connected: 54,
                ..
            })
        ),
        "the walk must report its exact committed prefixes, got {outcome:?}"
    );
    assert_eq!(
        connected_count.get(),
        54,
        "only the committed connect prefix is retired to the caller"
    );
    let connected_tip = Hash256::from_le_bytes(fork_blocks[53].block_hash().as_bytes());
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(connected_tip),
        "the successful connected prefix is the final active chain"
    );
    // MPL-04: the valid connected prefix reopens only after re-admission.
    assert!(handles.mempool_gateway.stable_generation().is_some());
    let mempool = handles.mempool.read();
    assert_eq!(
        mempool.len(),
        1,
        "exactly the still-off-chain tx is readmitted"
    );
    assert!(
        mempool.contains_txid(&spend_txid),
        "the disconnected matured spend stays eligible"
    );
    assert_eq!(
        mempool.sequence_number(),
        1,
        "reconsideration runs exactly once for the partial switch"
    );
    let reconnected_txid = fork_blocks[0].txs[0].txid();
    let reconnected_in_pool = mempool.contains_txid(&reconnected_txid);
    assert!(
        !reconnected_in_pool,
        "reconnected-block transactions are confirmed, never readmitted"
    );
    Ok(())
}

#[test]
fn fatal_disconnect_readmits_nothing() -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (mut handles, main, mut bodies) = matured_chain(101)?;
    let tip = main
        .last()
        .ok_or_else(|| std::io::Error::other("empty chain"))?;
    let spend_txid = tip.txs[1].txid();
    // The in-flight marker can never be cleared, so the very first
    // disconnect dies fatal after rolling back cleanly. The wrapper keeps
    // the real records; only the disarm fails.
    let real_store = Arc::clone(&handles.undo_store);
    handles.undo_store = Arc::new(DisarmFailsUndoStore { inner: real_store });
    let fork_root_hash = main[49].block_hash();
    let mut tree = handles.block_tree.write();
    let mut fork_parent = tree
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork_blocks = Vec::new();
    for height in 51..=52_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
        fork_prev = block.block_hash();
        fork_blocks.push(block);
    }
    let fork_target = fork_parent;
    drop(tree);
    for block in &fork_blocks {
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
        );
    }

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );

    assert!(
        matches!(outcome, Err(crate::reorg::ReorgError::Fatal(_))),
        "a stuck disconnect marker is fatal, got {outcome:?}"
    );
    assert!(
        handles.mempool.read().is_empty(),
        "a fatal disconnect must never reconsider disconnected transactions"
    );
    assert_eq!(handles.mempool.read().sequence_number(), 0);
    // MPL-04: a stuck marker must keep all later chain changes fenced.
    assert!(handles.mempool_gateway.stable_generation().is_none());
    assert!(handles.begin_transition().is_err());
    let spend_in_pool = handles.mempool.read().contains_txid(&spend_txid);
    assert!(
        !spend_in_pool,
        "the off-chain matured spend must not be readmitted after a fatal disconnect"
    );
    Ok(())
}
