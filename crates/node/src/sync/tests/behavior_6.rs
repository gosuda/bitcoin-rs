use super::*;

#[test]
fn tick_retries_when_all_selected_peers_have_expired_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _tree, _applied, expected) = sync_with_header_chain(3)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            pending_timeout: Duration::ZERO,
            getdata_batch_limit: 1,
            ..super::super::default_sync_budget()
        },
    );
    let rx = connect_peer(&peers, synthetic_peer(test_addr(9504, 0)?, 100));
    sync.tick();
    let _ = rx.try_recv()?;
    let _ = rx.try_recv()?;
    sync.tick();
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected expired-pending retry").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..1]);
    Ok(())
}

#[test]
fn tick_fans_out_getdata_across_eligible_peers() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    let mut receivers = Vec::new();
    for idx in 0..super::super::MIN_PEERS_FOR_FANOUT {
        receivers.push(connect_peer(
            &peers,
            eligible_peer(test_addr(9505, idx)?, 300 - i32::try_from(idx)?),
        ));
    }
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    // Effective fan-out stripe (mirrors `effective_peer_inflight`).
    let cap = super::super::PENDING_BUDGET
        .div_ceil(super::super::MIN_PEERS_FOR_FANOUT)
        .clamp(
            super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
            super::super::PEER_INFLIGHT_BUDGET,
        );
    for (idx, receiver) in receivers.iter().enumerate() {
        let Message::GetData(inventory) = receiver.try_recv()? else {
            return Err(std::io::Error::other("expected fanout getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * cap..(idx + 1) * cap]
        );
        if idx == 0 {
            assert!(matches!(receiver.try_recv()?, Message::GetHeaders(_)));
        }
        assert!(receiver.try_recv().is_err());
    }
    assert_eq!(
        sync.download_window.lock().pending_len(),
        super::super::PENDING_BUDGET
    );
    Ok(())
}

#[test]
fn tick_does_not_request_above_peer_advertised_height() -> Result<(), Box<dyn std::error::Error>> {
    clean_fast_path_caps_request_at_peer_height()
}

#[test]
fn stale_queued_block_keeps_payload_without_peer_credit() -> Result<(), Box<dyn std::error::Error>>
{
    unsolicited_stale_block_retries_from_resolved_header_height()
}

#[test]
fn stale_invalid_headers_cannot_evict_or_clear_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let table = Arc::new(PeerTable::new());
    let addr = test_addr(9507, 0)?;
    let (old_tx, _old_rx) = unbounded::<Message>();
    let old = PeerLease::new(old_tx);
    table.register(addr, old.clone());
    let (new_tx, _new_rx) = unbounded::<Message>();
    let new = PeerLease::new(new_tx);
    table.register(addr, new.clone());
    assert!(!table.disconnect_source(old.source(addr)));
    assert!(table.is_current(new.source(addr)));
    assert!(!new.is_cancelled());
    Ok(())
}

#[test]
fn prefix_probe_state_does_not_survive_owner_replacement() -> Result<(), Box<dyn std::error::Error>>
{
    tick_fanout_deferred_for_fresh_probe_engages_at_deadline()
}

#[test]
fn permanent_forward_failure_purges_invalid_blocks_without_retry()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Amount;
    let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    sync.ensure_genesis_tip();
    stage_body(&sync, &main[0]);
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));

    let main_hash = main[0].block_hash();
    let bad = mined_block_with_prev_hash(main_hash, 2, vec![coinbase_transaction(2)]);
    // The value change alters the txid, so the staged body contradicts the
    // header's merkle root: a permanent consensus failure.
    let mut bad_body = bad.clone();
    bad_body.txs[0].outputs[0].value = Amount::from_sat(2);
    let descendant = mined_block_with_prev_hash(bad.block_hash(), 3, vec![coinbase_transaction(3)]);
    {
        let mut tree = sync.handles.block_tree.write();
        let main_id = tree
            .lookup(Hash256::from_le_bytes(main_hash.as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing applied main block"))?;
        let bad_id = tree.insert_node(Some(main_id), bad.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(bad_id), descendant.header, NodeStatus::HeaderValid)?;
    }
    stage_body(&sync, &bad_body);
    stage_body(&sync, &descendant);

    assert_eq!(
        sync.apply_buffered_blocks(None),
        (0, 1),
        "the permanent failure must stop the window with nothing committed"
    );
    let bad_hash = Hash256::from_le_bytes(bad.block_hash().as_bytes());
    let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
    assert!(!sync.block_stager.lock().contains(&bad_hash));
    let descendant_staged = sync.block_stager.lock().contains(&descendant_hash);
    assert!(
        !descendant_staged,
        "invalid descendants must be purged from bounded staging"
    );
    assert_eq!(
        sync.apply_buffered_blocks(None),
        (0, 0),
        "the frontier must not cycle: nothing re-offers the invalidated blocks"
    );
    assert_eq!(applied_tip.load_full().map(|tip| tip.height), Some(1));
    Ok(())
}
