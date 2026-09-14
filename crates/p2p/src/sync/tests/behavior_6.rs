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
    assert_applied_genesis(&applied_tip, &block_tree)?;
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
