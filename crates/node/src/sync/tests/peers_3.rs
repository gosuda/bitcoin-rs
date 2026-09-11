use super::*;

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
