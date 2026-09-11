use super::*;

#[test]
fn non_witness_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>>
{
    let ineligible = PeerInfo {
        // NODE_NETWORK only — no NODE_WITNESS.
        services: 1,
        ..eligible_peer(test_addr(9210, 0)?, 300)
    };
    assert_fallback_with_ineligible_candidate(ineligible, true)
}

#[test]
fn far_behind_duplicate_of_applied_block_is_not_staged() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(64)?;
    let peer = test_addr(9321, 0)?;
    let rx = connect_peer(&peers, eligible_peer(peer, 100));

    sync.tick();
    let requested = next_getdata(&rx)?;
    assert_eq!(
        witness_block_inventory(requested)?,
        blocks.iter().map(Block::block_hash).collect::<Vec<_>>()
    );
    for block in &blocks {
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
    }
    sync.tick();
    assert_eq!(
        applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height,
        64
    );
    let stale_hash = Hash256::from_le_bytes(blocks[0].block_hash().as_bytes());
    assert!(
        !sync.download_window.lock().contains_pending(&stale_hash),
        "the replay must be unsolicited after its request was applied"
    );

    blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
        blocks[0].clone(),
    ))?;
    sync.tick();

    assert!(!sync.block_stager.lock().contains(&stale_hash));
    let window = sync.download_window.lock();
    assert_eq!(window.pending_len(), 0);
    assert_eq!(window.received_len(), 0);
    assert!(!window.contains_pending(&stale_hash));
    Ok(())
}

#[test]
fn received_only_state_uses_scan_path_without_duplicate_request()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
    let received_hash = Hash256::from_le_bytes(expected[1].as_bytes());
    {
        let mut window = sync.download_window.lock();
        let needs_height = window.mark_received(received_hash, 80, Instant::now());
        assert!(needs_height);
        window.update_received_height(&received_hash, 2);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 3));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(
        witness_block_inventory(inventory)?,
        alloc::vec![expected[0], expected[2]]
    );
    assert!(rx.try_recv().is_err());
    Ok(())
}
