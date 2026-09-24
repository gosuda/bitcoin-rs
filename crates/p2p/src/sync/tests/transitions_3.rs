use super::*;

#[test]
fn tick_skips_getheaders_when_header_tip_matches_peer_height()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
    let applied_snapshot = {
        let tree = block_tree.read();
        let chain_tip = sync
            .chain
            .chain_tip()
            .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
        let node_id = tree
            .node_at_height_from(chain_tip.tip_id, 1)
            .ok_or_else(|| std::io::Error::other("missing height one node"))?;
        let node = tree.node(node_id)?;
        TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        }
    };
    applied_tip.store(Some(Arc::new(applied_snapshot)));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 3));

    sync.tick();

    let first = rx.try_recv()?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[1..]);
    assert!(rx.try_recv().is_err());
    Ok(())
}
