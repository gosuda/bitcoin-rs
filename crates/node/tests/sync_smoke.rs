//! Block sync smoke tests.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_node::{BlockSync, Network};
use bitcoin_rs_p2p::{Message, PeerInfo};
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

#[test]
fn tick_sends_getheaders_to_best_peer_above_our_height() -> Result<(), Box<dyn std::error::Error>> {
    let chain_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(RwLock::new(Vec::new()));
    let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<bitcoin::block::Header>>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let sync = BlockSync::new(
        Arc::clone(&chain_tip),
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        Arc::clone(&block_tree),
        Network::Regtest,
        inbound_headers_rx,
    );

    sync.tick();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    peers.write().push(synthetic_peer(addr, 100));
    let (tx, rx) = unbounded::<Message>();
    peer_outbound.write().insert(addr, tx);

    sync.tick();

    let received = rx.try_recv()?;
    let NetworkMessage::GetHeaders(getheaders) = received else {
        panic!("expected getheaders");
    };
    let genesis_hash =
        BlockHash::from_byte_array(Network::Regtest.genesis_block_hash().to_le_bytes());
    assert_eq!(getheaders.locator_hashes.len(), 1);
    assert_eq!(getheaders.locator_hashes.first(), Some(&genesis_hash));
    assert_eq!(getheaders.stop_hash, BlockHash::all_zeros());
    Ok(())
}

fn synthetic_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
    PeerInfo {
        addr,
        version: 70_016,
        services: 0,
        user_agent: String::from("/test/"),
        start_height,
        conn_time: 0,
        inbound: true,
    }
}
