//! Regression for the ownership boundary between p2p sessions and node sync.
//!
//! `PeerTable` owns registration, same-address replacement, cancellation, and
//! handshake metadata. Node sync observes that table rather than registering
//! sessions through a callback or maintaining a second peer collection.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_node::{BlockSync, Network};
use bitcoin_rs_p2p::{Message, PeerInfo, PeerLease, PeerTable};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use crossbeam_channel::unbounded;
use parking_lot::{Mutex, RwLock};

fn make_sync(peer_table: Arc<PeerTable>) -> BlockSync {
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let chain_tip = block_tree.read().tip_handle();
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let (_headers_tx, headers_rx) = unbounded();
    let (_blocks_tx, blocks_rx) = unbounded();
    let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.set_listener(Box::new((*coin_stats).clone()));
    let handles = Chainstate::new(
        Network::Regtest,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::new(utxo),
        coin_stats,
        Arc::new(bitcoin_rs_chainstate::events::ChainEventPublisher::detached(0)),
    );
    let ibd = Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
        handles.applied_tip_handle(),
        handles.block_tree_handle(),
        Network::Regtest,
    ));
    bitcoin_rs_node::sync::block_sync(
        Arc::new(handles),
        bitcoin_rs_node::ChainFollowers::noop(),
        peer_table,
        Arc::new(Mutex::new(headers_rx)),
        Arc::new(Mutex::new(blocks_rx)),
        ibd,
    )
}

fn info(addr: SocketAddr) -> PeerInfo {
    PeerInfo {
        wtxid_relay: false,
        compact_block_relay: false,
        addr,
        version: 70_016,
        services: 1,
        user_agent: String::from("/test/"),
        start_height: 0,
        best_known_height: 0,
        conn_time: 0,
        addr_bind: addr,
        time_offset: 0,
        counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        inbound: true,
    }
}

#[test]
fn peer_table_owns_handshake_publication_and_replacement() {
    let table = Arc::new(PeerTable::new());
    let addr = SocketAddr::from(([127, 0, 0, 1], 18_447));
    let (old_tx, _old_rx) = unbounded::<Message>();
    let old = PeerLease::new(old_tx);
    assert!(!table.register(addr, old.clone()));
    assert!(table.publish_info(addr, &old, info(addr)));
    assert!(!old.is_cancelled());
    assert_eq!(table.len(), 1);
    assert_eq!(table.infos().len(), 1);

    let (new_tx, _new_rx) = unbounded::<Message>();
    let new = PeerLease::new(new_tx);
    assert!(table.register(addr, new.clone()));
    assert!(old.is_cancelled());
    assert!(!new.is_cancelled());
    assert!(table.is_current(new.source(addr)));

    let sync = make_sync(Arc::clone(&table));
    sync.tick();
    assert_eq!(table.live_sessions().len(), 1);
}
