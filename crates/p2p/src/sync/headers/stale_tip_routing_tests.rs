use super::super::BlockSync;
use super::super::chain::HeaderAdmission;
use super::super::chain::SyncChain;
use super::super::chain::SyncChainError;
use super::super::chain::WindowCommitError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::{BlockTree, ChainWork, NodeStatus};
use bitcoin_rs_primitives::{Hash256, Header, Network};
use parking_lot::RwLockReadGuard;
use std::sync::Arc;

struct RoutingStubChain {
    tree: parking_lot::RwLock<BlockTree>,
    network: Network,
    floor: ChainWork,
    applied: parking_lot::RwLock<Option<Arc<TipSnapshot>>>,
}

impl RoutingStubChain {
    fn with_floor(tree: BlockTree, floor: ChainWork) -> Self {
        let applied = tree.tip();
        Self {
            tree: parking_lot::RwLock::new(tree),
            network: Network::Regtest,
            floor,
            applied: parking_lot::RwLock::new(applied),
        }
    }
}

impl SyncChain for RoutingStubChain {
    fn network(&self) -> Network {
        self.network
    }

    fn block_tree(&self) -> RwLockReadGuard<'_, BlockTree> {
        self.tree.read()
    }

    fn chain_tip(&self) -> Option<Arc<TipSnapshot>> {
        self.tree.read().tip()
    }

    fn applied_tip(&self) -> Option<Arc<TipSnapshot>> {
        self.applied.read().clone()
    }

    fn bootstrap_genesis(&self) {}

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
        let mut tree = self.tree.write();
        match bitcoin_rs_chain::accept_headers(
            &mut tree,
            headers,
            self.network,
            bitcoin_rs_chain::current_unix_seconds(),
            bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
        ) {
            Ok(admitted) => {
                let announced_tip = admitted
                    .ids
                    .last()
                    .and_then(|id| tree.node(*id).ok())
                    .map(|node| node.hash);
                let active_height = tree.tip().zip(announced_tip).and_then(|(tip, hash)| {
                    tree.active_height_of(tip.tip_id, hash)
                        .and_then(|h| i32::try_from(h).ok())
                });
                HeaderAdmission::Accepted {
                    accepted: admitted.ids.len(),
                    announced_tip,
                    active_height,
                    demoted_tip: admitted.demoted_tip,
                }
            }
            Err(error) => HeaderAdmission::Rejected(error),
        }
    }

    fn minimum_chain_work(&self) -> ChainWork {
        self.floor
    }

    fn check_body_binding(
        &self,
        _block: &bitcoin_rs_primitives::Block,
    ) -> Result<(), SyncChainError> {
        Ok(())
    }

    fn window_len(&self, _serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
        0
    }

    fn commit_window(
        &self,
        _payloads: &[&bitcoin_rs_primitives::BlockPayload],
    ) -> Result<usize, WindowCommitError> {
        Ok(0)
    }

    fn switch_to_branch(
        &self,
        _target: bitcoin_rs_chain::NodeId,
        _staged_body: &mut dyn FnMut(Hash256) -> Option<bitcoin_rs_primitives::BlockPayload>,
        _connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), bitcoin_rs_chainstate::reorg::ReorgError> {
        Ok(())
    }
}

fn routing_sync(
    tree: BlockTree,
    floor: ChainWork,
) -> (
    BlockSync,
    Arc<crate::PeerTable>,
    crossbeam_channel::Sender<crate::InboundHeaders>,
) {
    let peers = Arc::new(crate::PeerTable::new());
    let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
    let (_blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
    let chain: Arc<dyn SyncChain> = Arc::new(RoutingStubChain::with_floor(tree, floor));
    let sync = BlockSync::new(
        chain,
        Arc::clone(&peers),
        headers_rx,
        blocks_rx,
        crate::sync::syncing_ibd_latch(),
    );
    (sync, peers, headers_tx)
}

fn connected_peer(
    peers: &Arc<crate::PeerTable>,
    port: u16,
    best_height: i32,
) -> (crate::PeerSource, crate::test_support::MessageReceiver) {
    let (tx, rx) = crate::test_support::message_channel();
    let lease = crate::PeerLease::new(tx);
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let endpoint = crate::PeerEndpoint::Ip(addr);
    peers.register(endpoint, lease.clone());
    let info = crate::peer_info::PeerInfo {
        addr: endpoint.into(),
        endpoint: Some(endpoint),
        network: endpoint.net(),
        version: 70016,
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        services: bitcoin::p2p::ServiceFlags::NETWORK.to_u64()
            | bitcoin::p2p::ServiceFlags::WITNESS.to_u64(),
        user_agent: String::from("/test/"),
        start_height: best_height,
        best_known_height: best_height,
        conn_time: 0,
        inbound: false,
        addr_bind: crate::TransportRemote::new(addr),
        time_offset: 0,
        counters: Arc::new(crate::PeerCounters::default()),
        transport: crate::TransportProtocol::V1,
    };
    peers.publish_info(endpoint, &lease, info);
    (lease.source_ip(addr), rx)
}

fn regtest_tree_with_main() -> BlockTree {
    let mut tree = BlockTree::new();
    let genesis = Network::Regtest.genesis_block();
    tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)
        .unwrap_or_else(|error| panic!("genesis inserts: {error}"));
    let mut prev = genesis.block_hash();
    let mut tip_id = tree
        .lookup(Hash256::from(prev))
        .unwrap_or_else(|| panic!("genesis indexed"));
    for height in 1..=2_u32 {
        let header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, height)
            .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        prev = header.compute_hash();
        tip_id = tree
            .insert_node(Some(tip_id), header, NodeStatus::HeaderValid)
            .unwrap_or_else(|error| panic!("main header inserts: {error}"));
    }
    tree
}

#[test]
fn low_work_stale_tip_page_defers_while_broken_page_admits() {
    let tree = regtest_tree_with_main();
    let floor = ChainWork::from_be_bytes([0xFF_u8; 32]);
    let (sync, _peers, _headers_tx) = routing_sync(tree, floor);
    let genesis_prev = Network::Regtest.genesis_block().block_hash();
    let first = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(genesis_prev, 101)
        .unwrap_or_else(|error| panic!("fixture mines: {error}"));
    let second = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(first.compute_hash(), 102)
        .unwrap_or_else(|error| panic!("fixture mines: {error}"));
    let valid_page = [first, second];
    assert!(
        sync.presync_anchor(&valid_page).is_some(),
        "the fixture page must sit below the raised floor"
    );
    assert!(
        !sync.body_carried_header_needs_admission(&valid_page),
        "a valid low-work stale-tip page must defer, not admit past the hold"
    );
    let mut broken = valid_page;
    broken[1].nonce = broken[1].nonce.wrapping_add(1).wrapping_mul(7919);
    if bitcoin_rs_chain::validate_pow(
        &broken[1],
        Hash256::from(broken[1].compute_hash()),
        Network::Regtest,
    )
    .is_ok()
    {
        broken[1].bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x1d00_ffff);
    }
    assert!(
        sync.body_carried_header_needs_admission(&broken),
        "a broken stale-tip page must admit so the fault is reported"
    );
}

#[test]
fn partial_prefix_rejection_preserves_demoted_tip() {
    let tree = regtest_tree_with_main();
    let floor = ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work());
    let (sync, peers, headers_tx) = routing_sync(tree, floor);
    let (source, _rx) = connected_peer(&peers, 18445, 3);
    let pre_tip = sync
        .chain
        .chain_tip()
        .unwrap_or_else(|| panic!("tree has a tip"))
        .hash;
    let genesis_prev = Network::Regtest.genesis_block().block_hash();
    let mut batch = Vec::new();
    let mut prev = genesis_prev;
    for height in [101_u32, 102, 103] {
        let header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, height)
            .unwrap_or_else(|error| panic!("fixture mines: {error}"));
        prev = header.compute_hash();
        batch.push(header);
    }
    let garbage = bitcoin_rs_primitives::BlockHash::from(
        bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xFF_u8; 32]),
    );
    batch.push(
        bitcoin_rs_chain::regtest_fixture::mined_regtest_header(garbage, 104)
            .unwrap_or_else(|error| panic!("fixture mines: {error}")),
    );
    headers_tx
        .send(crate::InboundHeaders {
            headers: batch,
            source: Some(source),
            wire_response: false,
        })
        .unwrap_or_else(|error| panic!("queue stale-tip batch: {error}"));
    sync.drain_inbound_headers();
    let moved = sync
        .chain
        .chain_tip()
        .unwrap_or_else(|| panic!("tree has a tip"))
        .hash;
    assert_ne!(
        moved, pre_tip,
        "the above-floor prefix must move the tip before the tail fails"
    );
    let fresh = crate::PeerSource::for_test(std::net::SocketAddr::from(([127, 0, 0, 1], 18499)));
    let pending = sync.stale_tips().pending_for(fresh, |_| true);
    assert!(
        pending.contains(&pre_tip),
        "the drain must retain the displaced tip for stale relay, got {pending:?}"
    );
}

#[test]
fn duplicate_fetch_skips_owned_body() {
    let tree = regtest_tree_with_main();
    let floor = ChainWork::from_be_bytes(Network::Regtest.minimum_chain_work());
    let (sync, peers, headers_tx) = routing_sync(tree, floor);
    let (source, rx) = connected_peer(&peers, 18446, 3);
    let tip = sync
        .chain
        .chain_tip()
        .unwrap_or_else(|| panic!("tree has a tip"));
    let prev = bitcoin_rs_primitives::BlockHash::from(tip.hash);
    let header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, 3)
        .unwrap_or_else(|error| panic!("fixture mines: {error}"));
    let tip_hash = Hash256::from(header.compute_hash());
    assert!(
        sync.enqueue_owned_body_fetch(source, tip_hash, || true),
        "the compact follow-up publishes ownership"
    );
    headers_tx
        .send(crate::InboundHeaders {
            headers: vec![header],
            source: Some(source),
            wire_response: true,
        })
        .unwrap_or_else(|error| panic!("queue owned announcement: {error}"));
    sync.drain_inbound_headers();
    assert!(
        sync.owns_body_fetch(source, tip_hash),
        "the owned mark must survive the drain that admitted its header"
    );
    let mut saw_getdata = false;
    while let Ok(message) = rx.try_recv() {
        if matches!(message, crate::Message::GetData(_)) {
            saw_getdata = true;
        }
    }
    assert!(
        !saw_getdata,
        "the owned body must not be direct-fetched twice"
    );
    let (control_source, control_rx) = connected_peer(&peers, 18447, 4);
    let tip = sync
        .chain
        .chain_tip()
        .unwrap_or_else(|| panic!("tree has a tip"));
    let prev = bitcoin_rs_primitives::BlockHash::from(tip.hash);
    let control_header = bitcoin_rs_chain::regtest_fixture::mined_regtest_header(prev, 4)
        .unwrap_or_else(|error| panic!("fixture mines: {error}"));
    headers_tx
        .send(crate::InboundHeaders {
            headers: vec![control_header],
            source: Some(control_source),
            wire_response: true,
        })
        .unwrap_or_else(|error| panic!("queue control announcement: {error}"));
    sync.drain_inbound_headers();
    let mut control_saw_getdata = false;
    while let Ok(message) = control_rx.try_recv() {
        if matches!(message, crate::Message::GetData(_)) {
            control_saw_getdata = true;
        }
    }
    assert!(
        control_saw_getdata,
        "the unowned control announcement must direct-fetch its body"
    );
}
