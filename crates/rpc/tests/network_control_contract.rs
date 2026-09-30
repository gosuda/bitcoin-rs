//! RPC network-control mutations run through the real P2P service owner.
//!
//! ARCH-07 mutation boundary: `setban`, `clearbanned`, `setnetworkactive`,
//! `addnode`, and `disconnectnode` reach the same [`P2pService`] that answers
//! read-only network queries. The RPC context receives only `P2pQuery` and
//! `P2pControl` capabilities, never the underlying writable state.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use bitcoin_rs_p2p::{OutboundDial, P2pService, P2pServiceConfig, PeerInfo, PeerLease};
use bitcoin_rs_rpc::{
    Handler, RpcError,
    context::{Context, ContextHandles, NetworkHandles},
};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

struct Fixture {
    handler: Handler,
    p2p: Arc<P2pService>,
}

impl Fixture {
    fn new(config: P2pServiceConfig) -> Self {
        let p2p = Arc::new(P2pService::new(config, Arc::new(AtomicBool::new(false))));
        let context = Context::from_handles(ContextHandles {
            network: NetworkHandles::from_p2p(Arc::clone(&p2p)),
            ..ContextHandles::default()
        });
        Self {
            handler: Handler::new(Arc::new(context)),
            p2p,
        }
    }

    fn dispatch(&self, method: &str, params: &sonic_rs::Value) -> sonic_rs::Value {
        self.handler
            .dispatch(method, params)
            .unwrap_or_else(|error| panic!("{method} failed: {error}"))
    }

    fn take_dials(&self) -> Vec<OutboundDial> {
        self.p2p.outbound_receiver().lock().try_iter().collect()
    }

    fn register_peer(&self, addr: SocketAddr) -> PeerLease {
        let info = PeerInfo {
            wtxid_relay: false,
            compact_block_relay: false,
            addr,
            version: 70_016,
            services: 9,
            user_agent: "test".to_owned(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: addr,
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        };
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        self.p2p.table().register(addr, lease.clone());
        self.p2p.table().publish_info(addr, &lease, info);
        lease
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new(P2pServiceConfig::default())
    }
}

#[test]
fn ban_rpcs_mutate_the_service_owned_list() {
    let fixture = Fixture::default();
    assert!(
        fixture
            .dispatch("setban", &json!(["10.0.0.1:8333", "add"]))
            .is_null()
    );
    assert_eq!(fixture.p2p.banned().len(), 1);
    let listed = fixture.dispatch("listbanned", &json!(null));
    assert_eq!(
        listed
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|entry| entry.get("address"))
            .and_then(JsonValueTrait::as_str),
        Some("10.0.0.1/32")
    );

    fixture.dispatch("setban", &json!(["10.0.0.1:8333", "remove"]));
    assert!(fixture.p2p.banned().is_empty());
    fixture.dispatch("setban", &json!(["192.0.2.1", "add"]));
    fixture.dispatch("clearbanned", &json!(null));
    assert!(fixture.p2p.banned().is_empty());
}

#[test]
fn setnetworkactive_mutates_the_service_latch_and_cancels_peers() {
    let fixture = Fixture::default();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
    let lease = fixture.register_peer(addr);

    assert_eq!(
        fixture
            .dispatch("setnetworkactive", &json!([false]))
            .as_bool(),
        Some(false)
    );
    assert!(!fixture.p2p.network_active());
    assert!(lease.is_cancelled());
    let info = fixture.dispatch("getnetworkinfo", &json!(null));
    assert_eq!(
        info.get("networkactive").and_then(JsonValueTrait::as_bool),
        Some(false)
    );

    fixture.dispatch("setnetworkactive", &json!([true]));
    assert!(fixture.p2p.network_active());
}

#[test]
fn addnode_preserves_persistence_and_dial_behavior() {
    let fixture = Fixture::default();
    for _ in 0..2 {
        fixture.dispatch("addnode", &json!(["127.0.0.1:8333", "add"]));
    }

    assert_eq!(
        fixture.p2p.added_nodes(),
        vec![SocketAddr::from(([127, 0, 0, 1], 8333))]
    );
    assert_eq!(fixture.take_dials().len(), 2);
    let listed = fixture.dispatch("getaddednodeinfo", &json!([]));
    assert_eq!(listed.as_array().map(sonic_rs::Array::len), Some(1));

    fixture.dispatch("addnode", &json!(["127.0.0.2:8333", "remove"]));
    assert_eq!(fixture.p2p.added_nodes().len(), 1);
    fixture.dispatch("addnode", &json!(["127.0.0.1:8333", "remove"]));
    assert!(fixture.p2p.added_nodes().is_empty());
}

#[test]
fn addnode_rejects_banned_destinations_before_persisting_or_dialing() {
    let fixture = Fixture::default();
    fixture.dispatch("setban", &json!(["127.0.0.0/24", "add"]));

    let Err(error) = fixture
        .handler
        .dispatch("addnode", &json!(["127.0.0.1:8333", "add"]))
    else {
        panic!("a banned destination must not be added");
    };
    assert!(matches!(&error, RpcError::InvalidParams(message) if *message == "node is banned"));
    assert!(fixture.p2p.added_nodes().is_empty());
    assert!(fixture.take_dials().is_empty());
}

#[test]
fn addnode_onetry_dials_without_persisting() {
    let fixture = Fixture::default();
    fixture.dispatch("addnode", &json!(["127.0.0.1:8333", "onetry"]));

    assert!(fixture.p2p.added_nodes().is_empty());
    assert_eq!(fixture.take_dials().len(), 1);
}

#[test]
fn addnode_queue_saturation_keeps_persistent_and_onetry_results_distinct() {
    let config = P2pServiceConfig {
        outbound_queue_limit: 1,
        ..P2pServiceConfig::default()
    };
    let persistent = Fixture::new(config.clone());
    persistent
        .p2p
        .outbound_sender()
        .try_send(OutboundDial::pinned(SocketAddr::from((
            [127, 0, 0, 9],
            8333,
        ))))
        .unwrap_or_else(|error| panic!("fill queue: {error}"));
    assert!(
        persistent
            .dispatch("addnode", &json!(["127.0.0.1:8333", "add"]))
            .is_null()
    );
    assert_eq!(persistent.p2p.added_nodes().len(), 1);

    let one_try = Fixture::new(config);
    one_try
        .p2p
        .outbound_sender()
        .try_send(OutboundDial::pinned(SocketAddr::from((
            [127, 0, 0, 9],
            8333,
        ))))
        .unwrap_or_else(|error| panic!("fill queue: {error}"));
    let Err(error) = one_try
        .handler
        .dispatch("addnode", &json!(["127.0.0.1:8333", "onetry"]))
    else {
        panic!("a saturated one-shot request must fail");
    };
    assert!(matches!(
        error,
        RpcError::Internal(message) if message == "p2p outbound queue full"
    ));
    assert!(one_try.p2p.added_nodes().is_empty());
}

#[test]
fn addnode_persists_without_dialing_while_network_is_inactive() {
    let fixture = Fixture::default();
    fixture.dispatch("setnetworkactive", &json!([false]));
    fixture.dispatch("addnode", &json!(["127.0.0.1:8333", "add"]));

    assert_eq!(fixture.p2p.added_nodes().len(), 1);
    assert!(fixture.take_dials().is_empty());
}

#[test]
fn disconnectnode_checks_the_reported_nodeid_before_service_mutation() {
    let fixture = Fixture::default();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
    let lease = fixture.register_peer(addr);

    let Err(error) = fixture
        .handler
        .dispatch("disconnectnode", &json!([addr.to_string().as_str(), 5]))
    else {
        panic!("a mismatched nodeid must be rejected");
    };
    assert!(matches!(error, RpcError::NotFound(_)));
    assert!(!lease.is_cancelled());

    fixture.dispatch("disconnectnode", &json!([addr.to_string().as_str(), 0]));
    assert!(lease.is_cancelled());
    assert_eq!(fixture.p2p.table().len(), 0);
}

#[test]
fn disconnectnode_without_nodeid_removes_the_matching_peer() {
    let fixture = Fixture::default();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
    fixture.register_peer(addr);

    fixture.dispatch("disconnectnode", &json!([addr.to_string().as_str()]));
    assert_eq!(fixture.p2p.table().len(), 0);
}
