#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Focused network RPC coverage through shared `NetworkControls`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin_rs_p2p::{Message, NetworkControls, PeerInfo, PeerLease};
use bitcoin_rs_rpc::context::Context;
use parking_lot::RwLock;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

fn controls() -> Arc<NetworkControls> {
    Arc::new(NetworkControls::new(
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(RwLock::new(hashbrown::HashMap::new())),
        Arc::new(RwLock::new(Vec::new())),
        8_333,
    ))
}

fn ctx_with(controls: Arc<NetworkControls>) -> Arc<Context> {
    Arc::new(Context::new().with_network_controls(controls))
}

fn insert_peer(controls: &NetworkControls, addr: SocketAddr, inbound: bool) -> PeerLease {
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = if inbound {
        PeerLease::new_inbound(tx)
    } else {
        PeerLease::new(tx)
    };
    controls.peer_outbound().write().insert(addr, lease.clone());
    controls.peer_registry().write().push(PeerInfo {
        addr,
        version: 70_016,
        services: (1_u64 << 0) | (1_u64 << 3),
        user_agent: "/test:0.1.0/".to_owned(),
        start_height: 100,
        conn_time: 1_700_000_000,
        inbound,
    });
    lease
}

#[test]
fn connection_count_and_peerinfo_use_shared_leases() {
    let controls = controls();
    let inbound = SocketAddr::from(([127, 0, 0, 1], 1));
    let outbound = SocketAddr::from(([127, 0, 0, 1], 2));
    let lease = insert_peer(&controls, inbound, true);
    insert_peer(&controls, outbound, false);
    lease.stats().record_recv(11);
    lease.stats().record_sent(17);
    let ctx = ctx_with(Arc::clone(&controls));

    let handler = bitcoin_rs_rpc::handlers::Handler::new(Arc::clone(&ctx));
    let count = handler
        .dispatch("getconnectioncount", &json!([]))
        .unwrap_or_else(|err| panic!("getconnectioncount failed: {err}"));
    assert_eq!(count.as_u64(), Some(2));

    let peers = handler
        .dispatch("getpeerinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getpeerinfo failed: {err}"));
    let arr = peers.as_array().unwrap_or_else(|| panic!("expected array"));
    assert_eq!(arr.len(), 2);
    let inbound_peer = arr
        .iter()
        .find(|peer| peer.get("inbound").and_then(JsonValueTrait::as_bool) == Some(true))
        .unwrap_or_else(|| panic!("missing inbound peer"));
    assert_eq!(
        inbound_peer
            .get("bytesrecv")
            .and_then(JsonValueTrait::as_u64),
        Some(11)
    );
    assert_eq!(
        inbound_peer
            .get("bytessent")
            .and_then(JsonValueTrait::as_u64),
        Some(17)
    );
    assert_eq!(
        inbound_peer.get("id").and_then(JsonValueTrait::as_u64),
        Some(lease.node_id())
    );
}

#[test]
fn getnettotals_reads_authoritative_byte_counters() {
    let controls = controls();
    controls.totals().record_recv(100);
    controls.totals().record_sent(250);
    let ctx = ctx_with(controls);
    let handler = bitcoin_rs_rpc::handlers::Handler::new(ctx);
    let totals = handler
        .dispatch("getnettotals", &json!([]))
        .unwrap_or_else(|err| panic!("getnettotals failed: {err}"));
    assert_eq!(
        totals
            .get("totalbytesrecv")
            .and_then(JsonValueTrait::as_u64),
        Some(100)
    );
    assert_eq!(
        totals
            .get("totalbytessent")
            .and_then(JsonValueTrait::as_u64),
        Some(250)
    );
    assert_eq!(
        totals
            .get("uploadtarget")
            .and_then(|value| value.get("timeframe"))
            .and_then(JsonValueTrait::as_u64),
        Some(86_400)
    );
}

#[test]
fn ping_queues_nonce_on_live_peer() {
    let controls = controls();
    let addr = SocketAddr::from(([10, 0, 0, 1], 8333));
    let (tx, rx) = crossbeam_channel::unbounded();
    let lease = PeerLease::new(tx);
    controls.peer_outbound().write().insert(addr, lease.clone());
    let ctx = ctx_with(Arc::clone(&controls));
    let handler = bitcoin_rs_rpc::handlers::Handler::new(ctx);

    let result = handler
        .dispatch("ping", &json!([]))
        .unwrap_or_else(|err| panic!("ping failed: {err}"));
    assert!(result.is_null());
    assert!(matches!(rx.try_recv(), Ok(Message::Ping(_))));
    assert!(lease.stats().ping_wait(1).is_some());
}

#[test]
fn disconnectnode_by_address_and_id_with_exact_missing_error() {
    let controls = controls();
    let addr = SocketAddr::from(([127, 0, 0, 9], 8333));
    let lease = insert_peer(&controls, addr, false);
    let node_id = lease.node_id();
    let ctx = ctx_with(Arc::clone(&controls));
    let handler = bitcoin_rs_rpc::handlers::Handler::new(Arc::clone(&ctx));

    let missing = handler.dispatch("disconnectnode", &json!(["127.0.0.1:1"]));
    assert!(
        missing.as_ref().err().is_some_and(|err| err
            .to_string()
            .contains("Node not found in connected nodes")),
        "unexpected: {missing:?}"
    );

    handler
        .dispatch("disconnectnode", &json!([addr.to_string()]))
        .unwrap_or_else(|err| panic!("disconnect by addr failed: {err}"));
    assert!(controls.peer_outbound().read().is_empty());

    let _lease = insert_peer(&controls, addr, false);
    let handler = bitcoin_rs_rpc::handlers::Handler::new(ctx);
    let current_id = controls
        .connected_peers()
        .first()
        .map_or(node_id, |peer| peer.node_id);
    handler
        .dispatch("disconnectnode", &json!(["", current_id]))
        .unwrap_or_else(|err| panic!("disconnect by id failed: {err}"));
    assert!(controls.peer_outbound().read().is_empty());
}

#[test]
fn addnode_mutations_visible_and_duplicate_errors() {
    let (tx, rx) = crossbeam_channel::unbounded();
    let controls = Arc::new(
        NetworkControls::new(
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(hashbrown::HashMap::new())),
            Arc::new(RwLock::new(Vec::new())),
            8_333,
        )
        .with_dial_sender(tx),
    );
    let ctx = ctx_with(Arc::clone(&controls));
    let handler = bitcoin_rs_rpc::handlers::Handler::new(ctx);

    handler
        .dispatch("addnode", &json!(["127.0.0.1:8333", "add"]))
        .unwrap_or_else(|err| panic!("addnode add failed: {err}"));
    assert_eq!(
        rx.try_recv().ok(),
        Some(SocketAddr::from(([127, 0, 0, 1], 8333)))
    );

    let infos = handler
        .dispatch("getaddednodeinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getaddednodeinfo failed: {err}"));
    assert!(infos.as_array().is_some_and(|arr| arr.len() == 1));

    let duplicate = handler.dispatch("addnode", &json!(["127.0.0.1:8333", "add"]));
    assert!(
        duplicate
            .as_ref()
            .err()
            .is_some_and(|err| err.to_string().contains("node already added")),
        "unexpected: {duplicate:?}"
    );

    let missing = handler.dispatch("addnode", &json!(["10.0.0.1:8333", "remove"]));
    assert!(
        missing.as_ref().err().is_some_and(|err| {
            err.to_string()
                .contains("node could not be removed. it has not been added previously.")
        }),
        "unexpected: {missing:?}"
    );
}

#[test]
fn ban_expiry_and_network_toggle_through_shared_controls() {
    let controls = controls();
    let ctx = ctx_with(Arc::clone(&controls));
    let handler = bitcoin_rs_rpc::handlers::Handler::new(Arc::clone(&ctx));

    let past = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs().saturating_sub(10));
    let past_err = handler.dispatch("setban", &json!(["203.0.113.1", "add", past, true]));
    assert!(
        past_err.as_ref().err().is_some_and(|err| err
            .to_string()
            .contains("absolute timestamp is in the past")),
        "unexpected: {past_err:?}"
    );

    handler
        .dispatch("setban", &json!(["203.0.113.0/24", "add", 1]))
        .unwrap_or_else(|err| panic!("setban failed: {err}"));
    let listed = handler
        .dispatch("listbanned", &json!([]))
        .unwrap_or_else(|err| panic!("listbanned failed: {err}"));
    assert!(listed.as_array().is_some_and(|arr| arr.len() == 1));

    std::thread::sleep(Duration::from_millis(1_100));
    let listed = handler
        .dispatch("listbanned", &json!([]))
        .unwrap_or_else(|err| panic!("listbanned after expiry failed: {err}"));
    assert!(listed.as_array().is_some_and(sonic_rs::Array::is_empty));

    let inactive = handler
        .dispatch("setnetworkactive", &json!([false]))
        .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
    assert_eq!(inactive.as_bool(), Some(false));
    let info = handler
        .dispatch("getnetworkinfo", &json!([]))
        .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
    assert_eq!(
        info.get("networkactive").and_then(JsonValueTrait::as_bool),
        Some(false)
    );
    assert!(!controls.network_active());
}
