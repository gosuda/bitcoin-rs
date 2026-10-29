use super::*;
use alloc::sync::Arc;
use sonic_rs::JsonValueTrait;
use sonic_rs::json;

#[test]
fn addnode_rejects_bad_address() {
    let ctx = Arc::new(Context::new());
    let result = addnode(&ctx, &json!(["definitely-not-an-address", "add"]));
    assert!(result.is_err());
}

#[test]
fn addnode_rejects_unknown_command() {
    let ctx = Arc::new(Context::new());
    let result = addnode(&ctx, &json!(["127.0.0.1:8333", "frobnicate"]));
    assert!(result.is_err());
}

#[test]
fn addnode_accepts_well_formed_input() {
    let ctx = Arc::new(Context::new());
    let result = addnode(&ctx, &json!(["127.0.0.1:8333", "onetry"]))
        .unwrap_or_else(|err| panic!("addnode failed: {err}"));
    assert!(result.is_null());
}

#[test]
fn addnode_skips_queueing_while_network_is_inactive() {
    let ctx = Arc::new(Context::new());
    ctx.network.p2p.set_network_active(false);

    let persisted = bitcoin_rs_p2p::PeerEndpoint::Ip(SocketAddr::from(([127, 0, 0, 1], 8333)));
    let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));
    assert!(result.is_ok());
    assert_eq!(ctx.network.p2p.added_nodes().as_slice(), &[persisted]);

    ctx.network.p2p.set_network_active(true);
    let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));
    assert!(result.is_ok());
}

#[test]
fn addnode_add_persists_node() {
    let ctx = Arc::new(Context::new());
    let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
        .unwrap_or_else(|err| panic!("addnode failed: {err}"));

    assert!(result.is_null());
    assert_eq!(
        ctx.network.p2p.added_nodes().as_slice(),
        &[bitcoin_rs_p2p::PeerEndpoint::from(([127, 0, 0, 1], 8333))]
    );
}

#[test]
fn addnode_returns_error_when_outbound_queue_is_full() {
    let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
        bitcoin_rs_p2p::P2pServiceConfig {
            outbound_queue_limit: 1,
            ..bitcoin_rs_p2p::P2pServiceConfig::default()
        },
        bitcoin_rs_chain::LatchReader::fixture_never(),
    ));
    p2p.add_node(SocketAddr::from(([127, 0, 0, 1], 8333)).into(), false)
        .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
    let mut ctx = Context::new();
    ctx.network.p2p = Arc::clone(&p2p);
    let ctx = Arc::new(ctx);

    let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));

    assert!(matches!(
        result,
        Err(RpcError::Internal(message)) if message == "p2p outbound queue full"
    ));
}

#[test]
fn addnode_add_persists_when_outbound_queue_is_full() {
    let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
        bitcoin_rs_p2p::P2pServiceConfig {
            outbound_queue_limit: 1,
            ..bitcoin_rs_p2p::P2pServiceConfig::default()
        },
        bitcoin_rs_chain::LatchReader::fixture_never(),
    ));
    p2p.add_node(SocketAddr::from(([127, 0, 0, 1], 8333)).into(), false)
        .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
    let mut ctx = Context::new();
    ctx.network.p2p = Arc::clone(&p2p);
    let ctx = Arc::new(ctx);

    let result = addnode(&ctx, &json!(["127.0.0.2:8333", "add"]))
        .unwrap_or_else(|err| panic!("addnode failed: {err}"));

    assert!(result.is_null());
    let added = ctx.network.p2p.added_nodes();
    assert_eq!(
        added.as_slice(),
        [bitcoin_rs_p2p::PeerEndpoint::from(([127, 0, 0, 2], 8333))]
    );
}

#[test]
fn addnode_rejects_manually_banned_subnet() {
    let ctx = Arc::new(Context::new());
    if let Err(err) = setban(&ctx, &json!(["127.0.0.0/24", "add"])) {
        panic!("setban failed: {err}");
    }

    let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));

    assert!(matches!(
        result,
        Err(RpcError::InvalidParams("node is banned"))
    ));
    assert_eq!(ctx.network.p2p.added_nodes().as_slice(), &[]);
}

#[test]
fn disconnectnode_rejects_bad_address() {
    let ctx = Arc::new(Context::new());
    let result = disconnectnode(&ctx, &json!(["definitely-not-an-address"]));
    assert!(result.is_err());
}

#[test]
fn disconnectnode_rejects_unconnected_address() {
    let ctx = Arc::new(Context::new());
    let result = disconnectnode(&ctx, &json!(["127.0.0.1:8333"]));
    assert!(matches!(result, Err(RpcError::NotFound(_))));
}

#[test]
fn disconnectnode_cancels_lease_and_removes_peer() {
    use bitcoin_rs_p2p::{PeerInfo, PeerLease};
    use crossbeam_channel::unbounded;

    let addr: SocketAddr = "127.0.0.1:8333".parse().expect("addr");
    let ctx = Context::new();
    let info = PeerInfo {
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        endpoint: Some(bitcoin_rs_p2p::PeerEndpoint::Ip(addr)),
        network: bitcoin_rs_p2p::PeerEndpoint::Ip(addr).net(),
        addr: addr.into(),
        version: 70_016,
        services: 9,
        user_agent: "test".to_owned(),
        start_height: 0,
        best_known_height: 0,
        conn_time: 0,
        inbound: false,
        addr_bind: bitcoin_rs_p2p::TransportRemote::new(addr),
        time_offset: 0,
        counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        transport: bitcoin_rs_p2p::TransportProtocol::V1,
    };
    let (tx, _rx) = unbounded();
    let lease = PeerLease::new(tx);
    ctx.network
        .peer_table
        .register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), lease.clone());
    ctx.network
        .peer_table
        .publish_info(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), &lease, info);
    let ctx = Arc::new(ctx);

    let result = disconnectnode(&ctx, &json!([addr.to_string().as_str()]))
        .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
    assert!(result.is_null());
    assert!(lease.is_cancelled());
    assert!(ctx.network.peer_table.is_empty());
    assert_eq!(ctx.network.peer_table.infos(), []);
}

fn peer_info_at(addr: SocketAddr) -> bitcoin_rs_p2p::PeerInfo {
    let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
    bitcoin_rs_p2p::PeerInfo {
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        addr: endpoint.into(),
        endpoint: Some(endpoint),
        network: endpoint.net(),
        version: 70_016,
        services: 9,
        user_agent: "test".to_owned(),
        start_height: 0,
        best_known_height: 0,
        conn_time: 0,
        inbound: false,
        addr_bind: bitcoin_rs_p2p::TransportRemote::new(addr),
        time_offset: 0,
        counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        transport: bitcoin_rs_p2p::TransportProtocol::V1,
    }
}

fn register_pending_peer(ctx: &Context, addr: SocketAddr) -> bitcoin_rs_p2p::PeerLease {
    let (tx, _rx) = crossbeam_channel::unbounded();
    let lease = bitcoin_rs_p2p::PeerLease::new(tx);
    ctx.network
        .peer_table
        .register(bitcoin_rs_p2p::PeerEndpoint::Ip(addr), lease.clone());
    lease
}

fn register_peer(ctx: &Context, addr: SocketAddr) -> bitcoin_rs_p2p::PeerLease {
    let lease = register_pending_peer(ctx, addr);
    let endpoint = bitcoin_rs_p2p::PeerEndpoint::Ip(addr);
    assert!(
        ctx.network
            .peer_table
            .publish_info(endpoint, &lease, peer_info_at(addr))
    );
    lease
}

#[test]
fn getpeerinfo_rows_match_the_pinned_v31_row() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;

    let ctx = Context::new();
    let _lease = register_peer(&ctx, "127.0.0.1:9101".parse()?);
    let ctx = Arc::new(ctx);

    let wire = getpeerinfo(&ctx, &json!(null))?;
    let typed: v31::GetPeerInfo = sonic_rs::from_str(&sonic_rs::to_string(&wire)?)?;
    let pinned = sonic_rs::to_value(&typed)?;

    let keys = |rows: &Value, keep_null: bool| -> Option<BTreeSet<String>> {
        let row = rows.as_array()?.first()?.as_object()?;
        Some(
            row.iter()
                .filter(|(_, field)| keep_null || !field.is_null())
                .map(|(key, _)| key.to_owned())
                .collect(),
        )
    };
    let wire_keys = keys(&wire, true).ok_or("the wire row is a one-element array of objects")?;
    let pinned_keys =
        keys(&pinned, false).ok_or("the pinned row is a one-element array of objects")?;
    assert_eq!(wire_keys, pinned_keys);

    let row = wire
        .as_array()
        .and_then(|rows| rows.first())
        .ok_or("the wire row is a one-element array")?;
    for key in [
        "connection_type",
        "presynced_headers",
        "synced_headers",
        "synced_blocks",
        "inflight",
    ] {
        assert!(row.get(key).is_some(), "{key} must stay populated: {row:?}");
    }
    Ok(())
}

fn fields_but_id(
    row: &Value,
) -> Result<std::collections::BTreeMap<&str, &Value>, Box<dyn std::error::Error>> {
    let object = row.as_object().ok_or("rows are objects")?;
    Ok(object.iter().filter(|(key, _)| *key != "id").collect())
}

#[test]
fn getpeerinfo_row_carries_ids_above_u32_max_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let _lease = register_peer(&ctx, "127.0.0.1:9102".parse()?);
    let sessions = ctx.network.peer_table.sessions();
    let session = sessions.first().ok_or("the fixture session is listed")?;
    let peer = session
        .info
        .as_ref()
        .ok_or("the fixture session completed its handshake")?;

    let ids = [
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::from(u32::MAX) + 2,
        u64::MAX - 1,
    ];
    assert_eq!(
        peer_info_wire(session, peer, 0.0).id,
        session.lease.node_id(),
        "the projection takes the id from the session's own lease"
    );
    let rows = ids
        .iter()
        .map(|&id| PeerInfoWire {
            id,
            ..peer_info_wire(session, peer, 0.0)
        })
        .collect::<Vec<_>>();
    let rendered = typed_to_sonic_omitting_nulls(&rows)?;
    let Some(rendered) = rendered.as_array() else {
        return Err("getpeerinfo must return an array".into());
    };

    let rendered_ids = rendered
        .iter()
        .map(|row| row.get("id").and_then(JsonValueTrait::as_u64))
        .collect::<Vec<_>>();
    assert_eq!(rendered_ids, ids.map(Some));

    let Some((first, rest)) = rendered.split_first() else {
        return Err("the rendered rows are not empty".into());
    };
    let expected = fields_but_id(first)?;
    for row in rest {
        assert_eq!(fields_but_id(row)?, expected);
    }
    Ok(())
}

#[test]
fn disconnectnode_nodeid_above_u32_max_never_aliases_a_live_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let lease = register_peer(&ctx, "127.0.0.1:9103".parse()?);
    let ctx = Arc::new(ctx);

    let wide = lease.node_id() + (u64::from(u32::MAX) + 1);
    let refused = disconnectnode(&ctx, &json!({ "nodeid": wide }));
    assert!(
        matches!(refused, Err(RpcError::NotFound(_))),
        "a wide selector is well-formed but names no connection"
    );
    assert!(!lease.is_cancelled());
    Ok(())
}

#[test]
fn getpeerinfo_ids_are_connection_identities_not_positions()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let addr_a: SocketAddr = "127.0.0.1:9001".parse()?;
    let addr_b: SocketAddr = "127.0.0.1:9002".parse()?;
    let addr_c: SocketAddr = "127.0.0.1:9003".parse()?;
    let lease_a = register_peer(&ctx, addr_a);
    let lease_b = register_peer(&ctx, addr_b);
    let lease_c = register_peer(&ctx, addr_c);
    let ctx = Arc::new(ctx);

    let first = getpeerinfo(&ctx, &json!(null))?;
    let Some(rows) = first.as_array() else {
        return Err("getpeerinfo must return an array".into());
    };
    let ids: Vec<u64> = rows
        .iter()
        .map(|row| {
            row.get("id")
                .and_then(JsonValueTrait::as_u64)
                .ok_or("every row carries an id")
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(
        ids,
        [lease_a.node_id(), lease_b.node_id(), lease_c.node_id()],
        "the reported id is the connection's own, in connection order"
    );

    assert!(ctx.network.p2p.disconnect_ready_node_id(lease_a.node_id()));
    let after = getpeerinfo(&ctx, &json!(null))?;
    let Some(rows) = after.as_array() else {
        return Err("getpeerinfo must return an array".into());
    };
    let ids: Vec<u64> = rows
        .iter()
        .map(|row| {
            row.get("id")
                .and_then(JsonValueTrait::as_u64)
                .ok_or("every row carries an id")
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(ids, [lease_b.node_id(), lease_c.node_id()]);
    assert!(!lease_b.is_cancelled());
    assert!(!lease_c.is_cancelled());
    Ok(())
}

#[test]
fn disconnectnode_nodeid_never_disconnects_a_replacement_at_the_same_address()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let addr: SocketAddr = "127.0.0.1:8333".parse()?;
    let selected = register_peer(&ctx, addr);
    let selected_id = selected.node_id();

    let replacement = register_peer(&ctx, addr);
    assert!(selected.is_cancelled());
    let replacement_id = replacement.node_id();
    assert_ne!(selected_id, replacement_id);
    let ctx = Arc::new(ctx);

    let stale = disconnectnode(&ctx, &json!(["", selected_id]));
    assert!(
        matches!(stale, Err(RpcError::NotFound(_))),
        "the named connection is gone, so the call must refuse instead of hitting its successor: {stale:?}"
    );
    assert!(
        !replacement.is_cancelled(),
        "the replacement was never named and must survive"
    );
    assert_eq!(ctx.network.peer_table.len(), 1);

    let named = disconnectnode(&ctx, &json!(["", replacement_id]))
        .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
    assert!(named.is_null());
    assert!(replacement.is_cancelled());
    assert!(ctx.network.peer_table.is_empty());
    Ok(())
}

#[test]
fn disconnectnode_nodeid_addresses_an_anonymous_inbound_session()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_p2p::{PeerInfo, PeerLease};
    use crossbeam_channel::unbounded;

    let ctx = Context::new();
    let (tx, _rx) = unbounded();
    let anon = PeerLease::new_inbound(tx);
    assert!(!ctx.network.peer_table.register_unidentified(anon.clone()));
    let info = PeerInfo {
        wtxid_relay: false,
        relay_transactions: true,
        compact_block_relay: false,
        send_headers: false,
        addr: bitcoin_rs_p2p::PeerRemote::AnonymousTor(anon.connection_id()),
        endpoint: None,
        network: bitcoin_rs_primitives::NetworkLabel::Onion,
        version: 70_016,
        services: 0,
        user_agent: "anon".to_owned(),
        start_height: 0,
        best_known_height: 0,
        conn_time: 0,
        inbound: true,
        addr_bind: bitcoin_rs_p2p::TransportRemote::new("127.0.0.1:9000".parse()?),
        time_offset: 0,
        counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        transport: bitcoin_rs_p2p::TransportProtocol::V1,
    };
    let published = ctx
        .network
        .peer_table
        .publish_info_unidentified(&anon, info);
    assert!(published);
    let node_id = anon.node_id();
    let handle = bitcoin_rs_p2p::PeerRemote::AnonymousTor(anon.connection_id()).to_string();
    let ctx = Arc::new(ctx);

    let peers = getpeerinfo(&ctx, &json!(null))?;
    let Some(rows) = peers.as_array() else {
        return Err("getpeerinfo must return an array".into());
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("addr").and_then(JsonValueTrait::as_str),
        Some(handle.as_str())
    );
    assert_eq!(
        rows[0].get("id").and_then(JsonValueTrait::as_u64),
        Some(node_id)
    );

    let result = disconnectnode(&ctx, &json!(["", node_id]))
        .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
    assert!(result.is_null());
    assert!(anon.is_cancelled());
    assert!(ctx.network.peer_table.is_empty());
    Ok(())
}

#[test]
fn disconnectnode_address_and_nodeid_is_a_conjunction_under_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let addr: SocketAddr = "127.0.0.1:8350".parse()?;
    let selected = register_peer(&ctx, addr);
    let selected_id = selected.node_id();
    let replacement = register_peer(&ctx, addr);
    let replacement_id = replacement.node_id();
    let ctx = Arc::new(ctx);
    let address = addr.to_string();

    let stale = disconnectnode(&ctx, &json!([address.as_str(), selected_id]));
    assert!(
        matches!(stale, Err(RpcError::NotFound(_))),
        "the stale id must not resolve to the connection now at the address: {stale:?}"
    );
    assert!(!replacement.is_cancelled());
    assert_eq!(ctx.network.peer_table.len(), 1);

    let other: SocketAddr = "127.0.0.1:8351".parse()?;
    let wrong_address = other.to_string();
    let wrong = disconnectnode(&ctx, &json!([wrong_address.as_str(), replacement_id]));
    assert!(
        matches!(wrong, Err(RpcError::NotFound(_))),
        "the id names a connection at a different address: {wrong:?}"
    );
    assert!(!replacement.is_cancelled());

    let matched = disconnectnode(&ctx, &json!([address.as_str(), replacement_id]))
        .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
    assert!(matched.is_null());
    assert!(replacement.is_cancelled());
    assert!(ctx.network.peer_table.is_empty());
    Ok(())
}

#[test]
fn disconnectnode_accepts_a_named_nodeid_alone_and_keeps_address_precedence()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let addr: SocketAddr = "127.0.0.1:8360".parse()?;
    let lease = register_peer(&ctx, addr);
    let node_id = lease.node_id();
    let ctx = Arc::new(ctx);

    assert!(matches!(
        disconnectnode(&ctx, &json!(["not-an-address", node_id])),
        Err(RpcError::InvalidParams(_))
    ));
    assert!(!lease.is_cancelled());

    let named = disconnectnode(&ctx, &json!({ "nodeid": node_id }))
        .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
    assert!(named.is_null());
    assert!(lease.is_cancelled());
    assert!(ctx.network.peer_table.is_empty());
    Ok(())
}

#[test]
fn disconnectnode_address_only_still_selects_by_address() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Context::new();
    let addr: SocketAddr = "127.0.0.1:8340".parse()?;
    let lease = register_peer(&ctx, addr);
    let ctx = Arc::new(ctx);

    let result = disconnectnode(&ctx, &json!([addr.to_string().as_str()]))
        .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
    assert!(result.is_null());
    assert!(lease.is_cancelled());
    assert!(ctx.network.peer_table.is_empty());
    assert!(matches!(
        disconnectnode(&ctx, &json!(["not-an-address"])),
        Err(RpcError::InvalidParams(_))
    ));
    Ok(())
}

#[test]
fn disconnectnode_address_only_ignores_a_session_still_handshaking()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let addr: SocketAddr = "127.0.0.1:8370".parse()?;
    let pending = register_pending_peer(&ctx, addr);
    let ctx = Arc::new(ctx);
    let address = addr.to_string();

    let refused = disconnectnode(&ctx, &json!([address.as_str()]));
    assert!(
        matches!(refused, Err(RpcError::NotFound(_))),
        "a handshaking session is not a connected node: {refused:?}"
    );
    assert!(!pending.is_cancelled());
    assert_eq!(ctx.network.peer_table.len(), 1);

    assert!(ctx.network.peer_table.publish_info(
        bitcoin_rs_p2p::PeerEndpoint::Ip(addr),
        &pending,
        peer_info_at(addr)
    ));
    let accepted = disconnectnode(&ctx, &json!([address.as_str()]))
        .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
    assert!(accepted.is_null());
    assert!(pending.is_cancelled());
    assert!(ctx.network.peer_table.is_empty());
    Ok(())
}

#[test]
fn disconnectnode_identity_forms_ignore_a_session_still_handshaking()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Context::new();
    let addr: SocketAddr = "127.0.0.1:8371".parse()?;
    let pending = register_pending_peer(&ctx, addr);
    let node_id = pending.node_id();
    let ctx = Arc::new(ctx);
    let address = addr.to_string();

    for params in [
        json!(["", node_id]),
        json!([address.as_str(), node_id]),
        json!({ "nodeid": node_id }),
    ] {
        let refused = disconnectnode(&ctx, &params);
        assert!(
            matches!(refused, Err(RpcError::NotFound(_))),
            "{params:?}: {refused:?}"
        );
        assert!(!pending.is_cancelled());
    }
    assert_eq!(ctx.network.peer_table.len(), 1);
    Ok(())
}
