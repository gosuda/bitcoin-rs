use std::net::SocketAddr;

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_consensus::primitives::{Hash256, Txid};
use bitcoin_rs_mempool::PeerToken;
use bitcoin_rs_wire::connection::PeerLease;
use bitcoin_rs_wire::peer_table::PeerTable;
use bitcoin_rs_wire::wire::Message;

fn parent(byte: u8) -> Txid {
    Txid::from(Hash256::from_le_bytes(&[byte; 32]))
}

fn source(lease: &PeerLease) -> PeerToken {
    crate::p2p::peer_token(lease.source_ip(SocketAddr::from(([127, 0, 0, 1], 8333))))
}

fn request_missing_parents(peers: &PeerTable, source: PeerToken, parents: &[Txid]) -> bool {
    let Some(session) = peers.sessions().into_iter().find(|session| {
        session.endpoint == source.endpoint
            && session.lease.connection_id().get() == source.connection_id
    }) else {
        return false;
    };
    let lease = session.lease;
    let connection = lease.source(session.endpoint);
    if crate::p2p::peer_token(connection) != source {
        return false;
    }
    let mut witness = false;
    peers.for_each_ready_lease(|addr, current, info| {
        if addr == source.endpoint && current.same_connection(&lease) {
            witness = info.services & bitcoin::p2p::ServiceFlags::WITNESS.to_u64() != 0;
        }
    });
    let mut seen = hashbrown::HashSet::new();
    let mut items: Vec<Inventory> = parents
        .iter()
        .filter(|txid| seen.insert(**txid))
        .map(|txid| Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())))
        .collect();
    if items.is_empty() {
        return false;
    }
    if witness {
        bitcoin_rs_wire::inv::request_witness(&mut items);
    }
    peers.send(connection, Message::GetData(items)).is_ok() && !lease.is_cancelled()
}

#[test]
fn missing_parents_use_txids_and_deduplicate_repeated_inputs() {
    let table = PeerTable::new();
    let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(2);
    let lease = PeerLease::new(sender);
    let source = source(&lease);
    table.register(source.addr.expect("known destination"), lease.clone());

    assert!(request_missing_parents(
        &table,
        source,
        &[parent(1), parent(2), parent(1)],
    ));
    let expected = Message::GetData(vec![
        Inventory::Transaction(bitcoin::Txid::from_byte_array(*parent(1).as_bytes())),
        Inventory::Transaction(bitcoin::Txid::from_byte_array(*parent(2).as_bytes())),
    ]);
    assert!(matches!(receiver.try_recv(), Ok(message) if message == expected));
    assert!(!request_missing_parents(&table, source, &[]));
    assert!(receiver.try_recv().is_err());
    assert!(!lease.is_cancelled());
}

#[test]
fn missing_parents_request_witness_by_service_not_announcement_preference() {
    use bitcoin::p2p::ServiceFlags;
    use std::sync::Arc;

    for witness in [false, true] {
        for wtxid_relay in [false, true] {
            let table = PeerTable::new();
            let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
            let lease = PeerLease::new(sender);
            let source = source(&lease);
            table.register(source.addr.expect("known destination"), lease.clone());
            let mut version = bitcoin_rs_wire::handshake::version_message(
                1,
                0,
                bitcoin_rs_wire::peer_info::PeerRole::FullRelay,
                bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
                bitcoin_rs_consensus::primitives::USER_AGENT,
            );
            version.services = if witness {
                ServiceFlags::NETWORK | ServiceFlags::WITNESS
            } else {
                ServiceFlags::NETWORK
            };
            let mut info = bitcoin_rs_wire::PeerInfo::inbound_from_version(
                source.addr.expect("known destination"),
                source
                    .addr
                    .expect("known destination")
                    .socket_addr()
                    .expect("expected IP fixture"),
                &version,
                0,
                0,
                Arc::new(bitcoin_rs_wire::PeerCounters::default()),
            );
            info.wtxid_relay = wtxid_relay;
            assert!(table.publish_info(source.addr.expect("known destination"), &lease, info,));

            assert!(request_missing_parents(
                &table,
                source,
                &[parent(1), parent(1)],
            ));
            let txid = bitcoin::Txid::from_byte_array(*parent(1).as_bytes());
            let expected = if witness {
                Inventory::WitnessTransaction(txid)
            } else {
                Inventory::Transaction(txid)
            };
            assert!(matches!(
                receiver.try_recv(),
                Ok(Message::GetData(items)) if items == vec![expected]
            ));
            assert!(receiver.try_recv().is_err());
            assert!(!lease.is_cancelled());
        }
    }
}

#[test]
fn stale_missing_parent_source_cannot_send_to_or_cancel_replacement() {
    let table = PeerTable::new();
    let (old_sender, old_receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
    let old = PeerLease::new(old_sender);
    let stale_source = source(&old);
    table.register(stale_source.addr.expect("known destination"), old);
    let (new_sender, new_receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
    let current = PeerLease::new(new_sender);
    table.register(
        stale_source.addr.expect("known destination"),
        current.clone(),
    );

    assert!(current.send(Message::Ping(7)).is_ok());
    assert!(!request_missing_parents(&table, stale_source, &[parent(1)]));
    assert!(old_receiver.try_recv().is_err());
    assert!(!current.is_cancelled());
    assert!(matches!(new_receiver.try_recv(), Ok(Message::Ping(7))));
    assert!(new_receiver.try_recv().is_err());
    assert!(request_missing_parents(
        &table,
        source(&current),
        &[parent(1)],
    ));
    assert!(matches!(new_receiver.try_recv(), Ok(Message::GetData(_))));
}

#[test]
fn missing_parent_request_keeps_outbound_saturation_policy() {
    let table = PeerTable::new();
    let (sender, _receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
    let lease = PeerLease::new(sender);
    let source = source(&lease);
    assert!(!request_missing_parents(&table, source, &[parent(1)]));
    table.register(source.addr.expect("known destination"), lease.clone());
    assert!(lease.send(Message::Ping(1)).is_ok());

    assert!(!request_missing_parents(&table, source, &[parent(1)]));
    assert!(lease.is_cancelled());
}

#[test]
fn cancelled_missing_parent_source_does_not_enqueue_a_request() {
    let table = PeerTable::new();
    let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
    let lease = PeerLease::new(sender);
    let source = source(&lease);
    table.register(source.addr.expect("known destination"), lease.clone());
    lease.cancel();

    assert!(!request_missing_parents(&table, source, &[parent(1)]));
    assert!(receiver.try_recv().is_err());
}

#[test]
fn missing_parents_serve_unidentified_inbound_through_own_lease() {
    let table = PeerTable::new();
    let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(2);
    let lease = PeerLease::new_inbound(sender);
    let source = crate::p2p::peer_token(lease.source(None));
    assert!(source.addr.is_none());
    table.register_unidentified(lease.clone());
    let (other_sender, other_receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(2);
    let other = PeerLease::new_inbound(other_sender);
    let other_source = crate::p2p::peer_token(other.source(None));
    assert!(other_source.addr.is_none());
    assert_ne!(other_source.connection_id, source.connection_id);
    table.register_unidentified(other.clone());

    assert!(request_missing_parents(
        &table,
        source,
        &[parent(1), parent(1)],
    ));
    let expected = Message::GetData(vec![Inventory::Transaction(
        bitcoin::Txid::from_byte_array(*parent(1).as_bytes()),
    )]);
    assert!(matches!(receiver.try_recv(), Ok(message) if message == expected));
    assert!(other_receiver.try_recv().is_err());
    assert!(!request_missing_parents(&table, source, &[]));
    assert!(receiver.try_recv().is_err());
    assert!(other_receiver.try_recv().is_err());
    assert!(!lease.is_cancelled());
    assert!(!other.is_cancelled());
}

#[test]
fn missing_parents_resolve_unidentified_sessions() {
    let table = PeerTable::new();
    let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(2);
    let lease = PeerLease::new(sender);
    table.register_unidentified(lease.clone());
    let source = crate::p2p::peer_token(lease.source(None));
    assert!(source.endpoint.is_none());

    assert!(request_missing_parents(&table, source, &[parent(1)]));
    let expected = Message::GetData(vec![Inventory::Transaction(
        bitcoin::Txid::from_byte_array(*parent(1).as_bytes()),
    )]);
    assert!(matches!(receiver.try_recv(), Ok(message) if message == expected));
    assert!(!lease.is_cancelled());

    let stale = PeerToken {
        endpoint: None,
        addr: None,
        connection_id: source.connection_id.wrapping_add(1),
    };
    assert!(!request_missing_parents(&table, stale, &[parent(1)]));
    assert!(receiver.try_recv().is_err());
}
