use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_mempool::PeerToken;
use bitcoin_rs_primitives::{BlockHash, Hash256, Txid};

#[cfg(test)]
use crate::wire::Message;

pub(crate) fn native_block_hash(hash: bitcoin::BlockHash) -> BlockHash {
    use bitcoin::hashes::Hash as _;
    BlockHash::from(Hash256::from_le_bytes(hash.as_byte_array()))
}

pub(crate) fn wire_block_hash(hash: BlockHash) -> bitcoin::BlockHash {
    use bitcoin::hashes::Hash as _;
    bitcoin::BlockHash::from_byte_array(*hash.as_bytes())
}

pub const MAX_INV_PER_MSG: usize = 50_000;

pub fn request_missing_parents(
    peers: &crate::PeerTable,
    source: PeerToken,
    parents: &[Txid],
) -> bool {
    use bitcoin::hashes::Hash as _;

    let Some(session) = peers.sessions().into_iter().find(|session| {
        session.endpoint == source.endpoint
            && session.lease.connection_id().get() == source.connection_id
    }) else {
        return false;
    };
    let lease = session.lease;
    let connection = lease.source(session.endpoint);
    if PeerToken::from(connection) != source {
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
    request_witness(&mut items, witness);
    let retained = peers.request_parent_transactions(connection, &items);
    retained && !lease.is_cancelled()
}

pub fn request_package_info(
    peers: &crate::PeerTable,
    source: PeerToken,
    subject: bitcoin_rs_primitives::Wtxid,
    parents: &[Txid],
) -> bool {
    peers.request_package_info_from_token(source, subject, parents)
}

/// Applies BIP144's witness request flag to transaction vectors without
pub(crate) fn request_witness(items: &mut [Inventory], witness: bool) {
    if !witness {
        return;
    }
    for item in items {
        if let Inventory::Transaction(txid) = *item {
            *item = Inventory::WitnessTransaction(txid);
        }
    }
}

pub(crate) fn inventory_block_hash(item: &Inventory) -> Option<Hash256> {
    use bitcoin::hashes::Hash as _;
    match item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
            Some(Hash256::from_le_bytes(hash.as_byte_array()))
        }
        _ => None,
    }
}

/// `WTx` (BIP339) it is the wtxid. The caller interprets the hash according
pub(crate) fn inventory_tx_hash(item: &Inventory) -> Option<Hash256> {
    use bitcoin::hashes::Hash as _;
    match item {
        Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
            Some(Hash256::from_le_bytes(txid.as_byte_array()))
        }
        Inventory::WTx(wtxid) => Some(Hash256::from_le_bytes(wtxid.as_byte_array())),
        _ => None,
    }
}

pub(crate) const fn is_within_inventory_bound(items: &[Inventory]) -> bool {
    items.len() <= MAX_INV_PER_MSG
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bitcoin::hashes::Hash as _;

    use super::*;
    use crate::{PeerLease, PeerTable};

    fn parent(byte: u8) -> Txid {
        Txid::from(Hash256::from_le_bytes(&[byte; 32]))
    }

    fn source(lease: &PeerLease) -> PeerToken {
        lease
            .source_ip(SocketAddr::from(([127, 0, 0, 1], 8333)))
            .into()
    }

    #[test]
    fn missing_parents_use_txids_and_deduplicate_repeated_inputs() {
        let table = PeerTable::new();
        let (sender, receiver) = crate::test_support::message_channel_bounded(2);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        table.register(
            source.addr.unwrap_or_else(|| panic!("known destination")),
            lease.clone(),
        );

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
                let (sender, receiver) = crate::test_support::message_channel_bounded(1);
                let lease = PeerLease::new(sender);
                let source = source(&lease);
                table.register(
                    source.addr.unwrap_or_else(|| panic!("known destination")),
                    lease.clone(),
                );
                let mut version = crate::handshake::version_message(
                    1,
                    0,
                    crate::peer_info::PeerRole::FullRelay,
                    bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
                );
                version.services = if witness {
                    ServiceFlags::NETWORK | ServiceFlags::WITNESS
                } else {
                    ServiceFlags::NETWORK
                };
                let mut info = crate::PeerInfo::inbound_from_version(
                    source.addr.unwrap_or_else(|| panic!("known destination")),
                    source
                        .addr
                        .unwrap_or_else(|| panic!("known destination"))
                        .socket_addr()
                        .unwrap_or_else(|| panic!("expected IP fixture")),
                    &version,
                    0,
                    0,
                    Arc::new(crate::PeerCounters::default()),
                );
                info.wtxid_relay = wtxid_relay;
                assert!(table.publish_info(
                    source.addr.unwrap_or_else(|| panic!("known destination")),
                    &lease,
                    info
                ));

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
    fn witness_flag_upgrades_transactions_only() {
        let txid = bitcoin::Txid::from_byte_array(*parent(1).as_bytes());
        let hash = bitcoin::BlockHash::from_byte_array([2; 32]);
        let mut items = vec![
            Inventory::Transaction(txid),
            Inventory::Block(hash),
            Inventory::CompactBlock(hash),
            Inventory::WitnessBlock(hash),
            Inventory::WitnessTransaction(txid),
            Inventory::Unknown {
                inv_type: 7,
                hash: [3; 32],
            },
        ];
        let unchanged = items.clone();
        request_witness(&mut items, false);
        assert_eq!(items, unchanged);

        request_witness(&mut items, true);
        let mut expected = unchanged;
        expected[0] = Inventory::WitnessTransaction(txid);
        assert_eq!(items, expected);
    }

    #[test]
    fn stale_missing_parent_source_cannot_send_to_or_cancel_replacement() {
        let table = PeerTable::new();
        let (old_sender, old_receiver) = crate::test_support::message_channel_bounded(1);
        let old = PeerLease::new(old_sender);
        let stale_source = source(&old);
        table.register(
            stale_source
                .addr
                .unwrap_or_else(|| panic!("known destination")),
            old,
        );
        let (new_sender, new_receiver) = crate::test_support::message_channel_bounded(1);
        let current = PeerLease::new(new_sender);
        table.register(
            stale_source
                .addr
                .unwrap_or_else(|| panic!("known destination")),
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
            &[parent(1)]
        ));
        assert!(matches!(new_receiver.try_recv(), Ok(Message::GetData(_))));
    }

    #[test]
    fn missing_parent_request_keeps_outbound_saturation_policy() {
        let table = PeerTable::new();
        let (sender, _receiver) = crate::test_support::message_channel_bounded(1);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        table.register(
            source.addr.unwrap_or_else(|| panic!("known destination")),
            lease.clone(),
        );
        assert!(lease.send(Message::Ping(1)).is_ok());

        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        assert!(lease.is_cancelled());
    }

    #[test]
    fn cancelled_missing_parent_source_does_not_enqueue_a_request() {
        let table = PeerTable::new();
        let (sender, receiver) = crate::test_support::message_channel_bounded(1);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        table.register(
            source.addr.unwrap_or_else(|| panic!("known destination")),
            lease.clone(),
        );
        lease.cancel();

        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn missing_parents_serve_unidentified_inbound_through_own_lease() {
        let table = PeerTable::new();
        let (sender, receiver) = crate::test_support::message_channel_bounded(2);
        let lease = PeerLease::new_inbound(sender);
        let source: PeerToken = lease.source(None).into();
        assert!(source.addr.is_none());
        table.register_unidentified(lease.clone());
        let (other_sender, other_receiver) = crate::test_support::message_channel_bounded(2);
        let other = PeerLease::new_inbound(other_sender);
        let other_source: PeerToken = other.source(None).into();
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
        let (sender, receiver) = crate::test_support::message_channel_bounded(2);
        let lease = PeerLease::new(sender);
        table.register_unidentified(lease.clone());
        let source = PeerToken::from(lease.source(None));
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
}
