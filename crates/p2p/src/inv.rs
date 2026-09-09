use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_mempool::PeerToken;
use bitcoin_rs_primitives::{Hash256, Txid};

use crate::wire::Message;

/// Maximum inventory vectors accepted in one message.
pub const MAX_INV_PER_MSG: usize = 50_000;

/// Inventory item advertised by a peer.
pub type InventoryVector = Inventory;

/// Requests missing parents from the connection that supplied the child.
///
/// Inventory identity, witness serialization, deduplication, and saturation
/// behavior follow `docs/policies/p2p-compatibility.md` §5; this function
/// adapts admission's parent txids to the authoritative peer-table enqueue.
pub fn request_missing_parents(
    peers: &crate::PeerTable,
    source: PeerToken,
    parents: &[Txid],
) -> bool {
    use bitcoin::hashes::Hash as _;

    let Some(lease) = peers.lease(source.addr) else {
        return false;
    };
    let connection = lease.source(source.addr);
    if PeerToken::from(connection) != source {
        return false;
    }
    let mut witness = false;
    peers.for_each_ready_lease(|addr, current, info| {
        if addr == source.addr && current.same_connection(&lease) {
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
    request_transaction_witness(&mut items, witness);
    // Capability metadata belongs to the same connection as the token. The
    // table rechecks that identity and pins it through the nonblocking enqueue,
    // so a replacement cannot inherit either the request or its service choice.
    // Bytes already in flight may still finish on a retiring socket.
    if peers.send(connection, Message::GetData(items)).is_err() {
        tracing::debug!(peer_addr = %source.addr, "orphan parent getdata not sent");
        false
    } else {
        true
    }
}

/// Selects BIP144 witness serialization for txid-based getdata requests.
/// This does not change identifiers or outbound inv announcement types.
pub(crate) fn request_transaction_witness(items: &mut [Inventory], witness: bool) {
    if witness {
        for item in items {
            if let Inventory::Transaction(txid) = *item {
                *item = Inventory::WitnessTransaction(txid);
            }
        }
    }
}

/// Classify an inbound inventory announcement into a getdata request.
///
/// Every announced item is requested. Use [`request_inventory_filtered`] to
/// suppress items the node already holds (mempool, orphan, or recent-rejects).
pub fn request_inventory(items: &[InventoryVector]) -> Option<Message> {
    request_inventory_filtered(items, &|_| false)
}

/// Classify an inbound inventory announcement into a getdata request,
/// suppressing every item for which `have` returns `true`.
///
/// `have` is the node-side "already have" predicate: it receives each
/// inventory vector and returns `true` when the node already holds the
/// referenced object, so the caller skips requesting it. Non-transaction
/// items (blocks, compact blocks, unknown) are never suppressed by the
/// tx-admission layer — the predicate is only consulted for tx-typed
/// vectors — so block relay behaviour is unchanged.
pub fn request_inventory_filtered(
    items: &[InventoryVector],
    have: &dyn Fn(&InventoryVector) -> bool,
) -> Option<Message> {
    let filtered: Vec<InventoryVector> = items.iter().copied().filter(|item| !have(item)).collect();
    if filtered.is_empty() {
        None
    } else {
        Some(Message::GetData(filtered))
    }
}

/// Returns the 32-byte hash carried by a transaction-typed inventory vector,
/// or `None` for non-transaction vectors.
///
/// For `Transaction` and `WitnessTransaction` the hash is the txid; for
/// `WTx` (BIP339) it is the wtxid. The caller interprets the hash according
/// to this inventory type, independently of either relay direction's preference.
pub fn inventory_tx_hash(item: &InventoryVector) -> Option<Hash256> {
    use bitcoin::hashes::Hash as _;
    match item {
        Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
            Some(Hash256::from_le_bytes(txid.as_byte_array()))
        }
        Inventory::WTx(wtxid) => Some(Hash256::from_le_bytes(wtxid.as_byte_array())),
        _ => None,
    }
}

/// Return true when the inventory list is within the protocol bound.
pub const fn is_within_inventory_bound(items: &[InventoryVector]) -> bool {
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
            .source(SocketAddr::from(([127, 0, 0, 1], 8333)))
            .into()
    }

    // P2P-01 / BIP339: unannounced parents may be requested by txid.
    #[test]
    fn missing_parents_use_txids_and_deduplicate_repeated_inputs() {
        let table = PeerTable::new();
        let (sender, receiver) = crossbeam_channel::bounded(2);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        table.register(source.addr, lease.clone());

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

    /// P2P-01 / BIP144: request witness serialization by txid from `NODE_WITNESS`
    /// sources. BIP339 announcement preference does not alter this requirement.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki#relay>
    #[test]
    fn missing_parents_request_witness_by_service_not_announcement_preference() {
        use bitcoin::p2p::ServiceFlags;
        use std::sync::Arc;

        for witness in [false, true] {
            for wtxid_relay in [false, true] {
                let table = PeerTable::new();
                let (sender, receiver) = crossbeam_channel::bounded(1);
                let lease = PeerLease::new(sender);
                let source = source(&lease);
                table.register(source.addr, lease.clone());
                let mut version = crate::handshake::version_message(1, 0);
                version.services = if witness {
                    ServiceFlags::NETWORK | ServiceFlags::WITNESS
                } else {
                    ServiceFlags::NETWORK
                };
                let mut info = crate::PeerInfo::inbound_from_version(
                    source.addr,
                    source.addr,
                    &version,
                    0,
                    0,
                    Arc::new(crate::PeerCounters::default()),
                );
                info.wtxid_relay = wtxid_relay;
                assert!(table.publish_info(source.addr, &lease, info));

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

    // P2P-02: a stale source cannot target or cancel its successor.
    #[test]
    fn stale_missing_parent_source_cannot_send_to_or_cancel_replacement() {
        let table = PeerTable::new();
        let (old_sender, old_receiver) = crossbeam_channel::bounded(1);
        let old = PeerLease::new(old_sender);
        let stale_source = source(&old);
        table.register(stale_source.addr, old);
        let (new_sender, new_receiver) = crossbeam_channel::bounded(1);
        let current = PeerLease::new(new_sender);
        table.register(stale_source.addr, current.clone());

        // Fill the replacement's queue: an incorrect address-only send would
        // both target the wrong connection and cancel it on saturation.
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

    // P2P-02: only the saturated delivering connection is cancelled.
    #[test]
    fn missing_parent_request_keeps_outbound_saturation_policy() {
        let table = PeerTable::new();
        let (sender, _receiver) = crossbeam_channel::bounded(1);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        table.register(source.addr, lease.clone());
        assert!(lease.send(Message::Ping(1)).is_ok());

        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        assert!(lease.is_cancelled());
    }

    // P2P-02: cancellation prevents subsequent parent-request enqueue.
    #[test]
    fn cancelled_missing_parent_source_does_not_enqueue_a_request() {
        let table = PeerTable::new();
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        table.register(source.addr, lease.clone());
        lease.cancel();

        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        assert!(receiver.try_recv().is_err());
    }
}
