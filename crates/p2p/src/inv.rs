use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_mempool::PeerToken;
use bitcoin_rs_primitives::{Hash256, Txid};

use crate::wire::Message;

/// Maximum inventory vectors accepted in one message.
pub const MAX_INV_PER_MSG: usize = 50_000;

/// Inventory item advertised by a peer.
pub type InventoryVector = Inventory;

/// Requests the missing parents identified by admission from their delivering
/// connection. A stale source never sends to a same-address replacement.
///
/// Parent inputs identify transactions by txid, so these requests use `MSG_TX`
/// even for a wtxid-relay peer, as permitted by BIP339 for unannounced parents.
/// Repeated parents produce one inventory item. Returns whether a non-empty
/// request was queued; outbound saturation keeps the lease's disconnect policy.
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
    let mut seen = hashbrown::HashSet::new();
    let items: Vec<Inventory> = parents
        .iter()
        .filter(|txid| seen.insert(**txid))
        .map(|txid| Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())))
        .collect();
    if items.is_empty() {
        return false;
    }
    // The snapshot only adapts the opaque admission token. PeerTable owns the
    // live-identity check and pins it through the nonblocking enqueue. Bytes
    // already in flight may still finish on a retiring socket.
    if peers.send(connection, Message::GetData(items)).is_err() {
        tracing::debug!(peer_addr = %source.addr, "orphan parent getdata not sent");
        false
    } else {
        true
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
