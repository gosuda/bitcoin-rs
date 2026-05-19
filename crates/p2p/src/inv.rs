use bitcoin::p2p::message_blockdata::Inventory;

use crate::wire::Message;

/// Maximum inventory vectors accepted in one message.
pub const MAX_INV_PER_MSG: usize = 50_000;

/// Inventory item advertised by a peer.
pub type InventoryVector = Inventory;

/// Classify an inbound inventory announcement into a getdata request.
pub fn request_inventory(items: &[InventoryVector]) -> Option<Message> {
    if items.is_empty() {
        None
    } else {
        Some(Message::GetData(items.to_vec()))
    }
}

/// Return true when the inventory list is within the protocol bound.
pub const fn is_within_inventory_bound(items: &[InventoryVector]) -> bool {
    items.len() <= MAX_INV_PER_MSG
}
