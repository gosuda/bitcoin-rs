pub use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};

/// BIP152 compact-block relay preference for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactBlockRelay {
    /// Whether high-bandwidth compact block announcements are requested.
    pub high_bandwidth: bool,
    /// Negotiated compact-block protocol version.
    pub version: u64,
}

impl Default for CompactBlockRelay {
    fn default() -> Self {
        Self {
            high_bandwidth: false,
            version: 1,
        }
    }
}

impl CompactBlockRelay {
    /// Build the corresponding `sendcmpct` message.
    pub const fn sendcmpct(self) -> SendCmpct {
        SendCmpct {
            send_compact: self.high_bandwidth,
            version: self.version,
        }
    }

    /// Apply a remote `sendcmpct` preference.
    pub const fn from_sendcmpct(message: SendCmpct) -> Self {
        Self {
            high_bandwidth: message.send_compact,
            version: message.version,
        }
    }
}
