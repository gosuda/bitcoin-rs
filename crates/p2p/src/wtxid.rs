/// BIP339 wtxid-relay negotiation state.
///
/// The production contract needs only the remote peer's advertised support:
/// the local node always advertises BIP339 in its feature messages
/// ([`crate::handshake::feature_messages`]), so local advertisement carries
/// no state worth tracking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WtxidRelayState {
    peer_advertised: bool,
}

impl WtxidRelayState {
    /// Mark that the remote peer sent `wtxidrelay`.
    pub const fn mark_peer_supported(&mut self) {
        self.peer_advertised = true;
    }

    /// Return true if the remote peer advertised BIP339 support.
    pub const fn peer_supported(self) -> bool {
        self.peer_advertised
    }
}
