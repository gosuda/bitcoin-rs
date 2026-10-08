/// BIP339 wtxid-relay negotiation state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WtxidRelayState {
    peer_advertised: bool,
}

impl WtxidRelayState {
    /// Mark that the remote peer sent `wtxidrelay`.
    pub(crate) const fn mark_peer_supported(&mut self) {
        self.peer_advertised = true;
    }

    /// Return true if the remote peer advertised BIP339 support.
    pub const fn peer_supported(self) -> bool {
        self.peer_advertised
    }
}
