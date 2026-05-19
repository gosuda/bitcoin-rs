/// BIP339 wtxid-relay negotiation state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WtxidRelayState {
    local_advertised: bool,
    peer_advertised: bool,
}

impl WtxidRelayState {
    /// Mark that the local peer sent `wtxidrelay`.
    pub fn mark_local_advertised(&mut self) {
        self.local_advertised = true;
    }

    /// Mark that the remote peer sent `wtxidrelay`.
    pub fn mark_peer_supported(&mut self) {
        self.peer_advertised = true;
    }

    /// Return true once both peers advertised BIP339 support.
    pub const fn is_enabled(self) -> bool {
        self.local_advertised && self.peer_advertised
    }

    /// Return true if the remote peer advertised BIP339 support.
    pub const fn peer_supported(self) -> bool {
        self.peer_advertised
    }
}
