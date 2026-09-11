use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use parking_lot::Mutex;

/// Warning kinds the node can raise, mirroring Core's kernel and node warning
/// ids.
///
/// Declaration order is the report order: Core keys its registry by
/// `std::variant<kernel::Warning, node::Warning>`, so kernel-issued warnings
/// sort before node-issued ones.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WarningKind {
    /// A versionbit unknown to this node activated on the network.
    UnknownNewRulesActivated,
    /// An invalid chain with substantially more work than the best chain was
    /// found.
    LargeWorkInvalidChain,
    /// The system clock is far out of sync with peer clocks.
    ClockOutOfSync,
    /// An internal error put the node in a state it cannot recover from.
    FatalInternalError,
}

/// Node warning registry, mirroring Core's `node::Warnings`.
///
/// At most one message per [`WarningKind`]: setting an already-active kind
/// keeps the original message, and [`Warnings::messages`] reports in kind
/// order. The registry is node-owned state; RPC projections read it live at
/// call time instead of copying warnings into transport-owned storage.
pub struct Warnings {
    active: Mutex<BTreeMap<WarningKind, String>>,
}

impl Default for Warnings {
    fn default() -> Self {
        Self::new()
    }
}

impl Warnings {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            active: Mutex::new(BTreeMap::new()),
        }
    }

    /// Activates the warning for `kind` with `message`.
    ///
    /// Returns `true` when the warning was newly set. An already-active kind
    /// keeps its original message and returns `false`, matching Core's
    /// `Warnings::Set`.
    pub fn set(&self, kind: WarningKind, message: impl Into<String>) -> bool {
        let mut active = self.active.lock();
        if active.contains_key(&kind) {
            return false;
        }
        active.insert(kind, message.into());
        true
    }

    /// Deactivates the warning for `kind`, returning whether one was active.
    pub fn unset(&self, kind: WarningKind) -> bool {
        self.active.lock().remove(&kind).is_some()
    }

    /// Returns the active warning messages ordered by kind.
    #[must_use]
    pub fn messages(&self) -> Vec<String> {
        self.active.lock().values().cloned().collect()
    }
}

static NODE_WARNINGS: Warnings = Warnings::new();

/// Returns the process-wide node warning registry.
///
/// This is the authoritative warnings fact source: the `getblockchaininfo`,
/// `getnetworkinfo`, and `getmininginfo` projections read it at invocation,
/// the way Core reads `NodeContext::warnings` through `GetWarningsForRpc`.
#[must_use]
pub fn node_warnings() -> &'static Warnings {
    &NODE_WARNINGS
}
