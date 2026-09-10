//! Authoritative, first-message-wins node warning state.

use std::collections::{BTreeMap, btree_map::Entry};

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
        match self.active.lock().entry(kind) {
            Entry::Vacant(entry) => {
                entry.insert(message.into());
                true
            }
            Entry::Occupied(_) => false,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warnings_keep_first_message_and_report_in_kind_order() {
        let warnings = Warnings::new();
        assert!(warnings.messages().is_empty());

        assert!(warnings.set(WarningKind::ClockOutOfSync, "clock out of sync"));
        // Core ignores a later message for an already-active kind.
        assert!(!warnings.set(WarningKind::ClockOutOfSync, "superseded message"));
        assert!(warnings.set(WarningKind::FatalInternalError, "fatal"));
        assert!(warnings.set(WarningKind::UnknownNewRulesActivated, "unknown rules"));

        assert_eq!(
            warnings.messages(),
            [
                "unknown rules".to_owned(),
                "clock out of sync".to_owned(),
                "fatal".to_owned(),
            ],
            "kernel warnings must sort before node warnings regardless of set order"
        );

        assert!(warnings.unset(WarningKind::ClockOutOfSync));
        assert!(!warnings.unset(WarningKind::ClockOutOfSync));
        assert_eq!(
            warnings.messages(),
            ["unknown rules".to_owned(), "fatal".to_owned()]
        );
    }

    struct UnexpectedMessage;

    impl From<UnexpectedMessage> for String {
        fn from(_: UnexpectedMessage) -> Self {
            panic!("an already-active warning must not convert the replacement message")
        }
    }

    // CONTRACT: docs/contracts/external-api.md#API-08
    #[test]
    // CONTRACT: docs/contracts/external-api.md#API-06
fn an_active_warning_does_not_convert_a_replacement_message() {
        let warnings = Warnings::new();
        assert!(warnings.set(WarningKind::ClockOutOfSync, "first"));
        assert!(!warnings.set(WarningKind::ClockOutOfSync, UnexpectedMessage));
        assert_eq!(warnings.messages(), ["first".to_owned()]);
    }
}
