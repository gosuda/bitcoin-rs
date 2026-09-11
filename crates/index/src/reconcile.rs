//! Derived-index reconciliation state and policy over supplied authoritative chain facts.
//!
//! The index owner decides how durable derived state reaches consistency with a
//! supplied active chain. The caller owns the authoritative chain representation
//! and implements [`ActiveChainView`]; agreement between index watermarks alone
//! never proves query readiness.

use bitcoin_rs_primitives::Hash256;

use crate::{IndexCapabilities, IndexWatermark, IndexWatermarks};

/// Durable consumer-cursor length: epoch (8 LE) + sequence (8 LE) + height (4 LE) + hash.
pub const CURSOR_BYTE_LEN: usize = 52;

/// Applied-tip identity consumed by index reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTip {
    /// Applied tip block hash.
    pub hash: Hash256,
    /// Applied tip height.
    pub height: u32,
}

/// Coherent publisher identity supplied by the authoritative chain owner.
///
/// The index does not own or advance these fields. It compares them with its
/// durable cursor so dropped wakeups and process restarts converge through the
/// same positional reconciliation path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainIdentity {
    /// Process epoch of the supplied committed-chain snapshot.
    pub epoch: u64,
    /// Commit sequence in that epoch.
    pub sequence: u64,
    /// Applied tip block hash.
    pub tip_hash: Hash256,
    /// Applied tip height.
    pub tip_height: u32,
}

/// Minimal authoritative-chain topology needed by derived-index reconciliation.
///
/// Index owns the decision. Node/chainstate owns the concrete tree and answers
/// topology questions against one selected active tip. Process lifecycle,
/// storage, and wake delivery are intentionally absent from this interface.
pub trait ActiveChainView {
    /// Whether `position` is represented by the authoritative chain topology.
    fn contains(&self, position: Hash256) -> bool;

    /// Whether `position` at `height` lies on the selected active chain.
    fn position_on_active_chain(&self, position: Hash256, height: u32) -> bool;

    /// Height of the newest block shared by `position` and the selected active
    /// chain, or `None` when ancestry cannot be resolved.
    fn common_ancestor_height(&self, position: Hash256) -> Option<u32>;
}

/// Durable position of an index consumer relative to committed chain events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumerCursor {
    /// Process epoch the consumed events belong to.
    pub epoch: u64,
    /// Commit-counter value of the last consumed event.
    pub sequence: u64,
    /// Height of the mirrored tip.
    pub height: u32,
    /// Hash of the mirrored tip.
    pub hash: Hash256,
}

impl ConsumerCursor {
    /// Builds the cursor for a fully consumed chain identity.
    #[must_use]
    pub const fn from_identity(identity: &ChainIdentity) -> Self {
        Self {
            epoch: identity.epoch,
            sequence: identity.sequence,
            height: identity.tip_height,
            hash: identity.tip_hash,
        }
    }

    /// Encodes the durable representation in [`CURSOR_BYTE_LEN`] bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CURSOR_BYTE_LEN] {
        let mut bytes = [0_u8; CURSOR_BYTE_LEN];
        bytes[..8].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.height.to_le_bytes());
        bytes[20..].copy_from_slice(&self.hash.to_le_bytes());
        bytes
    }

    /// Decodes the durable representation; `None` on any length mismatch.
    ///
    /// Cursor corruption is advisory-state corruption only. Row correctness is
    /// anchored by capability watermarks, so consumers re-plan from row state.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CURSOR_BYTE_LEN {
            return None;
        }
        Some(Self {
            epoch: u64::from_le_bytes(bytes[..8].try_into().ok()?),
            sequence: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            height: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
            hash: Hash256::from_le_bytes(&bytes[20..].try_into().ok()?),
        })
    }
}

/// What a derived-index consumer must do to move its rows onto the active chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcilePlan {
    /// The cursor names the live tip exactly; nothing to do.
    CaughtUp,
    /// The cursor position is on the active chain; connect forward.
    Forward {
        /// First height the consumer still has to index.
        from_height: u32,
    },
    /// The cursor position is orphaned; disconnect to the common ancestor,
    /// then connect forward.
    RollbackAndForward {
        /// Last height shared by the cursor branch and the active chain.
        ancestor_height: u32,
    },
    /// The cursor block or its ancestry cannot be resolved; rebuild from the
    /// consumer's earliest anchor.
    Rebuild,
}

/// Plans one positional reconciliation pass for `cursor` against `target`.
#[must_use]
pub fn plan(
    cursor: &ConsumerCursor,
    target: ChainTip,
    chain: &impl ActiveChainView,
) -> ReconcilePlan {
    if !chain.contains(cursor.hash) {
        return ReconcilePlan::Rebuild;
    }
    if cursor.height == target.height && cursor.hash == target.hash {
        return ReconcilePlan::CaughtUp;
    }
    if chain.position_on_active_chain(cursor.hash, cursor.height) {
        return ReconcilePlan::Forward {
            from_height: cursor.height.saturating_add(1),
        };
    }
    match chain.common_ancestor_height(cursor.hash) {
        Some(ancestor_height) => ReconcilePlan::RollbackAndForward { ancestor_height },
        None => ReconcilePlan::Rebuild,
    }
}

/// Plans from a coherent publisher identity plus the independently supplied
/// authoritative tip.
///
/// Publisher identity is only a shortcut when it also names `target`; an old or
/// torn identity must not manufacture `CaughtUp` against a different tip.
#[must_use]
pub fn plan_from_identity(
    cursor: &ConsumerCursor,
    identity: &ChainIdentity,
    target: ChainTip,
    chain: &impl ActiveChainView,
) -> ReconcilePlan {
    let identity_matches_cursor = cursor.epoch == identity.epoch
        && cursor.sequence == identity.sequence
        && cursor.hash == identity.tip_hash
        && cursor.height == identity.tip_height;
    let identity_matches_target = identity.tip_hash == target.hash && identity.tip_height == target.height;
    if identity_matches_cursor && identity_matches_target {
        return ReconcilePlan::CaughtUp;
    }
    plan(cursor, target, chain)
}

/// Canonical stale-branch depth used to choose rollback versus rebuild.
#[must_use]
pub fn rollback_depth(
    chain: &impl ActiveChainView,
    position: Hash256,
    position_height: u32,
) -> Option<u32> {
    chain
        .common_ancestor_height(position)
        .map(|ancestor_height| position_height.saturating_sub(ancestor_height))
}

/// Reconciliation leg one capability's rows are executing against the
/// applied tip. Forward is the resting leg: a watermark that names the
/// applied tip is ready; one below it is catching up.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReconcileLeg {
    /// Rows extend the active chain from the durable watermark.
    #[default]
    Forward,
    /// Rows on an abandoned or ahead-of-tip branch are deleted block by
    /// block from `from_height` down to the common ancestor `to_height`.
    RollingBack {
        /// Height of the watermark being rewound.
        from_height: u32,
        /// Height of the last block shared with the active chain.
        to_height: u32,
    },
    /// The rows were reset and rebuild from genesis.
    Rebuilding,
}

/// Reconciliation legs of every capability the worker owns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcilePhase {
    /// Transaction-lookup leg.
    pub tx_lookup: ReconcileLeg,
    /// Script-history leg.
    pub script_history: ReconcileLeg,
    /// Compact live-output leg.
    pub script_live: ReconcileLeg,
}

impl ReconcilePhase {
    /// Every capability moving forward.
    pub const FORWARD: Self = Self {
        tx_lookup: ReconcileLeg::Forward,
        script_history: ReconcileLeg::Forward,
        script_live: ReconcileLeg::Forward,
    };

    /// Returns the phase with `leg` assigned to every capability in
    /// `capabilities`.
    #[must_use]
    pub const fn with_leg(mut self, capabilities: IndexCapabilities, leg: ReconcileLeg) -> Self {
        if capabilities.tx_lookup {
            self.tx_lookup = leg;
        }
        if capabilities.script_history {
            self.script_history = leg;
        }
        if capabilities.script_live {
            self.script_live = leg;
        }
        self
    }

    /// Capabilities whose rows are rebuilding from genesis.
    #[must_use]
    pub const fn rebuilding(self) -> IndexCapabilities {
        IndexCapabilities {
            tx_lookup: matches!(self.tx_lookup, ReconcileLeg::Rebuilding),
            script_history: matches!(self.script_history, ReconcileLeg::Rebuilding),
            script_live: matches!(self.script_live, ReconcileLeg::Rebuilding),
        }
    }

    /// Widest rollback in flight: the highest watermark being rewound and
    /// the lowest common ancestor any capability rewinds to.
    #[must_use]
    pub fn rolling_back(self) -> Option<(u32, u32)> {
        [self.tx_lookup, self.script_history, self.script_live]
            .into_iter()
            .filter_map(|leg| match leg {
                ReconcileLeg::RollingBack {
                    from_height,
                    to_height,
                } => Some((from_height, to_height)),
                ReconcileLeg::Forward | ReconcileLeg::Rebuilding => None,
            })
            .reduce(|(from_a, to_a), (from_b, to_b)| (from_a.max(from_b), to_a.min(to_b)))
    }

    /// Ends every rollback leg; rebuild legs persist until their rows reach
    /// the applied tip.
    #[must_use]
    pub fn rollbacks_finished(self) -> Self {
        let finish = |leg| match leg {
            ReconcileLeg::RollingBack { .. } => ReconcileLeg::Forward,
            other => other,
        };
        Self {
            tx_lookup: finish(self.tx_lookup),
            script_history: finish(self.script_history),
            script_live: finish(self.script_live),
        }
    }
}

/// Whether a nonempty capability set has one exact durable watermark.
///
/// `Valid(None)` is an aligned, unindexed selection, not an empty selection
/// and not proof that a query is ready.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SelectedWatermark {
    /// Every selected capability has the same optional height and block hash.
    Valid(Option<IndexWatermark>),
    /// No capability was selected, or selected capabilities disagree.
    Invalid,
}

/// Selects an exact common watermark without consulting or owning chainstate.
#[must_use]
pub fn selected_watermark(
    watermarks: IndexWatermarks,
    capabilities: IndexCapabilities,
) -> SelectedWatermark {
    let selected = [
        capabilities.tx_lookup.then_some(watermarks.tx_lookup),
        capabilities
            .script_history
            .then_some(watermarks.script_history),
        capabilities.script_live.then_some(watermarks.script_live),
    ];
    let mut selected = selected.into_iter().flatten();
    let Some(first) = selected.next() else {
        return SelectedWatermark::Invalid;
    };
    if selected.all(|watermark| watermark == first) {
        SelectedWatermark::Valid(first)
    } else {
        SelectedWatermark::Invalid
    }
}

#[cfg(test)]
mod tests;
