//! Derived-index reconciliation state and capability alignment.
//!
//! These policies operate on supplied index state. The caller remains
//! responsible for capturing and validating the authoritative chain view;
//! agreement between watermarks alone does not prove query readiness.

use crate::{IndexCapabilities, IndexWatermark, IndexWatermarks};

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
///
/// Capabilities carry independent watermarks, so a selective reset can leave
/// one capability rebuilding while its sibling still rewinds. The worker
/// publishes each leg change so operators can tell a rewind or rebuild apart
/// from ordinary forward catch-up, whose progress is the durable watermark
/// itself.
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
///
/// Unselected capabilities do not affect the result. Equality includes both
/// height and hash; mixed initialized/uninitialized selections are invalid.
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
