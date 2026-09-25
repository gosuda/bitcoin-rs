use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_primitives::Tx;
use hashbrown::HashSet;
use thiserror::Error;

use crate::mutation::RemovalReason;
use crate::pool::tx_fee_rate;
use crate::{EntryId, Mempool, MempoolEntry, MempoolError};

/// Candidate transaction and feerate policy used for replacement validation.
#[derive(Clone, Debug)]
pub struct ReplacementCandidate {
    /// Replacement transaction.
    pub tx: Arc<Tx>,
    /// Replacement virtual size in vbytes.
    pub vsize: u32,
    /// Replacement fee in satoshis.
    pub fee: u64,
    /// Incremental relay fee rate in sat/kvB.
    pub min_relay_fee_rate: u64,
    /// BIP141 sigop cost against the resolved prevouts.
    ///
    /// Carried through so a replacement lands with the same accounting a plain
    /// acceptance would give it. Zero when the candidate was built without
    /// resolved prevouts, which means unknown rather than none.
    pub sigop_cost: u32,
    /// Whether the committed entry registers with the fee estimator.
    ///
    /// Reorg re-admissions set this false: the transaction already spent its
    /// time in the pool before the disconnect, matching Core's
    /// `validForFeeEstimation=false` on reorg re-acceptance.
    pub fee_estimate: bool,
}

impl ReplacementCandidate {
    /// Builds a replacement candidate.
    #[must_use]
    pub const fn new(tx: Arc<Tx>, vsize: u32, fee: u64, min_relay_fee_rate: u64) -> Self {
        Self {
            tx,
            vsize,
            fee,
            min_relay_fee_rate,
            sigop_cost: 0,
            fee_estimate: true,
        }
    }

    /// Attaches a sigop cost counted against resolved prevouts.
    #[must_use]
    pub const fn with_sigop_cost(mut self, sigop_cost: u32) -> Self {
        self.sigop_cost = sigop_cost;
        self
    }

    /// Sets whether the committed entry registers with the fee estimator.
    #[must_use]
    pub const fn with_fee_estimate(mut self, fee_estimate: bool) -> Self {
        self.fee_estimate = fee_estimate;
        self
    }

    /// Candidate fee rate in sat/vB multiplied by 1000.
    #[must_use]
    pub fn fee_rate(&self) -> u64 {
        tx_fee_rate(self.fee, self.vsize)
    }
}

/// Successful replacement validation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementPlan {
    /// Conflicts and descendants removed by the replacement.
    pub evicted: Vec<EntryId>,
}

/// Typed replacement-policy rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RbfError {
    /// Replacement modified fees do not cover the victims' modified fees.
    #[error("insufficient fee")]
    Rule3InsufficientAbsoluteFee,
    /// Replacement does not pay the incremental relay charge.
    #[error("insufficient fee")]
    Rule4InsufficientIncrementalFee,
    /// Too many distinct directly conflicting clusters.
    #[error("too many potential replacements")]
    TooManyConflictingClusters,
    /// Absolute fees are insufficient after adding the eligible TRUC sibling.
    #[error("insufficient fee (including sibling eviction)")]
    SiblingAbsoluteFee,
    /// Incremental fees are insufficient after adding the eligible TRUC sibling.
    #[error("insufficient fee (including sibling eviction)")]
    SiblingIncrementalFee,
    /// Adding a TRUC sibling exceeds the direct-conflict cluster budget.
    #[error("too many potential replacements (including sibling eviction)")]
    TooManySiblingConflictingClusters,
    /// The complete projected fee curve does not strictly improve.
    #[error("replacement-failed")]
    InsufficientFeerateDiagram,
    /// Fee or weight arithmetic cannot represent the supplied facts.
    #[error("replacement arithmetic overflow")]
    ArithmeticOverflow,
    /// A policy size has no valid positive weight representation.
    #[error("invalid replacement weight")]
    InvalidWeight,
    /// The owner's graph projection violates its link invariants.
    #[error("mempool graph is inconsistent")]
    InconsistentGraph,
    /// Prepared work belongs to an earlier pool or fee-delta state.
    #[error("mempool changed during replacement preparation")]
    StalePlan,
    /// Version-3 ancestry or size violates BIP431.
    #[error(transparent)]
    Truc(#[from] crate::TrucError),
    /// Insertion constraints reject before mutation.
    #[error(transparent)]
    Mempool(#[from] MempoolError),
}

impl From<crate::PolicyError> for RbfError {
    fn from(error: crate::PolicyError) -> Self {
        Self::Mempool(MempoolError::Policy(error))
    }
}

impl From<crate::fee_diagram::FeeDiagramError> for RbfError {
    fn from(error: crate::fee_diagram::FeeDiagramError) -> Self {
        match error {
            crate::fee_diagram::FeeDiagramError::Arithmetic => Self::ArithmeticOverflow,
            crate::fee_diagram::FeeDiagramError::Weight => Self::InvalidWeight,
            crate::fee_diagram::FeeDiagramError::Dependencies => Self::InconsistentGraph,
        }
    }
}

impl RbfError {
    pub(crate) fn into_pool_error(self) -> MempoolError {
        match self {
            Self::Mempool(error) => error,
            Self::ArithmeticOverflow => {
                MempoolError::FeeDiagram(crate::FeeDiagramError::Arithmetic)
            }
            Self::InvalidWeight => MempoolError::FeeDiagram(crate::FeeDiagramError::Weight),
            Self::StalePlan => MempoolError::StalePolicy,
            _ => MempoolError::FeeDiagram(crate::FeeDiagramError::Dependencies),
        }
    }
}

/// Core `CFeeRate::GetFee`: truncate the product, but charge at least one
/// satoshi for nonempty relay at a positive rate. No saturated fee can pass.
pub(crate) fn required_fee(rate: u64, vsize: u32) -> Result<i128, RbfError> {
    let fee = u128::from(rate)
        .checked_mul(u128::from(vsize))
        .ok_or(RbfError::ArithmeticOverflow)?
        / 1_000;
    let fee = if rate > 0 && vsize > 0 {
        fee.max(1)
    } else {
        fee
    };
    i128::try_from(fee).map_err(|_| RbfError::ArithmeticOverflow)
}

pub(crate) struct ReplacementInputs {
    stamp: crate::pool::fee_policy::PolicyStamp,
    direct: HashSet<EntryId>,
    evicted: HashSet<EntryId>,
    graphs: Option<(
        crate::pool::fee_policy::PolicyGraph,
        crate::pool::fee_policy::PolicyGraph,
    )>,
    entry: crate::pool::PreparedInsert,
    projected_vsize: u64,
    max_vsize: u64,
    limits: crate::MempoolLimits,
    fee_estimate: bool,
}

pub(crate) struct PreparedPoolChange {
    pub(crate) stamp: crate::pool::fee_policy::PolicyStamp,
    pub(crate) evicted: Vec<EntryId>,
    pub(crate) removals: Vec<(EntryId, RemovalReason)>,
    pub(crate) entry: Option<crate::pool::PreparedInsert>,
    pub(crate) fee_estimate: bool,
}

impl ReplacementInputs {
    /// The potentially expensive graph solver runs over owned facts, with
    /// no pool guard held. The returned plan can only commit at its stamp.
    pub(crate) fn verify(self) -> Result<PreparedPoolChange, RbfError> {
        let Some((before_graph, after_graph)) = self.graphs else {
            return Ok(PreparedPoolChange {
                stamp: self.stamp,
                evicted: Vec::new(),
                removals: Vec::new(),
                entry: Some(self.entry),
                fee_estimate: self.fee_estimate,
            });
        };
        after_graph.check_limits(self.limits)?;
        let needs_trim = self.max_vsize > 0 && self.projected_vsize > self.max_vsize;
        let after_chunks = if self.direct.is_empty() && !needs_trim {
            Vec::new()
        } else {
            after_graph.chunks()?
        };
        if !self.direct.is_empty() {
            let before_chunks = before_graph.chunks()?;
            let before = before_graph.affected_diagram(&before_chunks);
            let after = after_graph.affected_diagram(&after_chunks);
            if crate::fee_diagram::compare(&after, &before)? != Some(core::cmp::Ordering::Greater) {
                return Err(RbfError::InsufficientFeerateDiagram);
            }
        }
        let mut removed = self.evicted.clone();
        let mut removal_priority: Vec<_> = self.evicted.iter().copied().collect();
        removal_priority.sort_unstable();
        let mut size = self.projected_vsize;
        if needs_trim {
            for chunk in after_chunks.iter().rev() {
                if size <= self.max_vsize {
                    break;
                }
                // A replacement that would be shed is rejected as a whole,
                // before removing conflicts or updating estimator history.
                if chunk
                    .members
                    .iter()
                    .any(|&member| after_graph.nodes[member].id.is_none())
                {
                    return Err(MempoolError::Full.into());
                }
                for &member in &chunk.members {
                    let node = &after_graph.nodes[member];
                    let id = node.id.ok_or(RbfError::InconsistentGraph)?;
                    if removed.insert(id) {
                        removal_priority.push(id);
                        size = size
                            .checked_sub(u64::from(node.vsize))
                            .ok_or(RbfError::ArithmeticOverflow)?;
                    }
                }
            }
            if size > self.max_vsize {
                return Err(MempoolError::Full.into());
            }
        }
        let order = before_graph.removal_order(&removal_priority)?;
        let removals = order
            .into_iter()
            .map(|id| {
                let reason = if self.direct.contains(&id) {
                    RemovalReason::Replaced
                } else if self.evicted.contains(&id) {
                    RemovalReason::Descendant
                } else {
                    RemovalReason::PolicyEviction
                };
                (id, reason)
            })
            .collect();
        let mut evicted: Vec<_> = self.evicted.into_iter().collect();
        evicted.sort_unstable();
        Ok(PreparedPoolChange {
            stamp: self.stamp,
            evicted,
            removals,
            entry: Some(self.entry),
            fee_estimate: self.fee_estimate,
        })
    }
}

impl Mempool {
    pub(crate) fn capture_insertion(
        &self,
        entry: MempoolEntry,
    ) -> Result<ReplacementInputs, RbfError> {
        self.capture_pool_change(entry, Vec::new(), 0, false, true)
    }

    pub(crate) fn capture_replacement(
        &self,
        candidate: &ReplacementCandidate,
        time: u64,
        height: u32,
    ) -> Result<ReplacementInputs, RbfError> {
        let (conflicts, sibling_eviction) =
            self.truc_conflicts(&candidate.tx, candidate.vsize, true)?;
        let entry = MempoolEntry::new(
            Arc::clone(&candidate.tx),
            candidate.vsize,
            candidate.fee,
            time,
            height,
            candidate.sigop_cost,
        );
        self.capture_pool_change(
            entry,
            conflicts,
            candidate.min_relay_fee_rate,
            sibling_eviction,
            candidate.fee_estimate,
        )
    }

    fn capture_pool_change(
        &self,
        entry: MempoolEntry,
        conflicts: Vec<EntryId>,
        incremental_fee_rate: u64,
        sibling_eviction: bool,
        fee_estimate: bool,
    ) -> Result<ReplacementInputs, RbfError> {
        if !u32::try_from(self.conflicting_cluster_count(&conflicts)?)
            .is_ok_and(|count| count <= self.limits.max_replacement_clusters)
        {
            return Err(if sibling_eviction {
                RbfError::TooManySiblingConflictingClusters
            } else {
                RbfError::TooManyConflictingClusters
            });
        }
        let evicted = if conflicts.is_empty() {
            Vec::new()
        } else {
            self.descendants_of_conflicts(&conflicts)
        };
        if !conflicts.is_empty() {
            let modified_fee = self.modified_fee_for(entry.txid, entry.fee)?;
            let fees = evicted.iter().try_fold(0_i128, |total, &id| {
                let fee = self
                    .entry(id)
                    .ok_or(RbfError::InconsistentGraph)?
                    .modified_fee();
                total.checked_add(fee).ok_or(RbfError::ArithmeticOverflow)
            })?;
            if modified_fee < fees {
                return Err(if sibling_eviction {
                    RbfError::SiblingAbsoluteFee
                } else {
                    RbfError::Rule3InsufficientAbsoluteFee
                });
            }
            let additional = modified_fee
                .checked_sub(fees)
                .ok_or(RbfError::ArithmeticOverflow)?;
            if additional < required_fee(incremental_fee_rate, entry.vsize)? {
                return Err(if sibling_eviction {
                    RbfError::SiblingIncrementalFee
                } else {
                    RbfError::Rule4InsufficientIncrementalFee
                });
            }
        }
        let removed_vsize = evicted.iter().try_fold(0_u64, |total, &id| {
            let entry = self.entry(id).ok_or(RbfError::InconsistentGraph)?;
            total
                .checked_add(u64::from(entry.vsize))
                .ok_or(RbfError::ArithmeticOverflow)
        })?;
        let projected_vsize = self
            .total_vsize()
            .checked_sub(removed_vsize)
            .and_then(|size| size.checked_add(u64::from(entry.vsize)))
            .ok_or(RbfError::ArithmeticOverflow)?;
        let include_all =
            self.limits.max_total_bytes > 0 && projected_vsize > self.limits.max_total_bytes;
        let graphs = if conflicts.is_empty() && !include_all {
            None
        } else {
            Some(self.projected_graphs(core::slice::from_ref(&entry), &evicted, include_all)?)
        };
        let excluded: HashSet<_> = evicted.iter().copied().collect();
        let entry = self.validate_insert(entry, &excluded)?;
        Ok(ReplacementInputs {
            stamp: self.policy_stamp(),
            direct: conflicts.into_iter().collect(),
            evicted: excluded,
            graphs,
            entry,
            projected_vsize,
            max_vsize: self.limits.max_total_bytes,
            limits: self.limits,
            fee_estimate,
        })
    }

    /// Checks the complete replacement policy without changing pool state.
    pub fn check_replacement(
        &self,
        candidate: &ReplacementCandidate,
    ) -> Result<ReplacementPlan, RbfError> {
        let prepared = self.capture_replacement(candidate, 0, 0)?.verify()?;
        Ok(ReplacementPlan {
            evicted: prepared.evicted,
        })
    }

    pub(crate) fn commit_pool_change(
        &mut self,
        prepared: PreparedPoolChange,
    ) -> Result<crate::mutation::MutationResult, RbfError> {
        if !prepared.stamp.matches(self) {
            return Err(RbfError::StalePlan);
        }
        let mut changes = Vec::new();
        let replacement = prepared.removals.iter().any(|(_, reason)| {
            matches!(reason, RemovalReason::Replaced | RemovalReason::Descendant)
        });
        if replacement {
            self.remove_entries_with_reasons(&prepared.removals, &mut changes);
        }
        let arrival = prepared
            .entry
            .as_ref()
            .map(|insert| insert.entry.txid)
            .filter(|_| prepared.fee_estimate);
        if let Some(entry) = prepared.entry {
            changes.extend(self.commit_insert(entry).changes);
        }
        if !replacement {
            self.remove_entries_with_reasons(&prepared.removals, &mut changes);
        }
        if let Some(txid) = arrival {
            self.record_entry_arrival(txid);
        }
        Ok(self.finish_mutation(changes))
    }

    /// Trusted direct-pool replacement. The gateway captures and verifies
    /// separately so graph work never runs while holding its write lock.
    pub fn replace_transaction(
        &mut self,
        mut candidate: ReplacementCandidate,
        time: u64,
        height: u32,
        sigop_cost: u32,
    ) -> Result<crate::mutation::MutationResult, RbfError> {
        candidate.sigop_cost = sigop_cost;
        let prepared = self
            .capture_replacement(&candidate, time, height)?
            .verify()?;
        self.commit_pool_change(prepared)
    }
}
