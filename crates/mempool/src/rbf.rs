#[cfg(any(test, feature = "test-seam"))]
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_primitives::Tx;
use hashbrown::HashSet;
use thiserror::Error;

use crate::mutation::{AdmissionOrigin, RemovalReason};
use crate::{EntryId, Mempool, MempoolEntry, MempoolError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FeeEstimation {
    Estimate,
    Skip,
}

impl FeeEstimation {
    pub(crate) fn from_origin(origin: &AdmissionOrigin) -> Self {
        match origin {
            AdmissionOrigin::Reorg | AdmissionOrigin::Snapshot => Self::Skip,
            _ => Self::Estimate,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LimitEnforcement {
    Full,
    ExpireBeforeTrim(u64),
    Deferred,
}

#[cfg(any(test, feature = "test-seam"))]
#[derive(Clone, Debug)]
pub struct ReplacementCandidate {
    pub tx: Arc<Tx>,
    pub vsize: u32,
    pub fee: u64,
    pub min_relay_fee_rate: u64,
    pub sigop_cost: u32,
}

#[cfg(any(test, feature = "test-seam"))]
impl ReplacementCandidate {
    #[must_use]
    pub const fn new(tx: Arc<Tx>, vsize: u32, fee: u64, min_relay_fee_rate: u64) -> Self {
        Self {
            tx,
            vsize,
            fee,
            min_relay_fee_rate,
            sigop_cost: 0,
        }
    }

    #[must_use]
    pub const fn with_sigop_cost(mut self, sigop_cost: u32) -> Self {
        self.sigop_cost = sigop_cost;
        self
    }
}

#[cfg(any(test, feature = "test-seam"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementPlan {
    pub evicted: Vec<EntryId>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RbfError {
    #[error("insufficient fee")]
    Rule3InsufficientAbsoluteFee,
    #[error("insufficient fee")]
    Rule4InsufficientIncrementalFee,
    #[error("too many potential replacements")]
    TooManyConflictingClusters,
    #[error("insufficient fee (including sibling eviction)")]
    SiblingAbsoluteFee,
    #[error("insufficient fee (including sibling eviction)")]
    SiblingIncrementalFee,
    #[error("too many potential replacements (including sibling eviction)")]
    TooManySiblingConflictingClusters,
    #[error("replacement-failed")]
    InsufficientFeerateDiagram,
    #[error("replacement arithmetic overflow")]
    ArithmeticOverflow,
    #[error("invalid replacement weight")]
    InvalidWeight,
    #[error("mempool graph is inconsistent")]
    InconsistentGraph,
    #[error("mempool changed during replacement preparation")]
    StalePlan,
    #[error(transparent)]
    Truc(#[from] crate::TrucError),
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

pub(crate) fn trim_bump(
    modified_fee: i128,
    charged_weight: u64,
    incremental_relay_fee: u64,
) -> Option<u64> {
    let vsize = i128::from(charged_weight.div_ceil(4));
    let rate = if vsize == 0 {
        0
    } else {
        modified_fee.saturating_mul(1_000).div_euclid(vsize)
    };
    let bump = rate.saturating_add(i128::from(incremental_relay_fee));
    if bump <= 0 {
        return None;
    }
    Some(u64::try_from(bump).unwrap_or(u64::MAX))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrimBump {
    stamp: crate::pool::fee_policy::PolicyStamp,
    rate: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum Refusal {
    #[error(transparent)]
    Reject(RbfError),
    #[error("mempool full")]
    Full(Option<TrimBump>),
}

impl From<RbfError> for Refusal {
    fn from(error: RbfError) -> Self {
        Self::Reject(error)
    }
}

impl Refusal {
    pub(crate) fn into_parts(self) -> (RbfError, Option<TrimBump>) {
        match self {
            Self::Reject(error) => (error, None),
            Self::Full(bump) => (MempoolError::Full.into(), bump),
        }
    }
}

/// Core `CFeeRate::GetFee`: truncate the product, but charge at least one
/// satoshi for nonempty relay at a positive rate. No saturated fee can pass.
pub fn required_fee(rate: u64, vsize: u32) -> Result<i128, RbfError> {
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
    incremental_relay_fee: u64,
    fee_estimation: FeeEstimation,
    enforcement: LimitEnforcement,
    trim_graph: Option<crate::pool::fee_policy::PolicyGraph>,
}

pub(crate) struct PreparedPoolChange {
    pub(crate) expiry_time: Option<u64>,
    pub(crate) stamp: crate::pool::fee_policy::PolicyStamp,
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) evicted: Vec<EntryId>,
    pub(crate) removals: Vec<(EntryId, RemovalReason)>,
    pub(crate) entry: Option<crate::pool::PreparedInsert>,
    pub(crate) fee_estimation: FeeEstimation,
    pub(crate) rolling_fee_bump: Option<u64>,
}

impl PreparedPoolChange {
    pub(crate) fn replaced_entries<'a>(
        &'a self,
        pool: &'a Mempool,
    ) -> impl Iterator<Item = &'a MempoolEntry> + 'a {
        self.removals
            .iter()
            .filter(|(_, reason)| {
                matches!(reason, RemovalReason::Replaced | RemovalReason::Descendant)
            })
            .filter_map(move |(id, _)| pool.entry(*id))
    }
}

impl ReplacementInputs {
    #[expect(
        clippy::too_many_lines,
        reason = "keep RBF comparison and post-expiry capacity verification tied to one captured stamp"
    )]
    pub(crate) fn verify(self) -> Result<PreparedPoolChange, Refusal> {
        let expiry_time = match self.enforcement {
            LimitEnforcement::ExpireBeforeTrim(now) => Some(now),
            _ => None,
        };
        let Some((before_graph, after_graph)) = self.graphs else {
            return Ok(PreparedPoolChange {
                expiry_time,
                stamp: self.stamp,
                #[cfg(any(test, feature = "test-seam"))]
                evicted: Vec::new(),
                removals: Vec::new(),
                entry: Some(self.entry),
                fee_estimation: self.fee_estimation,
                rolling_fee_bump: None,
            });
        };
        after_graph.check_limits(self.limits)?;
        let needs_trim = self.enforcement != LimitEnforcement::Deferred
            && self.max_vsize > 0
            && self.projected_vsize > self.max_vsize;
        let after_chunks = if self.direct.is_empty() && (!needs_trim || self.trim_graph.is_some()) {
            Vec::new()
        } else {
            after_graph.chunks()?
        };
        if !self.direct.is_empty() {
            let before_chunks = before_graph.chunks()?;
            let before = before_graph.affected_diagram(&before_chunks);
            let after = after_graph.affected_diagram(&after_chunks);
            if crate::fee_diagram::compare(&after, &before).map_err(RbfError::from)?
                != Some(core::cmp::Ordering::Greater)
            {
                return Err(RbfError::InsufficientFeerateDiagram.into());
            }
        }
        let mut removed = self.evicted.clone();
        let mut removal_priority: Vec<_> = self.evicted.iter().copied().collect();
        removal_priority.sort_unstable();
        let mut size = self.projected_vsize;
        let mut bump = None;
        if needs_trim {
            let trim_graph = self.trim_graph.as_ref().unwrap_or(&after_graph);
            let trim_chunks = if self.trim_graph.is_some() {
                trim_graph.chunks()?
            } else {
                after_chunks
            };
            for chunk in trim_chunks.iter().rev() {
                if size <= self.max_vsize {
                    break;
                }
                bump = bump.max(trim_bump(
                    chunk.total.fee,
                    u64::from(chunk.total.weight),
                    self.incremental_relay_fee,
                ));
                if chunk
                    .members
                    .iter()
                    .any(|&member| trim_graph.nodes[member].id.is_none())
                {
                    return Err(refuse_full(self.stamp, bump));
                }
                for &member in &chunk.members {
                    let node = &trim_graph.nodes[member];
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
                return Err(refuse_full(self.stamp, bump));
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
        #[cfg(any(test, feature = "test-seam"))]
        let evicted = {
            let mut evicted: Vec<_> = self.evicted.into_iter().collect();
            evicted.sort_unstable();
            evicted
        };
        Ok(PreparedPoolChange {
            expiry_time,
            stamp: self.stamp,
            #[cfg(any(test, feature = "test-seam"))]
            evicted,
            removals,
            entry: Some(self.entry),
            fee_estimation: self.fee_estimation,
            rolling_fee_bump: bump,
        })
    }
}

fn refuse_full(stamp: crate::pool::fee_policy::PolicyStamp, bump: Option<u64>) -> Refusal {
    Refusal::Full(bump.map(|rate| TrimBump { stamp, rate }))
}

impl Mempool {
    pub(crate) fn capture_insertion(
        &self,
        entry: MempoolEntry,
        fee_estimation: FeeEstimation,
        enforcement: LimitEnforcement,
    ) -> Result<ReplacementInputs, RbfError> {
        self.capture_admission(entry, Vec::new(), 0, false, fee_estimation, enforcement)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) fn capture_replacement(
        &self,
        candidate: &ReplacementCandidate,
        time: u64,
        height: u32,
        fee_estimation: FeeEstimation,
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
        self.capture_admission(
            entry,
            conflicts,
            candidate.min_relay_fee_rate,
            sibling_eviction,
            fee_estimation,
            LimitEnforcement::Full,
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "capture pre-expiry replacement and post-expiry capacity facts under one pool guard"
    )]
    pub(crate) fn capture_admission(
        &self,
        entry: MempoolEntry,
        conflicts: Vec<EntryId>,
        incremental_fee_rate: u64,
        sibling_eviction: bool,
        fee_estimation: FeeEstimation,
        enforcement: LimitEnforcement,
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
        let mut projected_vsize = self
            .total_vsize()
            .checked_sub(removed_vsize)
            .and_then(|size| size.checked_add(u64::from(entry.vsize)))
            .ok_or(RbfError::ArithmeticOverflow)?;
        let include_all = enforcement != LimitEnforcement::Deferred
            && self.limits.max_total_bytes > 0
            && projected_vsize > self.limits.max_total_bytes;
        let graphs = if conflicts.is_empty() && !include_all {
            None
        } else {
            Some(self.projected_graphs(core::slice::from_ref(&entry), &evicted, include_all)?)
        };
        let excluded: HashSet<_> = evicted.iter().copied().collect();
        let trim_graph = if let LimitEnforcement::ExpireBeforeTrim(now) = enforcement {
            let expired: HashSet<_> = self.expired_entry_ids(now).into_iter().collect();
            if include_all && !expired.is_empty() {
                let mut excluded_trim = excluded.clone();
                for &id in &expired {
                    if excluded_trim.insert(id) {
                        projected_vsize = projected_vsize
                            .checked_sub(u64::from(
                                self.entry(id).ok_or(RbfError::InconsistentGraph)?.vsize,
                            ))
                            .ok_or(RbfError::ArithmeticOverflow)?;
                    }
                }
                let expires = entry
                    .tx
                    .inputs
                    .iter()
                    .filter_map(|input| self.entry_id_by_txid(&input.previous_output.txid))
                    .any(|id| expired.contains(&id));
                if expires {
                    projected_vsize = projected_vsize
                        .checked_sub(u64::from(entry.vsize))
                        .ok_or(RbfError::ArithmeticOverflow)?;
                }
                let candidates = if expires {
                    &[][..]
                } else {
                    core::slice::from_ref(&entry)
                };
                let mut excluded_trim: Vec<_> = excluded_trim.into_iter().collect();
                excluded_trim.sort_unstable();
                Some(self.projected_graphs(candidates, &excluded_trim, true)?.1)
            } else {
                None
            }
        } else {
            None
        };
        let entry = self.validate_insert(entry, &excluded, enforcement)?;
        Ok(ReplacementInputs {
            stamp: self.policy_stamp(),
            direct: conflicts.into_iter().collect(),
            evicted: excluded,
            graphs,
            entry,
            projected_vsize,
            max_vsize: self.limits.max_total_bytes,
            limits: self.limits,
            incremental_relay_fee: self.policy_snapshot().incremental_relay_fee_sat_per_kvb,
            fee_estimation,
            enforcement,
            trim_graph,
        })
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn check_replacement(
        &self,
        candidate: &ReplacementCandidate,
    ) -> Result<ReplacementPlan, RbfError> {
        let prepared = self
            .capture_replacement(candidate, 0, 0, FeeEstimation::Estimate)?
            .verify()
            .map_err(|refusal| refusal.into_parts().0)?;
        Ok(ReplacementPlan {
            evicted: prepared.evicted,
        })
    }

    pub(crate) fn track_refused_trim(&mut self, bump: TrimBump) -> Result<(), RbfError> {
        if !bump.stamp.matches(self) {
            return Err(RbfError::StalePlan);
        }
        self.track_package_removed(bump.rate);
        Ok(())
    }

    pub(crate) fn commit_pool_change(
        &mut self,
        prepared: PreparedPoolChange,
    ) -> Result<crate::mutation::MutationResult, RbfError> {
        if !prepared.stamp.matches(self) {
            return Err(RbfError::StalePlan);
        }
        let mut changes = Vec::new();
        let (replacements, remaining): (Vec<_>, Vec<_>) =
            prepared.removals.into_iter().partition(|(_, reason)| {
                matches!(reason, RemovalReason::Replaced | RemovalReason::Descendant)
            });
        self.remove_entries_with_reasons(&replacements, &mut changes);
        let arrival = prepared
            .entry
            .as_ref()
            .map(|insert| insert.entry.txid)
            .filter(|_| prepared.fee_estimation == FeeEstimation::Estimate);
        if let Some(entry) = prepared.entry {
            changes.extend(self.commit_insert(entry).changes);
        }
        if let Some(txid) = arrival {
            self.record_entry_arrival(txid);
        }
        if let Some(now) = prepared.expiry_time {
            changes.extend(self.expire(now).changes);
        }
        self.remove_entries_with_reasons(&remaining, &mut changes);
        if let Some(bump) = prepared.rolling_fee_bump {
            self.track_package_removed(bump);
        }
        Ok(self.finish_mutation(changes))
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn replace_transaction(
        &mut self,
        candidate: &ReplacementCandidate,
        time: u64,
        height: u32,
    ) -> Result<crate::mutation::MutationResult, RbfError> {
        let inputs = self.capture_replacement(candidate, time, height, FeeEstimation::Estimate)?;
        let prepared = match inputs.verify() {
            Ok(prepared) => prepared,
            Err(refusal) => {
                let (error, bump) = refusal.into_parts();
                if matches!(bump, Some(bump) if self.track_refused_trim(bump).is_err()) {
                    return Err(RbfError::StalePlan);
                }
                return Err(error);
            }
        };
        self.commit_pool_change(prepared)
    }
}

#[cfg(test)]
mod tests {
    use super::trim_bump;

    #[test]
    fn trim_bump_adds_incremental_to_the_floored_chunk_rate() {
        assert_eq!(trim_bump(400, 800, 1_000), Some(3_000));
        assert_eq!(trim_bump(0, 400, 1_000), Some(1_000));
        assert_eq!(trim_bump(1_500, 5, 1_000), Some(751_000));
    }

    #[test]
    fn trim_bump_floors_negative_fees_and_drops_nonpositive_bumps() {
        assert_eq!(trim_bump(-1_000, 12, 1_000), None);
        assert_eq!(trim_bump(-1_000, 1_000, 1_000), None);
    }
}
