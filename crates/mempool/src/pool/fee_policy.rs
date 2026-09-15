//! Immutable fee-policy projections captured from this pool's own links.

use super::{
    EntryId, Mempool, MempoolEntry, MempoolError, MempoolLimits, MempoolPolicySnapshot,
    PolicyError, VisitSet,
};
use crate::fee_diagram::{self, FeeWeight};
use crate::rbf::RbfError;
use alloc::vec::Vec;
use bitcoin_rs_primitives::Txid;
use hashbrown::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyStamp {
    sequence: u64,
    fee_sequence: u64,
    limits: MempoolLimits,
    policy: MempoolPolicySnapshot,
}

impl PolicyStamp {
    pub(crate) fn matches(self, pool: &Mempool) -> bool {
        self == pool.policy_stamp()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GraphNode {
    pub(crate) id: Option<EntryId>,
    pub(crate) txid: Txid,
    pub(crate) value: FeeWeight,
    pub(crate) vsize: u32,
    pub(crate) affected: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PolicyGraph {
    pub(crate) nodes: Vec<GraphNode>,
    pub(crate) parents: Vec<Vec<usize>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyChunk {
    pub(crate) members: Vec<usize>,
    pub(crate) value: FeeWeight,
}

impl PolicyGraph {
    pub(crate) fn removal_order(&self, priority: &[EntryId]) -> Result<Vec<EntryId>, RbfError> {
        let positions: HashMap<_, _> = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| node.id.map(|id| (id, index)))
            .collect();
        let members = priority
            .iter()
            .map(|id| {
                positions
                    .get(id)
                    .copied()
                    .ok_or(RbfError::InconsistentGraph)
            })
            .collect::<Result<Vec<_>, _>>()?;
        fee_diagram::topological(&self.parents, &members)?
            .into_iter()
            .map(|index| self.nodes[index].id.ok_or(RbfError::InconsistentGraph))
            .collect()
    }

    pub(crate) fn affected_diagram(&self, chunks: &[PolicyChunk]) -> Vec<FeeWeight> {
        chunks
            .iter()
            .filter(|chunk| chunk.members.iter().any(|&i| self.nodes[i].affected))
            .map(|chunk| chunk.value)
            .collect()
    }
    pub(crate) fn check_limits(&self, limits: MempoolLimits) -> Result<(), RbfError> {
        for members in fee_diagram::components(&self.parents)? {
            let count = u32::try_from(members.len()).map_err(|_| PolicyError::ClusterCountLimit)?;
            let weight = members.iter().try_fold(0_u64, |sum, &node| {
                sum.checked_add(u64::from(self.nodes[node].value.weight))
                    .ok_or(RbfError::ArithmeticOverflow)
            })?;
            super::cluster_within_limits(count, weight, &limits)?;
        }
        Ok(())
    }

    pub(crate) fn chunks(&self) -> Result<Vec<PolicyChunk>, RbfError> {
        let fees: Vec<_> = self.nodes.iter().map(|node| node.value).collect();
        Ok(fee_diagram::ordered_chunks(&fees, &self.parents)?
            .into_iter()
            .map(|chunk| PolicyChunk {
                members: chunk.members,
                value: chunk.total,
            })
            .collect())
    }
}

/// Raw pool APIs accept policy vsize supplied by their caller. Preserve its
/// vbyte granularity when it differs from the resolved wire/sigop weight;
/// the gateway supplies consistent facts and retains exact weight there.
pub(crate) fn policy_weight(wire_weight: u64, vsize: u32, sigops: u32) -> Result<u32, RbfError> {
    let weight = crate::accounting::charged_weight(wire_weight, vsize, sigops);
    if weight == 0 || weight > u64::from(i32::MAX.unsigned_abs()) {
        return Err(RbfError::InvalidWeight);
    }
    u32::try_from(weight).map_err(|_| RbfError::ArithmeticOverflow)
}

impl Mempool {
    pub(crate) fn modified_fee_for(&self, txid: Txid, base_fee: u64) -> Result<i128, RbfError> {
        i128::from(base_fee)
            .checked_add(i128::from(self.fee_deltas.get(&txid).copied().unwrap_or(0)))
            .ok_or(RbfError::ArithmeticOverflow)
    }
    pub(crate) fn policy_stamp(&self) -> PolicyStamp {
        PolicyStamp {
            sequence: self.mempool_sequence,
            fee_sequence: self.fee_delta_sequence,
            limits: self.limits,
            policy: self.policy_snapshot(),
        }
    }

    pub(crate) fn conflicting_cluster_count(
        &self,
        conflicts: &[EntryId],
    ) -> Result<usize, RbfError> {
        conflicts
            .iter()
            .map(|&id| self.component_id(id).ok_or(RbfError::InconsistentGraph))
            .collect::<Result<HashSet<_>, _>>()
            .map(|ids| ids.len())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep before/after projections tied to the same captured component membership"
    )]
    pub(crate) fn projected_graphs(
        &self,
        candidates: &[MempoolEntry],
        evicted: &[EntryId],
        include_all: bool,
    ) -> Result<(PolicyGraph, PolicyGraph), RbfError> {
        let excluded: HashSet<_> = evicted.iter().copied().collect();
        let parents: Vec<_> = candidates
            .iter()
            .flat_map(|entry| self.in_pool_parents(&entry.tx))
            .collect();
        if parents.iter().any(|parent| excluded.contains(parent)) {
            return Err(MempoolError::EvictedParent.into());
        }
        let children: Vec<_> = candidates
            .iter()
            .flat_map(|entry| self.in_pool_children(entry.txid))
            .collect();
        let mut affected = Vec::new();
        let mut seen = VisitSet::new();
        for &seed in evicted.iter().chain(&parents).chain(&children) {
            self.collect_component_members(seed, &mut seen, &mut affected);
        }
        let affected: HashSet<_> = affected.into_iter().collect();
        let mut members = Vec::new();
        if include_all {
            members.extend(
                self.entries
                    .iter()
                    .map(|(index, _)| {
                        EntryId::try_from(index).map_err(|_| RbfError::ArithmeticOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        } else {
            members.extend(affected.iter().copied());
        }
        members.sort_unstable();
        members.dedup();
        let positions: HashMap<_, _> = members
            .iter()
            .enumerate()
            .map(|(index, &id)| (id, index))
            .collect();
        let mut before = PolicyGraph::default();
        for &id in &members {
            let entry = self.entry(id).ok_or(RbfError::InconsistentGraph)?;
            let fee = entry.modified_fee();
            before.nodes.push(GraphNode {
                id: Some(id),
                txid: entry.txid,
                vsize: entry.vsize,
                affected: affected.contains(&id),
                value: FeeWeight {
                    fee,
                    weight: policy_weight(entry.weight, entry.vsize, entry.sigop_cost)?,
                },
            });
            let links = self.links(id).ok_or(RbfError::InconsistentGraph)?;
            before.parents.push(
                links
                    .parents
                    .iter()
                    .map(|parent| {
                        positions
                            .get(parent)
                            .copied()
                            .ok_or(RbfError::InconsistentGraph)
                    })
                    .collect::<Result<_, _>>()?,
            );
        }
        let mut after = PolicyGraph::default();
        let mut surviving = HashMap::new();
        for (old, node) in before.nodes.iter().enumerate() {
            if node.id.is_some_and(|id| excluded.contains(&id)) {
                continue;
            }
            surviving.insert(old, after.nodes.len());
            after.nodes.push(node.clone());
        }
        for (old, node) in before.nodes.iter().enumerate() {
            if node.id.is_some_and(|id| excluded.contains(&id)) {
                continue;
            }
            after.parents.push(
                before.parents[old]
                    .iter()
                    .map(|parent| {
                        surviving
                            .get(parent)
                            .copied()
                            .ok_or(RbfError::InconsistentGraph)
                    })
                    .collect::<Result<_, _>>()?,
            );
        }
        let mut tx_positions: HashMap<_, _> = after
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.txid, index))
            .collect();
        for candidate in candidates {
            let candidate_index = after.nodes.len();
            tx_positions.insert(candidate.txid, candidate_index);
            after.nodes.push(GraphNode {
                id: None,
                txid: candidate.txid,
                vsize: candidate.vsize,
                affected: true,
                value: FeeWeight {
                    fee: self.modified_fee_for(candidate.txid, candidate.fee)?,
                    weight: policy_weight(candidate.weight, candidate.vsize, candidate.sigop_cost)?,
                },
            });
            let mut parents: Vec<_> = candidate
                .tx
                .inputs
                .iter()
                .filter_map(|input| tx_positions.get(&input.previous_output.txid).copied())
                .collect();
            parents.sort_unstable();
            parents.dedup();
            after.parents.push(parents);
            for child in self.in_pool_children(candidate.txid) {
                if let Some(&old) = positions.get(&child)
                    && let Some(&new) = surviving.get(&old)
                {
                    after.parents[new].push(candidate_index);
                }
            }
        }
        Ok((before, after))
    }
}
