//! Package eviction policy.
//!
//! Eviction reads the maintained chunk index from the cheapest end under the
//! caller's pool guard: whole chunks go out cheapest first, each
//! chunk indivisible, until the pool fits. The selection is captured first
//! and validated before any mutation occurs. Each evicted chunk also earns
//! Core's rolling-floor bump (`TrimToSize`), read from the chunk's facts at
//! capture and applied when the plan commits.

use alloc::vec::Vec;

use hashbrown::HashMap;

use crate::mutation::{MutationChange, RemovalReason};
use crate::{EntryId, Mempool};

/// Capture of one eviction pass over the maintained chunk index.
///
/// `capture_eviction` walks the index from the low end and topologically
/// orders the selection while the guard is held; `verify` turns the ordered
/// capture into a removal plan with no guard held.
pub(crate) struct EvictionInputs {
    stamp: crate::pool::fee_policy::PolicyStamp,
    /// Selected entry ids in eviction order: cheapest chunks first, whole
    /// chunk, topologically ordered across the selection so a parent always
    /// precedes its child.
    selected: Option<Vec<EntryId>>,
    /// Highest [`crate::rbf::trim_bump`] over the evicted chunks, taken from
    /// each chunk's modified fee and charged weight while the guard held them.
    rolling_fee_bump: Option<u64>,
}

impl EvictionInputs {
    /// Turns the ordered capture into a removal plan. The capture already
    /// holds every check eviction needs, so this cannot fail.
    pub(crate) fn verify(self) -> crate::rbf::PreparedPoolChange {
        let removals = self
            .selected
            .unwrap_or_default()
            .into_iter()
            .map(|id| (id, RemovalReason::PolicyEviction))
            .collect();
        crate::rbf::PreparedPoolChange {
            stamp: self.stamp,
            #[cfg(any(test, feature = "test-seam"))]
            evicted: Vec::new(),
            removals,
            entry: None,
            fee_estimation: crate::rbf::FeeEstimation::Estimate,
            rolling_fee_bump: self.rolling_fee_bump,
        }
    }
}

impl Mempool {
    /// Captures the eviction selection for a pool above `target`: the
    /// maintained chunks from the cheapest, whole chunk, until the projected
    /// size fits. The walk shares the caller's read guard and copies only
    /// entry ids; the captured order is topological across the whole
    /// selection, so removal changes publish parents before children.
    pub(crate) fn capture_eviction(
        &self,
        target: u64,
    ) -> Result<EvictionInputs, crate::MempoolError> {
        let size = self.total_vsize();
        if size <= target {
            return Ok(EvictionInputs {
                stamp: self.policy_stamp(),
                selected: None,
                rolling_fee_bump: None,
            });
        }
        let incremental = self.policy_snapshot().incremental_relay_fee_sat_per_kvb;
        // The chunks are a partition of the live entries: one pass, no
        // membership checks, no quadratic scan.
        let mut projected = size;
        let mut selected = Vec::new();
        let mut bump = None;
        for chunk in self.chunks_by_feerate().rev() {
            if projected <= target {
                break;
            }
            // Core's `TrimToSize` bumps the floor for each worst chunk it
            // removes. The chunk's aggregate facts exist only under this
            // guard, so the bump is read here and carried, not recomputed.
            bump = bump.max(crate::rbf::trim_bump(
                chunk.modified_fee,
                chunk.charged_weight,
                incremental,
            ));
            for &member in chunk.members {
                let entry = self.entry(member).ok_or(crate::MempoolError::FeeDiagram(
                    crate::FeeDiagramError::Dependencies,
                ))?;
                selected.push(member);
                projected = projected
                    .checked_sub(u64::from(entry.vsize))
                    .ok_or(crate::FeeDiagramError::Arithmetic)?;
            }
        }
        if projected > target {
            return Err(crate::FeeDiagramError::Dependencies.into());
        }
        // The ascending walk visits a child chunk before its parent chunk, so
        // the capture is re-sorted into dependency order before it leaves the
        // guard: the cheapest chunk still comes first, but a parent always
        // precedes its child.
        let parents = |id: EntryId| self.parents_of(id);
        let selected = order_removals(&selected, &parents)?;
        Ok(EvictionInputs {
            stamp: self.policy_stamp(),
            selected: Some(selected),
            rolling_fee_bump: bump,
        })
    }
}

/// Orders eviction ids so every selected parent precedes its child. Only
/// parents that are themselves selected constrain the order; the walk order
/// breaks the rest, keeping the cheapest chunk first.
fn order_removals<'a>(
    selected: &[EntryId],
    parents: &dyn Fn(EntryId) -> &'a [EntryId],
) -> Result<Vec<EntryId>, crate::MempoolError> {
    let positions: HashMap<EntryId, usize> = selected
        .iter()
        .enumerate()
        .map(|(position, &id)| (id, position))
        .collect();
    let graph: Vec<Vec<usize>> = selected
        .iter()
        .map(|&id| {
            parents(id)
                .iter()
                .filter_map(|parent| positions.get(parent).copied())
                .collect()
        })
        .collect();
    let priority: Vec<usize> = (0..selected.len()).collect();
    let ordered = crate::fee_diagram::topological(&graph, &priority)?;
    Ok(ordered
        .into_iter()
        .map(|position| selected[position])
        .collect())
}

/// Evicts the lowest-fee dependency chunks until the pool fits.
/// The complete selection is validated before any mutation occurs.
pub(crate) fn evict_lowest_fee_packages(
    pool: &mut Mempool,
    target_size_bytes: u64,
) -> Result<Vec<MutationChange>, crate::MempoolError> {
    let plan = pool.capture_eviction(target_size_bytes)?.verify();
    pool.commit_pool_change(plan)
        .map(|result| result.changes)
        .map_err(crate::RbfError::into_pool_error)
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };

    use super::evict_lowest_fee_packages;
    use crate::mutation::{MutationChange, MutationOutcome, RemovalReason};
    use crate::{Mempool, MempoolEntry, MempoolLimits};

    #[test]
    fn eviction_removes_lowest_descendant_package_first() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 10_000,
            ..MempoolLimits::default()
        });
        let high = MempoolEntry::new(Arc::new(tx(2)), 100, 10_000, 1, 1, 0);
        let low = MempoolEntry::new(Arc::new(tx(3)), 100, 1_000, 2, 1, 0);
        pool.insert_entry(high).expect("high");
        pool.insert_entry(low).expect("low");

        let evicted = evict_lowest_fee_packages(&mut pool, 100).expect("eviction policy");
        assert_eq!(
            evicted,
            vec![MutationChange {
                txid: Hash256::from_le_bytes(tx(3).txid().as_bytes()),
                outcome: MutationOutcome::Removed(RemovalReason::PolicyEviction),
            }],
            "the lowest-fee package leaves first, tagged PolicyEviction"
        );
        assert_eq!(pool.len(), 1);
    }

    /// POL-05/MPL-02: low-fee choices retain their publication priority;
    /// selected dependencies must precede their descendants.
    #[test]
    fn multiple_evictions_preserve_fee_priority_and_dependency_order()
    -> Result<(), crate::MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        for (tag, fee) in [(1, 3_000), (2, 1_000), (3, 2_000)] {
            pool.insert_entry(MempoolEntry::new(Arc::new(tx(tag)), 100, fee, 1, 1, 0))?;
        }
        let changes = evict_lowest_fee_packages(&mut pool, 100)?;
        let ids: Vec<_> = changes.iter().map(|change| change.txid).collect();
        assert_eq!(
            ids,
            vec![Hash256::from(tx(2).txid()), Hash256::from(tx(3).txid())]
        );

        let mut pool = Mempool::new(MempoolLimits::default());
        let mut parent = tx(4);
        parent.outputs[0].value = Amount::from_sat(5_000);
        parent.outputs[0].script_pubkey = vec![0x51].into();
        let mut child = tx(5);
        child.inputs[0].previous_output = OutPoint::new(parent.txid(), 0);
        child.outputs[0].value = Amount::from_sat(3_100);
        let expected = vec![
            Hash256::from(tx(6).txid()),
            Hash256::from(parent.txid()),
            Hash256::from(child.txid()),
        ];
        for (transaction, fee) in [(parent, 100), (child, 1_900), (tx(6), 500), (tx(7), 10_000)] {
            pool.insert_entry(MempoolEntry::new(Arc::new(transaction), 100, fee, 1, 1, 0))?;
        }
        let changes = evict_lowest_fee_packages(&mut pool, 100)?;
        assert_eq!(
            changes.iter().map(|change| change.txid).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(pool.len(), 1);
        Ok(())
    }

    #[test]
    fn insertion_preflight_keeps_the_same_lowest_first_removal_order()
    -> Result<(), crate::MempoolError> {
        let mut pool = Mempool::new(MempoolLimits::default());
        for (tag, fee) in [(1, 3_000), (2, 1_000), (3, 2_000)] {
            pool.insert_entry(MempoolEntry::new(Arc::new(tx(tag)), 100, fee, 1, 1, 0))?;
        }
        pool.limits.max_total_bytes = 200;
        let changes =
            pool.insert_entry(MempoolEntry::new(Arc::new(tx(4)), 100, 10_000, 1, 1, 0))?;
        assert_eq!(changes.removed_txids(), vec![tx(2).txid(), tx(3).txid()]);
        assert_eq!(pool.total_vsize(), 200);
        Ok(())
    }

    #[test]
    fn eviction_bumps_rolling_min_fee() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            max_total_bytes: 400,
            ..MempoolLimits::default()
        });
        let low = tx(1);
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 200, 400, 1, 1, 0))
            .expect("low");
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(2)), 200, 800, 1, 1, 0))
            .expect("high");
        // No eviction yet: the rolling rate is zero, so the floor is min relay.
        assert_eq!(pool.min_fee_sat_per_kvb(1_000), 1_000);

        let evicted = evict_lowest_fee_packages(&mut pool, 200).expect("eviction policy");
        assert_eq!(evicted.len(), 1);
        assert_eq!(
            evicted[0].txid,
            Hash256::from(low_txid),
            "the lowest-fee package leaves first"
        );
        assert_eq!(
            evicted[0].outcome,
            MutationOutcome::Removed(RemovalReason::PolicyEviction),
            "eviction reports its PolicyEviction reason"
        );
        // Evicted chunk rate 2_000 sat/kvB plus the 1_000 incremental margin.
        // No block has connected, so the bump holds at any later clock.
        assert_eq!(pool.min_fee_sat_per_kvb(1_000), 3_000);
        assert_eq!(pool.min_fee_sat_per_kvb(1_000 + 12 * 60 * 60), 3_000);
    }

    #[test]
    fn eviction_of_a_negative_rate_chunk_leaves_the_floor() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 6,
            ..MempoolLimits::default()
        });
        let low = tx(11);
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 3, 100, 1, 1, 0))
            .expect("low");
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(12)), 3, 10_000, 1, 1, 0))
            .expect("high");
        pool.prioritise(low_txid, -1_100).expect("delta applies");
        // Modified fee -1_000 over 3 vB floors to -333_334; plus incremental
        // 1_000 stays far below zero, so the bump is empty.
        let evicted = evict_lowest_fee_packages(&mut pool, 3).expect("eviction policy");
        assert_eq!(evicted.len(), 1);
        assert_eq!(pool.min_fee_sat_per_kvb(1_000), 0);
    }

    #[test]
    fn stale_eviction_plan_neither_commits_nor_bumps() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 400,
            ..MempoolLimits::default()
        });
        let low = tx(21);
        let low_txid = low.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(low), 200, 400, 1, 1, 0))
            .expect("low");
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(22)), 200, 800, 1, 1, 0))
            .expect("high");
        let plan = pool.capture_eviction(200).expect("capture").verify();
        pool.prioritise(low_txid, 1).expect("delta moves the stamp");
        assert!(matches!(
            pool.commit_pool_change(plan),
            Err(crate::RbfError::StalePlan)
        ));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.min_fee_sat_per_kvb(1_000), 0);
    }

    fn tx(label: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51, label].into(),
            }],
        }
    }
}
