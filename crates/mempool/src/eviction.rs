use alloc::vec::Vec;

use crate::Mempool;
use crate::mutation::{MutationChange, RemovalReason};

pub(crate) struct EvictionInputs {
    stamp: crate::pool::fee_policy::PolicyStamp,
    data: Option<(crate::MempoolMiningSnapshot, Vec<crate::EntryId>)>,
    size: u64,
    target: u64,
}

impl EvictionInputs {
    pub(crate) fn verify(self) -> Result<crate::rbf::PreparedPoolChange, crate::MempoolError> {
        let mut removals = Vec::new();
        if let Some((snapshot, ids)) = self.data {
            let chunks = snapshot.fee_chunks()?;
            let mut size = self.size;
            let mut selected = vec![false; snapshot.entries.len()];
            for chunk in chunks.iter().rev() {
                if size <= self.target {
                    break;
                }
                for &index in &chunk.indices {
                    selected[index] = true;
                    size = size
                        .checked_sub(u64::from(snapshot.entries[index].vsize))
                        .ok_or(crate::FeeDiagramError::Arithmetic)?;
                }
            }
            if size > self.target {
                return Err(crate::FeeDiagramError::Dependencies.into());
            }
            let priority: Vec<_> = chunks
                .iter()
                .rev()
                .flat_map(|chunk| chunk.indices.iter().copied())
                .filter(|&index| selected[index])
                .collect();
            let parents = snapshot
                .entries
                .iter()
                .map(|entry| {
                    entry
                        .ancestors
                        .iter()
                        .map(|&index| {
                            usize::try_from(index).map_err(|_| crate::FeeDiagramError::Dependencies)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()?;
            removals.extend(
                crate::fee_diagram::topological(&parents, &priority)?
                    .into_iter()
                    .map(|index| (ids[index], RemovalReason::PolicyEviction)),
            );
        }
        Ok(crate::rbf::PreparedPoolChange {
            stamp: self.stamp,
            evicted: Vec::new(),
            removals,
            entry: None,
            fee_estimation: crate::rbf::FeeEstimation::Estimate,
        })
    }
}

impl Mempool {
    pub(crate) fn capture_eviction(
        &self,
        target: u64,
    ) -> Result<EvictionInputs, crate::MempoolError> {
        let size = self.total_vsize();
        let data = if size <= target {
            None
        } else {
            let snapshot = self.mining_snapshot();
            let ids = snapshot
                .entries
                .iter()
                .map(|entry| {
                    self.entry_id_by_txid(&entry.txid)
                        .ok_or(crate::MempoolError::FeeDiagram(
                            crate::FeeDiagramError::Dependencies,
                        ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some((snapshot, ids))
        };
        Ok(EvictionInputs {
            stamp: self.policy_stamp(),
            data,
            size,
            target,
        })
    }
}

/// Evicts the lowest-fee dependency chunks until the pool fits.
/// The complete selection is validated before any mutation occurs.
pub(crate) fn evict_lowest_fee_packages(
    pool: &mut Mempool,
    target_size_bytes: u64,
) -> Result<Vec<MutationChange>, crate::MempoolError> {
    let plan = pool.capture_eviction(target_size_bytes)?.verify()?;
    pool.commit_pool_change(plan)
        .map(|result| result.changes)
        .map_err(crate::RbfError::into_pool_error)
}

/// Local pressure-floor heuristic projected by `getmempoolinfo`.
/// It differs from Core's rolling minimum and decay, as recorded in POL-05.
///
/// When the pool occupies at least half of `max_total_bytes`, new admissions
/// must pay more than the cheapest currently-evictable entry by
/// `incremental_relay_fee_sat_per_kvb`. Below that pressure threshold the
/// configured min-relay fee is returned unchanged.
#[must_use]
pub fn mempool_min_fee_sat_per_kvb(pool: &Mempool, incremental_relay_fee_sat_per_kvb: u64) -> u64 {
    let maxmempool = pool.limits.max_total_bytes;
    let live_min_relay = pool.min_relay_fee_sat_per_kvb();
    if maxmempool > 0
        && pool.total_vsize().saturating_mul(2) >= maxmempool
        && let Some(lowest) = pool.lowest_fee_rate()
    {
        return live_min_relay.max(lowest.saturating_add(incremental_relay_fee_sat_per_kvb));
    }
    live_min_relay
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };

    use super::{evict_lowest_fee_packages, mempool_min_fee_sat_per_kvb};
    use crate::mutation::{MutationChange, MutationOutcome, RemovalReason};
    use crate::{Mempool, MempoolEntry, MempoolLimits};

    #[test]
    fn mempool_min_fee_equals_min_relay_below_half_full() {
        let pool = Mempool::new(MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 1_000,
            ..MempoolLimits::default()
        });
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 1_000);
    }

    #[test]
    fn mempool_min_fee_rises_above_cheapest_when_at_least_half_full() {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 400,
            min_relay_fee_sat_per_kvb: 1_000,
            ..MempoolLimits::default()
        });
        // 200 vbytes is exactly half of 400 — pressure threshold.
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1, 0))
            .expect("insert");
        // fee_rate = 400 * 1000 / 200 = 2_000 sat/kvB
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 3_000);
    }

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
        let changes = pool.insert_entry(MempoolEntry::new(Arc::new(tx(4)), 100, 10_000, 1, 1, 0))?;
        assert_eq!(changes.removed_txids(), vec![tx(2).txid(), tx(3).txid()]);
        assert_eq!(pool.total_vsize(), 200);
        Ok(())
    }

    #[test]
    fn eviction_raises_lowest_fee_rate_and_mempool_min_fee() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            max_total_bytes: 400,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1, 0))
            .expect("low");
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(2)), 200, 800, 1, 1, 0))
            .expect("high");
        assert_eq!(pool.lowest_fee_rate(), Some(2_000));
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 3_000);

        let evicted = evict_lowest_fee_packages(&mut pool, 200).expect("eviction policy");
        assert_eq!(evicted.len(), 1);
        assert_eq!(pool.lowest_fee_rate(), Some(4_000));
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 5_000);
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
