use alloc::vec::Vec;

use crate::entry::fee_rate;
use crate::{EntryId, Mempool};

/// Evicts the lowest-fee descendant packages until the pool is at or below `target_size_bytes`.
pub fn evict_lowest_fee_packages(pool: &mut Mempool, target_size_bytes: u64) -> Vec<EntryId> {
    let mut evicted = Vec::new();
    while pool.total_vsize() > target_size_bytes {
        let Some(id) = lowest_fee_package(pool) else {
            break;
        };
        evicted.extend(pool.remove_entry_and_descendants(id));
    }
    evicted.sort_unstable();
    evicted.dedup();
    evicted
}

fn lowest_fee_package(pool: &Mempool) -> Option<EntryId> {
    pool.entries
        .iter()
        .filter_map(|(index, entry)| {
            let id = EntryId::try_from(index).ok()?;
            let rate = fee_rate(entry.descendant_fee, entry.descendant_size);
            Some((id, rate, entry.time))
        })
        .min_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| right.2.cmp(&left.2))
                .then_with(|| left.0.cmp(&right.0))
        })
        .map(|(id, _, _)| id)
}

/// Dynamic mempool minimum fee under size pressure, matching Core's
/// `mempoolminfee` heuristic used by `getmempoolinfo`.
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

    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    use super::{evict_lowest_fee_packages, mempool_min_fee_sat_per_kvb};
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
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1))
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
        let high = MempoolEntry::new(Arc::new(tx(2)), 100, 10_000, 1, 1);
        let low = MempoolEntry::new(Arc::new(tx(3)), 100, 1_000, 2, 1);
        pool.insert_entry(high).expect("high");
        let low_id = pool.insert_entry(low).expect("low");

        let evicted = evict_lowest_fee_packages(&mut pool, 100);
        assert_eq!(evicted, vec![low_id]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn eviction_raises_lowest_fee_rate_and_mempool_min_fee() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            max_total_bytes: 400,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1))
            .expect("low");
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(2)), 200, 800, 1, 1))
            .expect("high");
        assert_eq!(pool.lowest_fee_rate(), Some(2_000));
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 3_000);

        let evicted = evict_lowest_fee_packages(&mut pool, 200);
        assert_eq!(evicted.len(), 1);
        assert_eq!(pool.lowest_fee_rate(), Some(4_000));
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 5_000);
    }

    fn tx(label: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([label; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
            }],
        }
    }
}
