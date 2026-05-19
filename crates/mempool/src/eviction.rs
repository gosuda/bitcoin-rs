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
