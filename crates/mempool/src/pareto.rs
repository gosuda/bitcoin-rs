use alloc::collections::{BTreeMap, BTreeSet};

use crate::{EntryId, MempoolEntry};

/// Priority index ordered by signed modified fee rate, modified ancestor fee
/// rate, then age.
#[derive(Clone, Debug, Default)]
pub(crate) struct ParetoFront {
    /// Keys in priority order.
    order: BTreeSet<ParetoKey>,
    /// The key currently indexed for each entry.
    keys: BTreeMap<EntryId, ParetoKey>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ParetoKey {
    id: EntryId,
    modified_fee_rate: i128,
    modified_ancestor_fee_rate: i128,
    time: u64,
}

impl Ord for ParetoKey {
    /// Highest modified fee rate first, then highest modified ancestor fee
    /// rate, then oldest.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other
            .modified_fee_rate
            .cmp(&self.modified_fee_rate)
            .then_with(|| {
                other
                    .modified_ancestor_fee_rate
                    .cmp(&self.modified_ancestor_fee_rate)
            })
            .then_with(|| self.time.cmp(&other.time))
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialOrd for ParetoKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ParetoKey {
    fn new(id: EntryId, entry: &MempoolEntry) -> Self {
        Self {
            id,
            modified_fee_rate: entry.modified_fee_rate(),
            modified_ancestor_fee_rate: entry.modified_ancestor_fee_rate(),
            time: entry.time,
        }
    }
}

impl ParetoFront {
    /// Inserts or replaces an entry in priority order.
    pub(crate) fn insert(&mut self, id: EntryId, entry: &MempoolEntry) {
        let key = ParetoKey::new(id, entry);
        if let Some(previous) = self.keys.insert(id, key) {
            let _ = self.order.remove(&previous);
        }
        let _ = self.order.insert(key);
    }

    /// Removes an entry from the priority index.
    pub(crate) fn remove(&mut self, id: EntryId) -> bool {
        let Some(key) = self.keys.remove(&id) else {
            return false;
        };
        self.order.remove(&key)
    }

    /// Returns the highest-priority `n` entry identifiers.
    pub(crate) fn top_n(&self, n: usize) -> impl Iterator<Item = EntryId> + '_ {
        self.order.iter().take(n).map(|key| key.id)
    }

    /// Returns `true` if the front is empty.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Returns the number of indexed entries.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    /// Estimates the heap this index occupies, in bytes.
    #[must_use]
    pub(crate) fn dynamic_memory_usage(&self) -> u64 {
        use core::mem::size_of;

        let ordered = u64::try_from(self.order.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<ParetoKey>()).unwrap_or(0));
        let by_id = u64::try_from(self.keys.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(EntryId, ParetoKey)>()).unwrap_or(0));
        ordered.saturating_add(by_id)
    }
}

#[cfg(test)]
mod memory_usage_tests {
    use alloc::sync::Arc;
    use core::mem::size_of;

    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };

    use super::*;

    fn entry(tag: u8) -> MempoolEntry {
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: alloc::vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[tag; 32])), 0,),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: alloc::vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::new(),
            }],
        };
        MempoolEntry::new(Arc::new(tx), 100, 10_000, u64::from(tag), 7, 0)
    }

    /// Every entry is stored twice, and the estimate says so.
    #[test]
    fn the_estimate_counts_both_key_collections() {
        const COUNT: u32 = 64;

        let mut front = ParetoFront::default();
        for id in 0..COUNT {
            front.insert(id, &entry(u8::try_from(id).unwrap_or(0)));
        }
        assert_eq!(front.len(), usize::try_from(COUNT).unwrap_or(0));

        let usage = front.dynamic_memory_usage();
        let two_keys_each = u64::from(COUNT)
            .saturating_mul(u64::try_from(size_of::<ParetoKey>()).unwrap_or(0))
            .saturating_mul(2);
        assert!(
            usage >= two_keys_each,
            "both collections must be counted: {usage} vs {two_keys_each}"
        );

        let one_key_each = two_keys_each / 2;
        assert!(
            usage > one_key_each,
            "counting one collection is the under-report this replaces"
        );
    }

    /// An empty index reports nothing, and a removal gives its memory back.
    #[test]
    fn the_estimate_follows_what_is_indexed() {
        let mut front = ParetoFront::default();
        assert_eq!(front.dynamic_memory_usage(), 0);

        for id in 0..16_u32 {
            front.insert(id, &entry(u8::try_from(id).unwrap_or(0)));
        }
        let full = front.dynamic_memory_usage();
        assert!(full > 0);

        for id in 0..16_u32 {
            assert!(front.remove(id), "the fixture must have indexed {id}");
        }
        assert_eq!(front.dynamic_memory_usage(), 0);
        assert!(full > front.dynamic_memory_usage());
    }
}
