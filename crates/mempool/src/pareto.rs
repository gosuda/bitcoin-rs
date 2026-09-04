use alloc::collections::{BTreeMap, BTreeSet};

use crate::{EntryId, MempoolEntry};

/// Priority index ordered by signed modified fee rate, modified ancestor fee
/// rate, then age.
///
/// Ordering lives in [`ParetoKey`]'s [`Ord`], and the set is kept in that order
/// rather than re-sorted. Insertion and removal are both `O(log n)`.
///
/// Insertion and removal stay logarithmic so peer-driven mempool growth does
/// not re-sort the complete priority set.
#[derive(Clone, Debug, Default)]
pub struct ParetoFront {
    /// Keys in priority order.
    order: BTreeSet<ParetoKey>,
    /// The key currently indexed for each entry.
    ///
    /// A removal is given an id, and the ordered set is keyed by priority, so
    /// without this a removal would have to search the set to find what to
    /// remove — which is the linear scan this type exists to avoid.
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
    ///
    /// The rates are the actual fee rate plus the signed mining-only overlay
    /// ([`MempoolEntry::modified_fee_rate`]), so `prioritisetransaction`
    /// moves entries without touching their actual fees. The rates are signed
    /// because a negative overlay can push a modified fee below zero.
    ///
    /// The final tiebreak on `id` is what makes this a *total* order, and that
    /// is load-bearing rather than cosmetic: the ordered set stores keys, so two
    /// entries whose keys compared `Equal` would collapse into one and an entry
    /// would silently vanish from the mempool's priority index. Entry ids are
    /// unique, so no two distinct entries can compare equal.
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
    /// Creates an empty priority index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            order: BTreeSet::new(),
            keys: BTreeMap::new(),
        }
    }

    /// Inserts or replaces an entry in priority order.
    ///
    /// Replacement is not a special case for the caller but is one here: an
    /// entry whose ancestor fee rate changed has a different key, so the stale
    /// key must leave the ordered set or the entry would be indexed twice.
    pub fn insert(&mut self, id: EntryId, entry: &MempoolEntry) {
        let key = ParetoKey::new(id, entry);
        if let Some(previous) = self.keys.insert(id, key) {
            let _ = self.order.remove(&previous);
        }
        let _ = self.order.insert(key);
    }

    /// Removes an entry from the priority index.
    pub fn remove(&mut self, id: EntryId) -> bool {
        let Some(key) = self.keys.remove(&id) else {
            return false;
        };
        self.order.remove(&key)
    }

    /// Returns the highest-priority `n` entry identifiers.
    pub fn top_n(&self, n: usize) -> impl Iterator<Item = EntryId> + '_ {
        self.order.iter().take(n).map(|key| key.id)
    }

    /// Returns `true` if the front is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Returns the number of indexed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Estimates the heap this index occupies, in bytes.
    ///
    /// **Every entry is stored twice.** `order` is keyed by priority so the
    /// front can be read in order, and `keys` is keyed by id so a removal does
    /// not have to search the set for what to remove -- the linear scan this
    /// type exists to avoid. Charging one `EntryId` per transaction, as
    /// `dynamic_memory_usage` did, misses both key copies and reports a small
    /// fraction of what the index actually holds.
    ///
    /// A lower bound rather than a measurement, and deliberately so: a B-tree
    /// allocates nodes of a fixed arity and leaves them partly filled, so its
    /// real footprint is above this and depends on insertion order. Bitcoin
    /// Core's own `DynamicMemoryUsage` is an estimate for the same reason --
    /// "no exact formula for `boost::multi_index_container` is implemented".
    /// What matters is that the term scales with what is stored, which one
    /// `EntryId` per entry did not.
    #[must_use]
    pub fn dynamic_memory_usage(&self) -> u64 {
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

    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};

    use super::*;

    fn entry(tag: u8) -> MempoolEntry {
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: alloc::vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[tag; 32])), 0,),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: alloc::vec![TxOut {
                value: 10_000,
                script_pubkey: Vec::new(),
            }],
        };
        MempoolEntry::new(Arc::new(tx), 100, 10_000, u64::from(tag), 7)
    }

    /// Every entry is stored twice, and the estimate says so.
    ///
    /// `order` is keyed by priority so the front can be read in order; `keys`
    /// is keyed by id so a removal need not search the set for what to remove.
    /// An estimate that counted only one of them -- or, as the pool's term
    /// did, one `EntryId` per transaction -- reports a small fraction of what
    /// the index holds, and the shortfall grows with the pool.
    ///
    /// The floor is two key copies per entry: deliberately below what the
    /// implementation computes, which also carries the id the map keys on, so
    /// this is a claim rather than a restatement of the formula. It is a lower
    /// bound in the other direction too -- a B-tree leaves its nodes partly
    /// filled, so the real footprint is above this.
    #[test]
    fn the_estimate_counts_both_key_collections() {
        const COUNT: u32 = 64;

        let mut front = ParetoFront::new();
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
    ///
    /// Unlike the pool's arena, the priority index has nothing that retains an
    /// allocation this estimate can see: both collections are B-trees keyed by
    /// value, and neither exposes a capacity. So `len`-based terms are right
    /// here for the same reason they were wrong there, and the two cases are
    /// pinned together so the distinction is not lost.
    #[test]
    fn the_estimate_follows_what_is_indexed() {
        let mut front = ParetoFront::new();
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
