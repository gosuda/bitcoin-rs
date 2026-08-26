use alloc::collections::{BTreeMap, BTreeSet};

use tinyvec::TinyVec;

use crate::{EntryId, MempoolEntry};

/// Priority index ordered by signed modified fee rate, modified ancestor fee
/// rate, then age.
///
/// Ordering lives in [`ParetoKey`]'s [`Ord`], and the set is kept in that order
/// rather than re-sorted. Insertion and removal are both `O(log n)`.
///
/// The previous implementation held the keys in a flat vector, and every
/// `insert` did a linear `remove` followed by a full `sort_by`. Filling a
/// mempool was therefore quadratic — 4.92 ms at 1,000 entries against 4.57 s at
/// 50,000, a measured exponent of 2.05 — and the cost is paid on the path that
/// accepts transactions from peers, so it was reachable by anyone who could fill
/// the mempool. [`SortedParetoFront`] keeps that implementation as the oracle
/// these tests compare against and as the benchmark's `before` arm.
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
}

/// The flat-vector priority index [`ParetoFront`] replaced.
///
/// Retained deliberately, not left behind: it is the oracle the equivalence
/// tests compare the replacement against, and the `before` arm of
/// `benches/pareto.rs`. Both arms have to run in one process over one fixture
/// for the ratio to mean anything, which they cannot do if this is deleted.
///
/// Nothing in the node uses it. It is quadratic to fill, which is the entire
/// reason it was replaced.
///
/// It keeps its own copy of the comparison rather than borrowing
/// [`ParetoKey`]'s [`Ord`]. Sharing it looked tidier and made the oracle
/// worthless: a mutation that reversed the ordering left both implementations
/// agreeing with each other, so the equivalence tests stayed green while the
/// index was ordered backwards. An oracle has to be able to disagree.
#[derive(Clone, Debug, Default)]
pub struct SortedParetoFront {
    entries: TinyVec<[ParetoKey; 256]>,
}

impl SortedParetoFront {
    /// Creates an empty priority index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: TinyVec::new(),
        }
    }

    /// Inserts or replaces an entry in priority order.
    pub fn insert(&mut self, id: EntryId, entry: &MempoolEntry) {
        self.remove(id);
        self.entries.push(ParetoKey::new(id, entry));
        self.entries.sort_by(legacy_compare_keys);
    }

    /// Removes an entry from the priority index.
    pub fn remove(&mut self, id: EntryId) -> bool {
        let Some(index) = self.entries.iter().position(|entry| entry.id == id) else {
            return false;
        };
        let _ = self.entries.remove(index);
        true
    }

    /// Returns the highest-priority `n` entry identifiers.
    pub fn top_n(&self, n: usize) -> impl Iterator<Item = EntryId> + '_ {
        self.entries.iter().take(n).map(|entry| entry.id)
    }

    /// Returns `true` if the front is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of indexed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The ordering the flat-vector index sorted by, kept verbatim.
///
/// Deliberately a duplicate of [`ParetoKey`]'s [`Ord`] rather than a call to it.
/// See [`SortedParetoFront`].
fn legacy_compare_keys(left: &ParetoKey, right: &ParetoKey) -> core::cmp::Ordering {
    right
        .modified_fee_rate
        .cmp(&left.modified_fee_rate)
        .then_with(|| {
            right
                .modified_ancestor_fee_rate
                .cmp(&left.modified_ancestor_fee_rate)
        })
        .then_with(|| left.time.cmp(&right.time))
        .then_with(|| left.id.cmp(&right.id))
}
