use tinyvec::TinyVec;

use crate::{EntryId, MempoolEntry};

/// Priority index ordered by fee rate, ancestor fee rate, then age.
#[derive(Clone, Debug, Default)]
pub struct ParetoFront {
    entries: TinyVec<[ParetoKey; 256]>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ParetoKey {
    id: EntryId,
    fee_rate: u64,
    ancestor_fee_rate: u64,
    time: u64,
}

impl ParetoFront {
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
        self.entries.push(ParetoKey {
            id,
            fee_rate: entry.fee_rate,
            ancestor_fee_rate: entry.ancestor_fee_rate(),
            time: entry.time,
        });
        self.entries.sort_by(compare_keys);
    }

    /// Removes an entry from the priority index.
    pub fn remove(&mut self, id: EntryId) -> bool {
        let Some(index) = self.entries.iter().position(|entry| entry.id == id) else {
            return false;
        };
        self.entries.remove(index);
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

fn compare_keys(left: &ParetoKey, right: &ParetoKey) -> core::cmp::Ordering {
    right
        .fee_rate
        .cmp(&left.fee_rate)
        .then_with(|| right.ancestor_fee_rate.cmp(&left.ancestor_fee_rate))
        .then_with(|| left.time.cmp(&right.time))
        .then_with(|| left.id.cmp(&right.id))
}
