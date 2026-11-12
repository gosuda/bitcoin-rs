use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use hashbrown::HashTable;
use parking_lot::Mutex;

use super::CoinKey;

const SHARD_COUNT: usize = 256;

struct ClockEntry {
    key: CoinKey,
    value: Bytes,
    referenced: bool,
}

struct ShardState {
    entries: Vec<ClockEntry>,
    index: HashTable<usize>,
    hand: usize,
    overhead_bytes: u64,
}

impl ShardState {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashTable::new(),
            hand: 0,
            overhead_bytes: 0,
        }
    }

    fn backing_bytes(&self) -> u64 {
        u64::try_from(self.entries.capacity())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<ClockEntry>()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(self.index.allocation_size()).unwrap_or(u64::MAX))
    }

    fn position(&self, key: &CoinKey, hash: u64) -> Option<usize> {
        self.index
            .find(hash, |&slot| self.entries[slot].key == *key)
            .copied()
    }

    fn remove(&mut self, position: usize, hasher: &RandomState) -> u64 {
        let hash = hasher.hash_one(self.entries[position].key.0);
        if let Ok(entry) = self.index.find_entry(hash, |&slot| slot == position) {
            entry.remove();
        }
        let removed = self.entries.swap_remove(position);
        let old_last = self.entries.len();
        if position != old_last {
            let moved_hash = hasher.hash_one(self.entries[position].key.0);
            if let Some(slot) = self.index.find_mut(moved_hash, |&slot| slot == old_last) {
                *slot = position;
            }
        }
        if self.entries.is_empty() {
            self.hand = 0;
        } else if self.hand == old_last {
            self.hand = position % self.entries.len();
        } else {
            self.hand %= self.entries.len();
        }
        u64::try_from(removed.value.len()).unwrap_or(u64::MAX)
    }

    fn evict(&mut self, hasher: &RandomState) -> u64 {
        loop {
            if self.entries.is_empty() {
                return 0;
            }
            let hand = self.hand;
            if self.entries[hand].referenced {
                self.entries[hand].referenced = false;
                self.hand = (hand + 1) % self.entries.len();
            } else {
                return self.remove(hand, hasher);
            }
        }
    }
}

/// Resident clock cache in front of the `coins` keyspace.
/// Growth reserves room for old and new backing together before allocating,
/// using the hashbrown 0.17 layout bound below. `Vec::try_reserve_exact` may
/// overallocate; its reported capacity is checked before allocating the index.
/// Such allocator over-allocation can transiently exceed the reservation and
/// is rejected rather than retained.
///
/// The budget charges value lengths, actual vector and hash-table backing
/// allocations, and explicit `note_bytes` charges. It does not measure allocator
/// metadata, RSS, shared `Bytes` backing capacity, or the fixed shard directory.
/// Only committed installs and epoch-guarded engine reads introduce values.
/// Lock order is resident counter then shard; lookup takes only a shard lock.
pub struct CoinCache {
    budget_bytes: u64,
    resident: Mutex<u64>,
    shards: Box<[ShardLock]>,
    hasher: RandomState,
}

#[repr(align(64))]
struct ShardLock {
    epoch: AtomicU64,
    state: Mutex<ShardState>,
}

impl ShardLock {
    fn lock(&self) -> parking_lot::MutexGuard<'_, ShardState> {
        self.state.lock()
    }
}

/// Conservative bound for hashbrown 0.17 `HashTable<usize>` reservations.
/// Small tables use at most 16 buckets; larger tables round capacity * 8 / 7
/// up to a power of two. Alignment padding and trailing controls add at most 32.
fn table_reservation_bound(capacity: usize) -> Option<usize> {
    let buckets = (capacity.checked_mul(8)? / 7)
        .max(16)
        .checked_next_power_of_two()?;
    buckets
        .checked_mul(size_of::<usize>().checked_add(1)?)?
        .checked_add(32)
}

impl CoinCache {
    #[must_use]
    pub fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            resident: Mutex::new(0),
            shards: (0..SHARD_COUNT)
                .map(|_| ShardLock {
                    epoch: AtomicU64::new(0),
                    state: Mutex::new(ShardState::new()),
                })
                .collect(),
            hasher: RandomState::new(),
        }
    }

    #[must_use]
    pub fn epoch(&self, shard: u8) -> u64 {
        self.shards[usize::from(shard)]
            .epoch
            .load(Ordering::Acquire)
    }

    #[must_use]
    pub const fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        *self.resident.lock()
    }

    #[must_use]
    pub fn lookup(&self, key: &CoinKey) -> Option<Bytes> {
        let hash = self.hasher.hash_one(key.0);
        let mut shard = self.shards[usize::from(key.shard())].lock();
        let position = shard.position(key, hash)?;
        let entry = &mut shard.entries[position];
        entry.referenced = true;
        Some(entry.value.clone())
    }

    pub fn fill_after_read(&self, key: &CoinKey, value: Bytes) {
        self.fill_after_read_guarded(key, value, self.epoch(key.shard()));
    }

    pub fn fill_after_read_guarded(&self, key: &CoinKey, value: Bytes, expected_epoch: u64) {
        let shard_lock = &self.shards[usize::from(key.shard())];
        if shard_lock.epoch.load(Ordering::Acquire) != expected_epoch {
            return;
        }
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        if shard_lock.epoch.load(Ordering::Acquire) != expected_epoch {
            return;
        }
        let hash = self.hasher.hash_one(key.0);
        if let Some(position) = shard.position(key, hash) {
            shard.entries[position].referenced = true;
            return;
        }
        self.admit(&mut shard, &mut resident, key, value, hash);
    }

    fn grow(&self, shard: &mut ShardState, resident: &mut u64, value_bytes: u64) {
        let Some(capacity) = shard.entries.capacity().max(1).checked_mul(2) else {
            return;
        };
        let Some(bound) = table_reservation_bound(capacity).and_then(|table| {
            capacity
                .checked_mul(size_of::<ClockEntry>())?
                .checked_add(table)
        }) else {
            return;
        };
        if u64::try_from(bound).unwrap_or(u64::MAX)
            > self
                .budget_bytes
                .saturating_sub(*resident)
                .saturating_sub(value_bytes)
        {
            return;
        }
        let mut entries = Vec::new();
        if entries.try_reserve_exact(capacity).is_err() {
            return;
        }
        let Some(vector_bytes) = entries.capacity().checked_mul(size_of::<ClockEntry>()) else {
            return;
        };
        let Some(table_bound) = table_reservation_bound(capacity) else {
            return;
        };
        if u64::try_from(vector_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(table_bound).unwrap_or(u64::MAX))
            > self
                .budget_bytes
                .saturating_sub(*resident)
                .saturating_sub(value_bytes)
        {
            return;
        }
        let mut index = HashTable::new();
        if index.try_reserve(capacity, |_| 0).is_err() {
            return;
        }
        let new_backing = u64::try_from(vector_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(index.allocation_size()).unwrap_or(u64::MAX));
        if new_backing
            > self
                .budget_bytes
                .saturating_sub(*resident)
                .saturating_sub(value_bytes)
        {
            return;
        }
        for (slot, entry) in shard.entries.iter().enumerate() {
            index.insert_unique(self.hasher.hash_one(entry.key.0), slot, |&slot| {
                self.hasher.hash_one(shard.entries[slot].key.0)
            });
        }
        *resident -= shard.backing_bytes();
        entries.append(&mut shard.entries);
        shard.entries = entries;
        shard.index = index;
        *resident += shard.backing_bytes();
    }

    fn admit(
        &self,
        shard: &mut ShardState,
        resident: &mut u64,
        key: &CoinKey,
        value: Bytes,
        hash: u64,
    ) {
        let value_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
        if value_bytes > self.budget_bytes {
            return;
        }
        if shard.entries.len() == shard.entries.capacity()
            || shard.index.capacity() == shard.entries.len()
        {
            self.grow(shard, resident, value_bytes);
        }
        while !shard.entries.is_empty()
            && (value_bytes > self.budget_bytes.saturating_sub(*resident)
                || shard.entries.len() == shard.entries.capacity()
                || shard.index.capacity() == shard.entries.len())
        {
            *resident -= shard.evict(&self.hasher);
        }
        if value_bytes > self.budget_bytes.saturating_sub(*resident)
            || shard.entries.len() == shard.entries.capacity()
            || shard.index.capacity() == shard.entries.len()
        {
            return;
        }
        let slot = shard.entries.len();
        shard.entries.push(ClockEntry {
            key: *key,
            value,
            referenced: true,
        });
        shard.index.insert_unique(hash, slot, |&slot| {
            self.hasher.hash_one(shard.entries[slot].key.0)
        });
        *resident += value_bytes;
    }

    pub fn install(&self, key: &CoinKey, record: Option<Bytes>) {
        let shard_lock = &self.shards[usize::from(key.shard())];
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        let hash = self.hasher.hash_one(key.0);
        if let Some(position) = shard.position(key, hash) {
            *resident -= shard.remove(position, &self.hasher);
        }
        if let Some(value) = record {
            self.admit(&mut shard, &mut resident, key, value, hash);
        }
        shard_lock.epoch.fetch_add(1, Ordering::Release);
    }

    pub fn note_bytes(&self, shard_index: u8, bytes: usize) {
        let charge = u64::try_from(bytes).unwrap_or(u64::MAX);
        if charge > self.budget_bytes {
            return;
        }
        let mut resident = self.resident.lock();
        let mut shard = self.shards[usize::from(shard_index)].lock();
        while charge > self.budget_bytes.saturating_sub(*resident) && !shard.entries.is_empty() {
            *resident -= shard.evict(&self.hasher);
        }
        if charge <= self.budget_bytes.saturating_sub(*resident) {
            shard.overhead_bytes += charge;
            *resident += charge;
        }
    }

    pub fn evict_to_budget(&self) {
        let mut resident = self.resident.lock();
        for shard_lock in &self.shards {
            if *resident <= self.budget_bytes {
                break;
            }
            let mut shard = shard_lock.lock();
            while *resident > self.budget_bytes && !shard.entries.is_empty() {
                *resident -= shard.evict(&self.hasher);
            }
            if *resident > self.budget_bytes {
                *resident -= shard.backing_bytes();
                shard.entries = Vec::new();
                shard.index = HashTable::new();
            }
        }
    }

    pub fn clear(&self) {
        let mut resident = self.resident.lock();
        for shard_lock in &self.shards {
            *shard_lock.lock() = ShardState::new();
            shard_lock.epoch.fetch_add(1, Ordering::Release);
        }
        *resident = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StorageError;
    use proptest::prelude::*;

    fn key(tail: u8) -> CoinKey {
        let mut bytes = [7; 32];
        bytes[31] = tail;
        CoinKey(bytes)
    }

    #[test]
    fn engine_fill_is_readable_but_does_not_replace_existing_commit() {
        let cache = CoinCache::new(8_192);
        let k = key(0);
        cache.fill_after_read(&k, Bytes::from_static(b"engine"));
        assert_eq!(cache.lookup(&k).as_deref(), Some(b"engine".as_slice()));
        cache.install(&k, Some(Bytes::from_static(b"commit")));
        cache.fill_after_read(&k, Bytes::from_static(b"older"));
        assert_eq!(cache.lookup(&k).as_deref(), Some(b"commit".as_slice()));
        cache.install(&k, Some(Bytes::from(vec![0; 8_193])));
        assert_eq!(cache.lookup(&k), None);
        assert!(cache.resident_bytes() <= cache.budget_bytes());
    }

    #[test]
    fn turnover_replacement_and_delete_return_only_current_values() {
        let cache = CoinCache::new(8_192);
        for tail in 0..8_u8 {
            cache.install(&key(tail), Some(Bytes::from(vec![tail])));
        }
        for tail in 0..8_u8 {
            assert_eq!(cache.lookup(&key(tail)), Some(Bytes::from(vec![tail])));
        }
        cache.install(&key(1), None);
        assert_eq!(cache.lookup(&key(1)), None);
        for tail in (0..8_u8).filter(|&tail| tail != 1) {
            assert_eq!(cache.lookup(&key(tail)), Some(Bytes::from(vec![tail])));
        }
        cache.clear();
        for generation in 0..12_u8 {
            for tail in 0..64_u8 {
                let k = key(tail);
                let value = Bytes::from(vec![generation, tail]);
                cache.install(&k, Some(value.clone()));
                assert_eq!(cache.lookup(&k), Some(value));
                if tail % 3 == 0 {
                    cache.install(&k, None);
                    assert_eq!(cache.lookup(&k), None);
                }
            }
            for tail in 0..64_u8 {
                if let Some(value) = cache.lookup(&key(tail)) {
                    assert_ne!(tail % 3, 0);
                    assert_eq!(value.as_ref(), &[generation, tail]);
                }
            }
        }
    }

    #[test]
    fn stale_guarded_read_cannot_replace_commit_or_resurrect_delete() {
        let cache = CoinCache::new(8_192);
        let k = key(1);
        let epoch = cache.epoch(k.shard());
        cache.install(&k, Some(Bytes::from_static(b"new")));
        cache.fill_after_read_guarded(&k, Bytes::from_static(b"old"), epoch);
        assert_eq!(cache.lookup(&k).as_deref(), Some(b"new".as_slice()));
        let epoch = cache.epoch(k.shard());
        cache.install(&k, None);
        cache.fill_after_read_guarded(&k, Bytes::from_static(b"old"), epoch);
        assert_eq!(cache.lookup(&k), None);
    }

    #[test]
    fn empty_values_still_consume_budget_and_clear_releases_backing() -> Result<(), StorageError> {
        let cache = CoinCache::new(8_192);
        for tail in 0..=255 {
            cache.install(&key(tail), Some(Bytes::new()));
        }
        let hits = (0..=255)
            .filter(|&tail| cache.lookup(&key(tail)).is_some())
            .count();
        assert!(hits > 0 && hits < 256);
        let hit_key_bytes = u64::try_from(hits * size_of::<CoinKey>())
            .map_err(|_| StorageError::InvalidOperation("cache key bytes overflow"))?;
        assert!(cache.resident_bytes() >= hit_key_bytes);
        assert!(cache.resident_bytes() <= cache.budget_bytes());
        for tail in 0..=255 {
            cache.install(&key(tail), None);
        }
        assert!(cache.resident_bytes() > 0);
        cache.note_bytes(7, 8_192);
        assert!(cache.resident_bytes() <= cache.budget_bytes());
        cache.clear();
        assert_eq!(cache.resident_bytes(), 0);
        cache.note_bytes(7, 8_192);
        assert_eq!(cache.resident_bytes(), 8_192);
        cache.install(&key(0), Some(Bytes::new()));
        assert_eq!(cache.lookup(&key(0)), None);
        Ok(())
    }

    proptest! {
        #[test]
        fn full_key_turnover_preserves_latest_values(
            operations in prop::collection::vec((any::<[u8; 32]>(), any::<u8>(), any::<bool>()), 1..400),
        ) {
            let cache = CoinCache::new(16_384);
            let mut latest = std::collections::BTreeMap::new();
            for (mut bytes, value, delete) in operations {
                bytes[..8].fill(7);
                let k = CoinKey(bytes);
                if delete {
                    cache.install(&k, None);
                    latest.remove(&bytes);
                } else {
                    cache.install(&k, Some(Bytes::from(vec![value])));
                    latest.insert(bytes, value);
                }
                for (bytes, value) in &latest {
                    if let Some(hit) = cache.lookup(&CoinKey(*bytes)) {
                        prop_assert_eq!(hit.as_ref(), &[*value]);
                    }
                }
                prop_assert!(cache.resident_bytes() <= cache.budget_bytes());
            }
        }
    }
}
