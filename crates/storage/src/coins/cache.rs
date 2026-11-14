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

    fn entry_bytes(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| u64::try_from(entry.value.len()).unwrap_or(u64::MAX))
            .sum()
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
///
/// The budget charges value lengths, actual vector and hash-table backing
/// allocations, and explicit `note_bytes` charges. It does not measure allocator
/// metadata, RSS, shared `Bytes` backing capacity, or the fixed shard directory.
/// Growth reserves room for old and new backing together before allocating,
/// using the hashbrown 0.17 layout bound below. `Vec::try_reserve_exact` may
/// overallocate; its reported capacity is checked before allocating the index.
/// Such allocator over-allocation can transiently exceed the reservation and
/// is rejected rather than retained.
///
/// Invariant: resident bytes (values, overhead, and retained backing) never
/// exceed the budget. Only `install` (called after a durable receipt) and
/// `fill_after_read_guarded` (engine-returned committed bytes) may introduce or
/// change values; `lookup` never returns bytes that did not enter through those
/// two paths.
///
/// Lock order: the node ledger is never held together with the resident or
/// shard locks. A mutation charges the ledger before locking, adjusts the
/// resident counter under the resident lock then the shard lock, and releases
/// evicted or refused charges after unlocking. The ledger balance tracks the
/// charged value and `note_bytes` bytes from an empty cache; retained vector
/// and hash-table backing is budget-tracked but never ledger-charged, so clear
/// and eviction release exactly the charged portion. Lookup takes only a shard
/// lock. The charge handle is fixed at construction.
pub struct CoinCache {
    budget_bytes: u64,
    resident: Mutex<u64>,
    shards: Box<[ShardLock]>,
    hasher: RandomState,
    charge: Option<super::super::budget::ChargeHandle>,
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
    #[cfg(test)]
    #[must_use]
    pub fn new(budget_bytes: u64) -> Self {
        Self::with_charge(budget_bytes, None)
    }

    #[must_use]
    pub fn with_charge(
        budget_bytes: u64,
        charge: Option<super::super::budget::ChargeHandle>,
    ) -> Self {
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
            charge,
        }
    }

    fn charge_delta(&self, bytes: u64) -> bool {
        let Some(handle) = self.charge.clone() else {
            return true;
        };
        handle.charge(bytes).is_ok()
    }

    fn release_delta(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Some(handle) = self.charge.clone() {
            handle.release(bytes);
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

    #[cfg(test)]
    pub fn fill_after_read(&self, key: &CoinKey, value: Bytes) {
        self.fill_after_read_guarded(key, value, self.epoch(key.shard()));
    }

    pub fn fill_after_read_guarded(&self, key: &CoinKey, value: Bytes, expected_epoch: u64) {
        let shard_lock = &self.shards[usize::from(key.shard())];
        if shard_lock.epoch.load(Ordering::Acquire) != expected_epoch {
            return;
        }
        let value_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
        let Some(charged) = self.charge_with_eviction(shard_lock, Some(value_bytes)) else {
            return;
        };
        let (admitted, freed) = self.insert_fresh_locked(shard_lock, key, value, expected_epoch);
        self.release_delta(freed);
        if !admitted {
            self.release_delta(charged);
        }
    }

    fn insert_fresh_locked(
        &self,
        shard_lock: &ShardLock,
        key: &CoinKey,
        value: Bytes,
        expected_epoch: u64,
    ) -> (bool, u64) {
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        if shard_lock.epoch.load(Ordering::Acquire) != expected_epoch {
            return (false, 0);
        }
        let hash = self.hasher.hash_one(key.0);
        if let Some(position) = shard.position(key, hash) {
            shard.entries[position].referenced = true;
            return (false, 0);
        }
        self.admit_locked(&mut shard, &mut resident, key, value, hash)
    }

    /// Replaces the entry for `key`. The old entry always leaves the cache
    /// and the shard epoch always advances, even when the new value is
    /// refused, so a stale read can never survive an install.
    pub fn install(&self, key: &CoinKey, record: Option<Bytes>) {
        let released_prior = self.remove_resident_locked(key);
        self.release_delta(released_prior);
        let wanted = record
            .as_ref()
            .map(|value| u64::try_from(value.len()).unwrap_or(u64::MAX));
        let charged = self.charge_with_eviction(&self.shards[usize::from(key.shard())], wanted);
        let value = record.filter(|_| charged.is_some());
        let (inserted, released) = self.replace_locked(key, value);
        self.release_delta(released);
        if let Some(bytes) = charged {
            if !inserted {
                self.release_delta(bytes);
            }
        }
    }

    fn charge_with_eviction(&self, shard_lock: &ShardLock, wanted: Option<u64>) -> Option<u64> {
        let bytes = wanted?;
        if bytes > self.budget_bytes {
            return None;
        }
        if !self.charge_delta(bytes) {
            let available = self.charge.as_ref().map_or(0, |handle| handle.available());
            let freed = self.evict_room_locked(shard_lock, bytes.saturating_sub(available));
            self.release_delta(freed);
            if !self.charge_delta(bytes) {
                return None;
            }
        }
        Some(bytes)
    }

    fn evict_room_locked(&self, shard_lock: &ShardLock, needed: u64) -> u64 {
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        let mut freed = 0_u64;
        while freed < needed && !shard.entries.is_empty() {
            let evicted = shard.evict(&self.hasher);
            freed += evicted;
            *resident -= evicted;
        }
        freed
    }

    fn remove_resident_locked(&self, key: &CoinKey) -> u64 {
        let shard_lock = &self.shards[usize::from(key.shard())];
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        let hash = self.hasher.hash_one(key.0);
        let Some(position) = shard.position(key, hash) else {
            return 0;
        };
        let bytes = shard.remove(position, &self.hasher);
        *resident -= bytes;
        shard_lock.epoch.fetch_add(1, Ordering::Release);
        bytes
    }

    fn replace_locked(&self, key: &CoinKey, value: Option<Bytes>) -> (bool, u64) {
        let shard_lock = &self.shards[usize::from(key.shard())];
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        let mut released = 0_u64;
        let hash = self.hasher.hash_one(key.0);
        if let Some(position) = shard.position(key, hash) {
            let bytes = shard.remove(position, &self.hasher);
            *resident -= bytes;
            released += bytes;
        }
        shard_lock.epoch.fetch_add(1, Ordering::Release);
        let Some(value) = value else {
            return (false, released);
        };
        let (inserted, freed) = self.admit_locked(&mut shard, &mut resident, key, value, hash);
        released += freed;
        (inserted, released)
    }

    pub fn note_bytes(&self, shard_index: u8, bytes: usize) {
        let charge = u64::try_from(bytes).unwrap_or(u64::MAX);
        let shard_lock = &self.shards[usize::from(shard_index)];
        let Some(charged) = self.charge_with_eviction(shard_lock, Some(charge)) else {
            return;
        };
        let (admitted, freed) = self.note_locked(shard_index, charged);
        self.release_delta(freed);
        if !admitted {
            self.release_delta(charged);
        }
    }

    fn note_locked(&self, shard_index: u8, charge: u64) -> (bool, u64) {
        let mut resident = self.resident.lock();
        let mut shard = self.shards[usize::from(shard_index)].lock();
        let mut freed = 0_u64;
        while *resident + charge > self.budget_bytes && !shard.entries.is_empty() {
            let evicted = shard.evict(&self.hasher);
            freed += evicted;
            *resident -= evicted;
        }
        if *resident + charge > self.budget_bytes {
            return (false, freed);
        }
        shard.overhead_bytes += charge;
        *resident += charge;
        (true, freed)
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

    /// Runs under the resident lock then the shard lock.
    fn admit_locked(
        &self,
        shard: &mut ShardState,
        resident: &mut u64,
        key: &CoinKey,
        value: Bytes,
        hash: u64,
    ) -> (bool, u64) {
        let value_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
        if value_bytes > self.budget_bytes {
            return (false, 0);
        }
        if shard.entries.len() == shard.entries.capacity()
            || shard.index.capacity() == shard.entries.len()
        {
            self.grow(shard, resident, value_bytes);
        }
        let mut freed = 0_u64;
        while !shard.entries.is_empty()
            && (value_bytes > self.budget_bytes.saturating_sub(*resident)
                || shard.entries.len() == shard.entries.capacity()
                || shard.index.capacity() == shard.entries.len())
        {
            let evicted = shard.evict(&self.hasher);
            freed += evicted;
            *resident -= evicted;
        }
        if value_bytes > self.budget_bytes.saturating_sub(*resident)
            || shard.entries.len() == shard.entries.capacity()
            || shard.index.capacity() == shard.entries.len()
        {
            return (false, freed);
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
        (true, freed)
    }

    pub fn evict_to_budget(&self) {
        let charged_freed = {
            let mut resident = self.resident.lock();
            let freed = self.evict_value_bytes_above_budget(&mut resident);
            self.release_retained_backing_above_budget(&mut resident);
            freed
        };
        self.release_delta(charged_freed);
    }

    fn evict_value_bytes_above_budget(&self, resident: &mut u64) -> u64 {
        let mut freed = 0_u64;
        while *resident > self.budget_bytes {
            let Some(index) = self.heaviest_value_shard() else {
                break;
            };
            let mut shard = self.shards[index].lock();
            let evicted = shard.evict(&self.hasher);
            freed += evicted;
            *resident -= evicted;
        }
        freed
    }

    fn heaviest_value_shard(&self) -> Option<usize> {
        let mut heaviest: Option<usize> = None;
        let mut heaviest_bytes = 0_u64;
        for (index, shard) in self.shards.iter().enumerate() {
            let bytes = shard.lock().entry_bytes();
            if bytes > heaviest_bytes {
                heaviest_bytes = bytes;
                heaviest = Some(index);
            }
        }
        heaviest
    }

    fn release_retained_backing_above_budget(&self, resident: &mut u64) {
        while *resident > self.budget_bytes {
            let Some(backing) = self.drop_first_retained_backing() else {
                break;
            };
            *resident -= backing;
        }
    }

    fn drop_first_retained_backing(&self) -> Option<u64> {
        for shard_lock in &self.shards {
            let mut shard = shard_lock.lock();
            let backing = shard.backing_bytes();
            if backing == 0 {
                continue;
            }
            shard.entries = Vec::new();
            shard.index = HashTable::new();
            shard.hand = 0;
            return Some(backing);
        }
        None
    }

    pub fn clear(&self) {
        let charged_bytes = {
            let mut guard = self.resident.lock();
            let mut backing_total = 0_u64;
            for shard_lock in &self.shards {
                let mut shard = shard_lock.lock();
                backing_total += shard.backing_bytes();
                *shard = ShardState::new();
                shard_lock.epoch.fetch_add(1, Ordering::Release);
            }
            std::mem::replace(&mut *guard, 0).saturating_sub(backing_total)
        };
        self.release_delta(charged_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StorageError;
    use crate::budget::{BudgetCharge, BudgetError, BudgetOwner, ChargeHandle};
    use proptest::prelude::*;
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Arc;

    fn key(shard: u8, tail: u8) -> CoinKey {
        CoinKey([
            shard, tail, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ])
    }

    fn value(len: usize) -> Bytes {
        Bytes::from(vec![0xa5_u8; len])
    }

    fn backing_of(cache: &CoinCache, shard: u8) -> u64 {
        cache.shards[usize::from(shard)].lock().backing_bytes()
    }

    #[test]
    fn engine_fill_is_readable_but_does_not_replace_existing_commit() {
        let cache = CoinCache::new(8_192);
        let k = key(7, 0);
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
            cache.install(&key(7, tail), Some(Bytes::from(vec![tail])));
        }
        for tail in 0..8_u8 {
            assert_eq!(cache.lookup(&key(7, tail)), Some(Bytes::from(vec![tail])));
        }
        cache.install(&key(7, 1), None);
        assert_eq!(cache.lookup(&key(7, 1)), None);
        for tail in (0..8_u8).filter(|&tail| tail != 1) {
            assert_eq!(cache.lookup(&key(7, tail)), Some(Bytes::from(vec![tail])));
        }
        cache.clear();
        for generation in 0..12_u8 {
            for tail in 0..64_u8 {
                let k = key(7, tail);
                let value = Bytes::from(vec![generation, tail]);
                cache.install(&k, Some(value.clone()));
                assert_eq!(cache.lookup(&k), Some(value));
                if tail % 3 == 0 {
                    cache.install(&k, None);
                    assert_eq!(cache.lookup(&k), None);
                }
            }
            for tail in 0..64_u8 {
                if let Some(value) = cache.lookup(&key(7, tail)) {
                    assert_ne!(tail % 3, 0);
                    assert_eq!(value.as_ref(), &[generation, tail]);
                }
            }
        }
    }

    #[test]
    fn stale_guarded_read_cannot_replace_commit_or_resurrect_delete() {
        let cache = CoinCache::new(8_192);
        let k = key(7, 1);
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
            cache.install(&key(7, tail), Some(Bytes::new()));
        }
        let hits = (0..=255)
            .filter(|&tail| cache.lookup(&key(7, tail)).is_some())
            .count();
        assert!(hits > 0 && hits < 256);
        let hit_key_bytes = u64::try_from(hits * size_of::<CoinKey>())
            .map_err(|_| StorageError::InvalidOperation("cache key bytes overflow"))?;
        assert!(cache.resident_bytes() >= hit_key_bytes);
        assert!(cache.resident_bytes() <= cache.budget_bytes());
        for tail in 0..=255 {
            cache.install(&key(7, tail), None);
        }
        assert!(cache.resident_bytes() > 0);
        cache.note_bytes(7, 8_192);
        assert!(cache.resident_bytes() <= cache.budget_bytes());
        cache.clear();
        assert_eq!(cache.resident_bytes(), 0);
        cache.note_bytes(7, 8_192);
        assert_eq!(cache.resident_bytes(), 8_192);
        cache.install(&key(7, 0), Some(Bytes::new()));
        assert_eq!(cache.lookup(&key(7, 0)), None);
        Ok(())
    }

    #[test]
    fn fill_after_read_then_lookup_returns_value() {
        let cache = CoinCache::new(1_000);
        let k = key(3, 7);
        cache.fill_after_read(&k, value(120));
        assert_eq!(
            cache.resident_bytes(),
            120 + backing_of(&cache, 3),
            "resident tracks value bytes plus retained backing"
        );
        assert_eq!(cache.lookup(&k).as_deref(), Some(&[0xa5_u8; 120][..]));
        assert_eq!(cache.resident_bytes(), 120 + backing_of(&cache, 3));
    }

    #[test]
    fn eviction_under_pressure_prefers_unreferenced_entries() {
        let cache = CoinCache::new(4_000);
        let k1 = key(1, 1);
        let k2 = key(1, 2);
        let k3 = key(1, 3);
        let k4 = key(1, 4);
        let k5 = key(1, 5);
        cache.fill_after_read(&k1, value(1_000));
        cache.fill_after_read(&k2, value(1_000));
        cache.fill_after_read(&k3, value(1_000));
        assert_eq!(
            cache.resident_bytes(),
            3_000 + backing_of(&cache, 1),
            "three fills land exactly once each"
        );

        cache.fill_after_read(&k4, value(1_000));
        assert!(cache.resident_bytes() <= 4_000);
        assert!(
            cache.lookup(&k1).is_none(),
            "one pass clears every armed bit and evicts at the hand"
        );

        assert!(
            cache.lookup(&k2).is_some(),
            "a lookup re-arms the entry for a second chance"
        );
        cache.fill_after_read(&k5, value(1_000));
        assert!(cache.resident_bytes() <= 4_000);
        assert_eq!(cache.resident_bytes(), 3_000 + backing_of(&cache, 1));
        assert!(cache.lookup(&k2).is_some(), "armed entry survives one pass");
        assert!(
            cache.lookup(&k3).is_none(),
            "unreferenced entry evicted before the armed one"
        );
        assert!(cache.lookup(&k4).is_some());
        assert!(cache.lookup(&k5).is_some());
    }

    #[test]
    fn install_delete_removes_resident_entry() {
        let cache = CoinCache::new(1_000);
        let k = key(9, 9);
        cache.install(&k, Some(value(200)));
        assert_eq!(cache.resident_bytes(), 200 + backing_of(&cache, 9));
        cache.install(&k, None);
        assert_eq!(
            cache.resident_bytes(),
            backing_of(&cache, 9),
            "only the charged value bytes leave; backing is retained"
        );
        assert!(cache.lookup(&k).is_none());
    }

    #[test]
    fn install_replaces_value_and_byte_count() {
        let cache = CoinCache::new(1_000);
        let k = key(2, 2);
        cache.install(&k, Some(value(100)));
        cache.install(&k, Some(value(400)));
        assert_eq!(cache.resident_bytes(), 400 + backing_of(&cache, 2));
        assert_eq!(cache.lookup(&k).map(|v| v.len()), Some(400));
    }

    #[test]
    fn note_bytes_respects_budget_and_evicts() {
        let cache = CoinCache::new(1_000);
        let k = key(4, 4);
        cache.fill_after_read(&k, value(200));
        cache.note_bytes(4, 750);
        assert!(
            cache.lookup(&k).is_none(),
            "overhead pressure evicts entries"
        );
        assert!(cache.resident_bytes() <= 1_000);
        let before_oversize = cache.resident_bytes();
        cache.note_bytes(4, 2_000);
        assert_eq!(
            cache.resident_bytes(),
            before_oversize,
            "oversized charge is ignored"
        );

        let cache = CoinCache::new(1_000);
        cache.fill_after_read(&k, value(100));
        cache.note_bytes(4, 100);
        assert_eq!(cache.resident_bytes(), 200 + backing_of(&cache, 4));
    }

    #[test]
    fn evict_to_budget_is_noop_within_budget() {
        let cache = CoinCache::new(4_000);
        let k1 = key(5, 1);
        let k2 = key(6, 2);
        cache.fill_after_read(&k1, value(1_000));
        cache.fill_after_read(&k2, value(1_000));
        assert!(cache.lookup(&k1).is_some());
        cache.evict_to_budget();
        assert!(cache.resident_bytes() <= 4_000);
        assert!(cache.lookup(&k1).is_some());
        assert!(cache.lookup(&k2).is_some());
    }

    #[test]
    fn clear_drops_every_entry() {
        let cache = CoinCache::new(1_000);
        let k1 = key(7, 1);
        let k2 = key(8, 2);
        cache.install(&k1, Some(value(100)));
        cache.install(&k2, Some(value(200)));
        cache.note_bytes(7, 50);
        cache.clear();
        assert_eq!(cache.resident_bytes(), 0);
        assert!(cache.lookup(&k1).is_none());
        assert!(cache.lookup(&k2).is_none());
    }

    #[test]
    fn oversized_entries_never_reside() {
        let cache = CoinCache::new(100);
        let k = key(1, 1);
        cache.fill_after_read(&k, value(101));
        assert_eq!(cache.resident_bytes(), 0);
        assert!(cache.lookup(&k).is_none());
    }

    #[test]
    fn oversized_committed_replacement_evicts_old_resident_entry() {
        let cache = CoinCache::new(1_200);
        let k = key(1, 1);
        cache.install(&k, Some(value(100)));
        assert_eq!(cache.resident_bytes(), 100 + backing_of(&cache, 1));
        assert!(cache.lookup(&k).is_some());
        cache.install(&k, Some(value(300)));
        assert_eq!(cache.resident_bytes(), 300 + backing_of(&cache, 1));
        assert_eq!(cache.lookup(&k).map(|v| v.len()), Some(300));
        cache.install(&k, Some(value(1_300)));
        assert_eq!(cache.resident_bytes(), backing_of(&cache, 1));
        assert!(
            cache.lookup(&k).is_none(),
            "oversized replacement purges the old entry"
        );
    }

    #[test]
    fn stale_read_fill_does_not_overwrite_newer_commit() {
        let cache = CoinCache::new(1_000);
        let k = key(2, 5);
        let epoch = cache.epoch(k.shard());
        let v_new = Bytes::from_static(b"new-committed-value");
        cache.install(&k, Some(v_new.clone()));
        assert_eq!(cache.lookup(&k), Some(v_new.clone()));

        let v_stale = Bytes::from_static(b"old-stale-value");
        cache.fill_after_read_guarded(&k, v_stale.clone(), epoch);
        assert_eq!(
            cache.lookup(&k),
            Some(v_new),
            "stale read fill must not overwrite newer commit"
        );

        let epoch_before_delete = cache.epoch(k.shard());
        cache.install(&k, None);
        assert!(cache.lookup(&k).is_none());
        cache.fill_after_read_guarded(&k, v_stale, epoch_before_delete);
        assert!(
            cache.lookup(&k).is_none(),
            "stale read fill must not resurrect deleted coin"
        );
    }

    #[derive(Default)]
    struct CappedLedger {
        outstanding: Mutex<u64>,
    }

    const LEDGER_CAP: u64 = 301_024;

    impl BudgetCharge for CappedLedger {
        fn reserve_bytes(&self, _owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
            let mut outstanding = self.outstanding.lock();
            let next = outstanding.saturating_add(bytes);
            if next > LEDGER_CAP {
                return Err(BudgetError::BudgetExhausted);
            }
            *outstanding = next;
            Ok(())
        }

        fn allocate_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
            Ok(())
        }

        fn release_bytes(&self, _owner: BudgetOwner, bytes: u64) {
            let mut outstanding = self.outstanding.lock();
            *outstanding = outstanding.saturating_sub(bytes);
        }

        fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
            LEDGER_CAP - *self.outstanding.lock()
        }
    }

    fn equal_cap_cache() -> (CoinCache, Arc<CappedLedger>) {
        let ledger = Arc::new(CappedLedger::default());
        let cache = CoinCache::with_charge(
            LEDGER_CAP,
            Some(ChargeHandle::new(ledger.clone(), BudgetOwner::CoinCache)),
        );
        (cache, ledger)
    }

    fn ledger_outstanding(ledger: &CappedLedger) -> u64 {
        *ledger.outstanding.lock()
    }

    // BUD-07
    #[test]
    fn equal_cap_fill_evicts_charged_bytes_to_admit_new_key() {
        let (cache, ledger) = equal_cap_cache();
        let k1 = key(1, 1);
        let k2 = key(1, 2);
        let k3 = key(1, 3);
        let k4 = key(1, 4);
        cache.fill_after_read(&k1, value(100_000));
        cache.fill_after_read(&k2, value(100_000));
        cache.fill_after_read(&k3, value(100_000));
        assert_eq!(ledger_outstanding(&ledger), 300_000);
        assert_eq!(cache.resident_bytes(), 300_000 + backing_of(&cache, 1));

        cache.fill_after_read(&k4, value(100_000));
        assert_eq!(
            ledger_outstanding(&ledger) + backing_of(&cache, 1),
            cache.resident_bytes(),
            "ledger mirrors exactly the charged value bytes, no leak"
        );
        assert_eq!(cache.resident_bytes(), 300_000 + backing_of(&cache, 1));
        assert!(
            cache.lookup(&k4).is_some(),
            "a full ledger must not stall turnover the clock can fund"
        );
        assert!(cache.lookup(&k1).is_none());
        assert!(cache.lookup(&k2).is_some());
        assert!(cache.lookup(&k3).is_some());
    }

    // BUD-07
    #[test]
    fn equal_cap_install_releases_old_charge_and_turns_over() {
        let (cache, ledger) = equal_cap_cache();
        let k1 = key(1, 1);
        let k2 = key(1, 2);
        let k3 = key(1, 3);
        cache.fill_after_read(&k1, value(100_000));
        cache.fill_after_read(&k2, value(100_000));
        cache.fill_after_read(&k3, value(100_000));
        assert_eq!(ledger_outstanding(&ledger), 300_000);
        assert_eq!(cache.resident_bytes(), 300_000 + backing_of(&cache, 1));

        cache.install(&k1, Some(value(150_000)));
        assert_eq!(cache.lookup(&k1).map(|entry| entry.len()), Some(150_000));
        let survivors = [&k2, &k3]
            .into_iter()
            .filter(|k| cache.lookup(k).is_some())
            .count();
        assert_eq!(survivors, 1, "clock eviction funds the larger replacement");
        let resident = cache.resident_bytes();
        assert_eq!(resident, 250_000 + backing_of(&cache, 1));
        assert_eq!(
            ledger_outstanding(&ledger) + backing_of(&cache, 1),
            resident,
            "old charge released before the replacement is charged, no leak"
        );

        let k9 = key(1, 9);
        let Ok(overlarge) = usize::try_from(LEDGER_CAP + 1) else {
            panic!("ledger cap does not fit usize");
        };
        cache.install(&k9, Some(value(overlarge)));
        assert!(cache.lookup(&k9).is_none(), "overlarge items stay rejected");
        assert_eq!(cache.lookup(&k1).map(|entry| entry.len()), Some(150_000));
        assert_eq!(cache.resident_bytes(), 250_000 + backing_of(&cache, 1));
        assert_eq!(ledger_outstanding(&ledger), 250_000);
    }

    #[derive(Clone, Debug)]
    enum Action {
        Fill(CoinKey, usize),
        InstallSome(CoinKey, usize),
        InstallNone(CoinKey),
        Note(u8, usize),
        Evict,
        Clear,
    }

    fn coin_key_strategy() -> impl Strategy<Value = CoinKey> {
        (0_u8..8, proptest::array::uniform32(any::<u8>())).prop_map(|(shard, mut bytes)| {
            bytes[0] = shard;
            CoinKey(bytes)
        })
    }

    fn action_strategy() -> impl Strategy<Value = Action> {
        prop_oneof![
            6 => (coin_key_strategy(), 1_usize..=600_usize).prop_map(|(key, len)| Action::Fill(key, len)),
            3 => (coin_key_strategy(), 1_usize..=600_usize).prop_map(|(key, len)| Action::InstallSome(key, len)),
            2 => coin_key_strategy().prop_map(Action::InstallNone),
            1 => (0_u8..8_u8, 1_usize..=600_usize).prop_map(|(shard, len)| Action::Note(shard, len)),
            1 => Just(Action::Evict),
            1 => Just(Action::Clear),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256),
            ..ProptestConfig::default()
        })]
        #[test]
        fn full_key_turnover_preserves_latest_values(
            budget in 2_000_u64..16_000_u64,
            actions in prop::collection::vec(action_strategy(), 1..400),
        ) {
            let cache = CoinCache::new(budget);
            let mut latest: BTreeMap<CoinKey, Bytes> = BTreeMap::new();
            let mut filled_since_commit: HashSet<CoinKey> = HashSet::new();
            for (step_index, action) in actions.iter().enumerate() {
                match action {
                    Action::Fill(key, len) => {
                        cache.fill_after_read(key, Bytes::from(vec![0xa5_u8; *len]));
                        filled_since_commit.insert(*key);
                    }
                    Action::InstallSome(key, len) => {
                        let value = Bytes::from(vec![0xa5_u8; *len]);
                        cache.install(key, Some(value.clone()));
                        latest.insert(*key, value);
                        filled_since_commit.remove(key);
                    }
                    Action::InstallNone(key) => {
                        cache.install(key, None);
                        latest.remove(key);
                        filled_since_commit.remove(key);
                    }
                    Action::Note(shard_index, len) => {
                        cache.note_bytes(*shard_index, *len);
                    }
                    Action::Evict => {
                        cache.evict_to_budget();
                    }
                    Action::Clear => {
                        cache.clear();
                        latest.clear();
                        filled_since_commit.clear();
                    }
                }
                for (key, committed) in &latest {
                    if filled_since_commit.contains(key) {
                        continue;
                    }
                    if let Some(hit) = cache.lookup(key) {
                        prop_assert_eq!(
                            &hit,
                            committed,
                            "step {}: resident value diverges from the latest commit",
                            step_index
                        );
                    }
                }
                let resident = cache.resident_bytes();
                prop_assert!(resident <= budget, "step {step_index} BUD-06");
            }
        }
    }
}
