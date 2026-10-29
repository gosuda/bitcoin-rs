//! Bounded script-execution cache for natively verified transactions.

use std::collections::{HashMap, VecDeque};

use bitcoin_rs_primitives::Wtxid;
use bitcoin_rs_script::VerifyFlags;
use parking_lot::Mutex;

/// Maximum live `(wtxid, flag-bits)` entries retained.
pub const SCRIPT_EXECUTION_CACHE_ENTRIES: usize = 1 << 18;

const QUEUE_COMPACT_LEN: usize = 2 * SCRIPT_EXECUTION_CACHE_ENTRIES;

type CacheKey = (Wtxid, u32);

struct Inner {
    live: HashMap<CacheKey, u64>,
    queue: VecDeque<(CacheKey, u64)>,
    next_generation: u64,
}

pub struct ScriptExecutionCache {
    inner: Mutex<Inner>,
}

impl ScriptExecutionCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                live: HashMap::new(),
                queue: VecDeque::new(),
                next_generation: 0,
            }),
        }
    }

    pub fn insert(&self, wtxid: Wtxid, flags: VerifyFlags) {
        let key = (wtxid, flags.bits());
        let mut inner = self.inner.lock();
        if inner.live.contains_key(&key) {
            return;
        }
        if inner.live.len() >= SCRIPT_EXECUTION_CACHE_ENTRIES {
            evict_oldest_live(&mut inner);
        }
        if inner.queue.len() >= QUEUE_COMPACT_LEN {
            let Inner { live, queue, .. } = &mut *inner;
            queue.retain(|(key, generation)| live.get(key) == Some(generation));
        }
        let generation = inner.next_generation;
        inner.next_generation = generation.wrapping_add(1);
        inner.live.insert(key, generation);
        inner.queue.push_back((key, generation));
    }

    pub fn take(&self, wtxid: Wtxid, flags: VerifyFlags) -> bool {
        self.inner
            .lock()
            .live
            .remove(&(wtxid, flags.bits()))
            .is_some()
    }
}

pub struct WindowCacheTakes<'a> {
    cache: &'a ScriptExecutionCache,
    taken: Vec<(Wtxid, VerifyFlags)>,
}

impl<'a> WindowCacheTakes<'a> {
    pub fn new(cache: &'a ScriptExecutionCache) -> Self {
        Self {
            cache,
            taken: Vec::new(),
        }
    }

    pub fn take(&mut self, wtxid: Wtxid, flags: VerifyFlags) -> bool {
        let hit = self.cache.take(wtxid, flags);
        if hit {
            self.taken.push((wtxid, flags));
        }
        hit
    }

    pub fn rollback(self) {
        self.rollback_to(0);
    }

    pub fn checkpoint(&self) -> usize {
        self.taken.len()
    }

    pub fn rollback_to(self, pos: usize) {
        for (wtxid, flags) in self.taken.into_iter().skip(pos) {
            self.cache.insert(wtxid, flags);
        }
    }
}

fn evict_oldest_live(inner: &mut Inner) {
    while let Some((old_key, old_generation)) = inner.queue.pop_front() {
        if inner.live.get(&old_key) == Some(&old_generation) {
            inner.live.remove(&old_key);
            return;
        }
    }
}

impl Default for ScriptExecutionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ScriptExecutionCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScriptExecutionCache")
            .field("live", &self.inner.lock().live.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::Hash256;

    fn key(i: usize) -> Wtxid {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&i.to_le_bytes()[..4]);
        Wtxid(Hash256::from_le_bytes(&bytes))
    }

    fn live_len(cache: &ScriptExecutionCache) -> usize {
        cache.inner.lock().live.len()
    }

    fn queue_len(cache: &ScriptExecutionCache) -> usize {
        cache.inner.lock().queue.len()
    }

    #[test]
    fn insert_then_take_hits_exactly_once() {
        let cache = ScriptExecutionCache::new();
        cache.insert(key(1), VerifyFlags::MANDATORY);
        assert!(cache.take(key(1), VerifyFlags::MANDATORY));
        assert!(!cache.take(key(1), VerifyFlags::MANDATORY));
    }

    #[test]
    fn different_flags_miss_and_leave_the_entry_live() {
        let cache = ScriptExecutionCache::new();
        cache.insert(key(2), VerifyFlags::MANDATORY);
        assert!(!cache.take(key(2), VerifyFlags::P2SH));
        assert!(!cache.take(key(2), VerifyFlags::STANDARD));
        assert!(cache.take(key(2), VerifyFlags::MANDATORY));
    }

    #[test]
    fn reinserting_a_live_key_adds_no_second_queue_node() {
        let cache = ScriptExecutionCache::new();
        cache.insert(key(3), VerifyFlags::MANDATORY);
        cache.insert(key(3), VerifyFlags::MANDATORY);
        assert_eq!(live_len(&cache), 1);
        assert_eq!(queue_len(&cache), 1);
        assert!(cache.take(key(3), VerifyFlags::MANDATORY));
    }

    #[test]
    fn capacity_plus_one_evicts_the_oldest() {
        let cache = ScriptExecutionCache::new();
        for i in 0..SCRIPT_EXECUTION_CACHE_ENTRIES {
            cache.insert(key(i), VerifyFlags::MANDATORY);
        }
        assert_eq!(live_len(&cache), SCRIPT_EXECUTION_CACHE_ENTRIES);
        cache.insert(key(SCRIPT_EXECUTION_CACHE_ENTRIES), VerifyFlags::MANDATORY);
        assert_eq!(live_len(&cache), SCRIPT_EXECUTION_CACHE_ENTRIES);
        assert!(!cache.take(key(0), VerifyFlags::MANDATORY));
        assert!(cache.take(key(1), VerifyFlags::MANDATORY));
        assert!(cache.take(key(SCRIPT_EXECUTION_CACHE_ENTRIES), VerifyFlags::MANDATORY));
    }

    #[test]
    fn taken_keys_are_not_counted_toward_eviction() {
        let cache = ScriptExecutionCache::new();
        for i in 0..SCRIPT_EXECUTION_CACHE_ENTRIES {
            cache.insert(key(i), VerifyFlags::MANDATORY);
        }
        assert!(cache.take(key(0), VerifyFlags::MANDATORY));
        cache.insert(key(SCRIPT_EXECUTION_CACHE_ENTRIES), VerifyFlags::MANDATORY);
        assert_eq!(live_len(&cache), SCRIPT_EXECUTION_CACHE_ENTRIES);
        cache.insert(
            key(SCRIPT_EXECUTION_CACHE_ENTRIES + 1),
            VerifyFlags::MANDATORY,
        );
        assert_eq!(live_len(&cache), SCRIPT_EXECUTION_CACHE_ENTRIES);
        assert!(!cache.take(key(0), VerifyFlags::MANDATORY));
        assert!(!cache.take(key(1), VerifyFlags::MANDATORY));
        assert!(cache.take(key(2), VerifyFlags::MANDATORY));
        assert!(cache.take(key(SCRIPT_EXECUTION_CACHE_ENTRIES), VerifyFlags::MANDATORY));
        assert!(cache.take(
            key(SCRIPT_EXECUTION_CACHE_ENTRIES + 1),
            VerifyFlags::MANDATORY
        ));
    }

    #[test]
    fn insert_take_reinsert_cycles_keep_both_structures_bounded() {
        let cache = ScriptExecutionCache::new();
        let rounds = 3;
        for n in 0..rounds * SCRIPT_EXECUTION_CACHE_ENTRIES {
            let i = n % (SCRIPT_EXECUTION_CACHE_ENTRIES + 1);
            let flags = if i.is_multiple_of(2) {
                VerifyFlags::MANDATORY
            } else {
                VerifyFlags::P2SH
            };
            cache.insert(key(i), flags);
            if i.is_multiple_of(3) {
                cache.take(key(i), flags);
            }
        }
        assert!(live_len(&cache) <= SCRIPT_EXECUTION_CACHE_ENTRIES);
        assert!(queue_len(&cache) <= QUEUE_COMPACT_LEN);
    }
}
