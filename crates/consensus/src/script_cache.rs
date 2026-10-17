//! Bounded script-execution cache for natively verified transactions.
//!
//! The mempool fills this cache after admitting a transaction under the next
//! block's script flags, and block connect consults it before building a
//! transaction's script checks: a hit skips re-execution of scripts the
//! admission path already verified. This mirrors Core's script-execution
//! cache (filling in `CheckInputsFromMempoolAndCache`, consulting in
//! `ConnectBlock`, `validation.cpp`), keyed by witness transaction id and
//! the exact flag bits.
//!
//! Soundness rests on two properties. First, script execution is a pure
//! function of the transaction, its prevouts, and the flags: an outpoint's
//! script and value are immutable once created, so a reorg can change which
//! outpoints are spendable but never what they contain; finality, amounts,
//! BIP68 locks, and sigop limits are NOT cached and always re-run. Second,
//! the key carries the exact flag bits, so any flag divergence between fill
//! and connect is a miss, never an unsound skip.
//!
//! Memory bound: at most [`SCRIPT_EXECUTION_CACHE_ENTRIES`] live keys in the
//! map, and the FIFO queue never exceeds twice that (a compaction retains
//! only live entries whenever the queue reaches the bound). Taken keys leave
//! one stale queue node each; the stale nodes are skipped during eviction and
//! reclaimed by compaction, so repeated insert/take/reinsert cycles cannot
//! grow either structure without bound.

use std::collections::{HashMap, VecDeque};

use bitcoin_rs_primitives::Wtxid;
use bitcoin_rs_script::VerifyFlags;
use parking_lot::Mutex;

/// Maximum live `(wtxid, flag-bits)` entries retained.
pub const SCRIPT_EXECUTION_CACHE_ENTRIES: usize = 1 << 18;

/// Queue length that triggers a live-only compaction (twice the live bound).
const QUEUE_COMPACT_LEN: usize = 2 * SCRIPT_EXECUTION_CACHE_ENTRIES;

type CacheKey = (Wtxid, u32);

struct Inner {
    /// Live keys mapped to their queue generation. Every live key owns
    /// exactly one queue node carrying the same generation; queue nodes
    /// whose generation disagrees are stale (taken or evicted) and skipped.
    live: HashMap<CacheKey, u64>,
    queue: VecDeque<(CacheKey, u64)>,
    next_generation: u64,
}

/// Bounded, shared script-execution result cache for the native engine.
///
/// `Send + Sync` so one instance is shared by the mempool gateway (fill) and
/// the chainstate connect path (consult). There is intentionally no signature
/// cache here: only full script executions verified under explicit flags are
/// recorded.
pub struct ScriptExecutionCache {
    inner: Mutex<Inner>,
}

impl ScriptExecutionCache {
    /// Creates an empty cache.
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

    /// Records a successful script execution of `wtxid` under `flags`.
    ///
    /// Re-inserting a live key is a no-op (no duplicate queue node), so the
    /// one-live-key-one-queue-node invariant — and with it the memory bound —
    /// holds under reinsertion pressure.
    pub fn insert(&self, wtxid: Wtxid, flags: VerifyFlags) {
        let key = (wtxid, flags.bits());
        let mut inner = self.inner.lock();
        if inner.live.contains_key(&key) {
            return;
        }
        if inner.live.len() >= SCRIPT_EXECUTION_CACHE_ENTRIES {
            evict_oldest_live(&mut inner);
        }
        // Disjoint field borrows through the guard: the queue compacts
        // against the live map without cloning either structure.
        if inner.queue.len() >= QUEUE_COMPACT_LEN {
            let Inner { live, queue, .. } = &mut *inner;
            queue.retain(|(key, generation)| live.get(key) == Some(generation));
        }
        let generation = inner.next_generation;
        inner.next_generation = generation.wrapping_add(1);
        inner.live.insert(key, generation);
        inner.queue.push_back((key, generation));
    }

    /// Removes `(wtxid, flags)` and reports whether it was present.
    ///
    /// Core erases a cache entry on block use; a hit fires exactly once and a
    /// second use re-verifies. The stale queue node is reclaimed by eviction
    /// or compaction.
    pub fn take(&self, wtxid: Wtxid, flags: VerifyFlags) -> bool {
        self.inner
            .lock()
            .live
            .remove(&(wtxid, flags.bits()))
            .is_some()
    }
}

/// Pops FIFO nodes until the oldest live entry is removed. Stale nodes left
/// behind by [`ScriptExecutionCache::take`] are skipped, so a taken key is
/// never counted toward eviction. Always terminates: every live key owns one
/// matching queue node, and the caller only evicts while a live key exists.
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

    /// Distinct cache keys for `0 <= i < SCRIPT_EXECUTION_CACHE_ENTRIES + 2`.
    /// The low four little-endian bytes are unique below 2^32 without any
    /// fallible conversion.
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
        // Take the oldest: the freed slot absorbs the next insert with no
        // eviction. One further insert crosses live capacity, and its
        // eviction must skip the taken key's stale queue node, dropping the
        // next-oldest live key instead.
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
        // Three full-capacity rounds flattened into one loop: takes interleave
        // with inserts and every key is reinserted under alternating flags.
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
