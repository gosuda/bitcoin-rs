use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
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
    hand: usize,
    overhead_bytes: u64,
}

impl ShardState {
    fn entry_bytes(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| u64::try_from(entry.value.len()).unwrap_or(u64::MAX))
            .sum()
    }
}

/// Resident clock cache in front of the `coins` keyspace.
///
/// Invariant: resident bytes (entries plus overhead) never exceed the budget.
/// Invariant: only `install` (called after a durable receipt) and
/// `fill_after_read` (engine-returned committed bytes) may introduce or change
/// values; `lookup` never returns bytes that did not enter through those two
/// paths.
///
/// Lock order: the global resident counter first, then a shard lock. `lookup`
/// takes only a shard lock.
pub struct CoinCache {
    budget_bytes: u64,
    resident: Mutex<u64>,
    shards: Box<[ShardLock]>,
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

impl CoinCache {
    #[must_use]
    pub fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            resident: Mutex::new(0),
            shards: (0..SHARD_COUNT)
                .map(|_| ShardLock {
                    epoch: AtomicU64::new(0),
                    state: Mutex::new(ShardState {
                        entries: Vec::new(),
                        hand: 0,
                        overhead_bytes: 0,
                    }),
                })
                .collect(),
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
        let mut shard = self.shards[usize::from(key.shard())].lock();
        let position = shard.entries.iter().position(|entry| entry.key == *key)?;
        let entry = &mut shard.entries[position];
        entry.referenced = true;
        Some(entry.value.clone())
    }

    pub fn fill_after_read(&self, key: &CoinKey, value: Bytes) {
        let epoch = self.epoch(key.shard());
        self.fill_after_read_guarded(key, value, epoch);
    }

    pub fn fill_after_read_guarded(&self, key: &CoinKey, value: Bytes, expected_epoch: u64) {
        let shard_idx = usize::from(key.shard());
        let shard_lock = &self.shards[shard_idx];
        if shard_lock.epoch.load(Ordering::Acquire) != expected_epoch {
            return;
        }
        let value_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
        if value_bytes > self.budget_bytes {
            return;
        }
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        if shard_lock.epoch.load(Ordering::Acquire) != expected_epoch {
            return;
        }
        if let Some(entry) = shard.entries.iter_mut().find(|entry| entry.key == *key) {
            entry.referenced = true;
            return;
        }
        while *resident + value_bytes > self.budget_bytes && !shard.entries.is_empty() {
            let freed = clock_evict_one(&mut shard);
            *resident -= freed;
        }
        if *resident + value_bytes > self.budget_bytes {
            return;
        }
        shard.entries.push(ClockEntry {
            key: *key,
            value,
            referenced: true,
        });
        *resident += value_bytes;
    }

    pub fn install(&self, key: &CoinKey, record: Option<Bytes>) {
        let shard_idx = usize::from(key.shard());
        let shard_lock = &self.shards[shard_idx];
        let mut resident = self.resident.lock();
        let mut shard = shard_lock.lock();
        if let Some(position) = shard.entries.iter().position(|entry| entry.key == *key) {
            let removed = shard.entries.remove(position);
            fix_hand_after_removal(&mut shard, position);
            *resident -= u64::try_from(removed.value.len()).unwrap_or(0);
        }
        if let Some(value) = record {
            let value_bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
            if value_bytes <= self.budget_bytes {
                while *resident + value_bytes > self.budget_bytes && !shard.entries.is_empty() {
                    let freed = clock_evict_one(&mut shard);
                    *resident -= freed;
                }
                if *resident + value_bytes <= self.budget_bytes {
                    shard.entries.push(ClockEntry {
                        key: *key,
                        value,
                        referenced: true,
                    });
                    *resident += value_bytes;
                }
            }
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
        while *resident + charge > self.budget_bytes && !shard.entries.is_empty() {
            let freed = clock_evict_one(&mut shard);
            *resident -= freed;
        }
        if *resident + charge > self.budget_bytes {
            return;
        }
        shard.overhead_bytes += charge;
        *resident += charge;
    }

    pub fn evict_to_budget(&self) {
        let mut resident = self.resident.lock();
        while *resident > self.budget_bytes {
            let mut heaviest: Option<usize> = None;
            let mut heaviest_bytes = 0_u64;
            for (index, shard) in self.shards.iter().enumerate() {
                let bytes = shard.lock().entry_bytes();
                if bytes > heaviest_bytes {
                    heaviest_bytes = bytes;
                    heaviest = Some(index);
                }
            }
            let Some(index) = heaviest else {
                return;
            };
            let mut shard = self.shards[index].lock();
            let freed = clock_evict_one(&mut shard);
            *resident -= freed;
        }
    }

    pub fn clear(&self) {
        let mut resident = self.resident.lock();
        for shard_lock in &self.shards {
            let mut shard = shard_lock.lock();
            shard.entries.clear();
            shard.overhead_bytes = 0;
            shard.hand = 0;
            shard_lock.epoch.fetch_add(1, Ordering::Release);
        }
        *resident = 0;
    }
}

fn clock_evict_one(shard: &mut ShardState) -> u64 {
    loop {
        if shard.entries.is_empty() {
            return 0;
        }
        let hand = shard.hand % shard.entries.len();
        let referenced = shard.entries[hand].referenced;
        if referenced {
            shard.entries[hand].referenced = false;
            shard.hand = (hand + 1) % shard.entries.len();
            continue;
        }
        let evicted = shard.entries.remove(hand);
        fix_hand_after_removal(shard, hand);
        return u64::try_from(evicted.value.len()).unwrap_or(0);
    }
}

fn fix_hand_after_removal(shard: &mut ShardState, position: usize) {
    if position < shard.hand {
        shard.hand -= 1;
    }
    if shard.entries.is_empty() {
        shard.hand = 0;
    } else {
        shard.hand %= shard.entries.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(shard: u8, tail: u8) -> CoinKey {
        CoinKey([
            shard, tail, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ])
    }

    fn value(len: usize) -> Bytes {
        Bytes::from(vec![0xa5_u8; len])
    }

    #[test]
    fn fill_after_read_then_lookup_returns_value() {
        let cache = CoinCache::new(1_000);
        let k = key(3, 7);
        cache.fill_after_read(&k, value(120));
        assert_eq!(cache.resident_bytes(), 120);
        assert_eq!(cache.lookup(&k).as_deref(), Some(&[0xa5_u8; 120][..]));
        assert_eq!(cache.resident_bytes(), 120);
    }

    #[test]
    fn eviction_under_pressure_prefers_unreferenced_entries() {
        let cache = CoinCache::new(300);
        let k1 = key(1, 1);
        let k2 = key(1, 2);
        let k3 = key(1, 3);
        let k4 = key(1, 4);
        let k5 = key(1, 5);
        cache.fill_after_read(&k1, value(100));
        cache.fill_after_read(&k2, value(100));
        cache.fill_after_read(&k3, value(100));
        assert_eq!(cache.resident_bytes(), 300);

        cache.fill_after_read(&k4, value(100));
        assert!(cache.resident_bytes() <= 300);
        assert!(
            cache.lookup(&k1).is_none(),
            "one pass clears every armed bit and evicts at the hand"
        );

        assert!(
            cache.lookup(&k2).is_some(),
            "a lookup re-arms the entry for a second chance"
        );
        cache.fill_after_read(&k5, value(100));
        assert!(cache.resident_bytes() <= 300);
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
        assert_eq!(cache.resident_bytes(), 200);
        cache.install(&k, None);
        assert_eq!(cache.resident_bytes(), 0);
        assert!(cache.lookup(&k).is_none());
    }

    #[test]
    fn install_replaces_value_and_byte_count() {
        let cache = CoinCache::new(1_000);
        let k = key(2, 2);
        cache.install(&k, Some(value(100)));
        cache.install(&k, Some(value(400)));
        assert_eq!(cache.resident_bytes(), 400);
        assert_eq!(cache.lookup(&k).map(|v| v.len()), Some(400));
    }

    #[test]
    fn note_bytes_respects_budget_and_evicts() {
        let cache = CoinCache::new(300);
        let k = key(4, 4);
        cache.fill_after_read(&k, value(200));
        cache.note_bytes(4, 250);
        assert!(cache.resident_bytes() <= 300);
        assert!(
            cache.lookup(&k).is_none(),
            "overhead pressure evicts entries"
        );
        cache.note_bytes(4, 250);
        assert!(cache.lookup(&k).is_none(), "oversized charge is ignored");

        let cache = CoinCache::new(300);
        cache.fill_after_read(&k, value(100));
        cache.note_bytes(4, 100);
        assert_eq!(cache.resident_bytes(), 200);
    }

    #[test]
    fn evict_to_budget_is_noop_within_budget() {
        let cache = CoinCache::new(300);
        let k1 = key(5, 1);
        let k2 = key(6, 2);
        cache.fill_after_read(&k1, value(100));
        cache.fill_after_read(&k2, value(100));
        assert!(cache.lookup(&k1).is_some());
        cache.evict_to_budget();
        assert!(cache.resident_bytes() <= 300);
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
        let cache = CoinCache::new(200);
        let k = key(1, 1);
        cache.install(&k, Some(value(100)));
        assert_eq!(cache.resident_bytes(), 100);
        assert!(cache.lookup(&k).is_some());
        cache.install(&k, Some(value(300)));
        assert_eq!(cache.resident_bytes(), 0);
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

    #[derive(Clone, Debug)]
    enum Action {
        Fill(CoinKey, usize),
        InstallSome(CoinKey, usize),
        InstallNone(CoinKey),
        Lookup(CoinKey),
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
            2 => (coin_key_strategy(), 1_usize..=600_usize).prop_map(|(key, len)| Action::InstallSome(key, len)),
            1 => coin_key_strategy().prop_map(Action::InstallNone),
            3 => coin_key_strategy().prop_map(Action::Lookup),
            1 => (0_u8..8_u8, 1_usize..=600_usize).prop_map(|(shard, len)| Action::Note(shard, len)),
            1 => Just(Action::Evict),
            1 => Just(Action::Clear),
        ]
    }

    struct ModelCache {
        budget: u64,
        resident: u64,
        shards: Vec<ModelShard>,
    }

    struct ModelShard {
        entries: Vec<(CoinKey, u64, bool)>,
        hand: usize,
        overhead: u64,
    }

    impl ModelCache {
        fn new(budget: u64) -> Self {
            Self {
                budget,
                resident: 0,
                shards: (0..256)
                    .map(|_| ModelShard {
                        entries: Vec::new(),
                        hand: 0,
                        overhead: 0,
                    })
                    .collect(),
            }
        }

        fn admit(&mut self, key: &CoinKey, len: usize) {
            let len = u64::try_from(len).unwrap_or(u64::MAX);
            let shard = &mut self.shards[usize::from(key.shard())];
            if let Some(position) = shard.entries.iter().position(|(k, _, _)| k == key) {
                let (_, replaced, _) = shard.entries.remove(position);
                fix_model_hand(shard, position);
                self.resident -= replaced;
            }
            if len > self.budget {
                return;
            }
            while self.resident + len > self.budget && !shard.entries.is_empty() {
                let freed = model_evict_one(shard);
                self.resident -= freed;
            }
            if self.resident + len > self.budget {
                return;
            }
            shard.entries.push((*key, len, true));
            self.resident += len;
        }

        fn step(&mut self, action: &Action) -> Option<(bool, Option<u64>)> {
            match action {
                Action::Fill(key, len) => {
                    let shard = &mut self.shards[usize::from(key.shard())];
                    if let Some(entry) = shard.entries.iter_mut().find(|(k, _, _)| k == key) {
                        entry.2 = true;
                    } else {
                        self.admit(key, *len);
                    }
                }
                Action::InstallSome(key, len) => self.admit(key, *len),
                Action::InstallNone(key) => {
                    let shard = &mut self.shards[usize::from(key.shard())];
                    if let Some(position) = shard.entries.iter().position(|(k, _, _)| k == key) {
                        let (_, removed, _) = shard.entries.remove(position);
                        fix_model_hand(shard, position);
                        self.resident -= removed;
                    }
                }
                Action::Lookup(key) => {
                    let shard = &mut self.shards[usize::from(key.shard())];
                    return Some(match shard.entries.iter().position(|(k, _, _)| k == key) {
                        Some(position) => {
                            shard.entries[position].2 = true;
                            (true, Some(shard.entries[position].1))
                        }
                        None => (false, None),
                    });
                }
                Action::Note(shard_index, len) => {
                    let charge = u64::try_from(*len).unwrap_or(u64::MAX);
                    if charge > self.budget {
                        return None;
                    }
                    let shard = &mut self.shards[usize::from(*shard_index)];
                    while self.resident + charge > self.budget && !shard.entries.is_empty() {
                        let freed = model_evict_one(shard);
                        self.resident -= freed;
                    }
                    if self.resident + charge > self.budget {
                        return None;
                    }
                    shard.overhead += charge;
                    self.resident += charge;
                }
                Action::Evict => {
                    while self.resident > self.budget {
                        let mut heaviest: Option<usize> = None;
                        let mut heaviest_bytes = 0_u64;
                        for (index, shard) in self.shards.iter().enumerate() {
                            let bytes: u64 = shard.entries.iter().map(|(_, len, _)| *len).sum();
                            if bytes > heaviest_bytes {
                                heaviest_bytes = bytes;
                                heaviest = Some(index);
                            }
                        }
                        let Some(index) = heaviest else { break };
                        let freed = model_evict_one(&mut self.shards[index]);
                        self.resident -= freed;
                    }
                }
                Action::Clear => {
                    for shard in &mut self.shards {
                        shard.entries.clear();
                        shard.overhead = 0;
                        shard.hand = 0;
                    }
                    self.resident = 0;
                }
            }
            None
        }
    }

    fn model_evict_one(shard: &mut ModelShard) -> u64 {
        loop {
            if shard.entries.is_empty() {
                return 0;
            }
            let hand = shard.hand % shard.entries.len();
            if shard.entries[hand].2 {
                shard.entries[hand].2 = false;
                shard.hand = (hand + 1) % shard.entries.len();
                continue;
            }
            let (_, removed, _) = shard.entries.remove(hand);
            fix_model_hand(shard, hand);
            return removed;
        }
    }

    fn fix_model_hand(shard: &mut ModelShard, position: usize) {
        if position < shard.hand {
            shard.hand -= 1;
        }
        if shard.entries.is_empty() {
            shard.hand = 0;
        } else {
            shard.hand %= shard.entries.len();
        }
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
        fn coin_cache_never_exceeds_budget(
            budget in 1_u64..2_000_u64,
            actions in prop::collection::vec(action_strategy(), 1..400),
        ) {
            let cache = CoinCache::new(budget);
            let mut model = ModelCache::new(budget);
            for (step_index, action) in actions.iter().enumerate() {
                match action {
                    Action::Lookup(key) => {
                        let got = cache.lookup(key);
                        let Some((present, model_len)) = model.step(action) else {
                            unreachable!("lookup always models");
                        };
                        assert_eq!(got.is_some(), present, "step {step_index}");
                        let got_len = got.as_ref().map(Bytes::len);
                        let model_len = model_len.and_then(|len| usize::try_from(len).ok());
                        assert_eq!(got_len, model_len, "step {step_index}");
                    }
                    Action::Fill(key, len) => {
                        cache.fill_after_read(key, Bytes::from(vec![0xa5_u8; *len]));
                        model.step(action);
                    }
                    Action::InstallSome(key, len) => {
                        cache.install(key, Some(Bytes::from(vec![0xa5_u8; *len])));
                        model.step(action);
                    }
                    Action::InstallNone(key) => {
                        cache.install(key, None);
                        model.step(action);
                    }
                    Action::Note(shard_index, len) => {
                        cache.note_bytes(*shard_index, *len);
                        model.step(action);
                    }
                    Action::Evict => {
                        cache.evict_to_budget();
                        model.step(action);
                    }
                    Action::Clear => {
                        cache.clear();
                        model.step(action);
                    }
                }
                let resident = cache.resident_bytes();
                assert_eq!(resident, model.resident, "step {step_index} byte accounting");
                assert!(resident <= budget, "step {step_index} BUD-06");
            }
        }
    }
}
