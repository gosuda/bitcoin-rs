//! Generation publication and predicate-checked long-poll waits.

use super::CoordinatorState;
use super::GenerationKey;
use super::LONG_POLL_SLICE;
use super::MempoolSequenceWake;
use super::MiningCoordinator;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Hash256;
use compact_str::CompactString;
use std::sync::atomic::Ordering;

impl MiningCoordinator {
    /// Publishes the live generation key and wakes every long-poll / single-flight waiter.
    ///
    /// Callers must invoke this after every authoritative applied-tip or mempool
    /// mutation and before any dependent notification. The published key is
    /// captured from live applied-tip / mempool state under the coordinator lock.
    pub fn publish_generation(&self) {
        let key = self.live_generation_key();
        let mut state = self.state.lock();
        if let Some(previous) = state.published
            && previous != key
        {
            state.invalidate_key(previous);
        }
        state.published = Some(key);
        self.wake.notify_all();
    }

    /// Publishes a generation key built from `applied_tip` and `sequence`
    /// without taking the mempool read lock, then wakes all waiters.
    ///
    /// The mempool observer calls this with the sequence the mutation already
    /// produced, avoiding a reentrant pool read that can deadlock under the
    /// gateway's publish mutex. Tip-move callers should use
    /// [`Self::publish_generation`] instead, which captures the live sequence
    /// safely (no write lock is held on that path).
    pub fn publish_generation_from(&self, sequence: u64) {
        let tip_hash = self
            .applied_tip
            .load_full()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash);
        let key = GenerationKey {
            tip_hash,
            mempool_sequence: sequence,
        };
        let mut state = self.state.lock();
        if let Some(previous) = state.published
            && previous != key
        {
            state.invalidate_key(previous);
        }
        state.published = Some(key);
        self.wake.notify_all();
    }

    /// Reduces shutdown latency after the caller sets the shared shutdown flag.
    ///
    /// Correctness does not depend on this notification: every wait is bounded
    /// and rechecks the shutdown predicate.
    pub fn notify_shutdown(&self) {
        self.wake.notify_all();
    }

    pub(super) fn live_generation_key(&self) -> GenerationKey {
        let tip_hash = self
            .applied_tip
            .load_full()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash);
        let mempool_sequence = self.mempool.read().sequence_number();
        GenerationKey {
            tip_hash,
            mempool_sequence,
        }
    }

    pub(super) fn ensure_published(&self, state: &mut CoordinatorState) -> GenerationKey {
        let live = self.live_generation_key();
        if state.published != Some(live) {
            if let Some(previous) = state.published
                && previous != live
            {
                state.invalidate_key(previous);
            }
            state.published = Some(live);
        }
        live
    }

    pub(super) fn wait_for_generation_change(
        &self,
        waited: GenerationKey,
    ) -> Result<GenerationKey, MiningControlError> {
        let mut state = self.state.lock();
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let live = self.ensure_published(&mut state);
            if live != waited {
                return Ok(live);
            }
            let _ = self.wake.wait_for(&mut state, LONG_POLL_SLICE);
        }
    }
}

impl MempoolSequenceWake for MiningCoordinator {
    fn publish_generation_from(&self, sequence: u64) {
        Self::publish_generation_from(self, sequence);
    }
}

pub(super) fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
    let hash_hex = id.get(..64)?;
    let sequence = id.get(64..)?;
    if sequence.is_empty() {
        return None;
    }
    let tip_hash = Hash256::from_str_be(hash_hex).ok()?;
    let mempool_sequence = sequence.parse().ok()?;
    Some(GenerationKey {
        tip_hash,
        mempool_sequence,
    })
}
