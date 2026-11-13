use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;

use bitcoin_rs_consensus::primitives::{OutPoint, Txid};
use bitcoin_rs_storage::utxo::{SnapshotCoin, SnapshotCoinObserver};

use crate::{IndexError, IndexWatermark, ScriptHash, types::ScriptLiveRow};

pub struct ScriptLiveSeedState {
    phase: Mutex<ScriptLiveSeedPhase>,
    staged: AtomicU64,
    error: Mutex<Option<IndexError>>,
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    queue: Mutex<SeedQueue>,
    reset_pending: AtomicBool,
    closed: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptLiveSeedPhase {
    Idle,
    Seeding,
    PublishPending { tip: IndexWatermark },
    AbortPending,
}

/// SNP-06: the decode runs inside `NodeState::open`, before any index worker
/// exists, so staging must never wait for a consumer. Rows queue in memory up
/// to a byte budget and then spill to a scratch file, so the retained memory
/// stays bounded while a full mainnet coin set still stages.
const SEED_BACKLOG_BYTES: u64 = 16 * 1024 * 1024;
const SEED_SPILL_NAME: &str = "script-live-seed.spill";
const SEED_WAKE_ROWS: u64 = 16_384;
const SEED_SPILL_FRAME_BYTES: usize = size_of::<u64>();

#[derive(Default)]
struct SeedQueue {
    pending: VecDeque<Vec<u8>>,
    memory_bytes: u64,
    spill: Option<File>,
    spill_read: u64,
    spill_write: u64,
}

impl SeedQueue {
    fn push(&mut self, row: Vec<u8>) -> Result<(), IndexError> {
        let len = u64::try_from(row.len()).map_err(|_| IndexError::SeedBacklogStalled)?;
        if self.spill_read == self.spill_write
            && self.memory_bytes.saturating_add(len) <= SEED_BACKLOG_BYTES
        {
            self.memory_bytes = self.memory_bytes.saturating_add(len);
            self.pending.push_back(row);
            return Ok(());
        }
        self.append_spilled(&row, len)
    }

    fn append_spilled(&mut self, row: &[u8], len: u64) -> Result<(), IndexError> {
        let frame_bytes =
            u64::try_from(SEED_SPILL_FRAME_BYTES).map_err(|_| IndexError::SeedBacklogStalled)?;
        let spill = self.spill.as_mut().ok_or(IndexError::SeedBacklogStalled)?;
        spill
            .seek(SeekFrom::Start(self.spill_write))
            .and_then(|_| spill.write_all(&len.to_le_bytes()))
            .and_then(|_| spill.write_all(row))
            .map_err(|_| IndexError::SeedBacklogStalled)?;
        self.spill_write = self
            .spill_write
            .saturating_add(frame_bytes)
            .saturating_add(len);
        Ok(())
    }

    fn pop_batch(&mut self, max_rows: usize) -> Result<Vec<Vec<u8>>, IndexError> {
        let mut rows = Vec::new();
        while rows.len() < max_rows {
            if let Some(row) = self.pending.pop_front() {
                self.memory_bytes = self
                    .memory_bytes
                    .saturating_sub(u64::try_from(row.len()).unwrap_or(u64::MAX));
                rows.push(row);
                continue;
            }
            if self.spill_read == self.spill_write {
                break;
            }
            rows.push(self.take_spilled()?);
        }
        Ok(rows)
    }

    fn take_spilled(&mut self) -> Result<Vec<u8>, IndexError> {
        let frame_bytes =
            u64::try_from(SEED_SPILL_FRAME_BYTES).map_err(|_| IndexError::SeedBacklogStalled)?;
        let spill = self.spill.as_mut().ok_or(IndexError::SeedBacklogStalled)?;
        let mut frame = [0_u8; SEED_SPILL_FRAME_BYTES];
        spill
            .seek(SeekFrom::Start(self.spill_read))
            .and_then(|_| spill.read_exact(&mut frame))
            .map_err(|_| IndexError::SeedBacklogStalled)?;
        let frame_len = u64::from_le_bytes(frame);
        let remaining = self
            .spill_write
            .saturating_sub(self.spill_read)
            .saturating_sub(frame_bytes);
        if frame_len > SEED_BACKLOG_BYTES || frame_len > remaining {
            return Err(IndexError::SeedBacklogStalled);
        }
        let row_len = usize::try_from(frame_len).map_err(|_| IndexError::SeedBacklogStalled)?;
        let mut row = vec![0_u8; row_len];
        spill
            .read_exact(&mut row)
            .map_err(|_| IndexError::SeedBacklogStalled)?;
        self.spill_read = self
            .spill_read
            .saturating_add(frame_bytes)
            .saturating_add(frame_len);
        Ok(row)
    }

    fn reset(&mut self) {
        self.pending.clear();
        self.memory_bytes = 0;
        self.spill_read = 0;
        self.spill_write = 0;
        if let Some(spill) = self.spill.as_mut() {
            let _truncated = spill
                .set_len(0)
                .and_then(|_| spill.seek(SeekFrom::Start(0)));
        }
    }
}

impl Default for ScriptLiveSeedState {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptLiveSeedState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase: Mutex::new(ScriptLiveSeedPhase::Idle),
            staged: AtomicU64::new(0),
            error: Mutex::new(None),
            wake: Mutex::new(None),
            queue: Mutex::new(SeedQueue::default()),
            reset_pending: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    /// SNP-06: staging spills into this directory once its memory budget is
    /// spent, so a mainnet coin set stages without holding it resident.
    pub fn set_spill_dir(&self, dir: &std::path::Path) {
        let mut queue = self.queue.lock();
        queue.spill = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(dir.join(SEED_SPILL_NAME))
            .ok();
    }

    /// The runtime installs its wake hook so staged rows reach the worker
    /// without waiting for the next external event.
    pub(crate) fn set_wake(&self, wake: Arc<dyn Fn() + Send + Sync>) {
        *self.wake.lock() = Some(wake);
    }

    fn notify_wake(&self, staged: u64) {
        if staged.is_multiple_of(SEED_WAKE_ROWS) {
            self.wake_worker();
        }
    }

    /// SNP-07: the one owner for worker wake on seed lifecycle changes. The
    /// caller publishes the new state first, and the callback runs with neither
    /// the phase lock, the queue lock, nor the wake lock held.
    fn wake_worker(&self) {
        let wake = self.wake.lock().clone();
        if let Some(wake) = wake {
            wake();
        }
    }

    #[must_use]
    pub fn phase(&self) -> ScriptLiveSeedPhase {
        self.phase.lock().clone()
    }

    #[must_use]
    pub fn staged_rows(&self) -> u64 {
        self.staged.load(Ordering::Acquire)
    }

    pub fn begin_session(self: &Arc<Self>) -> Result<ScriptLiveSeedSession, IndexError> {
        let mut phase = self.phase.lock();
        if !matches!(*phase, ScriptLiveSeedPhase::Idle) {
            return Err(IndexError::SeedAlreadyActive);
        }
        self.staged.store(0, Ordering::Release);
        *self.error.lock() = None;
        self.queue.lock().reset();
        self.reset_pending.store(true, Ordering::Release);
        self.closed.store(false, Ordering::Release);
        *phase = ScriptLiveSeedPhase::Seeding;
        drop(phase);
        Ok(ScriptLiveSeedSession {
            state: Arc::clone(self),
        })
    }

    /// SNP-07: a new session starts from an empty queue, so rows left by an
    /// interrupted seed must be cleared once before the first staged batch.
    pub(crate) fn claim_row_reset(&self) -> bool {
        self.reset_pending.swap(false, Ordering::AcqRel)
    }

    /// Holds the phase lock while the worker clears rows left by an
    /// interrupted seed; `begin_session` blocks on the same lock, so a decode
    /// that starts right after the clear keeps its rows.
    pub(crate) fn lock_idle(&self) -> Option<parking_lot::MutexGuard<'_, ScriptLiveSeedPhase>> {
        let guard = self.phase.lock();
        matches!(*guard, ScriptLiveSeedPhase::Idle).then_some(guard)
    }

    pub(crate) fn take_backlog(&self, max_rows: usize) -> Result<Vec<Vec<u8>>, IndexError> {
        self.queue.lock().pop_batch(max_rows)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn close_session(&self) {
        self.closed.store(true, Ordering::Release);
        self.request_transition(ScriptLiveSeedPhase::AbortPending);
    }

    pub(crate) fn request_publish(&self, tip: IndexWatermark) {
        self.request_transition(ScriptLiveSeedPhase::PublishPending { tip });
    }

    pub(crate) fn request_abort(&self) {
        self.request_transition(ScriptLiveSeedPhase::AbortPending);
    }

    /// SNP-07: publishes the requested transition, then wakes the worker. A
    /// closed session always wakes, because an abort requested before the drop
    /// may have woken a worker that found staging still open and the queue
    /// empty, and no later end-of-stream event would reach it.
    fn request_transition(&self, next: ScriptLiveSeedPhase) {
        let transitioned = {
            let mut phase = self.phase.lock();
            if matches!(*phase, ScriptLiveSeedPhase::Seeding) {
                *phase = next;
                true
            } else {
                false
            }
        };
        if transitioned || self.is_closed() {
            self.wake_worker();
        }
    }

    pub(crate) fn complete_publish(&self) {
        let mut phase = self.phase.lock();
        if matches!(*phase, ScriptLiveSeedPhase::PublishPending { .. }) {
            *phase = ScriptLiveSeedPhase::Idle;
            self.staged.store(0, Ordering::Release);
            self.queue.lock().reset();
        }
    }

    pub(crate) fn complete_abort(&self) {
        let mut phase = self.phase.lock();
        if matches!(*phase, ScriptLiveSeedPhase::AbortPending) {
            *phase = ScriptLiveSeedPhase::Idle;
            self.staged.store(0, Ordering::Release);
            self.queue.lock().reset();
        }
    }

    /// SNP-06: a dropped row would corrupt the ScriptLive base, so every
    /// refusal is sticky and fails the decode closed.
    fn stage(&self, coin: &SnapshotCoin<'_>) {
        let mut error = self.error.lock();
        if error.is_some() {
            return;
        }
        if self.is_closed() {
            *error = Some(IndexError::SeedChannelClosed);
            return;
        }
        let bytes = match Self::encode_row(coin) {
            Ok(bytes) => bytes,
            Err(source) => {
                *error = Some(source);
                return;
            }
        };
        let pushed = self.queue.lock().push(bytes);
        if let Err(source) = pushed {
            *error = Some(source);
            return;
        }
        drop(error);
        let staged = self.staged.fetch_add(1, Ordering::AcqRel) + 1;
        self.notify_wake(staged);
    }

    fn encode_row(coin: &SnapshotCoin<'_>) -> Result<Vec<u8>, IndexError> {
        let scripthash = ScriptHash::from_script_bytes(coin.script_pubkey);
        let outpoint = OutPoint::new(Txid::from(coin.txid), coin.vout);
        let row = ScriptLiveRow::new(scripthash, &outpoint);
        let coin_val =
            crate::types::ScriptLiveCoin::new(scripthash, coin.value, coin.height, coin.coinbase);
        let mut encoded = coin_val.encode_value()?;
        let mut bytes = Vec::with_capacity(crate::types::SCRIPT_LIVE_ROW_SIZE + encoded.len());
        bytes.extend_from_slice(row.as_bytes());
        bytes.append(&mut encoded);
        Ok(bytes)
    }
}

/// Node-side handle from [`ScriptLiveSeedState::begin_session`]. Dropping the
/// session closes staging, so the worker observes end-of-stream before it
/// publishes or aborts.
pub struct ScriptLiveSeedSession {
    state: Arc<ScriptLiveSeedState>,
}

impl ScriptLiveSeedSession {
    #[must_use]
    pub fn observer(&self) -> ScriptLiveSeedObserver<'_> {
        ScriptLiveSeedObserver { session: self }
    }

    #[must_use]
    pub fn staged_rows(&self) -> u64 {
        self.state.staged_rows()
    }

    #[must_use]
    pub fn take_error(&self) -> Option<IndexError> {
        self.state.error.lock().take()
    }

    pub fn publish(&self, tip: IndexWatermark) {
        self.state.request_publish(tip);
    }

    pub fn abort(&self) {
        self.state.request_abort();
    }
}

impl Drop for ScriptLiveSeedSession {
    fn drop(&mut self) {
        self.state.close_session();
    }
}

pub struct ScriptLiveSeedObserver<'a> {
    session: &'a ScriptLiveSeedSession,
}

impl SnapshotCoinObserver for ScriptLiveSeedObserver<'_> {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        self.session.state.stage(&coin);
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::Hash256;

    const SEED_CHANNEL_ROWS: usize = 65_536;

    fn coin(index: u64) -> SnapshotCoin<'static> {
        let mut txid = [0_u8; 32];
        txid[..8].copy_from_slice(&index.to_le_bytes());
        SnapshotCoin {
            txid: Hash256::from_le_bytes(&txid),
            vout: 0,
            value: 1,
            script_pubkey: &[0x51],
            height: 0,
            coinbase: false,
        }
    }

    // SNP-06, SNP-07
    #[test]
    fn decode_does_not_stall_without_a_worker() {
        let seed = Arc::new(ScriptLiveSeedState::new());
        let session = seed.begin_session().expect("session");
        let mut observer = session.observer();
        for index in 0..=u64::try_from(SEED_CHANNEL_ROWS).expect("rows fit") {
            observer.observe_coin(coin(index));
        }
        assert!(
            session.take_error().is_none(),
            "decode stalled because no worker drained the bounded seed channel"
        );
        assert_eq!(
            session.staged_rows(),
            u64::try_from(SEED_CHANNEL_ROWS).expect("rows fit") + 1
        );
    }

    // SNP-06
    #[test]
    fn spilled_rows_keep_decode_order() {
        let dir = tempfile::tempdir().expect("spill dir");
        let seed = Arc::new(ScriptLiveSeedState::new());
        seed.set_spill_dir(dir.path());
        let session = seed.begin_session().expect("session");
        let rows = 40_000_u64;
        {
            let mut observer = session.observer();
            for index in 0..rows {
                observer.observe_coin(coin(index));
            }
        }
        assert!(session.take_error().is_none());
        let drained = seed.take_backlog(usize::MAX).expect("drained rows");
        assert_eq!(
            u64::try_from(drained.len()).expect("rows fit"),
            rows,
            "every staged row must survive staging"
        );
        assert_eq!(seed.staged_rows(), rows);
    }

    // SNP-06
    #[test]
    fn a_new_session_keeps_the_spill_file() {
        let dir = tempfile::tempdir().expect("spill dir");
        let seed = Arc::new(ScriptLiveSeedState::new());
        seed.set_spill_dir(dir.path());
        let rows = 400_000_u64;
        let session = seed.begin_session().expect("session");
        {
            let mut observer = session.observer();
            for index in 0..rows {
                observer.observe_coin(coin(index));
            }
        }
        assert!(
            session.take_error().is_none(),
            "staging beyond the memory budget must spill instead of stalling"
        );
        let drained = seed.take_backlog(usize::MAX).expect("drained rows");
        assert_eq!(
            usize::try_from(rows).expect("rows fit"),
            drained.len(),
            "every staged row must survive the spill"
        );
        assert_eq!(
            drained.first().expect("first row"),
            &ScriptLiveSeedState::encode_row(&coin(0)).expect("encode first row"),
            "the first staged row must round-trip"
        );
        assert_eq!(
            drained.last().expect("last row"),
            &ScriptLiveSeedState::encode_row(&coin(rows - 1)).expect("encode last row"),
            "the last staged row must round-trip"
        );
        drop(session);
        seed.complete_abort();
        let next = seed.begin_session().expect("next session");
        {
            let mut observer = next.observer();
            for index in 0..rows {
                observer.observe_coin(coin(index));
            }
        }
        assert!(
            next.take_error().is_none(),
            "a session after a reset must still spill instead of stalling"
        );
        let refilled = seed.take_backlog(usize::MAX).expect("drained rows");
        assert_eq!(
            usize::try_from(rows).expect("rows fit"),
            refilled.len(),
            "every refilled row must survive the spill"
        );
        assert_eq!(
            refilled.last().expect("last refilled row"),
            &ScriptLiveSeedState::encode_row(&coin(rows - 1)).expect("encode last row"),
            "the last refilled row must round-trip"
        );
    }

    // SNP-06
    #[test]
    fn spilled_backlog_keeps_push_order_across_interleaved_drain_and_refill() {
        const ROW_BYTES: usize = 512 * 1024;
        let dir = tempfile::tempdir().expect("spill dir");
        let mut queue = SeedQueue {
            spill: Some(
                File::options()
                    .create(true)
                    .truncate(true)
                    .read(true)
                    .write(true)
                    .open(dir.path().join(SEED_SPILL_NAME))
                    .expect("spill file"),
            ),
            ..SeedQueue::default()
        };
        let row_bytes = u64::try_from(ROW_BYTES).expect("row fits");
        let retained_rows =
            usize::try_from(SEED_BACKLOG_BYTES.div_ceil(row_bytes)).expect("bound fits");

        fn stage(queue: &mut SeedQueue, tag: u64, row_bytes: usize, retained_rows: usize) {
            let mut row = vec![0_u8; row_bytes];
            row[..size_of::<u64>()].copy_from_slice(&tag.to_le_bytes());
            queue
                .push(row)
                .expect("staging with a spill file must not stall");
            assert!(
                queue.memory_bytes <= SEED_BACKLOG_BYTES,
                "retained staging bytes must stay within the backlog budget"
            );
            assert!(
                queue.pending.len() <= retained_rows,
                "retained queue state must stay bounded while rows spill"
            );
        }

        fn drain(queue: &mut SeedQueue, max_rows: usize) -> Vec<u64> {
            queue
                .pop_batch(max_rows)
                .expect("draining staged rows must not stall")
                .iter()
                .map(|row| {
                    u64::from_le_bytes(row[..size_of::<u64>()].try_into().expect("tag prefix"))
                })
                .collect()
        }

        let mut drained: Vec<u64> = Vec::new();
        for tag in 0..40_u64 {
            stage(&mut queue, tag, ROW_BYTES, retained_rows);
        }
        assert!(
            queue.spill_read < queue.spill_write,
            "rows large enough to exhaust the memory budget must spill"
        );
        drained.extend(drain(&mut queue, 8));
        for tag in 40..80_u64 {
            stage(&mut queue, tag, ROW_BYTES, retained_rows);
        }
        drained.extend(drain(&mut queue, 24));
        for tag in 80..128_u64 {
            stage(&mut queue, tag, ROW_BYTES, retained_rows);
        }
        loop {
            let batch = drain(&mut queue, 9);
            if batch.is_empty() {
                break;
            }
            drained.extend(batch);
        }
        assert_eq!(queue.pending.len(), 0);
        assert_eq!(queue.memory_bytes, 0);
        assert_eq!(queue.spill_read, queue.spill_write);
        let expected: Vec<u64> = (0..128_u64).collect();
        assert_eq!(
            drained, expected,
            "rows must drain in staged order across interleaved drain and refill"
        );
    }

    // SNP-07
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SeedWake {
        phase: ScriptLiveSeedPhase,
        closed: bool,
    }

    fn watch_wakes(seed: &Arc<ScriptLiveSeedState>) -> Arc<Mutex<Vec<SeedWake>>> {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let cb_seed = Arc::downgrade(seed);
        let cb_observed = Arc::clone(&observed);
        seed.set_wake(Arc::new(move || {
            let Some(cb_seed) = cb_seed.upgrade() else {
                return;
            };
            let sample = SeedWake {
                phase: cb_seed.phase(),
                closed: cb_seed.is_closed(),
            };
            cb_observed.lock().push(sample);
        }));
        observed
    }

    // SNP-07
    #[test]
    fn dropped_session_wakes_worker_with_abort_pending() {
        let seed = Arc::new(ScriptLiveSeedState::new());
        let observed = watch_wakes(&seed);
        let session = seed.begin_session().expect("session");
        {
            let mut observer = session.observer();
            observer.observe_coin(coin(0));
        }
        assert!(
            observed.lock().is_empty(),
            "staging below the wake threshold must not wake the worker"
        );
        drop(session);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
        assert_eq!(
            *observed.lock(),
            vec![SeedWake {
                phase: ScriptLiveSeedPhase::AbortPending,
                closed: true,
            }],
            "closing the session must wake the worker with the abort and the close visible"
        );
    }

    // SNP-07
    #[test]
    fn abort_before_drop_wakes_on_the_close_transition() {
        let seed = Arc::new(ScriptLiveSeedState::new());
        let observed = watch_wakes(&seed);
        let session = seed.begin_session().expect("session");
        {
            let mut observer = session.observer();
            observer.observe_coin(coin(0));
            observer.observe_coin(coin(1));
        }
        session.abort();
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
        assert!(!seed.is_closed(), "an abort must not close staging");
        assert_eq!(
            *observed.lock(),
            vec![SeedWake {
                phase: ScriptLiveSeedPhase::AbortPending,
                closed: false,
            }],
            "the abort wake must observe the pending abort while staging is open"
        );
        drop(session);
        assert!(seed.is_closed());
        assert_eq!(
            *observed.lock(),
            vec![
                SeedWake {
                    phase: ScriptLiveSeedPhase::AbortPending,
                    closed: false,
                },
                SeedWake {
                    phase: ScriptLiveSeedPhase::AbortPending,
                    closed: true,
                },
            ],
            "closing an already-aborted session must wake the worker with the close visible"
        );
        assert_eq!(
            seed.take_backlog(usize::MAX).expect("staged rows").len(),
            2,
            "an aborted seed keeps its staged rows for the discard pass"
        );
        seed.complete_abort();
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0);
        assert!(
            seed.take_backlog(usize::MAX)
                .expect("drained rows")
                .is_empty(),
            "completing the abort must clear the staged rows"
        );
    }

    // SNP-07
    #[test]
    fn publish_wakes_worker_before_the_session_drops() {
        let seed = Arc::new(ScriptLiveSeedState::new());
        let observed = watch_wakes(&seed);
        let session = seed.begin_session().expect("session");
        {
            let mut observer = session.observer();
            observer.observe_coin(coin(0));
        }
        let tip = IndexWatermark {
            height: 7,
            hash: [0x11; 32],
        };
        session.publish(tip);
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::PublishPending { tip });
        assert!(!seed.is_closed(), "publishing must not close staging");
        assert_eq!(
            *observed.lock(),
            vec![SeedWake {
                phase: ScriptLiveSeedPhase::PublishPending { tip },
                closed: false,
            }],
            "publishing must wake the worker with the pending tip visible"
        );
        drop(session);
        assert_eq!(
            *observed.lock(),
            vec![
                SeedWake {
                    phase: ScriptLiveSeedPhase::PublishPending { tip },
                    closed: false,
                },
                SeedWake {
                    phase: ScriptLiveSeedPhase::PublishPending { tip },
                    closed: true,
                },
            ],
            "closing a published session must wake the worker with the close visible"
        );
        let rows = seed.take_backlog(usize::MAX).expect("staged rows");
        assert_eq!(
            rows,
            vec![ScriptLiveSeedState::encode_row(&coin(0)).expect("encoded row")],
            "publishing keeps the staged rows for the publish pass"
        );
        seed.complete_publish();
        assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
        assert_eq!(seed.staged_rows(), 0);
        assert!(
            seed.take_backlog(usize::MAX)
                .expect("drained rows")
                .is_empty(),
            "completing the publish must clear the staged rows"
        );
    }
}
