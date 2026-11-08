use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
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

enum SeedEntry {
    Memory(Vec<u8>),
    Spill { offset: u64, len: usize },
}

#[derive(Default)]
struct SeedQueue {
    entries: VecDeque<SeedEntry>,
    memory_bytes: u64,
    spill: Option<File>,
    spill_path: Option<PathBuf>,
    spill_bytes: u64,
}

impl SeedQueue {
    fn push(&mut self, row: Vec<u8>) -> Result<(), IndexError> {
        let len = u64::try_from(row.len()).map_err(|_| IndexError::SeedBacklogStalled)?;
        if self.memory_bytes.saturating_add(len) <= SEED_BACKLOG_BYTES {
            self.memory_bytes = self.memory_bytes.saturating_add(len);
            self.entries.push_back(SeedEntry::Memory(row));
            return Ok(());
        }
        let spill = self.spill.as_mut().ok_or(IndexError::SeedBacklogStalled)?;
        let offset = self.spill_bytes;
        spill
            .seek(SeekFrom::Start(offset))
            .and_then(|_| spill.write_all(&row))
            .map_err(|_| IndexError::SeedBacklogStalled)?;
        self.spill_bytes = offset.saturating_add(len);
        self.entries.push_back(SeedEntry::Spill {
            offset,
            len: row.len(),
        });
        Ok(())
    }

    fn pop_batch(&mut self, max_rows: usize) -> Result<Vec<Vec<u8>>, IndexError> {
        let mut rows = Vec::new();
        while rows.len() < max_rows {
            let Some(entry) = self.entries.pop_front() else {
                break;
            };
            match entry {
                SeedEntry::Memory(row) => {
                    self.memory_bytes = self
                        .memory_bytes
                        .saturating_sub(u64::try_from(row.len()).unwrap_or(u64::MAX));
                    rows.push(row);
                }
                SeedEntry::Spill { offset, len } => {
                    let spill = self.spill.as_mut().ok_or(IndexError::SeedBacklogStalled)?;
                    let mut row = vec![0_u8; len];
                    spill
                        .seek(SeekFrom::Start(offset))
                        .and_then(|_| spill.read_exact(&mut row))
                        .map_err(|_| IndexError::SeedBacklogStalled)?;
                    rows.push(row);
                }
            }
        }
        Ok(rows)
    }

    fn reset(&mut self) {
        self.entries.clear();
        self.memory_bytes = 0;
        self.spill_bytes = 0;
        self.spill = None;
        if let Some(path) = self.spill_path.take() {
            let _removed = std::fs::remove_file(path);
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
        let path = dir.join(SEED_SPILL_NAME);
        queue.spill_path = Some(path.clone());
        queue.spill = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .ok();
    }

    /// The runtime installs its wake hook so staged rows reach the worker
    /// without waiting for the next external event.
    pub(crate) fn set_wake(&self, wake: Arc<dyn Fn() + Send + Sync>) {
        *self.wake.lock() = Some(wake);
    }

    fn notify_wake(&self, staged: u64) {
        if staged.is_multiple_of(SEED_WAKE_ROWS)
            && let Some(wake) = self.wake.lock().as_ref()
        {
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
        self.request_abort();
    }

    pub(crate) fn request_publish(&self, tip: IndexWatermark) {
        let mut phase = self.phase.lock();
        if matches!(*phase, ScriptLiveSeedPhase::Seeding) {
            *phase = ScriptLiveSeedPhase::PublishPending { tip };
        }
    }

    pub(crate) fn request_abort(&self) {
        let mut phase = self.phase.lock();
        if matches!(*phase, ScriptLiveSeedPhase::Seeding) {
            *phase = ScriptLiveSeedPhase::AbortPending;
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
        if let Err(source) = self.queue.lock().push(bytes) {
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
        assert_eq!(u64::try_from(seed.staged_rows()).expect("rows fit"), rows);
    }
}
