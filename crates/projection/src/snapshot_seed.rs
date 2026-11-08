use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crossbeam_channel::{Receiver, SendTimeoutError, bounded};
use parking_lot::Mutex;

use bitcoin_rs_consensus::primitives::{OutPoint, Txid};
use bitcoin_rs_storage::utxo::{SnapshotCoin, SnapshotCoinObserver};

use crate::{IndexError, IndexWatermark, ScriptHash, types::ScriptLiveRow};

pub struct ScriptLiveSeedState {
    phase: Mutex<ScriptLiveSeedPhase>,
    rows: Mutex<Option<Receiver<Vec<u8>>>>,
    staged: AtomicU64,
    error: Mutex<Option<IndexError>>,
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptLiveSeedPhase {
    Idle,
    Seeding,
    PublishPending { tip: IndexWatermark },
    AbortPending,
}

const SEED_CHANNEL_ROWS: usize = 65_536;
const SEED_SEND_TIMEOUT: Duration = Duration::from_secs(1);
const SEED_SEND_RETRIES: u32 = 60;
const SEED_WAKE_ROWS: u64 = 16_384;

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
            rows: Mutex::new(None),
            staged: AtomicU64::new(0),
            error: Mutex::new(None),
            wake: Mutex::new(None),
        }
    }

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
        let (sender, receiver) = bounded(SEED_CHANNEL_ROWS);
        *self.rows.lock() = Some(receiver);
        *phase = ScriptLiveSeedPhase::Seeding;
        drop(phase);
        Ok(ScriptLiveSeedSession {
            sender: Some(sender),
            state: Arc::clone(self),
        })
    }

    pub(crate) fn lock_idle(&self) -> Option<parking_lot::MutexGuard<'_, ScriptLiveSeedPhase>> {
        let guard = self.phase.lock();
        matches!(*guard, ScriptLiveSeedPhase::Idle).then_some(guard)
    }

    pub(crate) fn take_receiver(&self) -> Option<Receiver<Vec<u8>>> {
        self.rows.lock().take()
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
        }
    }

    pub(crate) fn complete_abort(&self) {
        let mut phase = self.phase.lock();
        if matches!(*phase, ScriptLiveSeedPhase::AbortPending) {
            *phase = ScriptLiveSeedPhase::Idle;
            self.staged.store(0, Ordering::Release);
        }
    }

    fn stage(&self, sender: &crossbeam_channel::Sender<Vec<u8>>, coin: &SnapshotCoin<'_>) {
        let mut error = self.error.lock();
        if error.is_some() {
            return;
        }
        let scripthash = ScriptHash::from_script_bytes(coin.script_pubkey);
        let outpoint = OutPoint::new(Txid::from(coin.txid), coin.vout);
        let row = ScriptLiveRow::new(scripthash, &outpoint);
        let coin_val =
            crate::types::ScriptLiveCoin::new(scripthash, coin.value, coin.height, coin.coinbase);
        let bytes = match coin_val.encode_value() {
            Ok(mut encoded) => {
                let mut bytes =
                    Vec::with_capacity(crate::types::SCRIPT_LIVE_ROW_SIZE + encoded.len());
                bytes.extend_from_slice(row.as_bytes());
                bytes.append(&mut encoded);
                bytes
            }
            Err(source) => {
                *error = Some(IndexError::from(source));
                return;
            }
        };
        let mut timeouts = 0_u32;
        loop {
            match sender.send_timeout(bytes.clone(), SEED_SEND_TIMEOUT) {
                Ok(()) => {
                    drop(error);
                    let staged = self.staged.fetch_add(1, Ordering::AcqRel) + 1;
                    self.notify_wake(staged);
                    return;
                }
                Err(SendTimeoutError::Timeout(_)) => {
                    timeouts += 1;
                    if timeouts >= SEED_SEND_RETRIES {
                        *error = Some(IndexError::SeedBacklogStalled);
                        return;
                    }
                }
                Err(SendTimeoutError::Disconnected(_)) => {
                    *error = Some(IndexError::SeedChannelClosed);
                    return;
                }
            }
        }
    }
}

pub struct ScriptLiveSeedSession {
    sender: Option<crossbeam_channel::Sender<Vec<u8>>>,
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
        self.sender.take();
        self.state.request_abort();
    }
}

pub struct ScriptLiveSeedObserver<'a> {
    session: &'a ScriptLiveSeedSession,
}

impl SnapshotCoinObserver for ScriptLiveSeedObserver<'_> {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        if let Some(sender) = self.session.sender.as_ref() {
            self.session.state.stage(sender, &coin);
        }
    }
}
