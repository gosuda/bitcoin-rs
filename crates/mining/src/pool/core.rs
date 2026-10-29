use super::{
    AcceptedShare, BlockReceipt, BlockStatus, ExtranonceLayout, FoundBlock, Installed, Job,
    JobBook, JobBookConfig, JobError, JobId, Session as BookSession, SessionId, ShareClass,
    ShareError, ShareOutcome, ShareSubmission, ShareTarget, StaleReason, fetch_template,
};
use crate::{Candidate, CoinbaseBudget, MiningControl, MiningControlError};
use bitcoin_rs_primitives::{BlockHash, Hash256, TxOut};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkerIdentity {
    pub account: String,
    pub worker: String,
}

/// The ledger could not take the record right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerUnavailable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    Recorded,
    AlreadyRecorded,
    Rejected,
}

/// Implementations must be idempotent on `share.hash`: the adapter retries a
/// failed call, and the common owner's duplicate set makes every first delivery
/// unique.
pub trait ShareLedger: Send + Sync {
    fn record_share(
        &self,
        worker: &WorkerIdentity,
        share: &AcceptedShare,
    ) -> Result<RecordOutcome, LedgerUnavailable>;

    fn record_block(
        &self,
        worker: &WorkerIdentity,
        block: &FoundBlock,
        submission: &Result<BlockReceipt, MiningControlError>,
    ) -> Result<(), LedgerUnavailable>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOutcome {
    Applied,
    Rejected,
    Undetermined,
    NodeError,
}

#[derive(Default)]
struct Published {
    seq: u64,
    clean_seq: u64,
    job: Option<Arc<Job>>,
}

pub(super) struct Latest {
    pub(super) seq: u64,
    pub(super) clean_seq: u64,
    pub(super) job: Option<Arc<Job>>,
}

pub(super) struct Lease {
    pub(super) pool: Arc<PoolCore>,
    pub(super) session: BookSession,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = locked(&self.pool.book).close_session(self.session.id());
    }
}

#[derive(Clone, Debug)]
enum Pending {
    Share {
        worker: WorkerIdentity,
        share: AcceptedShare,
        completion: Arc<Completion>,
    },
    BlockRecord {
        worker: WorkerIdentity,
        block: Box<FoundBlock>,
        submission: Result<BlockReceipt, MiningControlError>,
        completion: Arc<Completion>,
    },
}

pub(super) struct Completion {
    remaining: AtomicUsize,
    rejected: AtomicBool,
}

impl fmt::Debug for Completion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Completion")
            .field("remaining", &self.remaining.load(Ordering::Acquire))
            .field("rejected", &self.rejected.load(Ordering::Acquire))
            .finish()
    }
}

impl Completion {
    fn new(items: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(items),
            rejected: AtomicBool::new(false),
        }
    }

    fn record(&self) {
        let _ = self
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            });
    }

    fn record_rejected(&self) {
        self.rejected.store(true, Ordering::Release);
        self.record();
    }

    pub(super) fn is_complete(&self) -> bool {
        self.remaining.load(Ordering::Acquire) == 0
    }

    pub(super) fn is_rejected(&self) -> bool {
        self.rejected.load(Ordering::Acquire)
    }
}

impl Pending {
    fn hash(&self) -> BlockHash {
        match self {
            Self::Share { share, .. } => share.hash,
            Self::BlockRecord { block, .. } => block.share.hash,
        }
    }

    fn completion(&self) -> &Completion {
        match self {
            Self::Share { completion, .. } | Self::BlockRecord { completion, .. } => completion,
        }
    }

    fn bytes_cost(&self) -> usize {
        match self {
            Self::Share { .. } => SHARE_RECORD_BYTES,
            Self::BlockRecord { block, .. } => BLOCK_RECORD_FRAMING_BYTES + block.raw.len(),
        }
    }
}

pub(super) enum SubmitFailure {
    Share(ShareError),
    Duplicate,
    OutboxFull,
}

pub(super) struct Credited {
    pub(super) hash: BlockHash,
    pub(super) class: ShareClass,
    pub(super) completion: Arc<Completion>,
    pub(super) block: Option<BlockOutcome>,
}

#[derive(Default)]
struct Outbox {
    items: VecDeque<Pending>,
    total_bytes: usize,
    in_flight: usize,
    reserved_items: usize,
    reserved_bytes: usize,
}

const SHARE_RECORD_BYTES: usize = 256;
const BLOCK_RECORD_FRAMING_BYTES: usize = 512;
const MAX_BLOCK_BYTES: usize = 4_000_000;

struct OutboxReservation<'a> {
    pool: &'a PoolCore,
    items: usize,
    bytes: usize,
    active: bool,
}
struct DrainGuard<'a>(&'a AtomicBool);

impl Drop for DrainGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl OutboxReservation<'_> {
    fn commit_reserved(&mut self, item: Pending) -> bool {
        let cost = item.bytes_cost();
        debug_assert!(
            cost <= self.bytes,
            "outbox reservation underflow: cost {cost} exceeds {bytes}",
            bytes = self.bytes
        );
        let mut outbox = locked(&self.pool.outbox);
        if cost > self.bytes
            || outbox.reserved_items == 0
            || outbox.total_bytes.saturating_add(cost) > self.pool.outbox_max_bytes
        {
            return false;
        }
        outbox.reserved_items -= 1;
        outbox.reserved_bytes = outbox.reserved_bytes.saturating_sub(cost);
        outbox.total_bytes += cost;
        outbox.items.push_back(item);
        let total = outbox.items.len() + outbox.in_flight;
        self.pool.pending_count.store(total, Ordering::Release);
        self.items = self.items.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(cost);
        true
    }
}

impl Drop for OutboxReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            let mut outbox = locked(&self.pool.outbox);
            outbox.reserved_items = outbox.reserved_items.saturating_sub(self.items);
            outbox.reserved_bytes = outbox.reserved_bytes.saturating_sub(self.bytes);
            self.active = false;
        }
    }
}

pub(super) struct ShareRequest<'a> {
    pub(super) session: SessionId,
    pub(super) job: JobId,
    pub(super) rolled: &'a [u8],
    pub(super) ntime: u32,
    pub(super) nonce: u32,
    pub(super) version: u32,
}

pub struct PoolCore {
    book: Mutex<JobBook>,
    published: Mutex<Published>,
    control: Arc<dyn MiningControl>,
    ledger: Arc<dyn ShareLedger>,
    layout: ExtranonceLayout,
    version_mask: u32,
    budget: CoinbaseBudget,
    ledger_attempts: u32,
    ledger_backoff: Duration,
    outbox: Mutex<Outbox>,
    outbox_max_items: usize,
    outbox_max_bytes: usize,
    pending_count: AtomicUsize,
    draining: AtomicBool,
}

#[derive(Debug)]
pub struct Refreshed {
    pub installed: Installed,
    pub long_poll_id: String,
    pub submit_old: Option<bool>,
}

#[derive(Debug)]
pub enum RefreshError {
    Template(MiningControlError),
    Install(JobError),
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Template(error) => write!(f, "template fetch failed: {error}"),
            Self::Install(error) => write!(f, "job install failed: {error}"),
        }
    }
}

impl Error for RefreshError {}

impl PoolCore {
    pub fn new(
        config: JobBookConfig,
        control: Arc<dyn MiningControl>,
        ledger: Arc<dyn ShareLedger>,
    ) -> Result<Self, JobError> {
        let layout = config.extranonce;
        let version_mask = config.version_mask;
        let budget = config.budget;
        let book = JobBook::new(config)?;
        Ok(Self {
            book: Mutex::new(book),
            published: Mutex::new(Published::default()),
            control,
            ledger,
            layout,
            version_mask,
            budget,
            ledger_attempts: 3,
            ledger_backoff: Duration::from_millis(5),
            outbox: Mutex::new(Outbox::default()),
            outbox_max_items: 4096,
            outbox_max_bytes: 32 * 1024 * 1024,
            pending_count: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        })
    }

    #[must_use]
    pub fn with_ledger_retry(mut self, attempts: u32, backoff: Duration) -> Self {
        self.ledger_attempts = attempts.max(1);
        self.ledger_backoff = backoff;
        self
    }

    #[must_use]
    pub fn with_outbox(mut self, max_items: usize, max_bytes: usize) -> Self {
        self.outbox_max_items = max_items;
        self.outbox_max_bytes = max_bytes;
        self
    }

    #[must_use]
    pub fn pending_ledger_writes(&self) -> usize {
        self.pending_count.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn layout(&self) -> ExtranonceLayout {
        self.layout
    }

    #[must_use]
    pub fn version_mask(&self) -> u32 {
        self.version_mask
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        locked(&self.book).session_count()
    }

    pub fn with_job_book<R>(&self, operation: impl FnOnce(&mut JobBook) -> R) -> R {
        let mut book = locked(&self.book);
        operation(&mut book)
    }

    #[must_use]
    pub fn current_job(&self) -> Option<Arc<Job>> {
        self.with_job_book(|book| book.current().cloned())
    }

    #[must_use]
    pub fn current_installed(&self) -> Option<Installed> {
        self.with_job_book(|book| book.current_installed().cloned())
    }

    pub fn install(
        &self,
        candidate: Arc<Candidate>,
        extra_outputs: Vec<TxOut>,
    ) -> Result<Installed, JobError> {
        self.install_with(false, candidate, extra_outputs)
    }

    pub fn invalidate_active(&self) -> Vec<JobId> {
        let mut book = locked(&self.book);
        let stale = book.invalidate_active();
        let mut published = locked(&self.published);
        published.job = None;
        stale
    }

    pub fn refresh(
        &self,
        long_poll_id: Option<&str>,
        extra_outputs: Vec<TxOut>,
    ) -> Result<Refreshed, RefreshError> {
        let template = fetch_template(&*self.control, self.budget, long_poll_id)
            .map_err(RefreshError::Template)?;
        let next = template.candidate.template_id.as_str().to_owned();
        let invalidate = template.submit_old == Some(false);
        let installed = self
            .install_with(invalidate, Arc::clone(&template.candidate), extra_outputs)
            .map_err(RefreshError::Install)?;
        Ok(Refreshed {
            installed,
            long_poll_id: next,
            submit_old: template.submit_old,
        })
    }

    fn install_with(
        &self,
        invalidate: bool,
        candidate: Arc<Candidate>,
        extra_outputs: Vec<TxOut>,
    ) -> Result<Installed, JobError> {
        let mut book = locked(&self.book);
        if invalidate && !book.invalidate_active().is_empty() {
            locked(&self.published).job = None;
        }
        let installed = book.install(candidate, extra_outputs)?;
        if installed.fresh {
            let mut published = locked(&self.published);
            published.seq = published.seq.saturating_add(1);
            published.job = Some(Arc::clone(&installed.job));
            if installed.clean_jobs {
                published.clean_seq = published.seq;
            }
        }
        Ok(installed)
    }

    pub(super) fn open_lease(self: &Arc<Self>) -> Result<Lease, JobError> {
        let session = locked(&self.book).open_session()?;
        Ok(Lease {
            pool: Arc::clone(self),
            session,
        })
    }

    pub(super) fn latest(&self) -> Latest {
        let published = locked(&self.published);
        Latest {
            seq: published.seq,
            clean_seq: published.clean_seq,
            job: published.job.clone(),
        }
    }

    fn retry_pause(&self, attempt: u32, hash: BlockHash) {
        let jitter = u64::from(Hash256::from(hash).to_le_bytes()[0]) * 10;
        thread::sleep(self.ledger_backoff * (attempt + 1) + Duration::from_micros(jitter));
    }

    fn submit_block_to_node(&self, found: &FoundBlock) -> Result<BlockReceipt, MiningControlError> {
        const ATTEMPTS: u32 = 5;
        let mut attempt = 0;
        loop {
            match found.submit(&*self.control) {
                Ok(receipt) => {
                    if receipt.status() == BlockStatus::Applied {
                        self.invalidate_active();
                        return Ok(receipt);
                    }
                    if receipt.status() != BlockStatus::Undetermined {
                        return Ok(receipt);
                    }
                    attempt += 1;
                    if attempt >= ATTEMPTS {
                        return Ok(receipt);
                    }
                    self.retry_pause(attempt - 1, found.share.hash);
                }
                Err(
                    MiningControlError::Unavailable(message) | MiningControlError::Failed(message),
                ) => {
                    attempt += 1;
                    if attempt == ATTEMPTS {
                        return Err(MiningControlError::Failed(message));
                    }
                    self.retry_pause(attempt - 1, found.share.hash);
                }
                Err(non_retriable) => return Err(non_retriable),
            }
        }
    }

    fn attempt_item(&self, item: &Pending) -> Result<RecordOutcome, LedgerUnavailable> {
        match item {
            Pending::Share { worker, share, .. } => self.ledger.record_share(worker, share),
            Pending::BlockRecord {
                worker,
                block,
                submission,
                ..
            } => self
                .ledger
                .record_block(worker, block, submission)
                .map(|()| RecordOutcome::Recorded),
        }
    }

    fn deliver_inline(&self, item: &Pending) -> Result<RecordOutcome, LedgerUnavailable> {
        self.drain_outbox();
        if self.pending_count.load(Ordering::Acquire) > 0 {
            return Err(LedgerUnavailable);
        }
        let hash = item.hash();
        for attempt in 0..self.ledger_attempts {
            match self.attempt_item(item) {
                Ok(outcome) => return Ok(outcome),
                Err(LedgerUnavailable) => {
                    if attempt + 1 < self.ledger_attempts {
                        self.retry_pause(attempt, hash);
                    }
                }
            }
        }
        Err(LedgerUnavailable)
    }

    pub fn drain_outbox(&self) {
        if self.pending_count.load(Ordering::Acquire) == 0 {
            return;
        }
        if self
            .draining
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let _guard = DrainGuard(&self.draining);

        loop {
            let item = {
                let mut outbox = locked(&self.outbox);
                let Some(item) = outbox.items.pop_front() else {
                    outbox.in_flight = 0;
                    self.pending_count.store(0, Ordering::Release);
                    break;
                };
                outbox.total_bytes = outbox.total_bytes.saturating_sub(item.bytes_cost());
                outbox.in_flight = 1;
                self.pending_count
                    .store(outbox.items.len() + 1, Ordering::Release);
                item
            };

            let mut succeeded = false;
            for attempt in 0..self.ledger_attempts {
                match self.attempt_item(&item) {
                    Ok(RecordOutcome::Recorded | RecordOutcome::AlreadyRecorded) => {
                        item.completion().record();
                        succeeded = true;
                        break;
                    }
                    Ok(RecordOutcome::Rejected) => {
                        item.completion().record_rejected();
                        succeeded = true;
                        break;
                    }
                    Err(LedgerUnavailable) => {
                        if attempt + 1 < self.ledger_attempts {
                            self.retry_pause(attempt, item.hash());
                        }
                    }
                }
            }

            let mut outbox = locked(&self.outbox);
            outbox.in_flight = 0;
            if succeeded {
                self.pending_count
                    .store(outbox.items.len(), Ordering::Release);
            } else {
                outbox.total_bytes += item.bytes_cost();
                outbox.items.push_front(item);
                self.pending_count
                    .store(outbox.items.len(), Ordering::Release);
                break;
            }
        }
    }

    fn reserve_outbox_space(&self) -> Option<OutboxReservation<'_>> {
        self.drain_outbox();
        let reserve_items = 2_usize;
        let reserve_bytes = SHARE_RECORD_BYTES + BLOCK_RECORD_FRAMING_BYTES + MAX_BLOCK_BYTES;
        let mut outbox = locked(&self.outbox);
        let committed_items = outbox.items.len() + outbox.reserved_items;
        let committed_bytes = outbox.total_bytes.saturating_add(outbox.reserved_bytes);
        if committed_items.saturating_add(reserve_items) > self.outbox_max_items
            || committed_bytes.saturating_add(reserve_bytes) > self.outbox_max_bytes
        {
            None
        } else {
            outbox.reserved_items += reserve_items;
            outbox.reserved_bytes += reserve_bytes;
            Some(OutboxReservation {
                pool: self,
                items: reserve_items,
                bytes: reserve_bytes,
                active: true,
            })
        }
    }

    pub(super) fn submit(
        &self,
        worker: &WorkerIdentity,
        request: &ShareRequest<'_>,
        target: &ShareTarget,
    ) -> Result<Credited, SubmitFailure> {
        let mut reservation = self
            .reserve_outbox_space()
            .ok_or(SubmitFailure::OutboxFull)?;

        let outcome = {
            let mut book = locked(&self.book);
            let submission = ShareSubmission {
                session: request.session,
                job: request.job,
                rolled_extranonce: request.rolled,
                ntime: request.ntime,
                nonce: request.nonce,
                version: request.version,
            };
            book.validate(&submission, target)
                .map_err(SubmitFailure::Share)?
        };

        match outcome {
            ShareOutcome::Share(accepted) => {
                let hash = accepted.hash;
                let completion = Arc::new(Completion::new(1));
                let item = Pending::Share {
                    worker: worker.clone(),
                    share: *accepted,
                    completion: Arc::clone(&completion),
                };
                match self.deliver_inline(&item) {
                    Ok(RecordOutcome::Recorded) => completion.record(),
                    Ok(RecordOutcome::AlreadyRecorded | RecordOutcome::Rejected) => {
                        return Err(SubmitFailure::Duplicate);
                    }
                    Err(LedgerUnavailable) => {
                        if !reservation.commit_reserved(item) {
                            return Err(SubmitFailure::OutboxFull);
                        }
                    }
                }
                Ok(Credited {
                    hash,
                    class: ShareClass::Share,
                    completion,
                    block: None,
                })
            }
            ShareOutcome::Block(found) => {
                let submission = self.submit_block_to_node(&found);
                let block_outcome = match &submission {
                    Ok(receipt) => match receipt.status() {
                        BlockStatus::Applied => BlockOutcome::Applied,
                        BlockStatus::Rejected => BlockOutcome::Rejected,
                        BlockStatus::Undetermined => BlockOutcome::Undetermined,
                    },
                    Err(_) => BlockOutcome::NodeError,
                };
                let hash = found.share.hash;
                let job = found.share.job;
                let stale_parent = submission.as_ref().is_ok_and(BlockReceipt::is_stale_parent);
                let completion = Arc::new(Completion::new(2));
                let share_item = Pending::Share {
                    worker: worker.clone(),
                    share: found.share.clone(),
                    completion: Arc::clone(&completion),
                };
                let block_item = Pending::BlockRecord {
                    worker: worker.clone(),
                    block: found,
                    submission,
                    completion: Arc::clone(&completion),
                };

                let mut share_settled = false;
                match self.deliver_inline(&share_item) {
                    Ok(RecordOutcome::Recorded) => completion.record(),
                    Ok(RecordOutcome::AlreadyRecorded | RecordOutcome::Rejected) => {
                        completion.record();
                        share_settled = true;
                    }
                    Err(LedgerUnavailable) => {
                        if !reservation.commit_reserved(share_item) {
                            return Err(SubmitFailure::OutboxFull);
                        }
                    }
                }

                if self.deliver_inline(&block_item).is_err() {
                    if !reservation.commit_reserved(block_item) {
                        return Err(SubmitFailure::OutboxFull);
                    }
                } else {
                    completion.record();
                }

                if stale_parent {
                    return Err(SubmitFailure::Share(ShareError::Stale {
                        job,
                        reason: StaleReason::Invalidated,
                    }));
                }

                if share_settled {
                    return Err(SubmitFailure::Duplicate);
                }

                Ok(Credited {
                    hash,
                    class: ShareClass::Block,
                    completion,
                    block: Some(block_outcome),
                })
            }
        }
    }
}
