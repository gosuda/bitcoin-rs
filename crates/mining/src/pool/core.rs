//! Shared pool job publication, submission, and deferred accounting.
//!
//! Lock order is book then published. Neither lock spans a socket operation,
//! ledger call, or node call. Protocol sessions share the same `JobBook`.
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

/// Who a share is credited to: the pool account and the rig under it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkerIdentity {
    /// Account that is paid.
    pub account: String,
    /// Rig name under the account.
    pub worker: String,
}

/// The ledger could not take the record right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerUnavailable;

/// Whether a share row was new.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    /// New row written.
    Recorded,
    /// A row with this header hash already exists; nothing changed.
    AlreadyRecorded,
}

/// Idempotent accounting boundary shared by pool submission and its host.
///
/// Implementations must be idempotent on `share.hash`: the adapter retries a
/// failed call, and the common owner's duplicate set makes every first delivery
/// unique.
pub trait ShareLedger: Send + Sync {
    /// Records one accepted share (`share.class` may be `Block`) credited to
    /// `worker`. `share.hash` is the unique key; `share.work` is the work.
    fn record_share(
        &self,
        worker: &WorkerIdentity,
        share: &AcceptedShare,
    ) -> Result<RecordOutcome, LedgerUnavailable>;

    /// Records what the node answered when `block` was submitted. `Err` or an
    /// `Undetermined` receipt means the chain outcome is unknown: keep the
    /// block pending and reconcile from chain observation.
    fn record_block(
        &self,
        worker: &WorkerIdentity,
        block: &FoundBlock,
        submission: &Result<BlockReceipt, MiningControlError>,
    ) -> Result<(), LedgerUnavailable>;
}

/// What the node answered to a block found by a share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOutcome {
    /// Accepted, or its body was already connected.
    Applied,
    /// Rejected, or a duplicate of a known-invalid block.
    Rejected,
    /// The node could not conclude; the ledger reconciles from the chain.
    Undetermined,
    /// The submit call itself failed; chain outcome unknown.
    NodeError,
}

#[derive(Default)]
struct Published {
    /// Increments on every fresh job.
    seq: u64,
    /// `seq` of the newest job that was installed with `clean_jobs`.
    clean_seq: u64,
    /// Newest job while it is active; `None` after `invalidate_active`.
    job: Option<Arc<Job>>,
}

pub(super) struct Latest {
    pub(super) seq: u64,
    pub(super) clean_seq: u64,
    pub(super) job: Option<Arc<Job>>,
}

/// A session slot in the book, closed on drop.
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
}

/// Debug shows only the outstanding count; a completion carries no secrets.
impl fmt::Debug for Completion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Completion")
            .field("remaining", &self.remaining.load(Ordering::Acquire))
            .finish()
    }
}

impl Completion {
    fn new(items: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(items),
        }
    }

    fn record(&self) {
        let _ = self
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            });
    }

    pub(super) fn is_complete(&self) -> bool {
        self.remaining.load(Ordering::Acquire) == 0
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
            Self::Share { .. } => 256,
            Self::BlockRecord { block, .. } => 512 + block.payload.bytes().len(),
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

/// Atomically holds outbox space for one in-flight submit (up to 2 items and
/// 8 MiB for worst-case block entries).
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
    /// Commits an item into the outbox by consuming part of this reservation.
    /// Capacity is guaranteed because it was pre-allocated.
    fn commit(&mut self, item: Pending) {
        let cost = item.bytes_cost();
        let mut outbox = locked(&self.pool.outbox);
        outbox.reserved_items = outbox.reserved_items.saturating_sub(1);
        outbox.reserved_bytes = outbox.reserved_bytes.saturating_sub(cost);
        outbox.total_bytes += cost;
        outbox.items.push_back(item);
        let total = outbox.items.len() + outbox.in_flight;
        self.pool.pending_count.store(total, Ordering::Release);
        self.items = self.items.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(cost);
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
    pub(super) version_bits: Option<u32>,
}

/// The pool: one `JobBook`, the node control it submits blocks to, and the
/// ledger it credits. Shared by every connection thread.
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

/// A template fetched and installed by [`PoolCore::refresh`].
#[derive(Debug)]
pub struct Refreshed {
    /// What `JobBook::install` did.
    pub installed: Installed,
    /// Pass to the next [`PoolCore::refresh`] to long-poll for a newer template.
    pub long_poll_id: String,
    /// The template's `submit_old`.
    pub submit_old: Option<bool>,
}

/// [`PoolCore::refresh`] failure.
#[derive(Debug)]
pub enum RefreshError {
    /// The node would not give a template.
    Template(MiningControlError),
    /// The job book would not project it.
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
    /// Builds the pool over a fresh `JobBook`. Retries a failed ledger call
    /// three times with a 5 ms base backoff; see [`Self::with_ledger_retry`].
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

    /// Sets the ledger retry budget: `attempts` calls (at least one) with a
    /// sleep of `backoff * attempt` plus a per-share jitter of up to 2.5 ms
    /// between them.
    #[must_use]
    pub fn with_ledger_retry(mut self, attempts: u32, backoff: Duration) -> Self {
        self.ledger_attempts = attempts.max(1);
        self.ledger_backoff = backoff;
        self
    }

    /// Sets the outbox bounds for queuing writes when the ledger is unavailable.
    #[must_use]
    pub fn with_outbox(mut self, max_items: usize, max_bytes: usize) -> Self {
        self.outbox_max_items = max_items.max(1);
        self.outbox_max_bytes = max_bytes.max(1024);
        self
    }

    /// Number of writes currently waiting in the outbox.
    #[must_use]
    pub fn pending_ledger_writes(&self) -> usize {
        self.pending_count.load(Ordering::Acquire)
    }

    /// Extranonce split every session uses (SV1 `extranonce2_size` is its
    /// `rolled_len`).
    #[must_use]
    pub fn layout(&self) -> ExtranonceLayout {
        self.layout
    }

    /// Version bits the pool lets miners roll (zero: no rolling).
    #[must_use]
    pub fn version_mask(&self) -> u32 {
        self.version_mask
    }

    /// Open sessions in the book.
    #[must_use]
    pub fn session_count(&self) -> usize {
        locked(&self.book).session_count()
    }

    /// Runs an owner-local validation operation under the sole authoritative
    /// `JobBook` mutex. The callback must not re-enter `PoolCore`, install or
    /// invalidate jobs, or perform node, ledger, or other external I/O while
    /// this lock is held.
    pub fn with_job_book<R>(&self, operation: impl FnOnce(&mut JobBook) -> R) -> R {
        let mut book = locked(&self.book);
        operation(&mut book)
    }

    /// Returns the active job from the same authoritative `JobBook` used by
    /// SV1 validation and session allocation.
    #[must_use]
    pub fn current_job(&self) -> Option<Arc<Job>> {
        self.with_job_book(|book| book.current().cloned())
    }

    /// Returns the latest installation metadata from the authoritative pool
    /// owner. The value is absent before the first install or after explicit
    /// invalidation.
    #[must_use]
    pub fn current_installed(&self) -> Option<Installed> {
        self.with_job_book(|book| book.current_installed().cloned())
    }

    /// Installs `candidate` (with the pool's coinbase `extra_outputs`) and, when
    /// it is a fresh job, publishes it to every session at its next poll.
    pub fn install(
        &self,
        candidate: Arc<Candidate>,
        extra_outputs: Vec<TxOut>,
    ) -> Result<Installed, JobError> {
        self.install_with(false, candidate, extra_outputs)
    }

    /// Marks every active job stale. Sessions keep their last job until the
    /// next install, whose `clean_jobs` is then true; shares on the stale jobs
    /// are rejected by the book.
    pub fn invalidate_active(&self) -> Vec<JobId> {
        let mut book = locked(&self.book);
        let stale = book.invalidate_active();
        let mut published = locked(&self.published);
        published.job = None;
        stale
    }

    /// Fetches one template from the node (long-polling on `long_poll_id`) and
    /// installs it. `submit_old == Some(false)` first invalidates active jobs.
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
                    }
                    return Ok(receipt);
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

    /// Drains pending outbox items sequentially.
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
                    Ok(_) => {
                        item.completion().record();
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

    /// Atomically reserves outbox space for one share (and potential block).
    /// Returns `None` if the outbox has reached capacity.
    /// Per-session bound for withheld submit responses: one outstanding
    /// accounting completion. A second submit while the ledger is unavailable
    /// is shed with a retryable accounting error, not buffered.
    fn reserve_outbox_space(&self) -> Option<OutboxReservation<'_>> {
        self.drain_outbox();
        let reserve_items = 2_usize;
        let reserve_bytes = 8 * 1024 * 1024_usize;
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
        // Atomically reserve space BEFORE validation. If the outbox is at
        // capacity, fail with backpressure so the miner may retry and the hash
        // is never burned in `JobBook`.
        let mut reservation = self
            .reserve_outbox_space()
            .ok_or(SubmitFailure::OutboxFull)?;

        let outcome = {
            let mut book = locked(&self.book);
            let version = match (book.job(request.job), request.version_bits) {
                (Some(job), Some(bits)) => job
                    .version_from_rolled_bits(bits)
                    .map_err(SubmitFailure::Share)?,
                (Some(job), None) => job.version(),
                // The book rejects an unknown or retired job before it reads
                // the version.
                (None, _) => 0,
            };
            let submission = ShareSubmission {
                session: request.session,
                job: request.job,
                rolled_extranonce: request.rolled,
                ntime: request.ntime,
                nonce: request.nonce,
                version,
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
                // Attempt inline delivery first; otherwise the completion waits on the outbox.
                match self.deliver_inline(&item) {
                    Ok(RecordOutcome::Recorded) => completion.record(),
                    Ok(RecordOutcome::AlreadyRecorded) => return Err(SubmitFailure::Duplicate),
                    Err(LedgerUnavailable) => reservation.commit(item),
                }
                Ok(Credited {
                    hash,
                    class: ShareClass::Share,
                    completion,
                    block: None,
                })
            }
            ShareOutcome::Block(found) => {
                // Priority invariant: node submission runs before any ledger record.
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

                match self.deliver_inline(&share_item) {
                    Ok(RecordOutcome::Recorded) => completion.record(),
                    Ok(RecordOutcome::AlreadyRecorded) => return Err(SubmitFailure::Duplicate),
                    Err(LedgerUnavailable) => reservation.commit(share_item),
                }

                // Deliver or buffer block record.
                if self.deliver_inline(&block_item).is_err() {
                    reservation.commit(block_item);
                } else {
                    completion.record();
                }

                if stale_parent {
                    return Err(SubmitFailure::Share(ShareError::Stale {
                        job,
                        reason: StaleReason::Invalidated,
                    }));
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
