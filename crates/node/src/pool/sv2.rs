use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::pool::ledger::MinerId;
use bitcoin_rs_mining::pool::stratum::sv1::ConnectionLimiter;
use bitcoin_rs_mining::pool::stratum::sv2::{
    AdmitError, AuthorityKeypair, BlockSubmission, Connection, ERROR_CODE_SHARE_NOT_RECORDED,
    ERROR_CODE_SUBMIT_SHARES_STALE_SHARE, Event, Limits, MAX_FEED_LEN, PendingBlock, ServerConfig,
};
use bitcoin_rs_mining::pool::{BlockStatus, PoolCore, RecordOutcome};
use bitcoin_rs_primitives::BlockHash;

use super::authority;
use super::ledger::{BlockRecordOutcome, BlockRecordPermit, DeferredCharge, LedgerHost};
use crate::config::PoolConfig;

const CERTIFICATE_VALIDITY: Duration = Duration::new(86_400, 0);
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(100);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

struct DeferredBlock {
    hash: BlockHash,
    pending: PendingBlock,
    submission: BlockSubmission,
    attempts: u32,
    charge: DeferredCharge,
}

const DEFERRED_RESUBMIT_ATTEMPTS: u32 = 5;

struct BlockPipeline<'a> {
    permit: &'a mut Option<BlockRecordPermit>,
    deferred: &'a mut Vec<DeferredBlock>,
}

fn settle_one_deferred(
    mut entry: DeferredBlock,
    ledger: &LedgerHost,
    control: &dyn MiningControl,
    connection: &mut Connection,
    core: &PoolCore,
) -> Option<DeferredBlock> {
    if !matches!(ledger.found_block_recorded(entry.hash), Ok(true)) {
        return Some(entry);
    }
    if entry.submission.receipt().status() == BlockStatus::Undetermined
        && entry.attempts < DEFERRED_RESUBMIT_ATTEMPTS
    {
        entry.attempts = entry.attempts.saturating_add(1);
        match entry.pending.submit(control) {
            Ok(fresh) if fresh.receipt().status() == BlockStatus::Applied => {
                core.invalidate_active();
                entry.submission = fresh;
            }
            Ok(fresh) if fresh.receipt().status() == BlockStatus::Rejected => {
                if fresh.receipt().is_stale_parent() {
                    let _ = connection.reject_block(&fresh, ERROR_CODE_SUBMIT_SHARES_STALE_SHARE);
                }
                return None;
            }
            Ok(fresh) => {
                entry.submission = fresh;
                return Some(entry);
            }
            Err(_) => return Some(entry),
        }
    }
    if entry.submission.receipt().status() == BlockStatus::Applied {
        if connection.confirm_block(&entry.submission).is_err() {
            return Some(entry);
        }
        return None;
    }
    Some(entry)
}

pub(crate) struct Sv2Service {
    cancel: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    worker_panicked: Arc<AtomicBool>,
}

impl Sv2Service {
    pub(crate) fn stop(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    pub(crate) fn stop_join(&mut self, deadline: Instant) -> Result<()> {
        self.stop();
        wait_until_finished(self.listener.as_ref(), deadline, "SV2 listener")?;
        if let Some(listener) = self.listener.take() {
            listener
                .join()
                .map_err(|_| anyhow!("SV2 listener thread panicked"))?;
        }

        loop {
            let all_finished = self
                .connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .all(JoinHandle::is_finished);
            if all_finished {
                break;
            }
            if Instant::now() >= deadline {
                return Err(anyhow!("timed out joining SV2 connection threads"));
            }
            thread::sleep(
                ACCEPT_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        let mut panicked = self.worker_panicked.load(Ordering::Acquire);
        for connection in self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            if connection.join().is_err() {
                panicked = true;
                self.worker_panicked.store(true, Ordering::Release);
                tracing::warn!("SV2 connection thread panicked");
            }
        }
        if panicked {
            return Err(anyhow!("SV2 connection thread panicked"));
        }
        Ok(())
    }
}

impl Drop for Sv2Service {
    fn drop(&mut self) {
        self.stop();
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        for connection in self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            let _ = connection.join();
        }
    }
}

pub(crate) fn start(
    config: &PoolConfig,
    core: Arc<PoolCore>,
    ledger: Arc<LedgerHost>,
    control: Arc<dyn MiningControl>,
    cancel: Arc<AtomicBool>,
    limiter: Arc<ConnectionLimiter>,
) -> Result<Sv2Service> {
    let bind = config
        .sv2_bind
        .ok_or_else(|| anyhow!("SV2 start requires a listener address"))?;
    let key_path = config
        .sv2_authority_key
        .as_deref()
        .ok_or_else(|| anyhow!("SV2 start requires an authority key"))?;
    let authority = Arc::new(authority::load(key_path).context("loading SV2 authority key")?);
    let listener =
        TcpListener::bind(bind).with_context(|| format!("binding SV2 listener {bind}"))?;
    listener
        .set_nonblocking(true)
        .context("setting SV2 listener nonblocking")?;

    let connections = Arc::new(Mutex::new(Vec::new()));
    let thread_connections = Arc::clone(&connections);
    let thread_cancel = Arc::clone(&cancel);
    let worker_panicked = Arc::new(AtomicBool::new(false));
    let thread_panicked = Arc::clone(&worker_panicked);
    let initial_target = config.share_target;

    let listener_thread = thread::Builder::new()
        .name("pool-sv2-listener".to_owned())
        .spawn(move || {
            while !thread_cancel.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        reap_finished(&thread_connections, &thread_panicked);
                        let Ok(permit) = limiter.try_admit(peer.ip()) else {
                            drop(stream);
                            continue;
                        };
                        let core = Arc::clone(&core);
                        let ledger = Arc::clone(&ledger);
                        let control = Arc::clone(&control);
                        let authority = Arc::clone(&authority);
                        let cancel = Arc::clone(&thread_cancel);
                        let connection_ledger = Arc::clone(&ledger);
                        let admit_user = Arc::new(move |identity: &[u8]| {
                            let login = std::str::from_utf8(identity)
                                .map_err(|_| AdmitError::InvalidIdentity)?;
                            connection_ledger
                                .account(login)
                                .map(|_| ())
                                .ok_or(AdmitError::UnknownUser)
                        });
                        let mut server_config = ServerConfig::new(initial_target);
                        server_config.limits = Limits {
                            max_frame_payload: 8 * 1024,
                            max_channels: 8,
                            max_jobs_per_channel: 16,
                            max_pending_acks: 16,
                            pending_ack_timeout: Limits::DEFAULT.pending_ack_timeout,
                            max_outbound_frames: 256,
                            max_pending_events: 32,
                            max_outbound_bytes: 1_048_576,
                        };
                        server_config.admit_user = admit_user;
                        match thread::Builder::new()
                            .name(format!("pool-sv2-{}", peer.ip()))
                            .spawn(move || {
                                let _permit = permit;
                                if let Err(error) = serve_connection(
                                    stream,
                                    &authority,
                                    server_config,
                                    &core,
                                    &ledger,
                                    &*control,
                                    &cancel,
                                ) {
                                    tracing::debug!(peer = %peer, %error, "SV2 connection closed");
                                }
                            })
                        {
                            Ok(handle) => thread_connections
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(handle),
                            Err(error) => tracing::warn!(peer = %peer, %error, "could not spawn SV2 connection worker"),
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(error) => {
                        tracing::error!(%error, "SV2 listener failed");
                        break;
                    }
                }
            }
        })
        .context("spawning SV2 listener")?;

    Ok(Sv2Service {
        cancel,
        listener: Some(listener_thread),
        connections,
        worker_panicked,
    })
}

fn serve_connection(
    mut stream: TcpStream,
    authority: &AuthorityKeypair,
    config: ServerConfig,
    core: &PoolCore,
    ledger: &Arc<LedgerHost>,
    control: &dyn MiningControl,
    cancel: &AtomicBool,
) -> Result<()> {
    stream.set_nonblocking(true)?;
    stream.set_nodelay(true)?;
    let mut connection = core
        .with_job_book(|book| Connection::accept(authority, CERTIFICATE_VALIDITY, config, book))
        .context("creating authenticated SV2 connection")?;
    let mut accounts = HashMap::new();
    let mut input = vec![0; MAX_FEED_LEN];
    let mut buffered_input = None;
    let mut deferred: Vec<DeferredBlock> = Vec::new();
    let mut transmit = PendingTransmit::default();
    let start = Instant::now();
    let mut last_progress = start;
    let result = (|| -> Result<()> {
        while !cancel.load(Ordering::Acquire) && !connection.is_closing() {
            if !connection.session().is_open() && start.elapsed() >= HANDSHAKE_TIMEOUT {
                return Err(anyhow!("SV2 handshake timed out"));
            }
            if last_progress.elapsed() >= IDLE_TIMEOUT {
                return Err(anyhow!("SV2 connection idle timed out"));
            }
            let deferred_before = deferred.len();
            let mut still_deferred = Vec::with_capacity(deferred.len());
            for entry in std::mem::take(&mut deferred) {
                if let Some(waiter) =
                    settle_one_deferred(entry, ledger, control, &mut connection, core)
                {
                    still_deferred.push(waiter);
                }
            }
            deferred = still_deferred;
            if deferred.len() != deferred_before {
                last_progress = Instant::now();
            }
            announce_current_job(&mut connection, core)?;
            transmit.fill(&mut connection);
            let pending_bytes = transmit.remaining();
            transmit.flush(&mut stream)?;
            if pending_bytes != transmit.remaining() {
                last_progress = Instant::now();
            }

            if buffered_input.is_none() {
                let read_len = connection.read_hint().clamp(1, MAX_FEED_LEN);
                match stream.read(&mut input[..read_len]) {
                    Ok(0) => break,
                    Ok(length) => {
                        buffered_input = Some(length);
                        last_progress = Instant::now();
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) =>
                    {
                        thread::sleep(SOCKET_POLL_INTERVAL);
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
            }

            let Some(block_permit) = ledger.try_reserve_block_slot() else {
                thread::sleep(SOCKET_POLL_INTERVAL);
                continue;
            };
            let mut block_permit = Some(block_permit);
            let length = buffered_input
                .take()
                .ok_or_else(|| anyhow!("SV2 buffered input length is missing"))?;
            core.with_job_book(|book| connection.feed(&input[..length], book))?;
            let events_before = connection.session().pending_acks();
            handle_events(
                &mut connection,
                core,
                ledger,
                control,
                &mut accounts,
                BlockPipeline {
                    permit: &mut block_permit,
                    deferred: &mut deferred,
                },
            )?;
            let expired = core.with_job_book(|book| {
                connection
                    .session_mut()
                    .expire_tickets(book, Instant::now())
            });
            if !expired.is_empty() {
                tracing::debug!(count = expired.len(), "SV2 pending tickets expired");
            }
            if events_before != connection.session().pending_acks() || !expired.is_empty() {
                last_progress = Instant::now();
            }
            transmit.fill(&mut connection);
            let queued_before = transmit.remaining();
            transmit.flush(&mut stream)?;
            if transmit.remaining() != queued_before {
                last_progress = Instant::now();
            }
        }
        Ok(())
    })();
    let _ = transmit.drain(
        &mut connection,
        &mut stream,
        Instant::now() + SOCKET_POLL_INTERVAL,
    );
    core.with_job_book(|book| connection.release(book));
    result
}

fn announce_current_job(connection: &mut Connection, core: &PoolCore) -> Result<()> {
    if let Some(installed) = core.current_installed() {
        connection.announce(&installed)?;
    }
    Ok(())
}

fn handle_events(
    connection: &mut Connection,
    core: &PoolCore,
    ledger: &LedgerHost,
    control: &dyn MiningControl,
    accounts: &mut HashMap<u32, MinerId>,
    pipeline: BlockPipeline<'_>,
) -> Result<()> {
    let BlockPipeline {
        permit: block_permit,
        deferred,
    } = pipeline;
    while let Some(event) = connection.poll_event() {
        match event {
            Event::ChannelOpened {
                channel_id,
                user_identity,
                ..
            } => {
                if let Ok(login) = std::str::from_utf8(&user_identity)
                    && let Some(account) = ledger.account(login)
                {
                    accounts.insert(channel_id, account);
                }
            }
            Event::ChannelClosed { channel_id, .. } => {
                accounts.remove(&channel_id);
            }
            Event::ShareAccepted(event) => {
                let recorded = accounts
                    .get(&event.channel_id)
                    .copied()
                    .is_some_and(|account| {
                        matches!(
                            ledger.record_accepted_share(account, &event.outcome),
                            Ok(RecordOutcome::Recorded | RecordOutcome::AlreadyRecorded)
                        )
                    });
                if recorded {
                    connection.confirm_share(event.ticket)?;
                } else if connection.reject_share(event.ticket, ERROR_CODE_SHARE_NOT_RECORDED)? {
                    core.with_job_book(|book| {
                        let _ = book.unburn(&event.outcome.hash);
                    });
                }
            }
            Event::BlockFound(pending) => {
                let Some(account) = accounts.get(&pending.channel_id()).copied() else {
                    return Err(anyhow!("SV2 block channel has no admitted ledger account"));
                };
                let permit = block_permit
                    .take()
                    .ok_or_else(|| anyhow!("SV2 block event has no host record reservation"))?;
                let found = pending.found_block();
                let submission = pending.submit(control);
                if let Ok(submitted) = &submission
                    && submitted.receipt().status() == BlockStatus::Applied
                {
                    core.invalidate_active();
                }
                let receipt = submission
                    .as_ref()
                    .map(|submitted| submitted.receipt().clone())
                    .map_err(Clone::clone);
                match permit.record_or_enqueue(account, found, &receipt) {
                    (BlockRecordOutcome::Durable, charge) => {
                        if matches!(
                            &submission,
                            Ok(submitted)
                                if submitted.receipt().status() == BlockStatus::Undetermined
                        ) {
                            let Ok(submitted) = submission else {
                                return Err(anyhow!("SV2 block lost its submission"));
                            };
                            let hash = found.share.hash;
                            let Some(charge) = charge else {
                                return Err(anyhow!("SV2 durable recovery has no reservation"));
                            };
                            deferred.push(DeferredBlock {
                                hash,
                                pending,
                                submission: submitted,
                                attempts: 0,
                                charge,
                            });
                            continue;
                        }
                        debug_assert!(charge.is_none());
                    }
                    (BlockRecordOutcome::Queued, charge) => {
                        if matches!(
                            &submission,
                            Ok(submitted)
                                if matches!(
                                    submitted.receipt().status(),
                                    BlockStatus::Applied | BlockStatus::Undetermined
                                )
                        ) {
                            let Ok(submitted) = submission else {
                                return Err(anyhow!("SV2 block lost its submission"));
                            };
                            let hash = found.share.hash;
                            let Some(charge) = charge else {
                                return Err(anyhow!("SV2 queued recovery has no reservation"));
                            };
                            deferred.push(DeferredBlock {
                                hash,
                                pending,
                                submission: submitted,
                                attempts: 0,
                                charge,
                            });
                            continue;
                        }
                    }
                    (BlockRecordOutcome::Unrecordable, _) => {
                        return Err(anyhow!(
                            "SV2 block cannot be represented by the durable ledger"
                        ));
                    }
                }
                let submission = submission.context("SV2 block submission failed")?;
                match submission.receipt().status() {
                    BlockStatus::Applied => {
                        connection.confirm_block(&submission)?;
                    }
                    BlockStatus::Undetermined => {
                        return Err(anyhow!("SV2 Undetermined block lost its reservation"));
                    }
                    BlockStatus::Rejected if submission.receipt().is_stale_parent() => {
                        connection
                            .reject_block(&submission, ERROR_CODE_SUBMIT_SHARES_STALE_SHARE)?;
                    }
                    BlockStatus::Rejected => {
                        return Err(anyhow!("node rejected submitted SV2 block"));
                    }
                }
            }
            Event::SetupRejected { code } => tracing::debug!(code, "SV2 setup rejected"),
            Event::ChannelOpenRejected { code, .. } => {
                tracing::debug!(code, "SV2 channel open rejected");
            }
            Event::ShareRejected { code, .. } => tracing::debug!(code, "SV2 share rejected"),
            Event::SetupCompleted { .. } => {}
        }
    }
    drop(block_permit.take());
    Ok(())
}

fn reap_finished(connections: &Mutex<Vec<JoinHandle<()>>>, worker_panicked: &AtomicBool) {
    let mut connections = connections
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < connections.len() {
        if connections[index].is_finished() {
            let handle = connections.swap_remove(index);
            if handle.join().is_err() {
                worker_panicked.store(true, Ordering::Release);
                tracing::warn!("SV2 connection thread panicked");
            }
        } else {
            index += 1;
        }
    }
}

#[derive(Default)]
struct PendingTransmit {
    bytes: Vec<u8>,
    offset: usize,
}

impl PendingTransmit {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

impl PendingTransmit {
    fn fill(&mut self, connection: &mut Connection) {
        if self.offset == self.bytes.len() {
            self.bytes = connection.take_transmit();
            self.offset = 0;
        }
    }

    fn drain(
        &mut self,
        connection: &mut Connection,
        stream: &mut TcpStream,
        deadline: Instant,
    ) -> Result<()> {
        loop {
            self.fill(connection);
            self.flush(stream)?;
            self.fill(connection);
            if self.bytes.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(anyhow!("timed out draining SV2 connection output"));
            }
            thread::sleep(ACCEPT_POLL_INTERVAL);
        }
    }

    fn flush(&mut self, stream: &mut TcpStream) -> Result<()> {
        while self.offset < self.bytes.len() {
            match stream.write(&self.bytes[self.offset..]) {
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::WriteZero, "SV2 socket closed").into(),
                    );
                }
                Ok(written) => self.offset += written,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if self.offset == self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
        }
        Ok(())
    }
}

fn wait_until_finished(
    handle: Option<&JoinHandle<()>>,
    deadline: Instant,
    name: &str,
) -> Result<()> {
    while handle.is_some_and(|handle| !handle.is_finished()) {
        if Instant::now() >= deadline {
            return Err(anyhow!("timed out joining {name}"));
        }
        thread::sleep(ACCEPT_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    Ok(())
}

#[cfg(all(test, any(feature = "fjall", feature = "redb")))]
mod tests;
