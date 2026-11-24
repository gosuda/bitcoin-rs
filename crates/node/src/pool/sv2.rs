use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin_rs_consensus::primitives::BlockHash;
use bitcoin_rs_wire::mining::{MiningControl, MiningControlError};
use bitcoin_rs_wire::mining::pool::ledger::MinerId;
use bitcoin_rs_wire::mining::pool::stratum::sv1::{ConnectionLimiter, ConnectionPermit};
use bitcoin_rs_wire::mining::pool::stratum::sv2::{
    AdmitError, AuthorityKeypair, BlockSubmission, Connection, ERROR_CODE_SHARE_NOT_RECORDED,
    ERROR_CODE_SUBMIT_SHARES_STALE_SHARE, Event, Limits, MAX_FEED_LEN, PendingBlock, ServerConfig,
};
use bitcoin_rs_wire::mining::pool::{BlockStatus, PoolCore, RecordOutcome, ShareTarget};

use super::authority;
use super::ledger::{BlockRecordOutcome, BlockRecordPermit, DeferredCharge, LedgerHost};
use crate::config::PoolConfig;
use crate::run::{RunError, loopback_connect_addr};

const CERTIFICATE_VALIDITY: Duration = Duration::new(86_400, 0);
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(100);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

struct DeferredBlock {
    hash: BlockHash,
    pending: PendingBlock,
    submission: DeferredSubmission,
    attempts: u32,
    next_attempt: Instant,
    #[expect(dead_code, reason = "held for RAII drop cleanup")]
    charge: DeferredCharge,
}

enum DeferredSubmission {
    AwaitingAdmission,
    Submitted(BlockSubmission),
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
    mut clock: impl FnMut() -> Instant,
) -> Option<DeferredBlock> {
    if !matches!(ledger.found_block_recorded(entry.hash), Ok(true)) {
        return Some(entry);
    }
    let now = clock();
    let unresolved = match &entry.submission {
        DeferredSubmission::AwaitingAdmission => true,
        DeferredSubmission::Submitted(submission) => {
            submission.receipt().status() == BlockStatus::Undetermined
        }
    };
    if unresolved
        && entry.attempts < DEFERRED_RESUBMIT_ATTEMPTS
        && now >= entry.next_attempt
    {
        let submission = entry.pending.submit(control);
        entry.next_attempt = clock() + SOCKET_POLL_INTERVAL;
        match submission {
            Ok(fresh) if fresh.receipt().status() == BlockStatus::Applied => {
                core.invalidate_active();
                entry.submission = DeferredSubmission::Submitted(fresh);
            }
            Ok(fresh) if fresh.receipt().status() == BlockStatus::Rejected => {
                if fresh.receipt().is_stale_parent() {
                    let _ = connection.reject_block(&fresh, ERROR_CODE_SUBMIT_SHARES_STALE_SHARE);
                }
                return None;
            }
            Ok(fresh) => {
                entry.attempts += 1;
                entry.submission = DeferredSubmission::Submitted(fresh);
                return Some(entry);
            }
            Err(MiningControlError::Unavailable(_)) => return Some(entry),
            Err(error) => {
                entry.attempts += 1;
                log::warn!("deferred SV2 block {} submission failed: {error}", entry.hash);
                return Some(entry);
            }
        }
    }
    if let DeferredSubmission::Submitted(submission) = &entry.submission
        && submission.receipt().status() == BlockStatus::Applied
    {
        if connection.confirm_block(submission).is_err() {
            return Some(entry);
        }
        return None;
    }
    Some(entry)
}

pub(crate) struct Sv2Service {
    cancel: bitcoin_rs_consensus::latch::LatchWriter,
    listener: Option<JoinHandle<()>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    worker_panicked: Arc<AtomicBool>,
}

impl Sv2Service {
    pub(crate) fn stop(&self) {
        self.cancel.trigger();
    }
    pub(crate) fn stop_join(&mut self, deadline: Instant) -> Result<(), RunError> {
        self.stop();
        wait_until_finished(self.listener.as_ref(), deadline, "SV2 listener")?;
        if let Some(listener) = self.listener.take() {
            listener
                .join()
                .map_err(|_| RunError::PoolSv2ListenerPanicked)?;
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
                return Err(RunError::PoolSv2ConnectionJoinTimeout);
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
            return Err(RunError::PoolSv2ConnectionPanicked);
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

fn make_server_config(ledger: Arc<LedgerHost>, initial_target: ShareTarget) -> ServerConfig {
    let admit_user = Arc::new(move |identity: &[u8]| {
        let login = std::str::from_utf8(identity).map_err(|_| AdmitError::InvalidIdentity)?;
        ledger
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
    server_config
}

struct Sv2Services {
    core: Arc<PoolCore>,
    ledger: Arc<LedgerHost>,
    control: Arc<dyn MiningControl>,
}

struct ConnectionWorkerArgs {
    stream: TcpStream,
    peer: SocketAddr,
    permit: ConnectionPermit,
    authority: Arc<AuthorityKeypair>,
    server_config: ServerConfig,
    services: Sv2Services,
    cancel: bitcoin_rs_consensus::latch::LatchReader,
}

fn spawn_connection_worker(
    args: ConnectionWorkerArgs,
    connections: &Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let ConnectionWorkerArgs {
        stream,
        peer,
        permit,
        authority,
        server_config,
        services,
        cancel,
    } = args;
    match thread::Builder::new()
        .name(format!("pool-sv2-{}", peer.ip()))
        .spawn(move || {
            let _permit = permit;
            if let Err(error) =
                serve_connection(stream, &authority, server_config, &services, &cancel)
            {
                tracing::debug!(peer = %peer, %error, "SV2 connection closed");
            }
        }) {
        Ok(handle) => connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(handle),
        Err(error) => tracing::warn!(peer = %peer, %error, "could not spawn SV2 connection worker"),
    }
}

pub(crate) fn start(
    config: &PoolConfig,
    core: Arc<PoolCore>,
    ledger: Arc<LedgerHost>,
    control: Arc<dyn MiningControl>,
    cancel: bitcoin_rs_consensus::latch::LatchReader,
    limiter: Arc<ConnectionLimiter>,
) -> Result<Sv2Service, RunError> {
    let bind = config.sv2_bind.ok_or(RunError::PoolSv2BindMissing)?;
    let key_path = config
        .sv2_authority_key
        .as_deref()
        .ok_or(RunError::PoolSv2AuthorityKeyMissing)?;
    let authority = Arc::new(
        authority::load(key_path).map_err(|source| RunError::PoolSv2AuthorityKey { source })?,
    );
    let listener =
        TcpListener::bind(bind).map_err(|source| RunError::PoolSv2Bind { bind, source })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| RunError::PoolSv2Nonblocking { source })?;
    let connect_addr = loopback_connect_addr(local_addr);
    let service_cancel = cancel.child();
    let thread_cancel = service_cancel.reader();
    let cancel_hook = thread_cancel.on_cancel(move || {
        let _ = TcpStream::connect(connect_addr);
    });

    let connections = Arc::new(Mutex::new(Vec::new()));
    let thread_connections = Arc::clone(&connections);
    let worker_panicked = Arc::new(AtomicBool::new(false));
    let thread_panicked = Arc::clone(&worker_panicked);
    let initial_target = config.share_target;

    let listener_thread = thread::Builder::new()
        .name("pool-sv2-listener".to_owned())
        .spawn(move || {
            let _guard = cancel_hook;
            while !thread_cancel.is_triggered() {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        if thread_cancel.is_triggered() {
                            break;
                        }
                        reap_finished(&thread_connections, &thread_panicked);
                        let Ok(permit) = limiter.try_admit(peer.ip()) else {
                            drop(stream);
                            continue;
                        };
                        let server_config = make_server_config(Arc::clone(&ledger), initial_target);
                        let conn_writer = thread_cancel.child();
                        let cancel = conn_writer.reader();
                        let services = Sv2Services {
                            core: Arc::clone(&core),
                            ledger: Arc::clone(&ledger),
                            control: Arc::clone(&control),
                        };
                        spawn_connection_worker(
                            ConnectionWorkerArgs {
                                stream,
                                peer,
                                permit,
                                authority: Arc::clone(&authority),
                                server_config,
                                services,
                                cancel,
                            },
                            &thread_connections,
                        );
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        if !thread_cancel.is_triggered() {
                            tracing::error!(%error, "SV2 listener failed");
                        }
                        break;
                    }
                }
            }
        })
        .map_err(|source| RunError::PoolSv2ListenerSpawn { source })?;

    Ok(Sv2Service {
        cancel: service_cancel,
        listener: Some(listener_thread),
        connections,
        worker_panicked,
    })
}

fn process_deferred_blocks(
    deferred: &mut Vec<DeferredBlock>,
    ledger: &LedgerHost,
    control: &dyn MiningControl,
    connection: &mut Connection,
    core: &PoolCore,
) -> bool {
    let deferred_before = deferred.len();
    let mut still_deferred = Vec::with_capacity(deferred.len());
    for entry in std::mem::take(deferred) {
        if let Some(waiter) = settle_one_deferred(entry, ledger, control, connection, core, Instant::now) {
            still_deferred.push(waiter);
        }
    }
    *deferred = still_deferred;
    deferred.len() != deferred_before
}

fn flush_transmit(
    transmit: &mut PendingTransmit,
    connection: &mut Connection,
    stream: &mut TcpStream,
) -> Result<bool, RunError> {
    transmit.fill(connection);
    let pending_bytes = transmit.remaining();
    transmit.flush(stream)?;
    Ok(pending_bytes != transmit.remaining())
}

fn read_connection_input(
    stream: &mut TcpStream,
    connection: &Connection,
    input: &mut [u8],
) -> Result<Option<usize>, RunError> {
    let read_len = connection.read_hint().clamp(1, MAX_FEED_LEN);
    match stream.read(&mut input[..read_len]) {
        Ok(0) => Ok(None),
        Ok(length) => Ok(Some(length)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(Some(0))
        }
        Err(error) => Err(error.into()),
    }
}

fn configure_connection_stream(stream: &TcpStream) -> Result<(), RunError> {
    stream.set_nodelay(true)?;
    stream
        .set_read_timeout(Some(SOCKET_POLL_INTERVAL))
        .map_err(|source| RunError::PoolSv2Nonblocking { source })?;
    stream
        .set_write_timeout(Some(SOCKET_POLL_INTERVAL))
        .map_err(|source| RunError::PoolSv2Nonblocking { source })?;
    Ok(())
}

fn process_connection_turn(
    connection: &mut Connection,
    services: &Sv2Services,
    accounts: &mut HashMap<u32, MinerId>,
    pipeline: BlockPipeline<'_>,
    input: &[u8],
) -> Result<bool, RunError> {
    services
        .core
        .with_job_book(|book| connection.feed(input, book))?;
    let events_before = connection.session().pending_acks();
    handle_events(
        connection,
        &services.core,
        &services.ledger,
        &*services.control,
        accounts,
        pipeline,
    )?;
    let expired = services.core.with_job_book(|book| {
        connection
            .session_mut()
            .expire_tickets(book, Instant::now())
    });
    if !expired.is_empty() {
        tracing::debug!(count = expired.len(), "SV2 pending tickets expired");
    }
    Ok(events_before != connection.session().pending_acks() || !expired.is_empty())
}

fn serve_connection(
    mut stream: TcpStream,
    authority: &AuthorityKeypair,
    config: ServerConfig,
    services: &Sv2Services,
    cancel: &bitcoin_rs_consensus::latch::LatchReader,
) -> Result<(), RunError> {
    configure_connection_stream(&stream)?;
    let stream_clone = stream.try_clone()?;
    let _guard = cancel.on_cancel(move || {
        let _ = stream_clone.shutdown(std::net::Shutdown::Both);
    });
    let mut connection = services
        .core
        .with_job_book(|book| Connection::accept(authority, CERTIFICATE_VALIDITY, config, book))
        .map_err(|source| RunError::PoolSv2ConnectionAccept { source })?;
    let mut accounts = HashMap::new();
    let mut input = vec![0; MAX_FEED_LEN];
    let mut buffered_input = None;
    let mut deferred: Vec<DeferredBlock> = Vec::new();
    let mut transmit = PendingTransmit::default();
    let start = Instant::now();
    let mut last_progress = start;
    let result = (|| -> Result<(), RunError> {
        while !cancel.is_triggered() && !connection.is_closing() {
            if !connection.session().is_open() && start.elapsed() >= HANDSHAKE_TIMEOUT {
                return Err(RunError::PoolSv2HandshakeTimeout);
            }
            if last_progress.elapsed() >= IDLE_TIMEOUT {
                return Err(RunError::PoolSv2IdleTimeout);
            }
            if process_deferred_blocks(
                &mut deferred,
                &services.ledger,
                &*services.control,
                &mut connection,
                &services.core,
            ) {
                last_progress = Instant::now();
            }
            announce_current_job(&mut connection, &services.core)?;
            if flush_transmit(&mut transmit, &mut connection, &mut stream)? {
                last_progress = Instant::now();
            }

            if buffered_input.is_none() {
                match read_connection_input(&mut stream, &connection, &mut input)? {
                    None => break,
                    Some(0) => continue,
                    Some(length) => {
                        buffered_input = Some(length);
                        last_progress = Instant::now();
                    }
                }
            }

            let Some(block_permit) = services.ledger.try_reserve_block_slot() else {
                crossbeam_channel::select! {
                    recv(cancel.closed()) -> _ => break,
                    recv(crossbeam_channel::after(SOCKET_POLL_INTERVAL)) -> _ => continue,
                }
            };
            let mut block_permit = Some(block_permit);
            let length = buffered_input
                .take()
                .ok_or(RunError::PoolSv2BufferedInputMissing)?;
            let pipeline = BlockPipeline {
                permit: &mut block_permit,
                deferred: &mut deferred,
            };
            if process_connection_turn(
                &mut connection,
                services,
                &mut accounts,
                pipeline,
                &input[..length],
            )? {
                last_progress = Instant::now();
            }
            if flush_transmit(&mut transmit, &mut connection, &mut stream)? {
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
    services.core.with_job_book(|book| connection.release(book));
    result
}

fn announce_current_job(connection: &mut Connection, core: &PoolCore) -> Result<(), RunError> {
    if let Some(installed) = core.current_installed() {
        connection.announce(&installed)?;
    }
    Ok(())
}

fn handle_block_found(
    connection: &mut Connection,
    core: &PoolCore,
    control: &dyn MiningControl,
    account: MinerId,
    pending: PendingBlock,
    pipeline: BlockPipeline<'_>,
) -> Result<(), RunError> {
    let BlockPipeline {
        permit: block_permit,
        deferred,
    } = pipeline;
    let permit = block_permit
        .take()
        .ok_or(RunError::PoolSv2BlockReservationMissing)?;
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
    let (recorded, charge) = permit.record_or_enqueue(account, found, &receipt);
    if matches!(recorded, BlockRecordOutcome::Unrecordable) {
        return Err(RunError::PoolSv2BlockUnrecordable);
    }
    let should_defer = match &submission {
        Err(MiningControlError::Unavailable(_)) => true,
        Ok(submitted) => match submitted.receipt().status() {
            BlockStatus::Undetermined => true,
            BlockStatus::Applied => matches!(recorded, BlockRecordOutcome::Queued),
            BlockStatus::Rejected => false,
        },
        Err(_) => false,
    };
    if should_defer {
        let submission = match submission {
            Ok(submitted) => DeferredSubmission::Submitted(submitted),
            Err(MiningControlError::Unavailable(reason)) => {
                log::debug!("SV2 block {} awaits node admission: {reason}", found.share.hash);
                DeferredSubmission::AwaitingAdmission
            }
            Err(source) => return Err(RunError::PoolSv2BlockSubmissionFailed { source }),
        };
        let charge = charge.ok_or(match recorded {
            BlockRecordOutcome::Durable => RunError::PoolSv2DurableReservationMissing,
            BlockRecordOutcome::Queued => RunError::PoolSv2QueuedReservationMissing,
            BlockRecordOutcome::Unrecordable => RunError::PoolSv2BlockUnrecordable,
        })?;
        let next_attempt = if matches!(submission, DeferredSubmission::AwaitingAdmission) {
            Instant::now() + SOCKET_POLL_INTERVAL
        } else {
            Instant::now()
        };
        deferred.push(DeferredBlock {
            hash: found.share.hash,
            pending,
            submission,
            attempts: 0,
            next_attempt,
            charge,
        });
        return Ok(());
    }
    debug_assert!(charge.is_none());
    let submission =
        submission.map_err(|source| RunError::PoolSv2BlockSubmissionFailed { source })?;
    match submission.receipt().status() {
        BlockStatus::Applied => {
            connection.confirm_block(&submission)?;
        }
        BlockStatus::Undetermined => {
            return Err(RunError::PoolSv2UndeterminedReservationLost);
        }
        BlockStatus::Rejected if submission.receipt().is_stale_parent() => {
            connection.reject_block(&submission, ERROR_CODE_SUBMIT_SHARES_STALE_SHARE)?;
        }
        BlockStatus::Rejected => {
            return Err(RunError::PoolSv2BlockRejected);
        }
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
) -> Result<(), RunError> {
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
                    return Err(RunError::PoolSv2BlockChannelUnaccounted);
                };
                handle_block_found(
                    connection,
                    core,
                    control,
                    account,
                    pending,
                    BlockPipeline {
                        permit: block_permit,
                        deferred,
                    },
                )?;
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
    ) -> Result<(), RunError> {
        loop {
            self.fill(connection);
            self.flush(stream)?;
            self.fill(connection);
            if self.bytes.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(RunError::PoolSv2DrainTimeout);
            }
            thread::sleep(ACCEPT_POLL_INTERVAL);
        }
    }

    fn flush(&mut self, stream: &mut TcpStream) -> Result<(), RunError> {
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
) -> Result<(), RunError> {
    while handle.is_some_and(|handle| !handle.is_finished()) {
        if Instant::now() >= deadline {
            return Err(RunError::PoolSv2JoinTimeout {
                name: name.to_owned(),
            });
        }
        thread::sleep(ACCEPT_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use crate::pool::ledger::Ledger;
    use binary_sv2::{Encodable, GetSize, Str0255, U256};
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin_rs_chain::chain::compact_is_met_by;
    use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256, Network};
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_storage::KvStore;
    use bitcoin_rs_wire::context::PoolOperator as _;
    use bitcoin_rs_wire::mining::pool::ledger::{MinerId, PayoutPolicy, PoolConfig};
    use bitcoin_rs_wire::mining::pool::stratum::sv2::{
        AdmitError, AuthorityKeypair, Connection, FLAG_REQUIRES_STANDARD_JOBS, Limits, ServerConfig,
    };
    use bitcoin_rs_wire::mining::pool::{
        BIP320_VERSION_MASK, Extranonce, ExtranonceLayout, Job, JobBookConfig,
        MAX_NTIME_FORWARD_SECS, PoolCore, ShareLedger, ShareTarget,
    };
    use bitcoin_rs_wire::mining::{
        Candidate, CandidateContext, CoinbaseBudget, FakeMiningControl, MiningControl,
        assemble_candidate,
    };
    use codec_sv2::{
        Decoded, Decrypted, Handshake, InitiatorSent, MessageFrame, NoiseDecoder, NoiseEncoder,
        TransportDecryptState, TransportEncryptState,
    };
    use common_messages_sv2::{
        MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol,
        SetupConnection,
    };
    use mining_sv2::{
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
        MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
        OpenStandardMiningChannel, OpenStandardMiningChannelSuccess, SubmitSharesError,
        SubmitSharesStandard,
    };
    use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
    use zeroize::Zeroizing;

    use super::{BlockPipeline, DeferredBlock, LedgerHost, announce_current_job, handle_events};

    type TestResult = Result<(), FixtureError>;

    #[derive(Debug, thiserror::Error)]
    enum FixtureError {
        #[error("SV2 {stage} failed: {detail}")]
        Sv2 { stage: &'static str, detail: String },
        #[error("miner fixture is missing {0}")]
        Missing(&'static str),
        #[error("no received frame has type {0:#04x}")]
        NoFrame(u8),
        #[error("fewer than {0} nonces of the requested class exist")]
        NonceSpace(usize),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        Ledger(#[from] bitcoin_rs_wire::mining::pool::ledger::LedgerError),
        #[error(transparent)]
        Mining(#[from] bitcoin_rs_wire::mining::MiningError),
        #[error(transparent)]
        Job(#[from] bitcoin_rs_wire::mining::pool::JobError),
        #[error(transparent)]
        Secp(#[from] bitcoin::secp256k1::Error),
        #[error(transparent)]
        Sv2Config(#[from] bitcoin_rs_wire::mining::pool::stratum::sv2::ConfigError),
        #[error(transparent)]
        Transport(#[from] bitcoin_rs_wire::mining::pool::stratum::sv2::Error),
        #[error(transparent)]
        Run(#[from] crate::run::RunError),
    }

    fn sv2<E: std::fmt::Debug>(stage: &'static str) -> impl FnOnce(E) -> FixtureError {
        move |error| FixtureError::Sv2 {
            stage,
            detail: format!("{error:?}"),
        }
    }

    type Store = bitcoin_rs_storage::RocksDbStore;

    const LOGIN: &str = "42.rig";
    const PAYOUT: &[u8] = &[0x51];
    const EPOCH: u32 = 17;

    fn ledger_host(path: &Path) -> Result<Arc<LedgerHost>, FixtureError> {
        let store: Arc<dyn KvStore> = Arc::new(Store::open_with_cache(path, 0)?);
        let ledger = Ledger::create(store, PoolConfig::new(1_000, PAYOUT.to_vec()))?;
        ledger.set_payout_script(MinerId(42), PAYOUT)?;
        Ok(Arc::new(LedgerHost::new(
            Arc::new(ledger),
            EPOCH,
            PayoutPolicy {
                min_payout_sat: 1_000,
                max_outputs: 10,
            },
        )))
    }

    fn candidate(height: u32, parent: u8) -> Result<Arc<Candidate>, FixtureError> {
        let context = CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[parent; 32]),
            height,
            version: 0x2000_0000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            min_time: 1_700_000_001,
            current_time: 1_700_000_600,
            locktime_cutoff: 1_700_000_000,
            staged_parent_mtp: 1_700_000_000,
            coinbase_reserve: bitcoin_rs_wire::mining::CoinbaseReserve::EXACT,
            network: Network::Regtest,
            csv_active: true,
            segwit_active: true,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
        };
        let pool = Mempool::new(MempoolLimits::default());
        Ok(Arc::new(assemble_candidate(&context, &pool, PAYOUT)?))
    }

    fn pool_core(
        control: &Arc<FakeMiningControl>,
        ledger: &Arc<LedgerHost>,
    ) -> Result<PoolCore, FixtureError> {
        let control: Arc<dyn MiningControl> = Arc::<FakeMiningControl>::clone(control);
        let ledger: Arc<dyn ShareLedger> = Arc::<LedgerHost>::clone(ledger);
        let config = JobBookConfig {
            budget: CoinbaseBudget {
                additional_size: 0,
                additional_sigops: 0,
            },
            extranonce: ExtranonceLayout::new(4, 4),
            coinbase_tag: b"/btcrs/".to_vec(),
            version_mask: BIP320_VERSION_MASK,
            ntime_forward_secs: MAX_NTIME_FORWARD_SECS,
            max_jobs: 8,
            max_sessions: 4,
            max_shares_per_job: 64,
        };
        Ok(PoolCore::new(config, control, ledger)?)
    }

    fn server_config(ledger: &Arc<LedgerHost>) -> Result<ServerConfig, FixtureError> {
        let mut config = ServerConfig::new(ShareTarget::from_le_bytes([0xff; 32])?);
        config.limits = Limits {
            max_frame_payload: 8 * 1024,
            max_channels: 8,
            max_jobs_per_channel: 16,
            max_pending_acks: 16,
            pending_ack_timeout: Limits::DEFAULT.pending_ack_timeout,
            max_outbound_frames: 256,
            max_pending_events: 32,
            max_outbound_bytes: 1_048_576,
        };
        let ledger = Arc::clone(ledger);
        config.admit_user = Arc::new(move |identity: &[u8]| {
            let login = std::str::from_utf8(identity).map_err(|_| AdmitError::InvalidIdentity)?;
            ledger
                .account(login)
                .map(|_| ())
                .ok_or(AdmitError::UnknownUser)
        });
        Ok(config)
    }

    fn authority() -> Result<AuthorityKeypair, FixtureError> {
        let secp = Secp256k1::new();
        let pair = Keypair::from_seckey_slice(&secp, &[0x11; 32])?;
        Ok(AuthorityKeypair::from_bytes(
            pair.x_only_public_key().0.serialize(),
            Zeroizing::new(pair.secret_bytes()),
        ))
    }

    struct Frame {
        msg_type: u8,
        payload: Vec<u8>,
    }

    struct Channel {
        id: u32,
        prefix: Vec<u8>,
    }

    struct Miner {
        enc: TransportEncryptState,
        dec: Option<TransportDecryptState>,
        encoder: NoiseEncoder,
        decoder: NoiseDecoder,
        inbuf: Vec<u8>,
    }

    fn text(value: &'static str) -> Result<Str0255<'static>, FixtureError> {
        Str0255::try_from(value).map_err(sv2("text"))
    }

    impl Miner {
        fn seal<T: Encodable + GetSize>(
            &mut self,
            msg_type: u8,
            channel_msg: bool,
            msg: T,
        ) -> Result<Vec<u8>, FixtureError> {
            let frame =
                MessageFrame::from_message(msg, msg_type, 0, channel_msg).map_err(sv2("frame"))?;
            let sealed = self
                .encoder
                .encode_transport(frame, &mut self.enc)
                .map_err(sv2("encrypt"))?;
            let bytes: &[u8] = sealed.as_ref();
            Ok(bytes.to_vec())
        }

        fn open(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, FixtureError> {
            self.inbuf.extend_from_slice(bytes);
            let mut frames = Vec::new();
            loop {
                let state = self
                    .dec
                    .take()
                    .ok_or(FixtureError::Missing("decrypt state"))?;
                match self
                    .decoder
                    .next_transport_frame(state)
                    .map_err(sv2("server frame"))?
                {
                    Decrypted::Frame(mut frame, state) => {
                        self.dec = Some(state);
                        let msg_type = frame.header().msg_type();
                        frames.push(Frame {
                            msg_type,
                            payload: frame.payload().to_vec(),
                        });
                    }
                    Decrypted::Incomplete(state) => {
                        self.dec = Some(state);
                        let want = self.decoder.read_len();
                        if self.inbuf.len() < want {
                            break;
                        }
                        let window = self.decoder.read_buf();
                        window.copy_from_slice(&self.inbuf[..want]);
                        self.inbuf.drain(..want);
                        self.decoder.advance(want).map_err(sv2("server frame"))?;
                    }
                }
            }
            Ok(frames)
        }

        fn setup(&mut self) -> Result<Vec<u8>, FixtureError> {
            let setup = SetupConnection {
                protocol: Protocol::MiningProtocol,
                min_version: 2,
                max_version: 2,
                flags: FLAG_REQUIRES_STANDARD_JOBS,
                endpoint_host: text("pool.invalid")?,
                endpoint_port: 3333,
                vendor: text("host-test")?,
                hardware_version: text("sim-1")?,
                firmware: text("fw-0")?,
                device_id: text("")?,
            };
            self.seal(MESSAGE_TYPE_SETUP_CONNECTION, false, setup)
        }

        fn open_channel(&mut self) -> Result<Vec<u8>, FixtureError> {
            let open = OpenStandardMiningChannel {
                request_id: 7,
                user_identity: text(LOGIN)?,
                nominal_hash_rate: 1.0e12,
                max_target: U256::from(&[0xff_u8; 32]),
            };
            self.seal(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, false, open)
        }

        fn submit(
            &mut self,
            channel: &Channel,
            sequence_number: u32,
            job: &Job,
            nonce: u32,
        ) -> Result<Vec<u8>, FixtureError> {
            let share = SubmitSharesStandard {
                channel_id: channel.id,
                sequence_number,
                job_id: job.id().get(),
                nonce,
                ntime: job.ntime(),
                version: job.version(),
            };
            self.seal(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true, share)
        }
    }

    fn handshake(
        connection: &mut Connection,
        core: &PoolCore,
        pinned: [u8; 32],
    ) -> Result<Miner, FixtureError> {
        let initiator =
            Handshake::initiator(Initiator::from_raw_k(pinned).map_err(sv2("authority key"))?);
        let (act1, initiator) = initiator.step_0().map_err(sv2("handshake step 0"))?;
        let mut encoder = NoiseEncoder::new();
        let wire = encoder.encode_handshake(act1);
        let wire: &[u8] = wire.as_ref();
        core.with_job_book(|book| connection.feed(wire, book))
            .map_err(sv2("server feed"))?;
        let reply = connection.take_transmit();
        let mut decoder = NoiseDecoder::new();
        let mut offset = 0;
        let act2 = loop {
            match decoder
                .next_handshake_frame::<InitiatorSent>()
                .map_err(sv2("handshake decode"))?
            {
                Decoded::Frame(frame) => break frame,
                Decoded::Incomplete => {
                    let window = decoder.read_buf();
                    let end = offset + window.len();
                    window.copy_from_slice(
                        reply
                            .get(offset..end)
                            .ok_or(FixtureError::Missing("handshake reply bytes"))?,
                    );
                    let len = window.len();
                    offset = end;
                    decoder.advance(len).map_err(sv2("handshake decode"))?;
                }
            }
        };
        let act2: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] = act2
            .payload()
            .try_into()
            .map_err(|_| FixtureError::Missing("act 2 of the expected length"))?;
        let transport = initiator.step_2(act2).map_err(sv2("handshake step 2"))?;
        let (enc, dec) = transport.split();
        Ok(Miner {
            enc,
            dec: Some(dec),
            encoder,
            decoder: NoiseDecoder::new(),
            inbuf: Vec::new(),
        })
    }

    fn header_hash(job: &Job, prefix: &[u8], nonce: u32) -> Result<BlockHash, FixtureError> {
        let (session, rolled) = prefix.split_at(job.extranonce_layout().session_len());
        job.header(
            Extranonce { session, rolled },
            job.ntime(),
            job.version(),
            nonce,
        )
        .map(|header| header.compute_hash())
        .map_err(sv2("header"))
    }

    fn block_nonces(job: &Job, prefix: &[u8], count: usize) -> Result<Vec<u32>, FixtureError> {
        nonces(job, prefix, true, count)
    }

    fn share_nonce(job: &Job, prefix: &[u8]) -> Result<u32, FixtureError> {
        nonces(job, prefix, false, 1)?
            .pop()
            .ok_or(FixtureError::NonceSpace(1))
    }

    fn nonces(
        job: &Job,
        prefix: &[u8],
        meets_target: bool,
        count: usize,
    ) -> Result<Vec<u32>, FixtureError> {
        let mut found = Vec::with_capacity(count);
        for nonce in 0..u32::MAX {
            let hash = header_hash(job, prefix, nonce)?;
            if compact_is_met_by(job.bits(), Hash256::from(hash)) == meets_target {
                found.push(nonce);
                if found.len() == count {
                    return Ok(found);
                }
            }
        }
        Err(FixtureError::NonceSpace(count))
    }

    fn take(frames: &mut Vec<Frame>, msg_type: u8) -> Result<Frame, FixtureError> {
        let at = frames
            .iter()
            .position(|frame| frame.msg_type == msg_type)
            .ok_or(FixtureError::NoFrame(msg_type))?;
        Ok(frames.remove(at))
    }

    fn has(frames: &[Frame], msg_type: u8) -> bool {
        frames.iter().any(|frame| frame.msg_type == msg_type)
    }

    fn share_error(frames: &mut Vec<Frame>) -> Result<(u32, String), FixtureError> {
        let mut frame = take(frames, MESSAGE_TYPE_SUBMIT_SHARES_ERROR)?;
        let error: SubmitSharesError =
            binary_sv2::from_bytes(&mut frame.payload).map_err(sv2("share error decode"))?;
        Ok((error.sequence_number, error.error_code.as_utf8_or_hex()))
    }

    struct Host {
        core: PoolCore,
        ledger: Arc<LedgerHost>,
        control: Arc<FakeMiningControl>,
        connection: Connection,
        accounts: HashMap<u32, MinerId>,
        miner: Miner,
        job: Arc<Job>,
        deferred: Vec<DeferredBlock>,
        _directory: tempfile::TempDir,
    }

    impl Host {
        fn new() -> Result<Self, FixtureError> {
            let directory = tempfile::tempdir()?;
            let ledger = ledger_host(directory.path())?;
            let control = Arc::new(FakeMiningControl::default());
            let core = pool_core(&control, &ledger)?;
            let job = core.install(candidate(100, 0xab)?, Vec::new())?.job;
            let authority = authority()?;
            let config = server_config(&ledger)?;
            let mut connection = core.with_job_book(|book| {
                Connection::accept(&authority, Duration::from_secs(3_600), config, book)
            })?;
            let miner = handshake(&mut connection, &core, *authority.public())?;
            Ok(Self {
                core,
                ledger,
                control,
                connection,
                accounts: HashMap::new(),
                miner,
                job,
                deferred: Vec::new(),
                _directory: directory,
            })
        }

        fn deliver(&mut self, wire: &[u8]) -> Result<Vec<Frame>, FixtureError> {
            announce_current_job(&mut self.connection, &self.core)?;
            let permit = self
                .ledger
                .try_reserve_block_slot()
                .ok_or(FixtureError::Missing("block record permit"))?;
            let mut permit = Some(permit);
            self.core
                .with_job_book(|book| self.connection.feed(wire, book))?;
            handle_events(
                &mut self.connection,
                &self.core,
                &self.ledger,
                self.control.as_ref(),
                &mut self.accounts,
                BlockPipeline {
                    permit: &mut permit,
                    deferred: &mut self.deferred,
                },
            )?;
            let sent = self.connection.take_transmit();
            self.miner.open(&sent)
        }

        fn open_channel(&mut self) -> Result<Channel, FixtureError> {
            let setup = self.miner.setup()?;
            let frames = self.deliver(&setup)?;
            assert!(has(&frames, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS));
            let open = self.miner.open_channel()?;
            let mut frames = self.deliver(&open)?;
            let mut frame = take(
                &mut frames,
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            )?;
            let opened: OpenStandardMiningChannelSuccess =
                binary_sv2::from_bytes(&mut frame.payload).map_err(sv2("open decode"))?;
            let channel = Channel {
                id: opened.channel_id,
                prefix: opened.extranonce_prefix.as_bytes().to_vec(),
            };
            assert_eq!(self.accounts.get(&channel.id), Some(&MinerId(42)));
            Ok(channel)
        }

        fn submit(
            &mut self,
            channel: &Channel,
            sequence_number: u32,
            job: &Job,
            nonce: u32,
        ) -> Result<Vec<Frame>, FixtureError> {
            let wire = self.miner.submit(channel, sequence_number, job, nonce)?;
            self.deliver(&wire)
        }

        fn node_submissions(&self) -> usize {
            self.control.submit_calls.load(Ordering::Relaxed)
        }

        fn credited_shares(&self) -> Result<u64, FixtureError> {
            Ok(self.ledger.ledger().share_count()?)
        }
    }

    fn new_parent_work_is_accepted(host: &mut Host, channel: &Channel) -> TestResult {
        let next = host.core.install(candidate(101, 0xcd)?, Vec::new())?.job;
        let nonce = share_nonce(&next, &channel.prefix)?;
        let frames = host.submit(channel, 4, &next, nonce)?;
        assert!(has(&frames, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        assert_eq!(host.credited_shares()?, 2);
        assert_eq!(host.node_submissions(), 1);
        Ok(())
    }

    #[test]
    fn applied_sv2_block_retires_the_common_job_before_a_sibling_reaches_the_node() -> TestResult {
        let mut host = Host::new()?;
        let channel = host.open_channel()?;
        let job = Arc::clone(&host.job);
        let winners = block_nonces(&job, &channel.prefix, 2)?;
        let &[first, second] = winners.as_slice() else {
            return Err(FixtureError::NonceSpace(2));
        };

        let applied = host.submit(&channel, 1, &job, first)?;
        assert!(has(&applied, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        assert_eq!(host.node_submissions(), 1);
        let first_hash = header_hash(&job, &channel.prefix, first)?;
        assert!(host.ledger.found_block_recorded(first_hash)?);
        assert_eq!(host.credited_shares()?, 1);

        let sibling = host.submit(&channel, 2, &job, second);
        assert_eq!(
            host.node_submissions(),
            1,
            "sibling winner reached the node after an Applied block"
        );
        let mut frames = sibling?;
        assert_eq!(share_error(&mut frames)?, (2, "stale-share".to_owned()));
        let second_hash = header_hash(&job, &channel.prefix, second)?;
        assert!(!host.ledger.found_block_recorded(second_hash)?);
        assert_eq!(host.credited_shares()?, 1);

        let mut frames = host.submit(&channel, 3, &job, first)?;
        assert_eq!(share_error(&mut frames)?, (3, "duplicate-share".to_owned()));
        assert_eq!(host.node_submissions(), 1);
        assert_eq!(host.credited_shares()?, 1);

        new_parent_work_is_accepted(&mut host, &channel)
    }

    #[test]
    fn undetermined_sv2_block_withholds_success_and_retries_authoritative_state() -> TestResult {
        let mut host = Host::new()?;
        let channel = host.open_channel()?;
        let job = Arc::clone(&host.job);
        let winner = block_nonces(&job, &channel.prefix, 1)?
            .pop()
            .ok_or(FixtureError::NonceSpace(1))?;

        *host.control.submit.lock() = bitcoin_rs_wire::mining::BlockValidationResult::Inconclusive;
        let pending = host.submit(&channel, 1, &job, winner)?;
        assert!(
            !has(&pending, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS),
            "Undetermined success must be withheld, not confirmed"
        );
        let hash = header_hash(&job, &channel.prefix, winner)?;
        assert!(host.ledger.found_block_recorded(hash)?);
        assert_eq!(host.deferred.len(), 1, "Undetermined work is retained");
        assert_eq!(host.node_submissions(), 1);

        *host.control.submit.lock() = bitcoin_rs_wire::mining::BlockValidationResult::Accepted;
        let entry = host
            .deferred
            .pop()
            .ok_or(FixtureError::Missing("retained waiter"))?;
        let waiter = super::settle_one_deferred(
            entry,
            &host.ledger,
            host.control.as_ref(),
            &mut host.connection,
            &host.core,
            std::time::Instant::now,
        );
        assert!(
            waiter.is_none(),
            "Applied retry confirms and drops the waiter"
        );
        assert_eq!(
            host.node_submissions(),
            2,
            "deferred retry re-queries node state"
        );
        let confirmed = host.miner.open(&host.connection.take_transmit())?;
        assert!(has(&confirmed, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        Ok(())
    }

    // POOL-03, POOL-05
    #[test]
    fn unavailable_sv2_submission_retains_its_bounded_block_until_admission_recovers() -> TestResult {
        let mut host = Host::new()?;
        let channel = host.open_channel()?;
        let job = Arc::clone(&host.job);
        let winner = block_nonces(&job, &channel.prefix, 1)?
            .pop()
            .ok_or(FixtureError::NonceSpace(1))?;
        *host.control.fail.lock() = Some(bitcoin_rs_wire::mining::MiningControlError::Unavailable(
            "image budget is full".into(),
        ));
        let frames = host.submit(&channel, 1, &job, winner)?;
        assert!(!has(&frames, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        assert!(!has(&frames, MESSAGE_TYPE_SUBMIT_SHARES_ERROR));
        assert!(!host.connection.is_closing());
        assert_eq!(host.node_submissions(), 1);
        assert_eq!(host.deferred.len(), 1);
        let hash = header_hash(&job, &channel.prefix, winner)?;
        assert!(host.ledger.found_block_recorded(hash)?);
        assert_eq!(host.credited_shares()?, 1);
        let remaining = (0..7)
            .map(|_| {
                host.ledger
                    .try_reserve_block_slot()
                    .ok_or(FixtureError::Missing("remaining bounded slot"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(host.ledger.try_reserve_block_slot().is_none());

        for attempt in 0..7 {
            let entry = host
                .deferred
                .pop()
                .ok_or(FixtureError::Missing("admission waiter"))?;
            let now = entry.next_attempt;
            let entry = super::settle_one_deferred(
                entry,
                &host.ledger,
                host.control.as_ref(),
                &mut host.connection,
                &host.core,
                || now - Duration::from_nanos(1),
            )
            .ok_or(FixtureError::Missing("waiter before retry deadline"))?;
            assert_eq!(host.node_submissions(), 1 + attempt);
            let entry = super::settle_one_deferred(
                entry,
                &host.ledger,
                host.control.as_ref(),
                &mut host.connection,
                &host.core,
                || now,
            )
            .ok_or(FixtureError::Missing("waiter under continued refusal"))?;
            host.deferred.push(entry);
            assert_eq!(host.node_submissions(), 2 + attempt);
            assert!(host.ledger.try_reserve_block_slot().is_none());
            assert!(host.connection.take_transmit().is_empty());
            assert!(!host.connection.is_closing());
            assert_eq!(host.credited_shares()?, 1);
        }

        *host.control.fail.lock() = None;
        let entry = host
            .deferred
            .pop()
            .ok_or(FixtureError::Missing("recoverable admission waiter"))?;
        let now = entry.next_attempt;
        assert!(
            super::settle_one_deferred(
                entry,
                &host.ledger,
                host.control.as_ref(),
                &mut host.connection,
                &host.core,
                || now,
            )
            .is_none()
        );
        assert_eq!(host.node_submissions(), 9);
        let confirmed = host.miner.open(&host.connection.take_transmit())?;
        assert!(has(&confirmed, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        assert_eq!(host.credited_shares()?, 1);
        let mut duplicate = host.submit(&channel, 2, &job, winner)?;
        assert_eq!(share_error(&mut duplicate)?, (2, "duplicate-share".to_owned()));
        assert_eq!(host.node_submissions(), 9);
        assert_eq!(host.credited_shares()?, 1);
        let released = host
            .ledger
            .try_reserve_block_slot()
            .ok_or(FixtureError::Missing("released deferred slot"))?;
        assert!(host.ledger.try_reserve_block_slot().is_none());
        drop(released);
        drop(remaining);
        Ok(())
    }

    // POOL-03
    #[test]
    fn unavailable_retry_deadline_starts_after_submission_completes() -> TestResult {
        let mut host = Host::new()?;
        let channel = host.open_channel()?;
        let job = Arc::clone(&host.job);
        let winner = block_nonces(&job, &channel.prefix, 1)?
            .pop()
            .ok_or(FixtureError::NonceSpace(1))?;
        *host.control.fail.lock() = Some(bitcoin_rs_wire::mining::MiningControlError::Unavailable(
            "image budget is full".into(),
        ));
        let frames = host.submit(&channel, 1, &job, winner)?;
        assert!(!has(&frames, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        let entry = host
            .deferred
            .pop()
            .ok_or(FixtureError::Missing("admission waiter"))?;
        let started_at = entry.next_attempt;
        let completed_at = started_at + Duration::from_secs(2);
        let mut started = false;
        let clock = || {
            if started {
                completed_at
            } else {
                started = true;
                started_at
            }
        };
        let entry = super::settle_one_deferred(
            entry,
            &host.ledger,
            host.control.as_ref(),
            &mut host.connection,
            &host.core,
            clock,
        )
        .ok_or(FixtureError::Missing("waiter after slow submission"))?;
        assert_eq!(host.node_submissions(), 2);
        let entry = super::settle_one_deferred(
            entry,
            &host.ledger,
            host.control.as_ref(),
            &mut host.connection,
            &host.core,
            || completed_at + Duration::from_millis(99),
        )
        .ok_or(FixtureError::Missing("waiter before completion deadline"))?;
        assert_eq!(host.node_submissions(), 2);
        *host.control.fail.lock() = None;
        assert!(
            super::settle_one_deferred(
                entry,
                &host.ledger,
                host.control.as_ref(),
                &mut host.connection,
                &host.core,
                || completed_at + Duration::from_millis(100),
            )
            .is_none()
        );
        assert_eq!(host.node_submissions(), 3);
        let frames = host.miner.open(&host.connection.take_transmit())?;
        assert!(has(&frames, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        assert_eq!(host.credited_shares()?, 1);
        Ok(())
    }

    // POOL-05
    #[test]
    fn terminal_sv2_submission_errors_do_not_enter_the_admission_retry_queue() -> TestResult {
        use bitcoin_rs_wire::mining::MiningControlError;

        for error in [
            MiningControlError::InvalidRequest("invalid submission".into()),
            MiningControlError::Rejected("invalid block".into()),
            MiningControlError::Failed("fatal submission failure".into()),
        ] {
            let mut host = Host::new()?;
            let channel = host.open_channel()?;
            let job = Arc::clone(&host.job);
            let winner = block_nonces(&job, &channel.prefix, 1)?
                .pop()
                .ok_or(FixtureError::NonceSpace(1))?;
            *host.control.fail.lock() = Some(error.clone());
            let result = host.submit(&channel, 1, &job, winner);
            assert!(matches!(
                result,
                Err(FixtureError::Run(crate::run::RunError::PoolSv2BlockSubmissionFailed {
                    source
                })) if source == error
            ));
            assert!(host.deferred.is_empty());
            let slots = (0..8)
                .map(|_| {
                    host.ledger
                        .try_reserve_block_slot()
                        .ok_or(FixtureError::Missing("released terminal slot"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert!(host.ledger.try_reserve_block_slot().is_none());
            drop(slots);
        }
        Ok(())
    }

    // POOL-09
    #[test]
    fn reaped_worker_panic_propagates_through_stop_join() {
        use std::sync::Mutex;
        use std::sync::atomic::AtomicBool;
        use std::time::Instant;

        let connections: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let worker_panicked = Arc::new(AtomicBool::new(false));
        connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(std::thread::spawn(|| panic!("reaped SV2 worker boom")));
        while !connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .all(std::thread::JoinHandle::is_finished)
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        super::reap_finished(&connections, &worker_panicked);
        assert!(
            worker_panicked.load(Ordering::Acquire),
            "reap retains the worker panic"
        );
        assert!(
            connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "reaped handle leaves no join for stop_join"
        );
        let cancel = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut service = super::Sv2Service {
            cancel,
            listener: None,
            connections,
            worker_panicked,
        };
        let Err(error) = service.stop_join(Instant::now() + Duration::from_secs(5)) else {
            panic!("reaped panic must fail shutdown");
        };
        assert!(
            error.to_string().contains("panicked"),
            "unexpected error: {error:?}"
        );
    }

    // POOL-09
    #[test]
    fn stop_join_joins_remaining_workers_after_panic() {
        use std::sync::Mutex;
        use std::sync::atomic::AtomicBool;
        use std::time::Instant;

        let connections: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let worker_panicked = Arc::new(AtomicBool::new(false));
        {
            let mut guard = connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.push(std::thread::spawn(|| panic!("stop_join SV2 worker boom")));
            guard.push(std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
            }));
        }
        let cancel = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut service = super::Sv2Service {
            cancel,
            listener: None,
            connections: Arc::clone(&connections),
            worker_panicked: Arc::clone(&worker_panicked),
        };
        let Err(error) = service.stop_join(Instant::now() + Duration::from_secs(5)) else {
            panic!("worker panic must fail shutdown");
        };
        assert!(
            error.to_string().contains("panicked"),
            "unexpected error: {error:?}"
        );
        assert!(
            worker_panicked.load(Ordering::Acquire),
            "panic flag survives shutdown"
        );
        assert!(
            connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "stop_join joins every remaining worker"
        );
    }

    #[test]
    fn sv2_listener_stops_promptly_on_cancellation() -> TestResult {
        let cancel = bitcoin_rs_consensus::latch::LatchWriter::new();
        let cancel_reader = cancel.reader();
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").map_err(|error| FixtureError::Sv2 {
                stage: "bind",
                detail: error.to_string(),
            })?;
        let local_addr = listener.local_addr().map_err(|error| FixtureError::Sv2 {
            stage: "local_addr",
            detail: error.to_string(),
        })?;
        let cancel_hook = cancel_reader.on_cancel(move || {
            let _ = std::net::TcpStream::connect(local_addr);
        });
        let (tx, rx) = crossbeam_channel::bounded(1);
        let handle = std::thread::spawn(move || {
            let _guard = cancel_hook;
            while !cancel_reader.is_triggered() {
                match listener.accept() {
                    Ok((_stream, _peer)) => {
                        if cancel_reader.is_triggered() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = tx.send(());
        });
        std::thread::sleep(Duration::from_millis(5));
        cancel.trigger();
        let res = rx.recv_timeout(Duration::from_secs(5));
        assert!(
            res.is_ok(),
            "join deadline exceeded: sv2 listener did not exit within 5 seconds"
        );
        assert!(handle.join().is_ok(), "thread panicked");
        Ok(())
    }
}
