use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::pool::ledger::MinerId;
use bitcoin_rs_mining::pool::stratum::sv1::{ConnectionLimiter, ConnectionPermit};
use bitcoin_rs_mining::pool::stratum::sv2::{
    AdmitError, AuthorityKeypair, BlockSubmission, Connection, ERROR_CODE_SHARE_NOT_RECORDED,
    ERROR_CODE_SUBMIT_SHARES_STALE_SHARE, Event, Limits, MAX_FEED_LEN, PendingBlock, ServerConfig,
};
use bitcoin_rs_mining::pool::{BlockStatus, PoolCore, RecordOutcome, ShareTarget};
use bitcoin_rs_primitives::BlockHash;

use super::authority;
use super::ledger::{BlockRecordOutcome, BlockRecordPermit, DeferredCharge, LedgerHost};
use crate::config::PoolConfig;
use crate::run::RunError;

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
    #[expect(dead_code, reason = "held for RAII drop cleanup")]
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
    cancel: bitcoin_rs_chain::LatchWriter,
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

fn loopback_connect_addr(local_addr: SocketAddr) -> SocketAddr {
    match local_addr {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        ),
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            addr.port(),
        ),
        addr => addr,
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
    cancel: bitcoin_rs_chain::LatchReader,
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
    cancel: impl Into<bitcoin_rs_chain::LatchReader>,
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
    let parent_cancel = cancel.into();
    let service_cancel = parent_cancel.child();
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
        if let Some(waiter) = settle_one_deferred(entry, ledger, control, connection, core) {
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
    cancel: &bitcoin_rs_chain::LatchReader,
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
    match permit.record_or_enqueue(account, found, &receipt) {
        (BlockRecordOutcome::Durable, charge) => {
            if matches!(
                &submission,
                Ok(submitted) if submitted.receipt().status() == BlockStatus::Undetermined
            ) {
                let Ok(submitted) = submission else {
                    return Err(RunError::PoolSv2BlockSubmissionLost);
                };
                let hash = found.share.hash;
                let Some(charge) = charge else {
                    return Err(RunError::PoolSv2DurableReservationMissing);
                };
                deferred.push(DeferredBlock {
                    hash,
                    pending,
                    submission: submitted,
                    attempts: 0,
                    charge,
                });
                return Ok(());
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
                    return Err(RunError::PoolSv2BlockSubmissionLost);
                };
                let hash = found.share.hash;
                let Some(charge) = charge else {
                    return Err(RunError::PoolSv2QueuedReservationMissing);
                };
                deferred.push(DeferredBlock {
                    hash,
                    pending,
                    submission: submitted,
                    attempts: 0,
                    charge,
                });
                return Ok(());
            }
        }
        (BlockRecordOutcome::Unrecordable, _) => {
            return Err(RunError::PoolSv2BlockUnrecordable);
        }
    }
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

#[cfg(all(test, any(feature = "fjall", feature = "redb")))]
mod tests;
