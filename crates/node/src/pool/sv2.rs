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
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use binary_sv2::{Encodable, GetSize, Str0255, U256};
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin_rs_chain::compact_is_met_by;
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_mining::pool::ledger::{Ledger, MinerId, PayoutPolicy, PoolConfig};
    use bitcoin_rs_mining::pool::stratum::sv2::{
        AdmitError, AuthorityKeypair, Connection, FLAG_REQUIRES_STANDARD_JOBS, Limits, ServerConfig,
    };
    use bitcoin_rs_mining::pool::{
        BIP320_VERSION_MASK, Extranonce, ExtranonceLayout, Job, JobBookConfig,
        MAX_NTIME_FORWARD_SECS, PoolCore, ShareLedger, ShareTarget,
    };
    use bitcoin_rs_mining::{
        Candidate, CandidateContext, CoinbaseBudget, FakeMiningControl, MiningControl,
        assemble_candidate,
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};
    use bitcoin_rs_rpc::context::PoolOperator as _;
    use bitcoin_rs_storage::KvStore;
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

    type TestResult = Result<(), Box<dyn Error>>;

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
    }

    fn sv2<E: std::fmt::Debug>(stage: &'static str) -> impl FnOnce(E) -> FixtureError {
        move |error| FixtureError::Sv2 {
            stage,
            detail: format!("{error:?}"),
        }
    }

    #[cfg(feature = "fjall")]
    type Store = bitcoin_rs_storage::FjallStore;
    #[cfg(all(feature = "redb", not(feature = "fjall")))]
    type Store = bitcoin_rs_storage::RedbStore;

    const LOGIN: &str = "42.rig";
    const PAYOUT: &[u8] = &[0x51];
    const EPOCH: u32 = 17;

    fn ledger_host(path: &Path) -> Result<Arc<LedgerHost>, Box<dyn Error>> {
        let store: Arc<dyn KvStore> = Arc::new(Store::open(path)?);
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

    fn candidate(height: u32, parent: u8) -> Result<Arc<Candidate>, Box<dyn Error>> {
        let context = CandidateContext {
            previous_block_hash: Hash256::from_le_bytes(&[parent; 32]),
            height,
            version: 0x2000_0000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            min_time: 1_700_000_001,
            current_time: 1_700_000_600,
            locktime_cutoff: 1_700_000_000,
            staged_parent_mtp: 1_700_000_000,
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
    ) -> Result<PoolCore, Box<dyn Error>> {
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

    fn server_config(ledger: &Arc<LedgerHost>) -> Result<ServerConfig, Box<dyn Error>> {
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

    fn authority() -> Result<AuthorityKeypair, Box<dyn Error>> {
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
                let want = self.decoder.writable_len();
                if self.inbuf.len() < want {
                    break;
                }
                if want > 0 {
                    self.decoder.writable().copy_from_slice(&self.inbuf[..want]);
                    self.inbuf.drain(..want);
                }
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
                    Decrypted::Incomplete(_, state) => self.dec = Some(state),
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
            let window = decoder.writable();
            let end = offset + window.len();
            window.copy_from_slice(
                reply
                    .get(offset..end)
                    .ok_or(FixtureError::Missing("handshake reply bytes"))?,
            );
            offset = end;
            match decoder
                .next_handshake_frame::<InitiatorSent>()
                .map_err(sv2("handshake decode"))?
            {
                Decoded::Frame(frame) => break frame,
                Decoded::Incomplete(_) => {}
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
        fn new() -> Result<Self, Box<dyn Error>> {
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

        fn deliver(&mut self, wire: &[u8]) -> Result<Vec<Frame>, Box<dyn Error>> {
            announce_current_job(&mut self.connection, &self.core)?;
            let permit = self
                .ledger
                .try_reserve_block_slot()
                .ok_or("block record slot unavailable")?;
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
            Ok(self.miner.open(&sent)?)
        }

        fn open_channel(&mut self) -> Result<Channel, Box<dyn Error>> {
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
        ) -> Result<Vec<Frame>, Box<dyn Error>> {
            let wire = self.miner.submit(channel, sequence_number, job, nonce)?;
            self.deliver(&wire)
        }

        fn node_submissions(&self) -> usize {
            self.control.submit_calls.load(Ordering::Relaxed)
        }

        fn credited_shares(&self) -> Result<u64, Box<dyn Error>> {
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
            return Err("two winning nonces exist".into());
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
            .ok_or("a winning nonce exists")?;

        *host.control.submit.lock() = bitcoin_rs_mining::BlockValidationResult::Inconclusive;
        let pending = host.submit(&channel, 1, &job, winner)?;
        assert!(
            !has(&pending, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS),
            "Undetermined success must be withheld, not confirmed"
        );
        let hash = header_hash(&job, &channel.prefix, winner)?;
        assert!(host.ledger.found_block_recorded(hash)?);
        assert_eq!(host.deferred.len(), 1, "Undetermined work is retained");
        assert_eq!(host.node_submissions(), 1);

        *host.control.submit.lock() = bitcoin_rs_mining::BlockValidationResult::Accepted;
        let entry = host.deferred.pop().ok_or("retained waiter missing")?;
        let waiter = super::settle_one_deferred(
            entry,
            &host.ledger,
            host.control.as_ref(),
            &mut host.connection,
            &host.core,
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

    #[test]
    fn reaped_worker_panic_propagates_through_stop_join() -> TestResult {
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
            .all(|handle| handle.is_finished())
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
        let cancel = Arc::new(AtomicBool::new(false));
        let mut service = super::Sv2Service {
            cancel,
            listener: None,
            connections,
            worker_panicked,
        };
        let error = service
            .stop_join(Instant::now() + Duration::from_secs(5))
            .expect_err("reaped panic must fail shutdown");
        assert!(
            error.to_string().contains("panicked"),
            "unexpected error: {error:?}"
        );
        Ok(())
    }

    #[test]
    fn stop_join_joins_remaining_workers_after_panic() -> TestResult {
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
        let cancel = Arc::new(AtomicBool::new(false));
        let mut service = super::Sv2Service {
            cancel,
            listener: None,
            connections: Arc::clone(&connections),
            worker_panicked: Arc::clone(&worker_panicked),
        };
        let error = service
            .stop_join(Instant::now() + Duration::from_secs(5))
            .expect_err("worker panic must fail shutdown");
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
        Ok(())
    }
}
