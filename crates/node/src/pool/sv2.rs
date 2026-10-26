use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow};
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_stratum::{BlockStatus, ConnectionLimiter, PoolCore};
use bitcoin_rs_stratum_v2::{
    AdmitError, AuthorityKeypair, Connection, ERROR_CODE_SHARE_NOT_RECORDED,
    ERROR_CODE_SUBMIT_SHARES_STALE_SHARE, Event, Limits, MAX_FEED_LEN, ServerConfig,
};
use pool_ledger::MinerId;

use super::authority;
use super::ledger::{BlockRecordOutcome, BlockRecordPermit, LedgerHost};
use crate::config::PoolConfig;

const CERTIFICATE_VALIDITY: Duration = Duration::new(86_400, 0);
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(100);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Owned SV2 listener and connection threads.
pub(crate) struct Sv2Service {
    cancel: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Sv2Service {
    /// Stops admission and asks every connection to drain and release its owner sessions.
    pub(crate) fn stop(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    /// Stops admission and joins every runtime thread before `deadline`.
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
        for connection in self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            connection
                .join()
                .map_err(|_| anyhow!("SV2 connection thread panicked"))?;
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
    let initial_target = config.share_target;

    let listener_thread = thread::Builder::new()
        .name("pool-sv2-listener".to_owned())
        .spawn(move || {
            while !thread_cancel.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        reap_finished(&thread_connections);
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
                            max_pending_acks: 1,
                            max_pending_events: 1,
                            ..Limits::DEFAULT
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
    let mut transmit = PendingTransmit::default();
    let result = (|| -> Result<()> {
        while !cancel.load(Ordering::Acquire) && !connection.is_closing() {
            announce_current_job(&mut connection, core)?;
            transmit.fill(&mut connection);
            transmit.flush(&mut stream)?;

            if buffered_input.is_none() {
                let read_len = connection.read_hint().clamp(1, MAX_FEED_LEN);
                match stream.read(&mut input[..read_len]) {
                    Ok(0) => break,
                    Ok(length) => buffered_input = Some(length),
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
            handle_events(
                &mut connection,
                core,
                ledger,
                control,
                &mut accounts,
                &mut block_permit,
            )?;
            transmit.fill(&mut connection);
            transmit.flush(&mut stream)?;
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
    if let Some(mut installed) = core.current_installed() {
        // `fresh` describes the owner's latest refresh, not whether this
        // connection has received the job. Distribution itself is idempotent.
        installed.fresh = true;
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
    block_permit: &mut Option<BlockRecordPermit>,
) -> Result<()> {
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
                        ledger
                            .record_accepted_share(account, &event.outcome)
                            .is_ok()
                    });
                if recorded {
                    connection.confirm_share(event.ticket)?;
                } else {
                    connection.reject_share(event.ticket, ERROR_CODE_SHARE_NOT_RECORDED)?;
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
                // The node's Applied verdict is authoritative: retire the job
                // before any ledger or socket step below can return early.
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
                    BlockRecordOutcome::Durable => {}
                    BlockRecordOutcome::Queued => {
                        return Err(anyhow!(
                            "SV2 block record queued for durable reconciliation"
                        ));
                    }
                    BlockRecordOutcome::Unrecordable => {
                        return Err(anyhow!(
                            "SV2 block cannot be represented by the durable ledger"
                        ));
                    }
                }
                let submission = submission.context("SV2 block submission failed")?;
                match submission.receipt().status() {
                    BlockStatus::Applied | BlockStatus::Undetermined => {
                        connection.confirm_block(&submission)?;
                    }
                    BlockStatus::Rejected if submission.receipt().is_stale_parent() => {
                        connection
                            .reject_block(&submission, ERROR_CODE_SUBMIT_SHARES_STALE_SHARE)?;
                    }
                    BlockStatus::Rejected => {
                        // A rejected node verdict remains a pending accounting
                        // round until chain reconciliation. Do not send a
                        // success acknowledgement for the rejected submission.
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
    // A feed can validate at most one block under the configured adapter
    // limits. Release an unconsumed reservation after this feed/event drain.
    drop(block_permit.take());
    Ok(())
}

fn reap_finished(connections: &Mutex<Vec<JoinHandle<()>>>) {
    let mut connections = connections
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < connections.len() {
        if connections[index].is_finished() {
            let handle = connections.swap_remove(index);
            if handle.join().is_err() {
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

/// Host-path regression: a real `Connection` is driven through the node's own
/// `announce_current_job` / `handle_events` against a real `PoolCore`,
/// `LedgerHost`, and a recording `MiningControl`. Nothing here calls
/// `invalidate_active`; only the host's `Applied` handling may retire the job.
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
    use bitcoin_rs_mining::{
        Candidate, CandidateContext, CoinbaseBudget, FakeMiningControl, MiningControl,
        assemble_candidate,
    };
    use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};
    use bitcoin_rs_rpc::context::PoolOperator as _;
    use bitcoin_rs_storage::KvStore;
    use bitcoin_rs_stratum::{
        BIP320_VERSION_MASK, Extranonce, ExtranonceLayout, Job, JobBookConfig,
        MAX_NTIME_FORWARD_SECS, PoolCore, ShareLedger, ShareTarget,
    };
    use bitcoin_rs_stratum_v2::{
        AdmitError, AuthorityKeypair, Connection, FLAG_REQUIRES_STANDARD_JOBS, Limits, ServerConfig,
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
    use pool_ledger::{Ledger, MinerId, PayoutPolicy};
    use zeroize::Zeroizing;

    use super::{LedgerHost, announce_current_job, handle_events};

    type TestResult = Result<(), Box<dyn Error>>;

    /// Failure of the miner-side fixture itself, never of the host under test.
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

    // ---- host fixtures: the node's real composition, minus sockets ----------

    fn ledger_host(path: &Path) -> Result<Arc<LedgerHost>, Box<dyn Error>> {
        let store: Arc<dyn KvStore> = Arc::new(Store::open(path)?);
        let ledger = Ledger::create(store, pool_ledger::PoolConfig::new(1_000, PAYOUT.to_vec()))?;
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

    /// The connection configuration `start` builds for every accepted socket.
    fn server_config(ledger: &Arc<LedgerHost>) -> Result<ServerConfig, Box<dyn Error>> {
        let mut config = ServerConfig::new(ShareTarget::from_le_bytes([0xff; 32])?);
        config.limits = Limits {
            max_pending_acks: 1,
            max_pending_events: 1,
            ..Limits::DEFAULT
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

    /// A fixed, disposable authority key pair; never a real key.
    fn authority() -> Result<AuthorityKeypair, Box<dyn Error>> {
        let secp = Secp256k1::new();
        let pair = Keypair::from_seckey_slice(&secp, &[0x11; 32])?;
        Ok(AuthorityKeypair::from_bytes(
            pair.x_only_public_key().0.serialize(),
            Zeroizing::new(pair.secret_bytes()),
        ))
    }

    // ---- the miner side: a real Noise initiator over the same SRI crates ----

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

    /// Runs the miner's half of `Noise_NX` against the pinned authority.
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

    // ---- deterministic work -------------------------------------------------

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

    /// The first `count` nonces whose header meets the network target.
    fn block_nonces(job: &Job, prefix: &[u8], count: usize) -> Result<Vec<u32>, FixtureError> {
        nonces(job, prefix, true, count)
    }

    /// The first nonce whose header misses the network target: a plain share.
    fn share_nonce(job: &Job, prefix: &[u8]) -> Result<u32, FixtureError> {
        nonces(job, prefix, false, 1)?
            .pop()
            .ok_or(FixtureError::NonceSpace(1))
    }

    /// Scans upward from zero over the whole `u32` space. The job fixes every
    /// other header field, so the answer is fixed: no clock, no randomness.
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

    /// `(sequence_number, error_code)` of the one `SubmitShares.Error` in `frames`.
    fn share_error(frames: &mut Vec<Frame>) -> Result<(u32, String), FixtureError> {
        let mut frame = take(frames, MESSAGE_TYPE_SUBMIT_SHARES_ERROR)?;
        let error: SubmitSharesError =
            binary_sv2::from_bytes(&mut frame.payload).map_err(sv2("share error decode"))?;
        Ok((error.sequence_number, error.error_code.as_utf8_or_hex()))
    }

    // ---- the host under test ------------------------------------------------

    struct Host {
        core: PoolCore,
        ledger: Arc<LedgerHost>,
        control: Arc<FakeMiningControl>,
        connection: Connection,
        accounts: HashMap<u32, MinerId>,
        miner: Miner,
        job: Arc<Job>,
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
                _directory: directory,
            })
        }

        /// One `serve_connection` iteration: announce, reserve the block
        /// record permit, feed, then the node's own `handle_events`.
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
                &mut permit,
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

    /// After the retirement the same connection carries work on a new parent.
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

        // The node applies the first winner; the host acknowledges it only
        // after the durable found-block record.
        let applied = host.submit(&channel, 1, &job, first)?;
        assert!(has(&applied, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS));
        assert_eq!(host.node_submissions(), 1);
        let first_hash = header_hash(&job, &channel.prefix, first)?;
        assert!(host.ledger.found_block_recorded(first_hash)?);
        assert_eq!(host.credited_shares()?, 1);

        // A distinct winner on the same job is stale: the host's `Applied`
        // handling is the only thing that retired the job.
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

        // The exact accepted replay keeps its duplicate identity.
        let mut frames = host.submit(&channel, 3, &job, first)?;
        assert_eq!(share_error(&mut frames)?, (3, "duplicate-share".to_owned()));
        assert_eq!(host.node_submissions(), 1);
        assert_eq!(host.credited_shares()?, 1);

        new_parent_work_is_accepted(&mut host, &channel)
    }
}
