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
    BIP320_VERSION_MASK, Extranonce, ExtranonceLayout, Job, JobBookConfig, MAX_NTIME_FORWARD_SECS,
    PoolCore, ShareLedger, ShareTarget,
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
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol, SetupConnection,
};
use mining_sv2::{
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
    MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, OpenStandardMiningChannel,
    OpenStandardMiningChannelSuccess, SubmitSharesError, SubmitSharesStandard,
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
