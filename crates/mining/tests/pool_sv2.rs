use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binary_sv2::{B064K, B0255, Decodable, Encodable, GetSize, Seq0255, Str0255, U256};
use bitcoin_rs_chain::compact_is_met_by;
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_mempool::{
    AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolGateway,
    MempoolLimits, SubmitOutcome,
};
use bitcoin_rs_mining::pool::stratum::sv2::{
    AuthorityKeypair, CloseReason, Connection, Error, Event, FLAG_REQUIRES_STANDARD_JOBS,
    FLAG_REQUIRES_VERSION_ROLLING, FLAG_REQUIRES_WORK_SELECTION, Limits, ROLES, RoleStatus,
    SUCCESS_FLAG_REQUIRES_FIXED_VERSION, ServerConfig, SessionError, TransportError,
    target_difficulty,
};
use bitcoin_rs_mining::pool::{
    BIP320_VERSION_MASK, Extranonce, ExtranonceLayout, Installed, Job, JobBook, JobBookConfig,
    JobId, ShareClass, ShareError, ShareTarget,
};
use bitcoin_rs_mining::{
    BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, Candidate, CandidateContext,
    CoinbaseBudget, GenerateRequest, GeneratedBlock, MiningControl, MiningControlError, MiningInfo,
    STALE_PARENT_REASON, assemble_candidate,
};
use bitcoin_rs_primitives::{
    Amount, BlockPayload, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, encode::double_sha256,
};
use bitcoin_rs_script::VerifyFlags;
use codec_sv2::{
    Decoded, Decrypted, Handshake, InitiatorSent, MessageFrame, NoiseDecoder, NoiseEncoder,
    TransportDecryptState, TransportEncryptState,
};
use common_messages_sv2::{
    MESSAGE_TYPE_RECONNECT, MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol, SetupConnection, SetupConnectionError,
    SetupConnectionSuccess,
};
use mining_sv2::{
    CloseChannel, MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB, MESSAGE_TYPE_NEW_MINING_JOB,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
    MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR, MESSAGE_TYPE_SET_TARGET,
    MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
    MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
    MESSAGE_TYPE_UPDATE_CHANNEL, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR, NewExtendedMiningJob,
    NewMiningJob, OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess,
    OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess,
    SetCustomMiningJob, SetCustomMiningJobError, SetNewPrevHash, SetTarget, SubmitSharesError,
    SubmitSharesExtended, SubmitSharesStandard, SubmitSharesSuccess, UpdateChannel,
    UpdateChannelError,
};
use noise_sv2::{ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PAYOUT: &[u8] = &[0x51];
const ALL_ONES: [u8; 32] = [0xff; 32];
const WHOLE: usize = 1 << 20;

#[derive(Debug)]
struct TestError(String);

impl std::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TestError {}

impl From<String> for TestError {
    fn from(error: String) -> Self {
        Self(error)
    }
}

type TestResult<T = ()> = Result<T, TestError>;

fn context(height: u32, parent: u8) -> CandidateContext {
    CandidateContext {
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
    }
}

const COIN_VALUE_SAT: u64 = 1_000_000;
const ADMISSION_TIME: u64 = 1_700_000_000;

fn wsh_true_script() -> Vec<u8> {
    let program: [u8; 32] = Sha256::digest([0x51_u8]).into();
    let mut script = vec![0x00, 0x20];
    script.extend_from_slice(&program);
    script
}

fn p2wpkh_script(label: u8) -> Vec<u8> {
    let mut script = vec![0x00, 0x14];
    script.extend_from_slice(&[label; 20]);
    script
}

fn coin_outpoint(label: u8) -> OutPoint {
    let mut bytes = [0xc0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
}

fn spend(label: u8) -> Tx {
    let mut tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: coin_outpoint(label),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: Script::from_bytes(p2wpkh_script(label)),
        }],
        lock_time: LockTime::ZERO,
    };
    let fee = tx.vsize() * (2 + u64::from(label));
    tx.outputs[0].value = Amount::from_sat(COIN_VALUE_SAT - fee);
    tx
}

struct Coins(HashMap<OutPoint, TxOut>);

impl AdmissionChain for Coins {
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        let prevouts = tx
            .inputs
            .iter()
            .filter_map(|input| {
                self.0
                    .get(&input.previous_output)
                    .map(|output| (input.previous_output, output.clone()))
            })
            .collect();
        Some(ChainAdmissionSnapshot {
            prevouts,
            height: 1,
            locktime_cutoff: 0,
            csv_active: false,
            next_block_script_flags: VerifyFlags::STANDARD,
            confirmed: false,
            ..ChainAdmissionSnapshot::default()
        })
    }
}

fn admitted_gateway(count: u8) -> MempoolGateway {
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        None,
    );
    let script = wsh_true_script();
    let coins = Coins(
        (1..=count)
            .map(|label| {
                (
                    coin_outpoint(label),
                    TxOut {
                        value: Amount::from_sat(COIN_VALUE_SAT),
                        script_pubkey: Script::from_bytes(script.clone()),
                    },
                )
            })
            .collect(),
    );
    for label in 1..=count {
        let outcome = gateway
            .submit_transaction(
                Arc::new(spend(label)),
                AdmissionOrigin::Rpc,
                None,
                ADMISSION_TIME,
                &coins,
            )
            .unwrap_or_else(|error| panic!("gateway accepts the fixture submission: {error:?}"));
        assert!(
            matches!(outcome, SubmitOutcome::Committed(_)),
            "fixture transaction {label} was not committed: {outcome:?}"
        );
    }
    gateway
}

fn candidate(height: u32, parent: u8, txs: u8) -> Arc<Candidate> {
    let gateway = admitted_gateway(txs);
    let candidate = assemble_candidate(&context(height, parent), &gateway.read(), PAYOUT)
        .unwrap_or_else(|error| panic!("candidate assembles: {error:?}"));
    assert_eq!(candidate.transactions.len(), usize::from(txs));
    assert!(
        candidate
            .transactions
            .iter()
            .all(|entry| Hash256::from(entry.txid) != Hash256::from(entry.wtxid)),
        "fixture transactions carry witness data"
    );
    Arc::new(candidate)
}

fn book_config(version_mask: u32) -> JobBookConfig {
    JobBookConfig {
        budget: CoinbaseBudget {
            additional_size: 200,
            additional_sigops: 100,
        },
        extranonce: ExtranonceLayout::new(4, 4),
        coinbase_tag: b"/pool/".to_vec(),
        version_mask,
        ntime_forward_secs: 600,
        max_jobs: 8,
        max_sessions: 16,
        max_shares_per_job: 64,
    }
}

fn server_config() -> ServerConfig {
    ServerConfig::new(
        ShareTarget::from_le_bytes(ALL_ONES)
            .unwrap_or_else(|error| panic!("nonzero target: {error:?}")),
    )
}

fn fresh_authority() -> AuthorityKeypair {
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
    AuthorityKeypair::from_bytes(
        keypair.x_only_public_key().0.serialize(),
        Zeroizing::new(keypair.secret_bytes()),
    )
}

#[derive(Debug)]
struct Received {
    msg_type: u8,
    channel_msg: bool,
    payload: Vec<u8>,
}

fn parse<'a, T: Decodable<'a>>(received: &'a mut Received) -> T {
    binary_sv2::from_bytes(&mut received.payload)
        .unwrap_or_else(|error| panic!("message decodes: {error:?}"))
}

fn take_type(frames: &mut Vec<Received>, msg_type: u8) -> Received {
    let at = frames
        .iter()
        .position(|frame| frame.msg_type == msg_type)
        .unwrap_or_else(|| panic!("frame of that type present"));
    frames.remove(at)
}

fn types(frames: &[Received]) -> Vec<u8> {
    frames.iter().map(|frame| frame.msg_type).collect()
}

struct Client {
    enc: TransportEncryptState,
    dec: Option<TransportDecryptState>,
    encoder: NoiseEncoder,
    decoder: NoiseDecoder,
    inbuf: Vec<u8>,
}

impl Client {
    fn seal<T: Encodable + GetSize>(&mut self, msg_type: u8, channel_msg: bool, msg: T) -> Vec<u8> {
        self.seal_ext(msg_type, 0, channel_msg, msg)
    }

    fn seal_ext<T: Encodable + GetSize>(
        &mut self,
        msg_type: u8,
        extension_type: u16,
        channel_msg: bool,
        msg: T,
    ) -> Vec<u8> {
        let frame = MessageFrame::from_message(msg, msg_type, extension_type, channel_msg)
            .unwrap_or_else(|error| panic!("frame fits: {error:?}"));
        let encrypted = self
            .encoder
            .encode_transport(frame, &mut self.enc)
            .unwrap_or_else(|error| panic!("client encrypts: {error:?}"));
        let bytes: &[u8] = encrypted.as_ref();
        bytes.to_vec()
    }

    fn open(&mut self, bytes: &[u8]) -> Vec<Received> {
        self.inbuf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let want = self.decoder.writable_len();
            if self.inbuf.len() < want {
                break;
            }
            if want > 0 {
                let window = self.decoder.writable();
                window.copy_from_slice(&self.inbuf[..want]);
                self.inbuf.drain(..want);
            }
            let state = self
                .dec
                .take()
                .unwrap_or_else(|| panic!("decrypt state present"));
            match self
                .decoder
                .next_transport_frame(state)
                .unwrap_or_else(|error| panic!("server frames authenticate and decode: {error:?}"))
            {
                Decrypted::Frame(mut frame, state) => {
                    self.dec = Some(state);
                    let header = frame.header();
                    out.push(Received {
                        msg_type: header.msg_type(),
                        channel_msg: header.channel_msg(),
                        payload: frame.payload().to_vec(),
                    });
                }
                Decrypted::Incomplete(_, state) => self.dec = Some(state),
            }
        }
        out
    }
}

fn handshake(
    server: &mut Connection,
    book: &mut JobBook,
    pinned: [u8; 32],
    chunk: usize,
) -> Result<Client, TestError> {
    let initiator = Handshake::initiator(
        Initiator::from_raw_k(pinned).map_err(|e| format!("authority key: {e:?}"))?,
    );
    let (act1, initiator) = initiator.step_0().map_err(|e| format!("step 0: {e:?}"))?;
    let mut encoder = NoiseEncoder::new();
    let wire = encoder.encode_handshake(act1);
    let wire: &[u8] = wire.as_ref();
    assert_eq!(wire.len(), ELLSWIFT_ENCODING_SIZE);
    for piece in wire.chunks(chunk) {
        server
            .feed(piece, book)
            .map_err(|e| format!("server feed: {e:?}"))?;
    }
    let reply = server.take_transmit();
    assert_eq!(reply.len(), INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE);

    let mut decoder = NoiseDecoder::new();
    let mut offset = 0;
    let act2 = loop {
        let window = decoder.writable();
        let len = window.len();
        window.copy_from_slice(&reply[offset..offset + len]);
        offset += len;
        match decoder
            .next_handshake_frame::<InitiatorSent>()
            .map_err(|e| format!("decode handshake: {e:?}"))?
        {
            Decoded::Frame(frame) => break frame,
            Decoded::Incomplete(_) => {}
        }
    };
    let act2: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] = act2
        .payload()
        .try_into()
        .map_err(|_| "act 2 length".to_owned())?;
    let transport = initiator
        .step_2(act2)
        .map_err(|e| format!("step 2: {e:?}"))?;
    let (enc, dec) = transport.split();
    Ok(Client {
        enc,
        dec: Some(dec),
        encoder,
        decoder: NoiseDecoder::new(),
        inbuf: Vec::new(),
    })
}

#[derive(Clone, Copy)]
struct ShareWork {
    job_id: u32,
    nonce: u32,
    ntime: u32,
    version: u32,
}

struct Wire {
    conn: Connection,
    book: JobBook,
    client: Client,
    chunk: usize,
}

impl Wire {
    fn with(chunk: usize, config: ServerConfig, version_mask: u32) -> Self {
        let authority = fresh_authority();
        let mut book = JobBook::new(book_config(version_mask))
            .unwrap_or_else(|error| panic!("book config: {error:?}"));
        let mut conn = Connection::accept(&authority, Duration::from_secs(3_600), config, &book)
            .unwrap_or_else(|error| panic!("connection config: {error:?}"));
        let client = handshake(&mut conn, &mut book, *authority.public(), chunk)
            .unwrap_or_else(|error| panic!("handshake with the pinned authority: {error:?}"));
        Self {
            conn,
            book,
            client,
            chunk,
        }
    }

    fn new() -> Self {
        Self::with(WHOLE, server_config(), BIP320_VERSION_MASK)
    }

    fn try_exchange<T: Encodable + GetSize>(
        &mut self,
        msg_type: u8,
        channel_msg: bool,
        msg: T,
    ) -> Result<Vec<Received>, Error> {
        let bytes = self.client.seal(msg_type, channel_msg, msg);
        for piece in bytes.chunks(self.chunk) {
            self.conn.feed(piece, &mut self.book)?;
        }
        Ok(self.drain())
    }

    fn exchange<T: Encodable + GetSize>(
        &mut self,
        msg_type: u8,
        channel_msg: bool,
        msg: T,
    ) -> Vec<Received> {
        self.try_exchange(msg_type, channel_msg, msg)
            .unwrap_or_else(|error| panic!("server accepts the frame: {error:?}"))
    }

    fn drain(&mut self) -> Vec<Received> {
        let bytes = self.conn.take_transmit();
        self.client.open(&bytes)
    }

    fn events(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        while let Some(event) = self.conn.poll_event() {
            out.push(event);
        }
        out
    }

    fn setup(&mut self, protocol: Protocol, min: u16, max: u16, flags: u32) -> Vec<Received> {
        let msg = SetupConnection {
            protocol,
            min_version: min,
            max_version: max,
            flags,
            endpoint_host: Str0255::try_from("pool.invalid")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            endpoint_port: 3333,
            vendor: Str0255::try_from("test-miner")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            hardware_version: Str0255::try_from("sim-1")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            firmware: Str0255::try_from("fw-0").unwrap_or_else(|error| panic!("short: {error:?}")),
            device_id: Str0255::try_from("").unwrap_or_else(|error| panic!("empty: {error:?}")),
        };
        self.exchange(MESSAGE_TYPE_SETUP_CONNECTION, false, msg)
    }

    fn setup_mining(&mut self, flags: u32) -> u32 {
        let mut frames = self.setup(Protocol::MiningProtocol, 2, 2, flags);
        assert_eq!(types(&frames), vec![MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS]);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS);
        assert!(!frame.channel_msg);
        let success: SetupConnectionSuccess = parse(&mut frame);
        assert_eq!(success.used_version, 2);
        success.flags
    }

    fn open_standard(
        &mut self,
        request_id: u32,
        user: &str,
        max_target: [u8; 32],
    ) -> Vec<Received> {
        let msg = OpenStandardMiningChannel {
            request_id,
            user_identity: Str0255::try_from(user)
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            nominal_hash_rate: 1.0e12,
            max_target: U256::from(&max_target),
        };
        self.exchange(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, false, msg)
    }

    fn open_extended(
        &mut self,
        request_id: u32,
        user: &str,
        max_target: [u8; 32],
        min_extranonce_size: u16,
    ) -> Vec<Received> {
        let msg = OpenExtendedMiningChannel {
            request_id,
            user_identity: Str0255::try_from(user)
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            nominal_hash_rate: 5.0e12,
            max_target: U256::from(&max_target),
            min_extranonce_size,
        };
        self.exchange(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, false, msg)
    }

    fn submit_standard(
        &mut self,
        channel_id: u32,
        sequence_number: u32,
        job_id: u32,
        nonce: u32,
        ntime: u32,
        version: u32,
    ) -> Vec<Received> {
        let msg = SubmitSharesStandard {
            channel_id,
            sequence_number,
            job_id,
            nonce,
            ntime,
            version,
        };
        self.exchange(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true, msg)
    }

    fn submit_extended(
        &mut self,
        channel_id: u32,
        sequence_number: u32,
        work: ShareWork,
        extranonce: &[u8],
    ) -> Vec<Received> {
        let msg = SubmitSharesExtended {
            channel_id,
            sequence_number,
            job_id: work.job_id,
            nonce: work.nonce,
            ntime: work.ntime,
            version: work.version,
            extranonce: binary_sv2::B032::new(extranonce)
                .unwrap_or_else(|error| panic!("at most 32 bytes: {error:?}")),
        };
        self.exchange(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, true, msg)
    }

    fn job(&self, job_id: u32) -> Arc<Job> {
        Arc::clone(
            self.book
                .job(JobId::new(job_id))
                .unwrap_or_else(|| panic!("owner retains the job")),
        )
    }
}

struct Opened {
    channel_id: u32,
    group_id: u32,
    prefix: Vec<u8>,
    target: [u8; 32],
    extranonce_size: Option<u16>,
}

fn read_open_standard(frames: &mut Vec<Received>) -> Opened {
    let mut frame = take_type(frames, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS);
    assert!(!frame.channel_msg);
    let ok: OpenStandardMiningChannelSuccess = parse(&mut frame);
    Opened {
        channel_id: ok.channel_id,
        group_id: ok.group_channel_id,
        prefix: ok.extranonce_prefix.as_bytes().to_vec(),
        target: *ok.target.as_array(),
        extranonce_size: None,
    }
}

fn read_open_extended(frames: &mut Vec<Received>) -> Opened {
    let mut frame = take_type(frames, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS);
    assert!(!frame.channel_msg);
    let ok: OpenExtendedMiningChannelSuccess = parse(&mut frame);
    Opened {
        channel_id: ok.channel_id,
        group_id: ok.group_channel_id,
        prefix: ok.extranonce_prefix.as_bytes().to_vec(),
        target: *ok.target.as_array(),
        extranonce_size: Some(ok.extranonce_size),
    }
}

struct StdJob {
    channel_id: u32,
    job_id: u32,
    min_ntime: Option<u32>,
    version: u32,
    merkle_root: [u8; 32],
}

fn read_std_job(frames: &mut Vec<Received>) -> StdJob {
    let mut frame = take_type(frames, MESSAGE_TYPE_NEW_MINING_JOB);
    assert!(frame.channel_msg);
    let msg: NewMiningJob = parse(&mut frame);
    StdJob {
        channel_id: msg.channel_id,
        job_id: msg.job_id,
        version: msg.version,
        merkle_root: *msg.merkle_root.as_array(),
        min_ntime: msg.min_ntime.into_inner(),
    }
}

struct ExtJob {
    channel_id: u32,
    job_id: u32,
    min_ntime: Option<u32>,
    version: u32,
    rolling_allowed: bool,
    path: Vec<[u8; 32]>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

fn read_ext_job(frames: &mut Vec<Received>) -> ExtJob {
    let mut frame = take_type(frames, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB);
    assert!(frame.channel_msg);
    let msg: NewExtendedMiningJob = parse(&mut frame);
    ExtJob {
        channel_id: msg.channel_id,
        job_id: msg.job_id,
        version: msg.version,
        rolling_allowed: msg.version_rolling_allowed,
        path: msg
            .merkle_path
            .into_inner()
            .iter()
            .map(|hash| *hash.as_array())
            .collect(),
        prefix: msg.coinbase_tx_prefix.as_bytes().to_vec(),
        suffix: msg.coinbase_tx_suffix.as_bytes().to_vec(),
        min_ntime: msg.min_ntime.into_inner(),
    }
}

struct PrevHash {
    channel_id: u32,
    job_id: u32,
    prev: [u8; 32],
    min_ntime: u32,
    nbits: u32,
}

fn read_prev_hash(frames: &mut Vec<Received>) -> PrevHash {
    let mut frame = take_type(frames, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH);
    assert!(frame.channel_msg);
    let msg: SetNewPrevHash = parse(&mut frame);
    PrevHash {
        channel_id: msg.channel_id,
        job_id: msg.job_id,
        prev: *msg.prev_hash.as_array(),
        min_ntime: msg.min_ntime,
        nbits: msg.nbits,
    }
}

fn share_error(frames: &mut Vec<Received>) -> (u32, u32, String) {
    let mut frame = take_type(frames, MESSAGE_TYPE_SUBMIT_SHARES_ERROR);
    assert!(frame.channel_msg);
    let msg: SubmitSharesError = parse(&mut frame);
    (
        msg.channel_id,
        msg.sequence_number,
        msg.error_code.as_utf8_or_hex(),
    )
}

fn accepted(events: Vec<Event>) -> bitcoin_rs_mining::pool::stratum::sv2::ShareEvent {
    events
        .into_iter()
        .find_map(|event| match event {
            Event::ShareAccepted(share) => Some(share),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a share was accepted"))
}

fn find_nonce(job: &Job, extranonce_prefix: &[u8], version: u32, class: ShareClass) -> u32 {
    let (session, rolled) = extranonce_prefix.split_at(job.extranonce_layout().session_len());
    (0..u32::MAX)
        .find(|nonce| {
            let header = job
                .header(Extranonce { session, rolled }, job.ntime(), version, *nonce)
                .unwrap_or_else(|error| panic!("header builds: {error:?}"));
            let is_block = compact_is_met_by(job.bits(), Hash256::from(header.compute_hash()));
            is_block == (class == ShareClass::Block)
        })
        .unwrap_or_else(|| panic!("a nonce of the wanted class exists"))
}

fn share_nonce(job: &Job, extranonce_prefix: &[u8], version: u32) -> u32 {
    find_nonce(job, extranonce_prefix, version, ShareClass::Share)
}

fn block_nonce(job: &Job, extranonce_prefix: &[u8], version: u32) -> u32 {
    find_nonce(job, extranonce_prefix, version, ShareClass::Block)
}

struct Standard {
    wire: Wire,
    opened: Opened,
    job: Arc<Job>,
}

fn standard_with_job() -> Standard {
    let mut wire = Wire::new();
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
    let mut frames = wire.open_standard(7, "alice.rig1", ALL_ONES);
    let opened = read_open_standard(&mut frames);
    let job = read_std_job(&mut frames);
    assert_eq!(job.job_id, installed.job.id().get());
    read_prev_hash(&mut frames);
    wire.events();
    Standard {
        wire,
        opened,
        job: installed.job,
    }
}

#[test]
fn noise_handshake_authenticates_the_pool_to_a_pinned_miner() -> TestResult {
    let authority = fresh_authority();
    let mut book = JobBook::new(book_config(BIP320_VERSION_MASK))
        .map_err(|error| format!("book: {error:?}"))?;
    let mut conn = Connection::accept(&authority, Duration::from_secs(60), server_config(), &book)
        .map_err(|error| format!("config: {error:?}"))?;
    handshake(&mut conn, &mut book, *authority.public(), WHOLE)?;
    Ok(())
}

#[test]
fn a_miner_pinning_another_authority_rejects_the_server_certificate() -> TestResult {
    let authority = fresh_authority();
    let impostor = fresh_authority();
    let mut book = JobBook::new(book_config(BIP320_VERSION_MASK))
        .map_err(|error| format!("book: {error:?}"))?;
    let mut conn = Connection::accept(&authority, Duration::from_secs(60), server_config(), &book)
        .map_err(|error| format!("config: {error:?}"))?;
    let outcome = handshake(&mut conn, &mut book, *impostor.public(), WHOLE);
    assert!(
        outcome.is_err(),
        "certificate signed by another authority must not verify"
    );
    Ok(())
}

#[test]
fn a_mismatched_authority_key_pair_is_refused_at_accept() -> TestResult {
    let authority = fresh_authority();
    let other = fresh_authority();
    let mismatched = AuthorityKeypair::from_bytes(*authority.public(), Zeroizing::new([0x42; 32]));
    let book = JobBook::new(book_config(BIP320_VERSION_MASK))
        .map_err(|error| format!("book: {error:?}"))?;
    assert!(
        Connection::accept(&mismatched, Duration::from_secs(60), server_config(), &book).is_err()
    );
    assert!(Connection::accept(&other, Duration::ZERO, server_config(), &book).is_err());
    Ok(())
}

#[test]
fn byte_at_a_time_delivery_is_decoded_like_whole_reads() -> TestResult {
    let mut wire = Wire::with(1, server_config(), BIP320_VERSION_MASK);
    wire.book
        .install(candidate(100, 0xab, 2), Vec::new())
        .map_err(|error| format!("install: {error:?}"))?;
    wire.setup_mining(0);
    let mut frames = wire.open_standard(1, "carol", ALL_ONES);
    assert_eq!(
        types(&frames),
        vec![
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            MESSAGE_TYPE_NEW_MINING_JOB,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
        ]
    );
    let opened = read_open_standard(&mut frames);
    assert_eq!(opened.prefix.len(), 8);
    Ok(())
}

#[test]
fn a_flipped_ciphertext_bit_fails_the_mac_and_kills_the_connection() -> TestResult {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut bytes = wire.client.seal(
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        false,
        OpenStandardMiningChannel {
            request_id: 1,
            user_identity: Str0255::try_from("mallory")
                .map_err(|error| format!("short: {error:?}"))?,
            nominal_hash_rate: 1.0,
            max_target: U256::from(&ALL_ONES),
        },
    );
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let outcome = wire.conn.feed(&bytes, &mut wire.book);
    assert!(
        matches!(outcome, Err(Error::Transport(TransportError::Decrypt(_)))),
        "tampered frame must fail authentication: {outcome:?}"
    );
    assert!(wire.conn.is_closing());
    assert!(matches!(
        wire.conn.feed(&[0], &mut wire.book),
        Err(Error::Closed)
    ));
    assert_eq!(wire.conn.session().channel_count(), 0);
    Ok(())
}

#[test]
fn a_flipped_header_bit_also_fails_authentication() -> TestResult {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut bytes = wire.client.seal(
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        false,
        OpenStandardMiningChannel {
            request_id: 1,
            user_identity: Str0255::try_from("mallory")
                .map_err(|error| format!("short: {error:?}"))?,
            nominal_hash_rate: 1.0,
            max_target: U256::from(&ALL_ONES),
        },
    );
    bytes[3] ^= 0x80;
    let outcome = wire.conn.feed(&bytes, &mut wire.book);
    assert!(matches!(
        outcome,
        Err(Error::Transport(TransportError::Decrypt(_)))
    ));
    Ok(())
}

#[test]
fn a_replayed_ciphertext_does_not_authenticate_under_the_next_nonce() -> TestResult {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let bytes = wire.client.seal(
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        false,
        OpenStandardMiningChannel {
            request_id: 1,
            user_identity: Str0255::try_from("replay")
                .map_err(|error| format!("short: {error:?}"))?,
            nominal_hash_rate: 1.0,
            max_target: U256::from(&ALL_ONES),
        },
    );
    wire.conn
        .feed(&bytes, &mut wire.book)
        .map_err(|error| format!("first delivery: {error:?}"))?;
    assert_eq!(wire.conn.session().channel_count(), 1);
    let replay = wire.conn.feed(&bytes, &mut wire.book);
    assert!(matches!(
        replay,
        Err(Error::Transport(TransportError::Decrypt(_)))
    ));
    Ok(())
}

#[test]
fn an_oversize_declaration_is_refused_before_it_is_buffered() -> TestResult {
    let mut config = server_config();
    config.limits = Limits {
        max_frame_payload: 128,
        ..Limits::DEFAULT
    };
    let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
    let long = "a".repeat(100);
    let oversize = SetupConnection {
        protocol: Protocol::MiningProtocol,
        min_version: 2,
        max_version: 2,
        flags: 0,
        endpoint_host: Str0255::try_from(long.as_str())
            .map_err(|error| format!("100 bytes: {error:?}"))?,
        endpoint_port: 1,
        vendor: Str0255::try_from(long.as_str())
            .map_err(|error| format!("100 bytes: {error:?}"))?,
        hardware_version: Str0255::try_from(long.as_str())
            .map_err(|error| format!("100 bytes: {error:?}"))?,
        firmware: Str0255::try_from(long.as_str())
            .map_err(|error| format!("100 bytes: {error:?}"))?,
        device_id: Str0255::try_from(long.as_str())
            .map_err(|error| format!("100 bytes: {error:?}"))?,
    };
    let outcome = wire.try_exchange(MESSAGE_TYPE_SETUP_CONNECTION, false, oversize);
    assert!(
        matches!(
            outcome,
            Err(Error::Transport(TransportError::FrameTooLarge {
                limit: 128
            }))
        ),
        "{outcome:?}"
    );
    Ok(())
}

#[test]
fn limits_beyond_the_u24_wire_field_are_refused() {
    let mut config = server_config();
    config.limits = Limits {
        max_frame_payload: 0x0100_0000,
        ..Limits::DEFAULT
    };
    let authority = fresh_authority();
    let book = JobBook::new(book_config(BIP320_VERSION_MASK))
        .unwrap_or_else(|error| panic!("book: {error:?}"));
    assert!(
        Connection::accept(&authority, Duration::from_secs(60), config, &book).is_err(),
        "msg_length is a U24"
    );
}

#[test]
fn setup_succeeds_and_advertises_only_what_it_supports() {
    let mut wire = Wire::new();
    let flags = wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
    assert_eq!(flags, 0, "rolling is available, so no fixed-version flag");
    let events = wire.events();
    assert!(matches!(
        events.as_slice(),
        [Event::SetupCompleted {
            flags: FLAG_REQUIRES_STANDARD_JOBS
        }]
    ));

    let mut fixed = Wire::with(WHOLE, server_config(), 0);
    let flags = fixed.setup_mining(0);
    assert_eq!(
        flags, SUCCESS_FLAG_REQUIRES_FIXED_VERSION,
        "an owner without a version mask tells miners the version is fixed"
    );
}

#[test]
fn unsupported_flags_report_the_full_unsupported_set_and_close() {
    let mut wire = Wire::new();
    let mut frames = wire.setup(
        Protocol::MiningProtocol,
        2,
        2,
        FLAG_REQUIRES_WORK_SELECTION | FLAG_REQUIRES_STANDARD_JOBS,
    );
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
    let error: SetupConnectionError = parse(&mut frame);
    assert_eq!(error.flags, FLAG_REQUIRES_WORK_SELECTION);
    assert_eq!(
        error.error_code.as_utf8_or_hex(),
        "unsupported-feature-flags"
    );
    assert!(wire.conn.is_closing());
    assert!(matches!(
        wire.events().as_slice(),
        [Event::SetupRejected {
            code: "unsupported-feature-flags"
        }]
    ));

    let mut fixed = Wire::with(WHOLE, server_config(), 0);
    let mut frames = fixed.setup(
        Protocol::MiningProtocol,
        2,
        2,
        FLAG_REQUIRES_VERSION_ROLLING,
    );
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
    let error: SetupConnectionError = parse(&mut frame);
    assert_eq!(
        error.flags,
        FLAG_REQUIRES_WORK_SELECTION | FLAG_REQUIRES_VERSION_ROLLING
    );
}

#[test]
fn job_declaration_and_template_distribution_are_not_served() {
    for protocol in [
        Protocol::JobDeclarationProtocol,
        Protocol::TemplateDistributionProtocol,
    ] {
        let mut wire = Wire::new();
        let mut frames = wire.setup(protocol, 2, 2, 0);
        let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
        let error: SetupConnectionError = parse(&mut frame);
        assert_eq!(error.error_code.as_utf8_or_hex(), "unsupported-protocol");
        assert!(wire.conn.is_closing());
    }
}

#[test]
fn a_version_range_without_two_is_refused() {
    let mut wire = Wire::new();
    let mut frames = wire.setup(Protocol::MiningProtocol, 3, 4, 0);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
    let error: SetupConnectionError = parse(&mut frame);
    assert_eq!(
        error.error_code.as_utf8_or_hex(),
        "protocol-version-mismatch"
    );
}

#[test]
fn nothing_but_setup_may_open_a_connection() {
    let mut wire = Wire::new();
    let outcome = wire.try_exchange(
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        false,
        OpenStandardMiningChannel {
            request_id: 1,
            user_identity: Str0255::try_from("early")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            nominal_hash_rate: 1.0,
            max_target: U256::from(&ALL_ONES),
        },
    );
    assert!(matches!(
        outcome,
        Err(Error::Session(SessionError::SetupRequired { .. }))
    ));
}

#[test]
fn a_second_setup_and_a_wrong_channel_bit_are_protocol_violations() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let again = wire.try_exchange(
        MESSAGE_TYPE_SETUP_CONNECTION,
        false,
        SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: Str0255::try_from("h")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            endpoint_port: 1,
            vendor: Str0255::try_from("v").unwrap_or_else(|error| panic!("short: {error:?}")),
            hardware_version: Str0255::try_from("h")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            firmware: Str0255::try_from("f").unwrap_or_else(|error| panic!("short: {error:?}")),
            device_id: Str0255::try_from("").unwrap_or_else(|error| panic!("empty: {error:?}")),
        },
    );
    assert!(matches!(
        again,
        Err(Error::Session(SessionError::DuplicateSetup))
    ));

    let mut wire = Wire::new();
    wire.setup_mining(0);
    let wrong_bit = wire.try_exchange(
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        true,
        OpenStandardMiningChannel {
            request_id: 1,
            user_identity: Str0255::try_from("bit")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            nominal_hash_rate: 1.0,
            max_target: U256::from(&ALL_ONES),
        },
    );
    assert!(matches!(
        wrong_bit,
        Err(Error::Session(SessionError::ChannelBit { .. }))
    ));
}

#[test]
fn frames_of_an_unnegotiated_extension_are_discarded() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let bytes = wire.client.seal_ext(
        MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
        0x4001,
        true,
        SubmitSharesStandard {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce: 0,
            ntime: 0,
            version: 0,
        },
    );
    wire.conn
        .feed(&bytes, &mut wire.book)
        .unwrap_or_else(|error| panic!("ignored, not fatal: {error:?}"));
    assert!(wire.drain().is_empty());
    assert_eq!(wire.conn.session().ignored_extension_frames(), 1);
}

#[test]
fn standard_channel_gets_a_future_job_then_the_prev_hash_that_activates_it() {
    let mut wire = Wire::new();
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(0);
    let mut frames = wire.open_standard(7, "alice.rig1", ALL_ONES);
    assert_eq!(
        types(&frames),
        vec![
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            MESSAGE_TYPE_NEW_MINING_JOB,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
        ],
        "the first message after open is a future job, then its prev hash"
    );
    let opened = read_open_standard(&mut frames);
    let job = read_std_job(&mut frames);
    let prev = read_prev_hash(&mut frames);
    let owned = &installed.job;

    assert_ne!(opened.group_id, opened.channel_id);
    assert_eq!(opened.target, ALL_ONES);
    assert_eq!(
        opened.prefix.len(),
        8,
        "session prefix plus pool-fixed rolled bytes"
    );
    assert_eq!(job.channel_id, opened.channel_id);
    assert_eq!(job.job_id, owned.id().get());
    assert_eq!(job.min_ntime, None, "future job: ntime_start unset");
    assert_eq!(job.version, owned.version());
    let (session, rolled) = opened.prefix.split_at(4);
    let root = owned
        .merkle_root(Extranonce { session, rolled })
        .unwrap_or_else(|error| panic!("owner projects the merkle root: {error:?}"));
    assert_eq!(job.merkle_root, *root.as_byte_array());

    assert_eq!(prev.channel_id, opened.channel_id);
    assert_eq!(prev.job_id, owned.id().get());
    assert_eq!(prev.prev, *owned.previous_block_hash().as_bytes());
    assert_eq!(prev.nbits, 0x207f_ffff);
    assert_eq!(prev.min_ntime, owned.ntime());

    let events = wire.events();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::ChannelOpened { channel_id, .. } if *channel_id == opened.channel_id
    )));
    assert_eq!(wire.book.session_count(), 1);
}

#[test]
fn extended_channel_job_rebuilds_the_owners_merkle_root_from_the_wire_fields() {
    let mut wire = Wire::new();
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(0);
    let mut frames = wire.open_extended(9, "bob.farm", ALL_ONES, 4);
    let opened = read_open_extended(&mut frames);
    assert_eq!(opened.extranonce_size, Some(4));
    assert_eq!(opened.prefix.len(), 4);
    let job = read_ext_job(&mut frames);
    let prev = read_prev_hash(&mut frames);
    assert_eq!(job.channel_id, opened.channel_id);
    assert_eq!(job.min_ntime, None);
    assert_eq!(job.version, installed.job.version());
    assert!(job.rolling_allowed, "the owner has a version mask");
    assert_eq!(job.path.len(), 2, "coinbase plus two transactions");
    assert_eq!(prev.job_id, job.job_id);

    let rolled = [9_u8, 9, 9, 9];
    let mut coinbase = job.prefix.clone();
    coinbase.extend_from_slice(&opened.prefix);
    coinbase.extend_from_slice(&rolled);
    coinbase.extend_from_slice(&job.suffix);
    let mut root = double_sha256(&coinbase);
    for leaf in &job.path {
        let mut joined = root.as_byte_array().to_vec();
        joined.extend_from_slice(leaf);
        root = double_sha256(&joined);
    }
    let owned = installed
        .job
        .merkle_root(Extranonce {
            session: &opened.prefix,
            rolled: &rolled,
        })
        .unwrap_or_else(|error| panic!("owner root: {error:?}"));
    assert_eq!(
        root, owned,
        "wire coinbase halves and path reproduce the owner's root"
    );
}

#[test]
fn extended_share_is_validated_by_the_owner_and_extranonce_length_is_enforced() {
    let mut wire = Wire::new();
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(0);
    let mut frames = wire.open_extended(9, "bob.farm", ALL_ONES, 4);
    let opened = read_open_extended(&mut frames);
    let job = installed.job;
    let rolled = [9_u8, 9, 9, 9];
    let mut full = opened.prefix.clone();
    full.extend_from_slice(&rolled);
    let nonce = share_nonce(&job, &full, job.version());

    let mut frames = wire.submit_extended(
        opened.channel_id,
        1,
        ShareWork {
            job_id: job.id().get(),
            nonce,
            ntime: job.ntime(),
            version: job.version(),
        },
        &rolled,
    );
    assert!(frames.is_empty(), "no Success before the ledger confirms");
    let share = accepted(wire.events());
    assert_eq!(share.channel_id, opened.channel_id);
    assert_eq!(share.outcome.extranonce, full);

    let mut short = wire.submit_extended(
        opened.channel_id,
        2,
        ShareWork {
            job_id: job.id().get(),
            nonce,
            ntime: job.ntime(),
            version: job.version(),
        },
        &rolled[..3],
    );
    let (_, sequence, code) = share_error(&mut short);
    assert_eq!((sequence, code.as_str()), (2, "bad-extranonce-size"));
    frames.clear();
}

#[test]
fn min_extranonce_size_beyond_the_owners_rolled_length_is_refused() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut frames = wire.open_extended(3, "greedy", ALL_ONES, 5);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    let error: OpenMiningChannelError = parse(&mut frame);
    assert_eq!(error.request_id, 3);
    assert_eq!(
        error.error_code.as_utf8_or_hex(),
        "min-extranonce-size-too-large"
    );
    assert_eq!(
        wire.book.session_count(),
        0,
        "a refused open holds no session"
    );
}

#[test]
fn open_refusals_use_official_codes_and_hold_no_session() {
    let mut wire = Wire::new();
    wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
    let mut frames = wire.open_extended(1, "ext", ALL_ONES, 0);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    let error: OpenMiningChannelError = parse(&mut frame);
    assert_eq!(
        error.error_code.as_utf8_or_hex(),
        "extended-channels-not-supported-for-standard-jobs"
    );

    let mut frames = wire.open_standard(2, "", ALL_ONES);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    let error: OpenMiningChannelError = parse(&mut frame);
    assert_eq!(error.error_code.as_utf8_or_hex(), "invalid-user-identity");

    let mut frames = wire.open_standard(3, "zero", [0; 32]);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    let error: OpenMiningChannelError = parse(&mut frame);
    assert_eq!(error.error_code.as_utf8_or_hex(), "max-target-out-of-range");
    assert_eq!(wire.book.session_count(), 0);
}

#[test]
fn channel_capacity_is_bounded_by_the_connection_and_by_the_owner() {
    let mut config = server_config();
    config.limits = Limits {
        max_channels: 2,
        ..Limits::DEFAULT
    };
    let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
    wire.setup_mining(0);
    for request_id in 0..2 {
        let mut frames = wire.open_standard(request_id, "w", ALL_ONES);
        read_open_standard(&mut frames);
    }
    let mut frames = wire.open_standard(9, "w", ALL_ONES);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    let error: OpenMiningChannelError = parse(&mut frame);
    assert_eq!(
        error.error_code.as_utf8_or_hex(),
        "channel-capacity-exhausted"
    );
    assert_eq!(wire.book.session_count(), 2);
}

#[test]
fn channel_ids_are_unique_and_distinct_from_the_group_id() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut seen = Vec::new();
    let mut group = None;
    for request_id in 0..4 {
        let mut frames = wire.open_standard(request_id, "w", ALL_ONES);
        let opened = read_open_standard(&mut frames);
        assert!(!seen.contains(&opened.channel_id));
        assert_ne!(opened.channel_id, opened.group_id);
        assert_eq!(*group.get_or_insert(opened.group_id), opened.group_id);
        seen.push(opened.channel_id);
    }
    assert!(group.is_some_and(|id| !seen.contains(&id)));
    assert_eq!(wire.conn.session().channel_count(), 4);
    assert_eq!(wire.book.session_count(), 4);
}

#[test]
fn accepted_share_is_held_until_the_ledger_confirms_then_acknowledged() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);
    let frames = s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        nonce,
        s.job.ntime(),
        version,
    );
    assert!(
        frames.is_empty(),
        "no Success before the ledger records the share"
    );
    let share = accepted(s.wire.events());
    let hash = share.outcome.hash;
    assert_eq!(share.outcome.class, ShareClass::Share);
    assert_eq!(share.sequence_number, 1);
    assert_eq!(s.wire.conn.session().pending_acks(), 1);
    let work = share.outcome.work.as_u128();
    assert_eq!(work, Some(1), "an all-ones target is one hash per share");

    assert!(
        s.wire
            .conn
            .confirm_share(share.ticket)
            .unwrap_or_else(|error| panic!("flushes: {error:?}"))
    );
    assert_eq!(s.wire.conn.session().pending_acks(), 0);
    let mut frames = s.wire.drain();
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
    assert!(frame.channel_msg);
    let ok: SubmitSharesSuccess = parse(&mut frame);
    assert_eq!(ok.channel_id, s.opened.channel_id);
    assert_eq!(ok.last_sequence_number, 1);
    assert_eq!(ok.new_submits_accepted_count, 1);
    assert_eq!(
        ok.new_shares_sum, 1,
        "new_shares_sum carries assigned difficulty (clamped to 1 for all-ones), NOT raw work (scaled by 2^32)"
    );
    assert_eq!(
        hash,
        share.outcome.header.compute_hash(),
        "the header hash is the ledger idempotency key"
    );

    assert!(
        !s.wire
            .conn
            .confirm_share(share.ticket)
            .unwrap_or_else(|error| panic!("no-op: {error:?}"))
    );
    assert!(s.wire.drain().is_empty());
}

#[test]
fn target_difficulty_converts_share_targets_to_integer_difficulty_without_raw_hash_scaling()
-> TestResult {
    fn target<E: std::fmt::Debug>(
        result: Result<ShareTarget, E>,
        context: &str,
    ) -> TestResult<ShareTarget> {
        result.map_err(|error| TestError(format!("{context}: {error:?}")))
    }
    assert_eq!(
        target_difficulty(target(ShareTarget::from_pool_difficulty(1), "diff 1")?),
        1
    );
    assert_eq!(
        target_difficulty(target(ShareTarget::from_pool_difficulty(42), "diff 42")?),
        42
    );
    assert_eq!(
        target_difficulty(target(
            ShareTarget::from_pool_difficulty(16_384),
            "diff 16384"
        )?),
        16_384
    );
    assert_eq!(
        target_difficulty(target(
            ShareTarget::from_pool_difficulty(1_000_000),
            "diff 1M"
        )?),
        1_000_000
    );
    assert_eq!(
        target_difficulty(target(ShareTarget::from_le_bytes(ALL_ONES), "all ones")?),
        1,
        "sub-1 target difficulty floors at 1 unit of acknowledged work"
    );
    Ok(())
}

#[test]
fn the_host_can_refuse_to_credit_a_share() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        nonce,
        s.job.ntime(),
        version,
    );
    let share = accepted(s.wire.events());
    assert!(
        s.wire
            .conn
            .reject_share(
                share.ticket,
                bitcoin_rs_mining::pool::stratum::sv2::ERROR_CODE_SHARE_NOT_RECORDED
            )
            .unwrap_or_else(|error| panic!("flushes: {error:?}"))
    );
    let mut frames = s.wire.drain();
    let (channel, sequence, code) = share_error(&mut frames);
    assert_eq!(
        (channel, sequence, code.as_str()),
        (s.opened.channel_id, 1, "share-not-recorded")
    );
}

#[test]
fn a_block_candidate_carries_the_owners_full_block_for_the_node_submit_path() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = block_nonce(&s.job, &s.opened.prefix, version);
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        nonce,
        s.job.ntime(),
        version,
    );
    let pending = s
        .wire
        .events()
        .into_iter()
        .find_map(|event| match event {
            Event::BlockFound(pending) => Some(pending),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a block is surfaced as pending host work"));
    let found = pending.found_block();
    assert_eq!(found.share.class, ShareClass::Block);
    assert_eq!(found.share.hash, found.block.header.compute_hash());
    assert_eq!(found.block.header.nonce, nonce);
    assert!(found.raw.len() > 80, "serialized block, not a bare header");
    assert_eq!(found.coinbase_value, s.job.coinbase_value());
    assert!(matches!(
        s.wire.conn.confirm_share(pending.ticket()),
        Err(Error::Session(SessionError::BlockRequiresSubmission))
    ));
    assert!(s.wire.drain().is_empty());
}

#[test]
fn duplicate_share_is_refused_with_the_official_code() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);
    let job_id = s.job.id().get();
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        job_id,
        nonce,
        s.job.ntime(),
        version,
    );
    accepted(s.wire.events());
    let mut frames = s.wire.submit_standard(
        s.opened.channel_id,
        2,
        job_id,
        nonce,
        s.job.ntime(),
        version,
    );
    let (_, sequence, code) = share_error(&mut frames);
    assert_eq!((sequence, code.as_str()), (2, "duplicate-share"));
    let events = s.wire.events();
    assert!(matches!(
        events.as_slice(),
        [Event::ShareRejected {
            code: "duplicate-share",
            cause: Some(ShareError::Duplicate { .. }),
            ..
        }]
    ));
}

#[test]
fn a_share_above_the_channel_target_is_difficulty_too_low() {
    let mut wire = Wire::new();
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(0);
    let mut tight = [0_u8; 32];
    tight[8] = 1;
    let mut frames = wire.open_standard(1, "tight", tight);
    let opened = read_open_standard(&mut frames);
    assert_eq!(
        opened.target, tight,
        "the channel never starts easier than max_target"
    );
    let job = installed.job;
    let nonce = share_nonce(&job, &opened.prefix, job.version());
    let mut frames = wire.submit_standard(
        opened.channel_id,
        1,
        job.id().get(),
        nonce,
        job.ntime(),
        job.version(),
    );
    let (_, _, code) = share_error(&mut frames);
    assert_eq!(code, "difficulty-too-low");
}

#[test]
fn stale_jobs_unknown_jobs_and_closed_channels_use_official_codes() {
    let mut s = standard_with_job();
    let job_id = s.job.id().get();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);

    let mut frames =
        s.wire
            .submit_standard(s.opened.channel_id, 1, 999, nonce, s.job.ntime(), version);
    assert_eq!(share_error(&mut frames).2, "invalid-job-id");

    let mut frames = s
        .wire
        .submit_standard(4242, 1, job_id, nonce, s.job.ntime(), version);
    assert_eq!(share_error(&mut frames).2, "invalid-channel-id");

    let installed = s
        .wire
        .book
        .install(candidate(101, 0xcd, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    assert!(installed.fresh && installed.clean_jobs);
    assert!(installed.invalidated.contains(&s.job.id()));
    s.wire
        .conn
        .announce(&installed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let mut frames = s.wire.drain();
    assert_eq!(
        types(&frames),
        vec![
            MESSAGE_TYPE_NEW_MINING_JOB,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
        ]
    );
    let mut frames_stale = s.wire.submit_standard(
        s.opened.channel_id,
        2,
        job_id,
        nonce,
        s.job.ntime(),
        version,
    );
    let (_, _, code) = share_error(&mut frames_stale);
    assert_eq!(code, "stale-share");
    frames.clear();
}

#[test]
fn clean_jobs_send_a_future_job_and_a_prev_hash_but_a_refresh_does_not() {
    let mut s = standard_with_job();
    let old_job = s.job.id().get();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);

    let refresh_candidate = candidate(100, 0xab, 1);
    let refreshed = s
        .wire
        .book
        .install(Arc::clone(&refresh_candidate), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    assert!(refreshed.fresh);
    assert!(!refreshed.clean_jobs);
    s.wire
        .conn
        .announce(&refreshed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let mut frames = s.wire.drain();
    assert_eq!(types(&frames), vec![MESSAGE_TYPE_NEW_MINING_JOB]);
    let job = read_std_job(&mut frames);
    assert_eq!(job.job_id, refreshed.job.id().get());
    assert_eq!(
        job.min_ntime,
        Some(refreshed.job.ntime()),
        "active: ntime_start set"
    );

    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        old_job,
        nonce,
        s.job.ntime(),
        version,
    );
    accepted(s.wire.events());

    s.wire
        .conn
        .announce(&refreshed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    assert!(s.wire.drain().is_empty());

    let unchanged = s
        .wire
        .book
        .install(refresh_candidate, Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    assert!(!unchanged.fresh);
    s.wire
        .conn
        .announce(&unchanged)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    assert!(s.wire.drain().is_empty());
}

#[test]
fn sequence_numbers_must_increase_per_channel() {
    let mut s = standard_with_job();
    let ntime = s.job.ntime();
    let version = s.job.version();
    let channel = s.opened.channel_id;

    let mut frames = s.wire.submit_standard(channel, 5, 999, 0, ntime, version);
    assert_eq!(share_error(&mut frames).2, "invalid-job-id");
    for stale_sequence in [5, 4, 0] {
        let mut frames = s
            .wire
            .submit_standard(channel, stale_sequence, 999, 0, ntime, version);
        let (_, sequence, code) = share_error(&mut frames);
        assert_eq!(
            (sequence, code.as_str()),
            (stale_sequence, "invalid-sequence-number")
        );
    }
    let mut frames = s.wire.submit_standard(channel, 6, 999, 0, ntime, version);
    assert_eq!(share_error(&mut frames).2, "invalid-job-id");
}

#[test]
fn ntime_below_the_announced_start_is_refused() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);
    let mut frames = s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        nonce,
        s.job.ntime() - 1,
        version,
    );
    assert_eq!(share_error(&mut frames).2, "invalid-share");
}

#[test]
fn version_rolling_is_accepted_inside_the_mask_and_refused_outside_it() {
    let mut s = standard_with_job();
    let job_id = s.job.id().get();
    let rolled_version = s.job.version() | 0x0000_2000;
    assert_eq!(BIP320_VERSION_MASK & 0x2000, 0x2000);
    let nonce = share_nonce(&s.job, &s.opened.prefix, rolled_version);
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        job_id,
        nonce,
        s.job.ntime(),
        rolled_version,
    );
    let share = accepted(s.wire.events());
    assert_eq!(
        share.outcome.header.version,
        i32::from_le_bytes(rolled_version.to_le_bytes())
    );

    let outside = s.job.version() | 0x0000_0001;
    let mut frames = s.wire.submit_standard(
        s.opened.channel_id,
        2,
        job_id,
        nonce,
        s.job.ntime(),
        outside,
    );
    assert_eq!(
        share_error(&mut frames).2,
        "invalid-non-rollable-version-bit"
    );
}

#[test]
fn a_fixed_version_owner_refuses_any_version_change() {
    let mut wire = Wire::with(WHOLE, server_config(), 0);
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(0);
    let mut frames = wire.open_standard(1, "fixed", ALL_ONES);
    let opened = read_open_standard(&mut frames);
    let job = installed.job;
    let mut frames = wire.submit_standard(
        opened.channel_id,
        1,
        job.id().get(),
        0,
        job.ntime(),
        job.version() | 0x2000,
    );
    assert_eq!(share_error(&mut frames).2, "version-rolling-not-allowed");
}

#[test]
fn unconfirmed_shares_are_bounded_and_a_busy_refusal_is_not_recorded() {
    let mut config = server_config();
    config.limits = Limits {
        max_pending_acks: 1,
        ..Limits::DEFAULT
    };
    let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(0);
    let mut frames = wire.open_standard(1, "busy", ALL_ONES);
    let opened = read_open_standard(&mut frames);
    wire.events();
    let job = installed.job;
    let version = job.version();
    let first = share_nonce(&job, &opened.prefix, version);
    let (session, rolled) = opened.prefix.split_at(4);
    let second = (first + 1..u32::MAX)
        .find(|nonce| {
            let header = job
                .header(Extranonce { session, rolled }, job.ntime(), version, *nonce)
                .unwrap_or_else(|error| panic!("header: {error:?}"));
            !compact_is_met_by(job.bits(), Hash256::from(header.compute_hash()))
        })
        .unwrap_or_else(|| panic!("second nonce"));

    wire.submit_standard(
        opened.channel_id,
        1,
        job.id().get(),
        first,
        job.ntime(),
        version,
    );
    let share = accepted(wire.events());
    let mut frames = wire.submit_standard(
        opened.channel_id,
        2,
        job.id().get(),
        second,
        job.ntime(),
        version,
    );
    assert_eq!(share_error(&mut frames).2, "pool-busy");

    wire.conn
        .confirm_share(share.ticket)
        .unwrap_or_else(|error| panic!("confirm: {error:?}"));
    wire.drain();
    wire.submit_standard(
        opened.channel_id,
        3,
        job.id().get(),
        second,
        job.ntime(),
        version,
    );
    accepted(wire.events());
}

#[test]
fn expired_tickets_unburn_for_retry() {
    let mut config = server_config();
    config.limits = Limits {
        pending_ack_timeout: Duration::ZERO,
        ..Limits::DEFAULT
    };
    let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(0);
    let mut frames = wire.open_standard(1, "expiry", ALL_ONES);
    let opened = read_open_standard(&mut frames);
    wire.events();
    let job = installed.job;
    let version = job.version();
    let nonce = share_nonce(&job, &opened.prefix, version);
    wire.submit_standard(
        opened.channel_id,
        1,
        job.id().get(),
        nonce,
        job.ntime(),
        version,
    );
    let share = accepted(wire.events());
    let expired = wire
        .conn
        .session_mut()
        .expire_tickets(&mut wire.book, Instant::now());
    assert_eq!(expired, vec![share.ticket]);
    assert_eq!(wire.conn.session().pending_acks(), 0);
    wire.submit_standard(
        opened.channel_id,
        2,
        job.id().get(),
        nonce,
        job.ntime(),
        version,
    );
    accepted(wire.events());
}

#[test]
fn peer_close_releases_the_session_and_cancels_pending_acknowledgements() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        nonce,
        s.job.ntime(),
        version,
    );
    let share = accepted(s.wire.events());
    assert_eq!(s.wire.book.session_count(), 1);

    let frames = s.wire.exchange(
        MESSAGE_TYPE_CLOSE_CHANNEL,
        true,
        CloseChannel {
            channel_id: s.opened.channel_id,
            reason_code: Str0255::try_from("shutdown")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
        },
    );
    assert!(frames.is_empty());
    assert_eq!(
        s.wire.book.session_count(),
        0,
        "the owner's session is released"
    );
    assert_eq!(s.wire.conn.session().channel_count(), 0);
    assert_eq!(s.wire.conn.session().pending_acks(), 0);
    assert!(matches!(
        s.wire.events().as_slice(),
        [Event::ChannelClosed {
            reason: CloseReason::Peer,
            ..
        }]
    ));

    assert!(
        !s.wire
            .conn
            .confirm_share(share.ticket)
            .unwrap_or_else(|error| panic!("no-op: {error:?}"))
    );
    assert!(s.wire.drain().is_empty());
    let mut frames = s.wire.submit_standard(
        s.opened.channel_id,
        2,
        s.job.id().get(),
        nonce,
        s.job.ntime(),
        version,
    );
    assert_eq!(share_error(&mut frames).2, "invalid-channel-id");
}

#[test]
fn closing_the_group_channel_closes_every_member() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut frames = wire.open_standard(1, "a", ALL_ONES);
    let first = read_open_standard(&mut frames);
    let mut frames = wire.open_extended(2, "b", ALL_ONES, 4);
    let second = read_open_extended(&mut frames);
    assert_eq!(first.group_id, second.group_id);
    assert_eq!(wire.book.session_count(), 2);

    wire.exchange(
        MESSAGE_TYPE_CLOSE_CHANNEL,
        true,
        CloseChannel {
            channel_id: first.group_id,
            reason_code: Str0255::try_from("group-down")
                .unwrap_or_else(|error| panic!("short: {error:?}")),
        },
    );
    assert_eq!(wire.conn.session().channel_count(), 0);
    assert_eq!(wire.book.session_count(), 0);
}

#[test]
fn host_close_tells_the_miner_and_release_is_idempotent() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut frames = wire.open_standard(1, "a", ALL_ONES);
    let opened = read_open_standard(&mut frames);
    wire.conn
        .close_channel(&mut wire.book, opened.channel_id, "pool-maintenance")
        .unwrap_or_else(|error| panic!("close: {error:?}"));
    let mut frames = wire.drain();
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_CLOSE_CHANNEL);
    let close: CloseChannel = parse(&mut frame);
    assert_eq!(close.channel_id, opened.channel_id);
    assert_eq!(close.reason_code.as_utf8_or_hex(), "pool-maintenance");
    assert_eq!(wire.book.session_count(), 0);

    wire.conn.release(&mut wire.book);
    wire.conn.release(&mut wire.book);
    assert_eq!(wire.book.session_count(), 0);
}

#[test]
fn a_dropped_connection_releases_every_owner_session() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    for request_id in 0..3 {
        wire.open_standard(request_id, "w", ALL_ONES);
    }
    assert_eq!(wire.book.session_count(), 3);
    wire.conn.release(&mut wire.book);
    assert_eq!(wire.book.session_count(), 0);
}

#[test]
fn update_channel_reflects_a_smaller_max_target_in_a_set_target() {
    let mut s = standard_with_job();
    let mut smaller = [0_u8; 32];
    smaller[10] = 1;
    let frames = s.wire.exchange(
        MESSAGE_TYPE_UPDATE_CHANNEL,
        true,
        UpdateChannel {
            channel_id: s.opened.channel_id,
            nominal_hash_rate: 2.0e12,
            maximum_target: U256::from(&smaller),
        },
    );
    let mut frames = frames;
    assert_eq!(types(&frames), vec![MESSAGE_TYPE_SET_TARGET]);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_SET_TARGET);
    assert!(frame.channel_msg);
    let target: SetTarget = parse(&mut frame);
    assert_eq!(target.channel_id, s.opened.channel_id);
    assert_eq!(*target.maximum_target.as_array(), smaller);

    let frames = s.wire.exchange(
        MESSAGE_TYPE_UPDATE_CHANNEL,
        true,
        UpdateChannel {
            channel_id: s.opened.channel_id,
            nominal_hash_rate: 2.0e12,
            maximum_target: U256::from(&ALL_ONES),
        },
    );
    assert!(frames.is_empty());

    let mut frames = s.wire.exchange(
        MESSAGE_TYPE_UPDATE_CHANNEL,
        true,
        UpdateChannel {
            channel_id: 31_337,
            nominal_hash_rate: 1.0,
            maximum_target: U256::from(&ALL_ONES),
        },
    );
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR);
    let error: UpdateChannelError = parse(&mut frame);
    assert_eq!(error.error_code.as_utf8_or_hex(), "invalid-channel-id");
}

#[test]
fn a_host_retarget_is_sent_and_never_exceeds_the_miners_max_target() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut max_target = [0_u8; 32];
    max_target[9] = 0x10;
    let mut frames = wire.open_standard(1, "vardiff", max_target);
    let opened = read_open_standard(&mut frames);
    assert_eq!(opened.target, max_target);

    let easier =
        ShareTarget::from_le_bytes(ALL_ONES).unwrap_or_else(|error| panic!("nonzero: {error:?}"));
    assert!(matches!(
        wire.conn.set_target(opened.channel_id, easier),
        Err(Error::Session(SessionError::TargetAboveMaximum { .. }))
    ));

    let mut harder = [0_u8; 32];
    harder[2] = 1;
    wire.conn
        .set_target(
            opened.channel_id,
            ShareTarget::from_le_bytes(harder).unwrap_or_else(|error| panic!("nonzero: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("harder target accepted: {error:?}"));
    let mut frames = wire.drain();
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_SET_TARGET);
    assert!(frame.channel_msg);
    let msg: SetTarget = parse(&mut frame);
    assert_eq!(msg.channel_id, opened.channel_id);
    assert_eq!(*msg.maximum_target.as_array(), harder);
    let info = wire
        .conn
        .session()
        .channel(opened.channel_id)
        .unwrap_or_else(|| panic!("channel open"));
    assert_eq!(info.target.to_le_bytes(), harder);
    assert_eq!(info.max_target.to_le_bytes(), max_target);

    assert!(matches!(
        wire.conn.set_target(9_999, easier),
        Err(Error::Session(SessionError::UnknownChannel(9_999)))
    ));
    assert!(!wire.conn.is_closing());
}

#[test]
fn reconnect_is_sent_and_new_channels_are_refused_afterwards() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    wire.conn
        .request_reconnect("pool2.invalid", 3334)
        .unwrap_or_else(|error| panic!("reconnect: {error:?}"));
    let mut frames = wire.drain();
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_RECONNECT);
    assert!(!frame.channel_msg);
    let reconnect: common_messages_sv2::Reconnect = parse(&mut frame);
    assert_eq!(reconnect.new_host.as_utf8_or_hex(), "pool2.invalid");
    assert_eq!(reconnect.new_port, 3334);

    let mut frames = wire.open_standard(1, "late", ALL_ONES);
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    let error: OpenMiningChannelError = parse(&mut frame);
    assert_eq!(error.error_code.as_utf8_or_hex(), "reconnect-requested");
}

#[test]
fn a_connection_without_standard_jobs_gets_one_group_addressed_job() {
    let mut wire = Wire::new();
    wire.setup_mining(0);
    let mut frames = wire.open_standard(1, "std", ALL_ONES);
    let standard = read_open_standard(&mut frames);
    let mut frames = wire.open_extended(2, "ext", ALL_ONES, 4);
    let extended = read_open_extended(&mut frames);
    assert_eq!(standard.group_id, extended.group_id);
    let group = standard.group_id;

    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.conn
        .announce(&installed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let mut frames = wire.drain();
    assert_eq!(
        types(&frames),
        vec![
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
        ],
        "one broadcast for the whole group, not one per channel"
    );
    let job = read_ext_job(&mut frames);
    let prev = read_prev_hash(&mut frames);
    assert_eq!(job.channel_id, group);
    assert_eq!(prev.channel_id, group);
    assert_eq!(job.job_id, prev.job_id);
    assert_eq!(job.min_ntime, None);

    let owned = wire.job(job.job_id);
    let nonce = share_nonce(&owned, &standard.prefix, owned.version());
    wire.submit_standard(
        standard.channel_id,
        1,
        job.job_id,
        nonce,
        owned.ntime(),
        owned.version(),
    );
    assert_eq!(accepted(wire.events()).channel_id, standard.channel_id);

    let rolled = [1_u8, 2, 3, 4];
    let mut full = extended.prefix.clone();
    full.extend_from_slice(&rolled);
    let nonce = share_nonce(&owned, &full, owned.version());
    wire.submit_extended(
        extended.channel_id,
        1,
        ShareWork {
            job_id: job.job_id,
            nonce,
            ntime: owned.ntime(),
            version: owned.version(),
        },
        &rolled,
    );
    assert_eq!(accepted(wire.events()).channel_id, extended.channel_id);

    let refreshed = wire
        .book
        .install(candidate(100, 0xab, 1), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.conn
        .announce(&refreshed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let mut frames = wire.drain();
    assert_eq!(types(&frames), vec![MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB]);
    let job = read_ext_job(&mut frames);
    assert_eq!(job.channel_id, group);
    assert_eq!(job.min_ntime, Some(refreshed.job.ntime()));
}

#[test]
fn a_connection_requiring_standard_jobs_gets_one_job_per_channel() {
    let mut wire = Wire::new();
    wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
    let mut frames = wire.open_standard(1, "a", ALL_ONES);
    let a = read_open_standard(&mut frames);
    let mut frames = wire.open_standard(2, "b", ALL_ONES);
    let b = read_open_standard(&mut frames);
    assert_ne!(
        a.prefix, b.prefix,
        "every channel has a unique extranonce prefix"
    );

    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.conn
        .announce(&installed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let mut frames = wire.drain();
    assert_eq!(
        types(&frames),
        vec![
            MESSAGE_TYPE_NEW_MINING_JOB,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
            MESSAGE_TYPE_NEW_MINING_JOB,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
        ]
    );
    let first = read_std_job(&mut frames);
    let second = read_std_job(&mut frames);
    assert_eq!(first.job_id, second.job_id);
    assert_ne!(first.channel_id, second.channel_id);
    assert_ne!(
        first.merkle_root, second.merkle_root,
        "different extranonce, different merkle root"
    );
    assert_eq!(first.version, second.version);
}

#[test]
fn custom_jobs_are_answered_with_the_official_code_not_pretended() {
    let mut s = standard_with_job();
    let mut frames = s.wire.exchange(
        MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
        true,
        SetCustomMiningJob {
            channel_id: s.opened.channel_id,
            request_id: 5,
            token: B0255::new(&[1, 2, 3]).unwrap_or_else(|error| panic!("short: {error:?}")),
            version: 0x2000_0000,
            prev_hash: U256::from(&ALL_ONES),
            min_ntime: 1,
            nbits: 0x207f_ffff,
            coinbase_tx_version: 2,
            coinbase_prefix: B0255::new(&[0x03, 0x64, 0x00, 0x00])
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            coinbase_tx_input_n_sequence: u32::MAX,
            coinbase_tx_outputs: B064K::new(&[0])
                .unwrap_or_else(|error| panic!("short: {error:?}")),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255::new(Vec::new())
                .unwrap_or_else(|error| panic!("empty: {error:?}")),
        },
    );
    let mut frame = take_type(&mut frames, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR);
    let error: SetCustomMiningJobError = parse(&mut frame);
    assert_eq!(error.channel_id, s.opened.channel_id);
    assert_eq!(error.request_id, 5);
    assert_eq!(error.error_code.as_utf8_or_hex(), "jd-not-supported");
}

#[test]
fn the_role_matrix_does_not_claim_what_is_not_built() {
    let status = |name: &str| {
        ROLES
            .iter()
            .find(|role| role.name.starts_with(name))
            .map_or_else(|| panic!("role listed"), |role| role.status)
    };
    assert_eq!(status("Standard channels"), RoleStatus::Implemented);
    assert_eq!(status("Extended channels"), RoleStatus::Implemented);
    assert_eq!(status("Group channels"), RoleStatus::Implemented);
    assert_eq!(status("Noise_NX"), RoleStatus::Implemented);
    assert_eq!(status("Job Declaration server"), RoleStatus::NotImplemented);
    assert_eq!(
        status("Work selection"),
        RoleStatus::NotImplemented,
        "no owner-side install path for miner-declared jobs"
    );
    assert_eq!(
        status("Template Distribution server"),
        RoleStatus::NotImplemented
    );
    assert_eq!(status("Extensions negotiation"), RoleStatus::NotImplemented);
    assert!(
        ROLES
            .iter()
            .filter(|role| role.status == RoleStatus::NotImplemented)
            .all(|role| !role.detail.is_empty())
    );
}

#[test]
fn the_installed_fact_set_is_what_the_adapter_consumes() {
    fn contract(installed: &Installed) -> (bool, bool, usize, JobId) {
        (
            installed.fresh,
            installed.clean_jobs,
            installed.invalidated.len(),
            installed.job.id(),
        )
    }
    let mut book = JobBook::new(book_config(BIP320_VERSION_MASK))
        .unwrap_or_else(|error| panic!("book: {error:?}"));
    let installed = book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    let (fresh, clean, invalidated, id) = contract(&installed);
    assert!(fresh && clean && invalidated == 0);
    assert!(book.current().is_some_and(|job| job.id() == id));
}

#[test]
fn accepted_block_retirement_makes_second_same_job_submit_stale() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let first = block_nonce(&s.job, &s.opened.prefix, version);
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        first,
        s.job.ntime(),
        version,
    );
    let pending = s
        .wire
        .events()
        .into_iter()
        .find_map(|event| match event {
            Event::BlockFound(pending) => Some(pending),
            _ => None,
        })
        .unwrap_or_else(|| panic!("first winning nonce is a block candidate"));
    s.wire.book.invalidate_active();
    drop(pending);
    let (session, rolled) = s
        .opened
        .prefix
        .split_at(s.job.extranonce_layout().session_len());
    let second = (first + 1..u32::MAX)
        .find(|nonce| {
            let header = s
                .job
                .header(
                    Extranonce { session, rolled },
                    s.job.ntime(),
                    version,
                    *nonce,
                )
                .unwrap_or_else(|error| panic!("header builds: {error:?}"));
            compact_is_met_by(s.job.bits(), Hash256::from(header.compute_hash()))
        })
        .unwrap_or_else(|| panic!("a second winning nonce exists"));
    let mut frames = s.wire.submit_standard(
        s.opened.channel_id,
        2,
        s.job.id().get(),
        second,
        s.job.ntime(),
        version,
    );
    let (_, sequence, code) = share_error(&mut frames);
    assert_eq!((sequence, code.as_str()), (2, "stale-share"));
    let events = s.wire.events();
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, Event::BlockFound(_))),
        "stale share is never resubmitted to the node"
    );
    assert!(matches!(
        events.as_slice(),
        [Event::ShareRejected {
            code: "stale-share",
            ..
        }]
    ));
    let installed = s
        .wire
        .book
        .install(candidate(101, 0xcd, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    s.wire
        .conn
        .announce(&installed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    s.wire.drain();
    let nonce = share_nonce(&installed.job, &s.opened.prefix, installed.job.version());
    s.wire.submit_standard(
        s.opened.channel_id,
        3,
        installed.job.id().get(),
        nonce,
        installed.job.ntime(),
        installed.job.version(),
    );
    assert!(matches!(
        s.wire.events().as_slice(),
        [Event::ShareAccepted(_)]
    ));
}

fn unused_backend() -> MiningControlError {
    MiningControlError::Unavailable("not used by this test".into())
}

struct StaleParentControl;

impl MiningControl for StaleParentControl {
    fn get_block_template(
        &self,
        _request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        Err(unused_backend())
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        Err(unused_backend())
    }

    fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
        Err(unused_backend())
    }

    fn submit_block(
        &self,
        _payload: BlockPayload,
    ) -> Result<BlockValidationResult, MiningControlError> {
        Ok(BlockValidationResult::Rejected(STALE_PARENT_REASON.into()))
    }

    fn submit_header(&self, _header: Header) -> Result<(), MiningControlError> {
        Err(unused_backend())
    }

    fn publish_generation(&self) {}

    fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {}

    fn generate(
        &self,
        _request: GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        Err(unused_backend())
    }
}

#[test]
fn stale_sibling_receipt_sends_stale_error_without_closing() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = block_nonce(&s.job, &s.opened.prefix, version);
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        nonce,
        s.job.ntime(),
        version,
    );
    let pending = s
        .wire
        .events()
        .into_iter()
        .find_map(|event| match event {
            Event::BlockFound(pending) => Some(pending),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a block is surfaced as pending host work"));
    let control = StaleParentControl;
    let submission = pending
        .submit(&control)
        .unwrap_or_else(|error| panic!("fake backend answers: {error:?}"));
    assert!(matches!(
        &submission.receipt().result,
        BlockValidationResult::Rejected(reason)
            if reason.as_str() == STALE_PARENT_REASON
    ));
    let sent = s
        .wire
        .conn
        .reject_block(&submission, "stale-share")
        .unwrap_or_else(|error| panic!("stale error queues: {error:?}"));
    assert!(sent, "stale ticket produces one error frame");
    assert!(
        !s.wire.conn.is_closing(),
        "stale sibling keeps the connection usable"
    );
    let mut frames = s.wire.drain();
    let (_, sequence, code) = share_error(&mut frames);
    assert_eq!((sequence, code.as_str()), (1, "stale-share"));
    let retired = s
        .wire
        .conn
        .reject_block(&submission, "stale-share")
        .unwrap_or_else(|error| panic!("repeat reject: {error:?}"));
    assert!(!retired, "block ticket retires with the error frame");
    let installed = s
        .wire
        .book
        .install(candidate(101, 0xcd, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    s.wire
        .conn
        .announce(&installed)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let announced = s.wire.drain();
    assert!(!announced.is_empty(), "new parent job announced");
    let nonce = share_nonce(&installed.job, &s.opened.prefix, installed.job.version());
    s.wire.submit_standard(
        s.opened.channel_id,
        2,
        installed.job.id().get(),
        nonce,
        installed.job.ntime(),
        installed.job.version(),
    );
    assert!(matches!(
        s.wire.events().as_slice(),
        [Event::ShareAccepted(_)]
    ));
}

#[test]
fn malformed_reject_code_preserves_the_pending_ticket() {
    let mut s = standard_with_job();
    let version = s.job.version();
    let nonce = share_nonce(&s.job, &s.opened.prefix, version);
    s.wire.submit_standard(
        s.opened.channel_id,
        1,
        s.job.id().get(),
        nonce,
        s.job.ntime(),
        version,
    );
    let share = accepted(s.wire.events());
    let pending_before = s.wire.conn.session().pending_acks();
    assert_eq!(pending_before, 1);
    assert!(matches!(
        s.wire.conn.reject_share(share.ticket, "bad\ncode"),
        Err(Error::Session(SessionError::BadErrorCode))
    ));
    assert_eq!(
        s.wire.conn.session().pending_acks(),
        1,
        "malformed code leaves the ticket pending"
    );
    assert!(
        s.wire
            .conn
            .reject_share(
                share.ticket,
                bitcoin_rs_mining::pool::stratum::sv2::ERROR_CODE_SHARE_NOT_RECORDED
            )
            .unwrap_or_else(|error| panic!("valid refusal sends: {error:?}"))
    );
    let mut frames = s.wire.drain();
    let (channel, sequence, code) = share_error(&mut frames);
    assert_eq!(
        (channel, sequence, code.as_str()),
        (s.opened.channel_id, 1, "share-not-recorded")
    );
}

#[test]
fn full_event_queue_fails_before_share_validation_without_orphan_ticket() {
    let mut config = server_config();
    config.limits.max_pending_events = 2;
    config.limits.max_pending_acks = 8;
    let mut wire = Wire::with(WHOLE, config, BIP320_VERSION_MASK);
    let installed = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
    let mut frames = wire.open_standard(7, "alice.rig1", ALL_ONES);
    let opened = read_open_standard(&mut frames);
    let job = read_std_job(&mut frames);
    assert_eq!(job.job_id, installed.job.id().get());
    read_prev_hash(&mut frames);
    assert_eq!(wire.conn.session().pending_acks(), 0);
    let version = installed.job.version();
    let nonce = share_nonce(&installed.job, &opened.prefix, version);
    let msg = SubmitSharesStandard {
        channel_id: opened.channel_id,
        sequence_number: 1,
        job_id: installed.job.id().get(),
        nonce,
        ntime: installed.job.ntime(),
        version,
    };
    assert!(matches!(
        wire.try_exchange(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true, msg),
        Err(Error::Session(SessionError::Backlog { queue: "event", .. }))
    ));
    assert_eq!(
        wire.conn.session().pending_acks(),
        0,
        "no orphan ticket is inserted when the event queue is full"
    );
}

#[test]
fn active_refresh_upgrades_a_channel_that_missed_its_parent_to_future() {
    use bitcoin_rs_mining::pool::stratum::sv2::{Frame, ProtocolSession};
    fn setup_frame(msg_type: u8, channel_msg: bool, payload: Vec<u8>) -> Frame {
        Frame {
            extension_type: 0,
            msg_type,
            channel_msg,
            payload,
        }
    }
    let mut book = JobBook::new(book_config(BIP320_VERSION_MASK))
        .unwrap_or_else(|error| panic!("book: {error:?}"));
    let mut cfg = server_config();
    cfg.limits.max_outbound_frames = 3;
    let mut session =
        ProtocolSession::new(cfg, &book).unwrap_or_else(|error| panic!("session: {error:?}"));
    let setup = SetupConnection {
        protocol: Protocol::MiningProtocol,
        min_version: 2,
        max_version: 2,
        flags: FLAG_REQUIRES_STANDARD_JOBS,
        endpoint_host: Str0255::try_from("pool.invalid").unwrap(),
        endpoint_port: 3333,
        vendor: Str0255::try_from("test-miner").unwrap(),
        hardware_version: Str0255::try_from("sim-1").unwrap(),
        firmware: Str0255::try_from("fw-0").unwrap(),
        device_id: Str0255::try_from("").unwrap(),
    };
    let payload = binary_sv2::to_bytes(setup).unwrap_or_else(|error| panic!("encode: {error:?}"));
    session
        .handle(
            &mut book,
            setup_frame(MESSAGE_TYPE_SETUP_CONNECTION, false, payload),
        )
        .unwrap_or_else(|error| panic!("setup: {error:?}"));
    assert!(session.is_open());
    session.take_frames();
    let open = |session: &mut ProtocolSession, book: &mut JobBook, id: u32, user: &str| {
        let msg = OpenStandardMiningChannel {
            request_id: id,
            user_identity: Str0255::try_from(user).unwrap(),
            nominal_hash_rate: 1.0e12,
            max_target: U256::from(&ALL_ONES),
        };
        let payload = binary_sv2::to_bytes(msg).unwrap();
        session
            .handle(
                book,
                setup_frame(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, false, payload),
            )
            .unwrap_or_else(|error| panic!("open: {error:?}"));
        let mut out = session.take_frames();
        let mut received: Vec<Received> = out
            .drain(..)
            .map(|frame| Received {
                msg_type: frame.msg_type,
                channel_msg: frame.channel_msg,
                payload: frame.payload,
            })
            .collect();
        read_open_standard(&mut received)
    };
    let opened_a = open(&mut session, &mut book, 7, "alice.rig1");
    let opened_b = open(&mut session, &mut book, 8, "bob.rig1");
    let first = book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    assert!(session.announce(&first).is_err());
    let missed = session.take_frames();
    assert_eq!(missed.len(), 3);
    let second = book
        .install(candidate(100, 0xab, 3), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    assert!(!second.clean_jobs);
    assert!(
        second.job.id().get() != first.job.id().get(),
        "second install must be a new job"
    );
    session
        .announce(&second)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let announced = session.take_frames();
    let detail: Vec<(u8, Vec<u8>)> = announced
        .iter()
        .map(|frame| (frame.msg_type, frame.payload.clone()))
        .collect();
    assert_eq!(announced.len(), 3, "second announce frames: {:?}", detail);
    let mut received: Vec<Received> = announced
        .into_iter()
        .map(|frame| Received {
            msg_type: frame.msg_type,
            channel_msg: frame.channel_msg,
            payload: frame.payload,
        })
        .collect();
    let mut jobs = Vec::new();
    while received
        .iter()
        .any(|frame| frame.msg_type == MESSAGE_TYPE_NEW_MINING_JOB)
    {
        jobs.push(read_std_job(&mut received));
    }
    assert_eq!(jobs.len(), 2);
    let prev = read_prev_hash(&mut received);
    assert!(received.is_empty());
    let active = jobs
        .iter()
        .find(|job| job.min_ntime.is_some())
        .unwrap_or_else(|| panic!("one channel gets Active"));
    let future = jobs
        .iter()
        .find(|job| job.min_ntime.is_none())
        .unwrap_or_else(|| panic!("stale channel gets Future"));
    assert_eq!(active.job_id, second.job.id().get());
    assert_eq!(future.job_id, second.job.id().get());
    assert_eq!(prev.job_id, second.job.id().get());
    assert_eq!(future.channel_id, opened_b.channel_id);
    assert_eq!(prev.channel_id, opened_b.channel_id);
    assert_eq!(active.channel_id, opened_a.channel_id);
}

#[test]
fn announce_without_fresh_still_delivers_a_missing_job_and_parent() {
    let mut wire = Wire::new();
    wire.setup_mining(FLAG_REQUIRES_STANDARD_JOBS);
    let mut frames = wire.open_standard(7, "late.rig1", ALL_ONES);
    let opened = read_open_standard(&mut frames);
    assert!(wire.drain().is_empty());
    let first = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("install: {error:?}"));
    assert!(first.fresh);
    let second = wire
        .book
        .install(candidate(100, 0xab, 2), Vec::new())
        .unwrap_or_else(|error| panic!("reinstall: {error:?}"));
    assert!(!second.fresh);
    wire.conn
        .announce(&second)
        .unwrap_or_else(|error| panic!("announce: {error:?}"));
    let mut announced = wire.drain();
    let job = read_std_job(&mut announced);
    assert_eq!(job.job_id, first.job.id().get());
    let prev = read_prev_hash(&mut announced);
    assert_eq!(prev.job_id, first.job.id().get());
    assert_eq!(opened.channel_id, prev.channel_id);
}
