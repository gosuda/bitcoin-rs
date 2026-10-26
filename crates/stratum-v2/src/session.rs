//! Stratum V2 mining-protocol server state machine.
//!
//! [`ProtocolSession`] is one pool connection above the Noise transport: it
//! consumes plaintext [`Frame`]s and produces plaintext [`Frame`]s, so the
//! state machine is testable without a socket and the transport can be
//! swapped without touching it.
//!
//! The session is a *wire* adapter. It owns channel identity, the message
//! layouts, and the per-channel share target. Everything else is delegated to
//! the one owner, [`bitcoin_rs_stratum::JobBook`]:
//!
//! - job projection (coinbase split, merkle branch, header facts) comes from
//!   [`bitcoin_rs_stratum::Job`];
//! - extranonce uniqueness and session identity come from
//!   [`JobBook::open_session`] / [`JobBook::close_session`];
//! - every share verdict (stale, duplicate, version mask, time window, target,
//!   network target) comes from [`JobBook::validate`], whose rejection is only
//!   *mapped* here to an official SV2 error code;
//! - a block candidate is handed to the host as the owner's
//!   [`bitcoin_rs_stratum::FoundBlock`]; the node's authoritative submit path is
//!   called by the host through [`FoundBlock::submit`], never from here.
//!
//! One wire rule is checked here before delegating, because it is a rule about
//! the SV2 messages this session itself sent: §5.3.11 requires a share's
//! `ntime` to be at least the `ntime_start` the job announced, and the
//! announced value is `Job::ntime()`.
//!
//! Financial effects are not decided here. An accepted share becomes an
//! [`Event::ShareAccepted`] carrying the owner's accepted-share identity (its
//! header hash is the ledger's idempotency key). A network-target result is
//! instead emitted as [`Event::BlockFound`] and remains pending until the host
//! submits it through [`MiningControl`], records the receipt, and calls
//! [`ProtocolSession::confirm_block`]. `SubmitShares.Success` is held until
//! those host-owned durable steps complete.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;

use binary_sv2::{B032, B064K, Decodable, Encodable, GetSize, Seq0255, Str0255, Sv2Option, U256};
use bitcoin_rs_mining::{MiningControl, MiningControlError};
use bitcoin_rs_stratum::{
    AcceptedShare, BlockReceipt, Extranonce, FoundBlock, Job, JobBook, JobError, JobId, Session,
    SessionId, ShareError, ShareOutcome, ShareSubmission, ShareTarget,
};
use common_messages_sv2::{
    CHANNEL_BIT_RECONNECT, CHANNEL_BIT_SETUP_CONNECTION, CHANNEL_BIT_SETUP_CONNECTION_ERROR,
    CHANNEL_BIT_SETUP_CONNECTION_SUCCESS, ERROR_CODE_SETUP_CONNECTION_PROTOCOL_VERSION_MISMATCH,
    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS,
    ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL, MESSAGE_TYPE_RECONNECT,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol, Reconnect, SetupConnection,
    SetupConnectionError, SetupConnectionSuccess, has_requires_std_job, has_version_rolling,
    has_work_selection,
};
use mining_sv2::{
    CHANNEL_BIT_CLOSE_CHANNEL, CHANNEL_BIT_MINING_SET_NEW_PREV_HASH,
    CHANNEL_BIT_NEW_EXTENDED_MINING_JOB, CHANNEL_BIT_NEW_MINING_JOB,
    CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL, CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    CHANNEL_BIT_OPEN_MINING_CHANNEL_ERROR, CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
    CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, CHANNEL_BIT_SET_CUSTOM_MINING_JOB,
    CHANNEL_BIT_SET_CUSTOM_MINING_JOB_ERROR, CHANNEL_BIT_SET_TARGET,
    CHANNEL_BIT_SUBMIT_SHARES_ERROR, CHANNEL_BIT_SUBMIT_SHARES_EXTENDED,
    CHANNEL_BIT_SUBMIT_SHARES_STANDARD, CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
    CHANNEL_BIT_UPDATE_CHANNEL, CHANNEL_BIT_UPDATE_CHANNEL_ERROR, CloseChannel,
    ERROR_CODE_OPEN_MINING_CHANNEL_CHANNEL_CAPACITY_EXHAUSTED,
    ERROR_CODE_OPEN_MINING_CHANNEL_EXTENDED_CHANNELS_NOT_SUPPORTED_FOR_STANDARD_JOBS,
    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE,
    ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
    ERROR_CODE_OPEN_MINING_CHANNEL_MAX_TARGET_OUT_OF_RANGE,
    ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE,
    ERROR_CODE_OPEN_MINING_CHANNEL_UNKNOWN_USER, ERROR_CODE_SET_CUSTOM_MINING_JOB_JD_NOT_SUPPORTED,
    ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE, ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW,
    ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE, ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
    ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID,
    ERROR_CODE_SUBMIT_SHARES_INVALID_NON_ROLLABLE_VERSION_BIT,
    ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE, ERROR_CODE_SUBMIT_SHARES_STALE_SHARE,
    ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID,
    ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE,
    ERROR_CODE_UPDATE_CHANNEL_MAX_TARGET_OUT_OF_RANGE, ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
    MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
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
use ruint::Uint;
use thiserror::Error;

use crate::{ConfigError, Frame, MAX_EXTRANONCE_WIRE_LEN, PROTOCOL_VERSION, U24_MAX};

/// `SetupConnection.flags` bit 0: the client can only process standard jobs.
pub const FLAG_REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
/// `SetupConnection.flags` bit 1: the client will send `SetCustomMiningJob`.
pub const FLAG_REQUIRES_WORK_SELECTION: u32 = 1 << 1;
/// `SetupConnection.flags` bit 2: the client requires version rolling.
pub const FLAG_REQUIRES_VERSION_ROLLING: u32 = 1 << 2;
/// `SetupConnection.Success.flags` bit 0: the server accepts no version changes.
pub const SUCCESS_FLAG_REQUIRES_FIXED_VERSION: u32 = 1 << 0;
/// `SetupConnection.Success.flags` bit 1: the server accepts no standard channel.
pub const SUCCESS_FLAG_REQUIRES_EXTENDED_CHANNELS: u32 = 1 << 1;

/// Local error code: `sequence_number` did not increase on its channel.
pub const ERROR_CODE_INVALID_SEQUENCE_NUMBER: &str = "invalid-sequence-number";
/// Local error code: too many accepted shares await ledger confirmation.
pub const ERROR_CODE_POOL_BUSY: &str = "pool-busy";
/// Local error code: the job holds its maximum number of accepted shares.
pub const ERROR_CODE_JOB_SHARE_CAPACITY: &str = "job-share-capacity";
/// Local error code: the pool asked this connection to reconnect elsewhere.
pub const ERROR_CODE_RECONNECT_REQUESTED: &str = "reconnect-requested";
/// Local error code: the host closed the channel because the share was not recorded.
pub const ERROR_CODE_SHARE_NOT_RECORDED: &str = "share-not-recorded";

/// Why the host admission hook refused a `user_identity`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmitError {
    /// The identity is malformed for this pool (`invalid-user-identity`).
    InvalidIdentity,
    /// The identity is well formed but not registered (`unknown-user`).
    UnknownUser,
}

/// Host hook that admits or refuses a channel's `user_identity`.
///
/// The adapter never interprets the identity: payout mapping and registration
/// belong to the accounting layer, which supplies this closure.
pub type AdmitUser = Arc<dyn Fn(&[u8]) -> Result<(), AdmitError> + Send + Sync>;

/// Hard bounds on everything a peer can make this session hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Largest accepted plaintext frame payload, at most the U24 wire maximum.
    pub max_frame_payload: usize,
    /// Open channels per connection.
    pub max_channels: usize,
    /// Wire job records kept per channel (older ones answer `invalid-job-id`).
    pub max_jobs_per_channel: usize,
    /// Accepted shares awaiting [`ProtocolSession::confirm_share`].
    pub max_pending_acks: usize,
    /// Plaintext frames queued for the transport.
    pub max_outbound_frames: usize,
    /// Events queued for the host.
    pub max_pending_events: usize,
    /// Encrypted bytes queued for the socket.
    pub max_outbound_bytes: usize,
}

impl Limits {
    /// Conservative defaults for a pool-facing listener.
    pub const DEFAULT: Self = Self {
        max_frame_payload: 8 * 1024,
        max_channels: 64,
        max_jobs_per_channel: 64,
        max_pending_acks: 1024,
        max_outbound_frames: 4096,
        max_pending_events: 4096,
        max_outbound_bytes: 4 * 1024 * 1024,
    };

    /// Rejects limits that are zero or exceed the wire format.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_frame_payload < 64 || self.max_frame_payload > U24_MAX {
            return Err(ConfigError::Limits(
                "max_frame_payload must be within 64..=0x00ff_ffff (SV2 msg_length is a U24)",
            ));
        }
        if self.max_channels == 0
            || self.max_jobs_per_channel == 0
            || self.max_pending_acks == 0
            || self.max_outbound_frames == 0
            || self.max_pending_events == 0
            || self.max_outbound_bytes == 0
        {
            return Err(ConfigError::Limits("every limit must be at least 1"));
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Per-connection configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Resource bounds.
    pub limits: Limits,
    /// Starting share target of every channel; a channel never starts easier
    /// than the miner's own `max_target`.
    pub initial_target: ShareTarget,
    /// Identity admission hook.
    pub admit_user: AdmitUser,
}

impl ServerConfig {
    /// Default limits, and an admission hook that refuses only an empty identity.
    #[must_use]
    pub fn new(initial_target: ShareTarget) -> Self {
        Self {
            limits: Limits::DEFAULT,
            initial_target,
            admit_user: Arc::new(|identity: &[u8]| {
                if identity.is_empty() {
                    Err(AdmitError::InvalidIdentity)
                } else {
                    Ok(())
                }
            }),
        }
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("limits", &self.limits)
            .field("initial_target", &self.initial_target)
            .finish_non_exhaustive()
    }
}

/// Mining channel flavour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelKind {
    /// Header-only mining: the pool fixes the whole extranonce.
    Standard,
    /// The miner rolls `extranonce_size` bytes of the coinbase.
    Extended,
}

/// Ledger handle for one accepted share awaiting confirmation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShareTicket(pub u64);

/// One accepted share, handed to the host to record before the miner is told.
///
/// This event is emitted only for shares that do not meet the network target.
/// A block candidate is surfaced as [`Event::BlockFound`] instead, so the host
/// cannot accidentally acknowledge it without first submitting the block.
#[derive(Debug)]
pub struct ShareEvent {
    /// Pass back to [`ProtocolSession::confirm_share`] or [`ProtocolSession::reject_share`].
    pub ticket: ShareTicket,
    /// Channel the share arrived on.
    pub channel_id: u32,
    /// The miner's `sequence_number`.
    pub sequence_number: u32,
    /// The owner's accepted share. Block outcomes use [`PendingBlock`].
    pub outcome: AcceptedShare,
}

/// A block candidate awaiting the host's authoritative [`MiningControl`] submission.
///
/// The ticket remains pending until the host submits this block, records the
/// resulting [`BlockReceipt`] in its durable ledger, and calls
/// [`Connection::confirm_block`] with the [`BlockSubmission`] returned by
/// [`PendingBlock::submit`]. There is no conversion from a raw share ticket to
/// a block submission token.
#[derive(Debug)]
pub struct PendingBlock {
    ticket: ShareTicket,
    channel_id: u32,
    sequence_number: u32,
    found: Box<FoundBlock>,
}

impl PendingBlock {
    /// Ticket to use after the ledger has recorded this block.
    #[must_use]
    pub fn ticket(&self) -> ShareTicket {
        self.ticket
    }

    /// Channel carrying the pending block share.
    #[must_use]
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Miner sequence number for the pending share.
    #[must_use]
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// The complete block candidate and its accepted-share identity.
    #[must_use]
    pub fn found_block(&self) -> &FoundBlock {
        &self.found
    }

    /// Submit this candidate through the node's authoritative [`MiningControl`].
    ///
    /// The returned token is required by [`Connection::confirm_block`]. The
    /// host records its receipt in the durable ledger before passing the token
    /// to `confirm_block`. A submission error leaves this pending candidate
    /// available for retry.
    pub fn submit(
        &self,
        mining_control: &dyn MiningControl,
    ) -> Result<BlockSubmission, MiningControlError> {
        let receipt = self.found.submit(mining_control)?;
        Ok(BlockSubmission {
            ticket: self.ticket,
            channel_id: self.channel_id,
            sequence_number: self.sequence_number,
            block_hash: *receipt.hash.as_bytes(),
            receipt,
        })
    }
}

/// Proof that a pending block was submitted to [`MiningControl`].
///
/// This type is intentionally constructible only through
/// [`PendingBlock::submit`]. The host records [`Self::receipt`] in its ledger
/// before passing this token to [`Connection::confirm_block`].
#[derive(Debug)]
pub struct BlockSubmission {
    ticket: ShareTicket,
    channel_id: u32,
    sequence_number: u32,
    block_hash: [u8; 32],
    receipt: BlockReceipt,
}

impl BlockSubmission {
    /// Share ticket associated with the submitted block.
    #[must_use]
    pub fn ticket(&self) -> ShareTicket {
        self.ticket
    }

    /// [`MiningControl`]'s receipt, to pass to the ledger's block-record operation.
    #[must_use]
    pub fn receipt(&self) -> &BlockReceipt {
        &self.receipt
    }
}

/// Why a channel went away.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    /// The miner sent `CloseChannel`.
    Peer,
    /// The host closed it.
    Host,
}

/// Something the host must act on.
#[derive(Debug)]
pub enum Event {
    /// `SetupConnection` was accepted.
    SetupCompleted {
        /// Flags the client declared.
        flags: u32,
    },
    /// `SetupConnection` was refused; the connection is closing.
    SetupRejected {
        /// Official error code that was sent.
        code: &'static str,
    },
    /// A channel is open and holds an extranonce session.
    ChannelOpened {
        /// New channel id.
        channel_id: u32,
        /// Group channel the channel belongs to.
        group_channel_id: u32,
        /// Standard or extended.
        kind: ChannelKind,
        /// The owner's session identity (unique extranonce prefix).
        session: SessionId,
        /// Opaque identity the miner declared.
        user_identity: Vec<u8>,
        /// Declared hashrate, h/s.
        nominal_hash_rate: f32,
        /// Initial share target.
        target: ShareTarget,
    },
    /// An open request was refused.
    ChannelOpenRejected {
        /// The request's `request_id`.
        request_id: u32,
        /// Error code that was sent.
        code: &'static str,
    },
    /// A channel closed and its session was released.
    ChannelClosed {
        /// Closed channel id.
        channel_id: u32,
        /// Who closed it.
        reason: CloseReason,
    },
    /// A share passed the owner's predicate; record it, then confirm.
    ShareAccepted(ShareEvent),
    /// A block passed the network target and awaits host submission.
    BlockFound(PendingBlock),
    /// A share was refused and the miner was told why.
    ShareRejected {
        /// Channel the share arrived on.
        channel_id: u32,
        /// The miner's `sequence_number`.
        sequence_number: u32,
        /// Error code that was sent.
        code: &'static str,
        /// The owner's verdict, absent for rules that live on the wire only.
        cause: Option<ShareError>,
    },
}

/// Read-only view of one open channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelInfo {
    /// Channel id.
    pub channel_id: u32,
    /// Standard or extended.
    pub kind: ChannelKind,
    /// The owner's session.
    pub session: SessionId,
    /// Opaque identity the miner declared.
    pub user_identity: Vec<u8>,
    /// Current share target.
    pub target: ShareTarget,
    /// Largest target the miner accepts.
    pub max_target: ShareTarget,
    /// Bytes the miner was told as `extranonce_prefix`.
    pub extranonce_prefix: Vec<u8>,
}

/// Fatal protocol violations; the connection must be dropped.
#[derive(Debug, Error)]
pub enum SessionError {
    /// A message other than `SetupConnection` opened the connection.
    #[error("message type {msg_type:#04x} before SetupConnection")]
    SetupRequired {
        /// Offending message type.
        msg_type: u8,
    },
    /// `SetupConnection` arrived on an established connection.
    #[error("SetupConnection sent twice")]
    DuplicateSetup,
    /// The payload does not decode to exactly one message.
    #[error("malformed message {msg_type:#04x}: {detail}")]
    Malformed {
        /// Offending message type.
        msg_type: u8,
        /// What failed.
        detail: String,
    },
    /// The `channel_msg` bit does not match the message definition.
    #[error("message type {msg_type:#04x} requires channel_msg bit = {expected}")]
    ChannelBit {
        /// Offending message type.
        msg_type: u8,
        /// Bit value the definition requires.
        expected: bool,
    },
    /// A message type this server never accepts from a client.
    #[error("unexpected message type {msg_type:#04x}")]
    UnexpectedMessage {
        /// Offending message type.
        msg_type: u8,
    },
    /// The peer is not draining output.
    #[error("{queue} backlog exceeds {limit}")]
    Backlog {
        /// Which queue overflowed.
        queue: &'static str,
        /// Its bound.
        limit: usize,
    },
    /// A message this server built does not fit its wire type.
    #[error("cannot encode message {msg_type:#04x}: {detail}")]
    Encode {
        /// Message type.
        msg_type: u8,
        /// What failed.
        detail: String,
    },
    /// The job owner refused a request that cannot be a miner's fault.
    #[error("job owner: {0}")]
    Job(JobError),
    /// The job owner could not project a job for a channel.
    #[error("job projection: {0}")]
    Projection(ShareError),
    /// A host call named a channel that is not open.
    #[error("channel {0} is not open")]
    UnknownChannel(u32),
    /// A block ticket cannot be acknowledged as an ordinary share.
    #[error("block ticket requires `MiningControl` submission before confirmation")]
    BlockRequiresSubmission,
    /// A host-requested target is above the miner's own maximum.
    #[error("target exceeds the maximum target of channel {channel_id}")]
    TargetAboveMaximum {
        /// The channel whose bound would be violated.
        channel_id: u32,
    },
    /// An error code with bytes outside printable ASCII.
    #[error("error code is not printable ASCII")]
    BadErrorCode,
}

impl SessionError {
    /// False for host-call mistakes that leave the connection untouched.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        !matches!(
            self,
            Self::UnknownChannel(_)
                | Self::TargetAboveMaximum { .. }
                | Self::BadErrorCode
                | Self::BlockRequiresSubmission
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    AwaitSetup,
    Open,
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delivery {
    /// `ntime_start` unset; activated by the `SetNewPrevHash` that follows.
    Future,
    /// `ntime_start` set; mined immediately on the last announced prev hash.
    Active,
}

struct ChannelJob {
    /// Share target fixed when the job became active on the channel.
    /// `None` until a future job is activated.
    target: Option<ShareTarget>,
}

struct Channel {
    kind: ChannelKind,
    session: SessionId,
    /// The owner's session extranonce prefix.
    session_prefix: Vec<u8>,
    /// Standard channels: the pool-fixed rolled bytes. Extended: empty.
    rolled: Vec<u8>,
    user_identity: Vec<u8>,
    nominal_hash_rate: f32,
    max_target: ShareTarget,
    target: ShareTarget,
    last_sequence: Option<u32>,
    jobs: BTreeMap<u32, ChannelJob>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingKind {
    Share,
    Block,
}

struct Pending {
    channel_id: u32,
    sequence_number: u32,
    difficulty: u64,
    block_hash: Option<[u8; 32]>,
    kind: PendingKind,
}

/// One Stratum V2 pool connection, above the transport.
pub struct ProtocolSession {
    config: ServerConfig,
    phase: Phase,
    requires_standard_jobs: bool,
    reconnecting: bool,
    channels: BTreeMap<u32, Channel>,
    group_id: Option<u32>,
    next_id: u32,
    pending: BTreeMap<u64, Pending>,
    next_ticket: u64,
    out: VecDeque<Frame>,
    events: VecDeque<Event>,
    ignored_extension_frames: u64,
}

impl fmt::Debug for ProtocolSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolSession")
            .field("phase", &self.phase)
            .field("channels", &self.channels.len())
            .field("pending_acks", &self.pending.len())
            .finish_non_exhaustive()
    }
}

fn frame_of<T: Encodable + GetSize>(
    msg_type: u8,
    channel_msg: bool,
    msg: T,
) -> Result<Frame, SessionError> {
    let payload = binary_sv2::to_bytes(msg).map_err(|e| SessionError::Encode {
        msg_type,
        detail: e.to_string(),
    })?;
    if payload.len() > U24_MAX {
        return Err(SessionError::Encode {
            msg_type,
            detail: format!(
                "payload of {} bytes exceeds the U24 msg_length",
                payload.len()
            ),
        });
    }
    Ok(Frame {
        extension_type: 0,
        msg_type,
        channel_msg,
        payload,
    })
}

/// Decodes exactly one message; trailing bytes are a violation (no extension
/// TLV was negotiated, so none may follow).
fn decode<'a, T: Decodable<'a> + GetSize>(
    msg_type: u8,
    payload: &'a mut [u8],
) -> Result<T, SessionError> {
    let len = payload.len();
    let msg: T = binary_sv2::from_bytes(payload).map_err(|e| SessionError::Malformed {
        msg_type,
        detail: e.to_string(),
    })?;
    let used = msg.get_size();
    if used != len {
        return Err(SessionError::Malformed {
            msg_type,
            detail: format!("message uses {used} of {len} payload bytes"),
        });
    }
    Ok(msg)
}

fn check_bit(msg_type: u8, got: bool, expected: bool) -> Result<(), SessionError> {
    if got == expected {
        Ok(())
    } else {
        Err(SessionError::ChannelBit { msg_type, expected })
    }
}

fn code_str(code: &str) -> Result<Str0255<'_>, SessionError> {
    if !code.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(SessionError::BadErrorCode);
    }
    Str0255::try_from(code).map_err(|_| SessionError::BadErrorCode)
}

/// The integer pool difficulty (diff-1 basis, `0xffff << 208`) of `target`.
///
/// Spec §5.3.13: `SubmitShares.Success.new_shares_sum` is the sum of the
/// *difficulty* of the jobs the shares were submitted against, NOT the raw
/// hash count ([`bitcoin_rs_stratum::ShareWork`]), which is scaled by 2^32.
/// Targets easier than difficulty 1 clamp to 1 so that acknowledged shares
/// always contribute at least 1 unit to the acknowledged shares sum.
pub fn target_difficulty(target: ShareTarget) -> u64 {
    let target_u256 = Uint::<256, 4>::from_le_bytes(target.to_le_bytes());
    if target_u256.is_zero() {
        return 0;
    }
    let diff_one = Uint::<256, 4>::from(0xffff_u32) << 208_usize;
    let quotient = diff_one / target_u256;
    let diff = u64::try_from(quotient).unwrap_or(u64::MAX);
    diff.max(1)
}

/// Maps the owner's rejection onto an official SV2 `SubmitShares.Error` code.
fn share_error_code(error: &ShareError) -> &'static str {
    match error {
        ShareError::UnknownSession(_) => ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
        ShareError::UnknownJob(_) => ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID,
        ShareError::Stale { .. } => ERROR_CODE_SUBMIT_SHARES_STALE_SHARE,
        ShareError::SessionPrefixLength { .. } | ShareError::ExtranonceLength { .. } => {
            ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE
        }
        ShareError::VersionOutsideMask { mask, .. } => {
            if *mask == 0 {
                ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED
            } else {
                ERROR_CODE_SUBMIT_SHARES_INVALID_NON_ROLLABLE_VERSION_BIT
            }
        }
        ShareError::TimeTooEarly { .. } | ShareError::TimeTooLate { .. } => {
            ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE
        }
        ShareError::Duplicate { .. } => ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE,
        ShareError::BelowTarget { .. } => ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW,
        ShareError::JobShareCapacity { .. } => ERROR_CODE_JOB_SHARE_CAPACITY,
    }
}

/// `NewMiningJob` for a standard channel: the merkle root is the owner's.
fn standard_job_frame(
    channel_id: u32,
    job: &Job,
    session_prefix: &[u8],
    rolled: &[u8],
    delivery: Delivery,
) -> Result<Frame, SessionError> {
    let root = job
        .merkle_root(Extranonce {
            session: session_prefix,
            rolled,
        })
        .map_err(SessionError::Projection)?;
    let root = *root.as_byte_array();
    let msg = NewMiningJob {
        channel_id,
        job_id: job.id().get(),
        min_ntime: Sv2Option::new(match delivery {
            Delivery::Future => None,
            Delivery::Active => Some(job.ntime()),
        }),
        version: job.version(),
        merkle_root: U256::from(&root),
    };
    frame_of(MESSAGE_TYPE_NEW_MINING_JOB, CHANNEL_BIT_NEW_MINING_JOB, msg)
}

/// `NewExtendedMiningJob` for an extended channel or, with the group id, for
/// the whole group: the coinbase halves and merkle path are the owner's.
fn extended_job_frame(
    channel_id: u32,
    job: &Job,
    delivery: Delivery,
) -> Result<Frame, SessionError> {
    let branch: Vec<[u8; 32]> = job
        .merkle_branch()
        .iter()
        .map(|hash| *hash.as_byte_array())
        .collect();
    let path: Vec<U256<'_>> = branch.iter().map(U256::from).collect();
    let merkle_path = Seq0255::new(path).map_err(|e| SessionError::Encode {
        msg_type: MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        detail: e.to_string(),
    })?;
    let prefix = B064K::new(job.coinbase_prefix()).map_err(|e| SessionError::Encode {
        msg_type: MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        detail: e.to_string(),
    })?;
    let suffix = B064K::new(job.coinbase_suffix()).map_err(|e| SessionError::Encode {
        msg_type: MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        detail: e.to_string(),
    })?;
    let msg = NewExtendedMiningJob {
        channel_id,
        job_id: job.id().get(),
        min_ntime: Sv2Option::new(match delivery {
            Delivery::Future => None,
            Delivery::Active => Some(job.ntime()),
        }),
        version: job.version(),
        version_rolling_allowed: job.version_mask() != 0,
        merkle_path,
        coinbase_tx_prefix: prefix,
        coinbase_tx_suffix: suffix,
    };
    frame_of(
        MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        CHANNEL_BIT_NEW_EXTENDED_MINING_JOB,
        msg,
    )
}

fn prev_hash_frame(channel_id: u32, job: &Job) -> Result<Frame, SessionError> {
    let prev = *job.previous_block_hash().as_bytes();
    let msg = SetNewPrevHash {
        channel_id,
        job_id: job.id().get(),
        prev_hash: U256::from(&prev),
        min_ntime: job.ntime(),
        nbits: job.bits().to_consensus(),
    };
    frame_of(
        MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
        CHANNEL_BIT_MINING_SET_NEW_PREV_HASH,
        msg,
    )
}

struct OpenRequest {
    request_id: u32,
    user_identity: Vec<u8>,
    nominal_hash_rate: f32,
    max_target_le: [u8; 32],
    min_extranonce_size: u16,
}

fn decode_open_request(
    mut payload: Vec<u8>,
    kind: ChannelKind,
) -> Result<OpenRequest, SessionError> {
    match kind {
        ChannelKind::Standard => {
            let msg: OpenStandardMiningChannel<'_> =
                decode(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, &mut payload)?;
            Ok(OpenRequest {
                request_id: msg.request_id,
                user_identity: msg.user_identity.as_bytes().to_vec(),
                nominal_hash_rate: msg.nominal_hash_rate,
                max_target_le: *msg.max_target.as_array(),
                min_extranonce_size: 0,
            })
        }
        ChannelKind::Extended => {
            let msg: OpenExtendedMiningChannel<'_> =
                decode(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut payload)?;
            Ok(OpenRequest {
                request_id: msg.request_id,
                user_identity: msg.user_identity.as_bytes().to_vec(),
                nominal_hash_rate: msg.nominal_hash_rate,
                max_target_le: *msg.max_target.as_array(),
                min_extranonce_size: msg.min_extranonce_size,
            })
        }
    }
}

struct OpenSuccess<'a> {
    kind: ChannelKind,
    request_id: u32,
    channel_id: u32,
    group_channel_id: u32,
    target: ShareTarget,
    session_prefix: &'a [u8],
    rolled: &'a [u8],
    extranonce_size: usize,
}

fn open_success_frame(context: &OpenSuccess<'_>) -> Result<Frame, SessionError> {
    let &OpenSuccess {
        kind,
        request_id,
        channel_id,
        group_channel_id,
        target,
        session_prefix,
        rolled,
        extranonce_size,
    } = context;
    let target_le = target.to_le_bytes();
    match kind {
        ChannelKind::Standard => {
            let mut full = session_prefix.to_vec();
            full.extend_from_slice(rolled);
            let extranonce_prefix = B032::new(&full).map_err(|e| SessionError::Encode {
                msg_type: MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                detail: e.to_string(),
            })?;
            frame_of(
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                OpenStandardMiningChannelSuccess {
                    request_id,
                    channel_id,
                    target: U256::from(&target_le),
                    extranonce_prefix,
                    group_channel_id,
                },
            )
        }
        ChannelKind::Extended => {
            let extranonce_prefix =
                B032::new(session_prefix).map_err(|e| SessionError::Encode {
                    msg_type: MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                    detail: e.to_string(),
                })?;
            frame_of(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                OpenExtendedMiningChannelSuccess {
                    request_id,
                    channel_id,
                    target: U256::from(&target_le),
                    extranonce_size: u16::try_from(extranonce_size).unwrap_or(u16::MAX),
                    extranonce_prefix,
                    group_channel_id,
                },
            )
        }
    }
}

impl ProtocolSession {
    /// A session awaiting `SetupConnection`. `book` is checked for an
    /// extranonce layout the SV2 wire can carry.
    pub fn new(config: ServerConfig, book: &JobBook) -> Result<Self, ConfigError> {
        config.limits.validate()?;
        let layout = book.config().extranonce;
        if layout.total_len() > MAX_EXTRANONCE_WIRE_LEN {
            return Err(ConfigError::ExtranonceTooLong {
                total: layout.total_len(),
                max: MAX_EXTRANONCE_WIRE_LEN,
            });
        }
        Ok(Self {
            config,
            phase: Phase::AwaitSetup,
            requires_standard_jobs: false,
            reconnecting: false,
            channels: BTreeMap::new(),
            group_id: None,
            next_id: 1,
            pending: BTreeMap::new(),
            next_ticket: 0,
            out: VecDeque::new(),
            events: VecDeque::new(),
            ignored_extension_frames: 0,
        })
    }

    /// True once the connection must be flushed and closed.
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.phase == Phase::Closing
    }

    /// Frames with a non-zero `extension_type` discarded so far (§3.4.1: no
    /// extension is negotiated, so they are ignored).
    #[must_use]
    pub fn ignored_extension_frames(&self) -> u64 {
        self.ignored_extension_frames
    }

    /// Number of open channels.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Accepted shares awaiting [`Self::confirm_share`].
    #[must_use]
    pub fn pending_acks(&self) -> usize {
        self.pending.len()
    }

    /// The group channel id, once a channel was opened.
    #[must_use]
    pub fn group_channel_id(&self) -> Option<u32> {
        self.group_id
    }

    /// Ids of the open channels, ascending.
    #[must_use]
    pub fn channel_ids(&self) -> Vec<u32> {
        self.channels.keys().copied().collect()
    }

    /// View of one open channel.
    #[must_use]
    pub fn channel(&self, channel_id: u32) -> Option<ChannelInfo> {
        let channel = self.channels.get(&channel_id)?;
        let mut prefix = channel.session_prefix.clone();
        prefix.extend_from_slice(&channel.rolled);
        Some(ChannelInfo {
            channel_id,
            kind: channel.kind,
            session: channel.session,
            user_identity: channel.user_identity.clone(),
            target: channel.target,
            max_target: channel.max_target,
            extranonce_prefix: prefix,
        })
    }

    /// Drains the outbound plaintext frames, in send order.
    pub fn take_frames(&mut self) -> Vec<Frame> {
        self.out.drain(..).collect()
    }

    /// Next host event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn push_event(&mut self, event: Event) -> Result<(), SessionError> {
        if self.events.len() >= self.config.limits.max_pending_events {
            return Err(SessionError::Backlog {
                queue: "event",
                limit: self.config.limits.max_pending_events,
            });
        }
        self.events.push_back(event);
        Ok(())
    }

    fn push_frame(&mut self, frame: Frame) -> Result<(), SessionError> {
        if self.out.len() >= self.config.limits.max_outbound_frames {
            return Err(SessionError::Backlog {
                queue: "outbound frame",
                limit: self.config.limits.max_outbound_frames,
            });
        }
        self.out.push_back(frame);
        Ok(())
    }

    fn queue<T: Encodable + GetSize>(
        &mut self,
        msg_type: u8,
        channel_msg: bool,
        msg: T,
    ) -> Result<(), SessionError> {
        let frame = frame_of(msg_type, channel_msg, msg)?;
        self.push_frame(frame)
    }

    fn alloc_id(&mut self) -> Option<u32> {
        let id = self.next_id;
        self.next_id = id.checked_add(1)?;
        Some(id)
    }

    /// Consumes one plaintext frame from the peer.
    ///
    /// `Err` is a fatal violation: drop the connection and call
    /// [`Self::release`]. Refusals that the protocol answers with an error
    /// message (bad channel, stale share, ...) are `Ok` and visible as events.
    pub fn handle(&mut self, book: &mut JobBook, frame: Frame) -> Result<(), SessionError> {
        if self.phase == Phase::Closing {
            return Ok(());
        }
        if frame.extension_type != 0 {
            self.ignored_extension_frames = self.ignored_extension_frames.saturating_add(1);
            return Ok(());
        }
        let Frame {
            msg_type,
            channel_msg,
            payload,
            ..
        } = frame;
        match self.phase {
            Phase::AwaitSetup => {
                if msg_type != MESSAGE_TYPE_SETUP_CONNECTION {
                    return Err(SessionError::SetupRequired { msg_type });
                }
                check_bit(msg_type, channel_msg, CHANNEL_BIT_SETUP_CONNECTION)?;
                self.setup(book, payload)
            }
            Phase::Open => self.dispatch(book, msg_type, channel_msg, payload),
            Phase::Closing => Ok(()),
        }
    }

    fn reject_setup(&mut self, flags: u32, code: &'static str) -> Result<(), SessionError> {
        let msg = SetupConnectionError {
            flags,
            error_code: code_str(code)?,
        };
        self.queue(
            MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
            CHANNEL_BIT_SETUP_CONNECTION_ERROR,
            msg,
        )?;
        self.phase = Phase::Closing;
        self.push_event(Event::SetupRejected { code })
    }

    fn setup(&mut self, book: &JobBook, mut payload: Vec<u8>) -> Result<(), SessionError> {
        let (protocol, min_version, max_version, flags) = {
            let msg: SetupConnection<'_> = decode(MESSAGE_TYPE_SETUP_CONNECTION, &mut payload)?;
            (msg.protocol, msg.min_version, msg.max_version, msg.flags)
        };
        // The set of flags this server cannot honor. Work selection needs
        // custom jobs, which the job owner cannot install; version rolling
        // needs a non-empty version mask on the job owner.
        let rolling_available = book.config().version_mask != 0;
        let mut unsupported = FLAG_REQUIRES_WORK_SELECTION;
        if !rolling_available {
            unsupported |= FLAG_REQUIRES_VERSION_ROLLING;
        }
        match protocol {
            Protocol::MiningProtocol => {}
            Protocol::JobDeclarationProtocol | Protocol::TemplateDistributionProtocol => {
                return self.reject_setup(0, ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL);
            }
        }
        if min_version > PROTOCOL_VERSION || max_version < PROTOCOL_VERSION {
            return self.reject_setup(0, ERROR_CODE_SETUP_CONNECTION_PROTOCOL_VERSION_MISMATCH);
        }
        let asks_work_selection = has_work_selection(flags);
        let asks_rolling = has_version_rolling(flags);
        if (asks_work_selection && unsupported & FLAG_REQUIRES_WORK_SELECTION != 0)
            || (asks_rolling && unsupported & FLAG_REQUIRES_VERSION_ROLLING != 0)
        {
            return self.reject_setup(
                unsupported,
                ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS,
            );
        }
        self.requires_standard_jobs = has_requires_std_job(flags);
        let success_flags = if rolling_available {
            0
        } else {
            SUCCESS_FLAG_REQUIRES_FIXED_VERSION
        };
        self.queue(
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
            CHANNEL_BIT_SETUP_CONNECTION_SUCCESS,
            SetupConnectionSuccess {
                used_version: PROTOCOL_VERSION,
                flags: success_flags,
            },
        )?;
        self.phase = Phase::Open;
        self.push_event(Event::SetupCompleted { flags })
    }

    fn dispatch(
        &mut self,
        book: &mut JobBook,
        msg_type: u8,
        channel_msg: bool,
        payload: Vec<u8>,
    ) -> Result<(), SessionError> {
        match msg_type {
            MESSAGE_TYPE_SETUP_CONNECTION => Err(SessionError::DuplicateSetup),
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => {
                check_bit(
                    msg_type,
                    channel_msg,
                    CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
                )?;
                self.open_channel(book, payload, ChannelKind::Standard)
            }
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
                check_bit(
                    msg_type,
                    channel_msg,
                    CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL,
                )?;
                self.open_channel(book, payload, ChannelKind::Extended)
            }
            MESSAGE_TYPE_UPDATE_CHANNEL => {
                check_bit(msg_type, channel_msg, CHANNEL_BIT_UPDATE_CHANNEL)?;
                self.update_channel(payload)
            }
            MESSAGE_TYPE_CLOSE_CHANNEL => {
                check_bit(msg_type, channel_msg, CHANNEL_BIT_CLOSE_CHANNEL)?;
                self.peer_close(book, payload)
            }
            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD => {
                check_bit(msg_type, channel_msg, CHANNEL_BIT_SUBMIT_SHARES_STANDARD)?;
                self.submit_standard(book, payload)
            }
            MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED => {
                check_bit(msg_type, channel_msg, CHANNEL_BIT_SUBMIT_SHARES_EXTENDED)?;
                self.submit_extended(book, payload)
            }
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB => {
                check_bit(msg_type, channel_msg, CHANNEL_BIT_SET_CUSTOM_MINING_JOB)?;
                self.refuse_custom_job(payload)
            }
            _ => Err(SessionError::UnexpectedMessage { msg_type }),
        }
    }

    // ---- channel open ------------------------------------------------------

    fn reject_open(&mut self, request_id: u32, code: &'static str) -> Result<(), SessionError> {
        let msg = OpenMiningChannelError {
            request_id,
            error_code: code_str(code)?,
        };
        self.queue(
            MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
            CHANNEL_BIT_OPEN_MINING_CHANNEL_ERROR,
            msg,
        )?;
        self.push_event(Event::ChannelOpenRejected { request_id, code })
    }

    fn validate_open(
        &self,
        book: &JobBook,
        kind: ChannelKind,
        request: &OpenRequest,
    ) -> Result<ShareTarget, &'static str> {
        if self.reconnecting {
            return Err(ERROR_CODE_RECONNECT_REQUESTED);
        }
        if kind == ChannelKind::Extended && self.requires_standard_jobs {
            return Err(
                ERROR_CODE_OPEN_MINING_CHANNEL_EXTENDED_CHANNELS_NOT_SUPPORTED_FOR_STANDARD_JOBS,
            );
        }
        if self.channels.len() >= self.config.limits.max_channels {
            return Err(ERROR_CODE_OPEN_MINING_CHANNEL_CHANNEL_CAPACITY_EXHAUSTED);
        }
        if !request.nominal_hash_rate.is_finite() || request.nominal_hash_rate < 0.0 {
            return Err(ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE);
        }
        if let Err(refusal) = (self.config.admit_user)(&request.user_identity) {
            return Err(match refusal {
                AdmitError::InvalidIdentity => ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
                AdmitError::UnknownUser => ERROR_CODE_OPEN_MINING_CHANNEL_UNKNOWN_USER,
            });
        }
        let max_target = ShareTarget::from_le_bytes(request.max_target_le)
            .map_err(|_| ERROR_CODE_OPEN_MINING_CHANNEL_MAX_TARGET_OUT_OF_RANGE)?;
        if usize::from(request.min_extranonce_size) > book.config().extranonce.rolled_len() {
            return Err(ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE);
        }
        Ok(max_target)
    }

    fn allocate_open(
        &mut self,
        book: &mut JobBook,
    ) -> Result<Option<(u32, u32, Session)>, SessionError> {
        let group_id = self.group_id.or_else(|| {
            let group = self.alloc_id();
            self.group_id = group;
            group
        });
        let (Some(group_channel_id), Some(channel_id)) = (group_id, self.alloc_id()) else {
            return Ok(None);
        };
        let session = match book.open_session() {
            Ok(session) => session,
            Err(JobError::SessionCapacity { .. } | JobError::SessionIdExhausted) => {
                return Ok(None);
            }
            Err(other) => return Err(SessionError::Job(other)),
        };
        Ok(Some((group_channel_id, channel_id, session)))
    }

    fn open_channel(
        &mut self,
        book: &mut JobBook,
        payload: Vec<u8>,
        kind: ChannelKind,
    ) -> Result<(), SessionError> {
        let request = decode_open_request(payload, kind)?;
        let max_target = match self.validate_open(book, kind, &request) {
            Ok(max_target) => max_target,
            Err(code) => return self.reject_open(request.request_id, code),
        };
        let layout = book.config().extranonce;
        let Some((group_channel_id, channel_id, session)) = self.allocate_open(book)? else {
            return self.reject_open(
                request.request_id,
                ERROR_CODE_OPEN_MINING_CHANNEL_CHANNEL_CAPACITY_EXHAUSTED,
            );
        };

        let target = self.config.initial_target.min(max_target);
        let session_prefix = session.extranonce_prefix().to_vec();
        let rolled = match kind {
            ChannelKind::Standard => vec![0_u8; layout.rolled_len()],
            ChannelKind::Extended => Vec::new(),
        };
        let reply = open_success_frame(&OpenSuccess {
            kind,
            request_id: request.request_id,
            channel_id,
            group_channel_id,
            target,
            session_prefix: &session_prefix,
            rolled: &rolled,
            extranonce_size: layout.rolled_len(),
        });
        let reply = match reply {
            Ok(frame) => frame,
            Err(error) => {
                book.close_session(session.id());
                return Err(error);
            }
        };
        let session_id = session.id();
        if let Err(error) = self.push_frame(reply) {
            book.close_session(session_id);
            return Err(error);
        }
        self.channels.insert(
            channel_id,
            Channel {
                kind,
                session: session_id,
                session_prefix,
                rolled,
                user_identity: request.user_identity.clone(),
                nominal_hash_rate: request.nominal_hash_rate,
                max_target,
                target,
                last_sequence: None,
                jobs: BTreeMap::new(),
            },
        );
        self.push_event(Event::ChannelOpened {
            channel_id,
            group_channel_id,
            kind,
            session: session_id,
            user_identity: request.user_identity,
            nominal_hash_rate: request.nominal_hash_rate,
            target,
        })?;

        // §5.3.15/5.3.16: the first message after a channel opens is a future
        // job, followed by the `SetNewPrevHash` that activates it.
        if let Some(current) = book.current().cloned() {
            self.send_to_channel(channel_id, &current, Delivery::Future)?;
        }
        Ok(())
    }

    // ---- job distribution --------------------------------------------------

    /// Announces a job the owner just installed to every channel.
    ///
    /// `installed.fresh == false` sends nothing. `clean_jobs` sends a future
    /// job and the `SetNewPrevHash` that activates it (earlier jobs are stale
    /// in the owner and invalid on the miner); otherwise the job is active
    /// immediately on the last announced previous hash. Connections that did
    /// not set `REQUIRES_STANDARD_JOBS` receive one group-addressed
    /// `NewExtendedMiningJob`; the others, one job per channel.
    pub fn announce(
        &mut self,
        installed: &bitcoin_rs_stratum::Installed,
    ) -> Result<(), SessionError> {
        if self.phase != Phase::Open || !installed.fresh {
            return Ok(());
        }
        let delivery = if installed.clean_jobs {
            Delivery::Future
        } else {
            Delivery::Active
        };
        self.distribute(&installed.job, delivery)
    }

    fn distribute(&mut self, job: &Job, delivery: Delivery) -> Result<(), SessionError> {
        let job_id = job.id().get();
        let missing: Vec<u32> = self
            .channels
            .iter()
            .filter(|(_, channel)| !channel.jobs.contains_key(&job_id))
            .map(|(id, _)| *id)
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let group = match self.group_id {
            Some(group) if !self.requires_standard_jobs && missing.len() == self.channels.len() => {
                Some(group)
            }
            _ => None,
        };
        if let Some(group_id) = group {
            let frame = extended_job_frame(group_id, job, delivery)?;
            self.push_frame(frame)?;
            let max = self.config.limits.max_jobs_per_channel;
            for channel in self.channels.values_mut() {
                let target = match delivery {
                    Delivery::Future => None,
                    Delivery::Active => Some(channel.target),
                };
                record_job(channel, job_id, target, max);
            }
            if delivery == Delivery::Future {
                let frame = prev_hash_frame(group_id, job)?;
                self.push_frame(frame)?;
                for channel in self.channels.values_mut() {
                    activate_job(channel, job_id);
                }
            }
            return Ok(());
        }
        for channel_id in missing {
            self.send_to_channel(channel_id, job, delivery)?;
        }
        Ok(())
    }

    /// Channel-addressed delivery: the job, then (for a future job) the
    /// `SetNewPrevHash` that activates it.
    fn send_to_channel(
        &mut self,
        channel_id: u32,
        job: &Job,
        delivery: Delivery,
    ) -> Result<(), SessionError> {
        let (kind, session_prefix, rolled, target) = match self.channels.get(&channel_id) {
            Some(channel) => (
                channel.kind,
                channel.session_prefix.clone(),
                channel.rolled.clone(),
                channel.target,
            ),
            None => return Err(SessionError::UnknownChannel(channel_id)),
        };
        let frame = match kind {
            ChannelKind::Standard => {
                standard_job_frame(channel_id, job, &session_prefix, &rolled, delivery)?
            }
            ChannelKind::Extended => extended_job_frame(channel_id, job, delivery)?,
        };
        self.push_frame(frame)?;
        let max = self.config.limits.max_jobs_per_channel;
        let job_id = job.id().get();
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            record_job(
                channel,
                job_id,
                match delivery {
                    Delivery::Future => None,
                    Delivery::Active => Some(target),
                },
                max,
            );
        }
        if delivery == Delivery::Future {
            let frame = prev_hash_frame(channel_id, job)?;
            self.push_frame(frame)?;
            if let Some(channel) = self.channels.get_mut(&channel_id) {
                activate_job(channel, job_id);
            }
        }
        Ok(())
    }

    // ---- targets -----------------------------------------------------------

    fn queue_set_target(&mut self, id: u32, target: ShareTarget) -> Result<(), SessionError> {
        let le = target.to_le_bytes();
        self.queue(
            MESSAGE_TYPE_SET_TARGET,
            CHANNEL_BIT_SET_TARGET,
            SetTarget {
                channel_id: id,
                maximum_target: U256::from(&le),
            },
        )
    }

    /// Host-driven retarget (vardiff policy lives in the host).
    ///
    /// `id` is a channel or the group channel. The target must not exceed the
    /// miner's `max_target` (§5.3.21). Jobs already active keep the target they
    /// were issued under; future jobs take it when they activate.
    pub fn set_target(&mut self, id: u32, target: ShareTarget) -> Result<(), SessionError> {
        let members: Vec<u32> = if self.group_id == Some(id) {
            self.channels.keys().copied().collect()
        } else if self.channels.contains_key(&id) {
            vec![id]
        } else {
            return Err(SessionError::UnknownChannel(id));
        };
        for member in &members {
            if let Some(channel) = self.channels.get(member)
                && target > channel.max_target
            {
                return Err(SessionError::TargetAboveMaximum {
                    channel_id: *member,
                });
            }
        }
        for member in &members {
            if let Some(channel) = self.channels.get_mut(member) {
                channel.target = target;
            }
        }
        self.queue_set_target(id, target)
    }

    fn update_channel(&mut self, mut payload: Vec<u8>) -> Result<(), SessionError> {
        let (channel_id, hash_rate, max_le) = {
            let msg: UpdateChannel<'_> = decode(MESSAGE_TYPE_UPDATE_CHANNEL, &mut payload)?;
            (
                msg.channel_id,
                msg.nominal_hash_rate,
                *msg.maximum_target.as_array(),
            )
        };
        let refusal = if !self.channels.contains_key(&channel_id) {
            Some(ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID)
        } else if !hash_rate.is_finite() || hash_rate < 0.0 {
            Some(ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE)
        } else if ShareTarget::from_le_bytes(max_le).is_err() {
            Some(ERROR_CODE_UPDATE_CHANNEL_MAX_TARGET_OUT_OF_RANGE)
        } else {
            None
        };
        if let Some(code) = refusal {
            let msg = UpdateChannelError {
                channel_id,
                error_code: code_str(code)?,
            };
            return self.queue(
                MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
                CHANNEL_BIT_UPDATE_CHANNEL_ERROR,
                msg,
            );
        }
        let Ok(max_target) = ShareTarget::from_le_bytes(max_le) else {
            return Ok(());
        };
        let mut lowered = None;
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.nominal_hash_rate = hash_rate;
            channel.max_target = max_target;
            if channel.target > max_target {
                channel.target = max_target;
                lowered = Some(max_target);
            }
        }
        // §5.3.7: a smaller max_target must be reflected by a SetTarget.
        match lowered {
            Some(target) => self.queue_set_target(channel_id, target),
            None => Ok(()),
        }
    }

    // ---- shares ------------------------------------------------------------

    fn submit_standard(
        &mut self,
        book: &mut JobBook,
        mut payload: Vec<u8>,
    ) -> Result<(), SessionError> {
        let msg: SubmitSharesStandard = decode(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, &mut payload)?;
        self.submit(
            book,
            ChannelKind::Standard,
            &Submit {
                channel_id: msg.channel_id,
                sequence_number: msg.sequence_number,
                job_id: msg.job_id,
                nonce: msg.nonce,
                ntime: msg.ntime,
                version: msg.version,
                extranonce: None,
            },
        )
    }

    fn submit_extended(
        &mut self,
        book: &mut JobBook,
        mut payload: Vec<u8>,
    ) -> Result<(), SessionError> {
        let submit = {
            let msg: SubmitSharesExtended<'_> =
                decode(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut payload)?;
            Submit {
                channel_id: msg.channel_id,
                sequence_number: msg.sequence_number,
                job_id: msg.job_id,
                nonce: msg.nonce,
                ntime: msg.ntime,
                version: msg.version,
                extranonce: Some(msg.extranonce.as_bytes().to_vec()),
            }
        };
        self.submit(book, ChannelKind::Extended, &submit)
    }

    fn refuse_share(
        &mut self,
        channel_id: u32,
        sequence_number: u32,
        code: &'static str,
        cause: Option<ShareError>,
    ) -> Result<(), SessionError> {
        let msg = SubmitSharesError {
            channel_id,
            sequence_number,
            error_code: code_str(code)?,
        };
        self.queue(
            MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
            CHANNEL_BIT_SUBMIT_SHARES_ERROR,
            msg,
        )?;
        self.push_event(Event::ShareRejected {
            channel_id,
            sequence_number,
            code,
            cause,
        })
    }

    fn prepare_share(
        &mut self,
        book: &JobBook,
        message_kind: ChannelKind,
        share: &Submit,
    ) -> Result<PreparedShare, &'static str> {
        let (channel_id, sequence_number, job_id, ntime) = (
            share.channel_id,
            share.sequence_number,
            share.job_id,
            share.ntime,
        );
        let (session, rolled, issued_target, monotonic) = {
            let Some(channel) = self.channels.get_mut(&channel_id) else {
                return Err(ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
            };
            if channel.kind != message_kind {
                return Err(ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID);
            }
            let monotonic = channel
                .last_sequence
                .is_none_or(|last| sequence_number > last);
            if monotonic {
                channel.last_sequence = Some(sequence_number);
            }
            let rolled = match message_kind {
                ChannelKind::Standard => channel.rolled.clone(),
                ChannelKind::Extended => share.extranonce.clone().unwrap_or_default(),
            };
            (
                channel.session,
                rolled,
                channel.jobs.get(&job_id).map(|record| record.target),
                monotonic,
            )
        };
        if !monotonic {
            return Err(ERROR_CODE_INVALID_SEQUENCE_NUMBER);
        }
        if self.pending.len() >= self.config.limits.max_pending_acks {
            return Err(ERROR_CODE_POOL_BUSY);
        }
        let target = match issued_target {
            Some(Some(target)) => target,
            Some(None) | None => return Err(ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID),
        };
        let owner_job = JobId::new(job_id);
        if let Some(job) = book.job(owner_job)
            && ntime < job.ntime()
        {
            return Err(ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE);
        }
        Ok(PreparedShare {
            session,
            job: owner_job,
            rolled,
            target,
        })
    }

    fn submit(
        &mut self,
        book: &mut JobBook,
        message_kind: ChannelKind,
        share: &Submit,
    ) -> Result<(), SessionError> {
        let channel_id = share.channel_id;
        let sequence_number = share.sequence_number;
        let prepared = match self.prepare_share(book, message_kind, share) {
            Ok(prepared) => prepared,
            Err(code) => return self.refuse_share(channel_id, sequence_number, code, None),
        };
        let &Submit {
            nonce,
            ntime,
            version,
            ..
        } = share;
        let submission = ShareSubmission {
            session: prepared.session,
            job: prepared.job,
            rolled_extranonce: &prepared.rolled,
            ntime,
            nonce,
            version,
        };
        match book.validate(&submission, &prepared.target) {
            Ok(outcome) => {
                let difficulty = target_difficulty(prepared.target);
                let ticket = ShareTicket(self.next_ticket);
                self.next_ticket = self.next_ticket.wrapping_add(1);
                let event = match outcome {
                    ShareOutcome::Share(accepted) => {
                        self.pending.insert(
                            ticket.0,
                            Pending {
                                channel_id,
                                sequence_number,
                                difficulty,
                                block_hash: None,
                                kind: PendingKind::Share,
                            },
                        );
                        Event::ShareAccepted(ShareEvent {
                            ticket,
                            channel_id,
                            sequence_number,
                            outcome: *accepted,
                        })
                    }
                    ShareOutcome::Block(found) => {
                        self.pending.insert(
                            ticket.0,
                            Pending {
                                channel_id,
                                sequence_number,
                                difficulty,
                                block_hash: Some(*found.share.hash.as_bytes()),
                                kind: PendingKind::Block,
                            },
                        );
                        Event::BlockFound(PendingBlock {
                            ticket,
                            channel_id,
                            sequence_number,
                            found,
                        })
                    }
                };
                self.push_event(event)
            }
            Err(error) => {
                let code = share_error_code(&error);
                self.refuse_share(channel_id, sequence_number, code, Some(error))
            }
        }
    }

    /// The host recorded the share durably: tell the miner it counted.
    ///
    /// Returns `false` when the ticket is unknown or its channel closed
    /// meanwhile (nothing is sent).
    pub fn confirm_share(&mut self, ticket: ShareTicket) -> Result<bool, SessionError> {
        let Some(pending) = self.pending.get(&ticket.0) else {
            return Ok(false);
        };
        if matches!(pending.kind, PendingKind::Block) {
            return Err(SessionError::BlockRequiresSubmission);
        }
        let Some(pending) = self.pending.remove(&ticket.0) else {
            return Ok(false);
        };
        if !self.channels.contains_key(&pending.channel_id) {
            return Ok(false);
        }
        self.queue(
            MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
            CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
            SubmitSharesSuccess {
                channel_id: pending.channel_id,
                last_sequence_number: pending.sequence_number,
                new_submits_accepted_count: 1,
                new_shares_sum: pending.difficulty,
            },
        )?;
        Ok(true)
    }

    /// Records a submitted block and acknowledges its share.
    ///
    /// The caller must record [`BlockSubmission::receipt`] in the ledger
    /// before invoking this method. Only the opaque token produced by
    /// [`PendingBlock::submit`] can pass the ticket and channel checks.
    pub fn confirm_block(&mut self, submission: &BlockSubmission) -> Result<bool, SessionError> {
        let Some(pending) = self.pending.get(&submission.ticket.0) else {
            return Ok(false);
        };
        if !matches!(pending.kind, PendingKind::Block)
            || pending.channel_id != submission.channel_id
            || pending.sequence_number != submission.sequence_number
            || pending.block_hash != Some(submission.block_hash)
        {
            return Ok(false);
        }
        let Some(pending) = self.pending.remove(&submission.ticket.0) else {
            return Ok(false);
        };
        if !self.channels.contains_key(&pending.channel_id) {
            return Ok(false);
        }
        self.queue(
            MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
            CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
            SubmitSharesSuccess {
                channel_id: pending.channel_id,
                last_sequence_number: pending.sequence_number,
                new_submits_accepted_count: 1,
                new_shares_sum: pending.difficulty,
            },
        )?;
        Ok(true)
    }

    /// The host could not record the share: tell the miner it did not count.
    ///
    /// `code` must be printable ASCII (for example [`ERROR_CODE_SHARE_NOT_RECORDED`]).
    pub fn reject_share(
        &mut self,
        ticket: ShareTicket,
        code: &'static str,
    ) -> Result<bool, SessionError> {
        let Some(pending) = self.pending.get(&ticket.0) else {
            return Ok(false);
        };
        if matches!(pending.kind, PendingKind::Block) {
            return Err(SessionError::BlockRequiresSubmission);
        }
        let Some(pending) = self.pending.remove(&ticket.0) else {
            return Ok(false);
        };
        if !self.channels.contains_key(&pending.channel_id) {
            return Ok(false);
        }
        let msg = SubmitSharesError {
            channel_id: pending.channel_id,
            sequence_number: pending.sequence_number,
            error_code: code_str(code)?,
        };
        self.queue(
            MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
            CHANNEL_BIT_SUBMIT_SHARES_ERROR,
            msg,
        )?;
        Ok(true)
    }

    // ---- close, cancel, reconnect ----------------------------------------

    fn refuse_custom_job(&mut self, mut payload: Vec<u8>) -> Result<(), SessionError> {
        let (channel_id, request_id) = {
            let msg: SetCustomMiningJob<'_> =
                decode(MESSAGE_TYPE_SET_CUSTOM_MINING_JOB, &mut payload)?;
            (msg.channel_id, msg.request_id)
        };
        // Work selection is not advertised (SetupConnection refuses
        // REQUIRES_WORK_SELECTION), so a custom job is a client error that the
        // protocol answers with the official code rather than a disconnect.
        let msg = SetCustomMiningJobError {
            channel_id,
            request_id,
            error_code: code_str(ERROR_CODE_SET_CUSTOM_MINING_JOB_JD_NOT_SUPPORTED)?,
        };
        self.queue(
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
            CHANNEL_BIT_SET_CUSTOM_MINING_JOB_ERROR,
            msg,
        )
    }

    /// Channels a close of `id` covers: the channel, or every member for the group.
    fn close_scope(&self, id: u32) -> Vec<u32> {
        if self.group_id == Some(id) {
            self.channels.keys().copied().collect()
        } else if self.channels.contains_key(&id) {
            vec![id]
        } else {
            Vec::new()
        }
    }

    fn remove_channel(
        &mut self,
        book: &mut JobBook,
        channel_id: u32,
        reason: CloseReason,
    ) -> Result<(), SessionError> {
        let Some(channel) = self.channels.remove(&channel_id) else {
            return Ok(());
        };
        book.close_session(channel.session);
        // Cancel: shares of a closed channel are not acknowledged.
        self.pending
            .retain(|_, pending| pending.channel_id != channel_id);
        self.push_event(Event::ChannelClosed { channel_id, reason })
    }

    fn peer_close(&mut self, book: &mut JobBook, mut payload: Vec<u8>) -> Result<(), SessionError> {
        let channel_id = {
            let msg: CloseChannel<'_> = decode(MESSAGE_TYPE_CLOSE_CHANNEL, &mut payload)?;
            msg.channel_id
        };
        for id in self.close_scope(channel_id) {
            self.remove_channel(book, id, CloseReason::Peer)?;
        }
        Ok(())
    }

    /// Host-initiated close of a channel (or of the whole group).
    pub fn close_channel(
        &mut self,
        book: &mut JobBook,
        channel_id: u32,
        reason_code: &str,
    ) -> Result<(), SessionError> {
        let scope = self.close_scope(channel_id);
        if scope.is_empty() {
            return Err(SessionError::UnknownChannel(channel_id));
        }
        let msg = CloseChannel {
            channel_id,
            reason_code: code_str(reason_code)?,
        };
        self.queue(MESSAGE_TYPE_CLOSE_CHANNEL, CHANNEL_BIT_CLOSE_CHANNEL, msg)?;
        for id in scope {
            self.remove_channel(book, id, CloseReason::Host)?;
        }
        Ok(())
    }

    /// Asks the miner to reconnect (`Reconnect`, §3.6.5). An empty host and
    /// port 0 mean "same endpoint". Afterwards new channels are refused with
    /// [`ERROR_CODE_RECONNECT_REQUESTED`]; the host closes the connection when
    /// the miner leaves or after its own grace period.
    pub fn request_reconnect(&mut self, new_host: &str, new_port: u16) -> Result<(), SessionError> {
        let msg = Reconnect {
            new_host: code_str(new_host)?,
            new_port,
        };
        self.queue(MESSAGE_TYPE_RECONNECT, CHANNEL_BIT_RECONNECT, msg)?;
        self.reconnecting = true;
        Ok(())
    }

    /// Releases every owner session this connection holds. The host MUST call
    /// this when the connection ends, whatever the reason: the owner's session
    /// table is bounded and a leaked session shrinks it. Idempotent.
    pub fn release(&mut self, book: &mut JobBook) {
        for (_, channel) in std::mem::take(&mut self.channels) {
            book.close_session(channel.session);
        }
        self.pending.clear();
        self.phase = Phase::Closing;
    }
}

struct PreparedShare {
    session: SessionId,
    job: JobId,
    rolled: Vec<u8>,
    target: ShareTarget,
}

struct Submit {
    channel_id: u32,
    sequence_number: u32,
    job_id: u32,
    nonce: u32,
    ntime: u32,
    version: u32,
    extranonce: Option<Vec<u8>>,
}

fn record_job(channel: &mut Channel, job_id: u32, target: Option<ShareTarget>, max: usize) {
    channel.jobs.insert(job_id, ChannelJob { target });
    while channel.jobs.len() > max {
        channel.jobs.pop_first();
    }
}

fn activate_job(channel: &mut Channel, job_id: u32) {
    let target = channel.target;
    if let Some(record) = channel.jobs.get_mut(&job_id) {
        record.target = Some(target);
    }
}
