//! Job projection, extranonce allocation, and the single share predicate.
//!
//! One [`JobBook`] owns every fact a Stratum V1 or V2 adapter needs about
//! work it handed to miners: the coinbase split around the extranonce, the
//! merkle branch, the header template, bounded job retention, bounded session
//! identity, stale state, and duplicate state. The template itself is built by
//! `MiningControl`; a block is validated by `MiningControl`. Money, keys, and
//! difficulty policy are inputs, never state, here.
//!
//! Invariants:
//! - `coinbase_prefix || session || rolled || coinbase_suffix` is the exact
//!   non-witness (txid) serialization of the coinbase the block will carry.
//! - A job never grows its candidate's coinbase beyond the declared
//!   [`CoinbaseBudget`]: scriptSig growth stays under the 100-byte consensus
//!   limit, extra outputs stay inside the budget's size and sigop allowance,
//!   and `Candidate::admits` (the owner's rule) passes for the budget.
//! - A stale job is never revived.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use bitcoin_rs_chain::{ChainWork, compact_is_met_by};
use bitcoin_rs_consensus::transaction_sigop_cost;
use bitcoin_rs_mining::{
    BlockTemplate, BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult,
    BlockValidationResult, Candidate, CoinbaseBudget, MiningControl, MiningControlError,
    MiningError,
};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, Script, Tx, TxOut, Txid, Witness,
    encode::{consensus_bytes, double_sha256},
    varint,
};
use bitcoin_rs_script::VerifyFlags;
use compact_str::CompactString;
use ruint::Uint;
use thiserror::Error;

/// Consensus limit on a coinbase scriptSig length (`bad-cb-length`).
pub const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;
/// BIP320 general-purpose version-rolling bits.
pub const BIP320_VERSION_MASK: u32 = 0x1fff_e000;
/// Core's `MAX_FUTURE_BLOCK_TIME`: the largest forward `ntime` window a job may grant.
pub const MAX_NTIME_FORWARD_SECS: u32 = 7_200;

/// Smallest scriptSig the node builds (`bad-cb-length` lower bound).
const MIN_COINBASE_SCRIPT_SIG_LEN: usize = 2;
/// Offset of the scriptSig length byte in a one-input coinbase's txid serialization:
/// version (4) + input count (1) + outpoint (36).
const SCRIPT_SIG_LEN_OFFSET: usize = 41;
/// Offset of the first scriptSig byte in the same serialization.
const SCRIPT_SIG_OFFSET: usize = 42;

/// Wire-neutral job identity, unique and increasing within one [`JobBook`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobId(u32);

impl JobId {
    /// Wraps a raw wire value.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Session identity, unique within one [`JobBook`] lifetime.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(u32);

impl SessionId {
    /// Wraps a raw wire value.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw wire value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Split of the coinbase extranonce between the pool and the miner.
///
/// `session_len` bytes are assigned by the pool and unique per open session
/// (SV1 `extranonce1`, SV2 extended-channel prefix). `rolled_len` bytes are
/// chosen by the miner (SV1 `extranonce2`, SV2 remaining extranonce).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExtranonceLayout {
    session_len: u8,
    rolled_len: u8,
}

impl ExtranonceLayout {
    /// Builds a layout of `session_len` pool bytes and `rolled_len` miner bytes.
    #[must_use]
    pub const fn new(session_len: u8, rolled_len: u8) -> Self {
        Self {
            session_len,
            rolled_len,
        }
    }

    /// Pool-assigned bytes.
    #[must_use]
    pub fn session_len(self) -> usize {
        usize::from(self.session_len)
    }

    /// Miner-chosen bytes.
    #[must_use]
    pub fn rolled_len(self) -> usize {
        usize::from(self.rolled_len)
    }

    /// Total extranonce bytes inside the coinbase scriptSig.
    #[must_use]
    pub fn total_len(self) -> usize {
        self.session_len() + self.rolled_len()
    }

    /// Number of distinct pool prefixes this layout can name.
    fn session_capacity(self) -> u64 {
        match self.session_len {
            0 => 1,
            len @ 1..=7 => 1_u64 << (8 * u32::from(len)),
            _ => u64::MAX,
        }
    }
}

/// Extranonce bytes of one share: pool prefix plus miner-chosen bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extranonce<'a> {
    /// Pool-assigned prefix; length `ExtranonceLayout::session_len`.
    pub session: &'a [u8],
    /// Miner-chosen bytes; length `ExtranonceLayout::rolled_len`.
    pub rolled: &'a [u8],
}

/// One open miner session and its unique extranonce prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    id: SessionId,
    prefix: Vec<u8>,
    slot: u64,
}

impl Session {
    /// Session identity.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Pool-assigned extranonce prefix, `ExtranonceLayout::session_len` bytes.
    #[must_use]
    pub fn extranonce_prefix(&self) -> &[u8] {
        &self.prefix
    }
}

/// Bounded session table: unique prefixes, oldest-freed prefix reused first.
#[derive(Debug)]
struct SessionTable {
    layout: ExtranonceLayout,
    capacity: usize,
    next_slot: u64,
    free: VecDeque<u64>,
    next_id: u32,
    live: HashMap<SessionId, Session>,
}

impl SessionTable {
    fn new(layout: ExtranonceLayout, capacity: usize) -> Self {
        Self {
            layout,
            capacity,
            next_slot: 0,
            free: VecDeque::new(),
            next_id: 1,
            live: HashMap::new(),
        }
    }

    fn open(&mut self) -> Result<Session, JobError> {
        if self.live.len() >= self.capacity {
            return Err(JobError::SessionCapacity {
                capacity: self.capacity,
            });
        }
        let following = self
            .next_id
            .checked_add(1)
            .ok_or(JobError::SessionIdExhausted)?;
        let slot = if let Some(slot) = self.free.pop_front() {
            slot
        } else {
            let slot = self.next_slot;
            self.next_slot = slot.saturating_add(1);
            slot
        };
        let session = Session {
            id: SessionId(self.next_id),
            prefix: slot_prefix(slot, self.layout.session_len()),
            slot,
        };
        self.next_id = following;
        self.live.insert(session.id, session.clone());
        Ok(session)
    }

    fn close(&mut self, id: SessionId) -> bool {
        match self.live.remove(&id) {
            Some(session) => {
                self.free.push_back(session.slot);
                true
            }
            None => false,
        }
    }

    fn get(&self, id: SessionId) -> Option<&Session> {
        self.live.get(&id)
    }
}

/// Encodes `slot` little-endian into exactly `len` bytes, zero padded.
fn slot_prefix(slot: u64, len: usize) -> Vec<u8> {
    let le = slot.to_le_bytes();
    let mut prefix = vec![0_u8; len];
    let shared = len.min(le.len());
    prefix[..shared].copy_from_slice(&le[..shared]);
    prefix
}

/// Setup and projection failures. Nothing here is a share verdict.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum JobError {
    /// A configuration field is unusable.
    #[error("invalid job book configuration: {0}")]
    InvalidConfig(&'static str),
    /// The owner's rule: the candidate cannot admit the declared coinbase budget.
    #[error("candidate cannot admit the declared coinbase budget: {0}")]
    Budget(MiningError),
    /// The candidate coinbase is not a single-input coinbase with an output.
    #[error("candidate coinbase is not a one-input coinbase with at least one output")]
    CoinbaseShape,
    /// Tag plus extranonce do not fit under the scriptSig consensus limit.
    #[error(
        "coinbase tag and extranonce need {needed} scriptSig bytes but only {room} remain under the consensus limit"
    )]
    ExtranonceExceedsScriptSig {
        /// Bytes available after the node's height prefix.
        room: usize,
        /// Bytes the tag and extranonce need.
        needed: usize,
    },
    /// Extra outputs serialize to more bytes than the budget declares.
    #[error("extra coinbase outputs serialize to {used} bytes, budget allows {budget}")]
    ExtraOutputsSize {
        /// Serialized bytes of the extra outputs.
        used: u64,
        /// Declared `additional_size`.
        budget: u32,
    },
    /// Extra outputs cost more sigops than the budget declares.
    #[error("extra coinbase outputs cost {used} sigops, budget allows {budget}")]
    ExtraOutputsSigops {
        /// BIP141 sigop cost of the extra outputs.
        used: u32,
        /// Declared `additional_sigops`.
        budget: u16,
    },
    /// Extra outputs pay more than the node's coinbase output holds.
    #[error(
        "extra coinbase outputs pay {extra} sat but the node payout output holds {available} sat"
    )]
    ExtraOutputsValue {
        /// Sum of the extra output values.
        extra: u64,
        /// Value of the node payout output.
        available: u64,
    },
    /// The coinbase split failed its txid round-trip.
    #[error("coinbase split does not reproduce the coinbase txid serialization")]
    CoinbaseSplit,
    /// Every job id has been issued.
    #[error("job ids are exhausted")]
    JobIdExhausted,
    /// Every session id has been issued.
    #[error("session ids are exhausted")]
    SessionIdExhausted,
    /// All session slots are in use.
    #[error("all {capacity} session slots are in use")]
    SessionCapacity {
        /// Configured session capacity.
        capacity: usize,
    },
    /// A share target or difficulty of zero names no work.
    #[error("share target and pool difficulty must be nonzero")]
    ZeroTarget,
    /// Pool difficulty text is not a bounded plain decimal.
    #[error("pool difficulty is not a plain decimal of at most 19 digits")]
    InvalidDifficulty,
}

/// Why a job no longer accepts shares.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StaleReason {
    /// A job on a different parent was installed after it.
    PreviousBlockChanged,
    /// [`JobBook::invalidate_active`] retired it.
    Invalidated,
    /// Evicted by job retention; only the id is remembered.
    Retired,
}

/// Share verdicts that reject the share.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ShareError {
    /// The session is not open.
    #[error("unknown session {0:?}")]
    UnknownSession(SessionId),
    /// The job id was never issued.
    #[error("unknown job {0:?}")]
    UnknownJob(JobId),
    /// The job exists or existed but accepts no more shares.
    #[error("stale share for job {job:?}: {reason:?}")]
    Stale {
        /// Job the share named.
        job: JobId,
        /// Why it is stale.
        reason: StaleReason,
    },
    /// The session prefix does not match the layout.
    #[error("session extranonce prefix is {actual} bytes, layout needs {expected}")]
    SessionPrefixLength {
        /// Layout `session_len`.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// The miner-chosen extranonce length does not match the layout.
    #[error("rolled extranonce is {actual} bytes, layout needs {expected}")]
    ExtranonceLength {
        /// Layout `rolled_len`.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// The version changes bits outside the job's rolling mask.
    #[error(
        "version {version:#010x} differs from job version {job_version:#010x} outside mask {mask:#010x}"
    )]
    VersionOutsideMask {
        /// Submitted full version.
        version: u32,
        /// Job version.
        job_version: u32,
        /// Job rolling mask.
        mask: u32,
    },
    /// `ntime` is below the job's minimum legal timestamp.
    #[error("ntime {ntime} is before the job minimum {min_ntime}")]
    TimeTooEarly {
        /// Submitted time.
        ntime: u32,
        /// Job minimum.
        min_ntime: u32,
    },
    /// `ntime` is beyond the job's forward window.
    #[error("ntime {ntime} is after the job maximum {max_ntime}")]
    TimeTooLate {
        /// Submitted time.
        ntime: u32,
        /// Job maximum.
        max_ntime: u32,
    },
    /// The same header was already accepted.
    #[error("duplicate share {hash}, first accepted under job {first_job:?}")]
    Duplicate {
        /// Header hash.
        hash: BlockHash,
        /// Job it was first accepted under.
        first_job: JobId,
    },
    /// The hash meets neither the network target nor the share target.
    #[error("share hash {hash} does not meet the share target")]
    BelowTarget {
        /// Header hash.
        hash: BlockHash,
    },
    /// The job holds its maximum number of accepted shares.
    #[error("job {job:?} already holds {capacity} accepted shares")]
    JobShareCapacity {
        /// Job the share named.
        job: JobId,
        /// Configured per-job capacity.
        capacity: usize,
    },
}

/// A nonzero 256-bit share target. A hash meets it when it is less than or equal.
///
/// The value is the numeric hash order Bitcoin uses: `to_le_bytes` is the
/// internal byte order of [`Hash256`], `to_be_bytes` the display order and
/// the SV1 / SV2 `U256` target byte order after the adapter's own swap.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShareTarget(ChainWork);

impl ShareTarget {
    /// Builds a target from little-endian bytes; zero is rejected.
    pub fn from_le_bytes(bytes: [u8; 32]) -> Result<Self, JobError> {
        let value = ChainWork::from_le_bytes(bytes);
        if value == ChainWork::ZERO {
            return Err(JobError::ZeroTarget);
        }
        Ok(Self(value))
    }

    /// Builds a target from big-endian bytes; zero is rejected.
    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Result<Self, JobError> {
        bytes.reverse();
        Self::from_le_bytes(bytes)
    }

    /// Builds the target of integer pool difficulty `difficulty`; see
    /// [`Self::from_pool_difficulty_ratio`].
    pub fn from_pool_difficulty(difficulty: u64) -> Result<Self, JobError> {
        Self::from_pool_difficulty_ratio(difficulty, 1)
    }

    /// Builds the target of pool difficulty `numerator / denominator` exactly:
    /// `floor(0xffff * 2^208 * denominator / numerator)`. Difficulty 1 is
    /// compact `0x1d00ffff`. A difficulty so small that the target exceeds
    /// `2^256 - 1` saturates at `2^256 - 1`, which every hash meets.
    ///
    /// This is the one owner of difficulty-to-target arithmetic. Which
    /// difficulty a session gets (vardiff) stays the adapter's policy.
    pub fn from_pool_difficulty_ratio(numerator: u64, denominator: u64) -> Result<Self, JobError> {
        if numerator == 0 || denominator == 0 {
            return Err(JobError::ZeroTarget);
        }
        let difficulty_one = Uint::<512, 8>::from(0xffff_u32) << 208_usize;
        let scaled = difficulty_one * Uint::<512, 8>::from(denominator);
        let quotient = scaled / Uint::<512, 8>::from(numerator);
        let wide: [u8; 64] = quotient.to_le_bytes();
        let (low, high) = wide.split_at(32);
        let mut bytes = [0xff_u8; 32];
        if high.iter().all(|byte| *byte == 0) {
            bytes.copy_from_slice(low);
        }
        Self::from_le_bytes(bytes)
    }

    /// Builds the target of a pool difficulty written as a plain decimal such
    /// as `"16384"` or `"0.001"` (SV1 `mining.set_difficulty`), without floats.
    ///
    /// Accepted: ASCII digits, an optional `.` followed by digits, at most 19
    /// digits in total. Exponents, signs, and a missing integer part are
    /// rejected with [`JobError::InvalidDifficulty`]; zero with
    /// [`JobError::ZeroTarget`].
    pub fn from_pool_difficulty_decimal(text: &str) -> Result<Self, JobError> {
        let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
        let well_formed = !whole.is_empty()
            && whole.len() + fraction.len() <= 19
            && whole
                .bytes()
                .chain(fraction.bytes())
                .all(|byte| byte.is_ascii_digit());
        if !well_formed {
            return Err(JobError::InvalidDifficulty);
        }
        let numerator = whole
            .bytes()
            .chain(fraction.bytes())
            .fold(0_u64, |value, byte| value * 10 + u64::from(byte - b'0'));
        let scale = u32::try_from(fraction.len()).map_err(|_| JobError::InvalidDifficulty)?;
        let denominator = 10_u64
            .checked_pow(scale)
            .ok_or(JobError::InvalidDifficulty)?;
        Self::from_pool_difficulty_ratio(numerator, denominator)
    }

    /// Little-endian bytes (internal [`Hash256`] order).
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0.to_le_bytes()
    }

    /// Big-endian bytes (display order).
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }

    /// Whether `hash`, read as a little-endian 256-bit integer, is at most the target.
    #[must_use]
    pub fn meets(self, hash: Hash256) -> bool {
        ChainWork::from_le_bytes(hash.to_le_bytes()) <= self.0
    }

    /// Expected hashes behind one share at this target: `floor(2^256 / (target + 1))`.
    #[must_use]
    pub fn work(self) -> ShareWork {
        let one = ChainWork::from(1_u32);
        match self.0.checked_add(one) {
            // target = 2^256 - 1: every hash meets it, one hash per share.
            None => ShareWork(one),
            Some(denominator) => ShareWork((!self.0) / denominator + one),
        }
    }
}

/// Exact integer work of a share target, the unit PPLNS-style accounting sums.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShareWork(ChainWork);

impl ShareWork {
    /// Little-endian bytes of the 256-bit work value.
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0.to_le_bytes()
    }

    /// Big-endian bytes of the 256-bit work value.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }

    /// The work as `u128`, or `None` when it needs more than 128 bits.
    #[must_use]
    pub fn as_u128(self) -> Option<u128> {
        u128::try_from(&self.0).ok()
    }

    /// Sum of two work values, or `None` on 256-bit overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }
}

/// One share as submitted, with every field explicit.
#[derive(Clone, Copy, Debug)]
pub struct ShareSubmission<'a> {
    /// Submitting session.
    pub session: SessionId,
    /// Job the miner worked on.
    pub job: JobId,
    /// Miner-chosen extranonce bytes.
    pub rolled_extranonce: &'a [u8],
    /// Header time.
    pub ntime: u32,
    /// Header nonce.
    pub nonce: u32,
    /// Complete header version as hashed (rolled bits applied).
    pub version: u32,
}

/// What an accepted share is worth to the pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareClass {
    /// Meets the share target only.
    Share,
    /// Meets the network target: a block candidate.
    Block,
}

/// An accepted share: identity and work, with no financial meaning attached.
#[derive(Clone, Debug)]
pub struct AcceptedShare {
    /// Submitting session.
    pub session: SessionId,
    /// Job the share belongs to.
    pub job: JobId,
    /// Header hash. Unique per accepted share: the idempotency key a durable
    /// ledger must index uniquely.
    pub hash: BlockHash,
    /// The exact header hashed.
    pub header: Header,
    /// Candidate block height.
    pub height: u32,
    /// Parent block hash of the job.
    pub previous_block_hash: BlockHash,
    /// Session prefix followed by the miner-chosen bytes.
    pub extranonce: Vec<u8>,
    /// Share target the share was judged against.
    pub target: ShareTarget,
    /// Work of `target`, not of the hash found.
    pub work: ShareWork,
    /// Share or block candidate.
    pub class: ShareClass,
}

/// A share that meets the network target, with the full block to submit.
#[derive(Clone, Debug)]
pub struct FoundBlock {
    /// The accepted share that found it; `share.class` is [`ShareClass::Block`].
    pub share: AcceptedShare,
    /// The complete block: reassembled coinbase, then the candidate's transactions.
    pub block: Block,
    /// Exact consensus serialization of `block`.
    pub raw: Vec<u8>,
    /// Txid of the block's coinbase.
    pub coinbase_txid: Txid,
    /// Total coinbase output value (subsidy plus fees).
    pub coinbase_value: u64,
}

impl FoundBlock {
    /// Hands the block to the node's authoritative submit path.
    ///
    /// `&self` so an `Err` leaves the block available for a retry. An `Err`
    /// or an [`BlockStatus::Undetermined`] receipt means the chain outcome is
    /// unknown: the caller must not infer acceptance or rejection.
    pub fn submit(&self, control: &dyn MiningControl) -> Result<BlockReceipt, MiningControlError> {
        let result = control.submit_block_with_bytes(self.block.clone(), self.raw.clone())?;
        Ok(BlockReceipt {
            hash: self.share.hash,
            height: self.share.height,
            previous_block_hash: self.share.previous_block_hash,
            coinbase_txid: self.coinbase_txid,
            coinbase_value: self.coinbase_value,
            session: self.share.session,
            job: self.share.job,
            result,
        })
    }
}

/// Chain outcome class of a submitted block, from the node's verdict alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockStatus {
    /// Accepted, or its body was already connected.
    Applied,
    /// Rejected, or a duplicate of a known-invalid block.
    Rejected,
    /// The node could not conclude; reconcile from chain observation.
    Undetermined,
}

/// The node's answer to one block submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockReceipt {
    /// Block hash.
    pub hash: BlockHash,
    /// Block height.
    pub height: u32,
    /// Parent block hash.
    pub previous_block_hash: BlockHash,
    /// Coinbase txid.
    pub coinbase_txid: Txid,
    /// Total coinbase output value.
    pub coinbase_value: u64,
    /// Session that found the block.
    pub session: SessionId,
    /// Job the block was built from.
    pub job: JobId,
    /// The node's BIP22 verdict.
    pub result: BlockValidationResult,
}

impl BlockReceipt {
    /// Maps the node verdict onto the three outcomes a ledger can act on.
    #[must_use]
    pub fn status(&self) -> BlockStatus {
        match &self.result {
            BlockValidationResult::Accepted | BlockValidationResult::Duplicate => {
                BlockStatus::Applied
            }
            BlockValidationResult::DuplicateInvalid | BlockValidationResult::Rejected(_) => {
                BlockStatus::Rejected
            }
            BlockValidationResult::Inconclusive | BlockValidationResult::DuplicateInconclusive => {
                BlockStatus::Undetermined
            }
        }
    }
}

/// Result of a share that passed every check.
#[derive(Clone, Debug)]
pub enum ShareOutcome {
    /// Meets the share target only.
    Share(Box<AcceptedShare>),
    /// Meets the network target.
    Block(Box<FoundBlock>),
}

impl ShareOutcome {
    /// The accepted share, whichever class it is.
    #[must_use]
    pub fn share(&self) -> &AcceptedShare {
        match self {
            Self::Share(share) => share,
            Self::Block(found) => &found.share,
        }
    }
}

/// One immutable job: a candidate projected onto the Stratum work shape.
#[derive(Debug)]
pub struct Job {
    id: JobId,
    candidate: Arc<Candidate>,
    extranonce: ExtranonceLayout,
    version_mask: u32,
    version: u32,
    ntime: u32,
    max_ntime: u32,
    script_sig_head: Vec<u8>,
    coinbase_template: Tx,
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    merkle_branch: Vec<Hash256>,
    extra_outputs: Vec<TxOut>,
}

fn validate_extra_outputs(
    extra_outputs: Vec<TxOut>,
    available: u64,
    budget: CoinbaseBudget,
) -> Result<(Vec<TxOut>, u64), JobError> {
    let mut extra_size = 0_u64;
    let mut extra_value = 0_u64;
    for output in &extra_outputs {
        let script_len = u64::try_from(output.script_pubkey.len()).unwrap_or(u64::MAX);
        let prefix_len = u64::try_from(varint::encoded_len(script_len)).unwrap_or(u64::MAX);
        extra_size = extra_size
            .saturating_add(8)
            .saturating_add(prefix_len)
            .saturating_add(script_len);
        extra_value = extra_value.saturating_add(output.value.to_sat());
    }
    if extra_size > u64::from(budget.additional_size) {
        return Err(JobError::ExtraOutputsSize {
            used: extra_size,
            budget: budget.additional_size,
        });
    }
    let probe = Tx {
        outputs: extra_outputs,
        ..Tx::default()
    };
    let extra_sigops = transaction_sigop_cost(&probe, &[], VerifyFlags::NONE);
    if extra_sigops > u32::from(budget.additional_sigops) {
        return Err(JobError::ExtraOutputsSigops {
            used: extra_sigops,
            budget: budget.additional_sigops,
        });
    }
    if extra_value > available {
        return Err(JobError::ExtraOutputsValue {
            extra: extra_value,
            available,
        });
    }
    Ok((probe.outputs, extra_value))
}

impl Job {
    fn project(
        id: JobId,
        candidate: Arc<Candidate>,
        config: &JobBookConfig,
        extra_outputs: Vec<TxOut>,
    ) -> Result<Self, JobError> {
        candidate.admits(config.budget).map_err(JobError::Budget)?;

        let (Some(input), Some(payout)) = (
            candidate.coinbase.inputs.first(),
            candidate.coinbase.outputs.first(),
        ) else {
            return Err(JobError::CoinbaseShape);
        };
        if !candidate.coinbase.is_coinbase() {
            return Err(JobError::CoinbaseShape);
        }
        let available = payout.value.to_sat();
        let base = input.script_sig.as_bytes();
        let total = config.extranonce.total_len();
        let room = MAX_COINBASE_SCRIPT_SIG_LEN.saturating_sub(base.len());
        let needed = config.coinbase_tag.len().saturating_add(total);
        if needed > room {
            return Err(JobError::ExtranonceExceedsScriptSig { room, needed });
        }

        let (extra_outputs, extra_value) =
            validate_extra_outputs(extra_outputs, available, config.budget)?;

        let mut head = Vec::with_capacity(base.len() + config.coinbase_tag.len());
        head.extend_from_slice(base);
        head.extend_from_slice(&config.coinbase_tag);
        let mut placeholder = head.clone();
        placeholder.resize(head.len() + total, 0);

        let mut template = candidate.coinbase.clone();
        if let Some(first_input) = template.inputs.first_mut() {
            first_input.script_sig = Script::from_bytes(placeholder);
        }
        let mut outputs = Vec::with_capacity(template.outputs.len() + extra_outputs.len());
        let mut original = std::mem::take(&mut template.outputs).into_iter();
        if let Some(mut first) = original.next() {
            first.value = Amount::from_sat(available - extra_value);
            outputs.push(first);
        }
        outputs.extend(extra_outputs.iter().cloned());
        outputs.extend(original);
        template.outputs = outputs;

        let mut legacy = template.clone();
        for legacy_input in &mut legacy.inputs {
            legacy_input.witness = Witness::new();
        }
        let bytes = consensus_bytes(&legacy);
        let start = SCRIPT_SIG_OFFSET + head.len();
        let end = start + total;
        let declared = u8::try_from(head.len() + total).map_err(|_| JobError::CoinbaseSplit)?;
        let round_trips = bytes.get(4) == Some(&1)
            && bytes.get(SCRIPT_SIG_LEN_OFFSET) == Some(&declared)
            && end <= bytes.len()
            && double_sha256(&bytes) == Hash256::from(template.txid());
        if !round_trips {
            return Err(JobError::CoinbaseSplit);
        }
        let coinbase_prefix = bytes[..start].to_vec();
        let coinbase_suffix = bytes[end..].to_vec();

        let txids: Vec<Txid> = candidate
            .transactions
            .iter()
            .map(|entry| entry.txid)
            .collect();
        let merkle_branch = coinbase_merkle_branch(&txids);
        let ntime = candidate.current_time.max(candidate.min_time);

        Ok(Self {
            id,
            extranonce: config.extranonce,
            version_mask: config.version_mask,
            version: u32::from_le_bytes(candidate.version.to_le_bytes()),
            ntime,
            max_ntime: ntime.saturating_add(config.ntime_forward_secs),
            script_sig_head: head,
            coinbase_template: template,
            coinbase_prefix,
            coinbase_suffix,
            merkle_branch,
            extra_outputs,
            candidate,
        })
    }

    /// Job identity.
    #[must_use]
    pub const fn id(&self) -> JobId {
        self.id
    }

    /// The immutable candidate this job projects.
    #[must_use]
    pub fn candidate(&self) -> &Arc<Candidate> {
        &self.candidate
    }

    /// Candidate block height.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.candidate.height
    }

    /// Parent block hash (internal byte order).
    #[must_use]
    pub fn previous_block_hash(&self) -> BlockHash {
        BlockHash::from(self.candidate.previous_block_hash)
    }

    /// Header version as the unsigned wire value.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Network compact target bits.
    #[must_use]
    pub fn bits(&self) -> CompactTarget {
        self.candidate.bits
    }

    /// Header time the job was issued with.
    #[must_use]
    pub const fn ntime(&self) -> u32 {
        self.ntime
    }

    /// Smallest legal `ntime` (`Candidate::min_time`).
    #[must_use]
    pub fn min_ntime(&self) -> u32 {
        self.candidate.min_time
    }

    /// Largest `ntime` the job accepts.
    #[must_use]
    pub const fn max_ntime(&self) -> u32 {
        self.max_ntime
    }

    /// Version bits a miner may roll.
    #[must_use]
    pub const fn version_mask(&self) -> u32 {
        self.version_mask
    }

    /// Extranonce split of this job.
    #[must_use]
    pub const fn extranonce_layout(&self) -> ExtranonceLayout {
        self.extranonce
    }

    /// Coinbase txid serialization up to the extranonce (SV1 `coinb1`).
    #[must_use]
    pub fn coinbase_prefix(&self) -> &[u8] {
        &self.coinbase_prefix
    }

    /// Coinbase txid serialization after the extranonce (SV1 `coinb2`).
    #[must_use]
    pub fn coinbase_suffix(&self) -> &[u8] {
        &self.coinbase_suffix
    }

    /// Merkle branch of the coinbase path, internal byte order, leaf level first.
    #[must_use]
    pub fn merkle_branch(&self) -> &[Hash256] {
        &self.merkle_branch
    }

    /// Total coinbase output value (subsidy plus fees).
    #[must_use]
    pub fn coinbase_value(&self) -> u64 {
        self.candidate.coinbase_value
    }

    /// Pool outputs this job inserted into the coinbase.
    #[must_use]
    pub fn extra_outputs(&self) -> &[TxOut] {
        &self.extra_outputs
    }

    /// Maps SV1 `version_bits` onto the full header version (BIP310): rolled
    /// bits must lie inside the job mask.
    pub fn version_from_rolled_bits(&self, rolled: u32) -> Result<u32, ShareError> {
        let version = (self.version & !self.version_mask) | rolled;
        if rolled & !self.version_mask != 0 {
            return Err(ShareError::VersionOutsideMask {
                version,
                job_version: self.version,
                mask: self.version_mask,
            });
        }
        Ok(version)
    }

    /// Txid of the coinbase carrying `extranonce`.
    pub fn coinbase_txid(&self, extranonce: Extranonce<'_>) -> Result<Txid, ShareError> {
        let mut scratch = Vec::new();
        self.coinbase_hash_with(extranonce, &mut scratch)
            .map(Txid::from)
    }

    /// Header merkle root for the coinbase carrying `extranonce`.
    pub fn merkle_root(&self, extranonce: Extranonce<'_>) -> Result<Hash256, ShareError> {
        let mut scratch = Vec::new();
        self.merkle_root_with(extranonce, &mut scratch)
    }

    /// The header a miner hashes for these fields. No window checks: this is a
    /// projection, [`JobBook::validate`] is the predicate.
    pub fn header(
        &self,
        extranonce: Extranonce<'_>,
        ntime: u32,
        version: u32,
        nonce: u32,
    ) -> Result<Header, ShareError> {
        let root = self.merkle_root(extranonce)?;
        Ok(self.header_from(root, ntime, version, nonce))
    }

    fn header_from(&self, merkle_root: Hash256, ntime: u32, version: u32, nonce: u32) -> Header {
        Header {
            version: i32::from_le_bytes(version.to_le_bytes()),
            prev_blockhash: BlockHash::from(self.candidate.previous_block_hash),
            merkle_root,
            time: ntime,
            bits: self.candidate.bits,
            nonce,
        }
    }

    fn check_extranonce(&self, extranonce: Extranonce<'_>) -> Result<(), ShareError> {
        if extranonce.session.len() != self.extranonce.session_len() {
            return Err(ShareError::SessionPrefixLength {
                expected: self.extranonce.session_len(),
                actual: extranonce.session.len(),
            });
        }
        if extranonce.rolled.len() != self.extranonce.rolled_len() {
            return Err(ShareError::ExtranonceLength {
                expected: self.extranonce.rolled_len(),
                actual: extranonce.rolled.len(),
            });
        }
        Ok(())
    }

    fn coinbase_hash_with(
        &self,
        extranonce: Extranonce<'_>,
        scratch: &mut Vec<u8>,
    ) -> Result<Hash256, ShareError> {
        self.check_extranonce(extranonce)?;
        scratch.clear();
        scratch.extend_from_slice(&self.coinbase_prefix);
        scratch.extend_from_slice(extranonce.session);
        scratch.extend_from_slice(extranonce.rolled);
        scratch.extend_from_slice(&self.coinbase_suffix);
        Ok(double_sha256(scratch.as_slice()))
    }

    fn merkle_root_with(
        &self,
        extranonce: Extranonce<'_>,
        scratch: &mut Vec<u8>,
    ) -> Result<Hash256, ShareError> {
        let mut node = self.coinbase_hash_with(extranonce, scratch)?;
        let mut pair = [0_u8; 64];
        for sibling in &self.merkle_branch {
            pair[..32].copy_from_slice(node.as_byte_array());
            pair[32..].copy_from_slice(sibling.as_byte_array());
            node = double_sha256(&pair);
        }
        Ok(node)
    }

    /// Builds the complete block for a share that met the network target.
    fn found_block(&self, share: AcceptedShare, extranonce: Extranonce<'_>) -> FoundBlock {
        let mut coinbase = self.coinbase_template.clone();
        let mut script =
            Vec::with_capacity(self.script_sig_head.len() + self.extranonce.total_len());
        script.extend_from_slice(&self.script_sig_head);
        script.extend_from_slice(extranonce.session);
        script.extend_from_slice(extranonce.rolled);
        if let Some(input) = coinbase.inputs.first_mut() {
            input.script_sig = Script::from_bytes(script);
        }
        let coinbase_txid = coinbase.txid();
        let mut txs = Vec::with_capacity(self.candidate.transactions.len() + 1);
        txs.push(coinbase);
        txs.extend(
            self.candidate
                .transactions
                .iter()
                .map(|entry| Tx::clone(&entry.tx)),
        );
        let block = Block {
            header: share.header,
            txs,
        };
        let raw = consensus_bytes(&block);
        FoundBlock {
            share,
            block,
            raw,
            coinbase_txid,
            coinbase_value: self.candidate.coinbase_value,
        }
    }
}

/// Merkle branch of the coinbase path: the sibling hash at every tree level,
/// leaf level first. `txids` are the non-coinbase transactions in block order.
fn coinbase_merkle_branch(txids: &[Txid]) -> Vec<Hash256> {
    let mut rest: Vec<Hash256> = txids.iter().map(|txid| Hash256::from(*txid)).collect();
    let mut branch = Vec::new();
    let mut pair = [0_u8; 64];
    while let Some(&sibling) = rest.first() {
        branch.push(sibling);
        let mut tail: Vec<Hash256> = rest[1..].to_vec();
        if tail.len() % 2 == 1
            && let Some(&last) = tail.last()
        {
            tail.push(last);
        }
        rest = tail
            .as_chunks::<2>()
            .0
            .iter()
            .map(|nodes| {
                pair[..32].copy_from_slice(nodes[0].as_byte_array());
                pair[32..].copy_from_slice(nodes[1].as_byte_array());
                double_sha256(&pair)
            })
            .collect();
    }
    branch
}

/// Bounds and rules shared by every job and session of one [`JobBook`].
#[derive(Clone, Debug)]
pub struct JobBookConfig {
    /// Coinbase growth the pool declares to the template owner. Pass the same
    /// value to [`fetch_template`].
    pub budget: CoinbaseBudget,
    /// Extranonce split.
    pub extranonce: ExtranonceLayout,
    /// Static pool bytes placed after the node's height prefix, before the extranonce.
    pub coinbase_tag: Vec<u8>,
    /// Version bits miners may roll; a subset of [`BIP320_VERSION_MASK`], zero for none.
    pub version_mask: u32,
    /// Seconds past the job time a share's `ntime` may roll; at most [`MAX_NTIME_FORWARD_SECS`].
    pub ntime_forward_secs: u32,
    /// Jobs retained, active or stale.
    pub max_jobs: usize,
    /// Sessions open at once.
    pub max_sessions: usize,
    /// Accepted shares remembered per job for duplicate detection.
    pub max_shares_per_job: usize,
}

impl JobBookConfig {
    fn validate(&self) -> Result<(), JobError> {
        if self.max_jobs == 0 {
            return Err(JobError::InvalidConfig("max_jobs must be at least 1"));
        }
        if self.max_sessions == 0 {
            return Err(JobError::InvalidConfig("max_sessions must be at least 1"));
        }
        if self.max_shares_per_job == 0 {
            return Err(JobError::InvalidConfig(
                "max_shares_per_job must be at least 1",
            ));
        }
        let capacity = self.extranonce.session_capacity();
        if u64::try_from(self.max_sessions).unwrap_or(u64::MAX) > capacity {
            return Err(JobError::InvalidConfig(
                "max_sessions exceeds the prefixes session_len can name",
            ));
        }
        if self.version_mask & !BIP320_VERSION_MASK != 0 {
            return Err(JobError::InvalidConfig(
                "version_mask must be a subset of the BIP320 mask",
            ));
        }
        if self.ntime_forward_secs > MAX_NTIME_FORWARD_SECS {
            return Err(JobError::InvalidConfig(
                "ntime_forward_secs exceeds the consensus future-time limit",
            ));
        }
        let needed = self
            .coinbase_tag
            .len()
            .saturating_add(self.extranonce.total_len());
        if needed.saturating_add(MIN_COINBASE_SCRIPT_SIG_LEN) > MAX_COINBASE_SCRIPT_SIG_LEN {
            return Err(JobError::InvalidConfig(
                "coinbase tag and extranonce cannot fit under the scriptSig limit",
            ));
        }
        Ok(())
    }
}

/// Outcome of [`JobBook::install`].
#[derive(Clone, Debug)]
pub struct Installed {
    /// The job to announce (or the unchanged newest job).
    pub job: Arc<Job>,
    /// A new job was created. False: same template, time, and outputs as the
    /// newest active job; nothing needs sending.
    pub fresh: bool,
    /// Miners must drop all earlier work (SV1 `clean_jobs`, SV2 `SetNewPrevHash`).
    pub clean_jobs: bool,
    /// A job was already retained and its parent differs from the new job's.
    /// A fact about job parents only: it says nothing about whether the chain
    /// extended or reorganized. Chain reorganization is a chain observation.
    pub parent_changed: bool,
    /// Jobs that were active and are stale after this call.
    pub invalidated: Vec<JobId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobState {
    Active,
    Stale(StaleReason),
}

#[derive(Debug)]
struct JobEntry {
    job: Arc<Job>,
    state: JobState,
    hashes: Vec<Hash256>,
}

/// The job and share state of one pool endpoint.
///
/// Single owner, `&mut` methods: the adapter serializes access. Memory is
/// bounded by `max_jobs`, `max_sessions`, and `max_shares_per_job`.
#[derive(Debug)]
pub struct JobBook {
    config: JobBookConfig,
    sessions: SessionTable,
    jobs: VecDeque<JobEntry>,
    next_job: u32,
    last_issued: u32,
    seen: HashMap<Hash256, JobId>,
    scratch: Vec<u8>,
    last_installed: Option<Installed>,
}

impl JobBook {
    /// Builds an empty book; rejects an unusable configuration.
    pub fn new(config: JobBookConfig) -> Result<Self, JobError> {
        config.validate()?;
        let sessions = SessionTable::new(config.extranonce, config.max_sessions);
        Ok(Self {
            config,
            sessions,
            jobs: VecDeque::new(),
            next_job: 1,
            last_issued: 0,
            seen: HashMap::new(),
            scratch: Vec::new(),
            last_installed: None,
        })
    }

    /// The configuration this book was built with.
    #[must_use]
    pub fn config(&self) -> &JobBookConfig {
        &self.config
    }

    /// Opens a session with a unique extranonce prefix.
    pub fn open_session(&mut self) -> Result<Session, JobError> {
        self.sessions.open()
    }

    /// Closes a session and frees its prefix for reuse (oldest-freed first).
    pub fn close_session(&mut self, id: SessionId) -> bool {
        self.sessions.close(id)
    }

    /// Looks up an open session.
    #[must_use]
    pub fn session(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Open sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.live.len()
    }

    /// The newest job, if it is still active.
    #[must_use]
    pub fn current(&self) -> Option<&Arc<Job>> {
        self.jobs
            .back()
            .filter(|entry| entry.state == JobState::Active)
            .map(|entry| &entry.job)
    }
    /// The latest installation metadata, if an active job exists.
    #[must_use]
    pub fn current_installed(&self) -> Option<&Installed> {
        self.last_installed.as_ref()
    }

    /// A retained job, active or stale.
    #[must_use]
    pub fn job(&self, id: JobId) -> Option<&Arc<Job>> {
        self.locate(id)
            .ok()
            .and_then(|index| self.jobs.get(index))
            .map(|entry| &entry.job)
    }

    /// Marks every active job stale ([`StaleReason::Invalidated`]) and returns them.
    pub fn invalidate_active(&mut self) -> Vec<JobId> {
        let mut invalidated = Vec::new();
        for entry in &mut self.jobs {
            if entry.state == JobState::Active {
                entry.state = JobState::Stale(StaleReason::Invalidated);
                invalidated.push(entry.job.id);
            }
        }
        self.last_installed = None;
        invalidated
    }

    /// Projects `candidate` onto a new job, or returns the unchanged newest job.
    ///
    /// `extra_outputs` are pool coinbase outputs; see the crate interface note
    /// for their placement, budget, and value rules.
    pub fn install(
        &mut self,
        candidate: Arc<Candidate>,
        extra_outputs: Vec<TxOut>,
    ) -> Result<Installed, JobError> {
        if let Some(newest) = self.jobs.back()
            && newest.state == JobState::Active
            && newest.job.candidate.template_id == candidate.template_id
            && newest.job.candidate.current_time == candidate.current_time
            && newest.job.extra_outputs == extra_outputs
        {
            let installed = Installed {
                job: Arc::clone(&newest.job),
                fresh: false,
                clean_jobs: false,
                parent_changed: false,
                invalidated: Vec::new(),
            };
            self.last_installed = Some(installed.clone());
            return Ok(installed);
        }

        let raw_id = self.next_job;
        let following = raw_id.checked_add(1).ok_or(JobError::JobIdExhausted)?;
        let job = Arc::new(Job::project(
            JobId(raw_id),
            candidate,
            &self.config,
            extra_outputs,
        )?);

        let newest = self
            .jobs
            .back()
            .map(|entry| (entry.state, entry.job.candidate.previous_block_hash));
        let same_parent_active = matches!(
            newest,
            Some((JobState::Active, parent)) if parent == job.candidate.previous_block_hash
        );
        let clean_jobs = !same_parent_active;
        let parent_changed = matches!(
            newest,
            Some((_, parent)) if parent != job.candidate.previous_block_hash
        );
        let mut invalidated = Vec::new();
        if clean_jobs {
            for entry in &mut self.jobs {
                if entry.state == JobState::Active {
                    entry.state = JobState::Stale(StaleReason::PreviousBlockChanged);
                    invalidated.push(entry.job.id);
                }
            }
        }

        self.jobs.push_back(JobEntry {
            job: Arc::clone(&job),
            state: JobState::Active,
            hashes: Vec::new(),
        });
        self.next_job = following;
        self.last_issued = raw_id;
        while self.jobs.len() > self.config.max_jobs {
            if let Some(evicted) = self.jobs.pop_front() {
                for hash in &evicted.hashes {
                    self.seen.remove(hash);
                }
            }
        }

        let installed = Installed {
            job,
            fresh: true,
            clean_jobs,
            parent_changed,
            invalidated,
        };
        self.last_installed = Some(installed.clone());
        Ok(installed)
    }

    fn locate(&self, id: JobId) -> Result<usize, ShareError> {
        if id.0 == 0 || id.0 > self.last_issued {
            return Err(ShareError::UnknownJob(id));
        }
        let front = self.jobs.front().map_or_else(
            || self.last_issued.saturating_add(1),
            |entry| entry.job.id.0,
        );
        if id.0 < front {
            return Err(ShareError::Stale {
                job: id,
                reason: StaleReason::Retired,
            });
        }
        usize::try_from(id.0 - front).map_err(|_| ShareError::UnknownJob(id))
    }

    /// The single share predicate.
    ///
    /// Checks, in order: session, job existence, job staleness, extranonce
    /// lengths, version mask, `ntime` window, duplicate, network target, share
    /// target, per-job capacity. A header that meets the network target is a
    /// block candidate even when it misses `target`, and is never refused for
    /// capacity. Only accepted shares are remembered, so rejected input
    /// cannot consume duplicate-set capacity.
    pub fn validate(
        &mut self,
        share: &ShareSubmission<'_>,
        target: &ShareTarget,
    ) -> Result<ShareOutcome, ShareError> {
        let session = self
            .sessions
            .get(share.session)
            .ok_or(ShareError::UnknownSession(share.session))?;
        let index = self.locate(share.job)?;
        let entry = self
            .jobs
            .get(index)
            .ok_or(ShareError::UnknownJob(share.job))?;
        if let JobState::Stale(reason) = entry.state {
            return Err(ShareError::Stale {
                job: share.job,
                reason,
            });
        }
        let job = &entry.job;
        let extranonce = Extranonce {
            session: session.extranonce_prefix(),
            rolled: share.rolled_extranonce,
        };
        job.check_extranonce(extranonce)?;
        if (share.version ^ job.version) & !job.version_mask != 0 {
            return Err(ShareError::VersionOutsideMask {
                version: share.version,
                job_version: job.version,
                mask: job.version_mask,
            });
        }
        let min_ntime = job.min_ntime();
        if share.ntime < min_ntime {
            return Err(ShareError::TimeTooEarly {
                ntime: share.ntime,
                min_ntime,
            });
        }
        if share.ntime > job.max_ntime {
            return Err(ShareError::TimeTooLate {
                ntime: share.ntime,
                max_ntime: job.max_ntime,
            });
        }

        let root = job.merkle_root_with(extranonce, &mut self.scratch)?;
        let header = job.header_from(root, share.ntime, share.version, share.nonce);
        let hash = header.compute_hash();
        let raw_hash = Hash256::from(hash);
        if let Some(&first_job) = self.seen.get(&raw_hash) {
            return Err(ShareError::Duplicate { hash, first_job });
        }
        let is_block = compact_is_met_by(job.candidate.bits, raw_hash);
        if !is_block && !target.meets(raw_hash) {
            return Err(ShareError::BelowTarget { hash });
        }
        let remembered = entry.hashes.len();
        let room = remembered < self.config.max_shares_per_job;
        if !is_block && !room {
            return Err(ShareError::JobShareCapacity {
                job: share.job,
                capacity: self.config.max_shares_per_job,
            });
        }

        let mut full_extranonce =
            Vec::with_capacity(extranonce.session.len() + extranonce.rolled.len());
        full_extranonce.extend_from_slice(extranonce.session);
        full_extranonce.extend_from_slice(extranonce.rolled);
        let accepted = AcceptedShare {
            session: share.session,
            job: share.job,
            hash,
            header,
            height: job.candidate.height,
            previous_block_hash: BlockHash::from(job.candidate.previous_block_hash),
            extranonce: full_extranonce,
            target: *target,
            work: target.work(),
            class: if is_block {
                ShareClass::Block
            } else {
                ShareClass::Share
            },
        };
        let outcome = if is_block {
            ShareOutcome::Block(Box::new(job.found_block(accepted, extranonce)))
        } else {
            ShareOutcome::Share(Box::new(accepted))
        };

        if room {
            self.seen.insert(raw_hash, share.job);
            if let Some(entry) = self.jobs.get_mut(index) {
                entry.hashes.push(raw_hash);
            }
        }
        Ok(outcome)
    }
}

/// Requests a template that leaves `budget` of coinbase room, through the
/// node's one authoritative template path.
///
/// `long_poll_id` is the previous candidate's `template_id.as_str()`: the call
/// then waits for a newer generation. The returned template's `candidate`
/// feeds [`JobBook::install`]; `submit_old == Some(false)` means the previous
/// work's parent is no longer the applied tip.
pub fn fetch_template(
    control: &dyn MiningControl,
    budget: CoinbaseBudget,
    long_poll_id: Option<&str>,
) -> Result<BlockTemplate, MiningControlError> {
    let request = BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: long_poll_id.map(CompactString::from),
        coinbase_budget: Some(budget),
    };
    match control.get_block_template(request)? {
        BlockTemplateResult::Template(template) => Ok(template),
        BlockTemplateResult::Proposal(_) => Err(MiningControlError::Failed(CompactString::from(
            "template request was answered with a proposal result",
        ))),
    }
}
