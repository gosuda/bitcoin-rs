//! Durable PPLNS accounting with an external wallet signer boundary.
//!
//! The node supplies an `Arc<dyn bitcoin_rs_storage::KvStore>`. The ledger never opens an engine,
//! holds private keys, calls a wallet RPC, or broadcasts transactions. All mutations use one
//! revision-guarded durable batch; a revision conflict applies nothing, while a backend durability
//! error is ambiguous and must be reconciled through the operation's idempotent identity.
//! Creation requires an empty ledger namespace; opening verifies the immutable configuration.
//! There is no implicit migration from the standalone experimental ledger format.
//!
//! Layout:
//! - this file: identifiers, money/work arithmetic (checked integers only), PPLNS window and
//!   reward split, transaction parsing and payout verification, canonical request/receipt codecs,
//!   the chain-observation and signer seams, and the error type;
//! - [`store`]: durable accounting transitions ([`Ledger`]);
//! - `kv`: coherent logical-table views and the conditional durable commit boundary.
//!
//! Conventions: every `Hash32` is in internal byte order (the order used by transaction
//! serialization), money is `u64` satoshis, work is `u128`, and no floating point is used.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};

mod kv;
mod store;

pub use store::*;

/// A 32-byte hash in internal (serialization) byte order, never display-reversed.
pub type Hash32 = [u8; 32];

/// Maximum amount of money that can exist, in satoshis.
pub const MAX_MONEY_SAT: u64 = 2_100_000_000_000_000;
/// Longest accepted extranonce (`session || rolled`), in bytes.
pub const MAX_EXTRANONCE_LEN: usize = 64;
/// Longest accepted script, in bytes (the consensus script size limit).
pub const MAX_SCRIPT_LEN: usize = 10_000;
/// Largest raw transaction accepted from a signer, in bytes.
pub const MAX_RAW_TX_BYTES: usize = 4_000_000;
/// Largest number of outputs in one payout batch.
pub const MAX_BATCH_OUTPUTS: usize = 2_500;
/// Number of non-batch (change) outputs a signed payout transaction may carry.
pub const MAX_CHANGE_OUTPUTS: usize = 1;
/// Largest number of allowed change scripts in a pool configuration.
pub const MAX_CHANGE_SCRIPTS: usize = 16;

const OP_RETURN: u8 = 0x6a;
const BATCH_ID_DOMAIN: &[u8] = b"btcrs.pool.payout-batch.v1";
const REQUEST_MAGIC: &[u8; 4] = b"BRPR";
const RECEIPT_MAGIC: &[u8; 4] = b"BRPT";
const WIRE_VERSION: u8 = 1;

// ---------------------------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------------------------

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> Hash32 {
    Sha256::digest(data).into()
}

/// Double SHA-256 of `data` (Bitcoin transaction id hash).
#[must_use]
pub fn sha256d(data: &[u8]) -> Hash32 {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// Lowercase hex of `bytes` (diagnostics only; not a display-order conversion).
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Identifiers and job-owner inputs
// ---------------------------------------------------------------------------------------------

/// Pool account identifier. The protocol adapter maps an authorized worker/session to one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MinerId(pub u64);

/// One accepted share as reported by the common job owner (mirror of the job owner's
/// `AcceptedShare`, class `Share` or `Block`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareCredit {
    /// Header hash of the share. Primary idempotency key, unique-indexed by the ledger.
    pub header_hash: Hash32,
    /// Numeric job identifier.
    pub job: u64,
    /// Pool account credited with the work.
    pub account: MinerId,
    /// Session prefix followed by the rolled extranonce bytes.
    pub extranonce: Vec<u8>,
    /// Header nonce.
    pub nonce: u32,
    /// Exact work of the assigned share target, at least 1.
    pub work: u128,
}

impl ShareCredit {
    /// Check static bounds.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidInput`] for zero work or an oversized extranonce.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.work == 0 {
            return Err(LedgerError::InvalidInput("share work must be at least 1"));
        }
        if self.extranonce.len() > MAX_EXTRANONCE_LEN {
            return Err(LedgerError::InvalidInput("extranonce too long"));
        }
        Ok(())
    }

    /// Canonical secondary identity: `job || account || nonce || extranonce` (big-endian).
    /// Fixed-width fields come first, so the encoding is injective and prefix-scannable by job.
    #[must_use]
    pub fn tuple_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(20 + self.extranonce.len());
        key.extend_from_slice(&self.job.to_be_bytes());
        key.extend_from_slice(&self.account.0.to_be_bytes());
        key.extend_from_slice(&self.nonce.to_be_bytes());
        key.extend_from_slice(&self.extranonce);
        key
    }
}

/// Convert the exact little-endian 256-bit `ShareWork` bytes to `u128`.
///
/// # Errors
/// Returns [`LedgerError::Overflow`] if the value does not fit in 128 bits.
pub fn work_from_le_bytes(le: [u8; 32]) -> Result<u128, LedgerError> {
    let (low, high) = le.split_at(16);
    if high.iter().any(|byte| *byte != 0) {
        return Err(LedgerError::Overflow("share work exceeds 2^128"));
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(low);
    Ok(u128::from_le_bytes(buf))
}

/// A found block (mirror of the job owner's `FoundBlock`). Submission status is deliberately not
/// an input: a submission receipt moves no money.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFound {
    /// The block-class share. `share.header_hash` is the block hash.
    pub share: ShareCredit,
    /// Height of the block.
    pub height: u32,
    /// Coinbase transaction id claimed by the job owner (verified against the chain).
    pub coinbase_txid: Hash32,
    /// Total coinbase output value claimed by the job owner (verified against the chain).
    pub claimed_coinbase_value_sat: u64,
}

/// Outcome of crediting a share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareReceipt {
    /// The share was credited with sequence number `seq`.
    Credited {
        /// Ledger sequence number.
        seq: u64,
    },
    /// The same header hash was already credited at `seq`; nothing changed.
    Duplicate {
        /// Ledger sequence number of the original credit.
        seq: u64,
    },
}

impl ShareReceipt {
    /// Sequence number of the credit.
    #[must_use]
    pub fn seq(self) -> u64 {
        match self {
            Self::Credited { seq } | Self::Duplicate { seq } => seq,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

/// Immutable per-ledger accounting parameters. Stored at creation; a ledger refuses to open with
/// different values because they change money semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    /// PPLNS window size in accepted-share work units, at least 1.
    pub window_work: u128,
    /// Pool fee in basis points of the observed coinbase reward (0..=10000), rounded down.
    pub pool_fee_bps: u16,
    /// Confirmations (`tip - height + 1`) a block needs before its reward is credited.
    pub coinbase_maturity: u32,
    /// Confirmations a payout transaction needs before the batch is Confirmed.
    pub payout_confirmations: u32,
    /// Depth at which a conflicting confirmed spend makes a signed transaction dead.
    pub abandon_confirmations: u32,
    /// Depth after which rounds and confirmed batches leave reorg monitoring.
    pub reorg_watch_depth: u32,
    /// Smallest output the pool will ever pay, in satoshis.
    pub dust_limit_sat: u64,
    /// Script that the coinbase pays the pool reward to; reward basis is the sum of those outputs.
    pub pool_coinbase_script: Vec<u8>,
    /// Scripts a signed payout transaction may use for its (at most one) change output.
    pub change_scripts: Vec<Vec<u8>>,
}

impl PoolConfig {
    /// Mainnet-shaped defaults: no fee, maturity 100, 6 payout confirmations, 6 abandon depth,
    /// 1000-block reorg watch, 546 sat dust, no change scripts.
    #[must_use]
    pub fn new(window_work: u128, pool_coinbase_script: Vec<u8>) -> Self {
        Self {
            window_work,
            pool_fee_bps: 0,
            coinbase_maturity: 100,
            payout_confirmations: 6,
            abandon_confirmations: 6,
            reorg_watch_depth: 1_000,
            dust_limit_sat: 546,
            pool_coinbase_script,
            change_scripts: Vec::new(),
        }
    }

    /// Validate every field.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidConfig`] describing the first violated bound.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.window_work == 0 {
            return Err(LedgerError::InvalidConfig("window_work must be at least 1"));
        }
        if self.pool_fee_bps > 10_000 {
            return Err(LedgerError::InvalidConfig("pool_fee_bps exceeds 10000"));
        }
        if self.coinbase_maturity == 0
            || self.payout_confirmations == 0
            || self.abandon_confirmations == 0
        {
            return Err(LedgerError::InvalidConfig(
                "confirmation counts must be at least 1",
            ));
        }
        let deepest = self
            .coinbase_maturity
            .max(self.payout_confirmations)
            .max(self.abandon_confirmations);
        if self.reorg_watch_depth < deepest {
            return Err(LedgerError::InvalidConfig(
                "reorg_watch_depth must cover maturity, payout and abandon depths",
            ));
        }
        if self.dust_limit_sat == 0 || self.dust_limit_sat > MAX_MONEY_SAT {
            return Err(LedgerError::InvalidConfig("dust_limit_sat out of range"));
        }
        validate_script(&self.pool_coinbase_script)
            .map_err(|_| LedgerError::InvalidConfig("pool_coinbase_script invalid"))?;
        if self.change_scripts.len() > MAX_CHANGE_SCRIPTS {
            return Err(LedgerError::InvalidConfig("too many change scripts"));
        }
        for script in &self.change_scripts {
            validate_script(script)
                .map_err(|_| LedgerError::InvalidConfig("change script invalid"))?;
        }
        Ok(())
    }

    /// Canonical encoding stored in the ledger and compared at open.
    ///
    /// # Errors
    /// Returns [`LedgerError::Codec`] if a length does not fit the wire format.
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let mut enc = codec::Enc::new();
        enc.u8(WIRE_VERSION);
        enc.u128(self.window_work);
        enc.u32(u32::from(self.pool_fee_bps));
        enc.u32(self.coinbase_maturity);
        enc.u32(self.payout_confirmations);
        enc.u32(self.abandon_confirmations);
        enc.u32(self.reorg_watch_depth);
        enc.u64(self.dust_limit_sat);
        enc.bytes(&self.pool_coinbase_script);
        enc.len32(self.change_scripts.len());
        for script in &self.change_scripts {
            enc.bytes(script);
        }
        enc.finish()
    }
}

/// A payout or reward script must be non-empty, bounded and not provably unspendable.
fn validate_script(script: &[u8]) -> Result<(), LedgerError> {
    if script.is_empty() || script.len() > MAX_SCRIPT_LEN {
        return Err(LedgerError::InvalidInput("script length out of range"));
    }
    if script[0] == OP_RETURN {
        return Err(LedgerError::InvalidInput(
            "script is unspendable (OP_RETURN)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Rounds and balances
// ---------------------------------------------------------------------------------------------

/// Lifecycle of a reward round (one found block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundState {
    /// Recorded from a found block; the active chain has not shown the block yet.
    Pending,
    /// Block is on the active chain and the reward is fixed, but not yet mature.
    Immature,
    /// Block is mature on the active chain and allocations are credited to balances.
    Matured,
    /// Block was displaced from the active chain (credits, if any, were reversed).
    Orphaned,
}

impl RoundState {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Immature => 2,
            Self::Matured => 3,
            Self::Orphaned => 4,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Pending),
            2 => Some(Self::Immature),
            3 => Some(Self::Matured),
            4 => Some(Self::Orphaned),
            _ => None,
        }
    }
}

/// One reward round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    /// Ledger round id (1-based, monotonic).
    pub id: u64,
    /// Block hash (internal byte order).
    pub block_hash: Hash32,
    /// Block height.
    pub height: u32,
    /// Sequence number of the solving share; the PPLNS window ends there.
    pub solving_seq: u64,
    /// Coinbase txid claimed by the job owner.
    pub coinbase_txid: Hash32,
    /// Coinbase total claimed by the job owner.
    pub claimed_coinbase_value_sat: u64,
    /// Sum of the window weights (at most `window_work`).
    pub window_work_total: u128,
    /// True once the reward was read from the active chain and allocations were stored.
    pub reward_fixed: bool,
    /// Observed coinbase value paying the pool script (0 until fixed).
    pub gross_sat: u64,
    /// Pool fee withheld from `gross_sat`.
    pub pool_fee_sat: u64,
    /// Amount distributed to accounts: `gross_sat - pool_fee_sat`.
    pub net_sat: u64,
    /// Current state.
    pub state: RoundState,
}

/// Result of recording a found block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecorded {
    /// The round for the block (existing or new).
    pub round: Round,
    /// Outcome of crediting the solving share in the same transaction.
    pub share: ShareReceipt,
    /// True if this call created the round.
    pub newly_recorded: bool,
}

/// Account balance. Invariant: `available + reserved + paid - deficit == credited allocations`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// Credited and not reserved: eligible for the next payout batch.
    pub available_sat: u64,
    /// Reserved by an open payout batch.
    pub reserved_sat: u64,
    /// Paid by Confirmed payout batches.
    pub paid_sat: u64,
    /// Credits reversed after they were reserved or paid; netted against future credits.
    pub deficit_sat: u64,
}

/// One state change of a round during reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundTransition {
    /// Round id.
    pub round: u64,
    /// State before.
    pub from: RoundState,
    /// State after.
    pub to: RoundState,
    /// Satoshis credited to balances by this transition.
    pub credited_sat: u64,
    /// Satoshis removed from balances by this transition.
    pub reversed_sat: u64,
    /// Part of `reversed_sat` that could not be removed from `available` and became deficit.
    pub deficit_created_sat: u64,
}

// ---------------------------------------------------------------------------------------------
// Exact integer accounting
// ---------------------------------------------------------------------------------------------

/// Split a gross reward into `(pool_fee, net)`; the fee rounds down so miners get the remainder.
///
/// # Errors
/// Returns [`LedgerError::InvalidInput`] for `fee_bps > 10000` and [`LedgerError::Overflow`] on
/// impossible arithmetic.
pub fn split_pool_fee(gross_sat: u64, fee_bps: u16) -> Result<(u64, u64), LedgerError> {
    if fee_bps > 10_000 {
        return Err(LedgerError::InvalidInput("fee bps exceeds 10000"));
    }
    let fee = u128::from(gross_sat) * u128::from(fee_bps) / 10_000;
    let fee = u64::try_from(fee).map_err(|_| LedgerError::Overflow("pool fee"))?;
    let net = gross_sat
        .checked_sub(fee)
        .ok_or(LedgerError::Overflow("pool fee exceeds gross"))?;
    Ok((fee, net))
}

const MUL_DIV_LOW_LIMB: u128 = 0xffff_ffff_ffff_ffff;
const MUL_DIV_BITS: usize = 192;

/// Exact `(floor(a * b / d), (a * b) mod d)` with a 192-bit intermediate product.
///
/// Requires `0 < d` and `b <= d`, which guarantees the quotient is at most `a`.
///
/// # Errors
/// Returns [`LedgerError::InvalidInput`] if `d == 0` or `b > d`.
pub fn mul_div_rem(a: u64, b: u128, d: u128) -> Result<(u128, u128), LedgerError> {
    if d == 0 {
        return Err(LedgerError::InvalidInput("division by zero"));
    }
    if b > d {
        return Err(LedgerError::InvalidInput("weight exceeds total"));
    }
    let a = u128::from(a);
    let low = a * (b & MUL_DIV_LOW_LIMB);
    let high = a * (b >> 64);
    let mid = high + (low >> 64);
    let limbs: [u128; 3] = [low & MUL_DIV_LOW_LIMB, mid & MUL_DIV_LOW_LIMB, mid >> 64];
    let mut quotient: u128 = 0;
    let mut remainder: u128 = 0;
    for index in (0..MUL_DIV_BITS).rev() {
        let bit = (limbs[index / 64] >> (index % 64)) & 1;
        let carry = remainder >> 127;
        remainder = (remainder << 1) | bit;
        quotient <<= 1;
        if carry == 1 || remainder >= d {
            remainder = remainder.wrapping_sub(d);
            quotient |= 1;
        }
    }
    Ok((quotient, remainder))
}

/// Split `net_sat` across `weights` (strictly ascending by account, all non-zero).
///
/// Each account gets `floor(net * weight / total)`; the leftover satoshis go one each to the
/// largest fractional remainders (ties: lower `MinerId`). The result sums to exactly `net_sat`.
/// Zero allocations are omitted.
///
/// # Errors
/// Returns [`LedgerError::EmptyWindow`] for no weights, [`LedgerError::InvalidInput`] for unsorted
/// or zero weights, and [`LedgerError::Overflow`] on arithmetic failure.
pub fn split_reward(
    net_sat: u64,
    weights: &[(MinerId, u128)],
) -> Result<Vec<(MinerId, u64)>, LedgerError> {
    if weights.is_empty() {
        return Err(LedgerError::EmptyWindow);
    }
    let mut total: u128 = 0;
    let mut previous: Option<MinerId> = None;
    for (miner, weight) in weights {
        if *weight == 0 {
            return Err(LedgerError::InvalidInput("zero window weight"));
        }
        if previous.is_some_and(|prev| *miner <= prev) {
            return Err(LedgerError::InvalidInput(
                "window weights must be strictly ascending",
            ));
        }
        previous = Some(*miner);
        total = total
            .checked_add(*weight)
            .ok_or(LedgerError::Overflow("window total"))?;
    }
    let mut parts: Vec<(MinerId, u64, u128)> = Vec::with_capacity(weights.len());
    let mut floor_sum: u64 = 0;
    for (miner, weight) in weights {
        let (quotient, remainder) = mul_div_rem(net_sat, *weight, total)?;
        let quotient = u64::try_from(quotient).map_err(|_| LedgerError::Overflow("allocation"))?;
        floor_sum = floor_sum
            .checked_add(quotient)
            .ok_or(LedgerError::Overflow("allocation sum"))?;
        parts.push((*miner, quotient, remainder));
    }
    let residual = net_sat
        .checked_sub(floor_sum)
        .ok_or(LedgerError::Overflow("allocation floors exceed net"))?;
    let residual = usize::try_from(residual).map_err(|_| LedgerError::Overflow("residual"))?;
    if residual > parts.len() {
        return Err(LedgerError::Overflow("residual exceeds participants"));
    }
    let mut order: Vec<usize> = (0..parts.len()).collect();
    order.sort_by(|a, b| {
        parts[*b]
            .2
            .cmp(&parts[*a].2)
            .then(parts[*a].0.cmp(&parts[*b].0))
    });
    for index in order.into_iter().take(residual) {
        parts[index].1 = parts[index]
            .1
            .checked_add(1)
            .ok_or(LedgerError::Overflow("allocation residual"))?;
    }
    Ok(parts
        .into_iter()
        .filter(|(_, amount, _)| *amount > 0)
        .map(|(miner, amount, _)| (miner, amount))
        .collect())
}

/// Builds a bounded PPLNS window from shares fed newest first.
///
/// The share that straddles the window edge is truncated in integer work units so the window
/// total is exactly `target` once enough work exists.
#[derive(Clone, Debug)]
pub struct WindowAccumulator {
    target: u128,
    total: u128,
    by_account: BTreeMap<MinerId, u128>,
}

impl WindowAccumulator {
    /// New window of `target` work units.
    #[must_use]
    pub fn new(target: u128) -> Self {
        Self {
            target,
            total: 0,
            by_account: BTreeMap::new(),
        }
    }

    /// True once the window holds `target` work.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.total >= self.target
    }

    /// Work currently in the window.
    #[must_use]
    pub fn total(&self) -> u128 {
        self.total
    }

    /// Add the next-older share, truncated to the remaining room.
    ///
    /// # Errors
    /// Returns [`LedgerError::Overflow`] if a per-account total overflows.
    pub fn push_older(&mut self, account: MinerId, work: u128) -> Result<(), LedgerError> {
        let remaining = self.target.saturating_sub(self.total);
        let take = work.min(remaining);
        if take == 0 {
            return Ok(());
        }
        let entry = self.by_account.entry(account).or_insert(0);
        *entry = entry
            .checked_add(take)
            .ok_or(LedgerError::Overflow("window account work"))?;
        self.total = self
            .total
            .checked_add(take)
            .ok_or(LedgerError::Overflow("window total"))?;
        Ok(())
    }

    /// Per-account weights, ascending by account.
    #[must_use]
    pub fn into_weights(self) -> Vec<(MinerId, u128)> {
        self.by_account.into_iter().collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------------------------

/// A transaction output point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    /// Funding transaction id (internal byte order).
    pub txid: Hash32,
    /// Output index.
    pub vout: u32,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshis.
    pub value_sat: u64,
    /// Locking script.
    pub script_pubkey: Vec<u8>,
}

/// Transaction parse failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxParseError {
    /// Input ended early.
    Truncated,
    /// Bytes remained after the transaction.
    TrailingBytes,
    /// A compact size was not minimally encoded.
    NonCanonicalVarint,
    /// Transaction has no inputs.
    NoInputs,
    /// Transaction has no outputs.
    NoOutputs,
    /// Segwit marker present with a flag other than 1.
    BadWitnessFlag,
    /// Segwit encoding with all-empty witnesses.
    SuperfluousWitness,
    /// Transaction exceeds [`MAX_RAW_TX_BYTES`].
    TooLarge,
    /// An output value or the output sum exceeds [`MAX_MONEY_SAT`].
    ValueOutOfRange,
    /// A count cannot fit in the remaining bytes.
    CountTooLarge,
}

/// A parsed transaction: only what payout verification needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransaction {
    /// Transaction id recomputed from the bytes (internal byte order).
    pub txid: Hash32,
    /// Version field.
    pub version: i32,
    /// Lock time field.
    pub lock_time: u32,
    /// True if the bytes used the segwit serialization.
    pub has_witness: bool,
    /// Spent outpoints in order.
    pub inputs: Vec<OutPoint>,
    /// Outputs in order.
    pub outputs: Vec<TxOut>,
}

struct TxCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TxCursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxParseError> {
        let end = self.pos.checked_add(n).ok_or(TxParseError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(TxParseError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, TxParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16, TxParseError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| TxParseError::Truncated)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32_le(&mut self) -> Result<u32, TxParseError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| TxParseError::Truncated)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64_le(&mut self) -> Result<u64, TxParseError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| TxParseError::Truncated)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn hash(&mut self) -> Result<Hash32, TxParseError> {
        self.take(32)?
            .try_into()
            .map_err(|_| TxParseError::Truncated)
    }

    fn varint(&mut self) -> Result<u64, TxParseError> {
        let first = self.u8()?;
        match first {
            0..=0xfc => Ok(u64::from(first)),
            0xfd => {
                let value = u64::from(self.u16_le()?);
                if value < 0xfd {
                    return Err(TxParseError::NonCanonicalVarint);
                }
                Ok(value)
            }
            0xfe => {
                let value = u64::from(self.u32_le()?);
                if value < 0x1_0000 {
                    return Err(TxParseError::NonCanonicalVarint);
                }
                Ok(value)
            }
            0xff => {
                let value = self.u64_le()?;
                if value < 0x1_0000_0000 {
                    return Err(TxParseError::NonCanonicalVarint);
                }
                Ok(value)
            }
        }
    }

    /// Bound an element count by what the remaining bytes can possibly hold.
    fn bounded(&self, count: u64, min_item_bytes: usize) -> Result<usize, TxParseError> {
        let count = usize::try_from(count).map_err(|_| TxParseError::CountTooLarge)?;
        let remaining = self.buf.len().saturating_sub(self.pos);
        if count > remaining / min_item_bytes {
            return Err(TxParseError::CountTooLarge);
        }
        Ok(count)
    }

    fn var_bytes(&mut self) -> Result<&'a [u8], TxParseError> {
        let len = self.varint()?;
        let len = usize::try_from(len).map_err(|_| TxParseError::Truncated)?;
        self.take(len)
    }
}

/// Strictly parse a raw transaction (legacy or BIP144 segwit serialization) and recompute its
/// txid. The whole input must be consumed.
///
/// # Errors
/// Returns a [`TxParseError`] for any malformed or non-canonical encoding.
pub fn parse_transaction(raw: &[u8]) -> Result<ParsedTransaction, TxParseError> {
    if raw.len() > MAX_RAW_TX_BYTES {
        return Err(TxParseError::TooLarge);
    }
    let mut cursor = TxCursor { buf: raw, pos: 0 };
    let version = i32::from_le_bytes(
        cursor
            .take(4)?
            .try_into()
            .map_err(|_| TxParseError::Truncated)?,
    );
    let mut has_witness = false;
    let mut body_start = cursor.pos;
    let mut input_count = cursor.varint()?;
    if input_count == 0 {
        if cursor.u8()? != 1 {
            return Err(TxParseError::BadWitnessFlag);
        }
        has_witness = true;
        body_start = cursor.pos;
        input_count = cursor.varint()?;
    }
    if input_count == 0 {
        return Err(TxParseError::NoInputs);
    }
    let input_count = cursor.bounded(input_count, 41)?;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let txid = cursor.hash()?;
        let vout = cursor.u32_le()?;
        cursor.var_bytes()?;
        cursor.u32_le()?;
        inputs.push(OutPoint { txid, vout });
    }
    let output_count = cursor.varint()?;
    if output_count == 0 {
        return Err(TxParseError::NoOutputs);
    }
    let output_count = cursor.bounded(output_count, 9)?;
    let mut outputs = Vec::with_capacity(output_count);
    let mut output_sum: u64 = 0;
    for _ in 0..output_count {
        let value_sat = cursor.u64_le()?;
        if value_sat > MAX_MONEY_SAT {
            return Err(TxParseError::ValueOutOfRange);
        }
        output_sum = output_sum
            .checked_add(value_sat)
            .filter(|sum| *sum <= MAX_MONEY_SAT)
            .ok_or(TxParseError::ValueOutOfRange)?;
        let script_pubkey = cursor.var_bytes()?.to_vec();
        outputs.push(TxOut {
            value_sat,
            script_pubkey,
        });
    }
    let body_end = cursor.pos;
    if has_witness {
        let mut any_witness = false;
        for _ in 0..inputs.len() {
            let items = cursor.varint()?;
            let items = cursor.bounded(items, 1)?;
            if items > 0 {
                any_witness = true;
            }
            for _ in 0..items {
                cursor.var_bytes()?;
            }
        }
        if !any_witness {
            return Err(TxParseError::SuperfluousWitness);
        }
    }
    let lock_time = cursor.u32_le()?;
    if cursor.pos != raw.len() {
        return Err(TxParseError::TrailingBytes);
    }
    let txid = if has_witness {
        let mut stripped = Vec::with_capacity(8 + (body_end - body_start));
        stripped.extend_from_slice(&raw[..4]);
        stripped.extend_from_slice(&raw[body_start..body_end]);
        stripped.extend_from_slice(&raw[raw.len() - 4..]);
        sha256d(&stripped)
    } else {
        sha256d(raw)
    };
    Ok(ParsedTransaction {
        txid,
        version,
        lock_time,
        has_witness,
        inputs,
        outputs,
    })
}

// ---------------------------------------------------------------------------------------------
// Payout request / receipt (the external signer contract)
// ---------------------------------------------------------------------------------------------

/// One payout destination and amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutOutput {
    /// Account being paid.
    pub account: MinerId,
    /// Destination script, snapshotted when the batch was prepared.
    pub script_pubkey: Vec<u8>,
    /// Amount in satoshis (at least the dust limit).
    pub amount_sat: u64,
}

/// Unsigned payout instructions for an external signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutRequest {
    /// Immutable batch id.
    pub batch_id: Hash32,
    /// Outputs the signed transaction MUST contain exactly (script and amount).
    pub outputs: Vec<PayoutOutput>,
    /// Sum of the output amounts.
    pub total_sat: u64,
    /// Scripts the signer may use for a single change output.
    pub allowed_change_scripts: Vec<Vec<u8>>,
}

fn check_outputs(outputs: &[PayoutOutput]) -> Result<u64, LedgerError> {
    if outputs.is_empty() || outputs.len() > MAX_BATCH_OUTPUTS {
        return Err(LedgerError::InvalidInput(
            "payout output count out of range",
        ));
    }
    let mut total: u64 = 0;
    for output in outputs {
        validate_script(&output.script_pubkey)?;
        if output.amount_sat == 0 || output.amount_sat > MAX_MONEY_SAT {
            return Err(LedgerError::InvalidInput("payout amount out of range"));
        }
        total = total
            .checked_add(output.amount_sat)
            .filter(|sum| *sum <= MAX_MONEY_SAT)
            .ok_or(LedgerError::Overflow("payout total"))?;
    }
    Ok(total)
}

impl PayoutRequest {
    /// Canonical wire form: `"BRPR" | 0x01 | batch_id | n_outputs u32 | (account u64 | amount u64
    /// | script_len u32 | script)* | n_change u32 | (len u32 | script)*`, all big-endian.
    ///
    /// # Errors
    /// Returns an error if the request violates the bounds or does not fit the wire format.
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let total = check_outputs(&self.outputs)?;
        if total != self.total_sat {
            return Err(LedgerError::InvalidInput(
                "request total does not match outputs",
            ));
        }
        let mut enc = codec::Enc::new();
        enc.raw(REQUEST_MAGIC);
        enc.u8(WIRE_VERSION);
        enc.hash(&self.batch_id);
        enc.len32(self.outputs.len());
        for output in &self.outputs {
            enc.u64(output.account.0);
            enc.u64(output.amount_sat);
            enc.bytes(&output.script_pubkey);
        }
        enc.len32(self.allowed_change_scripts.len());
        for script in &self.allowed_change_scripts {
            enc.bytes(script);
        }
        enc.finish()
    }

    /// Strict inverse of [`PayoutRequest::encode`].
    ///
    /// # Errors
    /// Returns [`LedgerError::Codec`] or [`LedgerError::InvalidInput`] on any deviation.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut dec = codec::Dec::new(bytes);
        if dec.take(4)? != REQUEST_MAGIC {
            return Err(LedgerError::Codec("bad request magic"));
        }
        if dec.u8()? != WIRE_VERSION {
            return Err(LedgerError::Codec("unsupported request version"));
        }
        let batch_id = dec.hash()?;
        let count = dec.count(MAX_BATCH_OUTPUTS, 20)?;
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            let account = MinerId(dec.u64()?);
            let amount_sat = dec.u64()?;
            let script_pubkey = dec.bytes(MAX_SCRIPT_LEN)?.to_vec();
            outputs.push(PayoutOutput {
                account,
                script_pubkey,
                amount_sat,
            });
        }
        let change_count = dec.count(MAX_CHANGE_SCRIPTS, 4)?;
        let mut allowed_change_scripts = Vec::with_capacity(change_count);
        for _ in 0..change_count {
            let script = dec.bytes(MAX_SCRIPT_LEN)?.to_vec();
            validate_script(&script)?;
            allowed_change_scripts.push(script);
        }
        dec.finish()?;
        let total_sat = check_outputs(&outputs)?;
        Ok(Self {
            batch_id,
            outputs,
            total_sat,
            allowed_change_scripts,
        })
    }

    /// SHA-256 of the canonical encoding (what an air-gapped signer can display and confirm).
    ///
    /// # Errors
    /// Same as [`PayoutRequest::encode`].
    pub fn digest(&self) -> Result<Hash32, LedgerError> {
        Ok(sha256(&self.encode()?))
    }
}

/// The signer's answer: the fully signed transaction. The txid is recomputed by the ledger, so a
/// receipt cannot vouch for a transaction it does not contain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutReceipt {
    /// Batch the transaction pays.
    pub batch_id: Hash32,
    /// Claimed txid (internal byte order); must equal the recomputed txid.
    pub txid: Hash32,
    /// Serialized signed transaction (legacy or segwit serialization).
    pub raw_tx: Vec<u8>,
}

impl PayoutReceipt {
    /// Canonical wire form: `"BRPT" | 0x01 | batch_id | txid | raw_len u32 | raw_tx`.
    ///
    /// # Errors
    /// Returns an error if the transaction exceeds [`MAX_RAW_TX_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        if self.raw_tx.len() > MAX_RAW_TX_BYTES {
            return Err(LedgerError::InvalidInput("raw transaction too large"));
        }
        let mut enc = codec::Enc::new();
        enc.raw(RECEIPT_MAGIC);
        enc.u8(WIRE_VERSION);
        enc.hash(&self.batch_id);
        enc.hash(&self.txid);
        enc.bytes(&self.raw_tx);
        enc.finish()
    }

    /// Strict inverse of [`PayoutReceipt::encode`].
    ///
    /// # Errors
    /// Returns [`LedgerError::Codec`] on any deviation.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut dec = codec::Dec::new(bytes);
        if dec.take(4)? != RECEIPT_MAGIC {
            return Err(LedgerError::Codec("bad receipt magic"));
        }
        if dec.u8()? != WIRE_VERSION {
            return Err(LedgerError::Codec("unsupported receipt version"));
        }
        let batch_id = dec.hash()?;
        let txid = dec.hash()?;
        let raw_tx = dec.bytes(MAX_RAW_TX_BYTES)?.to_vec();
        dec.finish()?;
        Ok(Self {
            batch_id,
            txid,
            raw_tx,
        })
    }
}

/// The external signer adapter contract.
///
/// Implementations live outside this crate (wallet adapters); this crate never ships one and never
/// holds keys. Asynchronous wallets can skip the trait and deliver a [`PayoutReceipt`] to
/// `Ledger::record_signed` later.
pub trait ExternalSigner {
    /// Sign `request`'s exact outputs and return the signed transaction.
    ///
    /// # Errors
    /// Returns [`SignerError`] if the signer refuses or fails.
    fn sign(&self, request: &PayoutRequest) -> Result<PayoutReceipt, SignerError>;
}

/// Failure reported by an external signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerError(pub String);

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "external signer: {}", self.0)
    }
}

impl std::error::Error for SignerError {}

/// Why a signed transaction was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    /// The raw bytes did not parse.
    Parse(TxParseError),
    /// The claimed txid differs from the recomputed one.
    TxidMismatch,
    /// The transaction has no inputs.
    NoInputs,
    /// An input spends the null outpoint (coinbase-style input).
    NullPrevout,
    /// The same outpoint is spent twice.
    DuplicateInput,
    /// A batch output (by index) is not present with exact script and amount.
    MissingOutput {
        /// Index into the batch outputs.
        index: usize,
    },
    /// An extra output (by transaction index) is not an allowed change output.
    UnexpectedOutput {
        /// Index into the transaction outputs.
        index: usize,
    },
    /// More extra outputs than [`MAX_CHANGE_OUTPUTS`].
    TooManyExtraOutputs,
    /// The txid already belongs to another batch.
    TxidInOtherBatch,
    /// A replacement does not spend an input of an earlier signed transaction of the batch, so
    /// both could confirm and pay twice.
    NotConflicting {
        /// The earlier transaction that the new one does not conflict with.
        existing_txid: Hash32,
    },
}

impl From<TxParseError> for ReceiptError {
    fn from(error: TxParseError) -> Self {
        Self::Parse(error)
    }
}

/// Verify that `tx` pays exactly the batch `outputs` (script and amount, as a multiset) plus at
/// most [`MAX_CHANGE_OUTPUTS`] output to an allowed change script.
///
/// Signatures and input ownership are not checked here: that is the signer's and the node's job.
/// The chain observation of the recomputed txid is what proves the node accepted the signatures.
///
/// # Errors
/// Returns the first [`ReceiptError`] found.
pub fn verify_payout_transaction(
    outputs: &[PayoutOutput],
    allowed_change_scripts: &[Vec<u8>],
    tx: &ParsedTransaction,
) -> Result<(), ReceiptError> {
    if tx.inputs.is_empty() {
        return Err(ReceiptError::NoInputs);
    }
    let mut seen = BTreeSet::new();
    for input in &tx.inputs {
        if input.txid == [0u8; 32] && input.vout == u32::MAX {
            return Err(ReceiptError::NullPrevout);
        }
        if !seen.insert(*input) {
            return Err(ReceiptError::DuplicateInput);
        }
    }
    let mut used = vec![false; tx.outputs.len()];
    for (index, expected) in outputs.iter().enumerate() {
        let found = (0..tx.outputs.len()).find(|candidate| {
            !used[*candidate]
                && tx.outputs[*candidate].value_sat == expected.amount_sat
                && tx.outputs[*candidate].script_pubkey == expected.script_pubkey
        });
        match found {
            Some(position) => used[position] = true,
            None => return Err(ReceiptError::MissingOutput { index }),
        }
    }
    let extras: Vec<usize> = (0..tx.outputs.len())
        .filter(|index| !used[*index])
        .collect();
    if extras.len() > MAX_CHANGE_OUTPUTS {
        return Err(ReceiptError::TooManyExtraOutputs);
    }
    for index in extras {
        if !allowed_change_scripts
            .iter()
            .any(|script| *script == tx.outputs[index].script_pubkey)
        {
            return Err(ReceiptError::UnexpectedOutput { index });
        }
    }
    Ok(())
}

/// Immutable batch id: SHA-256 over a domain tag, the idempotency key and the canonical outputs.
///
/// # Errors
/// Returns an error if a length does not fit the wire format.
pub fn compute_batch_id(
    idempotency_key: &Hash32,
    outputs: &[PayoutOutput],
) -> Result<Hash32, LedgerError> {
    let mut enc = codec::Enc::new();
    enc.raw(BATCH_ID_DOMAIN);
    enc.hash(idempotency_key);
    enc.len32(outputs.len());
    for output in outputs {
        enc.u64(output.account.0);
        enc.u64(output.amount_sat);
        enc.bytes(&output.script_pubkey);
    }
    Ok(sha256(&enc.finish()?))
}

// ---------------------------------------------------------------------------------------------
// Payout batches
// ---------------------------------------------------------------------------------------------

/// Payout batch lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchState {
    /// Reserved; instructions exist but no signed transaction is known.
    Prepared,
    /// A signed transaction matching the batch was recorded.
    ExternallySigned,
    /// A signed transaction was observed in the mempool or a block.
    Broadcast,
    /// A signed transaction is confirmed on the active chain at the configured depth.
    Confirmed,
    /// Cancelled before any signed transaction existed; reservation released.
    Cancelled,
    /// Every known signed transaction was conclusively double-spent; reservation released.
    Failed,
}

impl BatchState {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::ExternallySigned => 2,
            Self::Broadcast => 3,
            Self::Confirmed => 4,
            Self::Cancelled => 5,
            Self::Failed => 6,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Prepared),
            2 => Some(Self::ExternallySigned),
            3 => Some(Self::Broadcast),
            4 => Some(Self::Confirmed),
            5 => Some(Self::Cancelled),
            6 => Some(Self::Failed),
            _ => None,
        }
    }

    /// True while the batch still holds its reservation (not yet paid, not released).
    #[must_use]
    pub fn holds_reservation(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::ExternallySigned | Self::Broadcast
        )
    }
}

/// A signed transaction recorded for a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    /// Recomputed txid.
    pub txid: Hash32,
    /// Outpoints the transaction spends.
    pub inputs: Vec<OutPoint>,
}

/// Where a batch's payment confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmation {
    /// Confirming transaction.
    pub txid: Hash32,
    /// Block that contains it.
    pub block_hash: Hash32,
    /// Height of that block.
    pub height: u32,
}

/// Operator attestation when cancelling a Prepared batch. The ledger cannot verify either value:
/// it is recorded in the audit trail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelBasis {
    /// The instructions were never given to a signer.
    NeverHandedToSigner,
    /// The signer was told to void the request and confirmed it will not sign.
    SignerRevoked,
}

impl CancelBasis {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::NeverHandedToSigner => 1,
            Self::SignerRevoked => 2,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::NeverHandedToSigner),
            2 => Some(Self::SignerRevoked),
            _ => None,
        }
    }
}

/// Terminal reason of a Cancelled or Failed batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closure {
    /// Operator cancelled a Prepared batch.
    Cancelled(CancelBasis),
    /// All signed transactions were double-spent; `conflicting_txid` spent an input of the first.
    Failed {
        /// Confirmed transaction that spent an input of a signed transaction.
        conflicting_txid: Hash32,
    },
}

/// Parameters for selecting accounts into a payout batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutPolicy {
    /// Accounts need at least this much available balance (and at least the dust limit).
    pub min_payout_sat: u64,
    /// Most outputs in the batch (1..=[`MAX_BATCH_OUTPUTS`]).
    pub max_outputs: usize,
}

/// A payout batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutBatch {
    /// Immutable id.
    pub id: Hash32,
    /// Creation order.
    pub seq: u64,
    /// Idempotency key of the prepare call.
    pub idempotency_key: Hash32,
    /// Current state.
    pub state: BatchState,
    /// Revision counter, bumped on every change.
    pub rev: u64,
    /// Outputs (snapshot of destination scripts and amounts).
    pub outputs: Vec<PayoutOutput>,
    /// Sum of outputs.
    pub total_sat: u64,
    /// Signed transactions recorded so far (RBF replacements add entries).
    pub transactions: Vec<SignedTx>,
    /// Transaction last observed in the mempool or a block.
    pub broadcast_txid: Option<Hash32>,
    /// Confirmation, while Confirmed.
    pub confirmation: Option<Confirmation>,
    /// Terminal reason, when Cancelled or Failed.
    pub closure: Option<Closure>,
}

/// One batch state change during reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchTransition {
    /// Batch id.
    pub batch_id: Hash32,
    /// State before.
    pub from: BatchState,
    /// State after (equal to `from` when a confirmation moved to another block).
    pub to: BatchState,
}

// ---------------------------------------------------------------------------------------------
// Chain observation seam
// ---------------------------------------------------------------------------------------------

/// Failure reported by a chain observer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainViewError(pub String);

impl fmt::Display for ChainViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chain view: {}", self.0)
    }
}

impl std::error::Error for ChainViewError {}

/// Coinbase transaction of an observed block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedCoinbase {
    /// Coinbase txid.
    pub txid: Hash32,
    /// Coinbase outputs.
    pub outputs: Vec<TxOut>,
}

/// Where a transaction is according to the active chain and mempool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// Neither confirmed nor in the mempool.
    Unknown,
    /// In the mempool.
    InMempool,
    /// In a block on the active chain.
    Confirmed {
        /// Containing block.
        block_hash: Hash32,
        /// Height of the containing block.
        height: u32,
    },
}

/// A confirmed spend of an outpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedSpend {
    /// Spending transaction.
    pub spender_txid: Hash32,
    /// Block containing the spend.
    pub block_hash: Hash32,
    /// Height of that block.
    pub height: u32,
}

/// Authoritative observations of the ACTIVE chain. The ledger decides block, maturity, reorg and
/// confirmation state only from these answers, never from job flags or submission receipts.
pub trait ChainView {
    /// Height of the active tip.
    ///
    /// # Errors
    /// Returns [`ChainViewError`] if the observer cannot answer.
    fn tip_height(&self) -> Result<u32, ChainViewError>;

    /// Locate this exact hash on the active chain or identify it as side-chain/unknown.
    /// `claimed_height` is only a lookup hint, never canonicality evidence. In particular a known
    /// displaced block remains `Side` even when a replacement chain's tip is lower or equal.
    ///
    /// # Errors
    /// Returns [`ChainViewError`] if the observer cannot answer.
    fn block_location(
        &self,
        block_hash: &Hash32,
        claimed_height: u32,
    ) -> Result<BlockLocation, ChainViewError>;

    /// Coinbase of the block with `block_hash`, `None` if the body is unavailable.
    ///
    /// # Errors
    /// Returns [`ChainViewError`] if the observer cannot answer.
    fn coinbase_of(&self, block_hash: &Hash32) -> Result<Option<ObservedCoinbase>, ChainViewError>;

    /// Position of `txid`.
    ///
    /// # Errors
    /// Returns [`ChainViewError`] if the observer cannot answer.
    fn tx_status(&self, txid: &Hash32) -> Result<TxStatus, ChainViewError>;

    /// The confirmed spend of `outpoint` on the active chain, if any.
    ///
    /// # Errors
    /// Returns [`ChainViewError`] if the observer cannot answer.
    fn confirmed_spender(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<ConfirmedSpend>, ChainViewError>;
}

// ---------------------------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------------------------

/// Kind of an audit record. Field meanings are documented per variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// subject 0; values `[below_seq, removed, kept_work_low64]`.
    SharesPruned,
    /// subject round id; hash block hash; values `[height, window_total_low64, solving_seq]`.
    RoundRecorded,
    /// subject round id; hash block hash; values `[gross, pool_fee, net]`.
    RewardFixed,
    /// subject round id; hash block hash; values `[credited_total, 0, 0]`.
    RoundMatured,
    /// subject round id; hash block hash; values `[reversed_total, deficit_created, was_credited]`.
    RoundOrphaned,
    /// subject round id; hash block hash; values `[0, 0, 0]` (Orphaned back to Immature).
    RoundRevived,
    /// subject account; hash SHA-256 of the script; values `[0, 0, 0]`.
    PayoutScriptSet,
    /// subject batch seq; hash batch id; values `[total, outputs, 0]`.
    BatchPrepared,
    /// subject batch seq; hash batch id; hash2 txid; values `[inputs, 0, 0]`.
    BatchSigned,
    /// subject batch seq; hash batch id; hash2 txid; values `[0, 0, 0]`.
    BatchBroadcast,
    /// subject batch seq; hash batch id; hash2 txid; values `[height, reconfirmed, 0]`.
    BatchConfirmed,
    /// subject batch seq; hash batch id; values `[from_state, to_state, 0]`.
    BatchReverted,
    /// subject batch seq; hash batch id; values `[basis, total, 0]`.
    BatchCancelled,
    /// subject batch seq; hash batch id; hash2 conflicting txid; values `[total, 0, 0]`.
    BatchFailed,
}

impl AuditKind {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::SharesPruned => 1,
            Self::RoundRecorded => 2,
            Self::RewardFixed => 3,
            Self::RoundMatured => 4,
            Self::RoundOrphaned => 5,
            Self::RoundRevived => 6,
            Self::PayoutScriptSet => 7,
            Self::BatchPrepared => 8,
            Self::BatchSigned => 9,
            Self::BatchBroadcast => 10,
            Self::BatchConfirmed => 11,
            Self::BatchReverted => 12,
            Self::BatchCancelled => 13,
            Self::BatchFailed => 14,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::SharesPruned),
            2 => Some(Self::RoundRecorded),
            3 => Some(Self::RewardFixed),
            4 => Some(Self::RoundMatured),
            5 => Some(Self::RoundOrphaned),
            6 => Some(Self::RoundRevived),
            7 => Some(Self::PayoutScriptSet),
            8 => Some(Self::BatchPrepared),
            9 => Some(Self::BatchSigned),
            10 => Some(Self::BatchBroadcast),
            11 => Some(Self::BatchConfirmed),
            12 => Some(Self::BatchReverted),
            13 => Some(Self::BatchCancelled),
            14 => Some(Self::BatchFailed),
            _ => None,
        }
    }
}

/// One hash-chained audit record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Monotonic sequence number, starting at 0.
    pub seq: u64,
    /// Record kind.
    pub kind: AuditKind,
    /// Kind-specific subject (round id, account, batch seq).
    pub subject: u64,
    /// Kind-specific hash.
    pub hash: Hash32,
    /// Kind-specific second hash.
    pub hash2: Hash32,
    /// Kind-specific values.
    pub values: [u64; 3],
    /// `SHA-256(domain || previous chain || seq || body)`.
    pub chain: Hash32,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Hash-keyed active-chain membership, independent of tip-height comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockLocation {
    /// This exact block is on the active chain at this height.
    Canonical {
        /// Active-chain height of the queried block hash.
        height: u32,
    },
    /// This known block is not on the active chain.
    Side,
    /// The observer cannot establish the block's membership.
    Unknown,
}

/// Every failure of the ledger.
#[derive(Debug)]
pub enum LedgerError {
    /// Pool configuration violates a bound.
    InvalidConfig(&'static str),
    /// The stored configuration differs from the supplied one.
    ConfigMismatch,
    /// The store has no ledger with a valid schema and revision.
    NotALedger,
    /// `create` refused to overwrite an occupied ledger namespace.
    PathExists,
    /// Backend failure; durability errors can be ambiguous after application.
    Storage(bitcoin_rs_storage::StorageError),
    /// Another ledger handle changed the revision; no effects were applied.
    Conflict,
    /// Stored data failed a decode or consistency check.
    Corrupt(String),
    /// Malformed canonical encoding.
    Codec(&'static str),
    /// Input violated a static bound.
    InvalidInput(&'static str),
    /// Checked arithmetic failed.
    Overflow(&'static str),
    /// No shares to split a reward over.
    EmptyWindow,
    /// The window would need shares that were pruned.
    WindowPruned,
    /// The job was retired; its shares are no longer accepted.
    JobRetired(u64),
    /// Same header hash with different work or identity.
    ShareConflict {
        /// Sequence number of the original credit.
        seq: u64,
    },
    /// Different header hash reusing a `(job, account, extranonce, nonce)` identity.
    ShareIdentityConflict {
        /// Sequence number of the original credit.
        seq: u64,
    },
    /// A referenced share does not exist.
    UnknownShare,
    /// The block is already recorded with a different claim.
    BlockConflict,
    /// No batch with this id.
    UnknownBatch(Hash32),
    /// The requested action is illegal in the batch's state.
    IllegalTransition {
        /// Batch id.
        batch: Hash32,
        /// Current state.
        from: BatchState,
        /// Attempted action.
        action: &'static str,
    },
    /// A signed transaction was refused.
    Receipt(ReceiptError),
    /// The chain observer has not seen the transaction.
    NotObserved(Hash32),
    /// Chain observer failure.
    Chain(ChainViewError),
    /// Signer failure.
    Signer(SignerError),
    /// A ledger invariant is violated.
    Invariant(String),
    /// A test fail plan fired.
    #[cfg(feature = "test-seam")]
    Injected(&'static str),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(m) => write!(f, "invalid pool config: {m}"),
            Self::ConfigMismatch => write!(f, "stored pool config differs from supplied config"),
            Self::NotALedger => write!(f, "store is not a pool accounting ledger"),
            Self::PathExists => write!(f, "ledger namespace already exists"),
            Self::Storage(m) => write!(f, "storage: {m}"),
            Self::Conflict => write!(f, "ledger revision changed; transaction not applied"),
            Self::Corrupt(m) => write!(f, "corrupt ledger: {m}"),
            Self::Codec(m) => write!(f, "codec: {m}"),
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Self::Overflow(m) => write!(f, "arithmetic overflow: {m}"),
            Self::EmptyWindow => write!(f, "no shares in the PPLNS window"),
            Self::WindowPruned => write!(f, "PPLNS window needs pruned shares"),
            Self::JobRetired(job) => write!(f, "job {job} is retired"),
            Self::ShareConflict { seq } => write!(f, "share conflicts with credit {seq}"),
            Self::ShareIdentityConflict { seq } => {
                write!(f, "share identity already used by credit {seq}")
            }
            Self::UnknownShare => write!(f, "unknown share"),
            Self::BlockConflict => write!(f, "block already recorded with a different claim"),
            Self::UnknownBatch(id) => write!(f, "unknown batch {}", to_hex(id)),
            Self::IllegalTransition {
                batch,
                from,
                action,
            } => {
                write!(
                    f,
                    "batch {} in state {from:?} cannot {action}",
                    to_hex(batch)
                )
            }
            Self::Receipt(e) => write!(f, "receipt refused: {e:?}"),
            Self::NotObserved(txid) => write!(f, "transaction {} not observed", to_hex(txid)),
            Self::Chain(e) => write!(f, "{e}"),
            Self::Signer(e) => write!(f, "{e}"),
            Self::Invariant(m) => write!(f, "invariant violated: {m}"),
            #[cfg(feature = "test-seam")]
            Self::Injected(op) => write!(f, "injected failure in {op}"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<ChainViewError> for LedgerError {
    fn from(error: ChainViewError) -> Self {
        Self::Chain(error)
    }
}

impl From<SignerError> for LedgerError {
    fn from(error: SignerError) -> Self {
        Self::Signer(error)
    }
}

impl From<ReceiptError> for LedgerError {
    fn from(error: ReceiptError) -> Self {
        Self::Receipt(error)
    }
}

impl From<bitcoin_rs_storage::StorageError> for LedgerError {
    fn from(error: bitcoin_rs_storage::StorageError) -> Self {
        Self::Storage(error)
    }
}

// ---------------------------------------------------------------------------------------------
// Canonical binary codec (big-endian, length-prefixed)
// ---------------------------------------------------------------------------------------------

pub(crate) mod codec {
    use super::{Hash32, LedgerError};

    pub(crate) struct Enc {
        buf: Vec<u8>,
        overflow: bool,
    }

    impl Enc {
        pub(crate) fn new() -> Self {
            Self {
                buf: Vec::new(),
                overflow: false,
            }
        }

        pub(crate) fn u8(&mut self, value: u8) {
            self.buf.push(value);
        }

        pub(crate) fn u32(&mut self, value: u32) {
            self.buf.extend_from_slice(&value.to_be_bytes());
        }

        pub(crate) fn u64(&mut self, value: u64) {
            self.buf.extend_from_slice(&value.to_be_bytes());
        }

        pub(crate) fn u128(&mut self, value: u128) {
            self.buf.extend_from_slice(&value.to_be_bytes());
        }

        pub(crate) fn hash(&mut self, value: &Hash32) {
            self.buf.extend_from_slice(value);
        }

        pub(crate) fn raw(&mut self, value: &[u8]) {
            self.buf.extend_from_slice(value);
        }

        pub(crate) fn len32(&mut self, len: usize) {
            if let Ok(value) = u32::try_from(len) {
                self.u32(value);
            } else {
                self.overflow = true;
                self.u32(0);
            }
        }

        pub(crate) fn bytes(&mut self, value: &[u8]) {
            self.len32(value.len());
            self.raw(value);
        }

        pub(crate) fn finish(self) -> Result<Vec<u8>, LedgerError> {
            if self.overflow {
                Err(LedgerError::Codec("length exceeds u32"))
            } else {
                Ok(self.buf)
            }
        }
    }

    pub(crate) struct Dec<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Dec<'a> {
        pub(crate) fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], LedgerError> {
            let end = self
                .pos
                .checked_add(n)
                .ok_or(LedgerError::Codec("length overflow"))?;
            let slice = self
                .buf
                .get(self.pos..end)
                .ok_or(LedgerError::Codec("truncated"))?;
            self.pos = end;
            Ok(slice)
        }

        pub(crate) fn u8(&mut self) -> Result<u8, LedgerError> {
            Ok(self.take(1)?[0])
        }

        pub(crate) fn u32(&mut self) -> Result<u32, LedgerError> {
            let bytes: [u8; 4] = self
                .take(4)?
                .try_into()
                .map_err(|_| LedgerError::Codec("truncated"))?;
            Ok(u32::from_be_bytes(bytes))
        }

        pub(crate) fn u64(&mut self) -> Result<u64, LedgerError> {
            let bytes: [u8; 8] = self
                .take(8)?
                .try_into()
                .map_err(|_| LedgerError::Codec("truncated"))?;
            Ok(u64::from_be_bytes(bytes))
        }

        pub(crate) fn u128(&mut self) -> Result<u128, LedgerError> {
            let bytes: [u8; 16] = self
                .take(16)?
                .try_into()
                .map_err(|_| LedgerError::Codec("truncated"))?;
            Ok(u128::from_be_bytes(bytes))
        }

        pub(crate) fn hash(&mut self) -> Result<Hash32, LedgerError> {
            self.take(32)?
                .try_into()
                .map_err(|_| LedgerError::Codec("truncated"))
        }

        /// Length-prefixed bytes, at most `max` long.
        pub(crate) fn bytes(&mut self, max: usize) -> Result<&'a [u8], LedgerError> {
            let len = usize::try_from(self.u32()?).map_err(|_| LedgerError::Codec("length"))?;
            if len > max {
                return Err(LedgerError::Codec("field too long"));
            }
            self.take(len)
        }

        /// Element count, at most `max` and at most what the remaining bytes can hold.
        pub(crate) fn count(
            &mut self,
            max: usize,
            min_item_bytes: usize,
        ) -> Result<usize, LedgerError> {
            let count = usize::try_from(self.u32()?).map_err(|_| LedgerError::Codec("count"))?;
            let remaining = self.buf.len().saturating_sub(self.pos);
            if count > max || count > remaining / min_item_bytes.max(1) {
                return Err(LedgerError::Codec("count too large"));
            }
            Ok(count)
        }

        pub(crate) fn finish(self) -> Result<(), LedgerError> {
            if self.pos == self.buf.len() {
                Ok(())
            } else {
                Err(LedgerError::Codec("trailing bytes"))
            }
        }
    }
}
