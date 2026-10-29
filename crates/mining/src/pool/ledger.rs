//! Durable PPLNS accounting with an external wallet signer boundary.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};

mod kv;
mod store;

pub use store::*;

pub type Hash32 = [u8; 32];

pub const MAX_MONEY_SAT: u64 = 2_100_000_000_000_000;
pub const MAX_EXTRANONCE_LEN: usize = 64;
/// Fixed-width prefix of [`ShareCredit::tuple_key`]: job, account, nonce, version, ntime.
const SHARE_TUPLE_FIXED_LEN: usize = 8 + 8 + 4 + 4 + 4;
pub(crate) const MAX_SHARE_TUPLE_LEN: usize = SHARE_TUPLE_FIXED_LEN + MAX_EXTRANONCE_LEN;
pub const MAX_SCRIPT_LEN: usize = 10_000;
pub const MAX_RAW_TX_BYTES: usize = 4_000_000;
pub const MAX_BATCH_OUTPUTS: usize = 2_500;
pub const MAX_STANDARD_TX_WEIGHT_WU: u64 = 400_000;
pub const PAYOUT_TX_HEADROOM_WU: u64 = 10_000;
pub const MAX_PAYOUT_OUTPUT_WEIGHT_WU: u64 = MAX_STANDARD_TX_WEIGHT_WU - PAYOUT_TX_HEADROOM_WU;
pub const MAX_CHANGE_OUTPUTS: usize = 1;
pub const MAX_CHANGE_SCRIPTS: usize = 16;

const OP_RETURN: u8 = 0x6a;
const BATCH_ID_DOMAIN: &[u8] = b"btcrs.pool.payout-batch.v1";
const REQUEST_MAGIC: &[u8; 4] = b"BRPR";
const RECEIPT_MAGIC: &[u8; 4] = b"BRPT";
const WIRE_VERSION: u8 = 1;

#[must_use]
pub fn sha256(data: &[u8]) -> Hash32 {
    Sha256::digest(data).into()
}

#[must_use]
pub fn sha256d(data: &[u8]) -> Hash32 {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MinerId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareCredit {
    pub header_hash: Hash32,
    pub job: u64,
    pub account: MinerId,
    pub extranonce: Vec<u8>,
    pub nonce: u32,
    pub version: i32,
    pub ntime: u32,
    pub work: u128,
}

impl ShareCredit {
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.work == 0 {
            return Err(LedgerError::InvalidInput("share work must be at least 1"));
        }
        if self.extranonce.len() > MAX_EXTRANONCE_LEN {
            return Err(LedgerError::InvalidInput("extranonce too long"));
        }
        Ok(())
    }

    #[must_use]
    pub fn tuple_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(SHARE_TUPLE_FIXED_LEN + self.extranonce.len());
        key.extend_from_slice(&self.job.to_be_bytes());
        key.extend_from_slice(&self.account.0.to_be_bytes());
        key.extend_from_slice(&self.nonce.to_be_bytes());
        key.extend_from_slice(&self.version.to_be_bytes());
        key.extend_from_slice(&self.ntime.to_be_bytes());
        key.extend_from_slice(&self.extranonce);
        key
    }
}

pub fn work_from_le_bytes(le: [u8; 32]) -> Result<u128, LedgerError> {
    let (low, high) = le.split_at(16);
    if high.iter().any(|byte| *byte != 0) {
        return Err(LedgerError::Overflow("share work exceeds 2^128"));
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(low);
    Ok(u128::from_le_bytes(buf))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFound {
    pub share: ShareCredit,
    pub height: u32,
    pub coinbase_txid: Hash32,
    pub claimed_coinbase_value_sat: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareReceipt {
    Credited { seq: u64 },
    Duplicate { seq: u64 },
}

impl ShareReceipt {
    #[must_use]
    pub fn seq(self) -> u64 {
        match self {
            Self::Credited { seq } | Self::Duplicate { seq } => seq,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub window_work: u128,
    pub pool_fee_bps: u16,
    pub coinbase_maturity: u32,
    pub payout_confirmations: u32,
    pub abandon_confirmations: u32,
    pub reorg_watch_depth: u32,
    pub dust_limit_sat: u64,
    pub pool_coinbase_script: Vec<u8>,
    pub change_scripts: Vec<Vec<u8>>,
}

impl PoolConfig {
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

    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        self.validate()?;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundState {
    Pending,
    Immature,
    Matured,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round {
    pub id: u64,
    pub block_hash: Hash32,
    pub height: u32,
    pub solving_seq: u64,
    pub coinbase_txid: Hash32,
    pub claimed_coinbase_value_sat: u64,
    pub window_work_total: u128,
    pub reward_fixed: bool,
    pub gross_sat: u64,
    pub pool_fee_sat: u64,
    pub net_sat: u64,
    pub state: RoundState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecorded {
    pub round: Round,
    pub share: ShareReceipt,
    pub newly_recorded: bool,
}

/// Account balance. Invariant: `available + reserved + paid - deficit == credited allocations`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub available_sat: u64,
    pub reserved_sat: u64,
    pub paid_sat: u64,
    pub deficit_sat: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundTransition {
    pub round: u64,
    pub from: RoundState,
    pub to: RoundState,
    pub credited_sat: u64,
    pub reversed_sat: u64,
    pub deficit_created_sat: u64,
}

/// Split a gross reward into `(pool_fee, net)`; the fee rounds down so miners get the remainder.
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

#[derive(Clone, Debug)]
pub struct WindowAccumulator {
    target: u128,
    total: u128,
    by_account: BTreeMap<MinerId, u128>,
}

impl WindowAccumulator {
    #[must_use]
    pub fn new(target: u128) -> Self {
        Self {
            target,
            total: 0,
            by_account: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.total >= self.target
    }

    #[must_use]
    pub fn total(&self) -> u128 {
        self.total
    }

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

    #[must_use]
    pub fn into_weights(self) -> Vec<(MinerId, u128)> {
        self.by_account.into_iter().collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    pub txid: Hash32,
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxParseError {
    Truncated,
    TrailingBytes,
    NonCanonicalVarint,
    NoInputs,
    NoOutputs,
    BadWitnessFlag,
    SuperfluousWitness,
    TooLarge,
    ValueOutOfRange,
    CountTooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransaction {
    pub txid: Hash32,
    pub version: i32,
    pub lock_time: u32,
    pub has_witness: bool,
    pub inputs: Vec<OutPoint>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutOutput {
    pub account: MinerId,
    pub script_pubkey: Vec<u8>,
    pub amount_sat: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutRequest {
    pub batch_id: Hash32,
    pub outputs: Vec<PayoutOutput>,
    pub total_sat: u64,
    pub allowed_change_scripts: Vec<Vec<u8>>,
}

#[must_use]
pub fn payout_output_weight_wu(script_len: usize) -> u64 {
    let prefix = if script_len <= 0xfc {
        1u64
    } else if script_len <= 0xffff {
        3u64
    } else if script_len <= 0xffff_ffff {
        5u64
    } else {
        9u64
    };
    let len = u64::try_from(script_len).unwrap_or(u64::MAX);
    let serialized = prefix
        .checked_add(len)
        .and_then(|sum| sum.checked_add(8))
        .unwrap_or(u64::MAX);
    serialized.checked_mul(4).unwrap_or(u64::MAX)
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
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let total = check_outputs(&self.outputs)?;
        if total != self.total_sat {
            return Err(LedgerError::InvalidInput(
                "request total does not match outputs",
            ));
        }
        if self.allowed_change_scripts.len() > MAX_CHANGE_SCRIPTS {
            return Err(LedgerError::InvalidInput("too many change scripts"));
        }
        for script in &self.allowed_change_scripts {
            validate_script(script)?;
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

    pub fn digest(&self) -> Result<Hash32, LedgerError> {
        Ok(sha256(&self.encode()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutReceipt {
    pub batch_id: Hash32,
    pub txid: Hash32,
    pub raw_tx: Vec<u8>,
}

impl PayoutReceipt {
    /// Canonical wire form: `"BRPT" | 0x01 | batch_id | txid | raw_len u32 | raw_tx`.
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

pub trait ExternalSigner {
    fn sign(&self, request: &PayoutRequest) -> Result<PayoutReceipt, SignerError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerError(pub String);

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "external signer: {}", self.0)
    }
}

impl std::error::Error for SignerError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    Parse(TxParseError),
    TxidMismatch,
    NoInputs,
    NullPrevout,
    DuplicateInput,
    MissingOutput { index: usize },
    UnexpectedOutput { index: usize },
    TooManyExtraOutputs,
    TxidInOtherBatch,
    NotConflicting { existing_txid: Hash32 },
}

impl From<TxParseError> for ReceiptError {
    fn from(error: TxParseError) -> Self {
        Self::Parse(error)
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchState {
    Prepared,
    ExternallySigned,
    Broadcast,
    Confirmed,
    Cancelled,
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

    #[must_use]
    pub fn holds_reservation(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::ExternallySigned | Self::Broadcast
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    pub txid: Hash32,
    pub inputs: Vec<OutPoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmation {
    pub txid: Hash32,
    pub block_hash: Hash32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelBasis {
    NeverHandedToSigner,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closure {
    Cancelled(CancelBasis),
    Failed { conflicting_txid: Hash32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutPolicy {
    pub min_payout_sat: u64,
    pub max_outputs: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutBatch {
    pub id: Hash32,
    pub seq: u64,
    pub idempotency_key: Hash32,
    pub state: BatchState,
    pub rev: u64,
    pub outputs: Vec<PayoutOutput>,
    pub total_sat: u64,
    pub transactions: Vec<SignedTx>,
    pub broadcast_txid: Option<Hash32>,
    pub confirmation: Option<Confirmation>,
    pub closure: Option<Closure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchTransition {
    pub batch_id: Hash32,
    pub from: BatchState,
    pub to: BatchState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainViewError(pub String);

impl fmt::Display for ChainViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chain view: {}", self.0)
    }
}

impl std::error::Error for ChainViewError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedCoinbase {
    pub txid: Hash32,
    pub outputs: Vec<TxOut>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Unknown,
    InMempool,
    Confirmed { block_hash: Hash32, height: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedSpend {
    pub spender_txid: Hash32,
    pub block_hash: Hash32,
    pub height: u32,
}

/// Authoritative observations of the ACTIVE chain. The ledger decides block, maturity, reorg and
/// confirmation state only from these answers, never from job flags or submission receipts.
pub trait ChainView {
    fn tip_height(&self) -> Result<u32, ChainViewError>;

    fn block_location(
        &self,
        block_hash: &Hash32,
        claimed_height: u32,
    ) -> Result<BlockLocation, ChainViewError>;

    fn coinbase_of(&self, block_hash: &Hash32) -> Result<Option<ObservedCoinbase>, ChainViewError>;

    fn tx_status(&self, txid: &Hash32) -> Result<TxStatus, ChainViewError>;

    fn confirmed_spender(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<ConfirmedSpend>, ChainViewError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    SharesPruned,
    RoundRecorded,
    RewardFixed,
    RoundMatured,
    RoundOrphaned,
    RoundRevived,
    PayoutScriptSet,
    BatchPrepared,
    BatchSigned,
    BatchBroadcast,
    BatchConfirmed,
    BatchReverted,
    BatchCancelled,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub kind: AuditKind,
    pub subject: u64,
    pub hash: Hash32,
    pub hash2: Hash32,
    pub values: [u64; 3],
    pub chain: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockLocation {
    Canonical { height: u32 },
    Side,
    Unknown,
}

#[derive(Debug)]
pub enum LedgerError {
    InvalidConfig(&'static str),
    ConfigMismatch,
    NotALedger,
    PathExists,
    Storage(bitcoin_rs_storage::StorageError),
    Conflict,
    Corrupt(String),
    Codec(&'static str),
    InvalidInput(&'static str),
    Overflow(&'static str),
    EmptyWindow,
    WindowPruned,
    JobRetired(u64),
    ShareConflict {
        seq: u64,
    },
    ShareIdentityConflict {
        seq: u64,
    },
    UnknownShare,
    BlockConflict,
    UnknownBatch(Hash32),
    IllegalTransition {
        batch: Hash32,
        from: BatchState,
        action: &'static str,
    },
    Receipt(ReceiptError),
    NotObserved(Hash32),
    Chain(ChainViewError),
    Signer(SignerError),
    Invariant(String),
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

impl LedgerError {
    /// True for share-crediting failures no retry can cure: the job is retired, the
    /// header hash or secondary identity is already taken, or the block is already
    /// recorded with a different claim.
    ///
    /// Protocol adapters must report these as rejected shares, never as a
    #[must_use]
    pub fn is_permanent_share_conflict(&self) -> bool {
        matches!(
            self,
            Self::JobRetired(_)
                | Self::ShareConflict { .. }
                | Self::ShareIdentityConflict { .. }
                | Self::BlockConflict
        )
    }
}

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

        pub(crate) fn bytes(&mut self, max: usize) -> Result<&'a [u8], LedgerError> {
            let len = usize::try_from(self.u32()?).map_err(|_| LedgerError::Codec("length"))?;
            if len > max {
                return Err(LedgerError::Codec("field too long"));
            }
            self.take(len)
        }

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
