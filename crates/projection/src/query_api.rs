use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Tx, Txid};
use compact_str::CompactString;

use crate::{IndexCapability, ScriptHash};

pub trait CompactFilterQuery: Send + Sync {
    fn block_filter(
        &self,
        hash: bitcoin_rs_consensus::primitives::Hash256,
    ) -> Result<Option<crate::BasicFilter>, TxQueryError>;
    fn for_each_filter(
        &self,
        start: u32,
        stop: bitcoin_rs_consensus::primitives::Hash256,
        step: u32,
        emit: &mut dyn FnMut(bitcoin_rs_consensus::primitives::Hash256, crate::BasicFilter) -> bool,
    ) -> Result<Option<[u8; 32]>, TxQueryError>;
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError>;
}

// PRJ-13
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedIndexInfo {
    pub synced: bool,
    pub best_block_height: u32,
    pub applied_height: u32,
    pub historical_height: u32,
    pub verified_height: u32,
    pub coverage_height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryReason {
    TipMoved {
        expected_commit: u64,
        current_commit: u64,
    },
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxQueryError {
    #[error("transaction index changed during query; retry")]
    Retry(RetryReason),
    #[error("transaction index unavailable: {0}")]
    Unavailable(TxUnavailableCause),
    #[error("serving view expired due to generation retirement")]
    ExpiredView,
    #[error("transaction index storage error: {0}")]
    Storage(CompactString),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxUnavailableCause {
    ScriptHashLimitExceeded { limit: usize },
    RowBudgetExhausted,
    NodeBudgetExhausted,
    RowBudgetExceeded,
    PrefixScanTruncated,
    LivePrefixScanTruncated,
    BodyReadBudgetExhausted,
    BodyBudgetExceeded,
    PrunedPrefixUnproven { family: &'static str, floor: u32 },
    HistoryUnproven { floor: u32 },
    OutsideCoverage { declared_floor_or_tip: u32 },
    CapabilityDisabled(IndexCapability),
    CapabilityUnpublished(IndexCapability),
    WorkerFailed(CompactString),
    WorkerStopped,
    CompactFilterFailed(CompactString),
    ScriptLiveUnavailable(CompactString),
    ScriptHistoryUnavailable(CompactString),
    MissingAuthority(&'static str),
    BlockBodyMissing { height: u32 },
    FilterDataMissing,
    Other(CompactString),
}

impl core::fmt::Display for TxUnavailableCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ScriptHashLimitExceeded { limit } => {
                write!(f, "scripthash limit exceeded ({limit} entries)")
            }
            Self::RowBudgetExhausted => f.write_str("txindex query work budget exhausted"),
            Self::NodeBudgetExhausted => f.write_str("txindex node budget exhausted"),
            Self::RowBudgetExceeded => f.write_str("txindex query work budget exceeded"),
            Self::PrefixScanTruncated => f.write_str("txindex prefix scan truncated"),
            Self::LivePrefixScanTruncated => f.write_str("txindex live prefix scan truncated"),
            Self::BodyReadBudgetExhausted => f.write_str("txindex query body budget exhausted"),
            Self::BodyBudgetExceeded => f.write_str("txindex query body budget exceeded"),
            Self::PrunedPrefixUnproven { family, floor } => write!(
                f,
                "{family} coverage starts at height {floor}; the pruned prefix is unproven"
            ),
            Self::HistoryUnproven { floor } => write!(
                f,
                "script history coverage starts at height {floor}; history cannot be proven complete"
            ),
            Self::OutsideCoverage {
                declared_floor_or_tip,
            } => write!(
                f,
                "requested data is outside declared coverage ending at height {declared_floor_or_tip}"
            ),
            Self::CapabilityDisabled(capability) => f.write_str(capability.disabled_message()),
            Self::CapabilityUnpublished(capability) => write!(
                f,
                "{} index has no published generation yet",
                capability.name()
            ),
            Self::WorkerFailed(message)
            | Self::CompactFilterFailed(message)
            | Self::ScriptLiveUnavailable(message)
            | Self::ScriptHistoryUnavailable(message)
            | Self::Other(message) => f.write_str(message),
            Self::WorkerStopped => f.write_str("txindex worker stopped"),
            Self::MissingAuthority(detail) => f.write_str(detail),
            Self::BlockBodyMissing { height } => {
                write!(f, "block body missing for txindex query at height {height}")
            }
            Self::FilterDataMissing => f.write_str("compact filter data is missing"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoveredPrefix {
    pub floor: u32,
    pub height: u32,
    pub hash: Hash256,
}

/// Chain identity of one applied epoch, captured once per read (`QRY-01`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppliedEpoch {
    pub hash: Hash256,
    pub height: u32,
    pub commit_id: u64,
}

/// Declared, complete coverage of one index capability (`QRY-05`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityCoverage {
    pub floor: u32,
    pub last_height: u32,
    pub last_hash: Hash256,
}

/// Provenance of the chain history an answer was built from (`QRY-04`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationState {
    ChainVerified,
    AssumedHistory {
        verified_height: u32,
        verified_hash: Hash256,
    },
}

/// Why a request cannot produce a value (`QRY-05`, `QRY-06`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryMiss {
    Absent,
    Unavailable {
        capability: IndexCapability,
        declared_floor_or_tip: u32,
    },
    ExpiredView,
}

impl QueryMiss {
    /// Maps a miss to a scoped result: `Absent` inside coverage produces `Ok(None)`,
    /// while `Unavailable` and `ExpiredView` produce the corresponding errors (`QRY-05`, `QRY-06`).
    pub const fn into_scoped<T>(self) -> Result<Option<T>, TxQueryError> {
        match self {
            Self::Absent => Ok(None),
            Self::Unavailable {
                declared_floor_or_tip,
                ..
            } => Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip,
                },
            )),
            Self::ExpiredView => Err(TxQueryError::ExpiredView),
        }
    }
}

impl<T> From<QueryMiss> for Result<Option<T>, TxQueryError> {
    fn from(miss: QueryMiss) -> Self {
        miss.into_scoped()
    }
}

impl TryFrom<QueryMiss> for TxQueryError {
    type Error = ();

    fn try_from(miss: QueryMiss) -> Result<Self, Self::Error> {
        match miss {
            QueryMiss::Absent => Err(()),
            QueryMiss::Unavailable {
                declared_floor_or_tip,
                ..
            } => Ok(Self::Unavailable(TxUnavailableCause::OutsideCoverage {
                declared_floor_or_tip,
            })),
            QueryMiss::ExpiredView => Ok(Self::ExpiredView),
        }
    }
}

/// A query result with its serving-view provenance (`QRY-04`). The external
/// JSON-RPC, REST, and Esplora adapters strip every field except `value`;
/// the embed API returns it whole.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Answer<T> {
    pub value: T,
    pub block_hash: Hash256,
    pub height: u32,
    pub coverage: CoveredPrefix,
    pub verification_state: VerificationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionBlock {
    pub height: u32,
    pub hash: Hash256,
}

pub trait DerivedIndexQuery: Send + Sync {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError>;
    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError>;
    fn transaction_block(
        &self,
        txid: &Txid,
    ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
        let _ = txid;
        Ok(None)
    }
    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptIndexRecord {
    pub txid: Txid,
    pub height: u32,
    pub value: u64,
    pub vout: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptHistoryRecord {
    pub txid: Txid,
    pub height: u32,
}

pub const SCRIPT_HISTORY_PAGE_MAX: usize = 100;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScriptHistoryPage {
    pub records: Vec<ScriptHistoryRecord>,
    pub cursor_found: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendingRecord {
    pub txid: Txid,
    pub height: u32,
    pub vin: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScriptIndexSnapshot {
    pub history: Vec<ScriptHistoryRecord>,
    pub funding: Vec<ScriptIndexRecord>,
}

pub trait RollbackWarningSource: Send + Sync {
    fn rollback_warnings(&self) -> Vec<String>;
}

pub trait ScriptIndexQuery: Send + Sync {
    /// Newest first, exclusive txid cursor. An unknown cursor starts at the tip.
    fn history_page(
        &self,
        script_hash: ScriptHash,
        last: Option<Txid>,
        limit: usize,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        Ok(self
            .confirmed_history_page(script_hash, last, limit)?
            .records)
    }
    fn unspent_outputs(
        &self,
        script_hash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError>;
    fn history_snapshot(
        &self,
        script_hash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError>;
    fn confirmed_history(
        &self,
        script_hash: ScriptHash,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        Ok(self.history_snapshot(script_hash)?.history)
    }
    fn confirmed_history_page(
        &self,
        script_hash: ScriptHash,
        cursor: Option<Txid>,
        limit: usize,
    ) -> Result<ScriptHistoryPage, TxQueryError> {
        let mut history = self.confirmed_history(script_hash)?;
        history.sort_by(|left, right| {
            right
                .height
                .cmp(&left.height)
                .then_with(|| right.txid.cmp(&left.txid))
        });
        let mut listed: Vec<ScriptHistoryRecord> = Vec::with_capacity(history.len());
        let mut seen = std::collections::BTreeSet::<Txid>::new();
        for record in history {
            if !seen.insert(record.txid) {
                continue;
            }
            listed.push(record);
        }
        let start = cursor.and_then(|txid| listed.iter().position(|record| record.txid == txid));
        let cursor_found = cursor.is_none() || start.is_some();
        Ok(ScriptHistoryPage {
            records: listed
                .into_iter()
                .skip(start.map_or(0, |index| index + 1))
                .take(limit.min(SCRIPT_HISTORY_PAGE_MAX))
                .collect(),
            cursor_found,
        })
    }
    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError>;
}

#[cfg(test)]
mod tests;
