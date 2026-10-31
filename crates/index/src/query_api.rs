//! Derived-index query contract: typed errors, progress info, and the
//! object-safe read traits the RPC surface and node composition consume.

use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, Txid};
use compact_str::CompactString;

use crate::{IndexCapability, ScriptHash};

/// Optional BIP157/158 queries shared by RPC and P2P adapters.
pub trait CompactFilterQuery: Send + Sync {
    fn block_filter(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<crate::BasicFilter>, TxQueryError>;
    fn for_each_filter(
        &self,
        start: u32,
        stop: bitcoin_rs_primitives::Hash256,
        step: u32,
        emit: &mut dyn FnMut(bitcoin_rs_primitives::Hash256, crate::BasicFilter) -> bool,
    ) -> Result<Option<[u8; 32]>, TxQueryError>;
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedIndexInfo {
    pub synced: bool,
    pub best_block_height: u32,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxQueryError {
    #[error("transaction index changed during query; retry")]
    Retry,
    #[error("transaction index unavailable: {0}")]
    Unavailable(TxUnavailableCause),
    #[error("transaction index storage error: {0}")]
    Storage(CompactString),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxUnavailableCause {
    RowBudgetExhausted,
    RowBudgetExceeded,
    PrefixScanTruncated,
    LivePrefixScanTruncated,
    BodyReadBudgetExhausted,
    BodyBudgetExceeded,
    PrunedPrefixUnproven {
        family: &'static str,
        floor: u32,
    },
    HistoryUnproven {
        floor: u32,
    },
    CapabilityDisabled(IndexCapability),
    WorkerFailed(CompactString),
    WorkerStopped,
    CompactFilterFailed(CompactString),
    /// Carries the stored worker reason verbatim; no new wire text beyond that reason.
    ScriptLiveUnavailable(CompactString),
    MissingAuthority(&'static str),
    BlockBodyMissing {
        height: u32,
    },
    FilterDataMissing,
    Other(CompactString),
}

impl core::fmt::Display for TxUnavailableCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RowBudgetExhausted => f.write_str("txindex query work budget exhausted"),
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
            Self::CapabilityDisabled(capability) => f.write_str(capability.disabled_message()),
            Self::WorkerFailed(message)
            | Self::CompactFilterFailed(message)
            | Self::ScriptLiveUnavailable(message)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtPrefix<T> {
    pub prefix: CoveredPrefix,
    pub answer: T,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HistoricalQueryError {
    #[error("historical index query raced chain or index progress; retry")]
    Retry,
    #[error("historical index query unavailable: {0}")]
    Unavailable(HistoricalUnavailableCause),
    #[error("historical index storage error: {0}")]
    Storage(CompactString),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoricalUnavailableCause {
    /// lifecycle, and pruned-prefix refusals keep their identical variant.
    Shared(TxUnavailableCause),
    NoCoveredPrefix {
        capability: IndexCapability,
    },
    AncestryBudgetExhausted {
        capability: IndexCapability,
        watermark_height: u32,
    },
    PrefixBelowFloor {
        floor: u32,
    },
}

impl core::fmt::Display for HistoricalUnavailableCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shared(cause) => core::fmt::Display::fmt(cause, f),
            Self::NoCoveredPrefix { capability } => write!(
                f,
                "historical index has no covered prefix for {}",
                capability.name()
            ),
            Self::AncestryBudgetExhausted {
                capability,
                watermark_height,
            } => write!(
                f,
                "historical index ancestry budget exhausted for {} at height {watermark_height}",
                capability.name()
            ),
            Self::PrefixBelowFloor { floor } => {
                write!(f, "historical index prefix below floor {floor}")
            }
        }
    }
}

pub trait DerivedIndexQuery: Send + Sync {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError>;
    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError>;
    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
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

/// Largest page the index returns, independent of the caller's request.
pub const SCRIPT_HISTORY_PAGE_MAX: usize = 100;

/// One bounded newest-first confirmed-history page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScriptHistoryPage {
    /// At most the caller-requested number of records, newest first.
    pub records: Vec<ScriptHistoryRecord>,
    /// Whether the supplied cursor named an exact occurrence of this script.
    /// A false value preserves API-09 by returning the first page.
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
    /// Returns one bounded newest-first page strictly after `cursor`.
    ///
    /// `cursor` is an API-09 transaction id. The default implementation orders
    /// complete history by `(height, txid)` descending and skips the cursor's
    /// first occurrence, so a page never repeats the cursor itself.
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
        history.dedup_by(|left, right| left.txid == right.txid && left.height == right.height);
        let start = cursor.and_then(|txid| history.iter().position(|record| record.txid == txid));
        let cursor_found = cursor.is_none() || start.is_some();
        Ok(ScriptHistoryPage {
            records: history
                .into_iter()
                .skip(start.map_or(0, |index| index + 1))
                .take(limit)
                .collect(),
            cursor_found,
        })
    }
    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError>;
}

#[cfg(test)]
mod tests;
