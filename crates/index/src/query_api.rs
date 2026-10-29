//! Derived-index query contract: typed errors, progress info, and the
//! object-safe read traits the RPC surface and node composition consume.
//!
//! Strict queries require a durable watermark equal to the applied tip.
//! Historical answers name their interval through [`AtPrefix`](crate::query_api::AtPrefix).
//! `bitcoin_rs_rpc::context` retains its existing strict-query re-exports.

use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, Txid};
use compact_str::CompactString;

use crate::{IndexCapability, ScriptHash};

/// Optional BIP157/158 queries shared by RPC and P2P adapters.
pub trait CompactFilterQuery: Send + Sync {
    /// Reads an active-chain block's basic filter. Unknown/stale hashes return None.
    fn block_filter(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<crate::BasicFilter>, TxQueryError>;
    /// Visits a bounded range from one immutable snapshot, retaining at most
    /// one serialized filter at a time. `step` is 1 or checkpoint interval 1000.
    /// Returns the previous header, or None for invalid/unknown ranges and a
    /// visitor that stopped. A concurrent tip change can return Retry after
    /// delivery; any delivered records still belong to the requested stop chain.
    fn for_each_filter(
        &self,
        start: u32,
        stop: bitcoin_rs_primitives::Hash256,
        step: u32,
        emit: &mut dyn FnMut(bitcoin_rs_primitives::Hash256, crate::BasicFilter) -> bool,
    ) -> Result<Option<[u8; 32]>, TxQueryError>;
    /// Actual durable progress; readiness is never inferred from configuration.
    fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError>;
}

/// Actual progress reported by the node-owned transaction index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedIndexInfo {
    /// Whether the index has completely caught up to the authoritative chain tip.
    pub synced: bool,
    /// Height of the best block completely covered by the index.
    pub best_block_height: u32,
}

/// Failure from a complete transaction-index query.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxQueryError {
    /// The query raced index or chain progress and should be retried.
    #[error("transaction index changed during query; retry")]
    Retry,
    /// The index cannot currently prove a complete answer.
    #[error("transaction index unavailable: {0}")]
    Unavailable(TxUnavailableCause),
    /// Durable index storage failed.
    #[error("transaction index storage error: {0}")]
    Storage(CompactString),
}

/// Why a transaction-index query could not prove a complete answer.
///
/// `Display` reproduces the exact refusal text the crate already emitted, so
/// wire-visible error strings do not change. Matchers MUST use the variant,
/// never the rendered text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxUnavailableCause {
    /// Row scan budget ran out mid-query.
    RowBudgetExhausted,
    /// Row scan budget exceeded.
    RowBudgetExceeded,
    /// Historical prefix scan hit the scan-count cap.
    PrefixScanTruncated,
    /// Live prefix scan hit the scan-count cap.
    LivePrefixScanTruncated,
    /// Body-read count budget ran out.
    BodyReadBudgetExhausted,
    /// Body-byte budget exceeded.
    BodyBudgetExceeded,
    /// Coverage starts at `floor`; the pruned prefix below it is unproven
    /// (txindex and other generic-family refusals).
    PrunedPrefixUnproven { family: &'static str, floor: u32 },
    /// Script-history coverage starts at `floor`; history cannot be
    /// proven complete below it.
    HistoryUnproven { floor: u32 },
    /// A required capability is disabled in this engine.
    CapabilityDisabled(IndexCapability),
    /// The index worker reported a failure.
    WorkerFailed(CompactString),
    /// The index worker stopped.
    WorkerStopped,
    /// The compact-filter worker reported a failure.
    CompactFilterFailed(CompactString),
    /// The `ScriptLive` view is unavailable while its scoped seed/replay outage persists.
    /// Carries the stored worker reason verbatim; no new wire text beyond that reason.
    ScriptLiveUnavailable(CompactString),
    /// A required authority handle is absent (UTXO view, chain-transition lock,
    /// `ScriptLive` locator). `detail` is the existing static refusal text.
    MissingAuthority(&'static str),
    /// Block body bytes could not be read at `height`.
    BlockBodyMissing { height: u32 },
    /// Compact filter data row is missing.
    FilterDataMissing,
    /// Unavailability with no dedicated variant: index lifecycle states
    /// (opening, abandoned at shutdown), RPC helpers, and test fakes.
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

/// Server-selected covered prefix proving a historical answer.
///
/// `floor` is the lowest provable height (`0` means genesis, positive means a
/// pruned prefix). `height` is the anchor height and `hash` the full chain
/// hash at that height on `chain(anchor)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoveredPrefix {
    /// Lowest provable height for this call.
    pub floor: u32,
    /// Anchor height: the common covered ancestor.
    pub height: u32,
    /// Full chain hash at the anchor height.
    pub hash: Hash256,
}

/// Historical answer qualified by the prefix it was proven against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtPrefix<T> {
    /// Prefix the answer was proven against.
    pub prefix: CoveredPrefix,
    /// Confirmed-only answer scoped to `[floor, anchor]` on `chain(anchor)`.
    pub answer: T,
}

/// Failure from a server-selected historical query.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HistoricalQueryError {
    /// The query raced chain or index progress and should be retried.
    #[error("historical index query raced chain or index progress; retry")]
    Retry,
    /// The historical query cannot currently prove a complete answer.
    #[error("historical index query unavailable: {0}")]
    Unavailable(HistoricalUnavailableCause),
    /// Durable index storage failed.
    #[error("historical index storage error: {0}")]
    Storage(CompactString),
}

/// Why a historical query could not prove a complete answer.
///
/// Matchers MUST use the variant, never the rendered text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoricalUnavailableCause {
    /// Wrapped exact-tip cause: row, scan, body, capability, worker,
    /// lifecycle, and pruned-prefix refusals keep their identical variant.
    Shared(TxUnavailableCause),
    /// A required watermark is absent in the snapshot (reset claim or
    /// rebuild in progress). Unavailable so rebuilds do not spin on `Retry`.
    NoCoveredPrefix {
        /// Capability whose watermark is absent.
        capability: IndexCapability,
    },
    /// A required watermark names a stale branch deeper than the shared
    /// bounded ancestry budget. Present but too deep, distinct from absent.
    AncestryBudgetExhausted {
        /// Capability whose watermark is too deep.
        capability: IndexCapability,
        /// Watermark height that could not be joined within budget.
        watermark_height: u32,
    },
    /// The derived anchor lies below the maximum consumed floor.
    PrefixBelowFloor {
        /// Maximum consumed floor for the call.
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

/// Lockless read-only adapter for complete transaction-index queries.
pub trait DerivedIndexQuery: Send + Sync {
    /// Resolves a confirmed transaction, returning `None` only after complete absence is proven.
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError>;
    /// Resolves a confirmed prevout value, returning `None` only after complete absence is proven.
    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError>;
    /// Resolves the height of the block confirming `txid`, without materializing the transaction.
    ///
    /// Callers that only need to locate the block — `gettxoutproof` is the one —
    /// would otherwise deserialize a transaction and throw it away. The default
    /// answers `None`, which every caller must already handle as "the index
    /// cannot say", so an implementor that does not track heights keeps working.
    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        let _ = txid;
        Ok(None)
    }
    /// Returns the transaction index's actual durable progress.
    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError>;
}

/// One current unspent output indexed for a script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptIndexRecord {
    /// Transaction creating the output.
    pub txid: Txid,
    /// Confirmed block height.
    pub height: u32,
    /// Output value in satoshis.
    pub value: u64,
    /// Output index.
    pub vout: u32,
}

/// One confirmed transaction in script history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptHistoryRecord {
    /// Transaction identifier.
    pub txid: Txid,
    /// Confirming block height.
    pub height: u32,
}

/// One confirmed transaction spending an indexed outpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendingRecord {
    /// Spending transaction identifier.
    pub txid: Txid,
    /// Confirming block height.
    pub height: u32,
    /// Input index that spends the outpoint.
    pub vin: u32,
}

/// A point-in-time script-history answer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScriptIndexSnapshot {
    /// All confirmed funding and spending transactions for the script.
    pub history: Vec<ScriptHistoryRecord>,
    /// Every confirmed output paying the script, spent ones included.
    ///
    /// Carried out of the same budgeted storage snapshot that produced
    /// `history`. Address statistics are sums over these rows; a caller without
    /// them has to re-read one transaction per history entry, and each of those
    /// reads is a fresh index query with its own budget, so the total escapes
    /// the bound this snapshot is taken under.
    pub funding: Vec<ScriptIndexRecord>,
}

/// Lockless query adapter for the node-owned generic script index.
///
/// A result is returned only when the script-index watermark proves coverage
/// of the exact applied tip.  `Retry` and `Unavailable` therefore never mean
/// an empty address.
/// Read-only source of rollback-evidence warnings for the RPC chain projection.
pub trait RollbackWarningSource: Send + Sync {
    /// Returns rendered warnings in deterministic order.
    fn rollback_warnings(&self) -> Vec<String>;
}

/// Read-side script-index queries against the derived index.
///
/// Implementors serve confirmed history, mempool deltas, and live UTXO
/// snapshots for a script hash; results are only authoritative when the
/// script-index watermark covers the queried tip.
pub trait ScriptIndexQuery: Send + Sync {
    /// Returns current UTXOs for a script.
    fn unspent_outputs(
        &self,
        script_hash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError>;
    /// Returns confirmed history from one storage snapshot.
    fn history_snapshot(
        &self,
        script_hash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError>;
    /// Returns confirmed history records from one storage snapshot.
    fn confirmed_history(
        &self,
        script_hash: ScriptHash,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        Ok(self.history_snapshot(script_hash)?.history)
    }
    /// Returns the confirmed transaction spending `outpoint`, if any.
    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError>;
}

#[cfg(test)]
mod tests;
