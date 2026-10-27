//! Derived-index query contract: typed errors, progress info, and the
//! object-safe read traits the RPC surface and node composition consume.
//!
//! These are index-owned contracts — answers are complete only at a durable
//! watermark equal to the applied tip. `bitcoin_rs_rpc::context` re-exports
//! them under its historical paths.

use bitcoin_rs_primitives::{OutPoint, Tx, Txid};
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

/// One bounded newest-first confirmed-history page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScriptHistoryPage {
    /// At most the caller-requested number of unique transaction ids.
    pub records: Vec<ScriptHistoryRecord>,
    /// Whether the supplied cursor was an exact active-history occurrence.
    /// A false value preserves API-09 by returning the first page.
    pub cursor_found: bool,
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
    /// Returns a bounded newest-first page after `cursor`.
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
        let start = cursor.and_then(|txid| history.iter().position(|record| record.txid == txid));
        let mut emitted = std::collections::HashSet::new();
        Ok(ScriptHistoryPage {
            records: history
                .into_iter()
                .skip(start.map_or(0, |index| index + 1))
                .filter(|record| emitted.insert(record.txid))
                .take(limit)
                .collect(),
            cursor_found: cursor.is_none() || start.is_some(),
        })
    }
    /// Returns the confirmed transaction spending `outpoint`, if any.
    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the byte-identical wire-text constraint: every
    /// variant must render the exact refusal text the crate emitted before
    /// the typed-cause retag. A later edit that drifts wire text fails here.
    fn assert_renders(cases: Vec<(TxUnavailableCause, &str)>) {
        for (cause, expected) in cases {
            assert_eq!(cause.to_string(), expected, "{cause:?}");
        }
    }

    #[test]
    fn fixed_unavailable_causes_render_pinned_wire_text() {
        assert_renders(vec![
            (
                TxUnavailableCause::RowBudgetExhausted,
                "txindex query work budget exhausted",
            ),
            (
                TxUnavailableCause::RowBudgetExceeded,
                "txindex query work budget exceeded",
            ),
            (
                TxUnavailableCause::PrefixScanTruncated,
                "txindex prefix scan truncated",
            ),
            (
                TxUnavailableCause::LivePrefixScanTruncated,
                "txindex live prefix scan truncated",
            ),
            (
                TxUnavailableCause::BodyReadBudgetExhausted,
                "txindex query body budget exhausted",
            ),
            (
                TxUnavailableCause::BodyBudgetExceeded,
                "txindex query body budget exceeded",
            ),
            (TxUnavailableCause::WorkerStopped, "txindex worker stopped"),
            (
                TxUnavailableCause::FilterDataMissing,
                "compact filter data is missing",
            ),
            (
                TxUnavailableCause::CapabilityDisabled(IndexCapability::TxLookup),
                "txindex is disabled",
            ),
            (
                TxUnavailableCause::CapabilityDisabled(IndexCapability::ScriptHistory),
                "script history is disabled",
            ),
            (
                TxUnavailableCause::CapabilityDisabled(IndexCapability::ScriptLive),
                "script live is disabled",
            ),
            (
                TxUnavailableCause::CapabilityDisabled(IndexCapability::CompactFilters),
                "blockfilterindex is disabled",
            ),
        ]);
    }

    #[test]
    fn carried_unavailable_causes_render_pinned_wire_text() {
        assert_renders(vec![
            (
                TxUnavailableCause::PrunedPrefixUnproven {
                    family: "transaction index",
                    floor: 100,
                },
                "transaction index coverage starts at height 100; the pruned prefix is unproven",
            ),
            (
                TxUnavailableCause::PrunedPrefixUnproven {
                    family: "script history",
                    floor: 7,
                },
                "script history coverage starts at height 7; the pruned prefix is unproven",
            ),
            (
                TxUnavailableCause::HistoryUnproven { floor: 5 },
                "script history coverage starts at height 5; history cannot be proven complete",
            ),
            (
                TxUnavailableCause::WorkerFailed("injected worker failure".into()),
                "injected worker failure",
            ),
            (
                TxUnavailableCause::WorkerFailed("txindex worker failed".into()),
                "txindex worker failed",
            ),
            (
                TxUnavailableCause::CompactFilterFailed("filter worker broke".into()),
                "filter worker broke",
            ),
            (
                TxUnavailableCause::MissingAuthority(
                    "chain transition authority missing for ScriptLive",
                ),
                "chain transition authority missing for ScriptLive",
            ),
            (
                TxUnavailableCause::MissingAuthority(
                    "authoritative UTXO view is unavailable for ScriptLive",
                ),
                "authoritative UTXO view is unavailable for ScriptLive",
            ),
            (
                TxUnavailableCause::MissingAuthority(
                    "ScriptLive locator is absent from authoritative UTXO",
                ),
                "ScriptLive locator is absent from authoritative UTXO",
            ),
            (
                TxUnavailableCause::BlockBodyMissing { height: 9 },
                "block body missing for txindex query at height 9",
            ),
            (
                TxUnavailableCause::Other("txindex is opening".into()),
                "txindex is opening",
            ),
            (
                TxUnavailableCause::WorkerFailed("txindex is unavailable".into()),
                "txindex is unavailable",
            ),
            (
                TxUnavailableCause::Other("txindex was abandoned at shutdown".into()),
                "txindex was abandoned at shutdown",
            ),
        ]);
    }

    use bitcoin_rs_primitives::Hash256;

    struct History(Vec<ScriptHistoryRecord>);

    impl ScriptIndexQuery for History {
        fn unspent_outputs(
            &self,
            _script: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
                "unexpected live query".into(),
            )))
        }

        fn history_snapshot(
            &self,
            _script: ScriptHash,
        ) -> Result<ScriptIndexSnapshot, TxQueryError> {
            Ok(ScriptIndexSnapshot {
                history: self.0.clone(),
                funding: Vec::new(),
            })
        }

        fn spender(&self, _outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
            Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
                "unexpected spender query".into(),
            )))
        }
    }

    #[test]
    fn default_history_pages_deduplicate_only_the_selected_page() -> Result<(), TxQueryError> {
        let record = |id: u8, height| ScriptHistoryRecord {
            txid: Txid(Hash256::from_le_bytes(&[id; 32])),
            height,
        };
        let source = History(vec![
            record(1, 7),
            record(2, 6),
            record(1, 5),
            record(3, 4),
            record(1, 3),
            record(3, 2),
            record(4, 1),
        ]);
        let script = ScriptHash::from_byte_array([0; 32]);
        let first = source.confirmed_history_page(script, None, 3)?;
        assert!(first.cursor_found);
        assert_eq!(
            first.records,
            vec![record(1, 7), record(2, 6), record(3, 4)]
        );
        let next = source.confirmed_history_page(script, Some(record(2, 6).txid), 3)?;
        assert!(next.cursor_found);
        // An occurrence preceding the cursor must not seed this page's set.
        // This is page-local uniqueness, not cross-page occurrence tracking.
        assert_eq!(next.records, vec![record(1, 5), record(3, 4), record(4, 1)]);
        let unknown = source.confirmed_history_page(script, Some(record(9, 0).txid), 3)?;
        assert!(!unknown.cursor_found);
        assert_eq!(unknown.records, first.records);
        let empty = source.confirmed_history_page(script, Some(record(2, 6).txid), 0)?;
        assert!(empty.cursor_found);
        assert_eq!(empty.records, []);
        Ok(())
    }
}
