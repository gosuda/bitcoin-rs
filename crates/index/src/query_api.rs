//! Derived-index query contract: typed errors, progress info, and the
//! object-safe read traits the RPC surface and node composition consume.
//!
//! These are index-owned contracts — answers are complete only at a durable
//! watermark equal to the applied tip. `bitcoin_rs_rpc::context` re-exports
//! them under its historical paths.

use bitcoin_rs_primitives::{OutPoint, Tx, Txid};
use compact_str::CompactString;

use crate::ScriptHash;

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
    Unavailable(CompactString),
    /// Durable index storage failed.
    #[error("transaction index storage error: {0}")]
    Storage(CompactString),
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
    use bitcoin_rs_primitives::Hash256;

    struct History(Vec<ScriptHistoryRecord>);

    impl ScriptIndexQuery for History {
        fn unspent_outputs(
            &self,
            _script: ScriptHash,
        ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
            Err(TxQueryError::Unavailable("unexpected live query".into()))
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
            Err(TxQueryError::Unavailable("unexpected spender query".into()))
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
