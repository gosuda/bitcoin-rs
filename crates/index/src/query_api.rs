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

    /// Acceptance row 13 (type-level half): the scoped `ScriptLive` outage is a
    /// typed `Unavailable` carrying the stored worker reason verbatim, never a
    /// `Retry` and never new wire text. Engine-level proof (flag set with no
    /// watermark gives `Unavailable(ScriptLiveUnavailable)` for `ScriptLive`
    /// queries while TxLookup/history keep serving and global `failed` stays
    /// unset) lives in the worker harness; this pins the contract the engine
    /// observes: passthrough display, `Unavailable` error prefix, variant
    /// distinctness, and untouched sibling refusals.
    #[test]
    fn script_live_unavailable_is_typed_passthrough_not_retry() {
        // Passthrough: the cause renders exactly the stored reason.
        for reason in [
            "script live seed pruned at height 100",
            "txindex worker: retained history unavailable: pruned at height 7",
            "",
        ] {
            let cause = TxUnavailableCause::ScriptLiveUnavailable(reason.into());
            assert_eq!(cause.to_string(), reason, "{cause:?}");
            let error = TxQueryError::Unavailable(cause);
            assert_eq!(
                error.to_string(),
                format!("transaction index unavailable: {reason}"),
            );
            assert!(!matches!(error, TxQueryError::Retry));
        }
        // Scoped: the outage variant never aliases another capability's refusal.
        let outage = TxUnavailableCause::ScriptLiveUnavailable("pruned".into());
        assert_ne!(outage, TxUnavailableCause::WorkerStopped);
        assert_ne!(
            outage,
            TxUnavailableCause::CompactFilterFailed("pruned".into())
        );
        assert_ne!(
            outage,
            TxUnavailableCause::CapabilityDisabled(IndexCapability::ScriptLive)
        );
        assert_ne!(outage, TxUnavailableCause::Other("pruned".into()));
        // The historical wrapper carries the scoped reason through unchanged,
        // should a historical path ever need to share it.
        let shared = HistoricalUnavailableCause::Shared(TxUnavailableCause::ScriptLiveUnavailable(
            "pruned".into(),
        ));
        assert_eq!(shared.to_string(), "pruned");
        // Sibling capabilities keep their exact wire text while the flag is set.
        assert_renders(vec![
            (
                TxUnavailableCause::PrunedPrefixUnproven {
                    family: "transaction index",
                    floor: 100,
                },
                "transaction index coverage starts at height 100; the pruned prefix is unproven",
            ),
            (
                TxUnavailableCause::HistoryUnproven { floor: 5 },
                "script history coverage starts at height 5; history cannot be proven complete",
            ),
        ]);
    }

    /// P1 acceptance row 13 (engine half): the scoped `ScriptLive` outage at
    /// the real query engine. Requires the `fjall` backend, like the worker
    /// owning suites (`recovery_tests`, `seed_paused_tests`): serving
    /// `TxLookup`/history needs committed watermarks plus real rows, which
    /// need a real store. Run with `--features fjall`.
    ///
    /// A real engine is built over a real store holding one committed genesis
    /// block, with the real `script_live_failure` flag set and no watermark
    /// gap anywhere: `ScriptLive` answers `Unavailable(ScriptLiveUnavailable)`
    /// carrying the worker reason verbatim, while `TxLookup` and history on
    /// the same engine keep serving real data and global `failed` stays unset.
    /// The block body source below serves the genuine committed bytes to the
    /// real engine; the system under test is the query routing, not storage.
    #[cfg(all(test, feature = "fjall"))]
    mod script_live_outage_engine_tests {
        use super::{DerivedIndexQuery, ScriptIndexQuery, TxQueryError, TxUnavailableCause};
        use crate::runtime::{
            DEFAULT_BATCH_LIMITS, DerivedIndexQueryEngine, DerivedIndexRuntime,
            DerivedIndexWorkerError, QueryEngineLive,
        };
        use crate::{
            ConsumerCursorUpdate, IndexCapabilities, IndexReader, IndexWatermark, IndexWriter,
            NoSpentScripts, PreparedBatch, ScriptHash,
        };
        use arc_swap::ArcSwapOption;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::{
            Amount, Block, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
            block::{Header as BlockHeader, Version as BlockVersion},
            pow::CompactTarget,
            script::Builder,
        };
        use bitcoin_rs_chain::{
            BlockBodyReadError, BlockBodySource, BlockTree, BlockTreeReader, ChainTxCount,
            NodeStatus, TipReader, TipSnapshot,
        };
        use bitcoin_rs_primitives::{BlockHash, Hash256, Header, Txid, deserialize};
        use bitcoin_rs_storage::FjallStore;
        use parking_lot::RwLock;
        use sha2::{Digest, Sha256};
        use std::sync::Arc;

        type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

        fn coinbase_tx(height: u32, extra: i64) -> Transaction {
            Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: Builder::new()
                        .push_int(i64::from(height))
                        .push_int(extra)
                        .into_script(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            }
        }

        /// One spend-free bitcoin block plus its consensus bytes and the
        /// matching primitives header: the same real pipeline the worker
        /// prepares, committed here directly.
        fn genesis_block() -> (Block, Hash256, Vec<u8>) {
            let mut block = Block {
                header: BlockHeader {
                    version: BlockVersion::ONE,
                    prev_blockhash: bitcoin::BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce: 0,
                },
                txdata: vec![coinbase_tx(0, 0)],
            };
            block.header.merkle_root = block
                .compute_merkle_root()
                .unwrap_or_else(TxMerkleNode::all_zeros);
            let body = serialize(&block);
            let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
            (block, hash, body)
        }

        fn primitives_header(block: &Block) -> TestResult<Header> {
            Ok(deserialize::<Header>(&serialize(&block.header))?)
        }

        /// Double-SHA256 of the transaction serialization: the exact txid the
        /// committed rows are keyed by, without crossing crate boundaries.
        fn expected_txid(block: &Block) -> Txid {
            let bytes = serialize(&block.txdata[0]);
            let digest = Sha256::digest(Sha256::digest(bytes).as_slice());
            Txid::from(Hash256::from_le_bytes(&digest.into()))
        }

        struct SingleBody {
            height: u32,
            hash: BlockHash,
            body: Vec<u8>,
        }

        impl BlockBodySource for SingleBody {
            fn block_body(
                &self,
                height: u32,
                hash: BlockHash,
            ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
                if height == self.height && hash == self.hash {
                    Ok(Some(self.body.clone()))
                } else {
                    Ok(None)
                }
            }
        }

        #[test]
        fn script_live_unavailable_query_shape() -> TestResult {
            let dir = tempfile::tempdir()?;
            let (block, hash, body) = genesis_block();
            let header = primitives_header(&block)?;

            let tree = Arc::new(RwLock::new(BlockTree::new()));
            let tip_id = tree
                .write()
                .insert_header(header, NodeStatus::HeaderValid)?;
            let chainwork = tree.read().node(tip_id)?.chainwork;
            let tip = Arc::new(TipSnapshot {
                tip_id,
                height: 0,
                chainwork,
                hash,
                chain_tx_count: ChainTxCount::established(1),
            });

            let store = Arc::new(FjallStore::open(dir.path())?);
            let mut index = IndexWriter::open(store, 1)?;
            // HISTORICAL only: TxLookup and history commit a watermark at the
            // tip while ScriptLive stays unwatermarked, the exact outage
            // state this row proves.
            let prepared = index.prepare_block_with_spent_scripts(
                IndexCapabilities::HISTORICAL,
                0,
                hash.to_le_bytes(),
                &body,
                &NoSpentScripts,
            )?;
            let (fence, _) = index.fenced_watermarks()?;
            let mut batch = PreparedBatch::new(DEFAULT_BATCH_LIMITS);
            batch
                .try_push(prepared)
                .map_err(|_| "batch rejected the prepared genesis block")?;
            let watermark =
                index.commit_forward_with_cursor(fence, batch, ConsumerCursorUpdate::Keep)?;
            let covered = IndexWatermark {
                height: 0,
                hash: hash.to_le_bytes(),
            };
            assert_eq!(watermark, covered);
            let marks = index.fenced_watermarks()?.1;
            assert_eq!(marks.tx_lookup, Some(covered));
            assert_eq!(marks.script_history, Some(covered));
            assert_eq!(marks.script_live, None);
            let reader: Arc<dyn IndexReader> = Arc::new(index);

            let applied_tip = Arc::new(ArcSwapOption::empty());
            let tip_reader = TipReader::new(Arc::clone(&applied_tip));
            tip_reader.store(Some(Arc::clone(&tip)));

            let (wake_tx, _wake_rx) = crossbeam_channel::bounded::<()>(16);
            let runtime = Arc::new(DerivedIndexRuntime::new(wake_tx));
            let outage = DerivedIndexWorkerError::ScriptLiveHistoryPruned;
            runtime.fail_script_live(&outage);
            assert!(runtime.script_live_failure().is_some());

            let engine = DerivedIndexQueryEngine::new(
                Arc::clone(&runtime),
                reader,
                BlockTreeReader::new(tree),
                tip_reader,
                Some(Arc::new(SingleBody {
                    height: 0,
                    hash: BlockHash::from(hash),
                    body,
                })),
                QueryEngineLive {
                    utxo: None,
                    chain_transition: None,
                    enabled: IndexCapabilities::TX_AND_SCRIPTS,
                },
            );

            // Flag set with no watermark gap: ScriptLive is unavailable with
            // the worker reason verbatim, never Retry.
            let script_hash = ScriptHash::from_script_bytes(&[0x51]);
            let expected_reason = outage.to_string();
            assert_eq!(
                engine.unspent_outputs(script_hash),
                Err(TxQueryError::Unavailable(
                    TxUnavailableCause::ScriptLiveUnavailable(expected_reason.as_str().into())
                ))
            );

            // The same engine keeps serving the other families from real rows.
            let txid = expected_txid(&block);
            assert_eq!(engine.transaction_height(&txid)?, Some(0));
            let history = engine.confirmed_history(script_hash)?;
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].txid, txid);
            assert_eq!(history[0].height, 0);

            // Scoped outage only: no global worker failure is published.
            assert!(runtime.failure_message().is_none());
            Ok(())
        }
    }
}
