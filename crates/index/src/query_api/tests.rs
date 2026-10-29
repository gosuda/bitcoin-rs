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
        BlockBodyReadError, BlockBodySource, BlockTree, BlockTreeReader, ChainTxCount, NodeStatus,
        TipReader, TipSnapshot,
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
