use super::*;

#[cfg(test)]
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
    use bitcoin_rs_consensus::primitives::{BlockHash, Hash256, Header, Txid, deserialize};
    use bitcoin_rs_execution::chain::{
        BlockTree, BlockTreeReader, ChainTxCount, NodeStatus, TipReader, TipSnapshot,
    };
    use bitcoin_rs_storage::RocksDbStore;
    use bitcoin_rs_storage::block_body::{BlockBodyReadError, BlockBodySource};
    use parking_lot::RwLock;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    type TestResult<T = ()> = Result<T, crate::portable::TestError>;

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

        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let mut index = IndexWriter::open(store, 1)?;
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
        let runtime = DerivedIndexRuntime::new(wake_tx);
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
                enabled: IndexCapabilities::TX_AND_SCRIPTS,
                generation: std::sync::Arc::new(crate::runtime::Generation::new(1)),
                historical_verified: None,
                chain_transition: None,
            },
        );

        let script_hash = ScriptHash::from_script_bytes(&[0x51]);
        let expected_reason = outage.to_string();
        assert_eq!(
            engine.unspent_outputs(script_hash),
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::ScriptLiveUnavailable(expected_reason.as_str().into())
            ))
        );

        let txid = expected_txid(&block);
        let expected_tx =
            deserialize::<bitcoin_rs_consensus::primitives::Tx>(&serialize(&block.txdata[0]))?;
        assert_eq!(expected_tx.txid(), txid);
        assert_eq!(
            engine.transaction_block(&txid)?,
            Some((expected_tx, super::TransactionBlock { height: 0, hash }))
        );
        let history = engine.confirmed_history(script_hash)?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].txid, txid);
        assert_eq!(history[0].height, 0);

        assert!(runtime.failure_message().is_none());
        Ok(())
    }
}

struct CompleteHistory(Vec<ScriptHistoryRecord>);

impl ScriptIndexQuery for CompleteHistory {
    fn unspent_outputs(&self, _script: ScriptHash) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        Err(TxQueryError::Unavailable(TxUnavailableCause::Other(
            "unexpected live query".into(),
        )))
    }

    fn history_snapshot(&self, _script: ScriptHash) -> Result<ScriptIndexSnapshot, TxQueryError> {
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

// IDX-02
#[test]
fn default_history_page_skips_the_cursor_and_restarts_when_unknown()
-> Result<(), crate::portable::TestError> {
    let record = |id: u8, height| ScriptHistoryRecord {
        txid: Txid(Hash256::from_le_bytes(&[id; 32])),
        height,
    };
    let source = CompleteHistory(vec![
        record(1, 7),
        record(2, 6),
        record(3, 4),
        record(4, 3),
        record(5, 1),
    ]);
    let script = ScriptHash::from_byte_array([0; 32]);

    let first = source.confirmed_history_page(script, None, 3)?;
    assert!(first.cursor_found);
    assert_eq!(
        first.records,
        vec![record(1, 7), record(2, 6), record(3, 4)]
    );

    let second = source.confirmed_history_page(script, Some(record(2, 6).txid), 3)?;
    assert!(second.cursor_found);
    assert_eq!(
        second.records,
        vec![record(3, 4), record(4, 3), record(5, 1)]
    );

    let unknown = source.confirmed_history_page(script, Some(record(9, 0).txid), 3)?;
    assert!(!unknown.cursor_found, "an absent transaction is reported");
    assert_eq!(unknown.records, first.records);

    let empty = source.confirmed_history_page(script, Some(record(2, 6).txid), 0)?;
    assert!(empty.cursor_found);
    assert_eq!(empty.records, Vec::new());
    Ok(())
}

// IDX-02
#[test]
fn default_history_page_lists_a_duplicated_txid_at_its_newest_occurrence()
-> Result<(), crate::portable::TestError> {
    let record = |id: u8, height| ScriptHistoryRecord {
        txid: Txid(Hash256::from_le_bytes(&[id; 32])),
        height,
    };
    let source = CompleteHistory(vec![record(1, 7), record(2, 6), record(2, 3), record(3, 1)]);
    let script = ScriptHash::from_byte_array([0; 32]);

    assert_eq!(
        source.history_page(script, None, usize::MAX)?,
        vec![record(1, 7), record(2, 6), record(3, 1)],
        "a duplicated txid lists once, at its newest occurrence"
    );
    assert_eq!(
        source.history_page(script, Some(record(2, 6).txid), usize::MAX)?,
        vec![record(3, 1)],
        "an exclusive cursor continues strictly below the newest occurrence"
    );
    assert_eq!(
        source.history_page(script, Some(record(2, 3).txid), usize::MAX)?,
        vec![record(3, 1)],
        "the older occurrence resolves to the newest and never repeats"
    );
    Ok(())
}

// IDX-02
#[test]
fn default_history_pages_are_bounded_by_the_page_max() -> Result<(), crate::portable::TestError> {
    let count = SCRIPT_HISTORY_PAGE_MAX * 2;
    let records = (0..count)
        .map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&u64::try_from(index)?.to_le_bytes());
            Ok(ScriptHistoryRecord {
                txid: Txid(Hash256::from_le_bytes(&bytes)),
                height: u32::try_from(index)?,
            })
        })
        .collect::<Result<Vec<_>, std::num::TryFromIntError>>()?;
    let source = CompleteHistory(records);
    let script = ScriptHash::from_byte_array([0; 32]);

    assert_eq!(
        source
            .confirmed_history_page(script, None, usize::MAX)?
            .records
            .len(),
        SCRIPT_HISTORY_PAGE_MAX,
        "a page never exceeds the script-history page maximum"
    );
    assert_eq!(
        source.history_page(script, None, usize::MAX)?.len(),
        SCRIPT_HISTORY_PAGE_MAX,
        "a legacy page never exceeds the script-history page maximum"
    );
    Ok(())
}

// QRY-05
#[test]
fn query_miss_absent_maps_to_scoped_none() {
    let absent = QueryMiss::Absent;
    let scoped: Result<Option<u32>, TxQueryError> = absent.into_scoped();
    assert_eq!(scoped, Ok(None));

    let from_result: Result<Option<String>, TxQueryError> = QueryMiss::Absent.into();
    assert_eq!(from_result, Ok(None));

    let try_err = TxQueryError::try_from(QueryMiss::Absent);
    assert_eq!(try_err, Err(()), "Absent inside coverage is not an error");

    let unavailable = QueryMiss::Unavailable {
        capability: IndexCapability::TxLookup,
        declared_floor_or_tip: 42,
    };
    let unavail_scoped: Result<Option<u32>, TxQueryError> = unavailable.into_scoped();
    assert_eq!(
        unavail_scoped,
        Err(TxQueryError::Unavailable(
            TxUnavailableCause::OutsideCoverage {
                declared_floor_or_tip: 42,
            }
        ))
    );

    let expired = QueryMiss::ExpiredView;
    let expired_scoped: Result<Option<u32>, TxQueryError> = expired.into_scoped();
    assert_eq!(expired_scoped, Err(TxQueryError::ExpiredView));
}
