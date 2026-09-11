//! IDX-03 / RCV-01: bodies are selected by the captured chain identity.
//!
//! These exercise the query engine rather than the removed node BlockLog
//! adapter. Metadata is not a body source; height alone cannot identify a body.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct SuppliedBody {
    bytes: Vec<u8>,
    range: Option<Vec<u8>>,
}

impl BlockBodySource for SuppliedBody {
    fn block_body(&self, _height: u32, _hash: BlockHash) -> Option<Vec<u8>> {
        Some(self.bytes.clone())
    }

    fn block_body_range(
        &self,
        _height: u32,
        _hash: BlockHash,
        _offset: u32,
        _len: u32,
    ) -> Option<Vec<u8>> {
        self.range.clone()
    }
}

fn indexed_genesis(positioned: bool) -> Result<(QueryFixture, Txid), Box<dyn std::error::Error>> {
    let block = Network::Regtest.genesis_block();
    let txid = block.txs[0].txid();
    let value = if positioned {
        TxPositionValue::encode(&[position_of_transaction(&block, 0)?])
    } else {
        Vec::new()
    };
    let fixture = QueryFixture::new(FixtureConfig {
        block,
        retain_body: true,
        scans: vec![scan_response(
            ColumnFamily::TxConfirmed,
            TxidRow::scan_prefix(&txid),
            vec![(TxidRow::row(&txid, 0).to_db_row().to_vec(), value)],
            true,
        )],
        aba_trigger: None,
        watermark: None,
    })?;
    Ok((fixture, txid))
}

#[test]
fn complete_transaction_reads_need_no_rpc_block_log() -> TestResult {
    let (fixture, txid) = indexed_genesis(false)?;
    assert_eq!(fixture.engine.transaction(&txid)?.map(|tx| tx.txid()), Some(txid));
    assert_eq!(fixture.full_reads()?, 1);
    Ok(())
}

#[test]
fn positioned_read_matches_the_full_serialized_transaction() -> TestResult {
    let (fixture, txid) = indexed_genesis(true)?;
    assert_eq!(
        fixture.engine.transaction(&txid)?,
        Some(Network::Regtest.genesis_block().txs[0].clone()),
    );
    assert_eq!(fixture.full_reads()?, 0);
    let body = fixture.body.as_ref().ok_or_else(|| std::io::Error::other("body"))?;
    assert_eq!(body.range_reads.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn declined_or_short_range_reads_fall_back_to_a_complete_block() -> TestResult {
    let block = Network::Regtest.genesis_block();
    for range in [None, Some(vec![0]), Some(Vec::new())] {
        let (mut fixture, txid) = indexed_genesis(true)?;
        fixture.engine.body_source = Some(Arc::new(SuppliedBody {
            bytes: consensus_bytes(&block),
            range,
        }));
        assert_eq!(fixture.engine.transaction(&txid)?.map(|tx| tx.txid()), Some(txid));
    }
    Ok(())
}

#[test]
fn a_metadata_tip_without_a_body_source_is_unavailable() -> TestResult {
    let (mut fixture, txid) = indexed_genesis(false)?;
    fixture.engine.body_source = None;
    assert!(matches!(fixture.engine.transaction(&txid), Err(TxQueryError::Unavailable(_))));
    Ok(())
}

#[test]
fn wrong_hash_body_is_a_storage_error_not_an_empty_answer() -> TestResult {
    let (mut fixture, txid) = indexed_genesis(false)?;
    let mut rival = Network::Regtest.genesis_block();
    rival.header.nonce = rival.header.nonce.wrapping_add(1);
    fixture.engine.body_source = Some(Arc::new(SuppliedBody {
        bytes: consensus_bytes(&rival),
        range: None,
    }));
    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Storage(reason)) if reason.contains("identity mismatch"),
    ));
    Ok(())
}

#[test]
fn corrupt_body_is_a_storage_error_not_an_empty_answer() -> TestResult {
    let (mut fixture, txid) = indexed_genesis(false)?;
    fixture.engine.body_source = Some(Arc::new(SuppliedBody {
        bytes: vec![0],
        range: None,
    }));
    assert!(matches!(
        fixture.engine.transaction(&txid),
        Err(TxQueryError::Storage(reason)) if reason.contains("corrupt serialized block"),
    ));
    Ok(())
}

struct IdentityBodySource {
    expected: BlockHash,
    body: Vec<u8>,
    requests: Mutex<Vec<(u32, BlockHash)>>,
}

impl BlockBodySource for IdentityBodySource {
    fn block_body(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        self.requests.lock().push((height, hash));
        (height == 0 && hash == self.expected).then(|| self.body.clone())
    }
}

#[test]
fn source_receives_height_and_hash_from_the_captured_applied_chain() -> TestResult {
    let (mut fixture, txid) = indexed_genesis(false)?;
    let block = Network::Regtest.genesis_block();
    let source = Arc::new(IdentityBodySource {
        expected: block.block_hash(),
        body: consensus_bytes(&block),
        requests: Mutex::new(Vec::new()),
    });
    fixture.engine.body_source = Some(source.clone());
    assert_eq!(fixture.engine.transaction(&txid)?.map(|tx| tx.txid()), Some(txid));
    assert_eq!(*source.requests.lock(), vec![(0, block.block_hash())]);
    Ok(())
}

#[test]
fn wrong_height_or_hash_at_the_source_cannot_serve_indexed_rows() -> TestResult {
    let (mut fixture, txid) = indexed_genesis(false)?;
    let source = Arc::new(IdentityBodySource {
        expected: BlockHash::from(Hash256::from_le_bytes(&[0x77; 32])),
        body: consensus_bytes(&Network::Regtest.genesis_block()),
        requests: Mutex::new(Vec::new()),
    });
    fixture.engine.body_source = Some(source);
    assert!(matches!(fixture.engine.transaction(&txid), Err(TxQueryError::Unavailable(_))));
    Ok(())
}

#[test]
fn failed_and_shutdown_runtimes_gate_reads_before_body_access() -> TestResult {
    for failed in [false, true] {
        let (fixture, txid) = indexed_genesis(false)?;
        if failed {
            fixture.engine.runtime.publish_failed("failed index");
        } else {
            fixture.engine.runtime.request_shutdown();
        }
        assert!(matches!(fixture.engine.transaction(&txid), Err(TxQueryError::Unavailable(_))));
        assert_eq!(fixture.full_reads()?, 0);
    }
    Ok(())
}
