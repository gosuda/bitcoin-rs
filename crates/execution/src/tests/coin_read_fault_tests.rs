//! Coin-store read faults must surface as storage errors, never as block verdicts.

#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::chain::regtest_fixture::{
    merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
};
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Witness,
};
use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;
use bitcoin_rs_storage::commit::AcceptedPrefix;
use bitcoin_rs_storage::durable_head::DurableHead;
use bitcoin_rs_storage::memory_kv::MemoryKvStore;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::{
    BufferedWriteBatch, CoinKey, ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault,
    PrefixScan, PrefixScanLimit, StorageError, WindowDelta, WriteCondition,
};
use parking_lot::Mutex;

use crate::test_fixtures::{TestError, TestResult, handles_with_store, seed_genesis};
use crate::{ApplyError, Chainstate, DisconnectError, WindowApplyDisposition};

struct PoisonedStore {
    inner: MemoryKvStore,
    poisoned_keys: Mutex<HashSet<Vec<u8>>>,
    fail_multi_get: AtomicBool,
}

impl PoisonedStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryKvStore::default(),
            poisoned_keys: Mutex::new(HashSet::new()),
            fail_multi_get: AtomicBool::new(false),
        })
    }

    fn poison_get(&self, key: &CoinKey) {
        self.poisoned_keys.lock().insert(key.as_bytes().to_vec());
    }

    fn fail_multi_get(&self) {
        self.fail_multi_get.store(true, Ordering::SeqCst);
    }

    fn injected() -> StorageError {
        StorageError::Io(std::io::Error::other("injected coin read failure"))
    }
}

impl KvStore for PoisonedStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if cf == ColumnFamily::Coins && self.poisoned_keys.lock().contains(key) {
            return Err(Self::injected());
        }
        self.inner.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.inner
            .scan_prefix_from_bounded(cf, prefix, start, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.inner.write(batch)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        self.inner.write_durable_if(conditions, batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.inner.flush()
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, StorageError> {
        if cf == ColumnFamily::Coins && self.fail_multi_get.load(Ordering::SeqCst) {
            return Err(Self::injected());
        }
        self.inner.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &std::path::Path,
    ) -> Result<u64, StorageError> {
        self.inner.ingest_sorted(cf, rows, scratch)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_range(cf, start, end)
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
        self.inner.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.inner.engine_cache_bytes()
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn arm_persist_fault(&self, fault: PersistFault) {
        self.inner.arm_persist_fault(fault);
    }
}

struct CoinReadFixture {
    chain: Chainstate,
    store: Arc<PoisonedStore>,
    payload: BlockImage,
    block: Block,
    coin_key: CoinKey,
}

fn coin_read_fixture() -> TestResult<CoinReadFixture> {
    let store = PoisonedStore::new();
    let chain = handles_with_store(Network::Regtest, Arc::new(UtxoSet::new()), store.clone());
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let owner_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };
    let coin_txid = owner_tx.txid();
    let coin_key = CoinKey(coin_txid.0.to_le_bytes());
    let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
        coin_txid.0,
        &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 0,
            value: 50_000,
            script_pubkey: vec![OP_PUSHNUM_1],
            coinbase: false,
            height: 0,
        }],
    )
    .map_err(|_| TestError::Missing("synthetic coin record"))?;
    store.put(ColumnFamily::Coins, coin_key.as_bytes(), record.bytes())?;

    let spend_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(coin_txid, 0),
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut block: Block = mined_child(genesis.block_hash(), 1)?;
    block.txs.push(spend_tx);
    block.header.merkle_root = merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    chain.admit_headers(&[block.header])?;

    Ok(CoinReadFixture {
        chain,
        store,
        payload: BlockImage::from_local(block.clone()),
        block,
        coin_key,
    })
}

fn commit_genesis_head(chain: &Chainstate) -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    chain
        .commit_authority
        .commit_prefix(AcceptedPrefix {
            expected_head: None,
            next_head: DurableHead {
                assumeutxo: crate::AssumeUtxoDiskStatus::Uninitialized,
                commit_id: 1,
                height: 0,
                tip: Hash256::from(genesis.block_hash()),
                chain_tx_count: 1,
                body_extent: None,
                undo_extent: None,
            },
            undo_rows: Vec::new(),
            body_rows: Vec::new(),
            attestation: None,
            coin_delta: WindowDelta::default(),
        })
        .map_err(|error| {
            TestError::Missing(match error {
                bitcoin_rs_storage::CommitError::Storage(_) => "genesis head storage failure",
                bitcoin_rs_storage::CommitError::AdmissionClosed => "genesis head admission closed",
                bitcoin_rs_storage::CommitError::PreconditionFailed => "genesis head precondition",
            })
        })?;
    Ok(())
}

// CMT-04
#[test]
fn validate_block_reports_coin_read_errors() -> TestResult {
    let fixture = coin_read_fixture()?;
    fixture.store.poison_get(&fixture.coin_key);

    let Err(error) = fixture.chain.validate_block(&fixture.payload) else {
        return Err(TestError::UnexpectedSuccess(
            "a coin read failure must not read as a valid block",
        ));
    };
    assert!(
        matches!(error, ApplyError::CoinStoreRead(_)),
        "expected a typed coin store read error, got: {error}"
    );
    Ok(())
}

// CMT-04
#[test]
fn window_prepare_coin_read_error_is_fatal() -> TestResult {
    let fixture = coin_read_fixture()?;
    fixture.store.fail_multi_get();

    let Err(error) = fixture.chain.apply_window(&[&fixture.payload]) else {
        return Err(TestError::UnexpectedSuccess(
            "a coin read failure must refuse the window",
        ));
    };
    assert!(
        matches!(error.source.as_ref(), ApplyError::CoinStoreRead(_)),
        "expected a typed coin store read error, got: {error}"
    );
    assert_eq!(error.disposition, WindowApplyDisposition::Fatal);

    let head = fixture
        .chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(
        head.height, 0,
        "the refused window must not advance the head"
    );
    Ok(())
}

// CMT-04
#[test]
fn coin_read_error_never_invalidates_the_block() -> TestResult {
    let fixture = coin_read_fixture()?;
    fixture.store.poison_get(&fixture.coin_key);

    let result = {
        let _fault = crate::window::prepare_fault::arm();
        fixture.chain.apply_window(&[&fixture.payload])
    };
    let Err(error) = result else {
        return Err(TestError::UnexpectedSuccess(
            "a coin read failure must refuse the window",
        ));
    };
    assert!(
        matches!(error.source.as_ref(), ApplyError::CoinStoreRead(_)),
        "expected a typed coin store read error, got: {error}"
    );
    assert_eq!(error.disposition, WindowApplyDisposition::Fatal);
    assert!(
        error.invalidated.is_empty(),
        "a transient coin read failure must not invalidate a block: {:?}",
        error.invalidated
    );

    let head = fixture
        .chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(
        head.height, 0,
        "the refused window must not advance the head"
    );
    Ok(())
}

// CMT-04
#[test]
fn disconnect_coin_read_error_is_fatal_and_keeps_the_committed_head() -> TestResult {
    let fixture = coin_read_fixture()?;
    fixture.chain.apply_block(&fixture.payload)?;

    let head_before = fixture
        .chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    let tip_before = fixture
        .chain
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip"))?;
    let spend_outpoint = OutPoint::new(fixture.block.txs[1].txid(), 0);
    fixture.store.fail_multi_get();

    let Err(DisconnectError::Fatal {
        hash,
        height,
        source,
    }) = fixture.chain.disconnect_block(&fixture.block)
    else {
        return Err(TestError::UnexpectedSuccess(
            "a coin read failure must refuse the disconnect",
        ));
    };
    assert_eq!(hash, Hash256::from(fixture.block.block_hash()));
    assert_eq!(height, 1);
    let ApplyError::CoinStoreRead(storage_error) = source.as_ref() else {
        return Err(TestError::Missing(
            "the fatal disconnect must carry a coin store read error",
        ));
    };
    assert!(
        matches!(
            storage_error,
            StorageError::Io(injected) if injected.kind() == std::io::ErrorKind::Other
        ),
        "the fatal source must be the injected coin read fault, got {storage_error}"
    );

    let head_after = fixture
        .chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(
        head_after.height, head_before.height,
        "a failed disconnect must not move the committed head height"
    );
    assert_eq!(
        head_after.tip, head_before.tip,
        "a failed disconnect must not move the committed head tip"
    );
    assert_eq!(
        head_after.commit_id, head_before.commit_id,
        "a failed disconnect must not commit a new head"
    );
    let tip_after = fixture
        .chain
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip"))?;
    assert_eq!(
        tip_after.hash, tip_before.hash,
        "a failed disconnect must not move the applied tip"
    );
    assert!(
        fixture.chain.utxo_reader().get(&spend_outpoint)?.is_some(),
        "a failed disconnect must not drop the connected block's coins"
    );
    Ok(())
}
