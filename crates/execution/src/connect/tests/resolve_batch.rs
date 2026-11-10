use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime, Network,
    OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;
use bitcoin_rs_storage::memory_kv::MemoryKvStore;
use bitcoin_rs_storage::utxo::UtxoCoin;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
use bitcoin_rs_storage::{
    BufferedWriteBatch, CoinKey, CoinStore, ColumnFamily, KvIter, KvSnapshot, KvStore,
    PersistFault, PrefixScan, PrefixScanLimit, StorageError, WriteCondition,
};

use bitcoin_rs_storage::budget::{BudgetCharge, BudgetError, BudgetOwner, ChargeHandle};

use crate::connect::ChainstateUtxoSource;
use crate::test_fixtures::{TestError, TestResult, handles_with_store};

#[derive(Default)]
struct CountingStore {
    inner: MemoryKvStore,
    coin_gets: AtomicUsize,
    coin_multi_gets: AtomicUsize,
    coin_multi_get_keys: AtomicUsize,
}

impl KvStore for CountingStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if cf == ColumnFamily::Coins {
            self.coin_gets.fetch_add(1, Ordering::SeqCst);
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
        if cf == ColumnFamily::Coins {
            self.coin_multi_gets.fetch_add(1, Ordering::SeqCst);
            self.coin_multi_get_keys
                .fetch_add(keys.len(), Ordering::SeqCst);
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

fn spend_tx(previous: &[OutPoint]) -> Tx {
    Tx {
        version: 2,
        inputs: previous
            .iter()
            .map(|outpoint| TxIn {
                previous_output: *outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn coinbase_tx() -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn funded_record(txid: Txid, base: u64) -> TestResult<(UtxoRecord, Vec<UtxoCoin>)> {
    let outputs: Vec<OwnedUtxoOut> = (0..3_u32)
        .map(|vout| OwnedUtxoOut::new(vout, base + u64::from(vout), vec![OP_PUSHNUM_1], false, 7))
        .collect();
    let record = UtxoRecord::from_owned_outputs(txid.0, &outputs)
        .map_err(|_| TestError::Missing("funding record"))?;
    let coins = outputs
        .iter()
        .map(|output| UtxoCoin {
            outpoint: OutPoint::new(txid, output.vout),
            txout: TxOut {
                value: Amount::from_sat(output.value),
                script_pubkey: Script::from_bytes(output.script_pubkey.clone()),
            },
            coinbase: false,
            height: 7,
        })
        .collect();
    Ok((record, coins))
}

// WIN-01
#[test]
fn inputs_sharing_a_previous_transaction_resolve_in_one_batch() -> TestResult {
    let store = Arc::new(CountingStore::default());
    let mut chain = handles_with_store(
        Network::Regtest,
        Arc::new(UtxoSet::new()),
        Arc::clone(&store),
    );
    let dyn_store: Arc<dyn KvStore> = store.clone();
    chain.coins = Arc::new(CoinStore::open(dyn_store, 0));

    let funding = [
        Txid(Hash256::from_le_bytes(&[0x11; 32])),
        Txid(Hash256::from_le_bytes(&[0x22; 32])),
    ];
    let mut funded = Vec::new();
    for (txid, base) in funding.into_iter().zip([1_000_u64, 2_000]) {
        let (record, coins) = funded_record(txid, base)?;
        chain.commit_authority.store().put(
            ColumnFamily::Coins,
            CoinKey(txid.0.to_le_bytes()).as_bytes(),
            record.bytes(),
        )?;
        funded.extend(coins);
    }

    let spent_a = [
        OutPoint::new(funding[0], 0),
        OutPoint::new(funding[0], 1),
        OutPoint::new(funding[1], 0),
    ];
    let spent_b = [
        OutPoint::new(funding[0], 2),
        OutPoint::new(funding[1], 1),
        OutPoint::new(funding[1], 2),
    ];
    let txs = vec![coinbase_tx(), spend_tx(&spent_a), spend_tx(&spent_b)];
    let txids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs,
    };
    let image = BlockImage::from_local(block);
    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    let input_count = spent_a.len() + spent_b.len();
    let distinct_previous_txids = funding.len();

    let gets_before = store.coin_gets.load(Ordering::SeqCst);
    let multi_before = store.coin_multi_gets.load(Ordering::SeqCst);
    let keys_before = store.coin_multi_get_keys.load(Ordering::SeqCst);
    let source = ChainstateUtxoSource::new(&chain);
    let resolved = crate::ResolvedUtxoView::resolve(&source, &image, &tx_plan);
    source.into_result()?;

    assert_eq!(
        store.coin_gets.load(Ordering::SeqCst) - gets_before,
        0,
        "resolution must not issue one point read per input"
    );
    assert_eq!(
        store.coin_multi_gets.load(Ordering::SeqCst) - multi_before,
        1,
        "resolution must read every previous transaction in one batch"
    );
    assert_eq!(
        store.coin_multi_get_keys.load(Ordering::SeqCst) - keys_before,
        distinct_previous_txids,
        "the batch must carry one key per distinct previous transaction"
    );
    assert_eq!(resolved.external.len(), input_count);
    for coin in &funded {
        let spent = spent_a.contains(&coin.outpoint) || spent_b.contains(&coin.outpoint);
        let resolved_coin = resolved.entry(&coin.outpoint);
        if spent {
            assert_eq!(resolved_coin, Some(coin));
        } else {
            assert_eq!(resolved_coin, None);
        }
    }
    Ok(())
}

fn fund_many(
    chain: &mut crate::Chainstate,
    distinct: usize,
) -> TestResult<(Vec<UtxoCoin>, Vec<OutPoint>)> {
    let mut funded = Vec::new();
    let mut spent = Vec::new();
    for i in 0..distinct {
        let mut raw = [0x5A_u8; 32];
        raw[0] = u8::try_from(i & 0xff)?;
        raw[1] = u8::try_from((i >> 8) & 0xff)?;
        let txid = Txid(Hash256::from_le_bytes(&raw));
        let (record, coins) = funded_record(txid, 1_000_u64 + u64::try_from(i)?)?;
        chain.commit_authority.store().put(
            ColumnFamily::Coins,
            CoinKey(txid.0.to_le_bytes()).as_bytes(),
            record.bytes(),
        )?;
        spent.push(OutPoint::new(txid, 0));
        funded.extend(coins);
    }
    Ok((funded, spent))
}

struct RefusingCharge;

impl BudgetCharge for RefusingCharge {
    fn reserve_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        Err(BudgetError::BudgetExhausted)
    }
    fn allocate_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        Err(BudgetError::BudgetExhausted)
    }
    fn release_bytes(&self, _owner: BudgetOwner, _bytes: u64) {}
    fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
        0
    }
}

// WIN-01
#[test]
fn many_previous_transactions_resolve_in_bounded_batches() -> TestResult {
    let chunk = crate::RESOLVE_TXIDS_PER_FETCH;
    let distinct = chunk * 2 + 1;
    let store = Arc::new(CountingStore::default());
    let mut chain = handles_with_store(
        Network::Regtest,
        Arc::new(UtxoSet::new()),
        Arc::clone(&store),
    );
    let dyn_store: Arc<dyn KvStore> = store.clone();
    chain.coins = Arc::new(CoinStore::open(dyn_store, 0));
    let (funded, spent) = fund_many(&mut chain, distinct)?;
    let txs = vec![coinbase_tx(), spend_tx(&spent)];
    let txids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs,
    };
    let image = BlockImage::from_local(block);
    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    let gets_before = store.coin_gets.load(Ordering::SeqCst);
    let multi_before = store.coin_multi_gets.load(Ordering::SeqCst);
    let keys_before = store.coin_multi_get_keys.load(Ordering::SeqCst);
    let source = ChainstateUtxoSource::new(&chain);
    let resolved = crate::ResolvedUtxoView::resolve(&source, &image, &tx_plan);
    source.into_result()?;
    assert_eq!(
        store.coin_gets.load(Ordering::SeqCst) - gets_before,
        0,
        "resolution must not issue one point read per input"
    );
    assert_eq!(
        store.coin_multi_get_keys.load(Ordering::SeqCst) - keys_before,
        distinct,
        "the batch must carry one key per distinct previous transaction"
    );
    assert_eq!(
        store.coin_multi_gets.load(Ordering::SeqCst) - multi_before,
        distinct.div_ceil(chunk),
        "resolution must fetch bounded batches with one read per distinct previous transaction"
    );
    assert_eq!(resolved.external.len(), distinct);
    for coin in &funded {
        if spent.contains(&coin.outpoint) {
            assert_eq!(resolved.entry(&coin.outpoint), Some(coin));
        } else {
            assert_eq!(resolved.entry(&coin.outpoint), None);
        }
    }
    Ok(())
}

// WIN-01
#[test]
fn same_block_spend_resolves_from_the_block_and_absent_stays_missing() -> TestResult {
    let store = Arc::new(CountingStore::default());
    let mut chain = handles_with_store(
        Network::Regtest,
        Arc::new(UtxoSet::new()),
        Arc::clone(&store),
    );
    let dyn_store: Arc<dyn KvStore> = store.clone();
    chain.coins = Arc::new(CoinStore::open(dyn_store, 0));
    let funding = Txid(Hash256::from_le_bytes(&[0x33; 32]));
    let (record, coins) = funded_record(funding, 3_000)?;
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(funding.0.to_le_bytes()).as_bytes(),
        record.bytes(),
    )?;
    let funded_out = OutPoint::new(funding, 0);
    let first = spend_tx(std::slice::from_ref(&funded_out));
    let first_txid = first.txid();
    let created = first.outputs[0].clone();
    let same = OutPoint::new(first_txid, 0);
    let absent = OutPoint::new(Txid(Hash256::from_le_bytes(&[0xAB; 32])), 0);
    let second = spend_tx(&[same, absent]);
    let txs = vec![coinbase_tx(), first, second];
    let txids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs,
    };
    let image = BlockImage::from_local(block);
    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    assert!(
        tx_plan
            .same_block_spent
            .as_ref()
            .is_some_and(|set| set.contains(&same))
    );
    let gets_before = store.coin_gets.load(Ordering::SeqCst);
    let multi_before = store.coin_multi_gets.load(Ordering::SeqCst);
    let keys_before = store.coin_multi_get_keys.load(Ordering::SeqCst);
    let source = ChainstateUtxoSource::new(&chain);
    let resolved = crate::ResolvedUtxoView::resolve(&source, &image, &tx_plan);
    source.into_result()?;
    assert_eq!(
        store.coin_gets.load(Ordering::SeqCst) - gets_before,
        0,
        "resolution must not issue one point read per input"
    );
    assert_eq!(
        store.coin_multi_get_keys.load(Ordering::SeqCst) - keys_before,
        2,
        "the same-block creation must not reach the coin store"
    );
    assert_eq!(
        store.coin_multi_gets.load(Ordering::SeqCst) - multi_before,
        1,
        "resolution must read every previous transaction in one batch"
    );
    assert_eq!(resolved.entry(&funded_out), Some(&coins[0]));
    assert_eq!(resolved.entry(&same), None);
    assert_eq!(resolved.entry(&absent), None);
    let prevouts =
        crate::prepare::resolve_block_prevouts(Arc::new(resolved), &image, &tx_plan, 2, &txids)?;
    assert_eq!(prevouts.len(), 3);
    assert_eq!(prevouts[1].len(), 1);
    assert_eq!(prevouts[2].len(), 2);
    assert_eq!(prevouts[1][0], Some(coins[0].txout.clone()));
    assert_eq!(prevouts[2][0], Some(created));
    assert_eq!(prevouts[2][1], None);
    Ok(())
}

// BUD-01
#[test]
fn refused_charge_stops_resolution_after_the_first_chunk() -> TestResult {
    let chunk = crate::RESOLVE_TXIDS_PER_FETCH;
    let distinct = chunk + 1;
    let store = Arc::new(CountingStore::default());
    let mut chain = handles_with_store(
        Network::Regtest,
        Arc::new(UtxoSet::new()),
        Arc::clone(&store),
    );
    let dyn_store: Arc<dyn KvStore> = store.clone();
    chain.coins = Arc::new(CoinStore::open(dyn_store, 0));
    let (_, spent) = fund_many(&mut chain, distinct)?;
    let txs = vec![coinbase_tx(), spend_tx(&spent)];
    let txids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs,
    };
    let image = BlockImage::from_local(block);
    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    let handle = ChargeHandle::new(Arc::new(RefusingCharge), BudgetOwner::StagedImages);
    let multi_before = store.coin_multi_gets.load(Ordering::SeqCst);
    let keys_before = store.coin_multi_get_keys.load(Ordering::SeqCst);
    let source = ChainstateUtxoSource::new(&chain);
    let result = crate::ResolvedUtxoView::resolve_charged(&source, &image, &tx_plan, Some(handle));
    let Err(error) = result else {
        return Err(TestError::Missing("charged resolution must refuse"));
    };
    assert!(matches!(error, crate::ApplyError::StagedBudgetExhausted));
    assert_eq!(
        store.coin_multi_gets.load(Ordering::SeqCst) - multi_before,
        1,
        "a refused charge must stop resolution before the next chunk is fetched"
    );
    assert_eq!(
        store.coin_multi_get_keys.load(Ordering::SeqCst) - keys_before,
        chunk,
        "only the first chunk may reach the coin store before refusal"
    );
    Ok(())
}
