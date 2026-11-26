//! Validated block connection and its ordered persistence/publication transaction.

#[cfg(test)]
mod tests {
    //! BIP68 relative-lock enforcement compares the transaction version as the unsigned
    //! wire value (Core's `uint32_t` `CTransaction::version`).
    //!
    //! BIP325 signet solutions are checked when a block commits and not when it is
    //! proposed.

    use std::sync::Arc;

    use crate::chain::regtest_fixture::{
        coinbase, mine_block_to_declared_target, mined_block_with_prev_hash,
        mined_regtest_child_at as mined_child,
    };
    use bitcoin_rs_consensus::ConsensusError;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, BlockImage, LockTime, Network, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Witness, consensus_bytes, deserialize,
    };

    use super::ApplyError;
    use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};

    mod bip30_overwrite {
        use std::sync::Arc;

        use bitcoin_rs_consensus::bip30::BIP30_DUPLICATE_TXID_EXCEPTIONS;
        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime,
            Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, deserialize,
        };
        use bitcoin_rs_storage::ColumnFamily;
        use bitcoin_rs_storage::StorageError;
        use bitcoin_rs_storage::block_body::BlockBodyStore;
        use bitcoin_rs_storage::coins::CoinKey;
        use bitcoin_rs_storage::utxo::UtxoSet;
        use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

        use crate::connect::{ChangeRequest, build_block_changes_checked};
        use crate::test_fixtures::{TestError, TestResult, handles};

        fn coinbase_tx() -> Tx {
            Tx {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: Script::from_bytes(vec![0x51]),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                }],
                lock_time: LockTime::ZERO,
            }
        }

        #[test]
        fn exception_block_undo_removes_the_coin_it_overwrites() -> TestResult {
            let (exception_height, exception_hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
            let coinbase = coinbase_tx();
            let txid = coinbase.txid();
            let block = Block {
                header: Header {
                    version: 1,
                    prev_blockhash: BlockHash(Hash256::default()),
                    merkle_root: Hash256::default(),
                    time: 1_300_000_000,
                    bits: CompactTarget::from_consensus(0x1d00ffff),
                    nonce: 1,
                },
                txs: vec![coinbase],
            };
            let image = BlockImage::from_local(block);

            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let prior = OwnedUtxoOut {
                vout: 0,
                value: 50_000,
                script_pubkey: vec![0x51],
                coinbase: true,
                height: 1,
            };
            let record = UtxoRecord::from_owned_outputs(txid.0, &[prior])
                .map_err(|_| TestError::Missing("prior coin record"))?;
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                record.bytes(),
            )?;

            let txids = [txid];
            let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
            let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
                &crate::connect::ChainstateUtxoSource::new(&chain),
                &image,
                &tx_plan,
            ));
            let Ok((_changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
                image: &image,
                block_hash: exception_hash,
                height: exception_height,
                txids: &txids,
                tx_plan: &tx_plan,
                resolved: &resolved,
            }) else {
                return Err(TestError::Missing(
                    "the BIP30 exception block must build its changes",
                ));
            };

            let overwritten = OutPoint::new(txid, 0);
            if undo
                .restores()
                .iter()
                .any(|restore| restore.outpoint == overwritten)
            {
                return Err(TestError::Missing(
                    "the exception block's undo must not restore the coin it overwrites, as Bitcoin Core",
                ));
            }
            if !undo.removes().contains(&overwritten) {
                return Err(TestError::Missing(
                    "the exception block's undo must remove the coin it overwrites",
                ));
            }
            Ok(())
        }

        #[test]
        fn exception_block_disconnect_drops_the_overwritten_engine_coin() -> TestResult {
            let (exception_height, exception_hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
            let coinbase = coinbase_tx();
            let txid = coinbase.txid();
            let block = Block {
                header: Header {
                    version: 1,
                    prev_blockhash: BlockHash(Hash256::default()),
                    merkle_root: Hash256::default(),
                    time: 1_300_000_000,
                    bits: CompactTarget::from_consensus(0x1d00ffff),
                    nonce: 1,
                },
                txs: vec![coinbase],
            };
            let image = BlockImage::from_local(block);

            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let prior = OwnedUtxoOut {
                vout: 0,
                value: 50_000,
                script_pubkey: vec![0x51],
                coinbase: true,
                height: 1,
            };
            let prior_record = UtxoRecord::from_owned_outputs(txid.0, &[prior])
                .map_err(|_| TestError::Missing("prior coin record"))?;
            let key = CoinKey(txid.0.to_le_bytes());
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                prior_record.bytes(),
            )?;

            let txids = [txid];
            let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
            let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
                &crate::connect::ChainstateUtxoSource::new(&chain),
                &image,
                &tx_plan,
            ));
            let Ok((changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
                image: &image,
                block_hash: exception_hash,
                height: exception_height,
                txids: &txids,
                tx_plan: &tx_plan,
                resolved: &resolved,
            }) else {
                return Err(TestError::Missing(
                    "the BIP30 exception block must build its changes",
                ));
            };

            let created: Vec<OwnedUtxoOut> = changes
                .adds()
                .iter()
                .filter(|add| add.outpoint.txid == txid)
                .map(|add| OwnedUtxoOut {
                    vout: add.outpoint.vout,
                    value: add.txout.value.to_sat(),
                    script_pubkey: add.txout.script_pubkey.to_vec(),
                    coinbase: add.coinbase,
                    height: add.height,
                })
                .collect();
            let post_connect = UtxoRecord::from_owned_outputs(txid.0, &created)
                .map_err(|_| TestError::Missing("post-connect coin record"))?;
            chain.coins.wipe()?;
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                post_connect.bytes(),
            )?;

            let delta = crate::disconnect::build_disconnect_delta(&chain.coins, &undo)?;
            let (_, remaining) = delta
                .records
                .iter()
                .find(|(record_key, _)| record_key.as_bytes() == key.as_bytes())
                .ok_or(TestError::Missing(
                    "disconnect must rewrite the exception block's txid",
                ))?;
            if remaining.is_some() {
                return Err(TestError::Missing(
                    "disconnect must drop the overwritten coin, as Bitcoin Core",
                ));
            }
            Ok(())
        }
        // CMT-06
        #[test]
        fn overwriting_block_disconnect_derives_removal_as_before() -> TestResult {
            let (exception_height, _) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
            let coinbase = coinbase_tx();
            let txid = coinbase.txid();
            let block = Block {
                header: Header {
                    version: 1,
                    prev_blockhash: BlockHash(Hash256::default()),
                    merkle_root: Hash256::default(),
                    time: 1_300_000_000,
                    bits: CompactTarget::from_consensus(0x1d00ffff),
                    nonce: 1,
                },
                txs: vec![coinbase],
            };
            let block_hash = Hash256::from(block.block_hash());
            let image = BlockImage::from_local(block.clone());
            let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let prior = OwnedUtxoOut {
                vout: 0,
                value: 50_000,
                script_pubkey: vec![0x51],
                coinbase: true,
                height: 1,
            };
            let prior_record = UtxoRecord::from_owned_outputs(txid.0, &[prior])
                .map_err(|_| TestError::Missing("prior coin record"))?;
            let key = CoinKey(txid.0.to_le_bytes());
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                prior_record.bytes(),
            )?;
            let txids = [txid];
            let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
            let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
                &crate::connect::ChainstateUtxoSource::new(&chain),
                &image,
                &tx_plan,
            ));
            let Ok((changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
                image: &image,
                block_hash,
                height: exception_height,
                txids: &txids,
                tx_plan: &tx_plan,
                resolved: &resolved,
            }) else {
                return Err(TestError::Missing(
                    "the BIP30 exception block must build its changes",
                ));
            };
            let created: Vec<OwnedUtxoOut> = changes
                .adds()
                .iter()
                .filter(|add| add.outpoint.txid == txid)
                .map(|add| OwnedUtxoOut {
                    vout: add.outpoint.vout,
                    value: add.txout.value.to_sat(),
                    script_pubkey: add.txout.script_pubkey.to_vec(),
                    coinbase: add.coinbase,
                    height: add.height,
                })
                .collect();
            let pre_bytes = prior_record.bytes().to_vec();
            if pre_bytes.is_empty() {
                return Err(TestError::Missing(
                    "prior coin set must hold the overwritten coin",
                ));
            }
            let post_connect = UtxoRecord::from_owned_outputs(txid.0, &created)
                .map_err(|_| TestError::Missing("post-connect coin record"))?;
            chain.coins.wipe()?;
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                post_connect.bytes(),
            )?;
            let encoded = bitcoin_rs_storage::utxo::contract::encode_undo_record(&undo, block_hash);
            let derived =
                bitcoin_rs_storage::utxo::contract::decode_undo_record_for_block(&encoded, &block)
                    .map_err(|_| TestError::Missing("derived undo must decode"))?;
            if !derived.restores().is_empty() {
                return Err(TestError::Missing(
                    "derived undo must hold no overwritten restore",
                ));
            }
            let overwritten = OutPoint::new(txid, 0);
            if !derived.removes().contains(&overwritten) {
                return Err(TestError::Missing(
                    "derived undo must remove the created outpoint",
                ));
            }
            let delta = crate::disconnect::build_disconnect_delta(&chain.coins, &derived)?;
            let (_, remaining) = delta
                .records
                .iter()
                .find(|(record_key, _)| record_key.as_bytes() == key.as_bytes())
                .ok_or(TestError::Missing(
                    "disconnect must rewrite the exception block's txid",
                ))?;
            if remaining.is_some() {
                return Err(TestError::Missing(
                    "disconnect must drop the overwritten coin, as Bitcoin Core",
                ));
            }
            Ok(())
        }

        struct FakeBlockLoader {
            height: u32,
            hash: Hash256,
            body: Vec<u8>,
        }

        impl BlockBodyStore for FakeBlockLoader {
            fn persist_block_body(
                &self,
                _height: u32,
                _hash: Hash256,
                _body: &[u8],
            ) -> Result<(), StorageError> {
                Err(StorageError::backend("the fake block loader is read-only"))
            }

            fn load_block_body(
                &self,
                height: u32,
                hash: Hash256,
            ) -> Result<Option<Vec<u8>>, StorageError> {
                Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
            }

            fn sync(&self) -> Result<(), StorageError> {
                Ok(())
            }
        }

        #[test]
        fn read_bip30_overwrite_undo_removes_the_overwritten_coin() -> TestResult {
            let (exception_height, exception_hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.block_body_store = Some(Arc::new(FakeBlockLoader {
                height: exception_height,
                hash: exception_hash,
                body: include_bytes!("../../../testdata/consensus/blocks/91842.bin").to_vec(),
            }));
            let body = chain
                .block_body_store
                .as_ref()
                .ok_or(TestError::Missing("the fake block loader is installed"))?
                .load_block_body(exception_height, exception_hash)?
                .ok_or(TestError::Missing("the loader serves the exception block"))?;
            let block = deserialize::<Block>(&body)
                .map_err(|_| TestError::Missing("the exception block must decode"))?;
            assert_eq!(
                Hash256::from(block.block_hash()),
                exception_hash,
                "the loaded block must be the BIP30 exception block"
            );
            let image = BlockImage::from_local(block.clone());
            let txids: Vec<_> = block.txs.iter().map(Tx::txid).collect();

            let prior = OwnedUtxoOut {
                vout: 0,
                value: 5_000_000_000,
                script_pubkey: vec![0x51],
                coinbase: true,
                height: 91_812,
            };
            let record = UtxoRecord::from_owned_outputs(txids[0].0, &[prior])
                .map_err(|_| TestError::Missing("prior coin record"))?;
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txids[0].0.to_le_bytes()).as_bytes(),
                record.bytes(),
            )?;

            let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
            let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
                &crate::connect::ChainstateUtxoSource::new(&chain),
                &image,
                &tx_plan,
            ));
            let Ok((_changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
                image: &image,
                block_hash: exception_hash,
                height: exception_height,
                txids: &txids,
                tx_plan: &tx_plan,
                resolved: &resolved,
            }) else {
                return Err(TestError::Missing(
                    "the BIP30 exception block must build its changes",
                ));
            };

            let overwritten = OutPoint::new(txids[0], 0);
            if undo
                .restores()
                .iter()
                .any(|entry| entry.outpoint == overwritten)
            {
                return Err(TestError::Missing(
                    "the undo must not restore the engine coin the exception block overwrites, as Bitcoin Core",
                ));
            }
            if !undo.removes().contains(&overwritten) {
                return Err(TestError::Missing(
                    "the undo must remove the engine coin the exception block overwrites",
                ));
            }
            Ok(())
        }
    }
    mod resolve_batch {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use bitcoin_rs_consensus::primitives::{
            Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime,
            Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
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

            fn delete_range(
                &self,
                cf: ColumnFamily,
                start: &[u8],
                end: &[u8],
            ) -> Result<(), StorageError> {
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

        fn local_block(txs: Vec<Tx>) -> Block {
            Block {
                header: Header {
                    version: 1,
                    prev_blockhash: BlockHash(Hash256::default()),
                    merkle_root: Hash256::default(),
                    time: 1_300_000_000,
                    bits: CompactTarget::from_consensus(0x1d00ffff),
                    nonce: 1,
                },
                txs,
            }
        }

        fn funded_record(txid: Txid, base: u64) -> TestResult<(UtxoRecord, Vec<UtxoCoin>)> {
            let outputs: Vec<OwnedUtxoOut> = (0..3_u32)
                .map(|vout| {
                    OwnedUtxoOut::new(vout, base + u64::from(vout), vec![OP_PUSHNUM_1], false, 7)
                })
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
            let block = local_block(txs);
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
            let block = local_block(txs);
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
            let block = local_block(txs);
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
            let prevouts = crate::prepare::resolve_block_prevouts(
                Arc::new(resolved),
                &image,
                &tx_plan,
                2,
                &txids,
                None,
            )?;
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
            let block = local_block(txs);
            let image = BlockImage::from_local(block);
            let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
            let handle = ChargeHandle::new(Arc::new(RefusingCharge), BudgetOwner::StagedImages);
            let multi_before = store.coin_multi_gets.load(Ordering::SeqCst);
            let keys_before = store.coin_multi_get_keys.load(Ordering::SeqCst);
            let source = ChainstateUtxoSource::new(&chain);
            let result =
                crate::ResolvedUtxoView::resolve_charged(&source, &image, &tx_plan, Some(handle));
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

        #[test]
        fn duplicate_outpoints_preserve_zip_association_and_first_seen_order() -> TestResult {
            let store = Arc::new(CountingStore::default());
            let mut chain = handles_with_store(
                Network::Regtest,
                Arc::new(UtxoSet::new()),
                Arc::clone(&store),
            );
            let dyn_store: Arc<dyn KvStore> = store.clone();
            chain.coins = Arc::new(CoinStore::open(dyn_store, 0));

            let txid = Txid(Hash256::from_le_bytes(&[0x33; 32]));
            let (record, coins) = funded_record(txid, 5_000)?;
            chain.commit_authority.store().put(
                ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                record.bytes(),
            )?;

            let spent = [
                OutPoint::new(txid, 0),
                OutPoint::new(txid, 0),
                OutPoint::new(txid, 1),
            ];
            let txs = vec![
                coinbase_tx(),
                spend_tx(&spent[0..1]),
                spend_tx(&spent[1..2]),
                spend_tx(&spent[2..3]),
            ];
            let txids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
            let block = local_block(txs);
            let image = BlockImage::from_local(block);
            let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
            let source = ChainstateUtxoSource::new(&chain);
            let resolved = crate::ResolvedUtxoView::resolve(&source, &image, &tx_plan);
            source.into_result()?;

            assert_eq!(resolved.entry(&OutPoint::new(txid, 0)), Some(&coins[0]));
            assert_eq!(resolved.entry(&OutPoint::new(txid, 1)), Some(&coins[1]));
            Ok(())
        }
    }
    mod sigops {
        //! Block budgets must survive script-proof and execution-skip paths (#1728).

        use super::*;
        use crate::chain::NodeStatus;
        use crate::chain::regtest_fixture::merkle_root;
        use crate::test_fixtures::TestError;
        use crate::{AssumeValidGate, ValidationMode, WindowApplyDisposition};
        use bitcoin_rs_consensus::primitives::encode::double_sha256;
        use bitcoin_rs_consensus::script::{opcode::*, push_data};
        use sha2::{Digest, Sha256};

        fn funded_chain() -> TestResult<(crate::Chainstate, Tx, BlockHash)> {
            let chain = handles(
                Network::Regtest,
                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            );
            seed_genesis(&chain)?;
            let mut funding = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
            funding.txs[0].outputs = (0..11)
                .map(|_| TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: vec![OP_PUSHNUM_1].into(),
                })
                .collect();
            remine(&mut funding)?;
            chain.apply_block(&BlockImage::from_local(funding.clone()))?;
            let mut parent = funding.block_hash();
            for height in 2..=100 {
                let child = mined_child(parent, height)?;
                chain.apply_block(&BlockImage::from_local(child.clone()))?;
                parent = child.block_hash();
            }
            Ok((chain, funding.txs.remove(0), parent))
        }

        fn remine(block: &mut Block) -> TestResult {
            block.header.merkle_root =
                merkle_root(&block.txs).ok_or(TestError::Missing("missing merkle root"))?;
            mine_block_to_declared_target(block)?;
            Ok(())
        }

        fn spend(inputs: Vec<TxIn>) -> Tx {
            Tx {
                version: 2,
                inputs,
                outputs: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: vec![OP_PUSHNUM_1].into(),
                }],
                lock_time: LockTime::ZERO,
            }
        }

        fn input(outpoint: OutPoint, script_sig: Vec<u8>, witness: Witness) -> TxIn {
            TxIn {
                previous_output: outpoint,
                script_sig: script_sig.into(),
                sequence: Sequence::MAX,
                witness,
            }
        }

        fn legacy_block(parent: BlockHash, funding: &Tx, transactions: u32) -> TestResult<Block> {
            let mut block = legacy_block_body(parent, funding, transactions)?;
            remine(&mut block)?;
            Ok(block)
        }

        fn legacy_block_with_coinbase_sigop(
            parent: BlockHash,
            funding: &Tx,
            transactions: u32,
        ) -> TestResult<Block> {
            let mut block = legacy_block_body(parent, funding, transactions)?;
            block.txs[0].outputs.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: vec![OP_CHECKSIG].into(),
            });
            remine(&mut block)?;
            Ok(block)
        }

        fn legacy_sigop_heavy_script() -> Vec<u8> {
            (0..100)
                .flat_map(|_| [OP_0, OP_0, OP_0, OP_CHECKMULTISIG, OP_DROP])
                .chain([OP_PUSHNUM_1])
                .collect()
        }

        fn dead_branch_multisig_script() -> Vec<u8> {
            [
                vec![OP_0, OP_IF],
                vec![OP_CHECKMULTISIG; 100],
                vec![OP_ENDIF, OP_PUSHNUM_1],
            ]
            .concat()
        }

        fn legacy_block_body(
            parent: BlockHash,
            funding: &Tx,
            transactions: u32,
        ) -> TestResult<Block> {
            let mut block = mined_child(parent, 101)?;
            let script = legacy_sigop_heavy_script();
            for vout in 0..transactions {
                block.txs.push(spend(vec![input(
                    OutPoint::new(funding.txid(), vout),
                    script.clone(),
                    Witness::new(),
                )]));
            }
            Ok(block)
        }

        #[derive(Clone, Copy)]
        enum Path {
            Direct,
            Proposal,
            Window,
            AssumeValid,
        }

        fn check_budget(
            chain: &mut crate::Chainstate,
            block: Block,
            path: Path,
            expected: &Result<(), ConsensusError>,
        ) -> TestResult {
            let hash = block.block_hash().0;
            if matches!(path, Path::Window | Path::AssumeValid) {
                chain
                    .block_tree
                    .write()
                    .insert_header(block.header, NodeStatus::HeaderValid)?;
            }
            if matches!(path, Path::AssumeValid) {
                chain.validation_mode = ValidationMode::AssumeValid;
                chain.assume_valid_height = 101;
                chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((101, hash))));
                chain.assume_valid_gate.evaluate(&chain.block_tree.read());
                assert!(chain.scripts_verified_upstream(
                    crate::BlockProvenance::Network,
                    101,
                    hash
                ));
            }
            let snapshot = chain.chain_snapshot();
            let tip = chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("missing applied tip"))?
                .hash;
            let head = chain.durable_head.load()?;
            let stats = chain.coin_stats.snapshot().to_bytes();
            let utxo_len = chain.utxo.len();
            let inputs: Vec<_> = block
                .txs
                .iter()
                .flat_map(|tx| &tx.inputs)
                .map(|input| {
                    (
                        input.previous_output,
                        chain.utxo.get(&input.previous_output),
                    )
                })
                .collect();
            let outputs: Vec<_> = block
                .txs
                .iter()
                .map(|tx| OutPoint::new(tx.txid(), 0))
                .collect();
            let payload = BlockImage::from_local(block);
            let result = match path {
                Path::Proposal => chain.validate_block(&payload),
                Path::Direct | Path::AssumeValid => chain.apply_block(&payload).map(|_| ()),
                Path::Window => chain
                    .apply_window(&[&payload])
                    .map(|_| ())
                    .map_err(|error| {
                        assert_eq!(error.applied, 0);
                        assert!(error.committed.is_empty());
                        assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
                        assert!(error.invalidated.contains(&hash));
                        *error.source
                    }),
            };
            match &expected {
                Ok(()) => {
                    result?;
                }
                Err(expected_error) => match &result {
                    Err(ApplyError::Consensus(err)) => {
                        assert_eq!(err, expected_error, "{result:?}")
                    }
                    other => {
                        panic!(
                            "expected Err(ApplyError::Consensus({expected_error:?})), got {other:?}"
                        )
                    }
                },
            }
            if expected.is_err() || matches!(path, Path::Proposal) {
                assert_eq!(chain.chain_snapshot(), snapshot);
                assert_eq!(
                    chain
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("missing applied tip"))?
                        .hash,
                    tip
                );
                assert_eq!(chain.durable_head.load()?, head);
                assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
                assert_eq!(chain.utxo.len(), utxo_len);
                for (outpoint, output) in inputs {
                    assert_eq!(chain.utxo.get(&outpoint), output);
                }
                for outpoint in outputs {
                    assert!(chain.utxo.get(&outpoint).is_none());
                }
            } else {
                assert_eq!(
                    chain
                        .applied_tip_snapshot()
                        .ok_or(TestError::Missing("missing applied tip"))?
                        .hash,
                    hash
                );
            }
            Ok(())
        }

        #[test]
        fn aggregate_sigops_enforce_the_inclusive_budget_on_every_connect_path() -> TestResult {
            for path in [
                Path::Direct,
                Path::Proposal,
                Path::Window,
                Path::AssumeValid,
            ] {
                for (transactions, cost) in [(10, 80_000), (11, 88_000)] {
                    let (mut chain, funding, parent) = funded_chain()?;
                    let block = legacy_block(parent, &funding, transactions)?;
                    let expected = if cost > 80_000 {
                        Err(ConsensusError::SigopsLimit { cost, max: 80_000 })
                    } else {
                        Ok(())
                    };
                    check_budget(&mut chain, block, path, &expected)?;
                }
                let (mut chain, funding, parent) = funded_chain()?;
                let block = legacy_block_with_coinbase_sigop(parent, &funding, 10)?;
                check_budget(
                    &mut chain,
                    block,
                    path,
                    &Err(ConsensusError::SigopsLimit {
                        cost: 80_004,
                        max: 80_000,
                    }),
                )?;
            }
            Ok(())
        }

        #[test]
        fn coinbase_only_blocks_obey_the_sigop_budget() -> TestResult {
            for (count, cost) in [(1_000, 80_000), (1_001, 80_080)] {
                let mut chain = handles(
                    Network::Regtest,
                    Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
                );
                seed_genesis(&chain)?;
                let mut block = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
                block.txs[0].outputs[0].script_pubkey = vec![OP_CHECKMULTISIG; count].into();
                remine(&mut block)?;
                let expected = if cost > 80_000 {
                    Err(ConsensusError::SigopsLimit { cost, max: 80_000 })
                } else {
                    Ok(())
                };
                check_budget(&mut chain, block, Path::Direct, &expected)?;
            }
            Ok(())
        }

        #[test]
        fn same_block_p2sh_and_witness_sigops_count_toward_the_budget() -> TestResult {
            let script = dead_branch_multisig_script();
            for witness in [false, true] {
                for extra in [false, true] {
                    let (mut chain, funding, parent) = funded_chain()?;
                    let program = if witness {
                        [vec![0, 32], Sha256::digest(&script).to_vec()].concat()
                    } else {
                        let hash = vec![
                            0x60, 0xdc, 0xe5, 0xf8, 0x78, 0x81, 0x19, 0xd9, 0x6e, 0x0d, 0x6e, 0xf6,
                            0x8b, 0x00, 0x72, 0x63, 0x85, 0xdc, 0x39, 0xe5,
                        ];
                        [vec![OP_HASH160, 20], hash, vec![OP_EQUAL]].concat()
                    };
                    let count: u32 = if witness { 40 } else { 10 };
                    let mut create = spend(vec![input(
                        OutPoint::new(funding.txid(), 0),
                        Vec::new(),
                        Witness::new(),
                    )]);
                    create.outputs = (0..count)
                        .map(|_| TxOut {
                            value: Amount::from_sat(100),
                            script_pubkey: program.clone().into(),
                        })
                        .collect();
                    let inputs = (0..count)
                        .map(|vout| {
                            input(
                                OutPoint::new(create.txid(), vout),
                                if witness {
                                    Vec::new()
                                } else {
                                    push_data(&script)
                                },
                                if witness {
                                    Witness::from_stack(vec![script.clone()])
                                } else {
                                    Witness::new()
                                },
                            )
                        })
                        .collect();
                    let mut block = mined_child(parent, 101)?;
                    block.txs.extend([create, spend(inputs)]);
                    if extra {
                        block.txs[0].outputs.push(TxOut {
                            value: Amount::ZERO,
                            script_pubkey: vec![OP_CHECKSIG].into(),
                        });
                    }
                    if witness {
                        block.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
                        let mut leaves = vec![[0; 32]];
                        leaves.extend(
                            block
                                .txs
                                .iter()
                                .skip(1)
                                .map(|tx| *tx.wtxid().0.as_byte_array()),
                        );
                        let root = bitcoin_rs_consensus::compute_merkle_root(&mut leaves)
                            .ok_or(TestError::Missing("missing witness root"))?;
                        let commitment = double_sha256(&[root, [0; 32]].concat());
                        block.txs[0].outputs.push(TxOut {
                            value: Amount::ZERO,
                            script_pubkey: [
                                vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
                                commitment.as_byte_array().to_vec(),
                            ]
                            .concat()
                            .into(),
                        });
                    }
                    remine(&mut block)?;
                    let expected = if extra {
                        Err(ConsensusError::SigopsLimit {
                            cost: 80_004,
                            max: 80_000,
                        })
                    } else {
                        Ok(())
                    };
                    check_budget(&mut chain, block, Path::Window, &expected)?;
                }
            }
            Ok(())
        }

        #[test]
        fn empty_coinbase_outputs_rejected_on_every_connect_path() -> TestResult {
            for path in [
                Path::Direct,
                Path::Proposal,
                Path::Window,
                Path::AssumeValid,
            ] {
                let (mut chain, _funding, parent) = funded_chain()?;
                let mut block = mined_child(parent, 101)?;
                block.txs[0].outputs.clear();
                remine(&mut block)?;
                check_budget(&mut chain, block, path, &Err(ConsensusError::EmptyOutputs))?;
            }
            Ok(())
        }
    }
    mod transaction_structure {
        //! Context-free transaction rules survive every script execution policy (#1737).

        use super::*;
        use crate::{AssumeValidGate, BlockProvenance, ValidationMode, WindowApplyDisposition};

        #[derive(Clone, Copy, Debug)]
        enum Path {
            Direct,
            Proposal,
            Window,
        }

        fn remine(block: &mut Block) -> TestResult {
            block.header.merkle_root = crate::chain::regtest_fixture::merkle_root(&block.txs)
                .ok_or("missing merkle root")?;
            mine_block_to_declared_target(block)?;
            Ok(())
        }

        #[test]
        fn zero_output_coinbase_never_publishes_under_any_script_policy() -> TestResult {
            for height in [1, 101] {
                for mode in [ValidationMode::Full, ValidationMode::AssumeValid] {
                    for path in [Path::Direct, Path::Proposal, Path::Window] {
                        for spends in 0..=if height == 101 { 2 } else { 0 } {
                            let mut chain = handles(
                                Network::Regtest,
                                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
                            );
                            seed_genesis(&chain)?;
                            let parent = apply_regtest_chain_to_height(&chain, height - 1)?;
                            let funding = OutPoint::new(coinbase(1).txid(), 0);
                            let funding_before = chain.utxo_reader().get(&funding)?;
                            let mut block = mined_child(parent, height)?;
                            block.txs[0].outputs.clear();
                            if spends > 0 {
                                let first = op_true_spend(funding, 1_000);
                                if spends == 2 {
                                    let second = op_true_spend(OutPoint::new(first.txid(), 0), 900);
                                    block.txs.extend([first, second]);
                                } else {
                                    block.txs.push(first);
                                }
                            }
                            remine(&mut block)?;
                            let hash = block.block_hash().0;
                            let successor = mined_child(block.block_hash(), height + 1)?;
                            chain.admit_headers(&[block.header, successor.header])?;
                            chain.validation_mode = mode;
                            if mode == ValidationMode::AssumeValid {
                                chain.assume_valid_height = height;
                                chain.assume_valid_gate =
                                    Arc::new(AssumeValidGate::with_anchor(Some((height, hash))));
                                chain.assume_valid_gate.evaluate(&chain.block_tree.read());
                            }
                            assert_eq!(
                                chain.scripts_verified_upstream(
                                    BlockProvenance::Network,
                                    height,
                                    hash
                                ),
                                mode != ValidationMode::Full
                            );
                            let tip = chain.applied_tip_snapshot().ok_or("missing tip")?;
                            let snapshot = chain.chain_snapshot();
                            let head = chain.durable_head.load()?;
                            let stats = chain.coin_stats.snapshot().to_bytes();
                            let utxo_len = chain.utxo.len();
                            let outputs: Vec<_> = block
                                .txs
                                .iter()
                                .skip(1)
                                .map(|tx| OutPoint::new(tx.txid(), 0))
                                .collect();
                            let payload = BlockImage::from_local(block);
                            let result = match path {
                                Path::Direct => chain.apply_block(&payload).map(|_| ()),
                                Path::Proposal => chain.validate_block(&payload),
                                Path::Window => chain
                                    .apply_window(&[&payload])
                                    .map(|_| ())
                                    .map_err(|error| {
                                        assert_eq!(error.applied, 0);
                                        assert!(error.committed.is_empty());
                                        assert_eq!(
                                            error.disposition,
                                            WindowApplyDisposition::Permanent
                                        );
                                        assert!(error.invalidated.contains(&hash));
                                        *error.source
                                    }),
                            };
                            assert!(
                                matches!(
                                    result,
                                    Err(ApplyError::Consensus(ConsensusError::EmptyOutputs))
                                ),
                                "height={height}, mode={mode:?}, path={path:?}, spends={spends}: {result:?}"
                            );
                            assert_eq!(chain.chain_snapshot(), snapshot);
                            assert_eq!(
                                chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
                                tip.hash
                            );
                            assert_eq!(chain.durable_head.load()?, head);
                            assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
                            assert_eq!(chain.utxo.len(), utxo_len);
                            assert_eq!(chain.utxo_reader().get(&funding)?, funding_before);
                            for outpoint in outputs {
                                assert!(chain.utxo_reader().get(&outpoint)?.is_none());
                            }
                            assert!(chain.undo_store.load_undo(height, hash)?.is_none());
                        }
                    }
                }
            }
            Ok(())
        }

        #[test]
        fn proposal_and_commit_agree_on_coinbase_finality_without_proposal_side_effects()
        -> TestResult {
            let non_final_time = Network::Regtest.genesis_block().header.time + 101;
            for (locktime, is_final) in [(100, true), (101, false), (non_final_time, false)] {
                let chain = handles(
                    Network::Regtest,
                    Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
                );
                seed_genesis(&chain)?;
                let parent = apply_regtest_chain_to_height(&chain, 100)?;
                let mut block = mined_child(parent, 101)?;
                block.txs[0].lock_time = LockTime::from_consensus(locktime);
                block.txs[0].inputs[0].sequence = Sequence::ZERO;
                remine(&mut block)?;
                let payload = BlockImage::from_local(block);
                let tip = chain.applied_tip_snapshot().ok_or("missing tip")?;
                let snapshot = chain.chain_snapshot();
                let head = chain.durable_head.load()?;
                let stats = chain.coin_stats.snapshot().to_bytes();
                let utxo_len = chain.utxo.len();
                let proposed = chain.validate_block(&payload);
                assert_eq!(chain.chain_snapshot(), snapshot);
                assert_eq!(
                    chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
                    tip.hash
                );
                assert_eq!(chain.durable_head.load()?, head);
                assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
                assert_eq!(chain.utxo.len(), utxo_len);
                let committed = chain.apply_block(&payload);
                if is_final {
                    proposed?;
                    committed?;
                } else {
                    for result in [proposed, committed.map(|_| ())] {
                        assert!(
                            matches!(
                                result,
                                Err(ApplyError::Consensus(ConsensusError::Bip {
                                    bip: "BIP113",
                                    ..
                                }))
                            ),
                            "{result:?}"
                        );
                    }
                    assert_eq!(chain.chain_snapshot(), snapshot);
                    assert_eq!(
                        chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
                        tip.hash
                    );
                    assert_eq!(chain.durable_head.load()?, head);
                    assert_eq!(chain.coin_stats.snapshot().to_bytes(), stats);
                    assert_eq!(chain.utxo.len(), utxo_len);
                }
            }
            Ok(())
        }
    }

    fn empty_handles() -> Arc<crate::Chainstate> {
        Arc::new(handles(
            Network::Regtest,
            Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
        ))
    }

    fn apply_regtest_chain_to_height(
        handles: &crate::Chainstate,
        height: u32,
    ) -> TestResult<BlockHash> {
        let genesis = Network::Regtest.genesis_block();
        let mut parent = genesis.block_hash();
        for current in 1..=height {
            let block = mined_child(parent, current)?;
            handles.apply_block(&BlockImage::from_local(block.clone()))?;
            parent = block.block_hash();
        }
        Ok(parent)
    }

    fn version_max_spend(sequence: u32, version: u32) -> Tx {
        Tx {
            version,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(coinbase(1).txid(), 0),
                script_sig: Script::from_bytes(vec![0x51]),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn op_true_spend(previous_output: OutPoint, value: u64) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::from_bytes(vec![0x51]),
                sequence: Sequence::from_consensus(0xffff_ffff),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    #[test]
    fn capture_rawtx_changes_only_the_outcome_payload() -> TestResult {
        let external = op_true_spend(OutPoint::new(coinbase(1).txid(), 0), 1_000);
        let same_block = op_true_spend(OutPoint::new(external.txid(), 0), 900);
        let final_outpoint = OutPoint::new(same_block.txid(), 0);
        let intermediate_outpoint = OutPoint::new(external.txid(), 0);
        let spent_outpoint = OutPoint::new(coinbase(1).txid(), 0);

        let mut outcomes = Vec::new();
        let mut undo_records = Vec::new();
        for capture_rawtx in [false, true] {
            let mut handles = handles(
                Network::Regtest,
                Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
            );
            seed_genesis(&handles)?;
            let tip_hash = apply_regtest_chain_to_height(&handles, 500)?;
            handles.set_capture_flags(capture_rawtx, false);
            let block = mined_block_with_prev_hash(
                tip_hash,
                501,
                vec![coinbase(501), external.clone(), same_block.clone()],
            )?;
            let outcome = handles.apply_block(&BlockImage::from_local(block.clone()))?;

            let utxo = handles.utxo_reader();
            assert!(
                utxo.get_entry(&spent_outpoint)?.is_none(),
                "external coin spent"
            );
            assert!(
                utxo.get_entry(&intermediate_outpoint)?.is_none(),
                "same-block coin spent"
            );
            let final_coin = utxo
                .get_entry(&final_outpoint)?
                .ok_or(TestError::Missing("final same-block output must be live"))?;
            assert_eq!(final_coin.txout.value.to_sat(), 900);

            match (&outcome.raw_txs, capture_rawtx) {
                (None, false) => {}
                (Some(raw_txs), true) => {
                    assert_eq!(raw_txs.len(), block.txs.len());
                    for (raw, tx) in raw_txs.iter().zip(&block.txs) {
                        assert_eq!(*raw, bitcoin_rs_consensus::primitives::consensus_bytes(tx));
                    }
                }
                (raw, flag) => panic!("raw_txs presence must follow capture_rawtx={flag}: {raw:?}"),
            }

            let undo =
                handles
                    .undo_store
                    .load_undo(501, outcome.hash)?
                    .ok_or(TestError::Missing(
                        "a committed block must persist its undo record",
                    ))?;
            assert!(!undo.is_empty(), "undo record must carry the spent coins");
            undo_records.push(undo);

            handles.disconnect_block(&block)?;
            let utxo = handles.utxo_reader();
            assert!(
                utxo.get_entry(&spent_outpoint)?.is_some(),
                "undo restores coin"
            );
            assert!(
                utxo.get_entry(&final_outpoint)?.is_none(),
                "undo removes output"
            );
            outcomes.push(outcome);
        }

        let (without, with) = (&outcomes[0], &outcomes[1]);
        assert_eq!(without.txids, with.txids);
        assert_eq!(without.hash, with.hash);
        assert_eq!(without.tip.height, with.tip.height);
        assert_eq!(without.tip.hash, with.tip.hash);
        assert_eq!(without.tip.chain_tx_count, with.tip.chain_tx_count);
        assert_eq!(without.commit_id, with.commit_id);
        assert_eq!(
            undo_records[0], undo_records[1],
            "undo bytes must be identical"
        );
        Ok(())
    }

    #[test]
    fn version_max_tx_enforces_bip68_relative_lock() -> TestResult {
        let handles = empty_handles();
        seed_genesis(&handles)?;

        let spend = version_max_spend(1000, u32::MAX);
        let tip_hash = apply_regtest_chain_to_height(&handles, 500)?;
        let mut block = mined_block_with_prev_hash(tip_hash, 501, vec![coinbase(501), spend])?;
        let error = handles
            .apply_block(&BlockImage::from_local(block.clone()))
            .err()
            .ok_or(TestError::UnexpectedSuccess(
                "an unmet relative lock must reject the block",
            ))?;
        let ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip, .. }) = error
        else {
            panic!("expected a BIP68 consensus error, got {error:?}");
        };
        assert_eq!(bip, "BIP68");

        let handles = empty_handles();
        seed_genesis(&handles)?;
        let tip_hash = apply_regtest_chain_to_height(&handles, 500)?;
        block = mined_block_with_prev_hash(
            tip_hash,
            501,
            vec![coinbase(501), version_max_spend(1000, 1)],
        )?;
        handles.apply_block(&BlockImage::from_local(block))?;
        Ok(())
    }

    const CORE_SIGNET_BLOCK_1: &str = "00000020f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000f575c83235984e7dc4afc1f30944c170462e84437ab6f2d52e16878a79e4678bd1914d5fae77031eccf4070001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025151feffffff0200f2052a010000001600149243f727dd5343293eb83174324019ec16c2630f0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402205e423a8754336ca99dbe16509b877ef1bf98d008836c725005b3c787c41ebe46022047246e4467ad7cc7f1ad98662afcaf14c115e0095a227c7b05c5182591c23e7e01000120000000000000000000000000000000000000000000000000000000000000000000000000";

    /// The marker of the BIP325 solution inside the witness-commitment output.
    const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

    fn signet_block_1() -> TestResult<Block> {
        let bytes = (0..CORE_SIGNET_BLOCK_1.len())
            .step_by(2)
            .map(|start| u8::from_str_radix(&CORE_SIGNET_BLOCK_1[start..start + 2], 16))
            .collect::<Result<Vec<u8>, _>>()?;
        Ok(deserialize::<Block>(&bytes)?)
    }

    fn solution_offset(script: &[u8]) -> Option<usize> {
        script
            .windows(SIGNET_HEADER.len())
            .position(|window| window == SIGNET_HEADER.as_slice())
    }

    fn with_invalid_solution(valid: &Block) -> TestResult<Block> {
        let mut block = valid.clone();
        let (index, solution_at) = block.txs[0]
            .outputs
            .iter()
            .enumerate()
            .find_map(|(index, output)| {
                solution_offset(&output.script_pubkey).map(|at| (index, at))
            })
            .ok_or(TestError::Missing("block 1 carries the solution header"))?;
        let mut script = block.txs[0].outputs[index].script_pubkey.to_vec();
        script[solution_at + SIGNET_HEADER.len() + 16] ^= 0x01;
        block.txs[0].outputs[index].script_pubkey = Script::from_bytes(script);
        block.header.merkle_root = block.txs[0].txid().into();
        mine_block_to_declared_target(&mut block)?;
        Ok(block)
    }

    #[test]
    fn signet_solution_is_checked_on_commit_not_proposal() -> TestResult {
        let handles = Arc::new(handles(
            Network::Signet,
            Arc::new(bitcoin_rs_storage::utxo::UtxoSet::new()),
        ));
        handles.apply_block(&BlockImage::from_local(Network::Signet.genesis_block()))?;

        let valid = signet_block_1()?;
        let invalid = with_invalid_solution(&valid)?;
        assert_ne!(invalid.block_hash(), valid.block_hash());

        let invalid_payload = BlockImage::from_local(invalid);
        handles.validate_block(&invalid_payload)?;
        let error =
            handles
                .apply_block(&invalid_payload)
                .err()
                .ok_or(TestError::UnexpectedSuccess(
                    "a bad solution must not commit",
                ))?;
        assert!(
            matches!(error, ApplyError::Consensus(ConsensusError::SignetSolution)),
            "expected a signet solution failure, got {error:?}"
        );
        assert_eq!(
            crate::classify_apply_error(&error),
            crate::WindowApplyDisposition::Permanent,
            "a bad solution invalidates the header branch; it is not retryable"
        );

        let valid_payload = BlockImage::from_local(valid);
        handles.validate_block(&valid_payload)?;
        handles.apply_block(&valid_payload)?;
        Ok(())
    }

    use crate::chain::regtest_fixture;
    use crate::test_support::MemoryBodies;
    use bitcoin_rs_consensus::primitives::encode::double_sha256;
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use bitcoin_rs_storage::utxo::UtxoSet;

    fn witness_child(
        parent: bitcoin_rs_consensus::primitives::BlockHash,
        height: u32,
    ) -> Result<Block, regtest_fixture::RegtestFixtureError> {
        let mut coinbase = regtest_fixture::coinbase(height);
        coinbase.inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
        let commitment = double_sha256(&[0; 64]);
        coinbase.outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: [
                vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
                commitment.as_byte_array().to_vec(),
            ]
            .concat()
            .into(),
        });
        regtest_fixture::mined_block_with_prev_hash(parent, height, vec![coinbase])
    }

    #[test]
    fn preserved_witness_body_is_bound_before_commit_and_disconnect_keeps_exact_bytes() -> TestResult
    {
        for engine in bitcoin_rs_consensus::ValidationEngine::ALL
            .iter()
            .copied()
            .filter(|e| e.is_supported())
        {
            let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            chain.validation_engine = engine;
            let bodies = Arc::new(MemoryBodies::default());
            chain.block_body_store = Some(bodies.clone());
            chain.set_capture_flags(false, true);
            let genesis = Network::Regtest.genesis_block();
            chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
            let child = witness_child(genesis.block_hash(), 1)?;
            let raw = bytes::Bytes::from(consensus_bytes(&child));
            let before = chain.chain_snapshot();
            let valid = BlockImage::from_raw(raw.clone())?;
            assert_eq!(valid.block_hash(), child.block_hash());
            assert_eq!(valid.bytes(), &raw);
            let mut changed = child.clone();
            changed.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![1; 32]]);
            assert_eq!(changed.txs[0].txid(), child.txs[0].txid());
            let changed_payload = BlockImage::from_local(changed);
            assert_eq!(changed_payload.bytes().len(), raw.len());
            assert_ne!(changed_payload.bytes(), &raw);
            let mut truncated = raw.to_vec();
            truncated.pop();
            assert!(BlockImage::from_raw(bytes::Bytes::from(truncated)).is_err());
            assert!(matches!(
                chain.apply_block(&changed_payload),
                Err(ApplyError::Consensus(_))
            ));
            assert_eq!(chain.chain_snapshot().tip_hash, before.tip_hash);
            assert!(bodies.load_block_body(1, child.block_hash().0)?.is_none());

            let outcome = chain.apply_block(&valid)?;
            assert_eq!(outcome.block_bytes, raw);
            assert_eq!(
                bodies.load_block_body(1, child.block_hash().0)?.as_deref(),
                Some(raw.as_ref())
            );

            let mut bad_merkle = witness_child(child.block_hash(), 2)?;
            bad_merkle.txs[0].outputs[0].value = Amount::from_sat(1);
            let bad_payload =
                BlockImage::from_raw(bytes::Bytes::from(consensus_bytes(&bad_merkle)))?;
            assert!(chain.apply_block(&bad_payload).is_err());
            assert_eq!(
                chain
                    .applied_tip_snapshot()
                    .ok_or(TestError::Missing("missing tip"))?
                    .hash,
                child.block_hash().0
            );
            assert!(
                bodies
                    .load_block_body(2, bad_merkle.block_hash().0)?
                    .is_none()
            );

            chain.disconnect_block(&child)?;
            let replayed = chain.apply_block(&BlockImage::from_local(child.clone()))?;
            assert_eq!(replayed.block_bytes, raw);
            assert_eq!(
                bodies.load_block_body(1, child.block_hash().0)?.as_deref(),
                Some(raw.as_ref())
            );
        }
        Ok(())
    }
}

use super::SameBlockSpentSet;
use super::prepare::{ScriptsRan, prepare_apply, verify_block_transactions};
use super::window::{PendingBlockCommit, PublishMode};
use super::{
    ApplyFinish, ApplyIntent, Bip68Context, BlockLocalUtxoView, BlockProvenance, BlockTxPlan,
    BlockValidationContext, Chainstate, ConnectOutcome, PreparedApply, ProvenApply,
    ResolvedUtxoView,
};
use crate::chain::TipSnapshot;
use crate::chain::node::NodeId;
use crate::error::ApplyError;
use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Header, Txid};
use bitcoin_rs_consensus::{MAX_SCRIPT_SIZE, UtxoView};
use bitcoin_rs_storage::ScriptAttestation;
use bitcoin_rs_storage::utxo::contract::{
    BlockChangeError, BlockChangeInputs, BlockChanges, BlockValueTotals, CoinEntryError, UndoBatch,
    UndoRecord, build_block_changes, resolve_coin_entries,
};
use hashbrown::HashMap;
use std::sync::Arc;

/// The provenance inputs of one block apply.
///
/// `staged` is the coin view of the uncommitted window prefix; it is the only
/// path by which staged coins become visible to block rules.
#[derive(Clone, Copy)]
pub(super) struct ApplyScope<'a> {
    pub provenance: BlockProvenance,
    pub staged: Option<&'a super::workspace::WindowWorkspace>,
}

pub(super) fn apply_committed_block_admitted<'b>(
    handles: &Chainstate,
    payload: &'b BlockImage,
    proven: Option<ProvenApply<'b>>,
    scope: ApplyScope<'_>,
    publication: PublishMode<'_>,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    match apply_block_admitted(
        handles,
        payload,
        proven,
        scope,
        ApplyIntent::Commit,
        publication,
    )? {
        ApplyFinish::Committed(outcome) => Ok(*outcome),
        ApplyFinish::Proposed => unreachable!("commit intent returns a committed tip"),
    }
}

#[derive(Default)]
struct ApplyTimings {
    block_rules: std::time::Duration,
    bip30_bip34: std::time::Duration,
    script_verify: std::time::Duration,
    utxo_commit: std::time::Duration,
    block_body_persist: std::time::Duration,
    block_tree_insert: std::time::Duration,
    coin_stats: std::time::Duration,
}

fn application_predecessor(
    handles: &Chainstate,
    block_hash: Hash256,
    prev_hash: Hash256,
    publication: &PublishMode<'_>,
) -> core::result::Result<(Option<Arc<TipSnapshot>>, u32), ApplyError> {
    match publication {
        PublishMode::Grouped(group) => match group.predecessor(prev_hash)? {
            Some((tip, height)) => Ok((Some(tip), height)),
            None => applied_predecessor(handles, block_hash, prev_hash),
        },
        PublishMode::Now | PublishMode::Replay { .. } => {
            applied_predecessor(handles, block_hash, prev_hash)
        }
    }
}

fn check_historical_target(
    handles: &Chainstate,
    height: u32,
    block_hash: Hash256,
) -> core::result::Result<(), ApplyError> {
    if let crate::assumeutxo::ChainstateRole::Historical {
        base_height,
        base_hash,
    } = handles.role()
    {
        if height > base_height {
            return Err(ApplyError::ConnectPastHistoricalTarget {
                height,
                base_height,
            });
        }
        if height == base_height && block_hash != base_hash {
            return Err(ApplyError::HistoricalTargetHashMismatch {
                base_height,
                expected: base_hash,
                found: block_hash,
            });
        }
    }
    Ok(())
}

fn check_contextual_header(
    handles: &Chainstate,
    header: &Header,
    height: u32,
    prior: Option<&TipSnapshot>,
    block_hash: Hash256,
) -> core::result::Result<(), ApplyError> {
    let contextual_header_started =
        tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let contextual_header_result = validate_contextual_block_header(handles, header, height, prior);
    tracing::debug!(
        height,
        %block_hash,
        contextual_header_us = contextual_header_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    contextual_header_result
}

fn check_self_pow(
    handles: &Chainstate,
    header: &Header,
    block_hash: Hash256,
    height: u32,
    intent: ApplyIntent,
) -> core::result::Result<(), ApplyError> {
    if intent != ApplyIntent::Commit {
        return Ok(());
    }
    let pow_self_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let pow_self_result =
        crate::chain::header_sync::validate_pow(header, block_hash, handles.network);
    tracing::debug!(
        height,
        %block_hash,
        pow_self_us = pow_self_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    pow_self_result.map_err(|_| ApplyError::ProofOfWork { hash: block_hash })
}

struct ValidationContexts {
    validation: BlockValidationContext,
    softfork: crate::chain::SoftforkState,
    median_time_past: u32,
}

fn validation_contexts(
    handles: &Chainstate,
    header: &Header,
    height: u32,
    block_hash: Hash256,
    prior: Option<&TipSnapshot>,
) -> ValidationContexts {
    let (prev_median_time_past, softfork_state) = if let Some(tip) = prior {
        let tree = handles.block_tree.read();
        let mtp = tree.median_time_past_at(tip.tip_id).unwrap_or(0);
        let softfork_state =
            crate::chain::softfork_state(&tree, handles.network, Some(tip.tip_id), height);
        (mtp, softfork_state)
    } else {
        let tree = handles.block_tree.read();
        (
            0,
            crate::chain::softfork_state(&tree, handles.network, None, height),
        )
    };
    let locktime_rule =
        bitcoin_rs_consensus::LocktimeRule::from_csv_active(softfork_state.csv_active);
    let locktime_cutoff =
        bitcoin_rs_consensus::locktime_cutoff(locktime_rule, prev_median_time_past, header.time);
    let verify_flags =
        bitcoin_rs_consensus::verify_flags(handles.network, height, block_hash, softfork_state);
    ValidationContexts {
        validation: BlockValidationContext {
            hash: block_hash,
            parent: header.prev_blockhash.0,
            height,
            flags: verify_flags,
            locktime_cutoff,
        },
        softfork: softfork_state,
        median_time_past: prev_median_time_past,
    }
}

struct ChainstateUtxoSource<'a> {
    handles: &'a Chainstate,
    read_failure: core::cell::RefCell<Option<ApplyError>>,
}

impl<'a> ChainstateUtxoSource<'a> {
    fn new(handles: &'a Chainstate) -> Self {
        Self {
            handles,
            read_failure: core::cell::RefCell::new(None),
        }
    }

    fn into_result(self) -> core::result::Result<(), ApplyError> {
        match self.read_failure.into_inner() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn note_failure(&self, error: ApplyError) {
        let mut slot = self.read_failure.borrow_mut();
        if slot.is_none() {
            *slot = Some(error);
        }
    }
}

impl bitcoin_rs_storage::utxo::contract::OutputSource for ChainstateUtxoSource<'_> {
    fn get_entry(
        &self,
        outpoint: &bitcoin_rs_consensus::primitives::OutPoint,
    ) -> Option<bitcoin_rs_storage::utxo::UtxoCoin> {
        self.get_entries(std::slice::from_ref(outpoint))
            .pop()
            .flatten()
    }

    fn get_entries(
        &self,
        outpoints: &[bitcoin_rs_consensus::primitives::OutPoint],
    ) -> Vec<Option<bitcoin_rs_storage::utxo::UtxoCoin>> {
        match resolve_coin_entries(&self.handles.coins, outpoints) {
            Ok(entries) => entries,
            Err(CoinEntryError::Read(source)) => {
                self.note_failure(ApplyError::CoinStoreRead(source));
                vec![None; outpoints.len()]
            }
            Err(CoinEntryError::Record(error)) => {
                self.note_failure(ApplyError::UtxoCommit(error));
                vec![None; outpoints.len()]
            }
        }
    }
}

fn prepare_block<'b>(
    handles: &Chainstate,
    payload: &'b BlockImage,
    proven: Option<ProvenApply<'b>>,
    context: &BlockValidationContext,
) -> core::result::Result<(PreparedApply<'b>, bool), ApplyError> {
    match proven {
        Some(ProvenApply::Proven(proof)) if &proof.context == context => Ok((proof.prepared, true)),
        Some(ProvenApply::AssumeValidSkipped(prepared)) => Ok((prepared, false)),
        Some(ProvenApply::Unproven(prepared)) => Ok((prepared, false)),
        Some(ProvenApply::Proven(proof)) => Ok((proof.prepared, false)),
        None => {
            let source = ChainstateUtxoSource::new(handles);
            let prepared = prepare_apply(
                payload,
                &source,
                handles.validation_engine,
                handles.prevout_charge.clone(),
            )?;
            source.into_result()?;
            Ok((prepared, false))
        }
    }
}

struct BlockRules<'a, 'b> {
    handles: &'a Chainstate,
    image: &'b BlockImage,
    block_hash: Hash256,
    prev_hash: Hash256,
    context: &'b BlockValidationContext,
    softfork: crate::chain::SoftforkState,
    prior_tip_id: Option<NodeId>,
    intent: ApplyIntent,
    scope: ApplyScope<'b>,
}

impl BlockRules<'_, '_> {
    fn check(
        &self,
        view: &mut bitcoin_rs_consensus::BlockView<'_>,
        has_witness: bool,
        timings: &mut ApplyTimings,
    ) -> core::result::Result<(), ApplyError> {
        let needs_wtxids = self.softfork.segwit_active && has_witness;
        if needs_wtxids {
            view.witness_ids();
        }
        let block_rules_started = quanta::Instant::now();
        let block_rules_result = bitcoin_rs_consensus::verify_block_image_rules(
            self.image,
            bitcoin_rs_consensus::BlockRuleContext {
                segwit_active: self.softfork.segwit_active,
            },
            view.facts(),
        );
        let block_rules_dur = block_rules_started.elapsed();
        metrics::histogram!("node.apply_block.block_rules_seconds")
            .record(block_rules_dur.as_secs_f64());
        timings.block_rules = block_rules_dur;
        block_rules_result?;
        if self.intent == ApplyIntent::Commit
            && let Some(challenge) = self.handles.network.signet_challenge()
        {
            bitcoin_rs_consensus::check_signet_block_solution(self.image, challenge)?;
        }
        check_block_finality(
            self.image,
            self.context.height,
            self.context.locktime_cutoff,
        )?;
        if self.intent == ApplyIntent::Commit {
            check_bip34(self.handles, self.image, self.context.height)?;
        }
        if self.intent == ApplyIntent::Commit
            && self.softfork.segwit_active
            && let Some(hook) = self.handles.pow_valid_block.get()
            && self
                .handles
                .applied_tip_snapshot()
                .is_some_and(|tip| tip.hash == self.prev_hash)
        {
            hook(self.image, self.block_hash, self.context.height);
        }
        let bip30_bip34_started = quanta::Instant::now();
        let bip30_bip34_result = check_bip30_and_bip34(
            self.handles,
            self.image,
            self.context.height,
            view.txids(),
            self.prior_tip_id,
            self.scope,
        );
        let bip30_bip34_dur = bip30_bip34_started.elapsed();
        metrics::histogram!("node.apply_block.bip30_bip34_seconds")
            .record(bip30_bip34_dur.as_secs_f64());
        timings.bip30_bip34 = bip30_bip34_dur;
        bip30_bip34_result
    }
}

struct ScriptVerification<'a, 'b> {
    handles: &'a Chainstate,
    view: &'a mut bitcoin_rs_consensus::BlockView<'b>,
    tx_plan: &'a BlockTxPlan,
    resolved: &'a Arc<ResolvedUtxoView>,
    context: &'a BlockValidationContext,
    provenance: BlockProvenance,
    script_source: &'a bitcoin_rs_consensus::kernel::BlockScriptSource,
    transactions_proven: bool,
    intent: ApplyIntent,
}

impl ScriptVerification<'_, '_> {
    fn run(
        &mut self,
        timings: &mut ApplyTimings,
    ) -> core::result::Result<(ScriptsRan, Option<super::PrevoutHold>), ApplyError> {
        let script_verify_started = quanta::Instant::now();
        let script_cache = if self.intent == ApplyIntent::Commit {
            self.handles.script_cache.as_deref()
        } else {
            None
        };
        let script_verify_result = if self.transactions_proven {
            Ok((ScriptsRan::Executed, None))
        } else {
            verify_block_transactions(
                self.handles,
                self.view,
                self.tx_plan,
                Arc::clone(self.resolved),
                self.context,
                self.provenance,
                self.script_source,
                script_cache,
            )
        };
        let script_verify_dur = script_verify_started.elapsed();
        metrics::histogram!("node.apply_block.script_verify_seconds")
            .record(script_verify_dur.as_secs_f64());
        timings.script_verify = script_verify_dur;
        tracing::debug!(
            height = self.context.height,
            %self.context.hash,
            script_verify_us = script_verify_dur.as_micros(),
            script_dispatch = if self.tx_plan.only_coinbase {
                "coinbase_only"
            } else if self.tx_plan.needs_local_utxo_overlay {
                "serial_overlay"
            } else {
                "parallel"
            },
            "apply_block: profile"
        );
        script_verify_result
    }
}

struct BudgetChecks<'a, 'b> {
    handles: &'a Chainstate,
    image: &'b BlockImage,
    block_hash: Hash256,
    tx_plan: &'b BlockTxPlan,
    txids: &'b [Txid],
    resolved: Arc<ResolvedUtxoView>,
    context: &'b BlockValidationContext,
    median_time_past: u32,
    softfork: crate::chain::SoftforkState,
    previous_tip_id: Option<NodeId>,
}

impl BudgetChecks<'_, '_> {
    fn run(&self) -> core::result::Result<(), ApplyError> {
        check_block_sigops(
            self.image,
            self.tx_plan,
            self.txids,
            Arc::clone(&self.resolved),
            self.context.height,
            self.context.flags,
        )?;

        let coinbase_maturity_started =
            tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
        let coinbase_maturity_result = check_coinbase_maturity(
            self.image,
            self.tx_plan,
            self.txids,
            Arc::clone(&self.resolved),
            self.context.height,
        );
        tracing::debug!(
            height = self.context.height,
            %self.block_hash,
            coinbase_maturity_us = coinbase_maturity_started.map(|start| start.elapsed().as_micros()),
            "apply_block: profile"
        );
        coinbase_maturity_result?;
        let bip68_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
        let bip68_result = check_bip68_sequence_locks(
            self.handles,
            self.image,
            self.tx_plan,
            self.txids,
            Arc::clone(&self.resolved),
            Bip68Context {
                validation: self.context,
                median_time_past: self.median_time_past,
                softfork_state: self.softfork,
                previous_tip_id: self.previous_tip_id,
            },
        );
        tracing::debug!(
            height = self.context.height,
            %self.block_hash,
            bip68_us = bip68_started.map(|start| start.elapsed().as_micros()),
            "apply_block: profile"
        );
        bip68_result
    }
}

struct ChangeRequest<'a, 'b> {
    image: &'b BlockImage,
    block_hash: Hash256,
    height: u32,
    txids: &'a [Txid],
    tx_plan: &'a BlockTxPlan,
    resolved: &'a Arc<ResolvedUtxoView>,
}

fn build_block_changes_checked(
    request: &ChangeRequest<'_, '_>,
) -> core::result::Result<
    (
        BlockChanges<bitcoin_rs_consensus::primitives::TxOut>,
        UndoBatch,
        BlockValueTotals,
    ),
    ApplyError,
> {
    let same_block_spent = request.tx_plan.same_block_spent.as_ref();
    let same_block_spent_len = same_block_spent.map_or(0_usize, SameBlockSpentSet::len);
    let utxo_add_capacity = request
        .tx_plan
        .created_output_count
        .saturating_sub(same_block_spent_len);
    let utxo_remove_capacity = request
        .tx_plan
        .spent_input_count
        .saturating_sub(request.tx_plan.same_block_spent_input_count);

    let utxo_changes_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let utxo_changes_result = build_block_changes(
        &BlockChangeInputs {
            block: request.image,
            height: request.height,
            txids: request.txids,
            same_block_spent,
            add_capacity: utxo_add_capacity,
            remove_capacity: utxo_remove_capacity,
            max_script_size: MAX_SCRIPT_SIZE,
        },
        request.resolved.as_ref(),
    );
    tracing::debug!(
        height = request.height,
        %request.block_hash,
        utxo_changes_us = utxo_changes_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    utxo_changes_result.map_err(|e| map_block_change_error(&e))
}

fn check_coinbase_value(
    handles: &Chainstate,
    height: u32,
    value_totals: &BlockValueTotals,
) -> core::result::Result<(), ApplyError> {
    if height > 0 {
        let fees = value_totals
            .fees()
            .ok_or(ApplyError::BlockOutputsExceedInputs)?;
        bitcoin_rs_consensus::verify_coinbase_amount(
            value_totals.coinbase_out,
            fees,
            height,
            handles.network.subsidy_halving_interval(),
        )?;
    }
    Ok(())
}

struct BlockOutcomeInputs<'a, 'b> {
    handles: &'a Chainstate,
    payload: &'b BlockImage,
    block_hash: Hash256,
    height: u32,
    txids: Vec<Txid>,
    resolved: Arc<ResolvedUtxoView>,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
    undo: &'b UndoBatch,
    total_started: quanta::Instant,
}

struct PersistedPayload {
    undo_record: UndoRecord,
    tip: TipSnapshot,
    block_bytes: bytes::Bytes,
    block_connected_dur: std::time::Duration,
    coin_stats_height_delta: i64,
}

fn persist_payload(
    input: &BlockOutcomeInputs<'_, '_>,
    timings: &mut ApplyTimings,
) -> core::result::Result<PersistedPayload, ApplyError> {
    let undo_encode_started = quanta::Instant::now();
    let undo_record = UndoRecord::new(bitcoin_rs_storage::utxo::contract::encode_undo_record(
        input.undo,
        input.block_hash,
    ));
    metrics::histogram!("node.apply_block.undo_persist_seconds")
        .record(undo_encode_started.elapsed().as_secs_f64());
    let block_bytes: bytes::Bytes = {
        let needs_body =
            input.handles.block_body_store.is_some() || input.handles.capture_block_bytes;
        if needs_body {
            input.payload.bytes().clone()
        } else {
            bytes::Bytes::new()
        }
    };

    let block_body_persist_started = quanta::Instant::now();
    let block_body_persist_result = match &input.handles.block_body_store {
        Some(store) => store
            .persist_block_body_value(input.height, input.block_hash, block_bytes.clone())
            .map_err(ApplyError::BlockBodyPersistence),
        None => Ok(()),
    };
    let block_body_persist_dur = block_body_persist_started.elapsed();
    metrics::histogram!("node.apply_block.block_body_persist_seconds")
        .record(block_body_persist_dur.as_secs_f64());
    timings.block_body_persist = block_body_persist_dur;
    block_body_persist_result?;

    let block_tree_insert_started = quanta::Instant::now();
    let tip = applied_header_tip(input.handles, input.block_hash, input.payload, input.height)?;
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());
    timings.block_tree_insert = block_tree_insert_dur;

    let block_connected_dur = input.total_started.elapsed();
    let coin_stats_height_delta =
        i64::from(input.height) - i64::from(input.handles.coin_stats.snapshot().height);
    Ok(PersistedPayload {
        undo_record,
        tip,
        block_bytes,
        block_connected_dur,
        coin_stats_height_delta,
    })
}

fn finish_block_outcome(
    input: BlockOutcomeInputs<'_, '_>,
    persisted: PersistedPayload,
    timings: &mut ApplyTimings,
) -> (ConnectOutcome, UndoRecord, i64) {
    let handles = input.handles;
    debug_assert!(
        handles
            .block_tree
            .read()
            .node_by_hash(input.block_hash)
            .is_some(),
        "block {} is entering the record log with no block-tree node; \
         its header would be unrecoverable",
        input.block_hash.to_string_be()
    );
    let tx_count_delta = u64::try_from(input.payload.tx_count()).unwrap_or(u64::MAX);
    let coin_stats_started = quanta::Instant::now();
    handles
        .coin_stats
        .finish_block(input.height, tx_count_delta);
    let coin_stats_dur = coin_stats_started.elapsed();
    metrics::histogram!("node.apply_block.coin_stats_finish_seconds")
        .record(coin_stats_dur.as_secs_f64());
    timings.coin_stats = coin_stats_dur;
    let total_dur = input.total_started.elapsed();
    metrics::histogram!("node.apply_block.total_seconds").record(total_dur.as_secs_f64());
    metrics::counter!("node.apply_block.txs_applied").increment(tx_count_delta);
    emit_block_connected(
        input.payload,
        &input.block_hash,
        input.height,
        &input.txids,
        &input.resolved,
        input.flags,
        persisted.block_connected_dur,
    );
    tracing::debug!(
        height = input.height,
        %input.block_hash,
        tx_count = input.payload.tx_count(),
        block_rules_us = timings.block_rules.as_micros(),
        bip30_bip34_us = timings.bip30_bip34.as_micros(),
        script_verify_us = timings.script_verify.as_micros(),
        utxo_commit_us = timings.utxo_commit.as_micros(),
        block_body_persist_us = timings.block_body_persist.as_micros(),
        block_tree_insert_us = timings.block_tree_insert.as_micros(),
        coin_stats_us = timings.coin_stats.as_micros(),
        total_us = total_dur.as_micros(),
        "apply_block: profile"
    );
    let raw_txs = handles.capture_rawtx.then(|| {
        (0..input.payload.tx_count())
            .map(|index| input.payload.tx(index).span_bytes().to_vec())
            .collect::<Vec<_>>()
    });
    let outcome = ConnectOutcome {
        tip: persisted.tip,
        commit_id: 0,
        height: input.height,
        hash: input.block_hash,
        txids: input.txids,
        block_bytes: persisted.block_bytes,
        raw_txs,
        committed_facts: None,
    };
    (
        outcome,
        persisted.undo_record,
        persisted.coin_stats_height_delta,
    )
}

struct Publication<'a, 'p, 'b> {
    handles: &'a Chainstate,
    image: &'b BlockImage,

    outcome: ConnectOutcome,
    publication: PublishMode<'p>,
    undo: UndoBatch,
    changes: BlockChanges<bitcoin_rs_consensus::primitives::TxOut>,
    undo_record: UndoRecord,
    attestation: Option<ScriptAttestation>,
    prev_hash: Hash256,
    #[expect(dead_code)]
    coin_stats_height_delta: i64,
}

impl Publication<'_, '_, '_> {
    fn run(self) -> core::result::Result<ApplyFinish, ApplyError> {
        let Publication {
            handles,
            image,
            mut outcome,
            publication,
            undo,
            changes,
            undo_record,
            attestation,
            prev_hash,
            coin_stats_height_delta: _,
        } = self;
        match publication {
            PublishMode::Now => {
                return Err(ApplyError::DurableHeadCommit(
                    bitcoin_rs_storage::StorageError::InvalidOperation(
                        "single-block connect must route through connect_window",
                    ),
                ));
            }
            PublishMode::Replay {
                receipt,
                certify_head,
            } => {
                let prior = handles
                    .durable_head
                    .load()
                    .map_err(ApplyError::DurableHeadCommit)?
                    .ok_or(ApplyError::DurableHeadCommit(
                        bitcoin_rs_storage::StorageError::InvalidOperation(
                            "replay commit with no durable head",
                        ),
                    ))?;
                let prefix = bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: Some(prior),
                    next_head: prior,
                    undo_rows: vec![(
                        outcome.height,
                        outcome.hash,
                        bytes::Bytes::copy_from_slice(undo_record.as_bytes()),
                    )],
                    body_rows: super::durable::stored_body_row(
                        handles,
                        outcome.height,
                        outcome.hash,
                    )?
                    .into_iter()
                    .collect(),
                    attestation: None,
                    coin_delta: replay_coin_delta(handles, &changes)?,
                };
                let commit_id = handles
                    .commit_authority
                    .commit_prefix(prefix)
                    .map_err(|error| match error {
                        bitcoin_rs_storage::CommitError::Storage(source) => {
                            ApplyError::DurableHeadCommit(source)
                        }
                        source @ (bitcoin_rs_storage::CommitError::AdmissionClosed
                        | bitcoin_rs_storage::CommitError::PreconditionFailed) => {
                            ApplyError::DurableHeadCommit(
                                bitcoin_rs_storage::StorageError::backend(source.to_string()),
                            )
                        }
                    })?
                    .commit_id();
                if certify_head {
                    outcome.tip = receipt.certify(outcome.tip);
                }
                outcome.commit_id = commit_id;
                outcome.committed_facts =
                    committed_facts_for_publish(handles, &outcome, image, &undo);
            }
            PublishMode::Grouped(group) => {
                outcome.committed_facts =
                    committed_facts_for_publish(handles, &outcome, image, &undo);
                group.stage(PendingBlockCommit {
                    outcome: outcome.clone(),
                    undo_record,
                    prev_hash,
                    attestation,
                });
                return Ok(ApplyFinish::Committed(Box::new(outcome)));
            }
        };

        handles.publish_applied(&outcome.tip, crate::events::HintKind::Connected);

        Ok(ApplyFinish::Committed(Box::new(outcome)))
    }
}

fn replay_coin_delta(
    handles: &Chainstate,
    changes: &BlockChanges<bitcoin_rs_consensus::primitives::TxOut>,
) -> Result<bitcoin_rs_storage::WindowDelta, ApplyError> {
    use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

    let mut adds_by_txid: HashMap<Hash256, Vec<_>> = HashMap::new();
    let mut removes_by_txid: HashMap<Hash256, Vec<u32>> = HashMap::new();
    for add in changes.adds() {
        adds_by_txid
            .entry(Hash256::from(add.outpoint.txid))
            .or_default()
            .push(add);
    }
    for spent in changes.spent_outpoints() {
        removes_by_txid
            .entry(Hash256::from(spent.txid))
            .or_default()
            .push(spent.vout);
    }
    let mut txids: Vec<Hash256> = adds_by_txid
        .keys()
        .chain(removes_by_txid.keys())
        .copied()
        .collect();
    txids.sort();
    txids.dedup();

    let mut delta = bitcoin_rs_storage::WindowDelta::default();
    for txid in txids {
        let key = bitcoin_rs_storage::CoinKey(txid.to_le_bytes());
        let mut outputs: Vec<OwnedUtxoOut> = match handles
            .coins
            .get(&key)
            .map_err(ApplyError::DurableHeadCommit)?
        {
            Some(bytes) => UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())
                .map_err(ApplyError::UtxoCommit)?
                .outputs()
                .map(|out| OwnedUtxoOut {
                    vout: out.vout,
                    value: out.value,
                    script_pubkey: out.script_pubkey.to_vec(),
                    coinbase: out.coinbase,
                    height: out.height,
                })
                .collect(),
            None => Vec::new(),
        };
        if let Some(removes) = removes_by_txid.get(&txid) {
            outputs.retain(|out| !removes.contains(&out.vout));
        }
        if let Some(adds) = adds_by_txid.get(&txid) {
            for add in adds {
                outputs.retain(|out| out.vout != add.outpoint.vout);
                outputs.push(OwnedUtxoOut {
                    vout: add.outpoint.vout,
                    value: add.txout.value.to_sat(),
                    script_pubkey: add.txout.script_pubkey.as_bytes().to_vec(),
                    coinbase: add.coinbase,
                    height: add.height,
                });
            }
        }
        outputs.sort_by_key(|out| out.vout);
        if outputs.is_empty() {
            delta.push_final(key, None);
            continue;
        }
        let record =
            UtxoRecord::from_owned_outputs(txid, &outputs).map_err(ApplyError::UtxoCommit)?;
        delta.push_final(key, Some(bytes::Bytes::copy_from_slice(record.bytes())));
    }
    Ok(delta)
}

fn committed_facts_for_publish(
    handles: &Chainstate,
    outcome: &ConnectOutcome,
    image: &BlockImage,
    undo: &UndoBatch,
) -> Option<Arc<bitcoin_rs_storage::CommittedFacts>> {
    if !handles.wants_committed_facts() {
        return None;
    }
    #[cfg(any(test, feature = "test-seam"))]
    handles
        .facts
        .builds
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    build_committed_facts(outcome, image, undo)
}

pub(crate) fn build_committed_facts(
    outcome: &ConnectOutcome,
    image: &BlockImage,
    undo: &UndoBatch,
) -> Option<std::sync::Arc<bitcoin_rs_storage::CommittedFacts>> {
    use bitcoin_rs_storage::{
        CommittedBlock, CommittedFacts, CreatedOutput, FactsScript, SpentPrevout, TxFacts,
    };
    use hashbrown::HashMap;

    let header: [u8; 80] = image.header_bytes();
    let block_hash = outcome.hash.to_le_bytes();
    let parent_hash = image.header().prev_blockhash.0.to_le_bytes();

    let mut prevout_map = HashMap::<([u8; 32], u32), (u64, FactsScript, u32, bool)>::with_capacity(
        undo.restores().len(),
    );
    for add in undo.restores() {
        let txid = *add.outpoint.txid.as_bytes();
        let vout = add.outpoint.vout;
        prevout_map.insert(
            (txid, vout),
            (
                add.txout.value.to_sat(),
                FactsScript::copy_from_slice(&add.txout.script_pubkey),
                add.height,
                add.coinbase,
            ),
        );
    }

    let tx_count = image.tx_count();
    let mut txs = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let tx = image.tx(i);
        let txid = *tx.txid().as_bytes();
        let offset = tx.layout().span().start();
        let len = tx.layout().span().len();

        let mut inputs = Vec::new();
        if !tx.is_coinbase() {
            for j in 0..tx.input_count() {
                let outpoint = tx.input_outpoint(j);
                let prev_txid = *outpoint.txid.as_bytes();
                let prev_vout = outpoint.vout;
                let (value, script, height, coinbase) =
                    prevout_map.get(&(prev_txid, prev_vout))?.clone();
                inputs.push(SpentPrevout {
                    txid: prev_txid,
                    vout: prev_vout,
                    value,
                    script,
                    height,
                    coinbase,
                });
            }
        }

        let output_count = tx.output_count();
        let mut outputs = Vec::with_capacity(output_count);
        for vout in 0..output_count {
            let vout_u32 = u32::try_from(vout).ok()?;
            let script = FactsScript::copy_from_slice(tx.output_script(vout));
            let value = tx.output_value(vout).to_sat();
            outputs.push(CreatedOutput {
                vout: vout_u32,
                value,
                script: script.clone(),
            });
            prevout_map.insert(
                (txid, vout_u32),
                (value, script, outcome.height, tx.is_coinbase()),
            );
        }
        txs.push(TxFacts {
            txid,
            offset,
            len,
            inputs,
            outputs,
        });
    }

    let committed_block = CommittedBlock {
        height: outcome.height,
        hash: block_hash,
        parent_hash,
        header,
        txs,
    };

    Some(std::sync::Arc::new(CommittedFacts {
        commit_id: outcome.commit_id,
        blocks: vec![committed_block],
    }))
}

struct BlockValidation<'a, 'b, 'c> {
    handles: &'a Chainstate,
    image: &'b BlockImage,
    block_hash: Hash256,
    prev_hash: Hash256,
    context: &'c BlockValidationContext,
    softfork: crate::chain::SoftforkState,
    median_time_past: u32,
    prior_tip_id: Option<NodeId>,
    scope: ApplyScope<'c>,
    intent: ApplyIntent,
    transactions_proven: bool,
    prepared: PreparedApply<'b>,
}

type BlockValidationOutcome = (
    Vec<Txid>,
    BlockTxPlan,
    Arc<ResolvedUtxoView>,
    Option<ScriptAttestation>,
);

impl BlockValidation<'_, '_, '_> {
    fn run(
        self,
        timings: &mut ApplyTimings,
    ) -> core::result::Result<BlockValidationOutcome, ApplyError> {
        let PreparedApply {
            script_source,
            mut view,
            tx_plan,
            resolved,
        } = self.prepared;
        BlockRules {
            handles: self.handles,
            image: self.image,
            block_hash: self.block_hash,
            prev_hash: self.prev_hash,
            context: self.context,
            softfork: self.softfork,
            prior_tip_id: self.prior_tip_id,
            intent: self.intent,
            scope: self.scope,
        }
        .check(&mut view, tx_plan.has_witness, timings)?;

        let (scripts_ran, _view_hold) = ScriptVerification {
            handles: self.handles,
            view: &mut view,
            tx_plan: &tx_plan,
            resolved: &resolved,
            context: self.context,
            provenance: self.scope.provenance,
            script_source: &script_source,
            transactions_proven: self.transactions_proven,
            intent: self.intent,
        }
        .run(timings)?;
        let attestation = match (self.scope.provenance, scripts_ran) {
            (BlockProvenance::LocalReplay(_), _) => None,
            (_, ScriptsRan::Skipped) => Some(ScriptAttestation::AssumeValid),
            (_, ScriptsRan::Executed) => Some(ScriptAttestation::Full),
        };

        BudgetChecks {
            handles: self.handles,
            image: self.image,
            block_hash: self.block_hash,
            tx_plan: &tx_plan,
            txids: view.txids(),
            resolved: Arc::clone(&resolved),
            context: self.context,
            median_time_past: self.median_time_past,
            softfork: self.softfork,
            previous_tip_id: self.prior_tip_id,
        }
        .run()?;

        Ok((view.into_txids(), tx_plan, resolved, attestation))
    }
}

struct CommitRequest<'a, 'p, 'b> {
    handles: &'a Chainstate,
    payload: &'b BlockImage,
    block_hash: Hash256,
    prev_hash: Hash256,
    height: u32,
    intent: ApplyIntent,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
    txids: Vec<Txid>,
    resolved: Arc<ResolvedUtxoView>,
    tx_plan: BlockTxPlan,
    attestation: Option<ScriptAttestation>,
    publication: PublishMode<'p>,
    total_started: quanta::Instant,
}

fn commit_application(
    request: CommitRequest<'_, '_, '_>,
    timings: &mut ApplyTimings,
) -> core::result::Result<ApplyFinish, ApplyError> {
    let CommitRequest {
        handles,
        payload,
        block_hash,
        prev_hash,
        height,
        intent,
        flags,
        txids,
        resolved,
        tx_plan,
        attestation,
        publication,
        total_started,
    } = request;
    let (changes, undo, value_totals) = build_block_changes_checked(&ChangeRequest {
        image: payload,
        block_hash,
        height,
        txids: &txids,
        tx_plan: &tx_plan,
        resolved: &resolved,
    })?;
    check_coinbase_value(handles, height, &value_totals)?;
    if intent == ApplyIntent::Propose {
        return Ok(ApplyFinish::Proposed);
    }

    let persist_input = BlockOutcomeInputs {
        handles,
        payload,
        block_hash,
        height,
        txids,
        resolved,
        flags,
        undo: &undo,
        total_started,
    };
    let persisted = persist_payload(&persist_input, timings)?;
    let (outcome, undo_record, coin_stats_height_delta) =
        finish_block_outcome(persist_input, persisted, timings);
    Publication {
        handles,
        image: payload,
        outcome,
        publication,
        undo,
        changes,
        undo_record,
        attestation,
        prev_hash,
        coin_stats_height_delta,
    }
    .run()
}

pub(super) fn apply_block_admitted<'b>(
    handles: &Chainstate,
    payload: &'b BlockImage,
    proven: Option<ProvenApply<'b>>,
    scope: ApplyScope<'_>,
    intent: ApplyIntent,
    publication: PublishMode<'_>,
) -> core::result::Result<ApplyFinish, ApplyError> {
    let header = payload.header();
    let total_started = quanta::Instant::now();
    let block_hash = payload.block_hash().0;
    let prev_hash = header.prev_blockhash.0;
    let (prior, height) = application_predecessor(handles, block_hash, prev_hash, &publication)?;
    check_historical_target(handles, height, block_hash)?;
    check_self_pow(handles, &header, block_hash, height, intent)?;
    if !matches!(publication, PublishMode::Replay { .. }) {
        check_contextual_header(handles, &header, height, prior.as_deref(), block_hash)?;
    }

    let ValidationContexts {
        validation,
        softfork,
        median_time_past,
    } = validation_contexts(handles, &header, height, block_hash, prior.as_deref());
    let (prepared, transactions_proven) = prepare_block(handles, payload, proven, &validation)?;
    let mut timings = ApplyTimings::default();
    let (txids, tx_plan, resolved, attestation) = BlockValidation {
        handles,
        image: payload,
        block_hash,
        prev_hash,
        context: &validation,
        softfork,
        median_time_past,
        prior_tip_id: prior.as_deref().map(|tip| tip.tip_id),
        scope,
        intent,
        transactions_proven,
        prepared,
    }
    .run(&mut timings)?;
    commit_application(
        CommitRequest {
            handles,
            payload,
            block_hash,
            prev_hash,
            height,
            intent,
            flags: validation.flags,
            txids,
            resolved,
            tx_plan,
            attestation,
            publication,
            total_started,
        },
        &mut timings,
    )
}

fn emit_block_connected(
    image: &BlockImage,
    block_hash: &Hash256,
    height: u32,
    txids: &[Txid],
    resolved: &Arc<ResolvedUtxoView>,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
    elapsed: std::time::Duration,
) {
    bitcoin_rs_consensus::trace::block_connected(move || {
        let mut view = BlockLocalUtxoView::new(Arc::clone(resolved), image, height, 0);
        let mut inputs: u32 = 0;
        let mut sigops: u64 = 0;
        for index in 0..image.tx_count() {
            let tx = image.tx(index);
            inputs = inputs.saturating_add(u32::try_from(tx.input_count()).unwrap_or(u32::MAX));
            let mut prevouts = Vec::with_capacity(tx.input_count());
            for input_index in 0..tx.input_count() {
                let previous_output = tx.input_outpoint(input_index);
                if let Some(output) = view.lookup(&previous_output) {
                    prevouts.push((previous_output, output));
                }
            }
            sigops = sigops.saturating_add(u64::from(
                bitcoin_rs_consensus::transaction_sigop_cost_view(tx.into(), &prevouts, flags),
            ));
            if let Some(txid) = txids.get(index) {
                let _ = view.add_outputs(
                    u32::try_from(index).unwrap_or(u32::MAX),
                    *txid,
                    tx.output_count(),
                );
            }
        }
        (
            block_hash.as_byte_array().as_ptr(),
            i32::try_from(height).unwrap_or(i32::MAX),
            u64::try_from(image.tx_count()).unwrap_or(u64::MAX),
            i32::try_from(inputs).unwrap_or(i32::MAX),
            i64::try_from(sigops).unwrap_or(i64::MAX),
            i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX),
        )
    });
}

fn check_block_sigops(
    image: &BlockImage,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
) -> Result<(), ApplyError> {
    let mut view = BlockLocalUtxoView::new(resolved, image, height, 0);
    let mut cost = 0_u32;
    let mut prevouts = Vec::new();
    for (index, txid) in txids.iter().enumerate() {
        let tx = image.tx(index);
        prevouts.clear();
        prevouts.extend((0..tx.input_count()).filter_map(|input_index| {
            let previous_output = tx.input_outpoint(input_index);
            view.lookup(&previous_output)
                .map(|output| (previous_output, output))
        }));
        cost = cost.saturating_add(bitcoin_rs_consensus::transaction_sigop_cost_view(
            tx.into(),
            &prevouts,
            flags,
        ));
        if cost > bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST {
            return Err(bitcoin_rs_consensus::ConsensusError::SigopsLimit {
                cost,
                max: bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST,
            }
            .into());
        }
        if tx_plan.needs_local_utxo_overlay {
            view.spend_inputs(&tx);
            view.add_outputs(
                u32::try_from(index).unwrap_or(u32::MAX),
                *txid,
                tx.output_count(),
            )?;
        }
    }
    Ok(())
}

fn check_coinbase_maturity(
    image: &BlockImage,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    debug_assert_eq!(image.tx_count(), txids.len());
    if tx_plan.only_coinbase {
        return Ok(());
    }
    if !tx_plan.needs_local_utxo_overlay {
        for index in 0..image.tx_count() {
            let tx = image.tx(index);
            if tx.is_coinbase() {
                continue;
            }
            for input_index in 0..tx.input_count() {
                let previous_output = tx.input_outpoint(input_index);
                let Some(entry) = resolved.lookup_meta(&previous_output) else {
                    continue;
                };
                bitcoin_rs_consensus::check_coinbase_maturity(
                    entry.coinbase,
                    entry.height,
                    height,
                )?;
            }
        }
        return Ok(());
    }

    let mut view = BlockLocalUtxoView::new(resolved, image, height, tx_plan.overlay_capacity);
    for (tx_index, txid) in txids.iter().enumerate() {
        let tx = image.tx(tx_index);
        let tx_index_u32 = u32::try_from(tx_index).unwrap_or(u32::MAX);
        if tx.is_coinbase() {
            view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
            continue;
        }
        for input_index in 0..tx.input_count() {
            let previous_output = tx.input_outpoint(input_index);
            let Some(entry) = view.lookup_meta(&previous_output) else {
                continue;
            };
            bitcoin_rs_consensus::check_coinbase_maturity(entry.coinbase, entry.height, height)?;
        }
        view.spend_inputs(&tx);
        view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
    }
    Ok(())
}

fn check_bip68_sequence_locks(
    handles: &Chainstate,
    image: &BlockImage,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    context: Bip68Context<'_>,
) -> core::result::Result<(), ApplyError> {
    if !context.softfork_state.csv_active
        || tx_plan.only_coinbase
        || !tx_plan.has_bip68_sequence_locks
    {
        return Ok(());
    }
    let height = context.validation.height;
    let mtp = context.median_time_past;
    debug_assert_eq!(image.tx_count(), txids.len());
    let mut view = BlockLocalUtxoView::new(resolved, image, height, tx_plan.overlay_capacity);
    let mut prevout_mtp_by_height = HashMap::new();
    for (tx_index, txid) in txids.iter().enumerate() {
        let tx = image.tx(tx_index);
        let tx_index_u32 = u32::try_from(tx_index).unwrap_or(u32::MAX);
        if tx.is_coinbase() {
            view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
            continue;
        }
        if tx.version() < 2 {
            view.spend_inputs(&tx);
            view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
            continue;
        }
        for input_index in 0..tx.input_count() {
            let sequence = tx.input_sequence(input_index);
            if sequence.to_consensus()
                & bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG
                != 0
            {
                continue;
            }
            let previous_output = tx.input_outpoint(input_index);
            let Some(entry) = view.lookup_meta(&previous_output) else {
                continue;
            };
            let prevout_mtp = if bitcoin_rs_consensus::bip68::sequence_lock_is_time_based(
                sequence.to_consensus(),
            ) {
                prevout_median_time_past(
                    handles,
                    context,
                    entry.height,
                    &mut prevout_mtp_by_height,
                )?
            } else {
                0
            };
            bitcoin_rs_consensus::bip68::check_sequence_lock(
                tx.version(),
                sequence.to_consensus(),
                entry.height,
                prevout_mtp,
                height,
                mtp,
            )?;
        }
        view.spend_inputs(&tx);
        view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
    }
    Ok(())
}

fn prevout_median_time_past(
    handles: &Chainstate,
    context: Bip68Context<'_>,
    entry_height: u32,
    cache: &mut HashMap<u32, u32>,
) -> core::result::Result<u32, ApplyError> {
    if entry_height == context.validation.height {
        return Ok(context.median_time_past);
    }
    if let Some(cached) = cache.get(&entry_height) {
        return Ok(*cached);
    }
    let Some(previous_tip_id) = context.previous_tip_id else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing previous tip for time-based sequence lock".to_owned(),
            },
        ));
    };
    let tree = handles.block_tree.read();
    let Some(prevout_mtp) = tree.median_time_past_before_height(previous_tip_id, entry_height)
    else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: format!(
                    "missing prevout ancestry at height {} for time-based sequence lock",
                    entry_height.saturating_sub(1)
                ),
            },
        ));
    };
    cache.insert(entry_height, prevout_mtp);
    Ok(prevout_mtp)
}

fn check_bip30_and_bip34(
    handles: &Chainstate,
    image: &BlockImage,
    height: u32,
    txids: &[Txid],
    previous_tip_id: Option<NodeId>,
    scope: ApplyScope<'_>,
) -> core::result::Result<(), ApplyError> {
    let replay_exempt = matches!(
        scope.provenance,
        BlockProvenance::LocalReplay(_) | BlockProvenance::ColdReplay(_)
    );
    let mut has_duplicate = false;
    if !replay_exempt
        && crate::chain::bip30_duplicate_scan_required(
            &handles.block_tree.read(),
            handles.network,
            height,
            previous_tip_id,
        )
    {
        for txid in txids {
            let known = scope
                .staged
                .and_then(|workspace| workspace.coin_presence_before(*txid, height));
            let present = match known {
                Some(present) => present,
                None => {
                    let key = bitcoin_rs_storage::CoinKey(txid.0.to_le_bytes());
                    handles
                        .coins
                        .get(&key)
                        .map_err(ApplyError::CoinStoreRead)?
                        .is_some()
                }
            };
            if present {
                has_duplicate = true;
                break;
            }
        }
    }
    let block_hash = image.block_hash().0;
    if has_duplicate {
        bitcoin_rs_consensus::bip30::check_duplicate_txid(height, block_hash)?;
    }
    check_bip34(handles, image, height)?;
    Ok(())
}

fn check_bip34(
    handles: &Chainstate,
    image: &BlockImage,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    if handles.network.is_bip34_active(height) {
        if image.tx_count() == 0 {
            return Err(bitcoin_rs_consensus::ConsensusError::EmptyBlock.into());
        }
        let coinbase = image.tx(0);
        if coinbase.input_count() == 0 {
            return Err(bitcoin_rs_consensus::ConsensusError::MissingCoinbase.into());
        }
        bitcoin_rs_consensus::bip34::check_bip34(height, coinbase.input_script_sig(0))?;
    }
    Ok(())
}

fn check_block_finality(
    image: &BlockImage,
    height: u32,
    locktime_cutoff: u32,
) -> core::result::Result<(), ApplyError> {
    for index in 0..image.tx_count() {
        let tx = image.tx(index);
        if !bitcoin_rs_consensus::is_final_tx_view(tx.into(), height, locktime_cutoff) {
            return Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip {
                    bip: "BIP113",
                    reason: format!(
                        "non-final transaction at height {height} locktime cutoff \
                         {locktime_cutoff}: locktime {}",
                        tx.lock_time(),
                    ),
                },
            ));
        }
    }
    Ok(())
}

fn validate_contextual_block_header(
    handles: &Chainstate,
    header: &Header,
    height: u32,
    prior: Option<&TipSnapshot>,
) -> Result<(), ApplyError> {
    if height == 0 {
        return Ok(());
    }
    let Some(prior) = prior else {
        return Err(ApplyError::Chain(crate::chain::ChainError::MissingParent {
            prev_hash: header.prev_blockhash.0,
        }));
    };
    let tree = handles.block_tree.read();
    crate::chain::validate_contextual_header(
        &tree,
        prior.tip_id,
        header,
        handles.network,
        crate::chain::current_unix_seconds(),
        crate::chain::HeaderValidationMode::LiveAdmission,
    )
    .map_err(ApplyError::Chain)
}

fn applied_predecessor(
    handles: &Chainstate,
    block_hash: bitcoin_rs_consensus::primitives::Hash256,
    prev_hash: bitcoin_rs_consensus::primitives::Hash256,
) -> core::result::Result<(Option<Arc<TipSnapshot>>, u32), ApplyError> {
    let prior = handles.applied_tip.load_full();
    let height = if let Some(tip) = prior.as_deref() {
        if tip.hash != prev_hash {
            return Err(ApplyError::PrevHashMismatch {
                tip: tip.hash,
                prev: prev_hash,
            });
        }
        tip.height
            .checked_add(1)
            .ok_or(ApplyError::HeightOverflow(tip.height))?
    } else {
        if block_hash != handles.network.genesis_block_hash() {
            return Err(ApplyError::Chain(crate::chain::ChainError::MissingParent {
                prev_hash,
            }));
        }
        0_u32
    };
    Ok((prior, height))
}

pub(super) fn applied_header_tip(
    handles: &Chainstate,
    block_hash: Hash256,
    image: &BlockImage,
    height: u32,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let mut tree = handles.block_tree.write();
    let node_id = match tree.lookup(block_hash) {
        Some(node_id) => node_id,
        None => tree.insert_header(image.header(), crate::chain::node::NodeStatus::Active)?,
    };
    let node = tree.node(node_id)?;
    if node.height != height {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "INTERNAL",
                reason: format!(
                    "block-tree height {} does not match applied height {height} for block {block_hash}",
                    node.height
                ),
            },
        ));
    }
    let parent_known = node
        .parent
        .and_then(|parent| tree.node(parent).ok())
        .is_some_and(|parent| parent.chain_tx_count.get().is_some());
    tree.record_applied_tx_count(node_id, u64::try_from(image.tx_count()).unwrap_or(u64::MAX))?;
    let node = tree.node(node_id)?;
    if parent_known && node.chain_tx_count.get().is_none() {
        tracing::warn!(
            height,
            hash = %block_hash,
            "cumulative chain transaction count overflowed; marking it unknown"
        );
    }
    Ok(TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    })
}

fn map_block_change_error(error: &BlockChangeError) -> ApplyError {
    match error {
        BlockChangeError::BlockValueOverflow => ApplyError::BlockValueOverflow,
        BlockChangeError::VoutOverflow { txid } => ApplyError::VoutOverflow { txid: *txid },
        BlockChangeError::TxidCountMismatch {
            transactions,
            txids,
        } => ApplyError::TxidCountMismatch {
            transactions: *transactions,
            txids: *txids,
        },
        BlockChangeError::UndoPrevoutMissing { txid, vout } => ApplyError::UndoPrevoutMissing {
            txid: *txid,
            vout: *vout,
        },
    }
}
