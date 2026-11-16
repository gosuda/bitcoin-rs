use crate::chain::BlockTree;
use bitcoin_rs_consensus::primitives::{Block, Hash256, deserialize};
use bitcoin_rs_storage::utxo::contract::{
    BlockSpends, BlockSpendsError, BlockUndoSource, HistoryUnavailable, UndoLoadError,
    block_spent_outputs, decode_undo_record_for_block,
};
use bitcoin_rs_storage::{DurableHead, pruning::HistoryLease};

use crate::{AssumeUtxoDiskStatus, Chainstate};

/// Limit the owned raw record before copying and decoding. Engine-internal
/// pages/cache/decompression are outside the storage method's copy bound.
pub(crate) const MAX_UNDO_QUERY_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_BLOCK_QUERY_BYTES: usize = 4_000_000;

impl BlockUndoSource for Chainstate {
    fn block_spends(
        &self,
        hash: Hash256,
        expected_applied_hash: Hash256,
    ) -> Result<BlockSpends, BlockSpendsError> {
        let (head, height, lease, availability) = {
            let _transition = self.chain_transition.lock();
            self.check_undo_read_state(expected_applied_hash)?;
            let tree = self.block_tree.read();
            let node = tree
                .node_by_hash(hash)
                .ok_or(BlockSpendsError::UnknownBlock)?;
            let height = node.height;
            drop(tree);
            let head = self
                .durable_head
                .load()?
                .ok_or(HistoryUnavailable::Missing)?;
            if head.tip != expected_applied_hash {
                return Err(BlockSpendsError::Retry);
            }
            let (lease, availability) = match self.history.request_history(height) {
                Ok(lease) => {
                    let availability = if certified(&self.block_tree.read(), &head, height, hash)? {
                        Ok(())
                    } else {
                        Err(HistoryUnavailable::Missing)
                    };
                    (Some(lease), availability)
                }
                Err(reason @ HistoryUnavailable::Pruned { .. }) => (None, Err(reason)),
                Err(reason) => return Err(reason.into()),
            };
            (head, height, lease, availability)
        };
        let result = self.read_block_spends(hash, height, availability);
        self.recheck_undo_read(
            expected_applied_hash,
            &head,
            height,
            lease.as_ref(),
            availability,
        )?;
        result
    }
}

impl Chainstate {
    fn check_undo_read_state(&self, expected: Hash256) -> Result<(), BlockSpendsError> {
        if self.is_closed_for_recovery() {
            return Err(BlockSpendsError::Closed);
        }
        if self.shutdown.reader().is_triggered() {
            return Err(HistoryUnavailable::Shutdown.into());
        }
        let applied = self.applied_tip.load_full();
        let hash = applied
            .as_ref()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash);
        if hash != expected {
            return Err(BlockSpendsError::Retry);
        }
        Ok(())
    }

    fn recheck_undo_read(
        &self,
        expected: Hash256,
        head: &DurableHead,
        height: u32,
        lease: Option<&HistoryLease>,
        availability: Result<(), HistoryUnavailable>,
    ) -> Result<(), BlockSpendsError> {
        let _transition = self.chain_transition.lock();
        self.check_undo_read_state(expected)?;
        if self.durable_head.load()?.as_ref() != Some(head) {
            return Err(BlockSpendsError::Retry);
        }
        if let Some(lease) = lease {
            if lease.floor() != Some(height) {
                let _probe = self.history.request_history(height)?;
                return Err(BlockSpendsError::Retry);
            }
        } else {
            match self.history.request_history(height) {
                Err(current) if availability == Err(current) => {}
                Err(current) => return Err(current.into()),
                Ok(_lease) => return Err(BlockSpendsError::Retry),
            }
        }
        Ok(())
    }

    fn read_block_spends(
        &self,
        hash: Hash256,
        height: u32,
        availability: Result<(), HistoryUnavailable>,
    ) -> Result<BlockSpends, BlockSpendsError> {
        let store = self
            .block_body_store
            .as_ref()
            .ok_or(BlockSpendsError::BodyRead(
                bitcoin_rs_storage::BoundedReadError::Unsupported,
            ))?;
        let bytes = store
            .load_block_body_bounded(height, hash, MAX_BLOCK_QUERY_BYTES)
            .map_err(BlockSpendsError::BodyRead)?
            .ok_or_else(|| availability.err().unwrap_or(HistoryUnavailable::Missing))?;
        let block: Block = deserialize(&bytes)
            .map_err(|_| BlockSpendsError::Corrupt("block body does not decode"))?;
        if block.block_hash().0 != hash {
            return Err(BlockSpendsError::Corrupt("block body hash differs"));
        }
        let segwit_active = {
            let tree = self.block_tree.read();
            let id = tree.lookup(hash).ok_or(BlockSpendsError::Corrupt(
                "retained body header is absent from the block tree",
            ))?;
            crate::chain::deployment_statuses(&tree, self.network, Some(id))
                .map_err(|error| match error {
                    crate::chain::DeploymentQueryError::Budget { .. } => {
                        BlockSpendsError::ResourceLimit
                    }
                    crate::chain::DeploymentQueryError::Chain(_)
                    | crate::chain::DeploymentQueryError::IncompleteAncestry => {
                        BlockSpendsError::Corrupt("block deployment ancestry is inconsistent")
                    }
                })?
                .into_iter()
                .find(|status| status.name == "segwit")
                .ok_or(BlockSpendsError::Corrupt(
                    "SegWit deployment status is absent",
                ))?
                .active_at_block
        };
        bitcoin_rs_consensus::check_block_body_binding(
            &block,
            bitcoin_rs_consensus::BlockRuleContext { segwit_active },
        )
        .map_err(|_| {
            BlockSpendsError::Corrupt("block body does not match its header commitments")
        })?;
        drop(bytes);
        if height == 0 && hash == self.network.genesis_block_hash() {
            return Ok(BlockSpends {
                block,
                spent: Ok(vec![Vec::new()]),
            });
        }
        if let Err(reason) = availability {
            return Ok(BlockSpends {
                block,
                spent: Err(reason),
            });
        }
        let record = self
            .undo_store
            .load_undo_bounded(height, hash, MAX_UNDO_QUERY_BYTES)?
            .ok_or(UndoLoadError::Missing { hash, height })?;
        let undo = decode_undo_record_for_block(&record, &block)
            .map_err(|source| UndoLoadError::Unreadable { hash, source })?;
        drop(record);
        let spent = block_spent_outputs(&block, height, &undo)?;
        Ok(BlockSpends {
            block,
            spent: Ok(spent),
        })
    }
}

fn ancestor_is(
    tree: &BlockTree,
    anchor: Hash256,
    height: u32,
    hash: Hash256,
    remaining: &mut usize,
) -> Result<bool, BlockSpendsError> {
    let Some(tip) = tree.lookup(anchor) else {
        return Ok(false);
    };
    Ok(tree
        .node_at_height_from_bounded(tip, height, remaining)
        .map_err(|_| BlockSpendsError::ResourceLimit)?
        .and_then(|id| tree.node(id).ok())
        .is_some_and(|node| node.hash == hash))
}

fn certified(
    tree: &BlockTree,
    head: &DurableHead,
    height: u32,
    hash: Hash256,
) -> Result<bool, BlockSpendsError> {
    let mut remaining = 4096;
    match head.assumeutxo {
        AssumeUtxoDiskStatus::Failed { .. } => return Err(BlockSpendsError::Closed),
        AssumeUtxoDiskStatus::Validating {
            base_height,
            historical_height,
            historical_hash,
            ..
        } if height <= base_height => {
            return if height <= historical_height {
                ancestor_is(tree, historical_hash, height, hash, &mut remaining)
            } else {
                Ok(false)
            };
        }
        _ => {}
    }
    if ancestor_is(tree, head.tip, height, hash, &mut remaining)? {
        return Ok(true);
    }
    match head.undo_extent {
        Some((extent_height, extent_hash)) if height <= extent_height => {
            ancestor_is(tree, extent_hash, height, hash, &mut remaining)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::chain::regtest_fixture::{
        coinbase, mined_block_with_prev_hash, mined_regtest_child_at,
    };
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Witness, consensus_bytes,
    };
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use bitcoin_rs_storage::pruning::{HistoryAccess, HistoryUnavailable, RetentionBudget};
    use bitcoin_rs_storage::utxo::{
        UtxoSet,
        contract::{BlockSpendsError, BlockUndoSource, UndoReadError},
    };
    use bitcoin_rs_storage::{KvUndoStore, StorageError, UndoStore};
    use parking_lot::Mutex;

    use crate::{
        AssumeUtxoDiskStatus, Chainstate,
        test_fixtures::{TestError, TestResult, handles},
        test_support::MemoryBodies,
    };

    #[derive(Default)]
    struct Bodies {
        inner: MemoryBodies,
        hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl BlockBodyStore for Bodies {
        fn load_block_body_bounded(
            &self,
            height: u32,
            hash: Hash256,
            max_bytes: usize,
        ) -> std::result::Result<Option<Vec<u8>>, bitcoin_rs_storage::BoundedReadError> {
            let hook = self.hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
            self.inner.load_block_body_bounded(height, hash, max_bytes)
        }

        fn persist_block_body(
            &self,
            height: u32,
            hash: Hash256,
            bytes: &[u8],
        ) -> std::result::Result<(), StorageError> {
            self.inner.persist_block_body(height, hash, bytes)
        }
        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, StorageError> {
            let hook = self.hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
            self.inner.load_block_body(height, hash)
        }
        fn sync(&self) -> std::result::Result<(), StorageError> {
            Ok(())
        }
    }
    struct Fixture {
        bodies: Arc<Bodies>,
        chain: Chainstate,
        undo: Arc<KvUndoStore<dyn bitcoin_rs_storage::KvStore>>,
        retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
        blocks: Vec<Block>,
    }
    fn fixture(count: u32) -> TestResult<Fixture> {
        let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let bodies = Arc::new(Bodies::default());
        let undo = Arc::new(KvUndoStore::new(Arc::clone(chain.commit_authority.store())));
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
        chain.block_body_store = Some(bodies.clone());
        chain.undo_store = undo.clone();
        chain.retention = bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention));
        chain.history =
            HistoryAccess::new(Arc::clone(&retention), RetentionBudget::from_blocks(288));
        let genesis = Network::Regtest.genesis_block();
        chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
        let mut blocks = vec![genesis];
        for height in 1..=count {
            let previous = blocks
                .last()
                .ok_or(TestError::Missing("no parent"))?
                .block_hash();
            let block = mined_regtest_child_at(previous, height)?;
            chain.apply_block(&BlockImage::from_local(block.clone()))?;
            blocks.push(block);
        }
        Ok(Fixture {
            chain,
            bodies,
            undo,
            retention,
            blocks,
        })
    }
    fn hash(block: &Block) -> Hash256 {
        block.block_hash().into()
    }
    fn tip(chain: &Chainstate) -> TestResult<Hash256> {
        Ok(chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("no applied tip"))?
            .hash)
    }

    // ARCH-07
    #[test]
    fn read_uses_receipts_and_rejects_uncertified_old_branches() -> TestResult {
        let f = fixture(2)?;
        let old = hash(&f.blocks[2]);
        assert_eq!(f.chain.block_spends(old, tip(&f.chain)?)?.spent?.len(), 1);
        f.chain.disconnect_block(&f.blocks[2])?;
        assert_eq!(
            f.chain.block_spends(old, tip(&f.chain)?)?.spent?,
            vec![vec![]]
        );
        let mut cb = coinbase(2);
        cb.inputs[0].script_sig = vec![0x52, 0x01, 0x01].into();
        let fork = mined_block_with_prev_hash(f.blocks[1].block_hash(), 2, vec![cb])?;
        f.chain.apply_block(&BlockImage::from_local(fork.clone()))?;
        assert!(matches!(
            f.chain.block_spends(old, tip(&f.chain)?)?.spent,
            Err(HistoryUnavailable::Missing)
        ));
        assert!(
            f.undo.load_undo(2, old)?.is_some(),
            "retained bytes alone are not certification"
        );
        assert!(matches!(
            f.chain.block_spends(hash(&fork), Hash256::default()),
            Err(BlockSpendsError::Retry)
        ));
        Ok(())
    }

    // ARCH-07
    #[test]
    fn snapshot_prefix_needs_archived_progress_even_when_rows_exist() -> TestResult {
        let f = fixture(2)?;
        let prior = f
            .chain
            .durable_head
            .load()?
            .ok_or(TestError::Missing("no head"))?;
        let mut next = prior;
        next.commit_id += 1;
        next.assumeutxo = AssumeUtxoDiskStatus::Validating {
            base_height: 2,
            base_hash: hash(&f.blocks[2]),
            expected_hash_serialized: Hash256::default(),
            chain_tx_count: 3,
            historical_height: 0,
            historical_hash: hash(&f.blocks[0]),
            pending: None,
            checkpoint: None,
        };
        f.chain
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: Some(prior),
                next_head: next,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(StorageError::backend)?;
        let queried = hash(&f.blocks[1]);
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?)?.spent,
            Err(HistoryUnavailable::Missing)
        ));
        let prior = next;
        if let &mut AssumeUtxoDiskStatus::Validating {
            ref mut historical_height,
            ref mut historical_hash,
            ..
        } = &mut next.assumeutxo
        {
            *historical_height = 1;
            *historical_hash = queried;
        }
        next.commit_id += 1;
        f.chain
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: Some(prior),
                next_head: next,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: bitcoin_rs_storage::WindowDelta::default(),
            })
            .map_err(StorageError::backend)?;
        assert_eq!(
            f.chain.block_spends(queried, tip(&f.chain)?)?.spent?,
            vec![vec![]]
        );
        let head = Arc::clone(f.chain.commit_authority());
        *f.bodies.hook.lock() = Some(Box::new(move || {
            let mut advanced = next;
            advanced.commit_id += 1;
            if let &mut AssumeUtxoDiskStatus::Validating {
                ref mut historical_height,
                ref mut historical_hash,
                ..
            } = &mut advanced.assumeutxo
            {
                *historical_height = 2;
                *historical_hash = next.tip;
            }
            assert!(
                head.commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: Some(next),
                    next_head: advanced,
                    undo_rows: Vec::new(),
                    body_rows: Vec::new(),
                    attestation: None,
                    coin_delta: bitcoin_rs_storage::WindowDelta::default(),
                })
                .is_ok()
            );
        }));
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?),
            Err(BlockSpendsError::Retry)
        ));
        Ok(())
    }

    #[test]
    fn pruning_reservations_and_expired_leases_keep_typed_failures() -> TestResult {
        let f = fixture(600)?;
        let queried = hash(&f.blocks[1]);
        let reservation = f.retention.reserve(2);
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?),
            Err(BlockSpendsError::History(HistoryUnavailable::Reserved {
                below: 2
            }))
        ));
        drop(reservation);
        let registry = Arc::clone(&f.retention);
        *f.bodies.hook.lock() = Some(Box::new(move || {
            registry.reserve(300).commit(300);
        }));
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?),
            Err(BlockSpendsError::History(HistoryUnavailable::Pruned {
                below: 300
            }))
        ));
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?)?.spent,
            Err(HistoryUnavailable::Pruned { below: 300 })
        ));
        f.retention.shutdown();
        assert!(matches!(
            f.chain.block_spends(hash(&f.blocks[600]), tip(&f.chain)?),
            Err(BlockSpendsError::History(HistoryUnavailable::Shutdown))
        ));
        Ok(())
    }

    #[test]
    fn missing_and_corrupt_expected_undo_are_not_empty_success() -> TestResult {
        let f = fixture(1)?;
        let queried = hash(&f.blocks[1]);
        f.undo.remove_archived(1, queried)?;
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?),
            Err(BlockSpendsError::Undo(UndoReadError::Missing { block, height }))
                if block == queried && height == 1
        ));
        f.undo.persist_undo(1, queried, b"bad")?;
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?),
            Err(BlockSpendsError::Undo(UndoReadError::Unreadable { block })) if block == queried
        ));
        f.chain.fail_closed_for_recovery();
        assert!(matches!(
            f.chain.block_spends(queried, tip(&f.chain)?),
            Err(BlockSpendsError::Closed)
        ));
        Ok(())
    }

    #[test]
    fn genesis_skips_undo_but_never_fabricates_missing_body() -> TestResult {
        let mut f = fixture(1)?;
        let genesis = hash(&f.blocks[0]);
        f.undo.remove_archived(0, genesis)?;
        assert_eq!(
            f.chain.block_spends(genesis, tip(&f.chain)?)?.spent?,
            vec![vec![]]
        );
        f.chain.block_body_store = Some(Arc::new(Bodies::default()));
        assert!(matches!(
            f.chain.block_spends(genesis, tip(&f.chain)?),
            Err(BlockSpendsError::History(HistoryUnavailable::Missing))
        ));
        Ok(())
    }

    #[test]
    fn certification_budget_stops_a_deep_side_anchor_before_body_io() -> TestResult {
        use crate::chain::{NodeStatus, regtest_fixture::mined_regtest_header};
        let f = fixture(4100)?;
        let mut previous = f.blocks[0].block_hash();
        {
            let mut tree = f.chain.block_tree.write();
            for height in 1..=4101 {
                let mut header = mined_regtest_header(previous, height)?;
                header.version = 5;
                let id = tree.insert_header(header, NodeStatus::HeaderValid)?;
                previous = tree.node(id)?.hash.into();
            }
        }
        *f.bodies.hook.lock() = Some(Box::new(|| panic!("budget refusal must precede body I/O")));
        assert!(matches!(
            f.chain.block_spends(hash(&f.blocks[1]), tip(&f.chain)?),
            Err(BlockSpendsError::ResourceLimit)
        ));
        Ok(())
    }

    #[test]
    fn retained_inputs_preserve_transaction_and_input_order_after_disconnect() -> TestResult {
        let f = fixture(101)?;
        let second = &f.blocks[2].txs[0];
        let first = &f.blocks[1].txs[0];
        let input = |tx: &Tx, vout| TxIn {
            previous_output: OutPoint::new(tx.txid(), vout),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let parent = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![input(second, 0), input(first, 0)],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(4_000_000_000),
                    script_pubkey: Script::new(),
                },
                TxOut {
                    value: Amount::from_sat(5_999_999_000),
                    script_pubkey: Script::new(),
                },
            ],
        };
        let child = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![input(&parent, 1), input(&parent, 0)],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_999_998_000),
                script_pubkey: Script::new(),
            }],
        };
        let block = mined_block_with_prev_hash(
            f.blocks[101].block_hash(),
            102,
            vec![coinbase(102), parent.clone(), child],
        )?;
        f.chain
            .apply_block(&BlockImage::from_local(block.clone()))?;
        for disconnected in [false, true] {
            if disconnected {
                f.chain.disconnect_block(&block)?;
            }
            let record = f.chain.block_spends(hash(&block), tip(&f.chain)?)?;
            assert_eq!(record.block, block);
            let rows = record.spent?;
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0], Vec::<bitcoin_rs_storage::utxo::UtxoCoin>::new());
            assert_eq!(rows[1].len(), 2);
            assert_eq!(rows[2].len(), 2);
            for (coin, (tx, height)) in rows[1].iter().zip([(second, 2), (first, 1)]) {
                assert_eq!(coin.outpoint, OutPoint::new(tx.txid(), 0));
                assert_eq!(coin.txout, tx.outputs[0]);
                assert_eq!(coin.height, height);
                assert!(coin.coinbase);
            }
            for (coin, (vout, output)) in rows[2]
                .iter()
                .zip([(1, &parent.outputs[1]), (0, &parent.outputs[0])])
            {
                assert_eq!(coin.outpoint, OutPoint::new(parent.txid(), vout));
                assert_eq!(&coin.txout, output);
                assert_eq!(coin.height, 102);
                assert!(!coin.coinbase);
            }
        }
        Ok(())
    }

    #[test]
    fn retained_body_rejects_witness_changes_that_preserve_header_and_txids() -> TestResult {
        let f = fixture(1)?;
        let original = &f.blocks[1];
        let mut injected = original.clone();
        injected.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
        assert_eq!(injected.txs[0].txid(), original.txs[0].txid());
        assert_eq!(hash(&injected), hash(original));
        f.bodies
            .persist_block_body(1, hash(original), &consensus_bytes(&injected))?;
        assert!(matches!(
            f.chain.block_spends(hash(original), tip(&f.chain)?),
            Err(BlockSpendsError::Corrupt(_))
        ));

        f.bodies
            .persist_block_body(1, hash(original), &consensus_bytes(original))?;

        let commitment = [
            0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69,
            0x53, 0x75, 0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36,
            0x97, 0x4e, 0x8c, 0xf9,
        ];
        let mut cb = coinbase(2);
        cb.inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
        cb.outputs.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: Script::from_bytes(
                [&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed][..], &commitment].concat(),
            ),
        });
        let committed = mined_block_with_prev_hash(original.block_hash(), 2, vec![cb])?;
        f.chain
            .apply_block(&BlockImage::from_local(committed.clone()))?;
        assert_eq!(
            f.chain
                .block_spends(hash(&committed), tip(&f.chain)?)?
                .block,
            committed
        );
        for witness in [Witness::from_stack(vec![vec![1; 32]]), Witness::new()] {
            let mut changed = committed.clone();
            changed.txs[0].inputs[0].witness = witness;
            assert_eq!(changed.txs[0].txid(), committed.txs[0].txid());
            assert_eq!(hash(&changed), hash(&committed));
            f.bodies
                .persist_block_body(2, hash(&committed), &consensus_bytes(&changed))?;
            assert!(matches!(
                f.chain.block_spends(hash(&committed), tip(&f.chain)?),
                Err(BlockSpendsError::Corrupt(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn retained_body_does_not_require_witness_for_pre_activation_commitment_lookalikes()
    -> TestResult {
        use crate::chain::NodeStatus;
        for (network, active) in [(Network::Mainnet, false), (Network::Regtest, true)] {
            let mut chain = handles(network, Arc::new(UtxoSet::new()));
            let bodies = Arc::new(Bodies::default());
            chain.block_body_store = Some(bodies.clone());
            let genesis = network.genesis_block();
            chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
            let mut cb = coinbase(1);
            cb.outputs.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes(
                    [&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed][..], &[0xff; 32]].concat(),
                ),
            });
            let block = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![cb])?;
            chain
                .block_tree
                .write()
                .insert_header(block.header, NodeStatus::HeaderValid)?;
            bodies.persist_block_body(1, hash(&block), &consensus_bytes(&block))?;
            let record = chain.block_spends(hash(&block), tip(&chain)?);
            if active {
                assert!(matches!(record, Err(BlockSpendsError::Corrupt(_))));
            } else {
                let record = record?;
                assert_eq!(record.block, block);
                assert!(matches!(record.spent, Err(HistoryUnavailable::Missing)));
            }
        }
        Ok(())
    }

    #[test]
    fn retained_body_deployment_work_is_bounded_and_skipped_when_body_is_missing() -> TestResult {
        use crate::chain::NodeStatus;
        let mut chain = handles(Network::Mainnet, Arc::new(UtxoSet::new()));
        let bodies = Arc::new(Bodies::default());
        chain.block_body_store = Some(bodies.clone());
        let genesis = Network::Mainnet.genesis_block();
        chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
        let block = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase(1)])?;
        let id = {
            let mut tree = chain.block_tree.write();
            let id = tree.insert_header(block.header, NodeStatus::HeaderValid)?;
            let mut competing = block.header;
            competing.nonce = competing.nonce.wrapping_add(1);
            let sibling = tree.insert_header(competing, NodeStatus::HeaderValid)?;
            competing.prev_blockhash = tree.node(sibling)?.hash.into();
            let competing_tip = tree.insert_header(competing, NodeStatus::HeaderValid)?;
            assert_eq!(tree.tip_id(), Some(competing_tip));
            tree.node_mut(id)?.height = 2_000_000;
            id
        };
        assert!(matches!(
            crate::chain::deployment_statuses(&chain.block_tree.read(), Network::Mainnet, Some(id)),
            Err(crate::chain::DeploymentQueryError::Budget { .. })
        ));
        assert!(matches!(
            chain.block_spends(hash(&block), tip(&chain)?),
            Err(BlockSpendsError::History(HistoryUnavailable::Missing))
        ));
        bodies.persist_block_body(2_000_000, hash(&block), &consensus_bytes(&block))?;
        assert!(matches!(
            chain.block_spends(hash(&block), tip(&chain)?),
            Err(BlockSpendsError::ResourceLimit)
        ));
        chain.block_tree.write().node_mut(id)?.height = 2;
        bodies.persist_block_body(2, hash(&block), &consensus_bytes(&block))?;
        assert!(matches!(
            chain.block_spends(hash(&block), tip(&chain)?),
            Err(BlockSpendsError::Corrupt(_))
        ));
        Ok(())
    }
}
