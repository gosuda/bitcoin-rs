use std::sync::Arc;

use bitcoin_rs_chain::regtest_fixture::{
    coinbase, mined_block_with_prev_hash, mined_regtest_child_at,
};
use bitcoin_rs_primitives::{
    Amount, Block, BlockPayload, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Witness, consensus_bytes,
};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::pruning::{HistoryAccess, HistoryUnavailable, RetentionBudget};
use bitcoin_rs_storage::{CommitRecords, InMemoryUndoStore, StorageError, UndoStore};
use bitcoin_rs_utxo::{
    UtxoSet,
    contract::{BlockSpendsError, BlockUndoSource, UndoLoadError},
};
use parking_lot::Mutex;

use crate::{
    AssumeUtxoDiskStatus, Chainstate,
    test_fixtures::{MemoryBodies, handles},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

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
    chain: Chainstate,
    bodies: Arc<Bodies>,
    undo: Arc<InMemoryUndoStore>,
    retention: Arc<bitcoin_rs_storage::RetentionRegistry>,
    blocks: Vec<Block>,
}
fn fixture(count: u32) -> Result<Fixture> {
    let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let bodies = Arc::new(Bodies::default());
    let undo = Arc::new(InMemoryUndoStore::default());
    let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
    chain.block_body_store = Some(bodies.clone());
    chain.undo_store = undo.clone();
    chain.retention = bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention));
    chain.history = HistoryAccess::new(Arc::clone(&retention), RetentionBudget::from_blocks(288));
    let genesis = Network::Regtest.genesis_block();
    chain.apply_block(&BlockPayload::from_local(genesis.clone()))?;
    let mut blocks = vec![genesis];
    for height in 1..=count {
        let previous = blocks.last().ok_or("no parent")?.block_hash();
        let block = mined_regtest_child_at(previous, height)?;
        chain.apply_block(&BlockPayload::from_local(block.clone()))?;
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
fn tip(chain: &Chainstate) -> Result<Hash256> {
    Ok(chain.applied_tip_snapshot().ok_or("no applied tip")?.hash)
}

#[test]
fn read_uses_receipts_and_rejects_uncertified_old_branches() -> Result {
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
    f.chain
        .apply_block(&BlockPayload::from_local(fork.clone()))?;
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

#[test]
fn snapshot_prefix_needs_archived_progress_even_when_rows_exist() -> Result {
    let f = fixture(2)?;
    let prior = f.chain.durable_head.load()?.ok_or("no head")?;
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
        .durable_head
        .commit(Some(&prior), &next, &CommitRecords::default())?;
    let queried = hash(&f.blocks[1]);
    assert!(matches!(
        f.chain.block_spends(queried, tip(&f.chain)?)?.spent,
        Err(HistoryUnavailable::Missing)
    ));
    let prior = next;
    if let AssumeUtxoDiskStatus::Validating {
        historical_height,
        historical_hash,
        ..
    } = &mut next.assumeutxo
    {
        *historical_height = 1;
        *historical_hash = queried;
    }
    next.commit_id += 1;
    f.chain
        .durable_head
        .commit(Some(&prior), &next, &CommitRecords::default())?;
    assert_eq!(
        f.chain.block_spends(queried, tip(&f.chain)?)?.spent?,
        vec![vec![]]
    );
    let head = Arc::clone(&f.chain.durable_head);
    *f.bodies.hook.lock() = Some(Box::new(move || {
        let mut advanced = next;
        advanced.commit_id += 1;
        if let AssumeUtxoDiskStatus::Validating {
            historical_height,
            historical_hash,
            ..
        } = &mut advanced.assumeutxo
        {
            *historical_height = 2;
            *historical_hash = next.tip;
        }
        assert!(
            head.commit(Some(&next), &advanced, &CommitRecords::default())
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
fn pruning_reservations_and_expired_leases_keep_typed_failures() -> Result {
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
fn missing_and_corrupt_expected_undo_are_not_empty_success() -> Result {
    let f = fixture(1)?;
    let queried = hash(&f.blocks[1]);
    f.undo.remove_archived(1, queried);
    assert!(matches!(
        f.chain.block_spends(queried, tip(&f.chain)?),
        Err(BlockSpendsError::Undo(UndoLoadError::Missing { .. }))
    ));
    f.undo.persist_undo(1, queried, b"bad")?;
    assert!(matches!(
        f.chain.block_spends(queried, tip(&f.chain)?),
        Err(BlockSpendsError::Undo(UndoLoadError::Unreadable { .. }))
    ));
    f.chain.fail_closed_for_recovery();
    assert!(matches!(
        f.chain.block_spends(queried, tip(&f.chain)?),
        Err(BlockSpendsError::Closed)
    ));
    Ok(())
}

#[test]
fn genesis_skips_undo_but_never_fabricates_missing_body() -> Result {
    let mut f = fixture(1)?;
    let genesis = hash(&f.blocks[0]);
    f.undo.remove_archived(0, genesis);
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
fn certification_budget_stops_a_deep_side_anchor_before_body_io() -> Result {
    use bitcoin_rs_chain::{NodeStatus, regtest_fixture::mined_regtest_header};
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
fn retained_inputs_preserve_transaction_and_input_order_after_disconnect() -> Result {
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
        .apply_block(&BlockPayload::from_local(block.clone()))?;
    for disconnected in [false, true] {
        if disconnected {
            f.chain.disconnect_block(&block)?;
        }
        let record = f.chain.block_spends(hash(&block), tip(&f.chain)?)?;
        assert_eq!(record.block, block);
        let rows = record.spent?;
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], Vec::<bitcoin_rs_utxo::UtxoCoin>::new());
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
fn retained_body_rejects_witness_changes_that_preserve_header_and_txids() -> Result {
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
        0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69, 0x53,
        0x75, 0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36, 0x97, 0x4e,
        0x8c, 0xf9,
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
        .apply_block(&BlockPayload::from_local(committed.clone()))?;
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
fn retained_body_does_not_require_witness_for_pre_activation_commitment_lookalikes() -> Result {
    use bitcoin_rs_chain::NodeStatus;
    for (network, active) in [(Network::Mainnet, false), (Network::Regtest, true)] {
        let mut chain = handles(network, Arc::new(UtxoSet::new()));
        let bodies = Arc::new(Bodies::default());
        chain.block_body_store = Some(bodies.clone());
        let genesis = network.genesis_block();
        chain.apply_block(&BlockPayload::from_local(genesis.clone()))?;
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
fn retained_body_deployment_work_is_bounded_and_skipped_when_body_is_missing() -> Result {
    use bitcoin_rs_chain::NodeStatus;
    let mut chain = handles(Network::Mainnet, Arc::new(UtxoSet::new()));
    let bodies = Arc::new(Bodies::default());
    chain.block_body_store = Some(bodies.clone());
    let genesis = Network::Mainnet.genesis_block();
    chain.apply_block(&BlockPayload::from_local(genesis.clone()))?;
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
        bitcoin_rs_chain::deployment_statuses(&chain.block_tree.read(), Network::Mainnet, Some(id)),
        Err(bitcoin_rs_chain::DeploymentQueryError::Budget { .. })
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
