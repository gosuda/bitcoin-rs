use std::sync::Arc;

use bitcoin_rs_chain::regtest_fixture::{
    coinbase, mined_block_with_prev_hash, mined_regtest_child_at,
};
use bitcoin_rs_primitives::{Block, Hash256, Network};
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
    chain.apply_block(&genesis, None)?;
    let mut blocks = vec![genesis];
    for height in 1..=count {
        let previous = blocks.last().ok_or("no parent")?.block_hash();
        let block = mined_regtest_child_at(previous, height)?;
        chain.apply_block(&block, None)?;
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
    f.chain.apply_block(&fork, None)?;
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
    // A retained body can still be returned without inputs after undo history
    // was pruned. The two consumers retain the explicit unavailability reason.
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
            // Synthetic header admission is enough to choose a distinct best
            // header branch; this test does not claim PoW/consensus evidence.
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
