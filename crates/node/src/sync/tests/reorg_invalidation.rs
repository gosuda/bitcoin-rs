use super::*;

use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use parking_lot::Mutex;

#[derive(Default)]
struct Bodies {
    bodies: Mutex<HashMap<(u32, Hash256), Vec<u8>>>,
}

impl BlockBodyStore for Bodies {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies.lock().insert((height, hash), body.to_vec());
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.bodies.lock().get(&(height, hash)).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

type MaturedBodyStore = (
    Chainstate,
    Vec<Block>,
    HashMap<Hash256, BlockPayload>,
    Arc<Bodies>,
);

fn matured_chain_with_body_store() -> Result<MaturedBodyStore, Box<dyn std::error::Error>> {
    let (_, main, _) = matured_chain(101)?;
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    for block in &main {
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
    }
    let bodies_store = Arc::new(Bodies::default());
    let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
    let handles =
        bitcoin_rs_chainstate::Chainstate::from_parts(bitcoin_rs_chainstate::ChainstateParts {
            network: Network::Regtest,
            block_tree: tree,
            restored_applied_tip: None,
            utxo: Arc::new(UtxoSet::new()),
            coin_stats: Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
                bitcoin_rs_utxo::stats::CoinStats::default(),
            )),
            chain_events: Arc::new(bitcoin_rs_chainstate::events::ChainEventPublisher::detached(0)),
            block_body_store: Some(bodies_store.clone()),
            undo_store: Arc::new(bitcoin_rs_storage::undo::InMemoryUndoStore::default()),
            durable_head: Arc::new(bitcoin_rs_storage::InMemoryDurableHeadStore::new()),
            chain_transition: bitcoin_rs_chain::TransitionDomain::new().authority(),
            assume_valid_height: 0,
            validation_mode: bitcoin_rs_chainstate::ValidationMode::AssumeValid,
            validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
            script_cache: None,
            journal: None,
            capture_rawtx: false,
            capture_block_bytes: true,
            retention: bitcoin_rs_storage::MandatoryRetention::new(Arc::clone(&retention)),
            history: bitcoin_rs_storage::pruning::HistoryAccess::new(
                retention,
                bitcoin_rs_storage::pruning::RetentionBudget::from_blocks(288),
            ),
            role: bitcoin_rs_chainstate::ChainstateRole::Ordinary,
        });
    handles.apply_block(&BlockPayload::from_local(genesis))?;
    for block in &main {
        handles.apply_block(&BlockPayload::from_local(block.clone()))?;
    }
    let bodies = main
        .iter()
        .map(|block| {
            (
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                BlockPayload::from_local(block.clone()),
            )
        })
        .collect();
    Ok((handles, main, bodies, bodies_store))
}

#[test]
fn branch_switch_retires_only_the_connected_prefix_after_connect_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (handles, main, mut bodies) = matured_chain(101)?;
    let handles = Arc::new(handles);
    let followers = crate::chain_effects::ChainFollowers::noop();
    let adapter = super::super::NodeSyncChain {
        block_tree: handles.block_tree_reader(),
        handles: Arc::clone(&handles),
        followers,
        assumeutxo: None,
    };
    let applied_tip = handles.applied_tip_reader();
    let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());

    let fork_root_hash = main[99].block_hash();
    let mut fork_parent = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork = Vec::new();
    for height in 101..=102_u32 {
        let mut coinbase = regtest_fixture::coinbase(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let mut block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = crate::sync::fixture_insert_header_node(
            &handles,
            fork_parent,
            block.header,
            NodeStatus::HeaderValid,
        )?;
        fork_prev = block.block_hash();
        if height == 102 {
            block.txs[0].outputs[0].value = Amount::from_sat(2);
        }
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            BlockPayload::from_local(block.clone()),
        );
        fork.push(block);
    }

    let mut retired = Vec::new();
    let outcome = adapter.switch_to_branch(
        fork_parent,
        &mut |hash| bodies.get(&hash).cloned(),
        &mut |hash| retired.push(hash),
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::ConnectFailed {
                stopped_at: 101,
                connected: 1,
                ref disposition,
                ref invalidated,
                ..
            }) if *disposition == bitcoin_rs_chainstate::WindowApplyDisposition::BodyMutated
                && invalidated.is_empty()
        ),
        "the mutated second body must fail as BodyMutated after one committed connect, \
         got {outcome:?}"
    );

    let tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("partial switch did not publish a tip"))?;
    assert_eq!(
        tip.hash,
        Hash256::from_le_bytes(fork[0].block_hash().as_bytes()),
        "the valid prefix must remain committed"
    );
    let first = Hash256::from_le_bytes(fork[0].block_hash().as_bytes());
    let failed = Hash256::from_le_bytes(fork[1].block_hash().as_bytes());
    assert_eq!(
        retired,
        vec![first],
        "only the connected prefix body retires"
    );
    assert!(
        bodies.contains_key(&failed) && bodies.contains_key(&main_tip_hash),
        "the failed and disconnected bodies stay staged for a later switch"
    );
    assert_ne!(
        handles
            .block_tree()
            .read()
            .node_by_hash(failed)
            .map(|node| node.status),
        Some(NodeStatus::Invalid),
        "a mutated body must not invalidate the header subtree"
    );
    Ok(())
}

#[test]
fn permanent_reorg_failure_invalidates_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let (handles, main, mut bodies) = matured_chain(101)?;
    let handles = Arc::new(handles);
    let followers = crate::chain_effects::ChainFollowers::noop();
    let adapter = super::super::NodeSyncChain {
        block_tree: handles.block_tree_reader(),
        handles: Arc::clone(&handles),
        followers,
        assumeutxo: None,
    };
    let applied_tip = handles.applied_tip_reader();

    let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());
    let main_coin = OutPoint::new(main[100].txs[1].txid(), 0);
    let main_coin_before = handles.utxo().get_entry(&main_coin);
    let utxo_len_before = handles.utxo().len();
    assert!(main_coin_before.is_some(), "main-tip spend must be live");
    let fork_root_hash = main[99].block_hash();
    let fork_root_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let invalid = mined_block_with_prev_hash(fork_root_hash, 101, Vec::new());
    let invalid_id = crate::sync::fixture_insert_header_node(
        &handles,
        fork_root_id,
        invalid.header,
        NodeStatus::HeaderValid,
    )?;
    let descendant = mined_block_with_prev_hash(
        invalid.block_hash(),
        102,
        vec![regtest_fixture::coinbase(102)],
    );
    let descendant_id = crate::sync::fixture_insert_header_node(
        &handles,
        invalid_id,
        descendant.header,
        NodeStatus::HeaderValid,
    )?;
    for block in [&invalid, &descendant] {
        let staged = (*block).clone();
        bodies.insert(
            Hash256::from_le_bytes(staged.block_hash().as_bytes()),
            BlockPayload::from_local(staged),
        );
    }

    let outcome = adapter.switch_to_branch(
        descendant_id,
        &mut |hash| bodies.get(&hash).cloned(),
        &mut |_| {},
    );
    assert!(
        matches!(
            &outcome,
            Err(crate::reorg::ReorgError::ConnectFailed {
                disposition: bitcoin_rs_chainstate::WindowApplyDisposition::Permanent,
                invalidated,
                ..
            }) if invalidated.len() == 2
        ),
        "an empty-block connect must fail Permanent and report the invalidated subtree, \
         got {outcome:?}"
    );

    {
        let tree = handles.block_tree().read();
        assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
        assert_eq!(
            tree.tip().map(|tip| tip.hash),
            Some(main_tip_hash),
            "the valid main branch must win after subtree invalidation"
        );
    }
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(main_tip_hash)
    );
    assert_eq!(handles.utxo().len(), utxo_len_before);
    assert_eq!(handles.utxo().get_entry(&main_coin), main_coin_before);
    Ok(())
}

#[test]
fn invalid_first_reorg_body_closes_if_old_body_disappears_during_restoration()
-> Result<(), Box<dyn std::error::Error>> {
    let (handles, main, mut bodies) = matured_chain(101)?;
    let handles = Arc::new(handles);
    let adapter = super::super::NodeSyncChain {
        block_tree: handles.block_tree_reader(),
        handles: Arc::clone(&handles),
        followers: crate::chain_effects::ChainFollowers::noop(),
        assumeutxo: None,
    };
    let old_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());
    let fork_root_hash = main[99].block_hash();
    let fork_root_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or("missing fork root")?;
    let invalid = mined_block_with_prev_hash(fork_root_hash, 101, Vec::new());
    let invalid_id = crate::sync::fixture_insert_header_node(
        &handles,
        fork_root_id,
        invalid.header,
        NodeStatus::HeaderValid,
    )?;
    bodies.insert(
        Hash256::from_le_bytes(invalid.block_hash().as_bytes()),
        BlockPayload::from_local(invalid),
    );

    let mut old_body_reads = 0;
    let outcome = adapter.switch_to_branch(
        invalid_id,
        &mut |hash| {
            if hash == old_tip_hash {
                old_body_reads += 1;
                if old_body_reads == 3 {
                    return None;
                }
            }
            bodies.get(&hash).cloned()
        },
        &mut |_| {},
    );
    let Err(crate::reorg::ReorgError::RestorationFailed { source, original }) = outcome else {
        panic!("restoration body loss must require recovery, got {outcome:?}");
    };
    assert!(matches!(
        *source,
        crate::reorg::ReorgError::MissingBody { hash, height: 101 }
            if hash == old_tip_hash
    ));
    assert!(matches!(
        *original,
        crate::reorg::ReorgError::ConnectFailed {
            disposition: bitcoin_rs_chainstate::WindowApplyDisposition::Permanent,
            ..
        }
    ));
    assert_eq!(old_body_reads, 3);
    assert!(handles.is_closed_for_recovery());
    Ok(())
}

#[test]
fn branch_switch_rejects_a_body_for_another_header_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (handles, main, mut bodies) = matured_chain(101)?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();
    let applied_before = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let utxo_len_before = handles.utxo().len();

    let fork_root_hash = main[99].block_hash();
    let fork_root_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut target_coinbase = regtest_fixture::coinbase(101);
    target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
    let target = mined_block_with_prev_hash(fork_root_hash, 101, vec![target_coinbase]);
    let target_id = crate::sync::fixture_insert_header_node(
        &handles,
        fork_root_id,
        target.header,
        NodeStatus::HeaderValid,
    )?;
    let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
    let mut wrong_coinbase = regtest_fixture::coinbase(101);
    wrong_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
    let wrong = mined_block_with_prev_hash(fork_root_hash, 101, vec![wrong_coinbase]);
    bodies.insert(target_hash, BlockPayload::from_local(wrong));

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &followers,
        target_id,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyHashMismatch { height: 101, .. })
        ),
        "a body keyed for another header must refuse before mutation, got {outcome:?}"
    );
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_before.hash),
        "a pre-mutation refusal must leave the applied tip untouched"
    );
    assert_eq!(
        handles.utxo().len(),
        utxo_len_before,
        "a pre-mutation refusal must leave the UTXO set untouched"
    );
    Ok(())
}

#[test]
fn branch_switch_rejects_malformed_body_before_mutation() -> Result<(), Box<dyn std::error::Error>>
{
    use bitcoin_rs_primitives::Script;
    let (handles, main, bodies, bodies_store) = matured_chain_with_body_store()?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();
    let applied_before = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let utxo_len_before = handles.utxo().len();

    let fork_root_hash = main[99].block_hash();
    let fork_root_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut target_coinbase = regtest_fixture::coinbase(101);
    target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
    let target = mined_block_with_prev_hash(fork_root_hash, 101, vec![target_coinbase]);
    let target_id = crate::sync::fixture_insert_header_node(
        &handles,
        fork_root_id,
        target.header,
        NodeStatus::HeaderValid,
    )?;
    let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
    let mut malformed = BlockPayload::from_local(target).bytes().clone();
    malformed.truncate(malformed.len() - 1);
    bodies_store
        .persist_block_body(101, target_hash, &malformed)
        .map_err(|error| {
            std::io::Error::other(format!("malformed fixture must persist: {error:?}"))
        })?;

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &followers,
        target_id,
        |hash| {
            if hash == target_hash {
                return None;
            }
            bodies.get(&hash).cloned()
        },
        |_| {},
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyDecode { height: 101, .. })
        ),
        "malformed body bytes must refuse before mutation, got {outcome:?}"
    );
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_before.hash),
        "a pre-mutation refusal must leave the applied tip untouched"
    );
    assert_eq!(
        handles.utxo().len(),
        utxo_len_before,
        "a pre-mutation refusal must leave the UTXO set untouched"
    );
    Ok(())
}
