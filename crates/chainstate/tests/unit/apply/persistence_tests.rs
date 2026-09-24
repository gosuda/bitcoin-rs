use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, TipSnapshot, compact_is_met_by};
use bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_storage::{
    CommitRecords, DisconnectMarker, DurableHead, DurableHeadStore, InMemoryDurableHeadStore,
    InMemoryUndoStore, StorageError, UndoStore,
};
use bitcoin_rs_utxo::connect::build_block_changes;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use hashbrown::HashMap;
use parking_lot::RwLock;

use super::{ApplyError, Chainstate, ResolvedUtxoView};

struct RejectingUndoStore {
    inner: InMemoryUndoStore,
}

impl UndoStore for RejectingUndoStore {
    fn persist_undo(
        &self,
        _height: u32,
        _hash: Hash256,
        _record: &[u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::backend("injected undo-persist failure"))
    }

    fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_undo(height, hash)
    }

    fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        self.inner.arm_disconnect(height, hash)
    }

    fn complete_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        self.inner.complete_disconnect(height, hash)
    }

    fn disarm_disconnect(&self) -> Result<(), StorageError> {
        self.inner.disarm_disconnect()
    }

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        self.inner.load_disconnect_marker()
    }
}

fn handles(network: Network, utxo: Arc<UtxoSet>) -> Chainstate {
    Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        utxo,
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    )
}

fn seed_genesis(handles: &Chainstate) -> Result<TipSnapshot, ApplyError> {
    let genesis = Network::Regtest.genesis_block();
    let tip = crate::connect::applied_header_tip(
        handles,
        Hash256::from(genesis.block_hash()),
        &genesis,
        0,
    )?;
    let tip = bitcoin_rs_chain::TipSnapshot {
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(1),
        ..tip
    };
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    Ok(tip)
}

fn coinbase(height: u32) -> Tx {
    let Ok(encoded_height) = u8::try_from(height) else {
        panic!("test coinbase height must fit in one byte");
    };
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, encoded_height, 0]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

fn mined_child(parent: BlockHash, height: u32) -> Result<Block, Box<dyn std::error::Error>> {
    let tx = coinbase(height);
    let mut leaves = vec![*tx.txid().as_bytes()];
    let merkle = bitcoin_rs_consensus::verify_block::compute_merkle_root(&mut leaves)
        .ok_or("coinbase merkle root missing")?;
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash: parent,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: 1_296_688_602_u32.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![tx],
    };
    while !compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or("test nonce exhausted")?;
    }
    Ok(block)
}

#[test]
fn undo_persist_failure_leaves_utxo_tip_and_tree_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = handles(Network::Regtest, Arc::clone(&utxo));
    seed_genesis(&handles)?;

    let first = mined_child(genesis.block_hash(), 1)?;
    handles.apply_block(&first, None)?;
    let applied_hash = Hash256::from(first.block_hash());
    let utxo_len = utxo.len();
    handles.undo_store = Arc::new(RejectingUndoStore {
        inner: InMemoryUndoStore::default(),
    });
    let next = mined_child(first.block_hash(), 2)?;
    let next_hash = Hash256::from(next.block_hash());

    let outcome = handles.apply_block(&next, None);
    assert!(matches!(outcome, Err(ApplyError::UndoPersistence(_))));
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_hash),
        "a failed precommit undo write must not publish a new tip"
    );
    assert_eq!(
        utxo.len(),
        utxo_len,
        "a failed undo write must not commit UTXOs"
    );
    assert!(
        handles.block_tree.read().node_by_hash(next_hash).is_none(),
        "tree preparation must not survive a failed undo write"
    );
    Ok(())
}

#[test]
fn bip30_overwrite_undo_restores_original_coin() -> Result<(), Box<dyn std::error::Error>> {
    let utxo = UtxoSet::new();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![coinbase(7)],
    };
    let reused = OutPoint::new(block.txs[0].txid(), 0);
    let older = TxOut {
        value: Amount::from_sat(4_242),
        script_pubkey: Script::from_bytes(vec![0x51]),
    };
    let mut seed = BlockChanges::default();
    seed.add(UtxoAdd::new(reused, older.clone(), true, 91_722));
    utxo.commit_block(&seed, &Hash256::from_le_bytes(&[0x30; 32]))?;

    let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let resolved = ResolvedUtxoView {
        external: HashMap::new(),
    };
    let (_changes, undo, _totals) = build_block_changes(
        &block,
        91_842,
        &txids,
        None,
        1,
        0,
        &resolved,
        Some(&utxo),
        MAX_SCRIPT_SIZE,
    )?;

    assert!(undo.removes().is_empty());
    let restored = undo
        .restores()
        .iter()
        .find(|entry| entry.outpoint == reused)
        .ok_or("undo does not restore overwritten coin")?;
    assert_eq!(restored.txout, older);
    assert_eq!(restored.height, 91_722);
    assert!(restored.coinbase);
    Ok(())
}

#[test]
fn close_requests_shutdown() {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let shutdown = handles.shutdown_handle();
    assert!(!shutdown.load(Ordering::Acquire));

    let _closed = handles.close();

    assert!(shutdown.load(Ordering::Acquire));
}

#[test]
fn direct_transition_fatal_error_closes_admission() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles)?;
    let child = mined_child(genesis.block_hash(), 1)?;
    let incompatible = DurableHead {
        commit_id: 1,
        height: 0,
        tip: Hash256::from_le_bytes(&[0x66; 32]),
        chain_tx_count: 1,
        body_extent: None,
        undo_extent: None,
    };
    let durable = Arc::new(InMemoryDurableHeadStore::new());
    durable.commit(None, &incompatible, &CommitRecords::default())?;
    handles.durable_head = durable;
    let shutdown = handles.shutdown_handle();

    let transition = handles.begin_transition()?;
    let outcome = transition.connect(&child, None);

    assert!(matches!(
        outcome,
        Err(ApplyError::DurableHeadLineage { .. })
    ));
    assert!(shutdown.load(Ordering::Acquire));
    drop(transition);
    assert!(matches!(
        handles.begin_transition(),
        Err(ApplyError::Shutdown)
    ));
    Ok(())
}

/// A disconnect off anything but the stored durable head refuses before the
/// first mutation: no rollback, no marker, admission still open.
#[test]
fn disconnect_off_durable_head_refuses_without_mutation() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = handles(Network::Regtest, Arc::clone(&utxo));
    handles.apply_block(&genesis, None)?;
    let first = mined_child(genesis.block_hash(), 1)?;
    handles.apply_block(&first, None)?;
    let first_outpoint = OutPoint::new(first.txs[0].txid(), 0);
    assert!(utxo.get(&first_outpoint).is_some());

    // The stored head no longer certifies the applied tip.
    handles.durable_head = Arc::new(InMemoryDurableHeadStore::new());

    let outcome = handles.begin_transition()?.disconnect(&first);
    let Err(crate::DisconnectError::Refused(error)) = outcome else {
        panic!("an uncertified disconnect must be refused, got {outcome:?}");
    };
    assert!(matches!(
        *error,
        ApplyError::DisconnectOffDurableHead { head: None, .. }
    ));
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(Hash256::from(first.block_hash())),
        "a refused disconnect must not move the applied tip"
    );
    assert!(
        utxo.get(&first_outpoint).is_some(),
        "a refused disconnect must not roll back the UTXO set"
    );
    assert_eq!(handles.undo_store.load_disconnect_marker()?, None);
    assert!(
        handles.begin_transition().is_ok(),
        "a refusal must leave admission open"
    );
    Ok(())
}
