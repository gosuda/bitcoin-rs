use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::chain::ActiveTipWait as _;

use crate::chain::regtest_fixture::{coinbase, mined_regtest_child_at as mined_child};
use bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
use bitcoin_rs_consensus::primitives::{
    AssumeUtxoData, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, Network,
    OutPoint, Tx,
};
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::contract::{BlockChangeInputs, build_block_changes};
use bitcoin_rs_storage::{CommitRecords, DurableHead, InMemoryDurableHeadStore, PersistFault};

use hashbrown::HashMap;

use super::{ApplyError, AssumeUtxoError, ResolvedUtxoView};
use crate::test_fixtures::{TestError, TestResult, handles, handles_with_store, seed_genesis};

#[test]
fn canonical_regtest_chain_connects_through_bip34_activation() -> TestResult {
    let network = Network::Regtest;
    let handles = handles(network, Arc::new(UtxoSet::new()));
    let genesis = network.genesis_block();
    handles.apply_block(&BlockImage::from_local(genesis.clone()))?;
    let mut parent = genesis.block_hash();
    for height in 1..=500 {
        let block = mined_child(parent, height)?;
        let outcome = handles.apply_block(&BlockImage::from_local(block.clone()))?;
        assert_eq!(outcome.tip.height, height);
        assert_eq!(outcome.hash, Hash256::from(block.block_hash()));
        assert_eq!(
            outcome.tip.chain_tx_count,
            crate::chain::ChainTxCount::established(u64::from(height) + 1)
        );
        parent = block.block_hash();
    }
    Ok(())
}

// ARCH-09, RCV-04
#[test]
fn undo_persist_failure_leaves_utxo_tip_and_tree_untouched() -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = handles(Network::Regtest, Arc::clone(&utxo));
    seed_genesis(&handles)?;

    let first = mined_child(genesis.block_hash(), 1)?;
    handles.apply_block(&BlockImage::from_local(first.clone()))?;
    let applied_hash = Hash256::from(first.block_hash());
    let utxo_len = utxo.len();
    handles
        .commit_authority
        .store()
        .arm_persist_fault(PersistFault::FailApply);
    let next = mined_child(first.block_hash(), 2)?;
    let next_hash = Hash256::from(next.block_hash());

    let observer = handles.clone();
    let stop = bitcoin_rs_consensus::latch::LatchWriter::new();
    let cancellation = stop.reader();
    let (answer_tx, answer_rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        answer_tx.send(observer.wait_for_tip(
            crate::chain::TipWaitCondition::Changed(Some(applied_hash)),
            None,
            &cancellation,
        ))
    });
    let registration_deadline = Instant::now() + Duration::from_secs(2);
    while handles.tip_notification.changed.notify_all() == 0 {
        assert!(Instant::now() < registration_deadline, "waiter must park");
        std::thread::yield_now();
    }
    let outcome = handles.apply_block(&BlockImage::from_local(next.clone()));
    let pending = answer_rx.recv_timeout(Duration::from_millis(30));
    let remained_pending = matches!(pending, Err(mpsc::RecvTimeoutError::Timeout));
    stop.trigger();
    handles.wake_waiters();
    let observed = match pending {
        Ok(answer) => answer,
        Err(_) => answer_rx.recv_timeout(Duration::from_secs(2))?,
    };
    waiter
        .join()
        .map_err(|_| TestError::WorkerPanicked("tip observer"))?
        .map_err(|_| TestError::Exhausted("waiter send"))?;
    assert!(matches!(outcome, Err(ApplyError::DurableHeadCommit(_))));
    assert!(
        !remained_pending,
        "an unrecoverable undo failure closes admission and the shutdown wake releases the waiter"
    );
    assert_eq!(observed.map(|tip| tip.hash), Some(applied_hash));
    assert!(
        handles.is_closed_for_recovery(),
        "undo persistence is unrecoverable in-process, so the transition fails closed"
    );
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_hash),
        "a failed durable commit must not publish a new tip"
    );
    assert_eq!(
        utxo.len(),
        utxo_len,
        "a failed durable commit must not commit UTXOs"
    );
    assert!(
        handles
            .utxo_reader()
            .get(&OutPoint::new(next.txs[0].txid(), 0))?
            .is_none(),
        "a failed durable commit must not commit coin rows"
    );
    if let Some(node) = handles.block_tree.read().node_by_hash(next_hash) {
        assert!(
            matches!(
                node.status,
                crate::chain::NodeStatus::Active | crate::chain::NodeStatus::HeaderValid
            ),
            "header may exist in the tree after a failed commit, but the block itself is never published"
        );
    }
    Ok(())
}

// RCV-08
#[test]
fn bip30_overwrite_undo_removes_the_overwritten_coin() -> TestResult {
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
    let out = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 0,
        value: 4_242,
        script_pubkey: vec![0x51],
        coinbase: true,
        height: 91_722,
    };
    let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
        Hash256::from(reused.txid),
        &[out],
    )?;
    utxo.insert_parsed_record(record);

    let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let resolved = ResolvedUtxoView {
        external: HashMap::new(),
        _hold: None,
    };
    let (_changes, undo, _totals) = build_block_changes(
        &BlockChangeInputs {
            block: &BlockImage::from_local(block.clone()),
            height: 91_842,
            txids: &txids,
            same_block_spent: None,
            add_capacity: 1,
            remove_capacity: 0,
            max_script_size: MAX_SCRIPT_SIZE,
        },
        &resolved,
    )?;

    assert_eq!(undo.removes(), [reused]);
    assert!(undo.restores().iter().all(|entry| entry.outpoint != reused));
    Ok(())
}

#[test]
fn close_requests_shutdown() {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let shutdown = handles.shutdown_reader();
    assert!(!shutdown.is_triggered());

    let _closed = handles.close();

    assert!(shutdown.is_triggered());
}

#[test]
fn direct_transition_fatal_error_closes_admission() -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    let mut handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles)?;
    let child = mined_child(genesis.block_hash(), 1)?;
    let incompatible = DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
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
    let shutdown = handles.shutdown_reader();

    let transition = handles.begin_transition()?;
    let outcome = transition.connect(&BlockImage::from_local(child));

    assert!(matches!(
        outcome,
        Err(ApplyError::DurableHeadLineage { .. })
    ));
    assert!(shutdown.is_triggered());
    drop(transition);
    assert!(matches!(
        handles.begin_transition(),
        Err(ApplyError::Shutdown)
    ));
    Ok(())
}

// RCV-08
#[test]
fn disconnect_off_durable_head_refuses_without_mutation() -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = handles(Network::Regtest, Arc::clone(&utxo));
    handles.apply_block(&BlockImage::from_local(genesis.clone()))?;
    let first = mined_child(genesis.block_hash(), 1)?;
    handles.apply_block(&BlockImage::from_local(first.clone()))?;
    let first_outpoint = OutPoint::new(first.txs[0].txid(), 0);
    assert!(handles.utxo_reader().get(&first_outpoint)?.is_some());

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
        handles.utxo_reader().get(&first_outpoint)?.is_some(),
        "a refused disconnect must not roll back the UTXO set"
    );
    assert_eq!(handles.undo_store.load_disconnect_marker()?, None);
    assert!(
        handles.begin_transition().is_ok(),
        "a refusal must leave admission open"
    );
    Ok(())
}

// RCV-02
#[test]
fn use_after_close_refuses_operations() {
    let utxo = Arc::new(UtxoSet::new());
    let handles = handles(Network::Regtest, utxo);
    assert!(!handles.is_closed_for_recovery());
    handles.fail_closed_for_recovery();
    assert!(handles.is_closed_for_recovery());

    assert!(matches!(
        handles.begin_transition(),
        Err(ApplyError::Shutdown)
    ));
    let genesis = Network::Regtest.genesis_block();
    let outcome = handles.apply_block(&BlockImage::from_local(genesis));
    assert!(matches!(outcome, Err(ApplyError::Shutdown)));
}

// RCV-09, RCV-11
#[test]
fn current_schema_version_mismatch_and_corruption_refuses_open() -> TestResult {
    use bitcoin_rs_storage::checkpoint::{
        CURRENT_SCHEMA_FILE, ensure_current_schema, open_data_dir,
    };
    let temp = tempfile::tempdir()?;
    let dir = open_data_dir(temp.path())?;

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"1\n")?;
    let result = ensure_current_schema(&dir);
    assert!(
        matches!(
            &result,
            Err(err) if err.kind() == std::io::ErrorKind::InvalidData
        ),
        "wrong schema epoch must be invalid data: {result:?}"
    );

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"0\n")?;
    assert!(ensure_current_schema(&dir).is_err());

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"2\n")?;
    assert!(ensure_current_schema(&dir).is_err());

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"corrupt\n")?;
    assert!(ensure_current_schema(&dir).is_err());

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"3\n")?;
    assert!(ensure_current_schema(&dir).is_err());

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"4\n")?;
    assert!(ensure_current_schema(&dir).is_err());

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"5\n")?;
    assert!(ensure_current_schema(&dir).is_err());

    std::fs::write(temp.path().join(CURRENT_SCHEMA_FILE), b"6\n")?;
    assert!(ensure_current_schema(&dir).is_ok());
    Ok(())
}

#[test]
fn fresh_node_rejected_snapshot_ingest_clears_marker_and_preserves_later_coins() -> TestResult {
    let network = Network::Regtest;
    let genesis = network.genesis_block();
    let genesis_header = genesis.header;
    let store = Arc::new(bitcoin_rs_storage::memory_kv::MemoryKvStore::new());
    let utxo = Arc::new(UtxoSet::new());
    let chain = handles_with_store(network, utxo, Arc::clone(&store));

    crate::chain::accept_headers(
        &mut chain.block_tree.write(),
        core::slice::from_ref(&genesis_header),
        network,
        crate::chain::current_unix_seconds(),
        crate::chain::HeaderValidationMode::LiveAdmission,
    )?;

    let pinned = AssumeUtxoData {
        height: 0,
        block_hash: Hash256::from(genesis.block_hash()),
        hash_serialized: Hash256::from_le_bytes(&[0x11; 32]),
        chain_tx_count: 1,
        index_commitments: [None; 4],
    };

    let outcome = chain.install_snapshot(
        &pinned,
        0,
        |_coins| {
            Err(AssumeUtxoError::SnapshotCommitmentMismatch {
                expected: pinned.hash_serialized,
                found: Hash256::from_le_bytes(&[0x22; 32]),
            })
        },
        |_coins, _tree, _tip, _prior, _marker, _streamed| Ok(()),
    );

    assert!(matches!(
        outcome,
        Err(AssumeUtxoError::SnapshotCommitmentMismatch { .. })
    ));
    assert!(
        chain
            .commit_authority
            .in_flight_snapshot_activation()?
            .is_none()
    );
    assert!(!chain.is_closed_for_recovery());
    assert!(chain.begin_transition().is_ok());

    chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
    let first = mined_child(genesis.block_hash(), 1)?;
    chain.apply_block(&BlockImage::from_local(first.clone()))?;
    let first_outpoint = OutPoint::new(first.txs[0].txid(), 0);
    assert!(chain.utxo_reader().get(&first_outpoint)?.is_some());

    let store: Arc<dyn bitcoin_rs_storage::KvStore> = store;
    let coins_reopened = Arc::new(bitcoin_rs_storage::CoinStore::open(
        Arc::clone(&store),
        64 * 1024 * 1024,
    ));
    let authority_reopened =
        bitcoin_rs_storage::CommitAuthority::new(store, Arc::clone(&coins_reopened));
    assert!(
        matches!(authority_reopened.recover_snapshot_activation(), Ok(None)),
        "no leftover marker must be recovered on restart"
    );
    let first_txid_le = first.txs[0].txid().0.to_le_bytes();
    let first_key = bitcoin_rs_storage::CoinKey(first_txid_le);
    let Some(encoded) = coins_reopened.get(&first_key)? else {
        return Err(TestError::Missing(
            "coin committed after rejected ingest must survive restart/recovery",
        ));
    };
    let record =
        bitcoin_rs_storage::utxo::UtxoRecord::from_encoded(encoded.to_vec().into_boxed_slice())?;
    assert_eq!(
        record.txid().to_le_bytes(),
        first_txid_le,
        "recovered coin row must carry the committed coinbase txid"
    );
    let expected = &first.txs[0].outputs[0];
    let mut saw_vout_zero = false;
    for output in record.outputs() {
        if output.vout != 0 {
            continue;
        }
        saw_vout_zero = true;
        assert_eq!(
            output.value,
            expected.value.to_sat(),
            "recovered coin value must match the committed block output"
        );
        assert_eq!(
            output.script_pubkey,
            expected.script_pubkey.as_bytes(),
            "recovered coin script must match the committed block output"
        );
        assert!(
            output.coinbase,
            "recovered coin must be the height-1 coinbase output"
        );
        assert_eq!(
            output.height, 1,
            "recovered coin must have creation height 1"
        );
    }
    assert!(
        saw_vout_zero,
        "recovered coin record must contain the block's output 0"
    );

    Ok(())
}
