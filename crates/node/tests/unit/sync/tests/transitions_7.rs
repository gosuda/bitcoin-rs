use super::*;

#[test]
fn mutated_connect_body_through_switch_to_branch_preserves_subtree()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (handles, main, mut bodies) = matured_chain(101)?;
    // Build a competing fork rooted at block 50. The first fork block has a
    // corrupted body (coinbase value changed → txid changed → merkle root
    // mismatch), so the connect stops on the first body. The descendant
    // header must remain eligible for a later delivery of the correct body.
    let fork_root_hash = main[49].block_hash();
    let mut tree = handles.block_tree().write();
    let mut fork_parent = tree
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork_blocks = Vec::new();
    for height in 51..=52_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
        fork_prev = block.block_hash();
        fork_blocks.push(block);
    }
    let fork_target = fork_parent;
    let invalid_id = tree
        .lookup(Hash256::from_le_bytes(
            fork_blocks[0].block_hash().as_bytes(),
        ))
        .ok_or_else(|| std::io::Error::other("missing invalid fork node"))?;
    let descendant_id = tree
        .lookup(Hash256::from_le_bytes(
            fork_blocks[1].block_hash().as_bytes(),
        ))
        .ok_or_else(|| std::io::Error::other("missing descendant fork node"))?;
    drop(tree);

    // Corrupt the first fork block's body: change the coinbase value so
    // the txid no longer matches the header's merkle root. This is a
    // body mutation (MerkleRoot), which must not invalidate the subtree.
    let mut corrupt = fork_blocks[0].clone();
    corrupt.txs[0].outputs[0].value = Amount::from_sat(2);
    fork_blocks[0] = corrupt;
    for block in &fork_blocks {
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
        );
    }

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );

    let Err(crate::reorg::ReorgError::ConnectFailed {
        disconnected,
        connected,
        disposition,
        invalidated,
        ..
    }) = outcome
    else {
        panic!("mutated connect body must return ConnectFailed");
    };
    assert_eq!(
        disconnected, 51,
        "the full disconnect prefix must be reported"
    );
    assert_eq!(connected, 0, "nothing connected before the body mutation");
    assert_eq!(
        disposition,
        bitcoin_rs_chainstate::WindowApplyDisposition::BodyMutated
    );
    assert!(
        invalidated.is_empty(),
        "body mutation cannot poison headers"
    );
    // Both headers remain valid and may be retried with another body.
    {
        let tree = handles.block_tree().read();
        assert_eq!(tree.node(invalid_id)?.status, NodeStatus::HeaderValid);
        assert_eq!(tree.node(descendant_id)?.status, NodeStatus::HeaderValid);
    }
    // The applied tip must be back at the fork root (block 50), the
    // successful disconnect prefix.
    let fork_root_id_hash = Hash256::from_le_bytes(fork_root_hash.as_bytes());
    assert_eq!(
        handles.applied_tip().load_full().map(|tip| tip.hash),
        Some(fork_root_id_hash),
        "the applied tip must be the fork root after disconnecting back to it"
    );
    Ok(())
}

/// A disconnected package re-enters the pool through the shared evaluator in
/// dependency order while the tip is fenced; a member made nonfinal by the
/// lower tip is refused, and the published mutation stream stays one ordered
/// Reorg sequence.
#[test]
#[allow(clippy::too_many_lines)]
fn disconnect_readmits_the_package_in_order_and_drops_the_nonfinal_member()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash as _, hash160};
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolGateway, MempoolLimits, MempoolObserver, MutationEnvelope,
    };
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, TxIn, TxOut, Witness};
    use bitcoin_rs_storage::StorageError;
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use parking_lot::Mutex;

    #[derive(Default)]
    struct Stream(Mutex<Vec<(Txid, bitcoin_rs_mempool::MutationOutcome, AdmissionOrigin)>>);

    impl MempoolObserver for Stream {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let mut seen = self.0.lock();
            for change in &envelope.result.changes {
                seen.push((Txid::from(change.txid), change.outcome, envelope.origin));
            }
        }
    }

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

        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.bodies.lock().get(&(height, hash)).cloned())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    let stream = Arc::new(Stream::default());
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some(stream.clone()),
    ));
    let followers = crate::chain_effects::ChainFollowers::new(
        crate::chain_effects::ChainEffects::noop(),
        Arc::new(crate::mining::MiningGenerationSignal::new()),
        Some(Arc::clone(&gateway)),
    );

    // A spendable coinbase output with an empty script: a bare `push 1`
    // scriptSig satisfies it. Children spend standard P2SH outputs whose
    // redeem script is a bare OP_TRUE.
    let redeem: Vec<u8> = vec![0x51];
    let p2sh = Script::from_bytes(
        [
            vec![0xa9, 0x14],
            hash160::Hash::hash(&redeem).to_byte_array().to_vec(),
            vec![0x87],
        ]
        .concat(),
    );
    let redeem_sig = Script::from_bytes(bitcoin_rs_script::push_data(&redeem));

    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut parent_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let mut prev_hash = genesis.block_hash();
    let mut blocks: Vec<Block> = Vec::new();
    let subsidy = 5_000_000_000_u64;
    let mut parent_tx: Option<Tx> = None;
    for height in 1..=101_u32 {
        let mut coinbase = coinbase_transaction(height);
        if height == 1 {
            coinbase.outputs[0].value = Amount::from_sat(subsidy);
        }
        let mut txs = vec![coinbase];
        if height == 101 {
            let first_txid = blocks[0].txs[0].txid();
            let parent = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(first_txid, 0),
                    script_sig: Script::from_bytes(push_int(1)),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::new(),
                }],
                outputs: vec![
                    TxOut {
                        value: Amount::from_sat(2_000_000_000),
                        script_pubkey: p2sh.clone(),
                    },
                    TxOut {
                        value: Amount::from_sat(2_900_000_000),
                        script_pubkey: p2sh.clone(),
                    },
                ],
                lock_time: LockTime::from_consensus(0),
            };
            let child = Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent.txid(), 0),
                    script_sig: redeem_sig.clone(),
                    sequence: Sequence::from_consensus(u32::MAX),
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(1_900_000_000),
                    script_pubkey: p2sh.clone(),
                }],
                lock_time: LockTime::from_consensus(0),
            };
            txs.push(parent.clone());
            txs.push(child);
            parent_tx = Some(parent.clone());
        }
        let block = mined_block_with_prev_hash(prev_hash, height, txs);
        parent_id = tree.insert_node(Some(parent_id), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    // A durable body store lets the reorg revisit the disconnected package
    // body for re-admission; connect persists each applied body into it.
    let handles =
        bitcoin_rs_chainstate::Chainstate::from_parts(bitcoin_rs_chainstate::ChainstateParts {
            network: Network::Regtest,
            chain_tip: tree.tip_handle(),
            applied_tip: Arc::new(ArcSwapOption::empty()),
            block_tree: Arc::new(RwLock::new(tree)),
            utxo: Arc::new(UtxoSet::new()),
            coin_stats: Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
                bitcoin_rs_utxo::stats::CoinStats::default(),
            )),
            chain_events: Arc::new(bitcoin_rs_chainstate::events::ChainEventPublisher::detached(0)),
            block_body_store: Some(Arc::new(Bodies::default())),
            undo_store: Arc::new(bitcoin_rs_storage::undo::InMemoryUndoStore::default()),
            durable_head: Arc::new(bitcoin_rs_storage::InMemoryDurableHeadStore::new()),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            assume_valid_height: 0,
            validation_mode: bitcoin_rs_chainstate::ValidationMode::AssumeValid,
            journal: None,
            capture_rawtx: false,
            capture_block_bytes: true,
        });
    handles.apply_block(&genesis, None)?;
    for block in &blocks {
        handles.apply_block(block, None)?;
    }

    let parent = parent_tx.ok_or_else(|| std::io::Error::other("package not built"))?;
    let tip = &blocks[100];
    let child_txid = tip.txs[2].txid();

    // A resident entry admitted while the tip is block 101 (next-height MTP
    // T+96) but nonfinal once the tip drops to block 100 (MTP T+95).
    let nonfinal = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent.txid(), 1),
            script_sig: redeem_sig,
            sequence: Sequence::from_consensus(0xffff_fffe),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(2_800_000_000),
            script_pubkey: p2sh,
        }],
        lock_time: LockTime::from_consensus(GENESIS_TIME + 95),
    };
    let nonfinal_txid = nonfinal.txid();
    let view = bitcoin_rs_rpc::context::ChainAdmissionView::new(
        handles.utxo(),
        handles.applied_tip(),
        handles.block_tree(),
        handles.network(),
    );
    let submitted = gateway.submit_transaction(
        Arc::new(nonfinal),
        bitcoin_rs_mempool::AdmissionOrigin::Rpc,
        None,
        1,
        &view,
    );
    assert!(
        submitted.is_ok(),
        "the resident fixture must be admitted before the disconnect, got {submitted:?}"
    );
    assert!(gateway.read().contains_txid(&nonfinal_txid));

    let invalidated = crate::reorg::invalidate_block(
        &handles,
        &followers,
        Hash256::from_le_bytes(tip.block_hash().as_bytes()),
    )
    .map_err(|error| std::io::Error::other(format!("invalidate failed: {error:?}")))?;
    assert_eq!(
        *invalidated.first().ok_or("nothing invalidated")?,
        Hash256::from_le_bytes(tip.block_hash().as_bytes())
    );
    assert_eq!(
        handles.applied_tip().load_full().map(|tip| tip.height),
        Some(100)
    );

    let pool = gateway.read();
    assert!(pool.contains_txid(&parent.txid()));
    assert!(pool.contains_txid(&child_txid));
    assert!(
        !pool.contains_txid(&nonfinal_txid),
        "the resident entry made nonfinal by the lower tip must be swept"
    );
    drop(pool);
    let seen = stream.0.lock().clone();
    let reorg: Vec<(Txid, bitcoin_rs_mempool::MutationOutcome)> = seen
        .iter()
        .filter(|(_, _, origin)| *origin == AdmissionOrigin::Reorg)
        .map(|(txid, outcome, _)| (*txid, *outcome))
        .collect();
    assert_eq!(
        reorg,
        vec![
            (parent.txid(), bitcoin_rs_mempool::MutationOutcome::Accepted),
            (child_txid, bitcoin_rs_mempool::MutationOutcome::Accepted),
            (
                nonfinal_txid,
                bitcoin_rs_mempool::MutationOutcome::Removed(
                    bitcoin_rs_mempool::RemovalReason::Reorg,
                ),
            ),
        ],
        "one ordered stream: dependency-ordered re-admission, then the sweep"
    );
    Ok(())
}
