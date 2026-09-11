use super::*;

#[test]
fn import_decodes_a_well_formed_block() -> Result<()> {
    let bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let block = Block::consensus_decode(&bytes)?;
    let genesis_hash = block.block_hash().0;

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = true;
    let mut state = NodeState::open(config, None)?;
    state.start_index_workers()?;
    let outcome = import_block(&state, &bytes)?;

    assert_eq!(outcome.tx_count, 1, "genesis has one transaction");
    assert!(outcome.applied, "decoded block must be applied");
    let tip = state
        .chain_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("missing chain tip after import"))?;
    assert_eq!(tip.height, 0);
    assert_eq!(tip.hash, genesis_hash);
    assert!(
        state.applied_tip().load_full().is_some(),
        "applied_tip published after import_block"
    );
    assert_eq!(
        state.utxo().len(),
        0,
        "genesis coinbase is unspendable and absent from live UTXO state"
    );
    assert!(
        state.transactions().read().is_empty(),
        "confirmed transaction cache must stay empty"
    );
    let coinbase = block
        .txs
        .first()
        .ok_or_else(|| anyhow::anyhow!("genesis block has no transactions"))?;
    let txid = coinbase.txid();
    let tx_index = state
        .tx_index_query()
        .ok_or_else(|| anyhow::anyhow!("txindex missing after enabled open"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tx_index.index_info() {
            Ok(info) if info.synced => break,
            Ok(_)
            | Err(
                bitcoin_rs_rpc::context::TxQueryError::Retry
                | bitcoin_rs_rpc::context::TxQueryError::Unavailable(_),
            ) => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            anyhow::bail!("txindex did not catch up after import");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let resolved = tx_index.transaction(&txid)?;
    assert_eq!(
        resolved.as_ref().map(Tx::txid),
        Some(txid),
        "genesis coinbase must resolve through txindex"
    );
    assert!(
        state.mempool().read().is_empty(),
        "genesis import must leave mempool empty"
    );
    Ok(())
}

#[test]
fn import_rejects_block_whose_hash_exceeds_declared_target() -> Result<()> {
    let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let mut block = Block::consensus_decode(&genesis_bytes)?;
    block.header.prev_blockhash = block.block_hash();
    block.header.time = block.header.time.saturating_add(1);
    block.header.bits = CompactTarget::from_consensus(0x0010_0001);

    let block_bytes = consensus_bytes(&block);

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let _genesis = import_block(&state, &genesis_bytes)?;

    let Err(error) = import_block(&state, &block_bytes) else {
        anyhow::bail!("block whose hash exceeds declared target should be rejected");
    };

    assert!(
        error.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<crate::apply::error::ApplyError>(),
                Some(crate::apply::error::ApplyError::ProofOfWork { .. })
            )
        }),
        "error chain should contain ProofOfWork rejection: {error:?}"
    );

    assert_eq!(
        state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
            .height,
        0,
        "rejected block must not advance chain tip"
    );
    Ok(())
}

#[test]
fn import_rejects_block_with_target_above_network_limit() -> Result<()> {
    let genesis_block = crate::Network::Mainnet.genesis_block();
    let genesis_bytes = encode_block(&genesis_block);
    let mut block = genesis_block.clone();
    block.header.prev_blockhash = genesis_block.block_hash();
    block.header.time = block.header.time.saturating_add(1);
    block.header.bits = CompactTarget::from_consensus(0x207f_ffff);
    block.txs[0].inputs[0].script_sig = Script::from_bytes(vec![1, 1]);
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    let block_bytes = encode_block(&block);

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Mainnet);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let _genesis = import_block(&state, &genesis_bytes)?;

    let Err(error) = import_block(&state, &block_bytes) else {
        anyhow::bail!("child block target exceeds mainnet PoW limit");
    };

    assert!(
        error.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<crate::apply::error::ApplyError>(),
                Some(crate::apply::error::ApplyError::TargetAboveLimit)
            )
        }),
        "error chain should contain TargetAboveLimit rejection: {error:?}"
    );
    assert_eq!(
        state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
            .height,
        0,
        "rejected block must not advance chain tip"
    );
    Ok(())
}

#[test]
fn import_rejects_non_retarget_child_with_changed_nbits() -> Result<()> {
    let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let mut block = Block::consensus_decode(&genesis_bytes)?;
    block.header.prev_blockhash = block.block_hash();
    block.header.time = block.header.time.saturating_add(1);
    block.header.bits = CompactTarget::from_consensus(0x207e_ffff);
    block.txs[0].inputs[0].script_sig = Script::from_bytes(vec![1, 1]);
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    let block_bytes = encode_block(&block);

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let _genesis = import_block(&state, &genesis_bytes)?;

    let Err(error) = import_block(&state, &block_bytes) else {
        anyhow::bail!("non-retarget child with changed nBits should be rejected");
    };

    assert!(
        error.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<crate::apply::error::ApplyError>(),
                Some(crate::apply::error::ApplyError::NbitsNonRetargetMismatch {
                    actual: 0x207e_ffff,
                    expected: 0x207f_ffff,
                    height: 1,
                })
            )
        }),
        "error chain should contain nBits mismatch rejection: {error:?}"
    );
    assert_eq!(
        state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
            .height,
        0,
        "rejected nBits mismatch must not advance chain tip"
    );
    Ok(())
}

#[test]
fn two_block_import_grows_block_tree_to_two_headers() -> Result<()> {
    let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let mut follow_up = Block::consensus_decode(&genesis_bytes)?;
    follow_up.header.prev_blockhash = follow_up.block_hash();
    follow_up.header.time = follow_up.header.time.saturating_add(1);
    follow_up.txs[0].inputs[0].script_sig = Script::from_bytes(vec![1, 1]);
    follow_up.header.merkle_root = compute_merkle_root(&follow_up)
        .ok_or_else(|| anyhow::anyhow!("follow-up block should have merkle root"))?;
    mine_block_to_declared_target(&mut follow_up)?;

    let follow_up_bytes = consensus_bytes(&follow_up);

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;

    let _genesis = import_block(&state, &genesis_bytes)?;
    let _follow_up = import_block(&state, &follow_up_bytes)?;

    assert_eq!(state.block_tree().read().len(), 2);
    Ok(())
}

#[test]
fn import_rejects_block_with_unspendable_input_tx() -> Result<()> {
    let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let mut block = Block::consensus_decode(&genesis_bytes)?;
    block.header.prev_blockhash = block.block_hash();
    block.header.time = block.header.time.saturating_add(1);
    block.txs[0].inputs[0].script_sig = Script::from_bytes(vec![1, 1]);
    block.txs.push(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0_u8; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    });
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;

    let block_bytes = consensus_bytes(&block);

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;

    let _genesis = import_block(&state, &genesis_bytes)?;
    let Err(error) = import_block(&state, &block_bytes) else {
        anyhow::bail!("block with missing prevout should be rejected");
    };

    assert!(
        error.chain().any(|cause| matches!(
            cause.downcast_ref::<bitcoin_rs_consensus::ConsensusError>(),
            Some(bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 })
        )),
        "error chain should contain MissingPrevout: {error:?}"
    );
    assert_eq!(
        state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
            .height,
        0
    );
    Ok(())
}
