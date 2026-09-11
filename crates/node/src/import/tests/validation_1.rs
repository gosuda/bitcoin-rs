use super::*;

#[test]
fn import_rejects_premature_coinbase_spend() -> Result<()> {
    let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let genesis_block = Block::consensus_decode(&genesis_bytes)?;

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let _genesis = import_block(&state, &genesis_bytes)?;

    let mut coinbase_block = genesis_block.clone();
    coinbase_block.header.prev_blockhash = genesis_block.block_hash();
    coinbase_block.header.time = coinbase_block.header.time.saturating_add(1);
    coinbase_block.txs[0].inputs[0].script_sig = Script::from_bytes(vec![1, 1]);
    coinbase_block.header.merkle_root = compute_merkle_root(&coinbase_block)
        .ok_or_else(|| anyhow::anyhow!("height-1 block should have merkle root"))?;
    mine_block_to_declared_target(&mut coinbase_block)?;
    let coinbase_bytes = encode_block(&coinbase_block);
    let _coinbase = import_block(&state, &coinbase_bytes)?;
    let immature_coinbase_txid = coinbase_block.txs[0].txid();

    let mut block = coinbase_block;
    block.header.prev_blockhash = block.block_hash();
    block.header.time = block.header.time.saturating_add(1);
    block.txs[0].inputs[0].script_sig = Script::from_bytes(vec![1, 2]);
    block.txs.push(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(immature_coinbase_txid, 0),
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

    let Err(error) = state.check_coinbase_maturity(&block, 2) else {
        anyhow::bail!("premature coinbase spend should be rejected");
    };

    assert!(
        matches!(
            error,
            crate::apply::error::ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "COINBASE_MATURITY",
                ..
            })
        ),
        "error should be COINBASE_MATURITY rejection: {error:?}"
    );
    assert_eq!(
        state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("genesis tip should remain published"))?
            .height,
        1
    );

    Ok(())
}

#[test]
fn import_rejects_block_with_no_coinbase() -> Result<()> {
    let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let mut block = Block::consensus_decode(&genesis_bytes)?;
    block.header.prev_blockhash = block.block_hash();
    block.header.time = block.header.time.saturating_add(1);
    block.txs[0].inputs[0].previous_output =
        OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0);
    let merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
    block.header.merkle_root = merkle_root;
    mine_block_to_declared_target(&mut block)?;

    let block_bytes = consensus_bytes(&block);

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let _genesis = import_block(&state, &genesis_bytes)?;

    let Err(error) = import_block(&state, &block_bytes) else {
        anyhow::bail!("block without coinbase should be rejected");
    };

    assert!(
        error.chain().any(
            |cause| cause.downcast_ref::<bitcoin_rs_consensus::ConsensusError>()
                == Some(&bitcoin_rs_consensus::ConsensusError::MissingCoinbase)
        ),
        "error chain should contain MissingCoinbase: {error:?}"
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
fn import_rejects_post_bip34_block_with_no_height_in_coinbase() -> Result<()> {
    let genesis_bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let mut block = Block::consensus_decode(&genesis_bytes)?;

    let dir = tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let synthetic_tip = seed_synthetic_header_tip(&state, 499)?;

    block.header.prev_blockhash = BlockHash(synthetic_tip.hash);
    block.txs[0].inputs[0].script_sig = Script::from_bytes(Vec::new());
    block.header.merkle_root = compute_merkle_root(&block)
        .ok_or_else(|| anyhow::anyhow!("mutated block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;

    let block_bytes = consensus_bytes(&block);

    let Err(error) = import_block(&state, &block_bytes) else {
        anyhow::bail!("post-BIP34 block without height should be rejected");
    };

    assert!(
        error.chain().any(|cause| matches!(
            cause.downcast_ref::<bitcoin_rs_consensus::ConsensusError>(),
            Some(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP34", .. })
        )),
        "error chain should contain BIP34 rejection: {error:?}"
    );
    assert_eq!(
        state
            .chain_tip()
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("synthetic tip should remain published"))?
            .height,
        synthetic_tip.height
    );
    Ok(())
}
