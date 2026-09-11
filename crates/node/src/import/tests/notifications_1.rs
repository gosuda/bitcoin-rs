use super::*;

#[test]
fn import_two_blocks_in_sequence_advances_height_to_one() -> Result<()> {
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

    let tip = state
        .chain_tip()
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("missing chain tip after second import"))?;
    assert_eq!(tip.height, 1);
    Ok(())
}
