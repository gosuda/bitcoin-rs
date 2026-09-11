use super::*;

#[test]
fn writer_refuses_a_best_tip_that_is_not_active() -> Result<(), Box<dyn std::error::Error>> {
    let (tree, _, applied) = chain_with_applied_height(3, 1)?;

    assert!(matches!(
        headers::write_headers(&mut Vec::new(), &tree, config(), NodeId::new(0), applied),
        Err(headers::HeaderCheckpointError::BestTipNotActive)
    ));
    Ok(())
}

#[test]
fn writer_refuses_an_applied_tip_off_the_active_best_ancestry()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut tree, best_tip_id, _) = chain_with_applied_height(3, 1)?;
    let genesis_hash = tree.node(NodeId::new(0))?.hash;
    let mut fork = next_header(
        BlockHash(genesis_hash),
        u32::from(NETWORK.genesis_block_hash().to_le_bytes()[0]) + 1,
    );
    mine_header_to_declared_target(&mut fork)?;
    let fork_id = accept_headers(
        &mut tree,
        core::slice::from_ref(&fork),
        NETWORK,
        bitcoin_rs_chain::current_unix_seconds(),
    )?[0];
    let fork = tree.node(fork_id)?;
    let applied = headers::HeaderCheckpointPoint {
        height: fork.height,
        hash: fork.hash,
    };

    assert!(matches!(
        headers::write_headers(&mut Vec::new(), &tree, config(), best_tip_id, applied),
        Err(headers::HeaderCheckpointError::AppliedTipNotBestPrefix)
    ));
    Ok(())
}

#[test]
fn immutable_generation_resumes_best_ahead_of_applied() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(3, 1)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let mut stats = CoinStats::new();
    stats.height = applied.height;
    let listener = CoinStatsListener::new(stats);

    assert!(matches!(
        super::super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &utxo,
            &listener,
            Some(&applied_tip),
        )?,
        CheckpointWrite::Published { .. }
    ));
    let loaded = load_checkpoint(dir.path(), config())?;
    let CheckpointLoad::Complete(restored) = loaded else {
        return Err("checkpoint did not restore complete chainstate".into());
    };
    assert_eq!(restored.tree.tip().map(|tip| tip.height), Some(3));
    assert_eq!(restored.applied_tip.height, 1);
    assert_eq!(restored.applied_tip.hash, applied.hash);
    assert_eq!(restored.utxo.record_count(), 0);
    assert_eq!(restored.coin_stats.height, 1);
    Ok(())
}

#[test]
fn no_applied_tip_skips_without_changing_current() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let tree = RwLock::new(tree);
    let utxo = UtxoSet::new();
    let listener = CoinStatsListener::new(CoinStats::new());
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &tree,
        &utxo,
        &listener,
        Some(&applied_tip),
    )?;
    let current_path = dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE);
    let before = fs::read(&current_path)?;
    assert_eq!(
        super::super::write_checkpoint(dir.path(), config(), &tree, &utxo, &listener, None)?,
        CheckpointWrite::SkippedNoAppliedTip
    );
    assert_eq!(fs::read(current_path)?, before);
    Ok(())
}

#[test]
fn authenticated_header_tip_and_commitment_mutations_require_resync()
-> Result<(), Box<dyn std::error::Error>> {
    for case in 0..4 {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(2, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        super::super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(CoinStats::new()),
            Some(&applied_tip),
        )?;
        mutate_authenticated_manifest(dir.path(), |manifest| match case {
            0 => manifest.best_header_tip.hash = "00".repeat(32),
            1 => manifest.applied_tip.hash = "00".repeat(32),
            2 => manifest.headers.best_chain_sha256 = "00".repeat(32),
            _ => manifest.headers.applied_chain_sha256 = "00".repeat(32),
        })?;
        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("corrupt checkpoint unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
    }
    Ok(())
}
