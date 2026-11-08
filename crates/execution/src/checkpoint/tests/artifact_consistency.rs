use super::*;

#[test]
fn checkpoint_transaction_counts_must_agree_when_known() -> TestResult {
    for chain_tx_count in [0, 1] {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        let applied_tip = crate::chain::TipSnapshot {
            chain_tx_count: crate::chain::ChainTxCount::from_wire(chain_tx_count),
            ..applied_tip
        };
        let mut stats = CoinStats::new();
        stats.finish_block(0, 1);
        super::super::write_checkpoint(
            dir.path(),
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(stats),
            Some(&applied_tip),
        )?;
        let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
            return Err(TestError::UnexpectedSuccess(
                "valid checkpoint did not load",
            ));
        };
        assert_eq!(
            restored.applied_tip.chain_tx_count.to_wire(),
            chain_tx_count
        );
        assert_eq!(restored.coin_stats.tx_count, 1);

        mutate_authenticated_manifest(dir.path(), |manifest| {
            manifest.applied_tip.chain_tx_count = 2;
        })?;
        let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
            return Err(TestError::UnexpectedSuccess(
                "inconsistent authenticated transaction counts were restored",
            ));
        };
    }
    Ok(())
}

#[test]
fn checkpoint_writer_refuses_inconsistent_transaction_counts() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let applied_tip = crate::chain::TipSnapshot {
        chain_tx_count: crate::chain::ChainTxCount::established(2),
        ..applied_tip
    };
    let result = super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    );
    let Err(_) = result else {
        return Err(TestError::UnexpectedSuccess(
            "inconsistent transaction counts were published",
        ));
    };
    assert!(!dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
    Ok(())
}
#[test]
fn checkpoint_writer_refuses_height_mismatch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let mut stats = CoinStats::new();
    stats.finish_block(1, 0);
    let result = super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(stats),
        Some(&applied_tip),
    );
    let Err(_) = result else {
        return Err(TestError::UnexpectedSuccess(
            "stale CoinStats unexpectedly published",
        ));
    };
    assert!(!dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
    Ok(())
}

#[test]
fn authenticated_header_semantics_require_resync() -> TestResult {
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
    mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
        bytes[headers::HEADER_PREFIX_LEN + 80 + 4] ^= 1;
    })?;

    let Err(CheckpointLoadError::Corrupt(_)) = load_checkpoint(dir.path(), config()) else {
        return Err(TestError::UnexpectedSuccess(
            "corrupt header checkpoint unexpectedly loaded",
        ));
    };
    Ok(())
}

/// The offsets below are the checkpoint envelope (16 bytes) followed by the stable
/// `CoinStats::to_bytes` layout defined in `crates/storage/src/utxo/stats/coin_stats.rs`:
/// `MuHash` numerator/denominator, then height, total amount, bogo size, transaction
/// count, and UTXO count.
///
/// The `full resync` assertion is the checkpoint recovery contract documented in
/// `docs/policies/db-migration.md` and exercised by the loader.
#[test]
fn authenticated_coinstats_semantics_require_resync() -> TestResult {
    const COINSTATS_ENVELOPE_BYTES: usize = 16;
    const MUHASH_BYTES: usize = 384 + 384;
    const HEIGHT_BYTES: usize = 4;
    const U64_BYTES: usize = 8;
    const COINSTATS_FIELD_OFFSETS: [usize; 6] = [
        COINSTATS_ENVELOPE_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + U64_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 2 * U64_BYTES,
        COINSTATS_ENVELOPE_BYTES + MUHASH_BYTES + HEIGHT_BYTES + 3 * U64_BYTES,
    ];

    for offset in COINSTATS_FIELD_OFFSETS {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
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
        mutate_authenticated_artifact(dir.path(), COINSTATS_FILE, |bytes| {
            bytes[offset] ^= 1;
        })?;

        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err(TestError::UnexpectedSuccess(
                "corrupt CoinStats checkpoint unexpectedly loaded",
            ));
        };
        assert!(
            matches!(error, CheckpointLoadError::Corrupt(_)),
            "unexpected checkpoint load error: {error}"
        );
    }
    Ok(())
}
