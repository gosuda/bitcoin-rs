use super::*;

#[test]
fn checkpoint_transaction_counts_must_agree_when_known() -> Result<(), Box<dyn std::error::Error>> {
    for chain_tx_count in [0, 1] {
        let dir = tempfile::tempdir()?;
        let (tree, _, applied) = chain_with_applied_height(0, 0)?;
        let applied_tip = tip_snapshot(&tree, applied)?;
        let tree = RwLock::new(tree);
        // The applied tip carries the count the checkpoint writes.
        let applied_tip = bitcoin_rs_chain::TipSnapshot {
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::from_wire(chain_tx_count),
            ..applied_tip
        };
        let mut stats = CoinStats::new();
        stats.finish_block(0, 1);
        let data_dir = super::super::open_data_dir(dir.path())?;
        super::super::write_checkpoint_from_dir(
            &data_dir,
            config(),
            &tree,
            &UtxoSet::new(),
            &CoinStatsListener::new(stats),
            Some(&applied_tip),
        )?;
        let CheckpointLoad::Complete(restored) = load_checkpoint(dir.path(), config())? else {
            return Err("valid checkpoint did not load".into());
        };
        assert_eq!(restored.chain_tx_count, chain_tx_count);
        assert_eq!(restored.coin_stats.tx_count, 1);

        mutate_authenticated_manifest(dir.path(), |manifest| {
            manifest.applied_tip.chain_tx_count = 2;
        })?;
        let Err(error) = load_checkpoint(dir.path(), config()) else {
            return Err("inconsistent authenticated transaction counts were restored".into());
        };
        assert!(error.to_string().contains("transaction count"));
        assert!(error.to_string().contains("full resync"));
    }
    Ok(())
}

#[test]
fn checkpoint_writer_refuses_inconsistent_transaction_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let applied_tip = bitcoin_rs_chain::TipSnapshot {
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(2),
        ..applied_tip
    };
    let data_dir = super::super::open_data_dir(dir.path())?;
    let result = super::super::write_checkpoint_from_dir(
        &data_dir,
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    );
    let Err(error) = result else {
        return Err("inconsistent transaction counts were published".into());
    };
    assert!(error.to_string().contains("transaction count"));
    assert!(!dir.path().join(CHECKPOINT_ROOT).join(CURRENT_FILE).exists());
    Ok(())
}

#[test]
fn checkpoint_writer_reports_height_mismatch_before_count_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    let data_dir = super::super::open_data_dir(dir.path())?;
    let mut stats = CoinStats::new();
    stats.finish_block(1, 1);
    let result = super::super::write_checkpoint_from_dir(
        &data_dir,
        config(),
        &RwLock::new(tree),
        &UtxoSet::new(),
        &CoinStatsListener::new(stats),
        Some(&applied_tip),
    );
    let Err(error) = result else {
        return Err("stale CoinStats unexpectedly published".into());
    };
    assert!(
        error
            .to_string()
            .contains("CoinStats height 1 does not match applied height 0")
    );
    Ok(())
}

#[test]
fn authenticated_header_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>> {
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

    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("corrupt header checkpoint unexpectedly loaded".into());
    };
    assert!(error.to_string().contains("full resync"));
    Ok(())
}

/// The offsets below are the checkpoint envelope (16 bytes) followed by the
/// stable `CoinStats::to_bytes` layout defined in
/// `crates/utxo/src/stats/coin_stats.rs`: `MuHash` numerator/denominator, then
/// height, total amount, bogo size, transaction count, and UTXO count.
/// The `full resync` assertion is the checkpoint recovery contract documented
/// in `docs/policies/db-migration.md` and exercised by the loader.
#[test]
fn authenticated_coinstats_semantics_require_resync() -> Result<(), Box<dyn std::error::Error>> {
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
            return Err("corrupt CoinStats checkpoint unexpectedly loaded".into());
        };
        assert!(error.to_string().contains("full resync"));
    }
    Ok(())
}

#[test]
fn authenticated_utxo_value_mutation_requires_resync() -> Result<(), Box<dyn std::error::Error>> {
    const FIRST_VALUE_OFFSET: usize = 52 + 45 + 4;

    let dir = tempfile::tempdir()?;
    let (tree, _, applied) = chain_with_applied_height(0, 0)?;
    let applied_tip = tip_snapshot(&tree, applied)?;
    super::super::write_checkpoint(
        dir.path(),
        config(),
        &RwLock::new(tree),
        &populated_utxo()?,
        &CoinStatsListener::new(CoinStats::new()),
        Some(&applied_tip),
    )?;

    mutate_authenticated_artifact(dir.path(), UTXO_FILE, |bytes| {
        bytes[FIRST_VALUE_OFFSET] ^= 1;
    })?;
    let Err(error) = load_checkpoint(dir.path(), config()) else {
        return Err("corrupt UTXO checkpoint unexpectedly loaded".into());
    };
    assert!(error.to_string().contains("full resync"));
    Ok(())
}
