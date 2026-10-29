use super::*;
use bitcoin_rs_utxo::core_snapshot::{SnapshotError, read_and_verify};

#[test]
fn active_origin_survives_failure_and_validated_provenance_survives_finalization() {
    let base = bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]);
    let absent = bitcoin_rs_primitives::Hash256::default();
    let assumed = ChainstateRole::AssumedActive {
        base_height: 200,
        base_hash: base,
    };
    let failed = AssumeUtxoDiskStatus::Failed {
        base_height: 200,
        base_hash: base,
        expected_hash_serialized: absent,
        actual_hash_serialized: absent,
    };
    assert_eq!(active_snapshot_base(assumed, &failed), Some(base));
    let finalized = AssumeUtxoDiskStatus::Finalized {
        base_height: 200,
        base_hash: base,
        validated_hash_serialized: absent,
    };
    assert_eq!(
        active_snapshot_base(ChainstateRole::Ordinary, &finalized),
        Some(base)
    );
    assert_eq!(
        active_snapshot_base(
            ChainstateRole::Ordinary,
            &AssumeUtxoDiskStatus::Uninitialized
        ),
        None
    );
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn input_fifo_is_rejected_without_waiting_for_a_writer() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("input.pipe");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let rejected = matches!(
            open_regular_input(&path),
            Err(SnapshotImportError::NotRegular)
        );
        let _ = sender.send(rejected);
    });
    assert!(
        receiver.recv_timeout(std::time::Duration::from_secs(1))?,
        "FIFO must be rejected as a non-regular input"
    );
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("input opener panicked"))?;
    Ok(())
}

fn node_config(dir: &Path) -> crate::NodeConfig {
    let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.join("node");
    config.p2p.listen.clear();
    config
}

fn core_headers() -> anyhow::Result<Vec<bitcoin_rs_primitives::Header>> {
    let raw: Vec<String> = sonic_rs::from_str(include_str!(
        "../../../utxo/tests/fixtures/core-v2/blocks200.json"
    ))?;
    raw.iter()
        .map(|hex| {
            let block: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex)?;
            bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&block.header))
                .map_err(anyhow::Error::from)
        })
        .collect()
}

fn snapshot_inputs(dir: &Path) -> anyhow::Result<(crate::state::NodeState, PathBuf, PathBuf)> {
    let state = crate::state::NodeState::open(node_config(dir), None)?;
    state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
        Network::Regtest.genesis_block(),
    ))?;
    state.chainstate().admit_headers(&core_headers()?)?;
    let core_bytes = include_bytes!("../../../utxo/tests/fixtures/core-v2/core200.dat");
    let core_path = dir.join("core.dat");
    std::fs::write(&core_path, core_bytes)?;
    let snapshot = read_and_verify(
        &mut core_bytes.as_slice(),
        Network::Regtest,
        SnapshotLimits::default(),
    )?;
    let mut native = Vec::new();
    bitcoin_rs_utxo::write_snapshot_observed(
        &snapshot.set,
        &snapshot.anchor.block_hash,
        snapshot.anchor.height,
        &mut native,
        (),
    )?;
    let native_path = dir.join("native.dat");
    std::fs::write(&native_path, &native)?;
    Ok((state, core_path, native_path))
}

#[test]
fn native_embedding_contract_and_shared_import_budget() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
    let native = std::fs::read(&native_path)?;
    let core_bytes = std::fs::read(&core_path)?;
    {
        let _permit = state.snapshots.import.lock();
        assert!(matches!(
            state.snapshots.import(&core_path),
            Err(SnapshotImportError::ImportInProgress)
        ));
        assert!(matches!(
            state.snapshots.import_native(&native_path),
            Err(SnapshotImportError::ImportInProgress)
        ));
    }
    assert!(state.activate_assumeutxo_snapshot_file(&core_path).is_err());
    state.activate_assumeutxo_snapshot_file(&native_path)?;
    assert!(matches!(
        state
            .snapshots
            .import_native(&dir.path().join("missing.dat")),
        Err(SnapshotImportError::Activation(
            AssumeUtxoError::AlreadyActive
        ))
    ));
    let view = state.chainstates_summary()?;
    assert_eq!(view.active_chainstate.height, Some(200));
    assert!(!view.active_chainstate.validated);
    assert!(view.historical_chainstate.is_some());
    assert_eq!(std::fs::read(native_path)?, native);
    assert_eq!(std::fs::read(core_path)?, core_bytes);
    Ok(())
}

#[test]
fn successful_snapshot_import_preserves_nonresident_fee_prioritisation() -> anyhow::Result<()> {
    use bitcoin_rs_mempool::PrioritisedTransaction;
    use bitcoin_rs_primitives::{Hash256, Txid};

    for native in [false, true] {
        let dir = tempfile::tempdir()?;
        let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
        let gateway = state.mempool_gateway();
        let txid = Txid(Hash256::from_le_bytes(&[42; 32]));
        gateway.prioritise(txid, 123)?;
        let expected = vec![PrioritisedTransaction {
            txid,
            fee_delta: 123,
            in_mempool: false,
            modified_fee: None,
        }];
        assert_eq!(gateway.prioritised_transactions(), expected);
        assert!(gateway.read().is_empty());
        let sequence = gateway.read().sequence_number();
        if native {
            state.snapshots.import_native(&native_path)?;
        } else {
            state.snapshots.import(&core_path)?;
        }
        assert_eq!(
            gateway.prioritised_transactions(),
            expected,
            "successful import must preserve operator fee deltas (native={native})"
        );
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert!(gateway.stable_generation().is_some());
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.height),
            Some(200)
        );
        assert!(state.chainstate().role().is_assumed_active());
    }
    Ok(())
}

#[test]
fn nonempty_mempool_refuses_both_formats_without_changing_state() -> anyhow::Result<()> {
    use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry};
    use bitcoin_rs_primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
    };

    let dir = tempfile::tempdir()?;
    let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
    let gateway = state.mempool_gateway();
    let transaction = Arc::new(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Network::Regtest.genesis_block().txs[0].txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]),
        }],
        lock_time: LockTime::ZERO,
    });
    gateway.insert_entry(
        AdmissionOrigin::Rpc,
        MempoolEntry::new(Arc::clone(&transaction), 100, 1_000, 0, 0, 0),
    )?;
    gateway.prioritise(transaction.txid(), 123)?;
    let before_tip = state.chainstate().applied_tip_snapshot();
    let before_stats = state.chainstate().coin_stats_handle().snapshot();
    let before_sequence = gateway.read().sequence_number();
    let before_fees = gateway.prioritised_transactions();
    let core_bytes = std::fs::read(&core_path)?;
    let native_bytes = std::fs::read(&native_path)?;
    for native in [false, true] {
        let result = if native {
            state.snapshots.import_native(&native_path)
        } else {
            state.snapshots.import(&core_path).map(|_| ())
        };
        assert!(
            matches!(result, Err(SnapshotImportError::MempoolNotEmpty)),
            "a populated mempool must refuse snapshot activation"
        );
        assert!(gateway.read().contains_txid(&transaction.txid()));
        assert_eq!(gateway.read().sequence_number(), before_sequence);
        assert_eq!(gateway.prioritised_transactions(), before_fees);
        assert!(
            gateway.stable_generation().is_some(),
            "refusal must settle its admission fence"
        );
        assert_eq!(state.chainstate().applied_tip_snapshot(), before_tip);
        assert_eq!(
            state.chainstate().coin_stats_handle().snapshot(),
            before_stats
        );
        assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert!(!state.chainstate().is_closed_for_recovery());
        assert!(!dir.path().join("node/assumeutxo").exists());
        assert_eq!(std::fs::read(&core_path)?, core_bytes);
        assert_eq!(std::fs::read(&native_path)?, native_bytes);
    }
    gateway.clear(AdmissionOrigin::Rpc);
    state.snapshots.import(&core_path)?;
    assert_eq!(
        state
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| tip.height),
        Some(200)
    );
    assert!(gateway.stable_generation().is_some());
    Ok(())
}

fn entry_names(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut names = std::fs::read_dir(dir)?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

#[test]
fn export_reproduces_the_core_snapshot_and_never_replaces_an_entry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (state, core_path, _native_path) = snapshot_inputs(dir.path())?;
    state.snapshots.import(&core_path)?;
    let core_bytes = std::fs::read(&core_path)?;
    let pin = Network::Regtest
        .assume_utxo_for_height(200)
        .ok_or_else(|| anyhow::anyhow!("the regtest 200-height pin is compiled"))?;
    let coins = read_and_verify(
        &mut core_bytes.as_slice(),
        Network::Regtest,
        SnapshotLimits::default(),
    )?
    .metadata
    .coins_count;
    let never = LatchReader::fixture_never();
    let out = dir.path().join("out");
    std::fs::create_dir(&out)?;
    let output = out.join("export.dat");

    let exported = state.snapshots.export(&output, &never)?;
    assert_eq!(std::fs::read(&output)?, core_bytes);
    assert_eq!(exported.coins_written, coins);
    assert_eq!(exported.base_height, 200);
    assert_eq!(exported.base_hash, pin.block_hash.to_string_be());
    assert_eq!(exported.txoutset_hash, pin.hash_serialized.to_string_be());
    assert_eq!(exported.nchaintx, pin.chain_tx_count);
    assert_eq!(
        exported.path,
        output.canonicalize()?.to_string_lossy().into_owned()
    );
    assert_eq!(entry_names(&out)?, ["export.dat"]);

    assert!(matches!(
        state.snapshots.export(&output, &never),
        Err(SnapshotExportError::Exists(_))
    ));
    let operator = out.join("operator.dat");
    std::fs::write(&operator, b"operator")?;
    assert!(matches!(
        state.snapshots.export(&operator, &never),
        Err(SnapshotExportError::Exists(_))
    ));
    assert_eq!(std::fs::read(&operator)?, b"operator");
    assert_eq!(std::fs::read(&output)?, core_bytes);
    assert_eq!(entry_names(&out)?, ["export.dat", "operator.dat"]);

    let relative = state.snapshots.export(Path::new("relative.dat"), &never)?;
    assert_eq!(
        std::fs::read(dir.path().join("node/relative.dat"))?,
        core_bytes
    );
    assert_eq!(
        relative.path,
        dir.path()
            .join("node/relative.dat")
            .canonicalize()?
            .to_string_lossy()
    );

    let recovery = dir.path().join("node/assumeutxo/export.dat");
    assert!(matches!(
        state.snapshots.export(&recovery, &never),
        Err(SnapshotExportError::RecoveryOutput)
    ));
    assert!(!recovery.exists());
    Ok(())
}

#[test]
fn interrupted_export_publishes_nothing_and_removes_its_staged_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (state, core_path, _native_path) = snapshot_inputs(dir.path())?;
    state.snapshots.import(&core_path)?;
    let out = dir.path().join("out");
    std::fs::create_dir(&out)?;
    let output = out.join("interrupted.dat");

    let cancelled = LatchReader::new(Arc::new(std::sync::atomic::AtomicBool::new(true)));
    assert!(matches!(
        state.snapshots.export(&output, &cancelled),
        Err(SnapshotExportError::Interrupted)
    ));
    assert_eq!(entry_names(&out)?, Vec::<String>::new());

    let polls = std::cell::Cell::new(0_u32);
    let stop = || {
        polls.set(polls.get() + 1);
        polls.get() > 1
    };
    let error = state
        .snapshots
        .export_until(&output, &stop)
        .err()
        .ok_or_else(|| anyhow::anyhow!("an interrupted export must fail"))?;
    assert!(matches!(
        error,
        SnapshotExportError::Codec(SnapshotError::Interrupted)
    ));
    assert!(matches!(
        SnapshotControlError::from(error),
        SnapshotControlError::Interrupted
    ));
    assert_eq!(entry_names(&out)?, Vec::<String>::new());

    state
        .snapshots
        .export(&output, &LatchReader::fixture_never())?;
    assert_eq!(entry_names(&out)?, ["interrupted.dat"]);

    state.chainstate().request_shutdown();
    assert!(matches!(
        state
            .snapshots
            .export(&out.join("shutdown.dat"), &LatchReader::fixture_never()),
        Err(SnapshotExportError::Interrupted)
    ));
    assert_eq!(entry_names(&out)?, ["interrupted.dat"]);
    Ok(())
}

#[test]
fn stale_same_pid_temp_does_not_block_a_new_export() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (state, core_path, _native_path) = snapshot_inputs(dir.path())?;
    state.snapshots.import(&core_path)?;
    let out = dir.path().join("out");
    std::fs::create_dir(&out)?;
    let stale = out.join(format!("export.dat.{}.incomplete", std::process::id()));
    std::fs::write(&stale, b"stale")?;
    let output = out.join("export.dat");

    let exported = state
        .snapshots
        .export(&output, &LatchReader::fixture_never())?;
    assert_eq!(
        exported.path,
        output.canonicalize()?.to_string_lossy().into_owned()
    );
    assert_eq!(std::fs::read(&stale)?, b"stale");
    assert!(output.is_file());
    let names = entry_names(&out)?;
    assert!(names.contains(&"export.dat".to_string()));
    assert!(
        names.contains(
            &stale
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("stale file name"))?
                .to_string_lossy()
                .into_owned()
        )
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| name.ends_with(".incomplete"))
            .count(),
        1,
        "the new export publishes without leaving its own staged file"
    );
    Ok(())
}

#[test]
fn concurrent_export_is_refused_while_the_permit_is_held() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (state, core_path, _native_path) = snapshot_inputs(dir.path())?;
    state.snapshots.import(&core_path)?;
    let output = dir.path().join("busy.dat");
    {
        let _permit = state.snapshots.export.lock();
        let error = state
            .snapshots
            .export(&output, &LatchReader::fixture_never())
            .err()
            .ok_or_else(|| anyhow::anyhow!("a held permit must refuse the export"))?;
        assert!(matches!(error, SnapshotExportError::ExportInProgress));
        assert!(matches!(
            SnapshotControlError::from(error),
            SnapshotControlError::Unavailable(_)
        ));
    }
    assert!(!output.exists());
    Ok(())
}

fn regtest_pin() -> anyhow::Result<&'static bitcoin_rs_primitives::AssumeUtxoData> {
    Network::Regtest
        .assume_utxo_for_height(200)
        .ok_or_else(|| anyhow::anyhow!("regtest height-200 anchor missing"))
}

type ValidatingIdentity = (
    u32,
    bitcoin_rs_primitives::Hash256,
    bitcoin_rs_primitives::Hash256,
    u64,
);

fn validating_identity(status: &AssumeUtxoDiskStatus) -> anyhow::Result<ValidatingIdentity> {
    match status {
        AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            chain_tx_count,
            ..
        } => Ok((
            *base_height,
            *base_hash,
            *expected_hash_serialized,
            *chain_tx_count,
        )),
        other => anyhow::bail!("expected a validating lifecycle, found {other:?}"),
    }
}

fn tip_identity(state: &crate::state::NodeState) -> Option<(u32, bitcoin_rs_primitives::Hash256)> {
    state
        .chainstate()
        .applied_tip_snapshot()
        .map(|tip| (tip.height, tip.hash))
}

#[test]
fn sealed_and_proofless_activation_install_identical_state_and_survive_restart()
-> anyhow::Result<()> {
    let pinned = regtest_pin()?;
    let mut installed = Vec::new();
    for native in [false, true] {
        let dir = tempfile::tempdir()?;
        let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
        if native {
            state.snapshots.import_native(&native_path)?;
        } else {
            state.snapshots.import(&core_path)?;
        }
        let stats = state.chainstate().coin_stats_handle().snapshot();
        let (commitment, mut scanned) = state.chainstate().utxo().with_stable_view(|view| {
            Ok::<_, bitcoin_rs_utxo::UtxoError>((
                view.hash_serialized_3_at_height(pinned.height)?,
                bitcoin_rs_utxo::stats::scan_coin_stats(view, pinned.height, true)?,
            ))
        })?;
        assert_eq!(commitment, pinned.hash_serialized, "native={native}");
        scanned.tx_count = pinned.chain_tx_count;
        assert_eq!(
            stats.to_bytes(),
            scanned.to_bytes(),
            "native={native}: installed statistics equal an independent scan"
        );
        assert_eq!(stats.utxo_count, 200);
        let identity = validating_identity(&state.snapshots.manager.status()?)?;
        assert_eq!(identity.1, pinned.block_hash);
        drop(state);

        let resumed = crate::state::NodeState::open(node_config(dir.path()), None)?;
        assert_eq!(
            resumed
                .chainstate()
                .coin_stats_handle()
                .snapshot()
                .to_bytes(),
            stats.to_bytes(),
            "native={native}: restart recomputation agrees with installed statistics"
        );
        assert_eq!(
            validating_identity(&resumed.snapshots.manager.status()?)?,
            identity
        );
        assert!(resumed.chainstate().role().is_assumed_active());
        assert_eq!(
            tip_identity(&resumed),
            Some((pinned.height, pinned.block_hash))
        );
        assert!(
            resumed
                .chainstates_summary()?
                .historical_chainstate
                .is_some()
        );
        installed.push(stats.to_bytes());
    }
    assert_eq!(
        installed[0], installed[1],
        "typed and proofless activation must be indistinguishable"
    );
    Ok(())
}

#[test]
fn wrong_commitment_changes_nothing_and_a_valid_retry_activates() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (state, core_path, _) = snapshot_inputs(dir.path())?;
    let mut forged = std::fs::read(&core_path)?;
    *forged
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("empty fixture"))? ^= 1;
    let forged_path = dir.path().join("forged.dat");
    std::fs::write(&forged_path, &forged)?;
    let before_tip = state.chainstate().applied_tip_snapshot();
    let before_stats = state.chainstate().coin_stats_handle().snapshot();
    assert!(matches!(
        state.snapshots.import(&forged_path),
        Err(SnapshotImportError::Codec(
            SnapshotError::CommitmentMismatch { .. }
        ))
    ));
    assert_eq!(state.chainstate().applied_tip_snapshot(), before_tip);
    assert_eq!(
        state.chainstate().coin_stats_handle().snapshot(),
        before_stats
    );
    assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
    assert!(matches!(
        state.snapshots.manager.status()?,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    assert!(!state.chainstate().is_closed_for_recovery());
    assert!(!dir.path().join("node/assumeutxo").exists());
    assert_eq!(std::fs::read(&forged_path)?, forged);
    state.snapshots.import(&core_path)?;
    assert_eq!(tip_identity(&state).map(|tip| tip.0), Some(200));
    Ok(())
}

#[test]
fn mutating_an_unproven_set_is_caught_by_the_single_verification() -> anyhow::Result<()> {
    let pinned = regtest_pin()?;
    let dir = tempfile::tempdir()?;
    let (state, core_path, _) = snapshot_inputs(dir.path())?;
    let bytes = std::fs::read(&core_path)?;
    let loaded = read_and_verify(
        &mut bytes.as_slice(),
        Network::Regtest,
        SnapshotLimits::default(),
    )?;
    loaded.set.replace_from(bitcoin_rs_utxo::UtxoSet::new());
    let before_tip = state.chainstate().applied_tip_snapshot();
    let before_stats = state.chainstate().coin_stats_handle().snapshot();
    let result = state.snapshots.manager.activate_snapshot_state(
        loaded.set,
        loaded.metadata.base_block_hash,
        loaded.anchor.height,
    );
    assert!(matches!(
        result,
        Err(AssumeUtxoError::SnapshotCommitmentMismatch { expected, .. })
            if expected == pinned.hash_serialized
    ));
    assert_eq!(state.chainstate().applied_tip_snapshot(), before_tip);
    assert_eq!(
        state.chainstate().coin_stats_handle().snapshot(),
        before_stats
    );
    assert!(matches!(
        state.snapshots.manager.status()?,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    assert!(!state.chainstate().is_closed_for_recovery());
    assert!(!dir.path().join("node/assumeutxo").exists());
    state.snapshots.import(&core_path)?;
    assert_eq!(tip_identity(&state).map(|tip| tip.0), Some(200));
    Ok(())
}

#[cfg(unix)]
#[test]
fn interrupted_activation_fails_closed_and_restart_retries_cleanly() -> anyhow::Result<()> {
    let pinned = regtest_pin()?;
    let dir = tempfile::tempdir()?;
    let (state, core_path, _) = snapshot_inputs(dir.path())?;
    let archive = dir
        .path()
        .join("node/assumeutxo")
        .join(pinned.block_hash.to_string());
    let obstruction = archive.join("headers.dat");
    std::fs::create_dir_all(&obstruction)?;
    let before_tip = tip_identity(&state);
    assert!(before_tip.is_some());
    assert!(matches!(
        state.snapshots.import(&core_path),
        Err(SnapshotImportError::Activation(AssumeUtxoError::Archive(_)))
    ));
    assert!(state.chainstate().is_closed_for_recovery());
    assert!(matches!(
        state.snapshots.manager.status()?,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
    assert_eq!(tip_identity(&state), before_tip);
    assert!(archive.join("coins.dat").is_file(), "orphan coin archive");
    drop(state);

    std::fs::remove_dir(&obstruction)?;
    let resumed = crate::state::NodeState::open(node_config(dir.path()), None)?;
    assert!(!resumed.chainstate().is_closed_for_recovery());
    assert!(matches!(
        resumed.snapshots.manager.status()?,
        AssumeUtxoDiskStatus::Uninitialized
    ));
    assert_eq!(resumed.chainstate().role(), ChainstateRole::Ordinary);
    assert_eq!(tip_identity(&resumed), before_tip);
    resumed.chainstate().admit_headers(&core_headers()?)?;
    resumed.snapshots.import(&core_path)?;
    assert_eq!(tip_identity(&resumed), Some((200, pinned.block_hash)));
    assert!(archive.join("headers.dat").is_file());
    let mut coins = BufReader::new(File::open(archive.join("coins.dat"))?);
    let archived = bitcoin_rs_utxo::read_snapshot_strict_v4(&mut coins)?;
    assert_eq!(
        (archived.height, archived.tip_hash, archived.set.len()),
        (pinned.height, pinned.block_hash, 200)
    );
    Ok(())
}
