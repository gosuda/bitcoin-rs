use std::fs;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_primitives::{Block, Hash256, Header, Network};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::snapshot::SnapshotLoad;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use parking_lot::RwLock;

use crate::Chainstate;
use crate::assumeutxo::{
    ActiveChainstateSummary, AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager,
    ChainstateRole, ChainstatesSummary, HistoricalChainstateSummary,
};
use crate::error::ApplyError;

fn make_test_chainstate(network: Network, role: ChainstateRole) -> Arc<Chainstate> {
    let cs = Arc::new(Chainstate::new(
        network,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(BlockTree::new())),
        Arc::new(UtxoSet::new()),
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        Arc::new(crate::events::ChainEventPublisher::detached(0)),
    ));
    cs.set_role(role);
    cs
}

fn dummy_snapshot_load(height: u32, tip_hash: Hash256) -> SnapshotLoad {
    SnapshotLoad {
        set: UtxoSet::new(),
        tip_hash,
        height,
        muhash_trailer: [0_u8; 384],
    }
}

#[test]
fn chainstate_role_predicates() {
    let ordinary = ChainstateRole::Ordinary;
    assert!(ordinary.is_ordinary());
    assert!(!ordinary.is_assumed_active());
    assert!(!ordinary.is_historical());

    let dummy_hash = Hash256::from_le_bytes(&[0x42; 32]);
    let assumed = ChainstateRole::AssumedActive {
        base_height: 110,
        base_hash: dummy_hash,
    };
    assert!(!assumed.is_ordinary());
    assert!(assumed.is_assumed_active());
    assert!(!assumed.is_historical());

    let historical = ChainstateRole::Historical {
        base_height: 110,
        base_hash: dummy_hash,
    };
    assert!(!historical.is_ordinary());
    assert!(!historical.is_assumed_active());
    assert!(historical.is_historical());
}

#[test]
fn pinned_metadata_available_for_networks() -> Result<(), Box<dyn std::error::Error>> {
    let mainnet_data = Network::Mainnet.assume_utxo_data();
    assert_eq!(mainnet_data.len(), 2);
    assert_eq!(mainnet_data[0].height, 840_000);
    assert_eq!(mainnet_data[1].height, 880_000);

    let testnet_data = Network::Testnet4.assume_utxo_data();
    assert_eq!(testnet_data.len(), 1);
    assert_eq!(testnet_data[0].height, 90_000);

    let regtest_data = Network::Regtest.assume_utxo_data();
    assert_eq!(regtest_data.len(), 2);
    assert_eq!(regtest_data[0].height, 110);
    assert_eq!(regtest_data[1].height, 200);

    let pinned_110 = Network::Regtest
        .assume_utxo_for_height(110)
        .ok_or("regtest 110 pinned data missing")?;
    assert_eq!(pinned_110.height, 110);
    assert_eq!(
        Network::Regtest
            .assume_utxo_for_hash(pinned_110.block_hash)
            .ok_or("regtest 110 block hash lookup failed")?
            .height,
        110
    );

    assert!(Network::Regtest.assume_utxo_for_height(999).is_none());
    assert!(
        Network::Regtest
            .assume_utxo_for_hash(Hash256::default())
            .is_none()
    );
    Ok(())
}

#[test]
fn assumeutxo_manager_open_fresh() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let active = make_test_chainstate(network, ChainstateRole::Ordinary);

    let manager = AssumeUtxoManager::open(network, active, Some(temp_dir.path().to_path_buf()))?;

    assert_eq!(manager.status(), AssumeUtxoDiskStatus::Uninitialized);
    assert!(manager.can_prune_height(0));
    assert!(manager.can_prune_height(110));

    let summary = manager.chainstates_summary();
    assert_eq!(summary.active_chainstate.role, ChainstateRole::Ordinary);
    assert!(summary.active_chainstate.validated);
    assert!(summary.historical_chainstate.is_none());
    assert_eq!(summary.status, AssumeUtxoDiskStatus::Uninitialized);
    Ok(())
}

#[test]
fn activate_snapshot_validation_failures() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let active = make_test_chainstate(network, ChainstateRole::Ordinary);
    let historical = make_test_chainstate(network, ChainstateRole::Ordinary);

    let manager = AssumeUtxoManager::open(network, active, Some(temp_dir.path().to_path_buf()))?;

    let pinned = network
        .assume_utxo_for_height(110)
        .ok_or("pinned 110 missing")?;

    // 1. Untrusted height
    let untrusted_load = dummy_snapshot_load(1234, pinned.block_hash);
    let Err(err) = manager.activate_snapshot(&untrusted_load, pinned.hash_serialized, &historical)
    else {
        return Err("expected UntrustedSnapshotHeight".into());
    };
    assert!(matches!(
        err,
        AssumeUtxoError::UntrustedSnapshotHeight(1234)
    ));

    // 2. Mismatched block hash
    let wrong_hash_load = dummy_snapshot_load(110, Hash256::from_le_bytes(&[0x99; 32]));
    let Err(err) = manager.activate_snapshot(&wrong_hash_load, pinned.hash_serialized, &historical)
    else {
        return Err("expected SnapshotBlockHashMismatch".into());
    };
    assert!(matches!(
        err,
        AssumeUtxoError::SnapshotBlockHashMismatch { .. }
    ));

    // 3. Mismatched commitment (MuHash)
    let valid_load = dummy_snapshot_load(110, pinned.block_hash);
    let wrong_muhash = Hash256::from_le_bytes(&[0xee; 32]);
    let Err(err) = manager.activate_snapshot(&valid_load, wrong_muhash, &historical) else {
        return Err("expected SnapshotCommitmentMismatch".into());
    };
    assert!(matches!(
        err,
        AssumeUtxoError::SnapshotCommitmentMismatch { .. }
    ));
    Ok(())
}

#[test]
fn activate_snapshot_success_and_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let active = make_test_chainstate(network, ChainstateRole::Ordinary);
    let historical = make_test_chainstate(network, ChainstateRole::Ordinary);

    let manager = AssumeUtxoManager::open(
        network,
        Arc::clone(&active),
        Some(temp_dir.path().to_path_buf()),
    )?;

    let pinned = network
        .assume_utxo_for_height(110)
        .ok_or("pinned 110 missing")?;
    let valid_load = dummy_snapshot_load(110, pinned.block_hash);

    manager.activate_snapshot(&valid_load, pinned.hash_serialized, &historical)?;

    // Verify active chainstate role
    assert_eq!(
        active.role(),
        ChainstateRole::AssumedActive {
            base_height: 110,
            base_hash: pinned.block_hash,
        }
    );

    // Verify historical chainstate role
    assert_eq!(
        historical.role(),
        ChainstateRole::Historical {
            base_height: 110,
            base_hash: pinned.block_hash,
        }
    );

    // Verify disk status
    assert!(matches!(
        manager.status(),
        AssumeUtxoDiskStatus::Validating {
            base_height: 110,
            ..
        }
    ));

    // Pruning rules: disallow <= base_height, allow > base_height
    assert!(!manager.can_prune_height(0));
    assert!(!manager.can_prune_height(109));
    assert!(!manager.can_prune_height(110));
    assert!(manager.can_prune_height(111));

    // Summary reporting
    let summary = manager.chainstates_summary();
    assert_eq!(
        summary.active_chainstate.role,
        ChainstateRole::AssumedActive {
            base_height: 110,
            base_hash: pinned.block_hash,
        }
    );
    assert!(!summary.active_chainstate.validated);
    assert!(summary.historical_chainstate.is_some());
    let hist_summary = summary
        .historical_chainstate
        .as_ref()
        .ok_or("historical chainstate summary missing")?;
    assert_eq!(hist_summary.base_height, 110);
    assert_eq!(hist_summary.base_hash, pinned.block_hash);

    // Re-activating snapshot fails with AlreadyActive
    let Err(err) = manager.activate_snapshot(&valid_load, pinned.hash_serialized, &historical)
    else {
        return Err("expected AlreadyActive error".into());
    };
    assert!(matches!(err, AssumeUtxoError::AlreadyActive));
    Ok(())
}

#[test]
fn reorg_constraint_refuses_disconnect_at_or_below_snapshot_base() {
    let network = Network::Regtest;
    let base_hash = Hash256::from_le_bytes(&[0x33; 32]);
    let active = make_test_chainstate(
        network,
        ChainstateRole::AssumedActive {
            base_height: 110,
            base_hash,
        },
    );

    let dummy_block = Block {
        header: Header {
            version: 1,
            prev_blockhash: Hash256::default().into(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: 0.into(),
            nonce: 0,
        },
        txs: Vec::new(),
    };

    // Synthesize applied tip at height 110 matching block hash
    let dummy_tip = bitcoin_rs_chain::TipSnapshot {
        height: 110,
        hash: base_hash,
        tip_id: bitcoin_rs_chain::NodeId::new(1),
        chainwork: bitcoin_rs_chain::ChainWork::ZERO,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(10),
    };
    active.applied_tip.store(Some(Arc::new(dummy_tip)));

    // Attempting to disconnect at base height 110 must fail with DisconnectBelowSnapshotBase
    let plan_result = crate::disconnect::plan_disconnect(&active, &dummy_block, base_hash);
    match plan_result {
        Err(ApplyError::DisconnectBelowSnapshotBase {
            height,
            base_height,
        }) => {
            assert_eq!(height, 110);
            assert_eq!(base_height, 110);
        }
        other => panic!("expected DisconnectBelowSnapshotBase, got {other:?}"),
    }

    // Now test Ordinary role does not refuse with DisconnectBelowSnapshotBase
    active.set_role(ChainstateRole::Ordinary);
    let plan_result_ordinary = crate::disconnect::plan_disconnect(&active, &dummy_block, base_hash);
    assert!(!matches!(
        plan_result_ordinary,
        Err(ApplyError::DisconnectBelowSnapshotBase { .. })
    ));
}

#[test]
fn historical_refuses_connect_past_target_height() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let base_hash = Hash256::from_le_bytes(&[0x55; 32]);
    let historical = make_test_chainstate(
        network,
        ChainstateRole::Historical {
            base_height: 110,
            base_hash,
        },
    );

    // Tip at height 110: next connected block would be at height 111
    let dummy_tip = bitcoin_rs_chain::TipSnapshot {
        height: 110,
        hash: base_hash,
        tip_id: bitcoin_rs_chain::NodeId::new(1),
        chainwork: bitcoin_rs_chain::ChainWork::ZERO,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(10),
    };
    historical.applied_tip.store(Some(Arc::new(dummy_tip)));

    let block_111 = Block {
        header: Header {
            version: 1,
            prev_blockhash: base_hash.into(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: 0.into(),
            nonce: 0,
        },
        txs: Vec::new(),
    };

    let transition = historical
        .lock_transition()
        .map_err(|e| format!("{e:?}"))?
        .into_transition();
    let outcome = transition.connect(&block_111, None);

    match outcome {
        Err(ApplyError::ConnectPastHistoricalTarget {
            height,
            base_height,
        }) => {
            assert_eq!(height, 111);
            assert_eq!(base_height, 110);
        }
        other => panic!("expected ConnectPastHistoricalTarget, got {other:?}"),
    }
    drop(transition);

    // Tip at height 109: next block is at height 110, but block hash does not match target base_hash
    let prev_109 = Hash256::from_le_bytes(&[0x44; 32]);
    let tip_109 = bitcoin_rs_chain::TipSnapshot {
        height: 109,
        hash: prev_109,
        tip_id: bitcoin_rs_chain::NodeId::new(1),
        chainwork: bitcoin_rs_chain::ChainWork::ZERO,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(9),
    };
    historical.applied_tip.store(Some(Arc::new(tip_109)));

    let wrong_hash_block = Block {
        header: Header {
            version: 1,
            prev_blockhash: prev_109.into(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: 0.into(),
            nonce: 0,
        },
        txs: Vec::new(),
    };

    let transition2 = historical
        .lock_transition()
        .map_err(|e| format!("{e:?}"))?
        .into_transition();
    let outcome_wrong = transition2.connect(&wrong_hash_block, None);

    match outcome_wrong {
        Err(ApplyError::PrevHashMismatch { tip, prev }) => {
            assert_eq!(tip, base_hash);
            assert_eq!(prev, wrong_hash_block.block_hash().0);
        }
        other => panic!("expected PrevHashMismatch, got {other:?}"),
    }
    drop(transition2);
    Ok(())
}

#[test]
fn fail_closed_for_recovery_behavior() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let active = make_test_chainstate(network, ChainstateRole::Ordinary);

    let pinned = network
        .assume_utxo_for_height(110)
        .ok_or("pinned 110 missing")?;
    let status_file = temp_dir.path().join("assumeutxo.json");

    // Write a Failed status file directly
    let failed_status = AssumeUtxoDiskStatus::Failed {
        base_height: 110,
        base_hash: pinned.block_hash,
        expected_muhash: pinned.hash_serialized,
        actual_muhash: Hash256::from_le_bytes(&[0xaa; 32]),
    };
    let json = serde_json::to_string_pretty(&failed_status)?;
    fs::write(&status_file, json)?;

    // Reopen manager: must fail closed immediately
    let res = AssumeUtxoManager::open(
        network,
        Arc::clone(&active),
        Some(temp_dir.path().to_path_buf()),
    );
    match res {
        Err(AssumeUtxoError::PreviouslyFailed {
            base_height,
            expected_muhash,
            actual_muhash,
        }) => {
            assert_eq!(base_height, 110);
            assert_eq!(expected_muhash, pinned.hash_serialized);
            assert_eq!(actual_muhash, Hash256::from_le_bytes(&[0xaa; 32]));
        }
        other => panic!("expected PreviouslyFailed, got {other:?}"),
    }

    // Active chainstate must be locked down
    assert!(active.is_closed_for_recovery());
    assert!(active.lock_transition().is_err());
    Ok(())
}

#[test]
fn crash_recovery_across_phases() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let network = Network::Regtest;
    let pinned = network
        .assume_utxo_for_height(110)
        .ok_or("pinned 110 missing")?;

    // Phase 1: Uninitialized
    {
        let active = make_test_chainstate(network, ChainstateRole::Ordinary);
        let manager = AssumeUtxoManager::open(
            network,
            Arc::clone(&active),
            Some(temp_dir.path().to_path_buf()),
        )?;
        assert_eq!(manager.status(), AssumeUtxoDiskStatus::Uninitialized);
        assert_eq!(active.role(), ChainstateRole::Ordinary);
    }

    // Phase 2: Validating
    {
        let active = make_test_chainstate(network, ChainstateRole::Ordinary);
        let historical = make_test_chainstate(network, ChainstateRole::Ordinary);
        let manager = AssumeUtxoManager::open(
            network,
            Arc::clone(&active),
            Some(temp_dir.path().to_path_buf()),
        )?;

        let valid_load = dummy_snapshot_load(110, pinned.block_hash);
        manager.activate_snapshot(&valid_load, pinned.hash_serialized, &historical)?;

        assert_eq!(
            active.role(),
            ChainstateRole::AssumedActive {
                base_height: 110,
                base_hash: pinned.block_hash,
            }
        );
    }

    // Simulate node crash and restart during Phase 2
    {
        let active = make_test_chainstate(network, ChainstateRole::Ordinary);
        let manager = AssumeUtxoManager::open(
            network,
            Arc::clone(&active),
            Some(temp_dir.path().to_path_buf()),
        )?;

        // Must restore AssumedActive role and Validating status
        assert_eq!(
            active.role(),
            ChainstateRole::AssumedActive {
                base_height: 110,
                base_hash: pinned.block_hash,
            }
        );
        assert!(matches!(
            manager.status(),
            AssumeUtxoDiskStatus::Validating {
                base_height: 110,
                ..
            }
        ));
    }

    // Phase 3: Finalized
    {
        let finalized_status = AssumeUtxoDiskStatus::Finalized {
            base_height: 110,
            base_hash: pinned.block_hash,
            validated_muhash: pinned.hash_serialized,
        };
        let status_file = temp_dir.path().join("assumeutxo.json");
        let json = serde_json::to_string_pretty(&finalized_status)?;
        fs::write(&status_file, json)?;

        let active = make_test_chainstate(
            network,
            ChainstateRole::AssumedActive {
                base_height: 110,
                base_hash: pinned.block_hash,
            },
        );
        let manager = AssumeUtxoManager::open(
            network,
            Arc::clone(&active),
            Some(temp_dir.path().to_path_buf()),
        )?;

        assert_eq!(manager.status(), finalized_status);
        assert_eq!(active.role(), ChainstateRole::Ordinary);
        assert!(manager.can_prune_height(110));
    }
    Ok(())
}

#[test]
fn chainstates_summary_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let dummy_hash = Hash256::from_le_bytes(&[0x12; 32]);
    let muhash = Hash256::from_le_bytes(&[0x34; 32]);

    let summary = ChainstatesSummary {
        active_chainstate: ActiveChainstateSummary {
            role: ChainstateRole::AssumedActive {
                base_height: 840_000,
                base_hash: dummy_hash,
            },
            height: Some(845_000),
            hash: Some(dummy_hash),
            validated: false,
        },
        historical_chainstate: Some(HistoricalChainstateSummary {
            base_height: 840_000,
            base_hash: dummy_hash,
            current_height: 500_000,
            current_hash: dummy_hash,
            expected_muhash: muhash,
            validated_utxo_count: 123_456,
        }),
        status: AssumeUtxoDiskStatus::Validating {
            base_height: 840_000,
            base_hash: dummy_hash,
            expected_muhash: muhash,
            chain_tx_count: 1_000_000_000,
            historical_height: 500_000,
            historical_hash: dummy_hash,
        },
    };

    let serialized = serde_json::to_string_pretty(&summary)?;
    let deserialized: ChainstatesSummary = serde_json::from_str(&serialized)?;
    assert_eq!(summary, deserialized);
    Ok(())
}
