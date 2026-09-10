use bitcoin_rs_primitives::{Hash256, Network};

use bitcoin_rs_storage::{DisconnectMarker, DisconnectPhase};

use crate::{ApplyError, NodeConfig, state::NodeState};

use std::sync::atomic::Ordering;

use super::{ReorgError, settle_reorg_transition};

fn regtest_state() -> anyhow::Result<(tempfile::TempDir, NodeState)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    state.apply_block(&Network::Regtest.genesis_block())?;
    Ok((dir, state))
}

fn connect_failure(source: ApplyError) -> ReorgError {
    ReorgError::ConnectFailed {
        disconnected: 3,
        connected: 2,
        hash: Hash256::from_le_bytes(&[0x67; 32]),
        stopped_at: 42,
        source: Box::new(source),
        invalidated: Vec::new(),
    }
}

/// MPL-04: a possibly torn commit must neither finish generation nor publish
/// the rolled-back disconnect debt, even if its generation moved meanwhile.
#[test]
fn utxo_commit_failure_preserves_odd_generation_and_disconnect_debt() -> anyhow::Result<()> {
    for move_generation in [false, true] {
        let (_dir, state) = regtest_state()?;
        let handles = state.chainstate();
        assert!(handles.checkpoint_publisher.is_some());
        let marker = DisconnectMarker {
            hash: Hash256::from_le_bytes(&[0x68; 32]),
            height: 1,
            phase: DisconnectPhase::RolledBack,
        };
        handles
            .undo_store
            .arm_disconnect(marker.height, marker.hash)?;
        handles
            .undo_store
            .complete_disconnect(marker.height, marker.hash)?;
        assert_eq!(
            handles.undo_store.load_disconnect_marker()?,
            Some(marker.clone())
        );
        let transition = handles.begin_transition()?;
        if move_generation {
            handles
                .mempool_gateway
                .force_chain_generation(transition.proof().odd_generation() + 2);
        }

        let outcome = settle_reorg_transition(
            transition,
            Err(connect_failure(ApplyError::UtxoCommit(
                bitcoin_rs_utxo::UtxoError::CorruptRecord,
            ))),
        );

        let Err(ReorgError::ConnectFailed {
            disconnected: 3,
            connected: 2,
            stopped_at: 42,
            source,
            ..
        }) = outcome
        else {
            anyhow::bail!("UTXO failure must bypass finish and retain its source: {outcome:?}");
        };
        assert!(matches!(
            source.as_ref(),
            ApplyError::UtxoCommit(bitcoin_rs_utxo::UtxoError::CorruptRecord)
        ));
        assert_eq!(handles.mempool_gateway.stable_generation(), None);
        assert_eq!(
            handles.undo_store.load_disconnect_marker()?,
            Some(marker),
            "possibly torn state must never publish or clear disconnect debt"
        );
        // Positive control: the fixture injected only an error outcome, not
        // torn coins. Its real publisher can settle this synthetic debt, so
        // reaching checkpoint publication above would have cleared the marker.
        assert!(handles.checkpoint()?);
        assert_eq!(handles.undo_store.load_disconnect_marker()?, None);
    }
    Ok(())
}

/// MPL-04: success is not reportable unless the reserved even generation was
/// published; a failed CAS closes the owner and requests shutdown.
#[test]
fn successful_reorg_with_failed_finish_closes_admission() -> anyhow::Result<()> {
    let (_dir, state) = regtest_state()?;
    let handles = state.chainstate();
    let transition = handles.begin_transition()?;
    handles
        .mempool_gateway
        .force_chain_generation(transition.proof().odd_generation() + 2);

    let outcome = settle_reorg_transition(transition, Ok(()));

    let Err(ReorgError::TransitionSettlement {
        source,
        original: None,
    }) = outcome
    else {
        anyhow::bail!("failed finish must replace apparent success: {outcome:?}");
    };
    assert!(matches!(source.as_ref(), ApplyError::Shutdown));
    assert_eq!(handles.mempool_gateway.stable_generation(), None);
    assert!(matches!(
        handles.lock_transition(),
        Err(ApplyError::Shutdown)
    ));
    assert!(handles.shutdown.load(Ordering::Acquire));
    Ok(())
}

/// MPL-04: a failed finish after a clean refusal must retain both the refusal
/// and its committed progress while closing admission.
#[test]
fn refused_reorg_with_failed_finish_preserves_original_progress() -> anyhow::Result<()> {
    let (_dir, state) = regtest_state()?;
    let handles = state.chainstate();
    let transition = handles.begin_transition()?;
    handles
        .mempool_gateway
        .force_chain_generation(transition.proof().odd_generation() + 2);

    let outcome = settle_reorg_transition(
        transition,
        Err(connect_failure(ApplyError::BlockValueOverflow)),
    );

    let Err(ReorgError::TransitionSettlement {
        source,
        original: Some(original),
    }) = outcome
    else {
        anyhow::bail!("failed finish must retain the clean refusal: {outcome:?}");
    };
    assert!(matches!(source.as_ref(), ApplyError::Shutdown));
    let ReorgError::ConnectFailed {
        disconnected,
        connected,
        hash,
        stopped_at,
        source,
        invalidated,
    } = *original
    else {
        anyhow::bail!("settlement lost its original ConnectFailed outcome");
    };
    assert_eq!((disconnected, connected, stopped_at), (3, 2, 42));
    assert_eq!(hash, Hash256::from_le_bytes(&[0x67; 32]));
    assert!(matches!(source.as_ref(), ApplyError::BlockValueOverflow));
    assert!(invalidated.is_empty());
    assert_eq!(handles.mempool_gateway.stable_generation(), None);
    assert!(matches!(
        handles.lock_transition(),
        Err(ApplyError::Shutdown)
    ));
    assert!(handles.shutdown.load(Ordering::Acquire));
    Ok(())
}
