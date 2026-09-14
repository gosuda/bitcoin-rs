use super::*;

#[test]
fn utxo_commit_failure_keeps_mempool_generation_odd() -> Result<(), Box<dyn std::error::Error>> {
    let (_sync, handles, _followers, _peers, _block_tree, _applied_tip, _expected) =
        sync_with_header_chain(1)?;
    let transition = handles.begin_transition()?;
    let error = crate::apply::WindowApplyError {
        applied: 0,
        committed: Vec::new(),
        source: crate::apply::error::ApplyError::UtxoCommit(
            bitcoin_rs_utxo::UtxoError::CorruptRecord,
        ),
        disposition: crate::apply::WindowApplyDisposition::Operational,
        invalidated: Box::default(),
    };

    let error = super::super::settle_window_failure(transition, error);

    assert!(matches!(
        error.source,
        crate::apply::error::ApplyError::UtxoCommit(bitcoin_rs_utxo::UtxoError::CorruptRecord)
    ));
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        None,
        "a possibly torn UTXO commit must keep admission closed"
    );
    Ok(())
}

#[test]
fn settle_window_failure_finish_failure_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
    let (_sync, handles, _followers, _peers, _block_tree, _applied_tip, _expected) =
        sync_with_header_chain(1)?;
    let transition = handles.begin_transition()?;
    // Force a different odd generation so the CAS in finish fails.
    handles
        .mempool_gateway
        .force_chain_generation(transition.proof().odd_generation().wrapping_add(2));
    let error = crate::apply::WindowApplyError {
        applied: 0,
        committed: Vec::new(),
        source: crate::apply::error::ApplyError::BlockValueOverflow,
        disposition: crate::apply::WindowApplyDisposition::Operational,
        invalidated: Box::default(),
    };

    let error = super::super::settle_window_failure(transition, error);

    assert_eq!(
        error.disposition,
        crate::apply::WindowApplyDisposition::Fatal,
        "finish failure must be classified Fatal"
    );
    assert!(
        matches!(
            error.source,
            crate::apply::error::ApplyError::BlockValueOverflow
        ),
        "original source must be preserved, not overwritten by the finish error"
    );
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        None,
        "generation must stay odd after a failed finish"
    );
    Ok(())
}

#[test]
fn utxo_commit_skip_holds_under_moved_generation() -> Result<(), Box<dyn std::error::Error>> {
    let (_sync, handles, _followers, _peers, _block_tree, _applied_tip, _expected) =
        sync_with_header_chain(1)?;
    let transition = handles.begin_transition()?;
    // Force a different odd generation so finish would fail if attempted.
    handles
        .mempool_gateway
        .force_chain_generation(transition.proof().odd_generation().wrapping_add(2));
    let error = crate::apply::WindowApplyError {
        applied: 0,
        committed: Vec::new(),
        source: crate::apply::error::ApplyError::UtxoCommit(
            bitcoin_rs_utxo::UtxoError::CorruptRecord,
        ),
        disposition: crate::apply::WindowApplyDisposition::Operational,
        invalidated: Box::default(),
    };

    let error = super::super::settle_window_failure(transition, error);

    assert_eq!(
        error.disposition,
        crate::apply::WindowApplyDisposition::Fatal,
        "UtxoCommit settlement must be fatal and must not attempt finish"
    );
    assert!(
        matches!(
            error.source,
            crate::apply::error::ApplyError::UtxoCommit(bitcoin_rs_utxo::UtxoError::CorruptRecord)
        ),
        "UtxoCommit source must be unchanged"
    );
    Ok(())
}

#[test]
fn settle_window_success_finish_failure_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
    let (_sync, handles, _followers, _peers, _block_tree, _applied_tip, _expected) =
        sync_with_header_chain(1)?;
    let transition = handles.begin_transition()?;
    // Force a different odd generation so the CAS in finish fails.
    handles
        .mempool_gateway
        .force_chain_generation(transition.proof().odd_generation().wrapping_add(2));
    let applied = 2_usize;
    let committed: Vec<crate::apply::ConnectOutcome> = Vec::new();

    let error = match super::super::settle_window_success(transition, applied, committed) {
        Err(error) => error,
        Ok(_) => panic!("finish failure must return Err, got Ok"),
    };

    assert_eq!(
        error.disposition,
        crate::apply::WindowApplyDisposition::Fatal,
        "success-path finish failure must be classified Fatal"
    );
    assert_eq!(error.applied, applied, "applied count must be preserved");
    assert!(
        error.committed.is_empty(),
        "committed outcomes must be preserved"
    );
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        None,
        "generation must stay odd after a failed finish"
    );
    Ok(())
}
