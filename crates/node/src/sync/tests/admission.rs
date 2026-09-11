use super::*;

#[test]
fn utxo_commit_failure_keeps_mempool_generation_odd() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
    let transition = sync.handles.begin_transition()?;
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
        sync.handles.mempool_gateway.stable_generation(),
        None,
        "a possibly torn UTXO commit must keep admission closed"
    );
    Ok(())
}

#[test]
fn utxo_commit_skip_holds_under_moved_generation() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
    let transition = sync.handles.begin_transition()?;
    // Force a different odd generation so finish would fail if attempted.
    sync.handles
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
