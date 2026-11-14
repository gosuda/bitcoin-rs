use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_storage::utxo::{SnapshotCoin, SnapshotCoinObserver as _};

use super::recovery_tests::{ForkFixture, SeedCellHarness, at};
use crate::snapshot_seed::ScriptLiveSeedPhase;
use crate::{IndexCapabilities, IndexError};

#[derive(Debug, thiserror::Error)]
enum SeedSessionTestError {
    #[error(transparent)]
    Index(#[from] crate::IndexError),
    #[error(transparent)]
    Int(#[from] std::num::TryFromIntError),
}

fn coin(index: u64, height: u32) -> SnapshotCoin<'static> {
    let mut txid = [0_u8; 32];
    txid[..8].copy_from_slice(&index.to_le_bytes());
    SnapshotCoin {
        txid: Hash256::from_le_bytes(&txid),
        vout: 0,
        value: 1_000 + index,
        script_pubkey: &[0x51],
        height,
        coinbase: false,
    }
}

// SYNC-03
#[test]
fn blocks_apply_while_a_paused_seed_is_stopped() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let seed = h.runtime.script_live_seed();
    let session = seed.begin_session()?;
    {
        let mut observer = session.observer();
        for index in 0..4 {
            observer.observe_coin(coin(index, 2));
        }
    }
    assert!(session.take_error().is_none(), "staging must not fail");
    assert_eq!(session.staged_rows(), 4);
    drop(session);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
    let tip = f.tip(f.a[3]);
    h.set_tip(&tip);
    let mut pending = None;
    h.settle(&mut pending);
    h.assert_at(&tip);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
    assert_eq!(seed.staged_rows(), 0);
    assert!(seed.take_backlog(usize::MAX)?.is_empty());
    Ok(())
}

// SNP-07
#[test]
fn staged_seed_rows_stay_unpublished_until_the_worker_publishes() -> Result<(), SeedSessionTestError>
{
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let base = f.tip(f.a[1]);
    h.stage_seed_rows(&base, 4);
    assert_eq!(
        h.watermarks().script_live,
        None,
        "rows exist without a watermark while decoding"
    );
    let tip = f.tip(f.a[3]);
    h.set_tip(&tip);
    let mut pending = None;
    h.settle(&mut pending);
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&tip)),
        "the worker publishes the staged base"
    );
    h.assert_at(&tip);
    Ok(())
}

// SNP-07
#[test]
fn an_aborted_session_discards_the_staged_base() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let seed = h.runtime.script_live_seed();
    let session = seed.begin_session()?;
    {
        let mut observer = session.observer();
        for index in 0..4 {
            observer.observe_coin(coin(index, 2));
        }
    }
    session.abort();
    drop(session);
    assert_eq!(h.watermarks().script_live, None);
    let tip = f.tip(f.a[3]);
    h.set_tip(&tip);
    let mut pending = None;
    h.settle(&mut pending);
    h.assert_at(&tip);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
    assert_eq!(seed.staged_rows(), 0);
    assert!(seed.take_backlog(usize::MAX)?.is_empty());
    seed.begin_session()?;
    Ok(())
}

// SNP-07
#[test]
fn stopping_a_paused_seed_discards_its_internal_data() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let seed = h.runtime.script_live_seed();
    let first = seed.begin_session()?;
    assert!(matches!(
        seed.begin_session(),
        Err(IndexError::SeedAlreadyActive)
    ));
    {
        let mut observer = first.observer();
        for index in 0..4 {
            observer.observe_coin(coin(index, 2));
        }
    }
    assert_eq!(first.staged_rows(), 4);
    drop(first);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::AbortPending);
    let tip = f.tip(f.a[3]);
    h.set_tip(&tip);
    let mut pending = None;
    h.settle(&mut pending);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
    assert_eq!(seed.staged_rows(), 0, "a stopped seed keeps no rows");
    assert!(seed.take_backlog(usize::MAX)?.is_empty());
    let second = seed.begin_session()?;
    assert!(
        seed.claim_row_reset(),
        "a fresh session starts from an empty queue"
    );
    {
        let mut observer = second.observer();
        for index in 0..2 {
            observer.observe_coin(coin(100 + index, 3));
        }
    }
    assert!(second.take_error().is_none());
    let rows = seed.take_backlog(usize::MAX)?;
    assert_eq!(
        rows.len(),
        2,
        "the backlog holds only the second session's rows"
    );
    Ok(())
}

#[test]
fn staging_needs_no_draining_worker() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(1);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let seed = h.runtime.script_live_seed();
    let session = seed.begin_session()?;
    const ROWS: u64 = 8_192;
    {
        let mut observer = session.observer();
        for index in 0..ROWS {
            observer.observe_coin(coin(index, 1));
        }
    }
    assert!(
        session.take_error().is_none(),
        "decode stalls when no worker drains the seed"
    );
    assert_eq!(session.staged_rows(), ROWS);
    let drained = seed.take_backlog(usize::MAX)?;
    assert_eq!(
        drained.len(),
        usize::try_from(ROWS)?,
        "every staged row survives staging"
    );
    Ok(())
}

// SNP-07
#[test]
fn a_seed_replaces_the_published_live_base() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(4);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let first = f.tip(f.a[1]);
    h.stage_seed_rows(&first, 4);
    h.set_tip(&first);
    let mut pending = None;
    h.settle(&mut pending);
    assert_eq!(h.watermarks().script_live, Some(at(&first)));
    assert_eq!(h.live_row_count(), 4, "the first seed owns the live base");

    let second = f.tip(f.a[3]);
    h.stage_seed_rows(&second, 2);
    h.set_tip(&second);
    h.settle(&mut pending);
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&second)),
        "the higher seed must publish over the replaced base"
    );
    assert_eq!(
        h.live_row_count(),
        2,
        "the replaced base holds only the new seed's rows"
    );
    h.assert_at(&second);
    assert_eq!(
        h.runtime.script_live_seed().phase(),
        ScriptLiveSeedPhase::Idle
    );
    Ok(())
}

// SNP-07
#[test]
fn an_abort_before_decode_preserves_the_published_live_base() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(2);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let base = f.tip(f.a[1]);
    h.stage_seed_rows(&base, 4);
    h.set_tip(&base);
    let mut pending = None;
    h.settle(&mut pending);
    assert_eq!(h.watermarks().script_live, Some(at(&base)));
    assert_eq!(h.live_row_count(), 4);

    let seed = h.runtime.script_live_seed();
    let session = seed.begin_session()?;
    session.abort();
    drop(session);
    h.settle(&mut pending);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
    assert_eq!(seed.staged_rows(), 0);
    assert!(seed.take_backlog(usize::MAX)?.is_empty());
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&base)),
        "a seed rejected before decoding must preserve the published base"
    );
    assert_eq!(
        h.live_row_count(),
        4,
        "the published rows must survive the abort"
    );
    Ok(())
}

// SNP-07
#[test]
fn an_abort_after_staging_preserves_the_published_live_base() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(3);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let first = f.tip(f.a[1]);
    h.stage_seed_rows(&first, 4);
    h.set_tip(&first);
    let mut pending = None;
    h.settle(&mut pending);
    assert_eq!(h.watermarks().script_live, Some(at(&first)));

    let second = f.tip(f.a[2]);
    let seed = h.runtime.script_live_seed();
    let session = seed.begin_session()?;
    {
        let mut observer = session.observer();
        for index in 0..3 {
            observer.observe_coin(coin(index, 3));
        }
    }
    assert!(session.take_error().is_none());
    h.set_tip(&second);
    assert!(
        h.stalled_pass(&mut pending),
        "an open seed pass must stall while the published base is present"
    );
    session.abort();
    drop(session);
    h.settle(&mut pending);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
    assert_eq!(seed.staged_rows(), 0);
    assert!(seed.take_backlog(usize::MAX)?.is_empty());
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&second)),
        "the preserved base must carry forward to the applied tip"
    );
    Ok(())
}

// SNP-07
#[test]
fn a_seed_at_or_below_the_published_base_is_already_covered() -> Result<(), SeedSessionTestError> {
    let f = ForkFixture::new(3);
    f.persist_undo();
    let h = SeedCellHarness::new(&f, IndexCapabilities::TX_AND_SCRIPTS);
    let tip = f.tip(f.a[2]);
    h.stage_seed_rows(&tip, 4);
    h.set_tip(&tip);
    let mut pending = None;
    h.settle(&mut pending);
    assert_eq!(h.watermarks().script_live, Some(at(&tip)));
    let rows_before = h.live_row_count();
    assert!(rows_before > 0, "the published base must hold rows");

    let seed = h.runtime.script_live_seed();
    let lower = f.tip(f.a[1]);
    let session = seed.begin_session()?;
    {
        let mut observer = session.observer();
        for index in 0..2 {
            observer.observe_coin(coin(index, lower.height));
        }
    }
    session.publish(at(&lower));
    assert!(h.stalled_pass(&mut pending));
    assert_eq!(
        seed.phase(),
        ScriptLiveSeedPhase::PublishPending { tip: at(&lower) }
    );
    drop(session);
    h.settle(&mut pending);
    assert_eq!(seed.phase(), ScriptLiveSeedPhase::Idle);
    assert_eq!(seed.staged_rows(), 0);
    assert!(seed.take_backlog(usize::MAX)?.is_empty());
    assert_eq!(
        h.watermarks().script_live,
        Some(at(&tip)),
        "a seed at or below the published base must not move the watermark"
    );
    assert_eq!(
        h.live_row_count(),
        rows_before,
        "a covered seed must leave the published rows untouched"
    );
    Ok(())
}
