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
