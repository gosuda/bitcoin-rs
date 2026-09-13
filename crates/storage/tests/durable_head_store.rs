//! Backend-level durable-head store laws, on a real `KvStore`.
//!
//! These exercise the receipt semantics the apply path leans on: `Ok(())`
//! from a commit means a reopened store sees the new head, an injected
//! durability fault never leaves a torn state, and the fence refuses a stale
//! expectation without applying the batch.

use std::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{
    CommitRecords, DurableHead, DurableHeadStore, KvDurableHeadStore, KvStore, PersistFault,
    StorageError,
};

fn head(commit_id: u64, height: u32) -> DurableHead {
    DurableHead {
        commit_id,
        height,
        tip: Hash256::from_le_bytes(&[0xB0; 32]),
        chain_tx_count: 10,
        body_extent: None,
        undo_extent: None,
    }
}

fn run_reopen_and_fence_laws() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let store = Arc::new(KvDurableHeadStore::new(Arc::new(
        bitcoin_rs_storage::FjallStore::open(temp.path())?,
    )));

    // An empty store must be named with a None fence.
    let first = head(1, 1);
    store.commit(None, &first, &CommitRecords::default())?;
    assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));

    // A stale fence applies nothing and reports the move.
    let second = head(2, 2);
    let stale = head(9, 9);
    assert!(
        store
            .commit(Some(&stale), &second, &CommitRecords::default())
            .is_err()
    );
    assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));
    store.commit(Some(&first), &second, &CommitRecords::default())?;

    // Ok(()) is the durability receipt: a reopened store sees the head.
    drop(store);
    let reopened =
        KvDurableHeadStore::new(Arc::new(bitcoin_rs_storage::FjallStore::open(temp.path())?));
    assert_eq!(reopened.load()?.map(|h| h.commit_id), Some(2));
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_durable_head_reopen_and_fence_laws() -> Result<(), StorageError> {
    run_reopen_and_fence_laws()?;
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_durable_head_faults_never_tear_the_state() -> Result<(), StorageError> {
    for fault in [
        PersistFault::FailApply,
        PersistFault::LostApply,
        PersistFault::PartialApply,
        PersistFault::FailSync,
        PersistFault::LostSync,
        PersistFault::FailFlush,
        PersistFault::LostFlush,
    ] {
        fault_leaves_an_intact_head(fault)?;
    }
    Ok(())
}

/// After a one-shot fault on the head commit, a reopened store shows either
/// the complete old head or the complete new head — never absence, never a
/// torn decode (`P2` at the storage boundary).
fn fault_leaves_an_intact_head(fault: PersistFault) -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let first = head(1, 1);
    let next = head(2, 2);
    let outcome = {
        let backend = Arc::new(bitcoin_rs_storage::FjallStore::open(temp.path())?);
        let store = KvDurableHeadStore::new(Arc::clone(&backend));

        store.commit(None, &first, &CommitRecords::default())?;
        backend.arm_persist_fault(fault);
        store.commit(Some(&first), &next, &CommitRecords::default())
    };

    let reopened =
        KvDurableHeadStore::new(Arc::new(bitcoin_rs_storage::FjallStore::open(temp.path())?));
    let recovered = reopened
        .load()?
        .ok_or_else(|| StorageError::Backend("head row vanished".to_owned()))?;
    assert!(
        recovered == first || recovered == next,
        "fault {fault:?} left a torn head: {recovered:?} (commit outcome {outcome:?})"
    );
    Ok(())
}
