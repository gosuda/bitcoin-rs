#![cfg(feature = "fjall")]

use std::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{
    CommitRecords, DurableHead, DurableHeadStore, KvDurableHeadStore, KvStore, PersistFault,
    ScriptAttestation, StorageError,
};

fn head(commit_id: u64, height: u32) -> DurableHead {
    DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
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

    let first = head(1, 1);
    store.commit(None, &first, &CommitRecords::default())?;
    assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));

    let second = head(2, 2);
    let stale = head(9, 9);
    assert!(
        store
            .commit(Some(&stale), &second, &CommitRecords::default())
            .is_err()
    );
    assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));
    store.commit(Some(&first), &second, &CommitRecords::default())?;

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
fn malformed_file_maximum_refuses_the_entire_head_batch() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let backend = Arc::new(bitcoin_rs_storage::FjallStore::open(temp.path())?);
    let store = KvDurableHeadStore::new(backend.clone());
    let first = head(1, 20);
    store.commit(None, &first, &CommitRecords::default())?;
    let key = bitcoin_rs_storage::block_file_max_height_key(0);
    let cf = bitcoin_rs_storage::pruning::BLOCK_DATA_CF;
    let mut batch = backend.new_batch();
    batch.put(cf, &key, b"corrupt");
    backend.write_durable(batch)?;
    let mut records = CommitRecords::default();
    records.body_rows.push((
        1,
        first.tip,
        bitcoin_rs_storage::BlockFilePosition {
            file_no: 0,
            offset: 0,
            len: 80,
        },
    ));
    assert!(matches!(
        store.commit(Some(&first), &head(2, 20), &records),
        Err(StorageError::IncompatibleData(_))
    ));
    assert_eq!(store.load()?, Some(first));
    assert_eq!(
        backend.get(cf, &key)?.as_deref(),
        Some(b"corrupt".as_slice())
    );
    assert!(
        backend
            .get(
                cf,
                &bitcoin_rs_storage::pruning::block_body_key(1, first.tip)
            )?
            .is_none()
    );
    Ok(())
}

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

fn open_store(
    path: &std::path::Path,
) -> Result<
    (
        Arc<bitcoin_rs_storage::FjallStore>,
        KvDurableHeadStore<bitcoin_rs_storage::FjallStore>,
    ),
    StorageError,
> {
    let backend = Arc::new(bitcoin_rs_storage::FjallStore::open(path)?);
    Ok((backend.clone(), KvDurableHeadStore::new(backend)))
}

fn batch_of(level: ScriptAttestation) -> CommitRecords<'static> {
    CommitRecords {
        attestation: Some(level),
        ..CommitRecords::default()
    }
}

// RCV-02
#[test]
fn a_commit_keeps_the_weakest_attestation_of_the_chain_so_far() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let (_backend, store) = open_store(temp.path())?;

    let first = head(1, 1);
    store.commit(None, &first, &batch_of(ScriptAttestation::Full))?;
    assert_eq!(store.load_attestation(&first)?, ScriptAttestation::Full);

    let second = head(2, 2);
    store.commit(
        Some(&first),
        &second,
        &batch_of(ScriptAttestation::AssumeValid),
    )?;
    assert_eq!(
        store.load_attestation(&second)?,
        ScriptAttestation::AssumeValid
    );

    let third = head(3, 3);
    store.commit(Some(&second), &third, &batch_of(ScriptAttestation::Full))?;
    assert_eq!(
        store.load_attestation(&third)?,
        ScriptAttestation::AssumeValid,
        "executing scripts for a later block never repairs an earlier skipped one"
    );

    let fourth = head(4, 4);
    store.commit(Some(&third), &fourth, &CommitRecords::default())?;
    assert_eq!(
        store.load_attestation(&fourth)?,
        ScriptAttestation::AssumeValid,
        "a replay that attests nothing carries the previous value to the new head"
    );
    Ok(())
}

// RCV-02
#[test]
fn a_head_committed_before_attestation_existed_reads_unattested_and_still_commits()
-> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let (backend, store) = open_store(temp.path())?;
    let legacy = head(7, 7);
    let mut batch = backend.new_batch();
    batch.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
        &legacy.encode(),
    );
    backend.write_durable(batch)?;
    assert_eq!(store.load()?, Some(legacy));
    assert_eq!(
        store.load_attestation(&legacy)?,
        ScriptAttestation::Unattested
    );

    let next = head(8, 8);
    store.commit(Some(&legacy), &next, &batch_of(ScriptAttestation::Full))?;
    assert_eq!(
        store.load_attestation(&next)?,
        ScriptAttestation::Unattested,
        "a weaker or unknown history is never upgraded by a stronger batch"
    );
    Ok(())
}

// RCV-02
#[test]
fn an_attestation_row_bound_to_another_head_reads_unattested() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let (_backend, store) = open_store(temp.path())?;
    let first = head(1, 1);
    store.commit(None, &first, &batch_of(ScriptAttestation::Full))?;
    let other = head(2, 2);
    assert_eq!(
        store.load_attestation(&other)?,
        ScriptAttestation::Unattested,
        "the row names commit 1, so a different head cannot inherit it"
    );
    Ok(())
}

// RCV-02
#[test]
fn a_corrupt_attestation_row_fails_closed() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let (backend, store) = open_store(temp.path())?;
    let first = head(1, 1);
    store.commit(None, &first, &batch_of(ScriptAttestation::Full))?;
    for corrupt in [&[0_u8; 3][..], &[1, 0, 0, 0, 0, 0, 0, 0, 9][..]] {
        let mut batch = backend.new_batch();
        batch.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            bitcoin_rs_storage::SCRIPT_ATTESTATION_KEY,
            corrupt,
        );
        backend.write_durable(batch)?;
        assert!(
            matches!(
                store.load_attestation(&first),
                Err(StorageError::IncompatibleData(_))
            ),
            "{corrupt:?} must be refused, never read as a weaker or stronger level"
        );
    }
    Ok(())
}

// RCV-02
#[test]
fn attest_raises_only_the_current_head() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let (_backend, store) = open_store(temp.path())?;
    let first = head(1, 1);
    store.commit(None, &first, &batch_of(ScriptAttestation::AssumeValid))?;
    store.attest(&first, ScriptAttestation::Full)?;
    assert_eq!(store.load_attestation(&first)?, ScriptAttestation::Full);
    let moved = head(2, 2);
    store.commit(Some(&first), &moved, &CommitRecords::default())?;
    assert!(
        store.attest(&first, ScriptAttestation::Full).is_err(),
        "a head that is no longer current cannot be attested"
    );
    Ok(())
}
