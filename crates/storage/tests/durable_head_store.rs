use std::sync::Arc;

use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_storage::{
    AcceptedPrefix, CoinStore, CommitAuthority, CommitError, CommitRecords, DurableHead,
    DurableHeadStore, KvDurableHeadStore, KvStore, PersistFault, ScriptAttestation, StorageError,
    WindowDelta,
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

struct Family {
    backend: Arc<bitcoin_rs_storage::RocksDbStore>,
    head: KvDurableHeadStore<bitcoin_rs_storage::RocksDbStore>,
    authority: CommitAuthority,
}

fn authority_for(backend: &Arc<bitcoin_rs_storage::RocksDbStore>) -> CommitAuthority {
    let dyn_store: Arc<dyn KvStore> = backend.clone();
    let coins = Arc::new(CoinStore::open(Arc::clone(&dyn_store), 64 * 1024 * 1024));
    CommitAuthority::new(dyn_store, coins)
}

fn commit(
    authority: &CommitAuthority,
    expected: Option<&DurableHead>,
    next: &DurableHead,
    records: CommitRecords<'_>,
) -> Result<(), StorageError> {
    authority
        .commit_prefix(AcceptedPrefix {
            expected_head: expected.copied(),
            next_head: *next,
            undo_rows: records
                .undo_rows
                .into_iter()
                .map(|(height, hash, bytes)| (height, hash, bytes::Bytes::copy_from_slice(bytes)))
                .collect(),
            body_rows: records.body_rows,
            attestation: records.attestation,
            coin_delta: WindowDelta::default(),
        })
        .map(|_receipt| ())
        .map_err(|error| match error {
            CommitError::Storage(storage) => storage,
            other => StorageError::backend(other),
        })
}

fn disconnect(
    authority: &CommitAuthority,
    expected: &DurableHead,
    next: &DurableHead,
) -> Result<(), StorageError> {
    authority
        .commit_disconnect(expected, next, WindowDelta::default())
        .map(|_receipt| ())
        .map_err(|error| match error {
            CommitError::Storage(storage) => storage,
            other => StorageError::backend(other),
        })
}

fn run_reopen_and_fence_laws() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
    let store = KvDurableHeadStore::new(Arc::clone(&backend));
    let authority = authority_for(&backend);

    let first = head(1, 1);
    commit(&authority, None, &first, CommitRecords::default())?;
    assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));

    let second = head(2, 2);
    let stale = head(9, 9);
    assert!(commit(&authority, Some(&stale), &second, CommitRecords::default()).is_err());
    assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));
    commit(&authority, Some(&first), &second, CommitRecords::default())?;

    drop(authority);
    drop(store);
    drop(backend);
    let reopened = KvDurableHeadStore::new(Arc::new(bitcoin_rs_storage::RocksDbStore::open(
        temp.path(),
    )?));
    assert_eq!(reopened.load()?.map(|h| h.commit_id), Some(2));
    Ok(())
}

#[test]
fn rocksdb_durable_head_reopen_and_fence_laws() -> Result<(), StorageError> {
    run_reopen_and_fence_laws()?;
    Ok(())
}

#[test]
fn malformed_file_maximum_refuses_the_entire_head_batch() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let family = open_store(temp.path())?;
    let first = head(1, 20);
    commit(&family.authority, None, &first, CommitRecords::default())?;
    let key = bitcoin_rs_storage::block_file_max_height_key(0);
    let cf = bitcoin_rs_storage::pruning::BLOCK_DATA_CF;
    let mut batch = family.backend.new_batch();
    batch.put(cf, &key, b"corrupt");
    family.backend.write_durable(batch)?;
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
        commit(&family.authority, Some(&first), &head(2, 20), records),
        Err(StorageError::IncompatibleData(_))
    ));
    assert_eq!(family.head.load()?, Some(first));
    assert_eq!(
        family.backend.get(cf, &key)?.as_deref(),
        Some(b"corrupt".as_slice())
    );
    assert!(
        family
            .backend
            .get(
                cf,
                &bitcoin_rs_storage::pruning::block_body_key(1, first.tip)
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn rocksdb_durable_head_faults_never_tear_the_state() -> Result<(), StorageError> {
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

fn fault_leaves_an_intact_head(fault: PersistFault) -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let first = head(1, 1);
    let next = head(2, 2);
    let outcome = {
        let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
        let authority = authority_for(&backend);

        commit(&authority, None, &first, CommitRecords::default())?;
        backend.arm_persist_fault(fault);
        commit(&authority, Some(&first), &next, CommitRecords::default())
    };

    let reopened = KvDurableHeadStore::new(Arc::new(bitcoin_rs_storage::RocksDbStore::open(
        temp.path(),
    )?));
    let recovered = reopened
        .load()?
        .ok_or_else(|| StorageError::Backend("head row vanished".to_owned()))?;
    assert!(
        recovered == first || recovered == next,
        "fault {fault:?} left a torn head: {recovered:?} (commit outcome {outcome:?})"
    );
    Ok(())
}

fn open_store(path: &std::path::Path) -> Result<Family, StorageError> {
    let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(path)?);
    let head = KvDurableHeadStore::new(Arc::clone(&backend));
    let authority = authority_for(&backend);
    Ok(Family {
        backend,
        head,
        authority,
    })
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
    let family = open_store(temp.path())?;

    let first = head(1, 1);
    commit(
        &family.authority,
        None,
        &first,
        batch_of(ScriptAttestation::Full),
    )?;
    assert_eq!(
        family.head.load_attestation(&first)?,
        ScriptAttestation::Full
    );

    let second = head(2, 2);
    commit(
        &family.authority,
        Some(&first),
        &second,
        batch_of(ScriptAttestation::AssumeValid),
    )?;
    assert_eq!(
        family.head.load_attestation(&second)?,
        ScriptAttestation::AssumeValid
    );

    let third = head(3, 3);
    commit(
        &family.authority,
        Some(&second),
        &third,
        batch_of(ScriptAttestation::Full),
    )?;
    assert_eq!(
        family.head.load_attestation(&third)?,
        ScriptAttestation::AssumeValid,
        "executing scripts for a later block never repairs an earlier skipped one"
    );

    let fourth = head(4, 4);
    commit(
        &family.authority,
        Some(&third),
        &fourth,
        CommitRecords::default(),
    )?;
    assert_eq!(
        family.head.load_attestation(&fourth)?,
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
    let family = open_store(temp.path())?;
    let legacy = head(7, 7);
    let mut batch = family.backend.new_batch();
    batch.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
        &legacy.encode(),
    );
    family.backend.write_durable(batch)?;
    assert_eq!(family.head.load()?, Some(legacy));
    assert_eq!(
        family.head.load_attestation(&legacy)?,
        ScriptAttestation::Unattested
    );

    let next = head(8, 8);
    commit(
        &family.authority,
        Some(&legacy),
        &next,
        batch_of(ScriptAttestation::Full),
    )?;
    assert_eq!(
        family.head.load_attestation(&next)?,
        ScriptAttestation::Unattested,
        "a weaker or unknown history is never upgraded by a stronger batch"
    );
    Ok(())
}

// RCV-02
#[test]
fn an_attestation_row_bound_to_another_head_reads_unattested() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let family = open_store(temp.path())?;
    let first = head(1, 1);
    commit(
        &family.authority,
        None,
        &first,
        batch_of(ScriptAttestation::Full),
    )?;
    let other = head(2, 2);
    assert_eq!(
        family.head.load_attestation(&other)?,
        ScriptAttestation::Unattested,
        "the row names commit 1, so a different head cannot inherit it"
    );
    Ok(())
}

// RCV-02
#[test]
fn a_corrupt_attestation_row_fails_closed() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let family = open_store(temp.path())?;
    let first = head(1, 1);
    commit(
        &family.authority,
        None,
        &first,
        batch_of(ScriptAttestation::Full),
    )?;
    for corrupt in [&[0_u8; 3][..], &[1, 0, 0, 0, 0, 0, 0, 0, 9][..]] {
        let mut batch = family.backend.new_batch();
        batch.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            bitcoin_rs_storage::SCRIPT_ATTESTATION_KEY,
            corrupt,
        );
        family.backend.write_durable(batch)?;
        assert!(
            matches!(
                family.head.load_attestation(&first),
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
    let family = open_store(temp.path())?;
    let first = head(1, 1);
    commit(
        &family.authority,
        None,
        &first,
        batch_of(ScriptAttestation::AssumeValid),
    )?;
    family.head.attest(&first, ScriptAttestation::Full)?;
    assert_eq!(
        family.head.load_attestation(&first)?,
        ScriptAttestation::Full
    );
    let moved = head(2, 2);
    commit(
        &family.authority,
        Some(&first),
        &moved,
        CommitRecords::default(),
    )?;
    assert!(
        family.head.attest(&first, ScriptAttestation::Full).is_err(),
        "a head that is no longer current cannot be attested"
    );
    Ok(())
}

// RCV-01, RCV-04
#[test]
fn rejects_reopen_with_corrupt_or_truncated_durable_head() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let family = open_store(temp.path())?;
    let valid = head(1, 1);
    commit(&family.authority, None, &valid, CommitRecords::default())?;
    let encoded = valid.encode();
    let cf = bitcoin_rs_storage::ColumnFamily::UtxoMeta;
    let key = bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY;

    let mut truncated = family.backend.new_batch();
    truncated.put(cf, key, &encoded[..10]);
    family.backend.write_durable(truncated)?;
    assert!(matches!(
        family.head.load(),
        Err(StorageError::IncompatibleData(_))
    ));

    let mut bad_magic = encoded;
    bad_magic[0] = b'X';
    let mut batch = family.backend.new_batch();
    batch.put(cf, key, &bad_magic);
    family.backend.write_durable(batch)?;
    assert!(matches!(
        family.head.load(),
        Err(StorageError::IncompatibleData(_))
    ));

    let mut bad_version = encoded;
    bad_version[4] = 99;
    let mut batch = family.backend.new_batch();
    batch.put(cf, key, &bad_version);
    family.backend.write_durable(batch)?;
    assert!(matches!(
        family.head.load(),
        Err(StorageError::IncompatibleData(_))
    ));

    let mut bad_crc = encoded;
    let last = bad_crc.len() - 1;
    bad_crc[last] ^= 0xff;
    let mut batch = family.backend.new_batch();
    batch.put(cf, key, &bad_crc);
    family.backend.write_durable(batch)?;
    assert!(matches!(
        family.head.load(),
        Err(StorageError::IncompatibleData(_))
    ));

    Ok(())
}

// RCV-03, RCV-04
#[test]
fn crash_windows_failing_backend_writer_at_each_write_index_preserves_atomic_reopen()
-> Result<(), StorageError> {
    let cf = bitcoin_rs_storage::ColumnFamily::TxConfirmed;
    let mut wrote_keys_before_fault = false;
    for fail_index in 0..=5_u8 {
        let temp = tempfile::tempdir()?;
        let present;
        {
            let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
            let mut prefix_batch = backend.new_batch();
            for i in 0..fail_index {
                prefix_batch.put(cf, &[i], &[i, i]);
            }
            backend.write_durable(prefix_batch)?;
            if fail_index < 5 {
                for i in 0..fail_index {
                    assert_eq!(
                        backend.get(cf, &[i])?.as_deref(),
                        Some(&[i, i][..]),
                        "fail_index {fail_index}: witness key {i} missing before the fault"
                    );
                }
                if fail_index > 0 {
                    wrote_keys_before_fault = true;
                }
                let mut full_batch = backend.new_batch();
                for i in 0..5_u8 {
                    full_batch.put(cf, &[i], &[i, i]);
                }
                backend.arm_persist_fault(PersistFault::LostApply);
                let _ = backend.write_durable(full_batch);
            }
            present = key_states(&backend, cf)?;
        }
        let reopened = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
        let reopened_present = key_states(&reopened, cf)?;
        let pre_batch: Vec<u8> = (0..fail_index).collect();
        let post_batch: Vec<u8> = (0..5).collect();
        assert!(
            reopened_present == pre_batch || reopened_present == post_batch,
            "fail_index {fail_index} reopened a torn state with keys {reopened_present:?} \
             present; expected exactly {pre_batch:?} or {post_batch:?}"
        );
        assert_eq!(present, pre_batch);
        assert_eq!(reopened_present, present);
    }
    assert!(
        wrote_keys_before_fault,
        "no fail_index run observed written keys before its fault"
    );
    Ok(())
}

fn validating_head(commit_id: u64, height: u32) -> DurableHead {
    DurableHead {
        assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Validating {
            base_height: 2,
            base_hash: Hash256::from_le_bytes(&[0xB1; 32]),
            expected_hash_serialized: Hash256::from_le_bytes(&[0xB2; 32]),
            chain_tx_count: 3,
            historical_height: 0,
            historical_hash: Hash256::default(),
            pending: None,
            checkpoint: None,
        },
        commit_id,
        height,
        tip: Hash256::from_le_bytes(&[0xB0; 32]),
        chain_tx_count: 10,
        body_extent: None,
        undo_extent: None,
    }
}

#[test]
fn rocksdb_suffix_attestation_tracks_only_pending_validation_commits() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let family = open_store(temp.path())?;
    let base = validating_head(1, 2);
    commit(&family.authority, None, &base, CommitRecords::default())?;
    assert_eq!(
        family.head.load_suffix_attestation(&base)?,
        ScriptAttestation::Full,
        "installing the base leaves no suffix commit to distrust"
    );
    let skipped = validating_head(2, 3);
    commit(
        &family.authority,
        Some(&base),
        &skipped,
        CommitRecords {
            attestation: Some(ScriptAttestation::AssumeValid),
            ..CommitRecords::default()
        },
    )?;
    assert_eq!(
        family.head.load_suffix_attestation(&skipped)?,
        ScriptAttestation::AssumeValid
    );
    let executed = validating_head(3, 4);
    commit(
        &family.authority,
        Some(&skipped),
        &executed,
        CommitRecords {
            attestation: Some(ScriptAttestation::Full),
            ..CommitRecords::default()
        },
    )?;
    assert_eq!(
        family.head.load_suffix_attestation(&executed)?,
        ScriptAttestation::AssumeValid,
        "a commit never raises the weakest suffix level"
    );
    let progress = validating_head(4, 4);
    commit(
        &family.authority,
        Some(&executed),
        &progress,
        CommitRecords::default(),
    )?;
    assert_eq!(
        family.head.load_suffix_attestation(&progress)?,
        ScriptAttestation::AssumeValid,
        "a status-only commit keeps the suffix level"
    );
    let finalized = head(5, 4);
    commit(
        &family.authority,
        Some(&progress),
        &finalized,
        CommitRecords::default(),
    )?;
    assert_eq!(
        family.head.load_suffix_attestation(&finalized)?,
        ScriptAttestation::Unattested,
        "the suffix row names only a pending-validation head"
    );
    Ok(())
}

// RCV-02, RCV-08
#[test]
fn a_disconnect_carries_the_attestation_to_the_new_commit() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let first = head(1, 1);
    let disconnected = head(2, 2);
    let back = head(3, 1);
    {
        let family = open_store(temp.path())?;
        commit(
            &family.authority,
            None,
            &first,
            batch_of(ScriptAttestation::Full),
        )?;
        commit(
            &family.authority,
            Some(&first),
            &disconnected,
            CommitRecords::default(),
        )?;
        disconnect(&family.authority, &disconnected, &back)?;
    }
    let reopened = open_store(temp.path())?;
    assert_eq!(reopened.head.load()?, Some(back));
    assert_eq!(
        reopened.head.load_attestation(&back)?,
        ScriptAttestation::Full,
        "a disconnect re-labels the previous attestation under the new commit id"
    );
    Ok(())
}

// RCV-02, RCV-08
#[test]
fn a_disconnect_carries_the_suffix_attestation_to_the_new_commit() -> Result<(), StorageError> {
    let temp = tempfile::tempdir()?;
    let base = validating_head(1, 2);
    let skipped = validating_head(2, 3);
    let back = validating_head(3, 2);
    {
        let family = open_store(temp.path())?;
        commit(&family.authority, None, &base, CommitRecords::default())?;
        commit(
            &family.authority,
            Some(&base),
            &skipped,
            batch_of(ScriptAttestation::AssumeValid),
        )?;
        disconnect(&family.authority, &skipped, &back)?;
    }
    let reopened = open_store(temp.path())?;
    assert_eq!(reopened.head.load()?, Some(back));
    assert_eq!(
        reopened.head.load_suffix_attestation(&back)?,
        ScriptAttestation::AssumeValid,
        "a disconnect re-labels the suffix level under the new commit id"
    );
    Ok(())
}

fn key_states(
    store: &Arc<bitcoin_rs_storage::RocksDbStore>,
    cf: bitcoin_rs_storage::ColumnFamily,
) -> Result<Vec<u8>, StorageError> {
    let mut present = Vec::new();
    for i in 0..5_u8 {
        let value = store.get(cf, &[i])?;
        if let Some(bytes) = value {
            assert_eq!(bytes.as_slice(), &[i, i][..], "key {i} holds torn bytes");
            present.push(i);
        }
    }
    Ok(present)
}
