use super::*;
use proptest::prelude::*;
use crate::test_support::{TestError, TestResult};

fn test_hash(byte: u8) -> Hash256 {
    Hash256::from_le_bytes(&[byte; 32])
}

#[cfg(feature = "redb")]
#[test]
fn a_deferred_undo_record_is_readable_before_any_flush() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(crate::RedbStore::open(dir.path())?);
    let undo_store = KvUndoStore::new(Arc::clone(&store));
    let hash = Hash256::from_le_bytes(&[0x4d; 32]);

    undo_store.persist_undo(4_242, hash, b"undo-record")?;

    let loaded = undo_store
        .load_undo(4_242, hash)?
        .ok_or(TestError::Missing("undo record must be readable in-process before any flush"))?;
    assert_eq!(
        loaded, b"undo-record",
        "the deferred write must return exactly what was written"
    );
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn an_armed_disconnect_marker_survives_closing_and_reopening_the_store()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let block_hash = Hash256::from_le_bytes(&[0xa7; 32]);

    {
        let store = Arc::new(crate::FjallStore::open(dir.path())?);
        KvUndoStore::new(store).arm_disconnect(140_003, block_hash)?;
    }

    let reopened = Arc::new(crate::FjallStore::open(dir.path())?);
    let marker = KvUndoStore::new(Arc::clone(&reopened))
        .load_disconnect_marker()?
        .ok_or(TestError::Missing("armed marker did not survive the reopen"))?;
    assert_eq!(marker.hash, block_hash, "hash must round-trip");
    assert_eq!(marker.height, 140_003, "height must round-trip");
    assert_eq!(
        marker.phase,
        DisconnectPhase::InFlight,
        "arming records an unfinished rollback"
    );

    assert!(matches!(
        KvUndoStore::new(Arc::clone(&reopened)).disarm_disconnect(),
        Err(StorageError::InvalidOperation(_))
    ));
    assert!(
        KvUndoStore::new(Arc::clone(&reopened))
            .load_disconnect_marker()?
            .is_some(),
        "a checkpoint must not clear an in-flight marker"
    );

    KvUndoStore::new(Arc::clone(&reopened)).complete_disconnect(140_003, block_hash)?;
    KvUndoStore::new(Arc::clone(&reopened)).disarm_disconnect()?;
    drop(reopened);
    let after = Arc::new(crate::FjallStore::open(dir.path())?);
    assert_eq!(
        KvUndoStore::new(after).load_disconnect_marker()?,
        None,
        "a completed rollback must clear and stay cleared across a reopen"
    );
    Ok(())
}

#[test]
fn a_truncated_disconnect_marker_is_an_error_not_an_absence() {
    let Err(error) = DisconnectMarker::decode(&[0_u8; 20]) else {
        panic!("a 20-byte marker must not decode as absent");
    };
    assert!(
        error.to_string().contains("expected 37"),
        "error must say what it expected, got: {error}"
    );
}

// EVT-05
#[test]
fn a_marker_row_with_a_trailing_byte_is_an_error_not_a_truncation() {
    let mut row = DisconnectMarker {
        hash: test_hash(0x31),
        height: 8_400_000,
        phase: DisconnectPhase::InFlight,
    }
    .encode()
    .to_vec();
    row.push(0);

    assert!(
        matches!(
            DisconnectMarker::decode(&row),
            Err(StorageError::Backend(_))
        ),
        "the marker row is exactly 37 bytes, so a 38-byte row is corrupt evidence; decoders that ignore trailing bytes would accept a row this format never writes"
    );
}

// EVT-05
#[test]
fn an_unknown_disconnect_phase_byte_is_an_error() {
    for phase in 2_u8..=u8::MAX {
        let mut row = DisconnectMarker {
            hash: test_hash(0x32),
            height: 1,
            phase: DisconnectPhase::RolledBack,
        }
        .encode();
        row[36] = phase;

        assert!(
            matches!(
                DisconnectMarker::decode(&row),
                Err(StorageError::Backend(_))
            ),
            "phase byte {phase} is outside the format's 0 and 1; reading it as a phase would invent recovery evidence"
        );
    }
}

proptest! {
    // EVT-05
    #[test]
    fn every_accepted_marker_row_re_encodes_to_the_same_bytes(
        hash_bytes in proptest::array::uniform32(any::<u8>()),
        height in any::<u32>(),
        phase_byte in 0_u8..=1,
    ) {
        let mut row = Vec::with_capacity(37);
        row.extend_from_slice(&hash_bytes);
        row.extend_from_slice(&height.to_be_bytes());
        row.push(phase_byte);

        let marker = DisconnectMarker::decode(&row)
            .expect("phase 0 and 1 rows are the format's accepted marker shape");
        prop_assert_eq!(marker.height, height);
        let reencoded = marker.encode();
        prop_assert_eq!(
            reencoded.as_slice(),
            row.as_slice(),
            "a decoded marker must re-encode to the bytes it came from, so no accepted row decodes to a different marker than it encodes"
        );
    }
}

// RCV-15
#[cfg(feature = "fjall")]
#[test]
fn a_corrupt_marker_row_fails_closed_and_stays_on_disk() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(crate::FjallStore::open(dir.path())?);
    store.put(ColumnFamily::UtxoMeta, DISCONNECT_MARKER_KEY, b"short")?;

    let outcome = KvUndoStore::new(Arc::clone(&store)).load_disconnect_marker();

    assert!(
        matches!(outcome, Err(StorageError::Backend(_))),
        "a 5-byte row is corrupt evidence; reporting absence would let recovery publish a checkpoint over an unfinished rollback"
    );
    assert_eq!(
        store.get(ColumnFamily::UtxoMeta, DISCONNECT_MARKER_KEY)?,
        Some(b"short".to_vec()),
        "a refused read must leave the evidence for the operator instead of deleting it"
    );
    Ok(())
}

// RCV-03
#[test]
fn undo_rows_for_two_blocks_at_one_height_never_alias() -> Result<(), StorageError> {
    let store = InMemoryUndoStore::default();
    let active = test_hash(0xaa);
    let side = test_hash(0xbb);

    store.persist_undo(120, active, b"active")?;
    store.persist_undo(120, side, b"side")?;

    assert_eq!(
        store.load_undo(120, active)?,
        Some(b"active".to_vec()),
        "the active branch must read back its own record"
    );
    assert_eq!(
        store.load_undo(120, side)?,
        Some(b"side".to_vec()),
        "a side branch at the active height must keep its own record, or a replay would undo the active branch's spends"
    );
    assert_eq!(
        store.load_undo(120, test_hash(0xcc))?,
        None,
        "a branch with no record must read as absent instead of borrowing another branch's record"
    );
    assert_ne!(
        block_undo_key(120, active),
        block_undo_key(120, side),
        "the two branches must occupy distinct keys"
    );
    Ok(())
}

// EVT-05
#[test]
fn a_rollback_completion_cannot_rewrite_a_marker_for_another_block() {
    let store = InMemoryUndoStore::default();
    store
        .arm_disconnect(700, test_hash(0x70))
        .expect("arming an in-flight marker succeeds");

    let outcome = store.complete_disconnect(701, test_hash(0x71));

    assert!(
        matches!(outcome, Err(StorageError::InvalidOperation(_))),
        "completing a rollback for any block but the armed one must refuse; accepting it would downgrade the real in-flight marker to RolledBack, and ordinary checkpoint publication clears RolledBack"
    );
    assert_eq!(
        store.load_disconnect_marker().expect("marker reads"),
        Some(DisconnectMarker {
            hash: test_hash(0x70),
            height: 700,
            phase: DisconnectPhase::InFlight,
        }),
        "the armed marker must keep its identity after the refusal"
    );
}

// EVT-05
#[test]
fn an_unarmed_rollback_completion_is_refused() {
    let store = InMemoryUndoStore::default();

    let outcome = store.complete_disconnect(700, test_hash(0x70));

    assert!(
        matches!(outcome, Err(StorageError::InvalidOperation(_))),
        "no disconnect was armed, so a completion has no rollback to attest and would fabricate recovery evidence"
    );
    assert_eq!(
        store.load_disconnect_marker().expect("marker reads"),
        None,
        "a refused completion must not create a marker"
    );
}

// EVT-05
#[test]
fn a_repeated_rollback_completion_for_the_same_block_succeeds() -> Result<(), StorageError> {
    let store = InMemoryUndoStore::default();
    store.arm_disconnect(700, test_hash(0x70))?;
    store.complete_disconnect(700, test_hash(0x70))?;

    store.complete_disconnect(700, test_hash(0x70))?;

    assert_eq!(
        store.load_disconnect_marker()?,
        Some(DisconnectMarker {
            hash: test_hash(0x70),
            height: 700,
            phase: DisconnectPhase::RolledBack,
        }),
        "retrying an interrupted completion for the same rollback must stay accepted"
    );
    Ok(())
}

// RCV-15
#[cfg(feature = "fjall")]
#[test]
fn disarming_an_absent_marker_is_a_no_op() -> TestResult {
    let dir = tempfile::tempdir()?;
    let undo = KvUndoStore::new(Arc::new(crate::FjallStore::open(dir.path())?));

    undo.disarm_disconnect()?;

    assert_eq!(
        undo.load_disconnect_marker()?,
        None,
        "no marker existed, so disarm must leave the store without one"
    );
    Ok(())
}

// EVT-05
#[cfg(feature = "fjall")]
#[test]
fn a_backend_marker_cannot_be_completed_for_another_block() -> TestResult
{
    let dir = tempfile::tempdir()?;
    let undo = KvUndoStore::new(Arc::new(crate::FjallStore::open(dir.path())?));
    undo.arm_disconnect(700, test_hash(0x70))?;

    let outcome = undo.complete_disconnect(701, test_hash(0x71));

    assert!(
        matches!(outcome, Err(StorageError::InvalidOperation(_))),
        "the durable marker must refuse a completion that names another block, exactly like the in-memory one"
    );
    assert_eq!(
        undo.load_disconnect_marker()?,
        Some(DisconnectMarker {
            hash: test_hash(0x70),
            height: 700,
            phase: DisconnectPhase::InFlight,
        }),
        "the durable marker must keep its identity after the refusal"
    );
    Ok(())
}

#[cfg(feature = "fjall")]
struct ArmOnMarkerRead {
    inner: Arc<crate::FjallStore>,
    next: parking_lot::Mutex<Option<(u32, Hash256)>>,
}

#[cfg(feature = "fjall")]
impl ArmOnMarkerRead {
    fn new(inner: Arc<crate::FjallStore>) -> Self {
        Self {
            inner,
            next: parking_lot::Mutex::new(None),
        }
    }

    fn arm_on_next_marker_read(&self, height: u32, hash: Hash256) {
        *self.next.lock() = Some((height, hash));
    }
}

#[cfg(feature = "fjall")]
impl KvStore for ArmOnMarkerRead {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let observed = self.inner.get(cf, key)?;
        if cf == ColumnFamily::UtxoMeta
            && key == DISCONNECT_MARKER_KEY
            && let Some((height, hash)) = self.next.lock().take()
        {
            let mut batch = self.inner.new_batch();
            batch.put(
                ColumnFamily::UtxoMeta,
                DISCONNECT_MARKER_KEY,
                &DisconnectMarker {
                    hash,
                    height,
                    phase: DisconnectPhase::InFlight,
                }
                .encode(),
            );
            self.inner.write(batch)?;
        }
        Ok(observed)
    }

    fn get_bounded(
        &self,
        cf: ColumnFamily,
        key: &[u8],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        self.inner.get_bounded(cf, key, max_bytes)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<crate::KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        self.inner
            .scan_prefix_from_bounded(cf, prefix, start, limit)
    }

    fn new_batch(&self) -> crate::BufferedWriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: crate::BufferedWriteBatch) -> Result<(), StorageError> {
        self.inner.write(batch)
    }

    fn write_deferred(&self, batch: crate::BufferedWriteBatch) -> Result<(), StorageError> {
        self.inner.write_deferred(batch)
    }

    fn write_durable_if(
        &self,
        conditions: &[crate::WriteCondition<'_>],
        batch: crate::BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        self.inner.write_durable_if(conditions, batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.inner.flush()
    }

    fn snapshot(&self) -> Result<Box<dyn crate::KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }

    fn arm_persist_fault(&self, fault: crate::PersistFault) {
        self.inner.arm_persist_fault(fault);
    }
}

// EVT-05
#[cfg(feature = "fjall")]
#[test]
fn a_disconnect_armed_while_the_marker_is_disarmed_survives()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let inner = Arc::new(crate::FjallStore::open(dir.path())?);
    let gated = Arc::new(ArmOnMarkerRead::new(Arc::clone(&inner)));
    let undo = KvUndoStore::new(Arc::clone(&gated));
    undo.arm_disconnect(90, test_hash(0x90))?;
    undo.complete_disconnect(90, test_hash(0x90))?;
    gated.arm_on_next_marker_read(91, test_hash(0x91));

    let outcome = undo.disarm_disconnect();

    assert!(
        matches!(outcome, Err(StorageError::InvalidOperation(_))),
        "a marker armed between the read and the clear must refuse the clear; deleting it would drop the only evidence of an unfinished rollback"
    );
    assert_eq!(
        undo.load_disconnect_marker()?,
        Some(DisconnectMarker {
            hash: test_hash(0x91),
            height: 91,
            phase: DisconnectPhase::InFlight,
        }),
        "the newly armed marker must survive the refused disarm"
    );
    Ok(())
}
