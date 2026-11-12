use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin_rs_consensus::primitives::Hash256;
use bytes::Bytes;

use crate::block_file::BlockFilePosition;
use crate::coins::{CoinStore, WindowDelta};
use crate::durable_head::{
    DURABLE_HEAD_KEY, DurableHead, SCRIPT_ATTESTATION_KEY, SCRIPT_ATTESTATION_SUFFIX_KEY,
    ScriptAttestation,
};
use crate::pruning::{BLOCK_DATA_CF, block_body_key};
use crate::undo::block_undo_key;
use crate::{ColumnFamily, KvStore, StorageError, WriteCondition};

/// Receipt certifying that an accepted prefix has committed durably.
///
/// Only [`CommitAuthority`] issues a receipt: the fields are private and the
/// only constructor is crate-private, so a caller cannot fabricate one. Every
/// receipt a caller holds was returned by a durable commit (MOD-02).
///
/// ```compile_fail
/// use bitcoin_rs_consensus::primitives::Hash256;
/// let _receipt = bitcoin_rs_storage::DurableReceipt {
///     commit_id: 1,
///     height: 1,
///     tip: Hash256::from_le_bytes(&[0_u8; 32]),
///     chain_tx_count: 1,
/// };
/// ```
// MOD-02
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableReceipt {
    commit_id: u64,
    height: u32,
    tip: Hash256,
    chain_tx_count: u64,
}

impl DurableReceipt {
    #[must_use]
    pub const fn commit_id(&self) -> u64 {
        self.commit_id
    }

    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    #[must_use]
    pub const fn tip(&self) -> Hash256 {
        self.tip
    }

    #[must_use]
    pub const fn chain_tx_count(&self) -> u64 {
        self.chain_tx_count
    }

    #[must_use]
    pub(crate) const fn from_head(head: &DurableHead) -> Self {
        Self {
            commit_id: head.commit_id,
            height: head.height,
            tip: head.tip,
            chain_tx_count: head.chain_tx_count,
        }
    }
}

/// Staged data for a valid prefix of blocks ready for atomic commit.
#[derive(Clone, Debug)]
pub struct AcceptedPrefix {
    pub expected_head: Option<DurableHead>,
    pub next_head: DurableHead,
    pub undo_rows: Vec<(u32, Hash256, Bytes)>,
    pub body_rows: Vec<(u32, Hash256, BlockFilePosition)>,
    pub attestation: Option<ScriptAttestation>,
    pub coin_delta: WindowDelta,
}

#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    #[error("mutation admission is closed due to a prior ambiguous storage failure")]
    AdmissionClosed,
    #[error("durable head moved since it was read")]
    PreconditionFailed,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Test-only injection point for durable-commit failures and kill points.
///
/// `before_commit` runs before the atomic batch is built so an injected
/// failure leaves the engine exactly at the previous committed prefix, on
/// every engine. `after_commit` runs once the batch is durable and before the
/// receipt returns, matching a crash between durability and publication.
#[cfg(any(test, feature = "test-seam"))]
pub trait CommitFault: Send + Sync {
    fn before_commit(&self, prefix: &AcceptedPrefix) -> Result<(), CommitError> {
        let _ = prefix;
        Ok(())
    }

    fn after_commit(&self, prefix: &AcceptedPrefix, receipt: &DurableReceipt) {
        let _ = (prefix, receipt);
    }
}

/// Single commit authority for canonical chain mutation (CMT-01).
pub struct CommitAuthority {
    store: Arc<dyn KvStore>,
    coins: Arc<CoinStore>,
    admission_closed: AtomicBool,
    #[cfg(any(test, feature = "test-seam"))]
    fault: parking_lot::Mutex<Option<Arc<dyn CommitFault>>>,
}

impl CommitAuthority {
    pub fn new(store: Arc<dyn KvStore>, coins: Arc<CoinStore>) -> Self {
        Self {
            store,
            coins,
            admission_closed: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-seam"))]
            fault: parking_lot::Mutex::new(None),
        }
    }

    #[must_use]
    pub fn is_admission_closed(&self) -> bool {
        self.admission_closed.load(Ordering::Acquire)
    }

    pub fn close_admission(&self) {
        self.admission_closed.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn coins(&self) -> &Arc<CoinStore> {
        &self.coins
    }

    #[must_use]
    pub fn store(&self) -> &Arc<dyn KvStore> {
        &self.store
    }

    pub fn in_flight_snapshot_activation(
        &self,
    ) -> Result<Option<crate::snapshot_activation::SnapshotActivationMarker>, StorageError> {
        use crate::snapshot_activation::{SNAPSHOT_ACTIVATION_KEY, SnapshotActivationMarker};

        let Some(marker_bytes) = self
            .store
            .get(ColumnFamily::UtxoMeta, SNAPSHOT_ACTIVATION_KEY)?
        else {
            return Ok(None);
        };
        SnapshotActivationMarker::decode(&marker_bytes)
            .map(Some)
            .ok_or_else(|| {
                StorageError::IncompatibleData(
                    "snapshot activation marker is unreadable; refusing to treat it as absent"
                        .to_owned(),
                )
            })
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn set_fault(&self, fault: Arc<dyn CommitFault>) {
        *self.fault.lock() = Some(fault);
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn clear_fault(&self) {
        *self.fault.lock() = None;
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn check_fault(&self, prefix: &AcceptedPrefix) -> Result<(), CommitError> {
        let fault = self.fault.lock().clone();
        match fault {
            Some(fault) => fault.before_commit(prefix),
            None => Ok(()),
        }
    }

    /// One atomic engine batch: head, attestation, undo rows, body index, coins
    /// (TLA `CommitBatch`, RCV-02, CMT-01, CMT-02 step 4).
    ///
    /// Cache install runs strictly after durable success (TLA `InstallCache`, CMT-02 step 5, CMT-03).
    /// Ambiguous storage failures close admission permanently (TLA `FailAmbiguous`, CMT-04).
    ///
    /// The parameter is the accepted-prefix type, never a plain block (MOD-02):
    ///
    /// ```compile_fail
    /// use bitcoin_rs_storage::{CommitAuthority, AcceptedPrefix};
    /// fn commit_image(
    ///     authority: &CommitAuthority,
    ///     image: bitcoin_rs_consensus::primitives::BlockImage,
    /// ) {
    ///     let _ = authority.commit_prefix(image);
    /// }
    /// ```
    pub fn commit_prefix(&self, prefix: AcceptedPrefix) -> Result<DurableReceipt, CommitError> {
        if self.is_admission_closed() {
            return Err(CommitError::AdmissionClosed);
        }
        #[cfg(any(test, feature = "test-seam"))]
        self.check_fault(&prefix)?;

        let mut batch = self.store.new_batch();
        self.stage_commit_rows(&mut batch, &prefix)?;
        let stats_feed = self.coins.plan_stats_feed(&prefix.coin_delta)?;
        let fence = self.head_fence(prefix.expected_head.as_ref())?;
        batch.put(
            ColumnFamily::UtxoMeta,
            DURABLE_HEAD_KEY,
            &prefix.next_head.encode(),
        );

        let write_result = self.store.write_durable_if(&[fence.as_condition()], batch);
        match write_result {
            Ok(true) => {
                #[cfg(any(test, feature = "test-seam"))]
                self.notify_commit(&prefix);
                self.coins.install_committed(&prefix.coin_delta, stats_feed);
                Ok(DurableReceipt::from_head(&prefix.next_head))
            }
            Ok(false) => Err(CommitError::PreconditionFailed),
            Err(err) => {
                self.close_admission();
                Err(CommitError::Storage(err))
            }
        }
    }

    /// Commit the snapshot-activation head and clear the activation marker in
    /// the same atomic batch (CMT-01).
    ///
    /// The staged snapshot coins were ingested under marker protection; this
    /// batch is the only step that publishes them, so a crash either leaves
    /// the marker (recovery wipes the coins) or lands head and marker clear
    /// together.
    pub fn commit_snapshot_activation(
        &self,
        prefix: AcceptedPrefix,
        marker: &crate::snapshot_activation::SnapshotActivationMarker,
    ) -> Result<DurableReceipt, CommitError> {
        use crate::snapshot_activation::SNAPSHOT_ACTIVATION_KEY;

        if self.is_admission_closed() {
            return Err(CommitError::AdmissionClosed);
        }
        #[cfg(any(test, feature = "test-seam"))]
        self.check_fault(&prefix)?;

        let marker_frame = marker.encode();
        let stored_marker = self
            .store
            .get(ColumnFamily::UtxoMeta, SNAPSHOT_ACTIVATION_KEY)?
            .ok_or(CommitError::PreconditionFailed)?;
        if stored_marker.as_slice() != marker_frame.as_slice() {
            return Err(CommitError::PreconditionFailed);
        }

        let mut batch = self.store.new_batch();
        self.stage_commit_rows(&mut batch, &prefix)?;
        let stats_feed = self.coins.plan_stats_feed(&prefix.coin_delta)?;
        let fence = self.head_fence(prefix.expected_head.as_ref())?;
        batch.put(
            ColumnFamily::UtxoMeta,
            DURABLE_HEAD_KEY,
            &prefix.next_head.encode(),
        );
        batch.delete(ColumnFamily::UtxoMeta, SNAPSHOT_ACTIVATION_KEY);

        let conditions = [
            fence.as_condition(),
            WriteCondition::Equals {
                cf: ColumnFamily::UtxoMeta,
                key: SNAPSHOT_ACTIVATION_KEY,
                expected: &marker_frame,
            },
        ];
        let write_result = self.store.write_durable_if(&conditions, batch);
        match write_result {
            Ok(true) => {
                #[cfg(any(test, feature = "test-seam"))]
                self.notify_commit(&prefix);
                self.coins.install_committed(&prefix.coin_delta, stats_feed);
                Ok(DurableReceipt::from_head(&prefix.next_head))
            }
            Ok(false) => Err(CommitError::PreconditionFailed),
            Err(err) => {
                self.close_admission();
                Err(CommitError::Storage(err))
            }
        }
    }

    /// Write the durable activation marker under the current-head fence.
    ///
    /// Must be called before any snapshot coin ingest so a restart can tell an
    /// interrupted ingest from a completed activation.
    pub fn begin_snapshot_activation(
        &self,
        expected: Option<&DurableHead>,
        marker: &crate::snapshot_activation::SnapshotActivationMarker,
    ) -> Result<(), CommitError> {
        use crate::snapshot_activation::SNAPSHOT_ACTIVATION_KEY;

        if self.is_admission_closed() {
            return Err(CommitError::AdmissionClosed);
        }
        let fence = self.head_fence(expected)?;
        let mut batch = self.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            SNAPSHOT_ACTIVATION_KEY,
            &marker.encode(),
        );
        match self.store.write_durable_if(&[fence.as_condition()], batch) {
            Ok(true) => Ok(()),
            Ok(false) => Err(CommitError::PreconditionFailed),
            Err(err) => {
                self.close_admission();
                Err(CommitError::Storage(err))
            }
        }
    }

    /// Reconcile an interrupted snapshot activation at boot (CMT-03).
    ///
    /// A marker without its activation head means the coin ingest was
    /// interrupted: the staged coins are wiped before anything reads the
    /// coins keyspace and the marker is handed back to the caller. The
    /// caller clears the marker with [`Self::clear_snapshot_activation_marker`]
    /// only after the out-of-band rollback cleanup (the orphan snapshot-base
    /// checkpoint removal) succeeds, so a failed cleanup keeps the marker
    /// durable and the next restart re-runs the rollback instead of adopting
    /// an uncommitted checkpoint. Calling this again after a partial
    /// rollback is idempotent: the coins are wiped again and the same marker
    /// is returned. A marker whose base hash matches the durable head is
    /// corruption, because the head commit clears the marker atomically.
    pub fn recover_snapshot_activation(
        &self,
    ) -> Result<Option<crate::snapshot_activation::SnapshotActivationMarker>, CommitError> {
        let outcome = self.recover_snapshot_activation_inner();
        if let Err(CommitError::Storage(_)) = &outcome {
            self.close_admission();
        }
        outcome
    }

    /// Durably clear the activation marker after the rollback cleanup
    /// succeeded. Absent-marker no-ops are fine: this runs only after
    /// [`Self::recover_snapshot_activation`] returned a marker.
    pub fn clear_snapshot_activation_marker(&self) -> Result<(), CommitError> {
        use crate::snapshot_activation::SNAPSHOT_ACTIVATION_KEY;

        let mut batch = self.store.new_batch();
        batch.delete(ColumnFamily::UtxoMeta, SNAPSHOT_ACTIVATION_KEY);
        match self.store.write_durable_if(&[], batch) {
            Ok(_) => Ok(()),
            Err(err) => {
                self.close_admission();
                Err(CommitError::Storage(err))
            }
        }
    }

    fn recover_snapshot_activation_inner(
        &self,
    ) -> Result<Option<crate::snapshot_activation::SnapshotActivationMarker>, CommitError> {
        use crate::snapshot_activation::{SNAPSHOT_ACTIVATION_KEY, SnapshotActivationMarker};

        let Some(marker_bytes) = self
            .store
            .get(ColumnFamily::UtxoMeta, SNAPSHOT_ACTIVATION_KEY)?
        else {
            return Ok(None);
        };
        let marker = SnapshotActivationMarker::decode(&marker_bytes).ok_or_else(|| {
            CommitError::Storage(StorageError::IncompatibleData(
                "snapshot activation marker is unreadable; refusing to treat it as absent"
                    .to_owned(),
            ))
        })?;
        let fence = self.head_fence(None)?;
        if let HeadFence {
            expected: Some(bytes),
            ..
        } = &fence
        {
            let stored_head = DurableHead::decode(bytes).ok_or_else(|| {
                CommitError::Storage(StorageError::IncompatibleData(
                    "durable head row is unreadable; refusing to treat it as absent".to_owned(),
                ))
            })?;
            if stored_head.tip == marker.base_hash {
                return Err(CommitError::Storage(StorageError::IncompatibleData(
                    "activation marker survived its own head commit".to_owned(),
                )));
            }
        }
        self.coins.wipe()?;
        Ok(Some(marker))
    }

    /// The stored head bytes as a write fence, refusing a stale caller view.
    fn head_fence(&self, expected: Option<&DurableHead>) -> Result<HeadFence, CommitError> {
        let stored = self.store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?;
        match (stored, expected) {
            (Some(bytes), Some(current)) => {
                if current.encode().as_slice() != bytes.as_slice() {
                    return Err(CommitError::PreconditionFailed);
                }
                Ok(HeadFence {
                    expected: Some(bytes),
                })
            }
            (Some(bytes), None) => Ok(HeadFence {
                expected: Some(bytes),
            }),
            (None, Some(_)) | (None, None) => Ok(HeadFence { expected: None }),
        }
    }

    fn stage_commit_rows(
        &self,
        batch: &mut crate::batch::BufferedWriteBatch,
        prefix: &AcceptedPrefix,
    ) -> Result<(), CommitError> {
        self.stage_attestation_rows(
            batch,
            prefix.expected_head.as_ref(),
            &prefix.next_head,
            prefix.attestation,
        )?;

        for (height, hash, record) in &prefix.undo_rows {
            batch.put(
                ColumnFamily::UndoData,
                &block_undo_key(*height, *hash),
                record,
            );
        }

        let mut file_heights = std::collections::BTreeMap::<u32, u32>::new();
        for (height, hash, position) in &prefix.body_rows {
            batch.put(
                BLOCK_DATA_CF,
                &block_body_key(*height, *hash),
                &position.encode(),
            );
            file_heights
                .entry(position.file_no)
                .and_modify(|maximum| *maximum = (*maximum).max(*height))
                .or_insert(*height);
        }
        for (file_no, maximum) in file_heights {
            let key = crate::block_file_max_height_key(file_no);
            let prior = self.store.get(BLOCK_DATA_CF, &key)?;
            let maximum = match prior {
                Some(bytes) => crate::decode_block_file_max_height(&bytes)
                    .ok_or_else(|| {
                        StorageError::IncompatibleData(
                            "invalid block-file maximum height".to_owned(),
                        )
                    })?
                    .max(maximum),
                None => maximum,
            };
            batch.put(
                BLOCK_DATA_CF,
                &key,
                &crate::encode_block_file_max_height(maximum),
            );
        }

        self.coins.append_window(batch, &prefix.coin_delta)?;
        Ok(())
    }

    fn stage_attestation_rows(
        &self,
        batch: &mut crate::batch::BufferedWriteBatch,
        expected_head: Option<&DurableHead>,
        next_head: &DurableHead,
        batch_attestation: Option<ScriptAttestation>,
    ) -> Result<(), CommitError> {
        let previous = match expected_head {
            Some(current) => self.load_attestation(current)?,
            None => ScriptAttestation::Full,
        };
        let attestation = batch_attestation.map_or(previous, |batch| previous.min(batch));
        batch.put(
            ColumnFamily::UtxoMeta,
            SCRIPT_ATTESTATION_KEY,
            &attestation.row(next_head.commit_id),
        );
        if let Some((level, commit_id)) =
            self.suffix_row(expected_head, next_head, batch_attestation)?
        {
            batch.put(
                ColumnFamily::UtxoMeta,
                SCRIPT_ATTESTATION_SUFFIX_KEY,
                &level.row(commit_id),
            );
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-seam"))]
    fn notify_commit(&self, prefix: &AcceptedPrefix) {
        let receipt = DurableReceipt::from_head(&prefix.next_head);
        let fault = self.fault.lock().clone();
        if let Some(fault) = fault {
            fault.after_commit(prefix, &receipt);
        }
    }
    /// Commit a chain disconnection durably.
    pub fn commit_disconnect(
        &self,
        expected_head: &DurableHead,
        next_head: &DurableHead,
        coin_delta: WindowDelta,
    ) -> Result<DurableReceipt, CommitError> {
        if self.is_admission_closed() {
            return Err(CommitError::AdmissionClosed);
        }
        let stored_bytes = self.store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?;
        let condition = match &stored_bytes {
            Some(bytes) => {
                if expected_head.encode() != bytes.as_slice() {
                    return Err(CommitError::PreconditionFailed);
                }
                WriteCondition::Equals {
                    cf: ColumnFamily::UtxoMeta,
                    key: DURABLE_HEAD_KEY,
                    expected: bytes,
                }
            }
            None => WriteCondition::Absent {
                cf: ColumnFamily::UtxoMeta,
                key: DURABLE_HEAD_KEY,
            },
        };
        let mut batch = self.store.new_batch();
        self.stage_attestation_rows(&mut batch, Some(expected_head), next_head, None)?;
        batch.put(
            ColumnFamily::UtxoMeta,
            DURABLE_HEAD_KEY,
            &next_head.encode(),
        );
        self.coins.append_window(&mut batch, &coin_delta)?;
        let stats_feed = self.coins.plan_stats_feed(&coin_delta)?;
        let write_result = self.store.write_durable_if(&[condition], batch);
        match write_result {
            Ok(true) => {
                self.coins.install_committed(&coin_delta, stats_feed);
                Ok(DurableReceipt::from_head(next_head))
            }
            Ok(false) => Err(CommitError::PreconditionFailed),
            Err(err) => {
                self.close_admission();
                Err(CommitError::Storage(err))
            }
        }
    }

    /// Write a coin-only delta under the current head precondition.
    ///
    /// Used during boot rewind when the checkpoint image has coins ahead of
    /// the durable head. The head row is unchanged.
    pub fn rewind_coins(&self, coin_delta: &WindowDelta) -> Result<(), CommitError> {
        if self.is_admission_closed() {
            return Err(CommitError::AdmissionClosed);
        }
        let Some(head_bytes) = self.store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)? else {
            return Ok(());
        };
        let condition = WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: DURABLE_HEAD_KEY,
            expected: &head_bytes,
        };
        let mut batch = self.store.new_batch();
        batch.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &head_bytes);
        self.coins.append_window(&mut batch, coin_delta)?;
        let stats_feed = self.coins.plan_stats_feed(coin_delta)?;
        let write_result = self.store.write_durable_if(&[condition], batch);
        match write_result {
            Ok(true) => {
                self.coins.install_committed(coin_delta, stats_feed);
                Ok(())
            }
            Ok(false) => Err(CommitError::PreconditionFailed),
            Err(err) => {
                self.close_admission();
                Err(CommitError::Storage(err))
            }
        }
    }

    fn load_attestation(&self, head: &DurableHead) -> Result<ScriptAttestation, StorageError> {
        self.store
            .get(ColumnFamily::UtxoMeta, SCRIPT_ATTESTATION_KEY)?
            .map_or(Ok(ScriptAttestation::Unattested), |row| {
                ScriptAttestation::from_row(&row, head)
            })
    }

    fn load_suffix_attestation(
        &self,
        head: &DurableHead,
    ) -> Result<ScriptAttestation, StorageError> {
        self.store
            .get(ColumnFamily::UtxoMeta, SCRIPT_ATTESTATION_SUFFIX_KEY)?
            .map_or(Ok(ScriptAttestation::Unattested), |row| {
                ScriptAttestation::from_row(&row, head)
            })
    }

    fn suffix_row(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        attestation: Option<ScriptAttestation>,
    ) -> Result<Option<(ScriptAttestation, u64)>, StorageError> {
        if !matches!(
            next.assumeutxo,
            crate::assumeutxo::AssumeUtxoDiskStatus::Validating { .. }
        ) {
            return Ok(None);
        }
        let level = match expected {
            Some(current)
                if matches!(
                    current.assumeutxo,
                    crate::assumeutxo::AssumeUtxoDiskStatus::Validating { .. }
                ) =>
            {
                let previous = self.load_suffix_attestation(current)?;
                attestation.map_or(previous, |batch| previous.min(batch))
            }
            _ => ScriptAttestation::Full,
        };
        Ok(Some((level, next.commit_id)))
    }
}

/// The stored durable-head bytes held as a compare-and-write fence.
struct HeadFence {
    expected: Option<Vec<u8>>,
}

impl HeadFence {
    fn as_condition(&self) -> WriteCondition<'_> {
        match &self.expected {
            Some(bytes) => WriteCondition::Equals {
                cf: ColumnFamily::UtxoMeta,
                key: DURABLE_HEAD_KEY,
                expected: bytes,
            },
            None => WriteCondition::Absent {
                cf: ColumnFamily::UtxoMeta,
                key: DURABLE_HEAD_KEY,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // MOD-02
    #[test]
    fn receipts_are_issued_only_by_the_commit_authority() {
        let store: Arc<dyn KvStore> = Arc::new(crate::MemoryKvStore::new());
        let coins = Arc::new(CoinStore::open(Arc::clone(&store), 64 * 1024 * 1024));
        let authority = CommitAuthority::new(Arc::clone(&store), coins);
        let next = DurableHead {
            assumeutxo: crate::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 5,
            tip: Hash256::from_le_bytes(&[7_u8; 32]),
            chain_tx_count: 42,
            body_extent: None,
            undo_extent: None,
        };
        let receipt = authority
            .commit_prefix(AcceptedPrefix {
                expected_head: None,
                next_head: next,
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: WindowDelta::default(),
            })
            .unwrap_or_else(|error| panic!("first commit: {error}"));
        assert_eq!(receipt.commit_id(), 1);
        assert_eq!(receipt.height(), 5);
        assert_eq!(receipt.tip(), next.tip);
        assert_eq!(receipt.chain_tx_count(), 42);
        let row = store
            .get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)
            .unwrap_or_else(|error| panic!("head row: {error}"))
            .unwrap_or_else(|| panic!("head row is present"));
        let stored = DurableHead::decode(&row);
        assert_eq!(stored.as_ref(), Some(&next));
    }
}
