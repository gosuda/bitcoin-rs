use bitcoin_rs_consensus::primitives::Hash256;

use crate::assumeutxo::AssumeUtxoDiskStatus;

pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}
use crate::{ColumnFamily, KvStore, StorageError, WriteCondition};

pub const DURABLE_HEAD_KEY: &[u8] = b"node:durable-head";

pub const SCRIPT_ATTESTATION_KEY: &[u8] = b"node:script-attestation";
pub const SCRIPT_ATTESTATION_SUFFIX_KEY: &[u8] = b"node:script-attestation-suffix";

const SCRIPT_ATTESTATION_ROW_LEN: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScriptAttestation {
    Unattested,
    AssumeValid,
    Full,
}

impl ScriptAttestation {
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Unattested => 0,
            Self::AssumeValid => 1,
            Self::Full => 2,
        }
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Unattested),
            1 => Some(Self::AssumeValid),
            2 => Some(Self::Full),
            _ => None,
        }
    }

    pub(crate) fn row(self, commit_id: u64) -> [u8; SCRIPT_ATTESTATION_ROW_LEN] {
        let mut row = [0_u8; SCRIPT_ATTESTATION_ROW_LEN];
        row[..8].copy_from_slice(&commit_id.to_le_bytes());
        row[8] = self.byte();
        row
    }

    pub(crate) fn from_row(row: &[u8], head: &DurableHead) -> Result<Self, StorageError> {
        let corrupt =
            || StorageError::IncompatibleData("script attestation row is unreadable".to_owned());
        let row: &[u8; SCRIPT_ATTESTATION_ROW_LEN] = row.try_into().map_err(|_| corrupt())?;
        let commit_id = u64::from_le_bytes(row[..8].try_into().map_err(|_| corrupt())?);
        let level = Self::from_byte(row[8]).ok_or_else(corrupt)?;
        Ok(if commit_id == head.commit_id {
            level
        } else {
            Self::Unattested
        })
    }
}

pub const DURABLE_HEAD_FORMAT_VERSION: u8 = 4;

const DURABLE_HEAD_MAGIC: [u8; 4] = *b"BRSD";

const DURABLE_HEAD_PAYLOAD_LEN: usize = 102 + crate::assumeutxo::AssumeUtxoDiskStatus::ENCODED_LEN;

const DURABLE_HEAD_FRAME_LEN: usize = DURABLE_HEAD_MAGIC.len() + 1 + 4 + DURABLE_HEAD_PAYLOAD_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyExtent {
    pub file_no: u32,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableHead {
    pub assumeutxo: crate::assumeutxo::AssumeUtxoDiskStatus,
    pub commit_id: u64,
    pub height: u32,
    pub tip: Hash256,
    pub chain_tx_count: u64,
    pub body_extent: Option<BodyExtent>,
    pub undo_extent: Option<(u32, Hash256)>,
}

impl DurableHead {
    #[must_use]
    pub fn encode(&self) -> [u8; DURABLE_HEAD_FRAME_LEN] {
        let mut payload = [0_u8; DURABLE_HEAD_PAYLOAD_LEN];
        payload[0..8].copy_from_slice(&self.commit_id.to_be_bytes());
        payload[8..12].copy_from_slice(&self.height.to_be_bytes());
        payload[12..44].copy_from_slice(self.tip.as_byte_array());
        payload[44..52].copy_from_slice(&self.chain_tx_count.to_be_bytes());
        payload[52] = u8::from(self.body_extent.is_some());
        if let Some(extent) = self.body_extent {
            payload[53..57].copy_from_slice(&extent.file_no.to_be_bytes());
            payload[57..65].copy_from_slice(&extent.offset.to_be_bytes());
        }
        payload[65] = u8::from(self.undo_extent.is_some());
        if let Some((height, hash)) = self.undo_extent {
            payload[66..70].copy_from_slice(&height.to_be_bytes());
            payload[70..102].copy_from_slice(hash.as_byte_array());
        }
        payload[102..].copy_from_slice(&self.assumeutxo.encode());

        let mut frame = [0_u8; DURABLE_HEAD_FRAME_LEN];
        frame[..DURABLE_HEAD_MAGIC.len()].copy_from_slice(&DURABLE_HEAD_MAGIC);
        frame[DURABLE_HEAD_MAGIC.len()] = DURABLE_HEAD_FORMAT_VERSION;
        let checksum = crc32c(&payload);
        frame[5..9].copy_from_slice(&checksum.to_le_bytes());
        frame[9..].copy_from_slice(&payload);
        frame
    }

    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let header = DURABLE_HEAD_MAGIC.len() + 1 + 4;
        if bytes.len() != DURABLE_HEAD_FRAME_LEN
            || bytes[..DURABLE_HEAD_MAGIC.len()] != DURABLE_HEAD_MAGIC
            || bytes[DURABLE_HEAD_MAGIC.len()] != DURABLE_HEAD_FORMAT_VERSION
        {
            return None;
        }
        let checksum = u32::from_le_bytes(
            bytes[DURABLE_HEAD_MAGIC.len() + 1..header]
                .try_into()
                .ok()?,
        );
        let payload = &bytes[header..];
        if crc32c(payload) != checksum {
            return None;
        }
        parse_payload(payload)
    }
}

fn parse_payload(payload: &[u8]) -> Option<DurableHead> {
    if payload.len() != DURABLE_HEAD_PAYLOAD_LEN {
        return None;
    }
    let commit_id = u64::from_be_bytes(payload[0..8].try_into().ok()?);
    let height = u32::from_be_bytes(payload[8..12].try_into().ok()?);
    let tip = Hash256::from_le_bytes(&payload[12..44].try_into().ok()?);
    let chain_tx_count = u64::from_be_bytes(payload[44..52].try_into().ok()?);
    let body_present = payload[52];
    let undo_present = payload[65];
    if body_present > 1 || undo_present > 1 {
        return None;
    }
    let body_extent = if body_present == 1 {
        Some(BodyExtent {
            file_no: u32::from_be_bytes(payload[53..57].try_into().ok()?),
            offset: u64::from_be_bytes(payload[57..65].try_into().ok()?),
        })
    } else {
        None
    };
    let undo_extent = if undo_present == 1 {
        let height = u32::from_be_bytes(payload[66..70].try_into().ok()?);
        let hash = Hash256::from_le_bytes(&payload[70..102].try_into().ok()?);
        Some((height, hash))
    } else {
        None
    };
    Some(DurableHead {
        assumeutxo: crate::assumeutxo::AssumeUtxoDiskStatus::decode(&payload[102..])?,
        commit_id,
        height,
        tip,
        chain_tx_count,
        body_extent,
        undo_extent,
    })
}

#[derive(Debug, Default)]
pub struct CommitRecords<'a> {
    pub undo_rows: Vec<(u32, Hash256, &'a [u8])>,
    pub body_rows: Vec<(u32, Hash256, crate::block_file::BlockFilePosition)>,
    pub attestation: Option<ScriptAttestation>,
}

pub trait DurableHeadStore: Send + Sync + 'static {
    fn load(&self) -> Result<Option<DurableHead>, StorageError>;

    fn load_attestation(&self, head: &DurableHead) -> Result<ScriptAttestation, StorageError>;

    /// The weakest level of the commits made above a pending assumeutxo base.
    /// An absent row, or a row naming another head, reads as `Unattested`.
    fn load_suffix_attestation(
        &self,
        head: &DurableHead,
    ) -> Result<ScriptAttestation, StorageError>;

    fn attest(&self, head: &DurableHead, level: ScriptAttestation) -> Result<(), StorageError>;
}

pub struct KvDurableHeadStore<S: KvStore> {
    store: std::sync::Arc<S>,
}

impl<S: KvStore> KvDurableHeadStore<S> {
    #[must_use]
    pub const fn new(store: std::sync::Arc<S>) -> Self {
        Self { store }
    }

    fn load_bytes(&self) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)
    }

    fn write_attestation(
        &self,
        head: &DurableHead,
        level: ScriptAttestation,
    ) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            SCRIPT_ATTESTATION_KEY,
            &level.row(head.commit_id),
        );
        let condition = WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: DURABLE_HEAD_KEY,
            expected: &head.encode(),
        };
        if !self.store.write_durable_if(&[condition], batch)? {
            return Err(StorageError::InvalidOperation(
                "durable head moved since it was read",
            ));
        }
        Ok(())
    }
}

impl<S: KvStore> DurableHeadStore for KvDurableHeadStore<S> {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        self.load_bytes()?
            .map(|bytes| {
                DurableHead::decode(&bytes).ok_or_else(|| {
                    StorageError::IncompatibleData(
                        "durable head row is unreadable; refusing to treat it as absent".to_owned(),
                    )
                })
            })
            .transpose()
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

    fn attest(&self, head: &DurableHead, level: ScriptAttestation) -> Result<(), StorageError> {
        self.write_attestation(head, level)
    }
}

#[derive(Debug, Default)]
pub struct InMemoryDurableHeadStore {
    head: parking_lot::RwLock<Option<DurableHead>>,
    attestation: parking_lot::RwLock<Option<(u64, ScriptAttestation)>>,
    suffix: parking_lot::RwLock<Option<(u64, ScriptAttestation)>>,
}

impl InMemoryDurableHeadStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: parking_lot::RwLock::new(None),
            attestation: parking_lot::RwLock::new(None),
            suffix: parking_lot::RwLock::new(None),
        }
    }
}

impl DurableHeadStore for InMemoryDurableHeadStore {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        Ok(*self.head.read())
    }

    fn load_attestation(&self, head: &DurableHead) -> Result<ScriptAttestation, StorageError> {
        let attestation = *self.attestation.read();
        Ok(match attestation {
            Some((commit_id, level)) if commit_id == head.commit_id => level,
            _ => ScriptAttestation::Unattested,
        })
    }

    fn load_suffix_attestation(
        &self,
        head: &DurableHead,
    ) -> Result<ScriptAttestation, StorageError> {
        let suffix = *self.suffix.read();
        Ok(match suffix {
            Some((commit_id, level)) if commit_id == head.commit_id => level,
            _ => ScriptAttestation::Unattested,
        })
    }

    fn attest(&self, head: &DurableHead, level: ScriptAttestation) -> Result<(), StorageError> {
        let current = self.head.read();
        if current.as_ref() != Some(head) {
            return Err(StorageError::InvalidOperation(
                "durable head moved since it was read",
            ));
        }
        *self.attestation.write() = Some((head.commit_id, level));
        Ok(())
    }
}

impl InMemoryDurableHeadStore {
    /// Test-seam head mutation for the in-memory stub; production code writes
    /// heads only through [`CommitAuthority`](crate::CommitAuthority).
    pub fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: &CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        let mut head = self.head.write();
        if head.as_ref() != expected {
            return Err(StorageError::InvalidOperation(
                "durable head moved since it was read",
            ));
        }
        let previous = match expected {
            Some(current) => self.load_attestation(current)?,
            None => ScriptAttestation::Full,
        };
        let level = records
            .attestation
            .map_or(previous, |batch| previous.min(batch));
        *self.attestation.write() = Some((next.commit_id, level));
        if matches!(next.assumeutxo, AssumeUtxoDiskStatus::Validating { .. }) {
            let suffix = match expected {
                Some(current)
                    if matches!(current.assumeutxo, AssumeUtxoDiskStatus::Validating { .. }) =>
                {
                    let previous = self.load_suffix_attestation(current)?;
                    records
                        .attestation
                        .map_or(previous, |batch| previous.min(batch))
                }
                _ => ScriptAttestation::Full,
            };
            *self.suffix.write() = Some((next.commit_id, suffix));
        }
        *head = Some(*next);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(commit_id: u64) -> DurableHead {
        DurableHead {
            assumeutxo: crate::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id,
            height: 41,
            tip: Hash256::from_le_bytes(&[0x5A_u8; 32]),
            chain_tx_count: 123_456,
            body_extent: Some(BodyExtent {
                file_no: 1,
                offset: 9_876,
            }),
            undo_extent: Some((41, Hash256::from_le_bytes(&[0x5A_u8; 32]))),
        }
    }

    #[test]
    fn frame_round_trips_extents() {
        let head = sample(7);
        assert_eq!(DurableHead::decode(&head.encode()), Some(head));

        let bare = DurableHead {
            body_extent: None,
            undo_extent: None,
            ..sample(1)
        };
        assert_eq!(DurableHead::decode(&bare.encode()), Some(bare));
    }

    #[test]
    fn snapshot_root_frame_covers_pending_and_terminal_states() {
        use crate::assumeutxo::{AssumeUtxoDiskStatus, PendingHistoricalBlock};
        let base_hash = Hash256::from_le_bytes(&[0x31; 32]);
        let commitment = Hash256::from_le_bytes(&[0x52; 32]);
        let statuses = [
            AssumeUtxoDiskStatus::Validating {
                base_height: 100,
                base_hash,
                expected_hash_serialized: commitment,
                chain_tx_count: 120,
                historical_height: 41,
                historical_hash: sample(1).tip,
                pending: Some(PendingHistoricalBlock {
                    height: 42,
                    hash: base_hash,
                    position: Some(crate::BlockFilePosition {
                        file_no: 7,
                        offset: 128,
                        len: 500,
                    }),
                }),
                checkpoint: Some(crate::assumeutxo::HistoricalCheckpointRef {
                    checkpoint: crate::checkpoint::CheckpointReference {
                        generation: 9,
                        manifest_sha256: [7; 32],
                    },
                    height: 40,
                    hash: base_hash,
                }),
            },
            AssumeUtxoDiskStatus::Finalized {
                base_height: 100,
                base_hash,
                validated_hash_serialized: commitment,
            },
            AssumeUtxoDiskStatus::Failed {
                base_height: 100,
                base_hash,
                expected_hash_serialized: commitment,
                actual_hash_serialized: Hash256::default(),
            },
        ];
        for assumeutxo in statuses {
            let root = DurableHead {
                assumeutxo,
                ..sample(5)
            };
            assert_eq!(DurableHead::decode(&root.encode()), Some(root));
            let mut frame = root.encode();
            let last = frame.len() - 1;
            frame[last] ^= 1;
            assert!(DurableHead::decode(&frame).is_none());
        }
    }

    #[test]
    fn frame_fails_closed_on_corruption() {
        let mut frame = sample(7).encode();
        frame[DURABLE_HEAD_MAGIC.len()] = DURABLE_HEAD_FORMAT_VERSION + 1;
        assert_eq!(DurableHead::decode(&frame), None);

        let mut frame = sample(7).encode();
        let last = frame.len() - 1;
        frame[last] ^= 0x80;
        assert_eq!(DurableHead::decode(&frame), None);

        let mut frame = sample(7).encode();
        frame[0] = b'X';
        assert_eq!(DurableHead::decode(&frame), None);

        let frame = sample(7).encode();
        assert_eq!(DurableHead::decode(&frame[..frame.len() - 1]), None);
    }

    #[test]
    fn memory_store_honors_the_fence() -> Result<(), StorageError> {
        let store = InMemoryDurableHeadStore::new();
        let first = sample(1);
        store.commit(None, &first, &CommitRecords::default())?;
        let second = DurableHead {
            commit_id: 2,
            ..sample(2)
        };
        let stale = DurableHead {
            commit_id: 9,
            ..first
        };
        assert!(
            store
                .commit(Some(&stale), &second, &CommitRecords::default())
                .is_err()
        );
        assert_eq!(store.load()?, Some(first));
        store.commit(Some(&first), &second, &CommitRecords::default())?;
        assert_eq!(store.load()?, Some(second));
        Ok(())
    }

    // RCV-02
    #[test]
    fn memory_attest_holds_the_head_until_the_attestation_is_written() -> Result<(), StorageError> {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let store = Arc::new(InMemoryDurableHeadStore::new());
        let head = sample(1);
        store.commit(None, &head, &CommitRecords::default())?;
        let attestation = store.attestation.write();
        let worker = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || store.attest(&head, ScriptAttestation::Full))
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if store.head.try_write().is_none() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "attest released the head before writing the attestation"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(attestation);
        worker
            .join()
            .map_err(|_| StorageError::InvalidOperation("attest thread panicked"))??;
        assert_eq!(
            store.load_attestation(&head)?,
            ScriptAttestation::Full,
            "the attestation names the head it was checked against"
        );
        Ok(())
    }
}
