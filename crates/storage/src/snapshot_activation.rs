use bitcoin_rs_consensus::primitives::Hash256;

use crate::durable_head::crc32c;

pub const SNAPSHOT_ACTIVATION_KEY: &[u8] = b"node:snapshot-activation";

const ACTIVATION_MARKER_MAGIC: [u8; 4] = *b"BRSA";
const ACTIVATION_MARKER_VERSION: u8 = 1;
const ACTIVATION_MARKER_PAYLOAD_LEN: usize = 32 + 8 + 32;
const ACTIVATION_MARKER_FRAME_LEN: usize =
    ACTIVATION_MARKER_MAGIC.len() + 1 + ACTIVATION_MARKER_PAYLOAD_LEN + 4;

/// Durable guard row for an assumeutxo activation.
///
/// The marker exists exactly while staged snapshot coins may be durable in the
/// engine `coins` keyspace without their activation head. The head commit
/// clears it in the same atomic batch that moves the head to the snapshot tip,
/// so a restart that finds the marker knows the coin ingest was interrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotActivationMarker {
    pub base_hash: Hash256,
    pub coin_count: u64,
    pub coin_digest: Hash256,
}

impl SnapshotActivationMarker {
    pub fn encode(&self) -> [u8; ACTIVATION_MARKER_FRAME_LEN] {
        let mut frame = [0_u8; ACTIVATION_MARKER_FRAME_LEN];
        let mut offset = 0;
        frame[..4].copy_from_slice(&ACTIVATION_MARKER_MAGIC);
        offset += 4;
        frame[offset] = ACTIVATION_MARKER_VERSION;
        offset += 1;
        frame[offset..offset + 32].copy_from_slice(&self.base_hash.to_le_bytes());
        offset += 32;
        frame[offset..offset + 8].copy_from_slice(&self.coin_count.to_le_bytes());
        offset += 8;
        frame[offset..offset + 32].copy_from_slice(&self.coin_digest.to_le_bytes());
        offset += 32;
        let checksum = crc32c(&frame[..offset]);
        frame[offset..offset + 4].copy_from_slice(&checksum.to_le_bytes());
        frame
    }

    /// Decodes strictly: any length, magic, version, or checksum deviation is
    /// corruption, not absence.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ACTIVATION_MARKER_FRAME_LEN {
            return None;
        }
        if bytes[..4] != ACTIVATION_MARKER_MAGIC || bytes[4] != ACTIVATION_MARKER_VERSION {
            return None;
        }
        let payload_end = 4 + 1 + ACTIVATION_MARKER_PAYLOAD_LEN;
        let stored = u32::from_le_bytes(bytes[payload_end..payload_end + 4].try_into().ok()?);
        if crc32c(&bytes[..payload_end]) != stored {
            return None;
        }
        let mut base = [0_u8; 32];
        base.copy_from_slice(&bytes[5..37]);
        let mut count = [0_u8; 8];
        count.copy_from_slice(&bytes[37..45]);
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes[45..77]);
        Some(Self {
            base_hash: Hash256::from_le_bytes(&base),
            coin_count: u64::from_le_bytes(count),
            coin_digest: Hash256::from_le_bytes(&digest),
        })
    }
}

/// Outcome of the boot-time activation reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotActivationRecovery {
    /// No interrupted activation is recorded.
    Clean,
    /// The staged coins were wiped and the marker cleared; the durable head
    /// never moved to the snapshot tip.
    RolledBack { marker: SnapshotActivationMarker },
}
