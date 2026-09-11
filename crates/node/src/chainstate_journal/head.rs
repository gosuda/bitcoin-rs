//! Canonical framed journal head and its size-checked file reader.
//!
//! This module owns representation, not publication. Only the writer advances
//! the durable frontier after the storage and segment durability dependencies.

use super::error::JournalWriterError;

/// Magic prefix of `head.json` payload bytes (versioned container, crc32c).
const HEAD_MAGIC: [u8; 4] = *b"JRNH";
/// Current `head.json` format version.
const HEAD_VERSION: u8 = 1;
/// Maximum serialized `head.json` size accepted on load.
const MAX_HEAD_BYTES: u64 = 4 * 1024;
/// Durable head marker payload (`head.json`, plan §2.1).
///
/// Serialized as: `HEAD_MAGIC | version u8 | crc32c(payload) | payload`,
/// where payload is a JSON object. The checksum covers the payload so a torn
/// rename or a bit flip fails closed at load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeadMarker {
    /// Checkpoint generation this journal extends.
    pub(crate) base_generation: u64,
    /// Applied-tip height of the checkpoint base.
    pub(crate) base_height: u32,
    /// Applied-tip hash of the checkpoint base.
    pub(crate) base_hash: [u8; 32],
    /// Cumulative transaction count through the checkpoint base.
    pub(crate) base_chain_tx_count: u64,
    /// Oldest RETAINED segment generation (the base cursor).
    pub(crate) start_gen: u64,
    /// Byte offset within the oldest retained segment's active record window.
    pub(crate) start_offset: u64,
    /// Generation of the segment holding the durable frontier.
    pub(crate) journal_gen: u64,
    /// Byte offset of the durable frontier inside `journal_gen`'s segment.
    pub(crate) offset: u64,
    /// Height of the last durably journaled block.
    pub(crate) height: u32,
    /// Hash of the last durably journaled block (32 raw bytes).
    pub(crate) block_hash: [u8; 32],
    /// Hash of its predecessor (32 raw bytes).
    pub(crate) prev_hash: [u8; 32],
    /// Cumulative transaction count through the head tip.
    pub(crate) chain_tx_count: u64,
    /// Number of records retained from `(start_gen, start_offset)` through head.
    pub(crate) record_count: u64,
}

impl HeadMarker {
    fn crc32c(bytes: &[u8]) -> u32 {
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

    pub(super) fn serialize(&self) -> Result<Vec<u8>, JournalWriterError> {
        let payload = serde_json::to_vec(self).map_err(|error| {
            JournalWriterError::HeadUnreadable(format!("marker serialization failed: {error}"))
        })?;
        let checksum = Self::crc32c(&payload);
        let mut bytes = Vec::with_capacity(payload.len() + 9);
        bytes.extend_from_slice(&HEAD_MAGIC);
        bytes.push(HEAD_VERSION);
        bytes.extend_from_slice(&checksum.to_le_bytes());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub(crate) fn deserialize(bytes: &[u8]) -> Result<Self, JournalWriterError> {
        if bytes.len() < 9 {
            return Err(JournalWriterError::HeadUnreadable(
                "marker shorter than its frame header".to_owned(),
            ));
        }
        if bytes[..4] != HEAD_MAGIC {
            return Err(JournalWriterError::HeadUnreadable(
                "marker magic mismatch".to_owned(),
            ));
        }
        if bytes[4] != HEAD_VERSION {
            return Err(JournalWriterError::HeadUnreadable(format!(
                "marker version {} not supported",
                bytes[4]
            )));
        }
        let expected = u32::from_le_bytes(bytes[5..9].try_into().map_err(|_| {
            JournalWriterError::HeadUnreadable("marker frame header is short".to_owned())
        })?);
        let payload = &bytes[9..];
        let found = Self::crc32c(payload);
        if found != expected {
            return Err(JournalWriterError::HeadUnreadable(format!(
                "marker checksum mismatch: expected {expected:#010x}, found {found:#010x}"
            )));
        }
        serde_json::from_slice(payload)
            .map_err(|error| JournalWriterError::HeadUnreadable(error.to_string()))
    }
}

/// Reads the framed head shared by writer startup and boot replay.
///
/// `head.json` is bounded by [`MAX_HEAD_BYTES`].
pub(crate) fn read_head_bytes(
    dir: &cap_std::fs::Dir,
) -> Result<Option<Vec<u8>>, JournalWriterError> {
    match dir.open("head.json") {
        Ok(mut file) => {
            let length = file.metadata()?.len();
            if length > MAX_HEAD_BYTES {
                return Err(JournalWriterError::HeadUnreadable(format!(
                    "head marker {length} bytes exceeds {MAX_HEAD_BYTES}"
                )));
            }
            let capacity = usize::try_from(length).map_err(|_| {
                JournalWriterError::HeadUnreadable("head marker is too large".to_owned())
            })?;
            let mut bytes = Vec::with_capacity(capacity);
            std::io::Read::read_to_end(&mut file, &mut bytes)?;
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
