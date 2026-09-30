//! Storage-owned journal framing and committed-range replay.

use bitcoin_rs_primitives::hex_encode;

use super::record::{FRAME_HEADER_LEN, JournalRecord, MAX_PAYLOAD_LEN, decode_record};
use super::writer::{HeadMarker, read_head_bytes};

/// Fail-closed errors encountered while replaying the committed journal range.
#[derive(Debug, thiserror::Error)]
pub enum JournalReplayError {
    /// No durable head marker exists.
    #[error("no journal head marker")]
    NoHead,
    /// The durable head marker cannot be decoded or authenticated.
    #[error("journal head marker unreadable: {0}")]
    HeadUnreadable(String),
    /// The journal's base is not the restored checkpoint tip: the generation
    /// describes a different chain and must be discarded.
    #[error("journal base does not match the checkpoint tip")]
    BaseMismatch,
    /// A record inside the committed range is corrupt or non-contiguous:
    /// fail closed, never truncate the committed prefix.
    #[error("committed journal range is invalid: {0}")]
    CommittedRangeInvalid(String),
    /// Header-chain rebuild rejected a journaled header: fail closed.
    #[error("header rebuild rejected: {0}")]
    HeaderRebuildRejected(String),
}

impl JournalReplayError {
    /// Returns a stable machine-readable error reason.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::NoHead => "no_head",
            Self::HeadUnreadable(_) => "head_unreadable",
            Self::BaseMismatch => "base_mismatch",
            Self::CommittedRangeInvalid(_) => "committed_range_invalid",
            Self::HeaderRebuildRejected(_) => "header_rebuild_rejected",
        }
    }

    /// Reports whether the failure indicates checksum damage.
    pub fn is_checksum_failure(&self) -> bool {
        match self {
            Self::HeadUnreadable(_) => true,
            Self::CommittedRangeInvalid(message) => {
                message.contains("crc") || message.contains("checksum")
            }
            Self::NoHead | Self::BaseMismatch | Self::HeaderRebuildRejected(_) => false,
        }
    }
}

/// Reads and validates the committed range `(start..=head)` from the journal
/// directory: every record decodes, crc32c passes, and the contiguity
/// predicate (`record[i].height == record[i-1].height + 1` AND
/// `record[i].prev_hash == record[i-1].block_hash`) holds, with the first
/// record anchored to the checkpoint base tip.
pub(crate) fn stream_committed_range(
    dir: &cap_std::fs::Dir,
    head: &HeadMarker,
    base_tip_hash: [u8; 32],
    base_tip_height: u32,
    mut apply_record: impl FnMut(&JournalRecord) -> Result<(), JournalReplayError>,
) -> Result<u64, JournalReplayError> {
    let mut generations = Vec::new();
    for entry in dir.entries().map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("segment listing failed: {error}"))
    })? {
        let entry = entry.map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!("segment entry: {error}"))
        })?;
        if let Some(generation) =
            super::writer::parse_segment_name(entry.file_name().to_string_lossy().as_ref())
            && generation >= head.start_gen
            && generation <= head.journal_gen
        {
            generations.push(generation);
        }
    }
    generations.sort_unstable();
    if generations.first() != Some(&head.start_gen) || generations.last() != Some(&head.journal_gen)
    {
        return Err(JournalReplayError::CommittedRangeInvalid(
            "retained segment window is incomplete".to_owned(),
        ));
    }

    let mut expected_height = base_tip_height.checked_add(1).ok_or_else(|| {
        JournalReplayError::CommittedRangeInvalid("base tip height overflow".to_owned())
    })?;
    let mut expected_prev = base_tip_hash;
    let mut record_count = 0_u64;
    for generation in &generations {
        let end = if *generation == head.journal_gen {
            head.offset
        } else {
            u64::MAX
        };
        record_count = record_count
            .checked_add(stream_segment(
                dir,
                *generation,
                head,
                end,
                &mut expected_height,
                &mut expected_prev,
                &mut apply_record,
            )?)
            .ok_or_else(|| {
                JournalReplayError::CommittedRangeInvalid("record count overflow".to_owned())
            })?;
    }
    Ok(record_count)
}

pub(crate) fn checked_frame_len(payload_len: u32) -> Result<usize, JournalReplayError> {
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        JournalReplayError::CommittedRangeInvalid("payload length overflow".to_owned())
    })?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "payload length exceeds codec limit: {payload_len} > {MAX_PAYLOAD_LEN}"
        )));
    }
    FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
        .ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("frame length overflow".to_owned())
        })
}

pub(crate) fn stream_segment(
    dir: &cap_std::fs::Dir,
    generation: u64,
    head: &HeadMarker,
    window_end: u64,
    expected_height: &mut u32,
    expected_prev: &mut [u8; 32],
    apply_record: &mut impl FnMut(&JournalRecord) -> Result<(), JournalReplayError>,
) -> Result<u64, JournalReplayError> {
    use std::io::{Read, Seek, SeekFrom};

    let frame_header_len = u64::try_from(FRAME_HEADER_LEN).map_err(|_| {
        JournalReplayError::CommittedRangeInvalid("frame header size overflow".to_owned())
    })?;

    let name = super::writer::segment_name(generation);
    let file = dir.open(name.as_str()).map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("open segment {generation}: {error}"))
    })?;
    let length = file.metadata().map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("stat segment {generation}: {error}"))
    })?;
    let end = window_end.min(length.len());
    let mut offset = if generation == head.start_gen {
        head.start_offset
    } else {
        0
    };
    let mut reader = std::io::BufReader::new(file);
    reader.seek(SeekFrom::Start(offset)).map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!(
            "seek segment {generation} to {offset}: {error}"
        ))
    })?;
    let mut record_count = 0_u64;

    while offset < end {
        if offset
            .checked_add(frame_header_len)
            .is_none_or(|header_end| header_end > end)
        {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: truncated frame header at offset {offset}"
            )));
        }
        let mut header = [0_u8; FRAME_HEADER_LEN];
        reader.read_exact(&mut header).map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: read frame header at offset {offset}: {error}"
            ))
        })?;
        let payload_len = u32::from_le_bytes(header[5..9].try_into().map_err(|_| {
            JournalReplayError::CommittedRangeInvalid(
                "frame header length slice mismatch".to_owned(),
            )
        })?);
        let frame_size = checked_frame_len(payload_len)?;
        let frame_len = u64::try_from(frame_size).map_err(|_| {
            JournalReplayError::CommittedRangeInvalid("frame size overflow".to_owned())
        })?;
        if offset
            .checked_add(frame_len)
            .is_none_or(|frame_end| frame_end > end)
        {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: truncated frame at offset {offset}"
            )));
        }
        let mut frame = Vec::with_capacity(frame_size);
        frame.extend_from_slice(&header);
        frame.resize(frame_size, 0);
        reader
            .read_exact(&mut frame[FRAME_HEADER_LEN..])
            .map_err(|error| {
                JournalReplayError::CommittedRangeInvalid(format!(
                    "segment {generation}: read frame at offset {offset}: {error}"
                ))
            })?;
        let record = decode_record(&frame).map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation} offset {offset}: {error}"
            ))
        })?;
        if record.height != *expected_height || record.prev_hash != *expected_prev {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "contiguity break at height {}: expected ({}, {}), found ({}, {})",
                record.height,
                *expected_height,
                hex_encode(expected_prev),
                record.height,
                hex_encode(&record.prev_hash)
            )));
        }
        *expected_height = record.height.checked_add(1).ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("record height overflow".to_owned())
        })?;
        *expected_prev = record.block_hash;
        offset = offset.checked_add(frame_len).ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("frame offset overflow".to_owned())
        })?;
        apply_record(&record)?;
        record_count = record_count.checked_add(1).ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("record count overflow".to_owned())
        })?;
    }
    Ok(record_count)
}

/// Checkpoint tip that must anchor journal replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalReplayBase {
    /// Checkpoint generation recorded in the journal head.
    pub generation: u64,
    /// Checkpoint height.
    pub height: u32,
    /// Checkpoint block hash in internal byte order.
    pub block_hash: [u8; 32],
    /// Cumulative transaction count at the checkpoint tip.
    pub chain_tx_count: u64,
}

/// Journal frontier reconstructed after replaying committed records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayedHead {
    /// Last replayed block height.
    pub height: u32,
    /// Last replayed block hash in internal byte order.
    pub block_hash: [u8; 32],
    /// Cumulative transaction count at the replayed head.
    pub chain_tx_count: u64,
    /// Number of records applied during replay.
    pub record_count: u64,
}

/// Validates and applies the journal range committed by its durable head.
pub fn replay_committed_range(
    dir: &cap_std::fs::Dir,
    base: JournalReplayBase,
    mut apply: impl FnMut(&JournalRecord) -> Result<(), JournalReplayError>,
) -> Result<ReplayedHead, JournalReplayError> {
    let head_bytes = match read_head_bytes(dir) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(JournalReplayError::NoHead),
        Err(error) => return Err(JournalReplayError::HeadUnreadable(error.to_string())),
    };
    let head = HeadMarker::deserialize(&head_bytes)
        .map_err(|error| JournalReplayError::HeadUnreadable(error.to_string()))?;
    if head.base_generation != base.generation
        || head.base_height != base.height
        || head.base_hash != base.block_hash
        || head.base_chain_tx_count != base.chain_tx_count
        || head.height < base.height
    {
        return Err(JournalReplayError::BaseMismatch);
    }
    let record_count = if head.height == base.height {
        if head.block_hash != head.base_hash
            || head.chain_tx_count != base.chain_tx_count
            || head.record_count != 0
        {
            return Err(JournalReplayError::BaseMismatch);
        }
        0
    } else {
        stream_committed_range(dir, &head, base.block_hash, base.height, |record| {
            apply(record)
        })?
    };
    if record_count != head.record_count {
        return Err(JournalReplayError::CommittedRangeInvalid(
            "record count does not match head marker".to_owned(),
        ));
    }
    Ok(ReplayedHead {
        height: head.height,
        block_hash: head.block_hash,
        chain_tx_count: head.chain_tx_count,
        record_count,
    })
}

#[cfg(test)]
mod tests {
    use super::super::record::MAX_PAYLOAD_LEN;
    use super::{JournalReplayError, checked_frame_len};

    #[test]
    fn oversized_frame_is_rejected_before_payload_allocation() {
        let Ok(oversized) = u32::try_from(MAX_PAYLOAD_LEN + 1) else {
            panic!("test limit fits u32");
        };
        assert!(matches!(
            checked_frame_len(oversized),
            Err(JournalReplayError::CommittedRangeInvalid(message))
                if message.contains("payload length exceeds")
        ));
    }
}
