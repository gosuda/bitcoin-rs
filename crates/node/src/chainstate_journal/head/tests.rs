//! Representation controls for the current checkpoint journal, not power-loss proof.
//! CONTRACT: docs/chainstate-recovery.md, current journal implementation.

use super::*;

fn marker() -> HeadMarker {
    HeadMarker {
        base_generation: 7,
        base_height: 10,
        base_hash: [1; 32],
        base_chain_tx_count: 11,
        start_gen: 2,
        start_offset: 3,
        journal_gen: 4,
        offset: 5,
        height: 12,
        block_hash: [6; 32],
        prev_hash: [8; 32],
        chain_tx_count: 19,
        record_count: 2,
    }
}

#[test]
fn head_frame_preserves_magic_version_and_every_field() -> Result<(), JournalWriterError> {
    let head = marker();
    let bytes = head.serialize()?;
    // Immutable head-v1 representation from the pre-cut writer: JRNH, version 1,
    // little-endian CRC32C, then the existing JSON field representation.
    assert_eq!(&bytes[..5], b"JRNH\x01");
    assert_eq!(HeadMarker::deserialize(&bytes)?, head);
    let payload: serde_json::Value = serde_json::from_slice(&bytes[9..])
        .map_err(|error| JournalWriterError::HeadUnreadable(error.to_string()))?;
    assert_eq!(payload["base_generation"], 7);
    assert_eq!(payload["height"], 12);
    assert_eq!(payload["record_count"], 2);
    assert_eq!(payload.as_object().map(serde_json::Map::len), Some(13));
    Ok(())
}

#[test]
fn head_frame_rejects_short_magic_version_and_checksum_corruption() -> Result<(), JournalWriterError>
{
    let bytes = marker().serialize()?;
    for length in 0..9 {
        assert!(matches!(
            HeadMarker::deserialize(&bytes[..length]),
            Err(JournalWriterError::HeadUnreadable(_))
        ));
    }
    for position in [0, 4, 5, 9] {
        let mut corrupt = bytes.clone();
        corrupt[position] ^= 1;
        assert!(matches!(
            HeadMarker::deserialize(&corrupt),
            Err(JournalWriterError::HeadUnreadable(_))
        ));
    }
    Ok(())
}

#[test]
fn head_reader_distinguishes_absence_and_existing_size_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let dir = cap_std::fs::Dir::open_ambient_dir(temp.path(), cap_std::ambient_authority())?;
    assert_eq!(read_head_bytes(&dir)?, None);
    // File-size checks and frame validity are separate, as on the pre-cut reader.
    dir.write("head.json", vec![0; 4096])?;
    let bytes = read_head_bytes(&dir)?.ok_or("head disappeared")?;
    assert_eq!(bytes.len(), 4096);
    assert!(HeadMarker::deserialize(&bytes).is_err());
    dir.write("head.json", vec![0; 4097])?;
    assert!(matches!(
        read_head_bytes(&dir),
        Err(JournalWriterError::HeadUnreadable(_))
    ));
    assert_eq!(dir.metadata("head.json")?.len(), 4097);
    Ok(())
}
