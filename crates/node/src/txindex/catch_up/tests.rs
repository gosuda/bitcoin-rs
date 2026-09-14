use super::*;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::consume_prefetched_position;

/// Body bytes for a prefetched position. Cursor advancement is delegated to
/// the storage reader's authoritative implementation.
struct CursorReader {
    entries: Vec<(u32, Hash256, Vec<u8>)>,
    next: usize,
}

impl BlockBodyReader for CursorReader {
    fn load_block_body(
        &mut self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let position = self
            .entries
            .get(self.next)
            .map(|(entry_height, entry_hash, body)| (*entry_height, *entry_hash, body.clone()));
        consume_prefetched_position(
            &mut self.next,
            position.map(|(entry_height, entry_hash, _)| (entry_height, entry_hash)),
            height,
            hash,
        )?;
        Ok(Some(position.expect("validated prefetched position").2))
    }
}

fn identity(height: u32) -> BlockIdentity {
    let mut hash = [0_u8; 32];
    hash[0..4].copy_from_slice(&height.to_le_bytes());
    BlockIdentity {
        height,
        hash,
        parent_hash: [0_u8; 32],
    }
}

#[test]
fn byte_cap_retains_every_body_the_cursor_consumed() -> Result<(), StorageError> {
    // Three bodies of just over half the cap: the second reaches the cap.
    let size = PREPARE_CHUNK_BYTES / 2 + 1;
    let identities: Vec<BlockIdentity> = (0..3).map(identity).collect();
    let mut reader = CursorReader {
        entries: identities
            .iter()
            .map(|id| {
                (
                    id.height,
                    Hash256::from_le_bytes(&id.hash),
                    vec![0_u8; size],
                )
            })
            .collect(),
        next: 0,
    };

    let missing = || StorageError::InvalidOperation("body missing");
    let first = load_body_prefix(&mut reader, &identities)?.ok_or_else(missing)?;
    assert_eq!(first.len(), 2);
    assert_eq!(first.len(), reader.next);

    let rest = load_body_prefix(&mut reader, &identities[first.len()..])?.ok_or_else(missing)?;
    assert_eq!(rest.len(), 1);
    assert_eq!(reader.next, 3);
    Ok(())
}

#[test]
fn count_cap_bounds_the_prefix() -> Result<(), StorageError> {
    let count = u32::try_from(PREPARE_CHUNK_BLOCKS)
        .map_err(|_| StorageError::InvalidOperation("cap exceeds u32"))?;
    let identities: Vec<BlockIdentity> = (0..=count).map(identity).collect();
    let mut reader = CursorReader {
        entries: identities
            .iter()
            .map(|id| (id.height, Hash256::from_le_bytes(&id.hash), vec![0_u8; 1]))
            .collect(),
        next: 0,
    };
    let first = load_body_prefix(&mut reader, &identities)?
        .ok_or(StorageError::InvalidOperation("body missing"))?;
    assert_eq!(first.len(), PREPARE_CHUNK_BLOCKS);
    assert_eq!(reader.next, PREPARE_CHUNK_BLOCKS);
    Ok(())
}
