use crate::{
    BlockFilePosition, BufferedWriteBatch, ColumnFamily, FlatFileBlockStore, KvStore, StorageError,
    decode_block_file_max_height,
};
use bitcoin_rs_primitives::Hash256;

use crate::pruning::{PruneError, PruneOutcome, PrunePolicy, row_len_u64};

const BLOCK_BODY_PREFIX: u8 = b'b';
pub(crate) const BLOCK_BODY_PREFIX_BYTES: &[u8] = b"b";
const BLOCK_FILE_PREFIX_BYTES: &[u8] = b"blkfile";
const BLOCK_FILE_KEY_LEN: usize = 11;
const HEIGHT_START: usize = 1;
const HEIGHT_END: usize = 5;
const KEY_LEN: usize = 37;

/// Column family used for serialized block-body rows.
pub const BLOCK_DATA_CF: ColumnFamily = ColumnFamily::BlockBodies;

/// Builds the canonical pruning key for a stored block body.
#[must_use]
pub fn block_body_key(height: u32, hash: Hash256) -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    key[0] = BLOCK_BODY_PREFIX;
    key[HEIGHT_START..HEIGHT_END].copy_from_slice(&height.to_be_bytes());
    key[HEIGHT_END..].copy_from_slice(hash.as_byte_array());
    key
}

/// The lowest row height still stored under `prefix`, when a row survives.
///
/// Keys are `(prefix, big-endian height, hash)`, so a family iterates in
/// height order and the first row that parses names the lowest surviving
/// height. A row whose height does not parse proves nothing about where
/// deletion stopped, so it is skipped.
pub(crate) fn lowest_stored_height<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    prefix: &[u8],
) -> Result<Option<u32>, StorageError> {
    for row in store.iter_prefix(cf, prefix)? {
        let (key, _) = row?;
        if let Some(height) = row_height(&key, prefix) {
            return Ok(Some(height));
        }
    }
    Ok(None)
}

pub(crate) fn prune_prefixed_rows_into_batch<S: KvStore>(
    store: &S,
    batch: &mut BufferedWriteBatch,
    cf: ColumnFamily,
    prefix: &[u8],
    prune_below_height: u32,
    policy: PrunePolicy,
) -> Result<PruneOutcome, PruneError> {
    let target_bytes = policy.target_size_bytes();
    let mut total_bytes = 0_u64;
    let mut candidates = Vec::new();

    for row in store.iter_prefix(cf, prefix)? {
        let (key, value) = row?;
        let row_bytes = row_len_u64(&value)?;
        total_bytes = total_bytes.saturating_add(row_bytes);

        if let Some(height) = row_height(&key, prefix)
            && height < prune_below_height
        {
            candidates.push((key, row_bytes, height));
        }
    }

    if total_bytes <= target_bytes || candidates.is_empty() {
        return Ok(PruneOutcome::default());
    }

    let mut remaining_bytes = total_bytes;
    let mut outcome = PruneOutcome::default();

    for (key, row_bytes, height) in candidates {
        if remaining_bytes <= target_bytes {
            break;
        }

        batch.delete(cf, &key);
        remaining_bytes = remaining_bytes.saturating_sub(row_bytes);
        outcome.record_removed(row_bytes, height);
    }

    Ok(outcome)
}

pub(crate) fn stage_flat_block_file_prune<S: KvStore>(
    store: &S,
    batch: &mut BufferedWriteBatch,
    block_files: &FlatFileBlockStore,
    prune_below_height: u32,
    policy: PrunePolicy,
) -> Result<(PruneOutcome, Vec<u32>), PruneError> {
    let current_file = block_files.current_file_number();
    let mut file_numbers = Vec::new();
    for row in store.iter_prefix(BLOCK_DATA_CF, BLOCK_FILE_PREFIX_BYTES)? {
        let (key, value) = row?;
        if key.len() != BLOCK_FILE_KEY_LEN {
            continue;
        }
        let Some(max_height) = decode_block_file_max_height(&value) else {
            continue;
        };
        if max_height >= prune_below_height {
            continue;
        }

        let mut encoded_file_no = [0_u8; 4];
        encoded_file_no.copy_from_slice(&key[BLOCK_FILE_PREFIX_BYTES.len()..]);
        let file_no = u32::from_be_bytes(encoded_file_no);
        if file_no != current_file {
            file_numbers.push(file_no);
        }
    }

    let target_bytes = policy.target_size_bytes();
    let mut total_bytes = 0_u64;
    let mut candidates = Vec::new();
    for row in store.iter_prefix(BLOCK_DATA_CF, BLOCK_BODY_PREFIX_BYTES)? {
        let (key, value) = row?;
        if key.len() != KEY_LEN {
            continue;
        }
        let row_bytes = row_len_u64(&value)?;
        total_bytes = total_bytes.saturating_add(row_bytes);
        let position = BlockFilePosition::decode(&value).ok_or_else(|| {
            StorageError::IncompatibleData(
                "block-body index row is not a 16-byte flat-file position".to_owned(),
            )
        })?;
        let selected_file = file_numbers.binary_search(&position.file_no).is_ok();
        let height = row_height(&key, BLOCK_BODY_PREFIX_BYTES)
            .unwrap_or_else(|| prune_below_height.saturating_sub(1));
        let below_horizon = height < prune_below_height;
        if selected_file || below_horizon {
            candidates.push((key, row_bytes, height, selected_file));
        }
    }
    let mut remaining_bytes = total_bytes;
    let mut outcome = PruneOutcome::default();
    for (key, row_bytes, height, selected_file) in candidates {
        if !selected_file && remaining_bytes <= target_bytes {
            continue;
        }

        batch.delete(BLOCK_DATA_CF, &key);
        remaining_bytes = remaining_bytes.saturating_sub(row_bytes);
        outcome.record_removed(row_bytes, height);
    }

    Ok((outcome, file_numbers))
}

fn row_height(key: &[u8], prefix: &[u8]) -> Option<u32> {
    if key.len() != KEY_LEN || !key.starts_with(prefix) {
        return None;
    }

    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&key[HEIGHT_START..HEIGHT_END]);
    Some(u32::from_be_bytes(bytes))
}
