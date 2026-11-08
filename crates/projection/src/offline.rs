use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit};

use crate::IndexError;

/// Every column family the derived-index projection owns inside its
/// namespace store. `UtxoMeta` carries only index metadata there: watermark
/// rows, the consumer cursor, reset fencing state, and compact filters.
const INDEX_FAMILIES: [ColumnFamily; 13] = [
    ColumnFamily::TxConfirmed,
    ColumnFamily::BlockHeaders,
    ColumnFamily::Funding,
    ColumnFamily::Spending,
    ColumnFamily::UtxoMeta,
    ColumnFamily::ScriptLive,
    ColumnFamily::IdxMeta,
    ColumnFamily::TxDir,
    ColumnFamily::ScriptDict,
    ColumnFamily::ScriptPost,
    ColumnFamily::SpendDir,
    ColumnFamily::ScriptStats,
    ColumnFamily::Filters,
];

const WIPE_SCAN_ROWS: usize = 10_000;

/// Row counts removed per column family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexResetReport {
    pub families: Vec<(ColumnFamily, u64)>,
    pub format_version: u32,
}

/// Offline equivalent of the node's format-mismatch reset: wipes every
/// derived row and metadata marker, then stamps the current format version so
/// the node rebuilds the projection from retained chainstate on its next
/// start. The datadir must be closed; the storage engine refuses a locked
/// store. Idempotent: reruns find nothing left to remove.
pub fn reset_offline(store: &dyn KvStore) -> Result<IndexResetReport, IndexError> {
    let mut families = Vec::with_capacity(INDEX_FAMILIES.len());
    for cf in INDEX_FAMILIES {
        let removed = wipe_family(store, cf)?;
        families.push((cf, removed));
    }
    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::UtxoMeta,
        crate::types::INDEX_FORMAT_VERSION_KEY,
        &crate::types::INDEX_FORMAT_VERSION_VALUE,
    );
    store.write_durable(batch).map_err(IndexError::from)?;
    Ok(IndexResetReport {
        families,
        format_version: u32::from_le_bytes(crate::types::INDEX_FORMAT_VERSION_VALUE),
    })
}

fn wipe_family(store: &dyn KvStore, cf: ColumnFamily) -> Result<u64, IndexError> {
    let mut removed = 0_u64;
    let limit = PrefixScanLimit {
        max_rows: WIPE_SCAN_ROWS,
        max_bytes: usize::MAX,
    };
    loop {
        let scan = store
            .scan_prefix_bounded(cf, &[], limit)
            .map_err(IndexError::from)?;
        if scan.rows.is_empty() {
            return Ok(removed);
        }
        let len = u64::try_from(scan.rows.len()).map_err(|_| IndexError::MutationSizeOverflow)?;
        removed = removed
            .checked_add(len)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let mut batch = store.new_batch();
        for (key, _) in &scan.rows {
            batch.delete(cf, key);
        }
        store.write_durable(batch).map_err(IndexError::from)?;
    }
}
