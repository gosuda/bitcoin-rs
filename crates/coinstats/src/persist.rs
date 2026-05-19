use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError, WriteBatch};

use crate::{CoinStats, CoinStatsDecodeError};

/// Persistence error for coinstats rows.
#[derive(Debug, thiserror::Error)]
pub enum CoinStatsPersistError {
    /// Storage backend failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Stored bytes were invalid.
    #[error(transparent)]
    Decode(#[from] CoinStatsDecodeError),
}

/// Stores `stats` keyed by its height encoded as little-endian `u32`.
pub fn store_coin_stats(
    store: &impl KvStore,
    stats: &CoinStats,
) -> Result<(), CoinStatsPersistError> {
    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::Coinstats,
        &stats.height.to_le_bytes(),
        &stats.to_bytes(),
    );
    store.write(batch)?;
    Ok(())
}

/// Loads coinstats for `height`, if present.
pub fn load_coin_stats(
    store: &impl KvStore,
    height: u32,
) -> Result<Option<CoinStats>, CoinStatsPersistError> {
    let Some(bytes) = store.get(ColumnFamily::Coinstats, &height.to_le_bytes())? else {
        return Ok(None);
    };
    Ok(Some(CoinStats::from_bytes(&bytes)?))
}
