use std::sync::Arc;

use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_storage::utxo::UtxoReader;
use bitcoin_rs_storage::{CoinKey, CoinStore, ColumnFamily, KvStore, MemoryKvStore, StorageError};

pub(crate) fn utxo_reader_with_undecodable_coin(
    txid: &Hash256,
) -> Result<UtxoReader, StorageError> {
    let store = Arc::new(MemoryKvStore::new());
    store.put(
        ColumnFamily::Coins,
        CoinKey(txid.to_le_bytes()).as_bytes(),
        &[0xff; 3],
    )?;
    Ok(UtxoReader::from_coin_store(Arc::new(CoinStore::open(
        store,
        1024 * 1024,
    ))))
}
