use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, Script, TxOut};
use crossbeam_utils::CachePadded;
use hashbrown::HashTable;
use parking_lot::RwLock;

use crate::utxo::{UtxoCoin, UtxoKey, record::UtxoRecord};

pub(crate) struct ShardTable {
    pub table: HashTable<UtxoRecord>,
}

impl ShardTable {
    fn new() -> Self {
        Self {
            table: HashTable::new(),
        }
    }

    pub(crate) fn record_count(&self) -> usize {
        self.table.len()
    }

    pub(crate) fn output_count(&self) -> usize {
        self.table.iter().map(UtxoRecord::output_count).sum()
    }

    pub(crate) fn record_payload_bytes(&self) -> usize {
        self.table.iter().map(UtxoRecord::payload_bytes).sum()
    }

    pub(crate) fn table_bytes(&self) -> usize {
        let capacity = self.table.capacity();
        if capacity == 0 {
            return 0;
        }
        let buckets = capacity.saturating_mul(8).div_ceil(7).next_power_of_two();
        buckets.saturating_mul(core::mem::size_of::<UtxoRecord>() + 1)
    }
}

pub(crate) struct Shard {
    inner: CachePadded<RwLock<ShardTable>>,
}

impl Shard {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: CachePadded::new(RwLock::new(ShardTable::new())),
        }
    }

    #[must_use]
    pub(crate) fn get(&self, key: UtxoKey, txid: &Hash256, vout: u32) -> Option<TxOut> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        Some(txout_from_parts(output.value, output.script_pubkey))
    }

    #[must_use]
    pub(crate) fn get_entry(&self, key: UtxoKey, txid: &Hash256, vout: u32) -> Option<UtxoCoin> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        Some(UtxoCoin {
            outpoint: OutPoint::new((*txid).into(), vout),
            txout: txout_from_parts(output.value, output.script_pubkey),
            coinbase: output.coinbase,
            height: output.height,
        })
    }

    #[must_use]
    pub(crate) fn has_live_outputs_for_txid(&self, key: UtxoKey, txid: &Hash256) -> bool {
        let table = self.inner.read();
        table
            .table
            .find(key.hash(), |record| {
                record.key() == key && record.txid() == *txid
            })
            .is_some_and(|record| !record.is_empty())
    }

    pub(crate) fn with_table<R>(&self, f: impl FnOnce(&ShardTable) -> R) -> R {
        let table = self.inner.read();
        f(&table)
    }

    pub(crate) fn for_each_all(&self, mut f: impl FnMut(&OutPoint, &[u8])) {
        let table = self.inner.read();
        for record in &table.table {
            for output in record.outputs() {
                let outpoint = OutPoint::new(record.txid().into(), output.vout);
                f(&outpoint, output.script_pubkey);
            }
        }
    }

    pub(crate) fn record_count(&self) -> usize {
        let table = self.inner.read();
        table.record_count()
    }

    pub(crate) fn output_count(&self) -> usize {
        let table = self.inner.read();
        table.output_count()
    }

    pub(crate) fn record_payload_bytes(&self) -> usize {
        let table = self.inner.read();
        table.record_payload_bytes()
    }

    pub(crate) fn table_bytes(&self) -> usize {
        let table = self.inner.read();
        table.table_bytes()
    }

    pub(crate) fn insert_record(&self, record: UtxoRecord) {
        if record.is_empty() {
            return;
        }
        let mut table = self.inner.write();
        replace_record(&mut table, record.key(), record.txid(), record);
    }
}

impl Default for Shard {
    fn default() -> Self {
        Self::new()
    }
}

fn replace_record(table: &mut ShardTable, key: UtxoKey, txid: Hash256, record: UtxoRecord) {
    match table.table.find_entry(key.hash(), |current| {
        current.key() == key && current.txid() == txid
    }) {
        Ok(occupied) => {
            *occupied.into_mut() = record;
        }
        Err(absent) => {
            absent
                .into_table()
                .insert_unique(key.hash(), record, |record| record.key().hash());
        }
    }
}

fn txout_from_parts(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: Script::from_bytes(script.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::UtxoError;

    #[test]
    fn empty_owned_record_is_not_inserted() -> Result<(), UtxoError> {
        let shard = Shard::new();
        shard.insert_record(UtxoRecord::from_owned_outputs(Hash256::default(), &[])?);
        assert_eq!(shard.record_count(), 0);
        Ok(())
    }
}
