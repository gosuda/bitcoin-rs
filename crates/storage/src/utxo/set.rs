#[cfg(any(test, feature = "test-seam"))]
use std::borrow::Borrow;
use std::io;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, Script, TxOut, Txid};
use parking_lot::{RwLock, RwLockReadGuard};
use thiserror::Error;

#[cfg(any(test, feature = "test-seam"))]
use crate::utxo::contract::BlockChanges;
use crate::utxo::stats::CoinStatsListener;
use crate::utxo::{UtxoKey, record::UtxoRecord, shard::Shard};
#[derive(Debug, Error)]
pub enum UtxoError {
    #[error(transparent)]
    Scan(#[from] crate::utxo::scan::UtxoScanError),
    #[error(transparent)]
    Storage(#[from] crate::StorageError),
    #[error("script_pubkey is too large for a u16 length: {len} bytes")]
    ScriptTooLarge { len: usize },
    #[error("encoded UTXO record exceeds addressable size at {len} bytes")]
    RecordTooLarge { len: usize },
    #[error("invalid encoded UTXO record")]
    CorruptRecord,
    #[error("snapshot coin height {height} exceeds snapshot base {snapshot_height}")]
    SnapshotCoinHeightOutOfRange { height: u32, snapshot_height: u32 },
    #[error("snapshot I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid snapshot magic {actual:#010x}")]
    InvalidSnapshotMagic { actual: u32 },
    #[error("unsupported snapshot version {version}")]
    UnsupportedSnapshotVersion { version: u32 },
    #[error("snapshot record count {count} does not fit usize")]
    SnapshotRecordCountTooLarge { count: u64 },
    #[error("strict snapshot record count mismatch: declared {declared}, actual {actual}")]
    SnapshotRecordCountMismatch { declared: u64, actual: usize },
    #[error("snapshot record has too many live outputs: {count}")]
    SnapshotOutputCountTooLarge { count: usize },
    #[error("snapshot record duplicates vout {vout}")]
    SnapshotDuplicateVout { vout: u32 },
    #[error("snapshot shard {shard} does not match key shard {key_shard}")]
    SnapshotShardMismatch { shard: u8, key_shard: u8 },
    #[error("snapshot txid prefix does not match record key prefix")]
    SnapshotTxidPrefixMismatch,
    #[error("output value {value} exceeds the maximum money supply")]
    AmountOutOfRange { value: u64 },
    #[error("UTXO walk cancelled")]
    Cancelled,
}

#[cfg(test)]
std::thread_local! {
    pub(crate) static PARSED_RECORD_INSERTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub use bitcoin_rs_consensus::UtxoCoin;

#[derive(Debug, Default)]
pub struct UtxoScan {
    pub txouts: usize,
    pub unspents: Vec<UtxoCoin>,
}

pub struct UtxoSet {
    pub(crate) shards: [Shard; UtxoKey::SHARD_COUNT],
    stable_view_lock: RwLock<()>,
    pub(crate) scan: crate::utxo::scan::ScanState,
    listener: Option<CoinStatsListener>,
}

#[derive(Debug, Default)]
pub struct UtxoMemoryReport {
    pub records: usize,
    pub outputs: usize,
    pub record_payload_bytes: usize,
    pub table_bytes: usize,
}

impl UtxoMemoryReport {
    #[must_use]
    pub const fn accounted_bytes(&self) -> usize {
        self.record_payload_bytes.saturating_add(self.table_bytes)
    }
}

enum ViewBacking<'a> {
    Borrowed {
        set: &'a UtxoSet,
        _guard: RwLockReadGuard<'a, ()>,
    },
    Owned(Box<UtxoSet>),
}

pub struct UtxoSetView<'a> {
    backing: ViewBacking<'a>,
}

impl UtxoSetView<'_> {
    fn backing_set(&self) -> &UtxoSet {
        match &self.backing {
            ViewBacking::Borrowed { set, .. } => set,
            ViewBacking::Owned(set) => set,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.backing_set()
            .shards
            .iter()
            .map(Shard::output_count)
            .sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.backing_set()
            .shards
            .iter()
            .map(Shard::record_count)
            .sum()
    }

    #[must_use]
    pub fn memory_report(&self) -> UtxoMemoryReport {
        let mut report = UtxoMemoryReport::default();
        for shard in &self.backing_set().shards {
            report.records += shard.record_count();
            report.outputs += shard.output_count();
            report.record_payload_bytes += shard.record_payload_bytes();
            report.table_bytes += shard.table_bytes();
        }
        report
    }

    pub fn hash_serialized_3(&self) -> Result<Hash256, UtxoError> {
        crate::utxo::snapshot::hash_serialized_3_stable(self)
    }

    pub fn hash_serialized_3_at_height(&self, snapshot_height: u32) -> Result<Hash256, UtxoError> {
        crate::utxo::snapshot::hash_serialized_3_stable_at_height(self, snapshot_height)
    }

    pub fn hash_serialized_3_cancellable(
        &self,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Hash256, UtxoError> {
        crate::utxo::snapshot::hash_serialized_3_stable_cancellable(self, cancelled)
    }

    pub fn for_each_all(&self, mut f: impl FnMut(&OutPoint, &[u8])) {
        for shard in &self.backing_set().shards {
            shard.for_each_all(&mut f);
        }
    }

    #[must_use]
    pub fn get_entry(&self, op: &OutPoint) -> Option<UtxoCoin> {
        let key = UtxoKey::from_txid(&op.txid);
        self.backing_set().shards[usize::from(key.shard())].get_entry(key, &op.txid.into(), op.vout)
    }

    pub(crate) fn shard(&self, idx: usize) -> &Shard {
        &self.backing_set().shards[idx]
    }

    pub(crate) fn snapshot_muhash_accumulator(
        &self,
    ) -> Option<crate::utxo::stats::CoinStatsAccumulator> {
        match &self.backing {
            ViewBacking::Owned(_) => Some(crate::utxo::stats::CoinStatsAccumulator::with_muhash(0)),
            ViewBacking::Borrowed { .. } => None,
        }
    }

    pub(crate) fn listener_muhash3072(&self) -> Option<[u8; 384]> {
        self.backing_set()
            .listener
            .as_ref()
            .map(CoinStatsListener::muhash3072)
    }
}

impl UtxoSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: [(); UtxoKey::SHARD_COUNT].map(|()| Shard::new()),
            stable_view_lock: RwLock::new(()),
            scan: crate::utxo::scan::ScanState::default(),
            listener: None,
        }
    }

    pub fn track_coin_stats(&mut self, listener: CoinStatsListener) {
        self.listener = Some(listener);
    }

    pub fn with_stable_view<R>(&self, read: impl FnOnce(&UtxoSetView<'_>) -> R) -> R {
        read(&self.lock_stable_view())
    }

    #[must_use]
    pub fn lock_stable_view(&self) -> UtxoSetView<'_> {
        UtxoSetView {
            backing: ViewBacking::Borrowed {
                set: self,
                _guard: self.stable_view_lock.read(),
            },
        }
    }

    #[must_use]
    pub fn get(&self, op: &OutPoint) -> Option<TxOut> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get(key, &op.txid.into(), op.vout)
    }

    #[must_use]
    pub fn get_entry(&self, op: &OutPoint) -> Option<UtxoCoin> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get_entry(key, &op.txid.into(), op.vout)
    }

    #[must_use]
    pub fn has_live_outputs_for_txid(&self, txid: &Hash256) -> bool {
        let key = UtxoKey::from_txid(&Txid::from(*txid));
        self.shards[usize::from(key.shard())].has_live_outputs_for_txid(key, txid)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(Shard::output_count).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.with_stable_view(|view| view.record_count())
    }

    pub fn insert_parsed_record(&self, record: UtxoRecord) {
        #[cfg(test)]
        PARSED_RECORD_INSERTIONS.with(|count| count.set(count.get() + 1));
        self.shards[usize::from(record.key().shard())].insert_record(record);
    }

    #[must_use]
    pub fn all_records(&self) -> Vec<UtxoRecord> {
        let mut records = Vec::new();
        for shard in &self.shards {
            shard.with_table(|table| {
                records.extend(table.table.iter().cloned());
            });
        }
        records
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct UtxoReader {
    set: Arc<UtxoSet>,
    coin_store: Arc<crate::CoinStore>,
}

impl UtxoReader {
    pub fn reserve_scan(
        &self,
    ) -> Result<crate::utxo::scan::UtxoScanPermit<'_>, crate::utxo::scan::UtxoScanError> {
        crate::utxo::scan::UtxoScanPermit::reserve(&self.set)
    }

    /// Captures a point-in-time engine snapshot of the `coins` keyspace for a
    /// streaming scan.
    ///
    /// Callers pair this with the chain-transition lock so the snapshot and the
    /// applied tip describe the same committed state.
    pub fn scan_coin_snapshot(
        &self,
    ) -> Result<Box<dyn crate::KvSnapshot + '_>, crate::StorageError> {
        self.coin_store.scan_snapshot()
    }

    #[must_use]
    pub fn scan_progress(&self) -> Option<u8> {
        self.set.scan.status()
    }

    pub fn abort_scan(&self) -> bool {
        self.set.scan.abort()
    }

    #[must_use]
    pub fn with_coin_store(set: Arc<UtxoSet>, coin_store: Arc<crate::CoinStore>) -> Self {
        Self { set, coin_store }
    }

    #[must_use]
    pub fn from_coin_store(coin_store: Arc<crate::CoinStore>) -> Self {
        Self {
            set: Arc::new(UtxoSet::new()),
            coin_store,
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn fixture_new() -> Self {
        let store = Arc::new(crate::MemoryKvStore::new());
        let coin_store = Arc::new(crate::CoinStore::open(store, 64 * 1024 * 1024));
        Self::from_coin_store(coin_store)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn fixture_with_set(set: Arc<UtxoSet>) -> Result<Self, UtxoError> {
        use crate::KvStore as _;

        let store = Arc::new(crate::MemoryKvStore::new());
        {
            let _view = set.lock_stable_view();
            for record in set.all_records() {
                store.put(
                    crate::ColumnFamily::Coins,
                    &record.txid().to_le_bytes(),
                    record.bytes(),
                )?;
            }
        }
        let coin_store = Arc::new(crate::CoinStore::open(store, 64 * 1024 * 1024));
        Ok(Self::with_coin_store(set, coin_store))
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn fixture_set(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.set)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn populate_fixture_coins<T: Borrow<TxOut>>(
        &self,
        changes: &BlockChanges<T>,
    ) -> Result<(), UtxoError> {
        crate::utxo::contract::populate_block_changes(&self.coin_store, changes)
    }

    pub fn get(&self, op: &OutPoint) -> Result<Option<TxOut>, UtxoError> {
        Ok(self.get_entry(op)?.map(|coin| coin.txout))
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn fixture_coin_store(&self) -> &Arc<crate::CoinStore> {
        &self.coin_store
    }

    pub fn get_entry(&self, op: &OutPoint) -> Result<Option<UtxoCoin>, UtxoError> {
        let key = crate::CoinKey(op.txid.0.to_le_bytes());
        let Some(bytes) = self.coin_store.get(&key)? else {
            return Ok(None);
        };
        let record = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())?;
        Ok(record.find_output(op.vout).map(|out| UtxoCoin {
            outpoint: *op,
            txout: TxOut {
                value: Amount::from_sat(out.value),
                script_pubkey: Script::from_bytes(out.script_pubkey.to_vec()),
            },
            coinbase: out.coinbase,
            height: out.height,
        }))
    }

    pub fn has_live_outputs_for_txid(&self, txid: &Hash256) -> Result<bool, UtxoError> {
        let key = crate::CoinKey(txid.to_le_bytes());
        let Some(bytes) = self.coin_store.get(&key)? else {
            return Ok(false);
        };
        let record = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())?;
        Ok(!record.is_empty())
    }

    pub fn confirmation_height(
        &self,
        txid: &Hash256,
        output_limit: u32,
    ) -> Result<Option<u32>, UtxoError> {
        let key = crate::CoinKey(txid.to_le_bytes());
        let Some(bytes) = self.coin_store.get(&key)? else {
            return Ok(None);
        };
        let record = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())?;
        Ok(record
            .outputs()
            .filter(|output| output.vout < output_limit)
            .min_by_key(|output| output.vout)
            .map(|output| output.height))
    }

    pub fn with_stable_view<R>(
        &self,
        read: impl FnOnce(&UtxoSetView<'_>) -> R,
    ) -> Result<R, UtxoError> {
        let view = self.lock_stable_view()?;
        Ok(read(&view))
    }

    pub fn lock_stable_view(&self) -> Result<UtxoSetView<'_>, UtxoError> {
        let snapshot = self.scan_coin_snapshot()?;
        let set = Box::new(UtxoSet::new());
        let rows = snapshot.iter_prefix(crate::ColumnFamily::Coins, &[])?;
        for row in rows {
            let (key, value) = row?;
            let key = crate::CoinKey::from_slice(&key)?;
            let record = UtxoRecord::from_encoded(value.to_vec().into_boxed_slice())?;
            if key.0 != record.txid().to_le_bytes() {
                return Err(UtxoError::CorruptRecord);
            }
            set.insert_parsed_record(record);
        }
        Ok(UtxoSetView {
            backing: ViewBacking::Owned(set),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::record::{OwnedUtxoOut, UtxoRecord};
    #[test]
    fn confirmation_height_uses_lowest_eligible_live_vout() -> Result<(), UtxoError> {
        let set = Arc::new(UtxoSet::new());
        let txid = Hash256::from_le_bytes(&[0xB1; 32]);
        set.insert_parsed_record(UtxoRecord::from_owned_outputs(
            txid,
            &[
                OwnedUtxoOut::new(2, 100, vec![0x51], false, 20),
                OwnedUtxoOut::new(9, 200, vec![0x52], false, 3),
            ],
        )?);
        let reader = UtxoReader::fixture_with_set(set)?;
        assert_eq!(reader.confirmation_height(&txid, 0)?, None);
        assert_eq!(reader.confirmation_height(&txid, 2)?, None);
        assert_eq!(reader.confirmation_height(&txid, 3)?, Some(20));
        assert_eq!(reader.confirmation_height(&txid, u32::MAX)?, Some(20));
        assert_eq!(
            reader.confirmation_height(&Hash256::default(), u32::MAX)?,
            None
        );
        Ok(())
    }

    // ARCH-07a
    #[test]
    fn query_views_keep_independent_committed_snapshots() -> Result<(), UtxoError> {
        use crate::utxo::contract::UtxoAdd;

        let reader = UtxoReader::fixture_new();
        let outpoint = OutPoint::new(Hash256::from_le_bytes(&[0xC1; 32]).into(), 0);
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            outpoint,
            TxOut {
                value: Amount::from_sat(17),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            false,
            7,
        ));
        reader.populate_fixture_coins(&changes)?;
        let first = reader.lock_stable_view()?;
        let mut removal = BlockChanges::<TxOut>::default();
        removal.remove(outpoint);
        reader.populate_fixture_coins(&removal)?;
        let second = reader.lock_stable_view()?;
        assert_eq!(first.len(), 1);
        assert_eq!(
            first
                .get_entry(&outpoint)
                .map(|coin| coin.txout.value.to_sat()),
            Some(17)
        );
        assert!(second.is_empty());
        assert!(second.get_entry(&outpoint).is_none());
        drop(second);
        assert_eq!(first.get_entry(&outpoint).map(|coin| coin.height), Some(7));
        assert!(reader.get_entry(&outpoint)?.is_none());
        Ok(())
    }

    #[test]
    fn reader_snapshot_trailers_hash_the_captured_image_not_the_live_listener()
    -> Result<(), UtxoError> {
        use crate::utxo::contract::UtxoAdd;
        use crate::utxo::stats::CoinStats;

        let outpoint = OutPoint::new(Hash256::from_le_bytes(&[0xD1; 32]).into(), 3);
        let txout = TxOut {
            value: Amount::from_sat(29),
            script_pubkey: Script::from_bytes(vec![0x51, 0x52]),
        };
        let mut expected = CoinStats::new();
        expected.insert_utxo(&outpoint, &txout, 11, true);
        let listener = CoinStatsListener::new(expected.clone());
        let mut source = UtxoSet::new();
        source.track_coin_stats(listener.clone());
        let reader = UtxoReader::fixture_with_set(Arc::new(source))?;
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(outpoint, txout.clone(), true, 11));
        reader.populate_fixture_coins(&changes)?;
        let captured = reader.lock_stable_view()?;

        let mut removal = BlockChanges::<TxOut>::default();
        removal.remove(outpoint);
        reader.populate_fixture_coins(&removal)?;
        listener.reset(CoinStats::new());
        let empty = reader.lock_stable_view()?;

        let tip = Hash256::from_le_bytes(&[0xD2; 32]);
        let mut bytes = Vec::new();
        let (trailer, ()) = captured.write_snapshot_observed(&tip, 11, &mut bytes, ())?;
        let expected_trailer = expected.muhash.finalize();
        assert_ne!(expected_trailer, [0_u8; 384]);
        assert_eq!(trailer, expected_trailer);
        assert_eq!(&bytes[bytes.len() - 384..], &expected_trailer);
        let decoded = crate::utxo::read_snapshot_strict_v4(&mut bytes.as_slice())?;
        assert_eq!(decoded.set.get(&outpoint), Some(txout));

        let mut empty_bytes = Vec::new();
        let (empty_trailer, ()) = empty.write_snapshot_observed(&tip, 12, &mut empty_bytes, ())?;
        assert_eq!(empty_trailer, CoinStats::new().muhash.finalize());
        assert_ne!(trailer, empty_trailer);
        Ok(())
    }

    #[test]
    fn fixture_with_set_seeds_authoritative_coin_reads() -> Result<(), UtxoError> {
        let set = Arc::new(UtxoSet::new());
        let txid = Hash256::from_le_bytes(&[0xA1; 32]);
        set.insert_parsed_record(UtxoRecord::from_owned_outputs(
            txid,
            &[
                OwnedUtxoOut::new(0, 100, vec![0x51], true, 7),
                OwnedUtxoOut::new(2, 200, vec![0x52], false, 8),
            ],
        )?);
        let reader = UtxoReader::fixture_with_set(set)?;
        for (vout, value, script, coinbase, height) in [
            (0, 100, vec![0x51], true, 7),
            (2, 200, vec![0x52], false, 8),
        ] {
            let op = OutPoint::new(txid.into(), vout);
            assert_eq!(
                reader.get_entry(&op)?,
                Some(UtxoCoin {
                    outpoint: op,
                    txout: TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: Script::from_bytes(script),
                    },
                    coinbase,
                    height,
                })
            );
        }
        assert!(reader.has_live_outputs_for_txid(&txid)?);
        assert!(reader.get_entry(&OutPoint::new(txid.into(), 1))?.is_none());
        assert_eq!(reader.with_stable_view(|view| view.len())?, 2);
        Ok(())
    }

    #[test]
    fn memory_report_accounts_payload_and_table_bytes_of_resident_records() -> Result<(), UtxoError>
    {
        let empty = UtxoSet::new();
        let empty_report = empty.lock_stable_view().memory_report();
        assert_eq!(empty_report.accounted_bytes(), 0);
        assert_eq!(empty_report.records, 0);

        let set = UtxoSet::new();
        let txid = Hash256::default();
        let outputs = vec![
            OwnedUtxoOut::new(0, 100, vec![0x51], false, 1),
            OwnedUtxoOut::new(1, 200, vec![0x52], false, 1),
            OwnedUtxoOut::new(2, 300, vec![0x53], false, 1),
        ];
        let record = UtxoRecord::from_owned_outputs(txid, &outputs)?;
        let payload_bytes = record.payload_bytes();
        set.insert_parsed_record(record);

        let report = set.lock_stable_view().memory_report();
        assert_eq!(report.records, 1);
        assert_eq!(report.outputs, 3);
        assert_eq!(
            report.record_payload_bytes, payload_bytes,
            "payload accounting must equal the stored record length"
        );
        assert!(
            report.accounted_bytes() > payload_bytes,
            "table overhead must be charged beside the payload"
        );
        Ok(())
    }
}
