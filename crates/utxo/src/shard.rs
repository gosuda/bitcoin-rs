use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, TxOut};
use bumpalo::{Bump, collections::Vec as BumpVec};
use crossbeam_utils::CachePadded;
use hashbrown::HashTable;
use parking_lot::RwLock;
use self_cell::self_cell;

use crate::{
    UtxoError, UtxoKey,
    record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord, validate_bitmap_vout},
    set::{BuildPayload, SpendPayload, UtxoChangeListener},
};

const OPS_AT_ONCE: usize = 32;

/// Per-shard hash table and script slab borrowed from the pinned arena owner.
pub struct ShardTable<'arena> {
    /// Raw hash table of arena-resident UTXO records.
    pub table: HashTable<&'arena UtxoRecord<'arena>>,
    /// Maximum script-slab byte length since the last rebuild.
    pub byte_arena_high_water: usize,
    /// Number of arena-resident records made unreachable by deletion/update.
    pub deleted: u32,
    pub(crate) script_bytes: BumpVec<'arena, u8>,
}

impl<'arena> ShardTable<'arena> {
    fn new(arena: &'arena Bump) -> Self {
        Self {
            table: HashTable::new(),
            byte_arena_high_water: 0,
            deleted: 0,
            script_bytes: BumpVec::new_in(arena),
        }
    }

    pub(crate) fn record_count(&self) -> usize {
        self.table.len()
    }

    pub(crate) fn output_count(&self) -> usize {
        self.table.iter().map(|record| record.output_count()).sum()
    }
}

/// One live UTXO output with the metadata consensus consumers need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveOutput {
    /// The transaction output script + value.
    pub txout: TxOut,
    /// Whether the originating transaction was a coinbase.
    pub coinbase: bool,
    /// Block height at which this output was created.
    pub height: u32,
}

self_cell! {
    /// Pinned shard arena plus the table that borrows from it.
    pub struct ShardCell {
        owner: Box<Bump>,
        #[covariant]
        dependent: ShardTable,
    }
}

/// One cache-padded, lock-protected UTXO shard.
pub struct Shard {
    inner: CachePadded<RwLock<ShardCell>>,
}

// SAFETY: `Shard` never exposes the self-cell owner or dependent by reference
// outside methods that hold the `RwLock`. Read methods only inspect immutable
// table/script data; all arena allocation and table mutation happen under the
// write lock, so sharing `&Shard` across rayon workers does not create
// concurrent access to `Bump`'s interior `Cell`s or to `bumpalo::Vec`.
unsafe impl Sync for Shard {}

impl Shard {
    /// Builds an empty shard with a pinned `Bump` owner.
    #[must_use]
    pub fn new() -> Self {
        let cell = ShardCell::new(Box::new(Bump::new()), |arena| ShardTable::new(arena));
        Self {
            inner: CachePadded::new(RwLock::new(cell)),
        }
    }

    pub(crate) fn commit_batch(
        &self,
        adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
        removes: &[SpendPayload<'_>],
        listener: Option<&(dyn UtxoChangeListener + Send + Sync)>,
    ) -> Result<(), UtxoError> {
        let mut cell = self.inner.write();
        cell.with_dependent_mut(|arena, table| {
            for chunk in removes.chunks(OPS_AT_ONCE) {
                for remove in chunk {
                    apply_remove(arena, table, remove, listener)?;
                }
            }
            for chunk in adds.chunks(OPS_AT_ONCE) {
                for (key, txid, payload) in chunk {
                    apply_add(arena, table, *key, *txid, payload, listener)?;
                }
            }
            Ok::<(), UtxoError>(())
        })
    }

    /// Returns an owned transaction output if `key:vout` is live in this shard.
    #[must_use]
    pub fn get(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<TxOut> {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| {
            let record = table.table.find(key.hash(), |record| {
                record.key() == *key && record.txid() == *txid
            })?;
            let output = record.find_output(vout)?;
            let script = script_slice(table, output)?;
            Some(txout_from_parts(output.value, script))
        })
    }

    /// Returns the full live-output entry (txout + coinbase + height)
    /// if `key:vout` is live in this shard.
    #[must_use]
    pub fn get_entry(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<LiveOutput> {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| {
            let record = table.table.find(key.hash(), |record| {
                record.key() == *key && record.txid() == *txid
            })?;
            let output = record.find_output(vout)?;
            let script = script_slice(table, output)?;
            Some(LiveOutput {
                txout: txout_from_parts(output.value, script),
                coinbase: output.coinbase,
                height: output.height,
            })
        })
    }

    pub(crate) fn with_table<R>(&self, f: impl FnOnce(&ShardTable<'_>) -> R) -> R {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| f(table))
    }

    pub(crate) fn record_count(&self) -> usize {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| table.record_count())
    }

    pub(crate) fn output_count(&self) -> usize {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| table.output_count())
    }

    pub(crate) fn arena_high_water(&self) -> usize {
        self.with_table(|table| table.byte_arena_high_water)
    }

    pub(crate) fn insert_owned_record(
        &self,
        key: UtxoKey,
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<(), UtxoError> {
        let mut cell = self.inner.write();
        cell.with_dependent_mut(|arena, table| {
            let _old = take_record(table, key, txid);
            let mut record = UtxoRecord::new(key, txid);
            for output in outputs {
                append_owned_output(table, &mut record, output)?;
            }
            if !record.is_empty() {
                insert_record(arena, table, record);
            }
            Ok::<(), UtxoError>(())
        })
    }

    pub(crate) fn defrag_if_needed(&self) -> Result<(), UtxoError> {
        let mut cell = self.inner.write();
        let records = cell.with_dependent(|_arena, table| {
            let deleted = usize::try_from(table.deleted).unwrap_or(usize::MAX);
            let live = table.table.len();
            let total = live.saturating_add(deleted);
            if total == 0 || deleted.saturating_mul(4) <= total {
                Ok::<Option<Vec<(UtxoKey, Hash256, Vec<OwnedUtxoOut>)>>, UtxoError>(None)
            } else {
                collect_owned_records(table).map(Some)
            }
        })?;

        let Some(records) = records else {
            return Ok(());
        };

        let mut replacement = ShardCell::new(Box::new(Bump::new()), |arena| {
            let mut table = ShardTable::new(arena);
            table.table = HashTable::with_capacity(records.len());
            table
        });
        replacement.with_dependent_mut(|arena, table| {
            for (key, txid, outputs) in &records {
                let mut record = UtxoRecord::new(*key, *txid);
                for output in outputs {
                    append_owned_output(table, &mut record, output)?;
                }
                if !record.is_empty() {
                    insert_record(arena, table, record);
                }
            }
            table.deleted = 0;
            table.byte_arena_high_water = table.script_bytes.len();
            Ok::<(), UtxoError>(())
        })?;

        *cell = replacement;
        Ok(())
    }
}

impl Default for Shard {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_add<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    payload: &BuildPayload<'_>,
    listener: Option<&(dyn UtxoChangeListener + Send + Sync)>,
) -> Result<(), UtxoError> {
    validate_bitmap_vout(payload.vout)?;
    let mut record = take_record(table, key, txid).unwrap_or_else(|| UtxoRecord::new(key, txid));
    let script = payload.txout.script_pubkey.as_bytes();
    let script_len =
        u16::try_from(script.len()).map_err(|_| UtxoError::ScriptTooLarge { len: script.len() })?;
    let offset =
        u32::try_from(table.script_bytes.len()).map_err(|_| UtxoError::ArenaOffsetOverflow {
            len: table.script_bytes.len(),
        })?;
    table.script_bytes.extend_from_slice(script);
    table.byte_arena_high_water = table.byte_arena_high_water.max(table.script_bytes.len());
    record.add_output(OneUtxoOut {
        vout: payload.vout,
        value: payload.txout.value.to_sat(),
        script_pubkey_offset: offset,
        script_pubkey_len: script_len,
        coinbase: payload.coinbase,
        height: payload.height,
    })?;
    insert_record(arena, table, record);
    if let Some(listener) = listener {
        listener.on_insert(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        );
    }
    Ok(())
}

fn apply_remove<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    remove: &SpendPayload<'_>,
    listener: Option<&(dyn UtxoChangeListener + Send + Sync)>,
) -> Result<(), UtxoError> {
    validate_bitmap_vout(remove.vout)?;
    let Some(mut record) = take_record(table, remove.key, remove.txid) else {
        return Ok(());
    };
    let removed_output = record.find_output(remove.vout).and_then(|output| {
        let script = script_slice(table, output)?;
        Some((
            txout_from_parts(output.value, script),
            output.height,
            output.coinbase,
        ))
    });
    let removed = record.remove_output(remove.vout)?;
    if removed && !record.is_empty() {
        insert_record(arena, table, record);
    }
    if let (true, Some((txout, height, coinbase)), Some(listener)) =
        (removed, removed_output, listener)
    {
        listener.on_remove_coin(remove.op, &txout, height, coinbase);
    }
    Ok(())
}

fn append_owned_output<'arena>(
    table: &mut ShardTable<'arena>,
    record: &mut UtxoRecord<'arena>,
    output: &OwnedUtxoOut,
) -> Result<(), UtxoError> {
    validate_bitmap_vout(output.vout)?;
    let script_len =
        u16::try_from(output.script_pubkey.len()).map_err(|_| UtxoError::ScriptTooLarge {
            len: output.script_pubkey.len(),
        })?;
    let offset =
        u32::try_from(table.script_bytes.len()).map_err(|_| UtxoError::ArenaOffsetOverflow {
            len: table.script_bytes.len(),
        })?;
    table.script_bytes.extend_from_slice(&output.script_pubkey);
    table.byte_arena_high_water = table.byte_arena_high_water.max(table.script_bytes.len());
    record.add_output(OneUtxoOut {
        vout: output.vout,
        value: output.value,
        script_pubkey_offset: offset,
        script_pubkey_len: script_len,
        coinbase: output.coinbase,
        height: output.height,
    })
}

fn take_record<'arena>(
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
) -> Option<UtxoRecord<'arena>> {
    let entry = table
        .table
        .find_entry(key.hash(), |record| {
            record.key() == key && record.txid() == txid
        })
        .ok()?;
    let (record, _vacant) = entry.remove();
    table.deleted = table.deleted.saturating_add(1);
    Some(record.clone())
}

fn insert_record<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    record: UtxoRecord<'arena>,
) {
    let key = record.key();
    let record_ref: &'arena UtxoRecord<'arena> = arena.alloc(record);
    table
        .table
        .insert_unique(key.hash(), record_ref, |record| record.key().hash());
}

fn collect_owned_records(
    table: &ShardTable<'_>,
) -> Result<Vec<(UtxoKey, Hash256, Vec<OwnedUtxoOut>)>, UtxoError> {
    let mut records = Vec::with_capacity(table.table.len());
    for record in &table.table {
        let mut outputs = Vec::with_capacity(record.output_count());
        for output in record.iter_outputs() {
            let script = script_slice(table, output).ok_or(UtxoError::CorruptArena)?;
            outputs.push(OwnedUtxoOut::new(
                output.vout,
                output.value,
                script.to_vec(),
                output.coinbase,
                output.height,
            ));
        }
        records.push((record.key(), record.txid(), outputs));
    }
    Ok(records)
}

fn script_slice<'table>(
    table: &'table ShardTable<'_>,
    output: &OneUtxoOut,
) -> Option<&'table [u8]> {
    let start = usize::try_from(output.script_pubkey_offset).ok()?;
    let len = usize::from(output.script_pubkey_len);
    let end = start.checked_add(len)?;
    table.script_bytes.get(start..end)
}

fn txout_from_parts(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
    }
}
