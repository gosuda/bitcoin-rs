use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bumpalo::{Bump, collections::Vec as BumpVec};
use crossbeam_utils::CachePadded;
use hashbrown::HashTable;
use parking_lot::RwLock;
use self_cell::self_cell;
use smallvec::SmallVec;

use crate::{
    UtxoError, UtxoKey,
    record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord, bitmap_vout_bit},
    set::{
        BuildPayload, ScannedUtxo, SpendPayload, UtxoAddView, UtxoChangeEvents, UtxoChangeListener,
        UtxoInserted, UtxoRemoved, UtxoScan,
    },
};

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

/// One live UTXO output's metadata without script or value materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveOutputMeta {
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
            if listener.is_some() {
                commit_batch_with_listener(arena, table, adds, removes, listener)
            } else {
                commit_batch_coalesced(arena, table, adds, removes)
            }
        })
    }

    pub(crate) fn commit_batch_collect_events<'a>(
        &self,
        adds: &'a [(UtxoKey, Hash256, BuildPayload<'a>)],
        removes: &[SpendPayload<'_>],
        coalesce_events: bool,
    ) -> (UtxoChangeEvents<'a>, Result<(), UtxoError>) {
        let mut cell = self.inner.write();
        cell.with_dependent_mut(|arena, table| {
            commit_batch_collect_events(arena, table, adds, removes, coalesce_events)
        })
    }

    pub(crate) fn commit_single_shard_batch<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
        shard_idx: usize,
    ) -> Result<(), UtxoError> {
        let mut cell = self.inner.write();
        cell.with_dependent_mut(|arena, table| {
            commit_single_shard_coalesced(arena, table, adds, removes, shard_idx)
        })
    }

    pub(crate) fn commit_single_shard_batch_with_listener<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
        shard_idx: usize,
        listener: &(dyn UtxoChangeListener + Send + Sync),
    ) -> Result<(), UtxoError> {
        let mut cell = self.inner.write();
        cell.with_dependent_mut(|arena, table| {
            commit_single_shard_with_listener(arena, table, adds, removes, shard_idx, listener)
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

    /// Returns live-output metadata without materializing script bytes.
    #[must_use]
    pub fn get_meta(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<LiveOutputMeta> {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| {
            let record = table.table.find(key.hash(), |record| {
                record.key() == *key && record.txid() == *txid
            })?;
            let output = record.find_output(vout)?;
            Some(LiveOutputMeta {
                coinbase: output.coinbase,
                height: output.height,
            })
        })
    }

    /// Returns true when this shard has any live output for `txid`.
    #[must_use]
    pub fn has_live_outputs_for_txid(&self, key: &UtxoKey, txid: &Hash256) -> bool {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| {
            table
                .table
                .find(key.hash(), |record| {
                    record.key() == *key && record.txid() == *txid
                })
                .is_some_and(|record| !record.is_empty())
        })
    }

    pub(crate) fn with_table<R>(&self, f: impl FnOnce(&ShardTable<'_>) -> R) -> R {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| f(table))
    }

    pub(crate) fn scan_script_pubkeys(
        &self,
        scripts: &[ScriptBuf],
        scan: &mut UtxoScan,
    ) -> Result<(), UtxoError> {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| {
            for record in &table.table {
                for output in record.iter_outputs() {
                    scan.txouts = scan.txouts.saturating_add(1);
                    let script = script_slice(table, output).ok_or(UtxoError::CorruptArena)?;
                    if scripts.iter().any(|target| target.as_bytes() == script) {
                        scan.unspents.push(ScannedUtxo {
                            outpoint: OutPoint::new(record.txid(), output.vout),
                            txout: txout_from_parts(output.value, script),
                            coinbase: output.coinbase,
                            height: output.height,
                        });
                    }
                }
            }
            Ok(())
        })
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

    pub(crate) fn validate_script_capacity(
        &self,
        adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    ) -> Result<(), UtxoError> {
        let cell = self.inner.read();
        cell.with_dependent(|_arena, table| {
            validate_append_script_offsets(table.script_bytes.len(), adds)
        })
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

fn commit_batch_with_listener<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    removes: &[SpendPayload<'_>],
    listener: Option<&(dyn UtxoChangeListener + Send + Sync)>,
) -> Result<(), UtxoError> {
    let Some(listener) = listener else {
        return commit_batch_coalesced(arena, table, adds, removes);
    };

    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let run_len = rest
            .iter()
            .take_while(|remove| remove.key == first.key && remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_remove_run_with_listener(arena, table, &remaining_removes[..run_len], listener);
        remaining_removes = &remaining_removes[run_len..];
    }

    let mut remaining_adds = adds;
    while let Some(((key, txid, _payload), rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| next_key == key && next_txid == txid)
            .count()
            .saturating_add(1);
        apply_add_run_with_listener(
            arena,
            table,
            *key,
            *txid,
            &remaining_adds[..run_len],
            listener,
        )?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn commit_batch_collect_events<'arena, 'add>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    adds: &'add [(UtxoKey, Hash256, BuildPayload<'add>)],
    removes: &[SpendPayload<'_>],
    coalesce_events: bool,
) -> (UtxoChangeEvents<'add>, Result<(), UtxoError>) {
    let mut events = if coalesce_events {
        UtxoChangeEvents::with_coalesced_capacity(adds.len(), removes.len())
    } else {
        UtxoChangeEvents::default()
    };
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let run_len = rest
            .iter()
            .take_while(|remove| remove.key == first.key && remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_remove_run_collect_events(
            arena,
            table,
            &remaining_removes[..run_len],
            &mut events,
            coalesce_events,
        );
        remaining_removes = &remaining_removes[run_len..];
    }

    let mut remaining_adds = adds;
    while let Some(((key, txid, _payload), rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| next_key == key && next_txid == txid)
            .count()
            .saturating_add(1);
        if let Err(error) = apply_add_run_collect_events(
            arena,
            table,
            *key,
            *txid,
            &remaining_adds[..run_len],
            &mut events,
            coalesce_events,
        ) {
            return (events, Err(error));
        }
        remaining_adds = &remaining_adds[run_len..];
    }
    (events, Ok(()))
}

fn commit_batch_coalesced<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    removes: &[SpendPayload<'_>],
) -> Result<(), UtxoError> {
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let run_len = rest
            .iter()
            .take_while(|remove| remove.key == first.key && remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_remove_run(arena, table, &remaining_removes[..run_len]);
        remaining_removes = &remaining_removes[run_len..];
    }

    let mut remaining_adds = adds;
    while let Some(((key, txid, _payload), rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| next_key == key && next_txid == txid)
            .count()
            .saturating_add(1);
        apply_add_run(arena, table, *key, *txid, &remaining_adds[..run_len])?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn commit_single_shard_coalesced<'arena, A: UtxoAddView>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    adds: &[A],
    removes: &[OutPoint],
    shard_idx: usize,
) -> Result<(), UtxoError> {
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let key = UtxoKey::from_txid(&first.txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|remove| remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_outpoint_remove_run(arena, table, key, first.txid, &remaining_removes[..run_len]);
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, utxo_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let key = UtxoKey::from_txid(&first.outpoint().txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|add| add.outpoint().txid == first.outpoint().txid)
            .count()
            .saturating_add(1);
        apply_utxo_add_run(
            arena,
            table,
            key,
            first.outpoint().txid,
            &remaining_adds[..run_len],
        )?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn commit_single_shard_with_listener<'arena, A: UtxoAddView>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    adds: &[A],
    removes: &[OutPoint],
    shard_idx: usize,
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let key = UtxoKey::from_txid(&first.txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|remove| remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_outpoint_remove_run_with_listener(
            arena,
            table,
            key,
            first.txid,
            &remaining_removes[..run_len],
            listener,
        );
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, utxo_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let key = UtxoKey::from_txid(&first.outpoint().txid);
        debug_assert_eq!(usize::from(key.shard()), shard_idx);
        let run_len = rest
            .iter()
            .take_while(|add| add.outpoint().txid == first.outpoint().txid)
            .count()
            .saturating_add(1);
        apply_utxo_add_run_with_listener(
            arena,
            table,
            key,
            first.outpoint().txid,
            &remaining_adds[..run_len],
            listener,
        )?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn reserve_add_runs(table: &mut ShardTable<'_>, additional_runs: usize) {
    if additional_runs != 0 {
        table
            .table
            .reserve(additional_runs, |record| record.key().hash());
    }
}

fn utxo_add_run_count<A: UtxoAddView>(adds: &[A]) -> usize {
    let mut run_count = 0usize;
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|add| add.outpoint().txid == first.outpoint().txid)
            .count()
            .saturating_add(1);
        run_count = run_count.saturating_add(1);
        remaining_adds = &remaining_adds[run_len..];
    }
    run_count
}

fn apply_remove_run<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    removes: &[SpendPayload<'_>],
) {
    let Some(first) = removes.first() else {
        return;
    };
    if delete_record_if_fully_spent(
        table,
        first.key,
        first.txid,
        removes.len(),
        |index| removes[index].vout,
        |vout| removes.iter().any(|remove| remove.vout == vout),
    ) {
        return;
    }
    let Some(mut record) = take_record(table, first.key, first.txid) else {
        return;
    };
    for remove in removes {
        let _removed = record.remove_output(remove.vout);
    }
    if !record.is_empty() {
        insert_record(arena, table, record);
    }
}

fn apply_outpoint_remove_run<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    removes: &[OutPoint],
) {
    if delete_record_if_fully_spent(
        table,
        key,
        txid,
        removes.len(),
        |index| removes[index].vout,
        |vout| removes.iter().any(|remove| remove.vout == vout),
    ) {
        return;
    }
    let Some(mut record) = take_record(table, key, txid) else {
        return;
    };
    for remove in removes {
        let _removed = record.remove_output(remove.vout);
    }
    if !record.is_empty() {
        insert_record(arena, table, record);
    }
}

fn apply_remove_run_with_listener<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    removes: &[SpendPayload<'_>],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) {
    let Some(first) = removes.first() else {
        return;
    };
    let Some(mut record) = take_record(table, first.key, first.txid) else {
        return;
    };
    if let Some(removed_coins) = full_record_removals_by_order::<[UtxoRemoved; 2]>(
        table,
        &record,
        removes.len(),
        |index| removes[index].vout,
        |index| *removes[index].op,
    ) {
        listener.on_remove_coins(&removed_coins);
        return;
    }
    let mut removed_coins = SmallVec::<[UtxoRemoved; 2]>::with_capacity(removes.len());
    for remove in removes {
        if let Some(removed_output) = record.remove_output(remove.vout)
            && let Some((txout, height, coinbase)) = output_details(table, &removed_output)
        {
            removed_coins.push(UtxoRemoved::new(*remove.op, txout, height, coinbase));
        }
    }
    listener.on_remove_coins(&removed_coins);
    if !record.is_empty() {
        insert_record(arena, table, record);
    }
}

fn apply_remove_run_collect_events<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    removes: &[SpendPayload<'_>],
    events: &mut UtxoChangeEvents<'_>,
    coalesce_events: bool,
) {
    let Some(first) = removes.first() else {
        return;
    };
    let Some(mut record) = take_record(table, first.key, first.txid) else {
        return;
    };
    if let Some(removed_coins) = full_record_removals_by_order::<[UtxoRemoved; 2]>(
        table,
        &record,
        removes.len(),
        |index| removes[index].vout,
        |index| *removes[index].op,
    ) {
        if coalesce_events {
            events.push_remove_batch_coalesced(removed_coins);
        } else {
            events.push_remove_batch(removed_coins);
        }
        return;
    }
    let mut removed_coins = SmallVec::<[UtxoRemoved; 2]>::with_capacity(removes.len());
    for remove in removes {
        if let Some(removed_output) = record.remove_output(remove.vout)
            && let Some((txout, height, coinbase)) = output_details(table, &removed_output)
        {
            removed_coins.push(UtxoRemoved::new(*remove.op, txout, height, coinbase));
        }
    }
    if coalesce_events {
        events.push_remove_batch_coalesced(removed_coins);
    } else {
        events.push_remove_batch(removed_coins);
    }
    if !record.is_empty() {
        insert_record(arena, table, record);
    }
}

fn apply_outpoint_remove_run_with_listener<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    removes: &[OutPoint],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) {
    let Some(mut record) = take_record(table, key, txid) else {
        return;
    };
    if let Some(removed_coins) = full_record_removals_by_order::<[UtxoRemoved; 8]>(
        table,
        &record,
        removes.len(),
        |index| removes[index].vout,
        |index| removes[index],
    ) {
        listener.on_remove_coins(&removed_coins);
        return;
    }
    let mut removed_coins = SmallVec::<[UtxoRemoved; 8]>::with_capacity(removes.len());
    for remove in removes {
        if let Some(removed_output) = record.remove_output(remove.vout)
            && let Some((txout, height, coinbase)) = output_details(table, &removed_output)
        {
            removed_coins.push(UtxoRemoved::new(*remove, txout, height, coinbase));
        }
    }
    listener.on_remove_coins(&removed_coins);
    if !record.is_empty() {
        insert_record(arena, table, record);
    }
}

fn full_record_removals_by_order<A>(
    table: &ShardTable<'_>,
    record: &UtxoRecord<'_>,
    remove_count: usize,
    mut remove_vout: impl FnMut(usize) -> u32,
    mut remove_outpoint: impl FnMut(usize) -> OutPoint,
) -> Option<SmallVec<A>>
where
    A: smallvec::Array<Item = UtxoRemoved>,
{
    if record.output_count() != remove_count
        || usize::try_from(record.vout_bitmap.count_ones()).ok()? != remove_count
    {
        return None;
    }

    let mut outputs = [None; 64];
    let mut record_bitmap = 0_u64;
    for output in record.iter_outputs() {
        let bit = bitmap_vout_bit(output.vout)?;
        let index = usize::try_from(output.vout).ok()?;
        if outputs[index].replace(*output).is_some() {
            return None;
        }
        record_bitmap |= bit;
    }
    if record_bitmap != record.vout_bitmap {
        return None;
    }

    let mut remove_bitmap = 0_u64;
    let mut removed_coins = SmallVec::<A>::with_capacity(remove_count);
    for index in 0..remove_count {
        let vout = remove_vout(index);
        let bit = bitmap_vout_bit(vout)?;
        if remove_bitmap & bit != 0 {
            return None;
        }
        remove_bitmap |= bit;
        let output = outputs[usize::try_from(vout).ok()?]?;
        let (txout, height, coinbase) = output_details(table, &output)?;
        removed_coins.push(UtxoRemoved::new(
            remove_outpoint(index),
            txout,
            height,
            coinbase,
        ));
    }

    (remove_bitmap == record.vout_bitmap).then_some(removed_coins)
}

fn apply_add_run<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
) -> Result<(), UtxoError> {
    let mut record = take_record(table, key, txid).unwrap_or_else(|| UtxoRecord::new(key, txid));
    let add_unique = build_adds_extend_record(
        &record,
        adds.iter().map(|(_key, _txid, payload)| payload.vout),
    );
    for (_key, _txid, payload) in adds {
        if add_unique {
            append_unique_build_output(table, &mut record, payload)?;
        } else {
            append_build_output(table, &mut record, payload)?;
        }
    }
    insert_record(arena, table, record);
    Ok(())
}

fn apply_utxo_add_run<'arena, A: UtxoAddView>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    adds: &[A],
) -> Result<(), UtxoError> {
    let mut record = take_record(table, key, txid).unwrap_or_else(|| UtxoRecord::new(key, txid));
    let add_unique = build_adds_extend_record(&record, adds.iter().map(|add| add.outpoint().vout));
    for add in adds {
        let payload = add.payload();
        if add_unique {
            append_unique_build_output(table, &mut record, &payload)?;
        } else {
            append_build_output(table, &mut record, &payload)?;
        }
    }
    insert_record(arena, table, record);
    Ok(())
}

fn apply_utxo_add_run_with_listener<'arena, A: UtxoAddView>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    adds: &[A],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let mut record = take_record(table, key, txid).unwrap_or_else(|| UtxoRecord::new(key, txid));
    let add_unique = build_adds_extend_record(&record, adds.iter().map(|add| add.outpoint().vout));
    let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
    for add in adds {
        let payload = add.payload();
        if add_unique {
            append_unique_build_output(table, &mut record, &payload)?;
        } else {
            let overwritten = match record.find_output(payload.vout) {
                Some(output) => Some(output_details(table, output).ok_or(UtxoError::CorruptArena)?),
                None => None,
            };
            append_build_output(table, &mut record, &payload)?;
            if let Some((txout, height, coinbase)) = overwritten {
                flush_inserted_coins(listener, &mut inserted_coins);
                listener.on_remove_coin(payload.outpoint, &txout, height, coinbase);
            }
        }
        inserted_coins.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    insert_record(arena, table, record);
    flush_inserted_coins(listener, &mut inserted_coins);
    Ok(())
}

fn apply_add_run_with_listener<'arena>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let mut record = take_record(table, key, txid).unwrap_or_else(|| UtxoRecord::new(key, txid));
    let add_unique = build_adds_extend_record(
        &record,
        adds.iter().map(|(_key, _txid, payload)| payload.vout),
    );
    let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
    for (_key, _txid, payload) in adds {
        if add_unique {
            append_unique_build_output(table, &mut record, payload)?;
        } else {
            let overwritten = match record.find_output(payload.vout) {
                Some(output) => Some(output_details(table, output).ok_or(UtxoError::CorruptArena)?),
                None => None,
            };
            append_build_output(table, &mut record, payload)?;
            if let Some((txout, height, coinbase)) = overwritten {
                flush_inserted_coins(listener, &mut inserted_coins);
                listener.on_remove_coin(payload.outpoint, &txout, height, coinbase);
            }
        }
        inserted_coins.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    insert_record(arena, table, record);
    flush_inserted_coins(listener, &mut inserted_coins);
    Ok(())
}

fn apply_add_run_collect_events<'arena, 'add>(
    arena: &'arena Bump,
    table: &mut ShardTable<'arena>,
    key: UtxoKey,
    txid: Hash256,
    adds: &'add [(UtxoKey, Hash256, BuildPayload<'add>)],
    events: &mut UtxoChangeEvents<'add>,
    coalesce_events: bool,
) -> Result<(), UtxoError> {
    let mut record = take_record(table, key, txid).unwrap_or_else(|| UtxoRecord::new(key, txid));
    let add_unique = build_adds_extend_record(
        &record,
        adds.iter().map(|(_key, _txid, payload)| payload.vout),
    );
    let mut inserted_coins = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(adds.len());
    for (_key, _txid, payload) in adds {
        if add_unique {
            append_unique_build_output(table, &mut record, payload)?;
        } else {
            let overwritten = match record.find_output(payload.vout) {
                Some(output) => Some(output_details(table, output).ok_or(UtxoError::CorruptArena)?),
                None => None,
            };
            append_build_output(table, &mut record, payload)?;
            if let Some((txout, height, coinbase)) = overwritten {
                flush_inserted_events(events, &mut inserted_coins, coalesce_events);
                events.push_remove_coin(UtxoRemoved::new(
                    *payload.outpoint,
                    txout,
                    height,
                    coinbase,
                ));
            }
        }
        inserted_coins.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    insert_record(arena, table, record);
    flush_inserted_events(events, &mut inserted_coins, coalesce_events);
    Ok(())
}

fn flush_inserted_events<'add>(
    events: &mut UtxoChangeEvents<'add>,
    inserted_coins: &mut SmallVec<[UtxoInserted<'add>; 8]>,
    coalesce_events: bool,
) {
    if !inserted_coins.is_empty() {
        if coalesce_events {
            events.push_insert_batch_coalesced(core::mem::take(inserted_coins));
        } else {
            events.push_insert_batch(core::mem::take(inserted_coins));
        }
    }
}

fn flush_inserted_coins(
    listener: &(dyn UtxoChangeListener + Send + Sync),
    inserted_coins: &mut SmallVec<[UtxoInserted<'_>; 8]>,
) {
    if !inserted_coins.is_empty() {
        listener.on_insert_coins(inserted_coins);
        inserted_coins.clear();
    }
}

fn validate_append_script_offsets(
    current_len: usize,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
) -> Result<(), UtxoError> {
    let mut next_offset = current_len;
    for (_key, _txid, payload) in adds {
        let script_len = payload.txout.script_pubkey.as_bytes().len();
        let _fits =
            u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
        let _offset = u32::try_from(next_offset)
            .map_err(|_| UtxoError::ArenaOffsetOverflow { len: next_offset })?;
        next_offset = next_offset
            .checked_add(script_len)
            .ok_or(UtxoError::ArenaOffsetOverflow { len: next_offset })?;
    }
    Ok(())
}

fn append_build_output<'arena>(
    table: &mut ShardTable<'arena>,
    record: &mut UtxoRecord<'arena>,
    payload: &BuildPayload<'_>,
) -> Result<(), UtxoError> {
    append_record_output::<false>(table, record, payload)
}

fn append_unique_build_output<'arena>(
    table: &mut ShardTable<'arena>,
    record: &mut UtxoRecord<'arena>,
    payload: &BuildPayload<'_>,
) -> Result<(), UtxoError> {
    append_record_output::<true>(table, record, payload)
}

fn append_record_output<'arena, const UNIQUE: bool>(
    table: &mut ShardTable<'arena>,
    record: &mut UtxoRecord<'arena>,
    payload: &BuildPayload<'_>,
) -> Result<(), UtxoError> {
    let script = payload.txout.script_pubkey.as_bytes();
    let script_len =
        u16::try_from(script.len()).map_err(|_| UtxoError::ScriptTooLarge { len: script.len() })?;
    let offset =
        u32::try_from(table.script_bytes.len()).map_err(|_| UtxoError::ArenaOffsetOverflow {
            len: table.script_bytes.len(),
        })?;
    table.script_bytes.extend_from_slice(script);
    table.byte_arena_high_water = table.byte_arena_high_water.max(table.script_bytes.len());
    let output = OneUtxoOut {
        vout: payload.vout,
        value: payload.txout.value.to_sat(),
        script_pubkey_offset: offset,
        script_pubkey_len: script_len,
        coinbase: payload.coinbase,
        height: payload.height,
    };
    if UNIQUE {
        record.add_unique_output(output);
    } else {
        record.add_output(output);
    }
    Ok(())
}

fn build_adds_extend_record(record: &UtxoRecord<'_>, vouts: impl Iterator<Item = u32>) -> bool {
    let mut previous = record.max_vout();
    for vout in vouts {
        if previous.is_some_and(|previous| vout <= previous) {
            return false;
        }
        previous = Some(vout);
    }
    true
}

fn append_owned_output<'arena>(
    table: &mut ShardTable<'arena>,
    record: &mut UtxoRecord<'arena>,
    output: &OwnedUtxoOut,
) -> Result<(), UtxoError> {
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
    });
    Ok(())
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

fn delete_record_if_fully_spent(
    table: &mut ShardTable<'_>,
    key: UtxoKey,
    txid: Hash256,
    remove_count: usize,
    mut remove_vout: impl FnMut(usize) -> u32,
    contains_vout: impl Fn(u32) -> bool,
) -> bool {
    let Ok(entry) = table.table.find_entry(key.hash(), |record| {
        record.key() == key && record.txid() == txid
    }) else {
        return false;
    };
    let record = entry.get();
    if record.output_count() != remove_count {
        return false;
    }
    match record_fully_spent_by_bitmap(record, remove_count, &mut remove_vout) {
        Some(true) => {}
        Some(false) => return false,
        None => {
            if !record
                .iter_outputs()
                .all(|output| contains_vout(output.vout))
            {
                return false;
            }
        }
    }
    let (_record, _vacant) = entry.remove();
    table.deleted = table.deleted.saturating_add(1);
    true
}

fn record_fully_spent_by_bitmap(
    record: &UtxoRecord<'_>,
    remove_count: usize,
    remove_vout: &mut impl FnMut(usize) -> u32,
) -> Option<bool> {
    let mut record_bitmap = 0_u64;
    for output in record.iter_outputs() {
        let bit = bitmap_vout_bit(output.vout)?;
        if record_bitmap & bit != 0 {
            return None;
        }
        record_bitmap |= bit;
    }
    if record_bitmap != record.vout_bitmap {
        return None;
    }

    let mut remove_bitmap = 0_u64;
    for index in 0..remove_count {
        let bit = bitmap_vout_bit(remove_vout(index))?;
        if remove_bitmap & bit != 0 {
            return None;
        }
        remove_bitmap |= bit;
    }
    Some(remove_bitmap == record_bitmap)
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

fn output_details(table: &ShardTable<'_>, output: &OneUtxoOut) -> Option<(TxOut, u32, bool)> {
    let script = script_slice(table, output)?;
    Some((
        txout_from_parts(output.value, script),
        output.height,
        output.coinbase,
    ))
}

fn txout_from_parts(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
    }
}
