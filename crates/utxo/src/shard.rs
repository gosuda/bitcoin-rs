use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use crossbeam_utils::CachePadded;
use hashbrown::HashTable;
use parking_lot::RwLock;
use smallvec::SmallVec;

use crate::{
    UtxoError, UtxoKey,
    record::{OutputParts, OwnedUtxoOut, RemovedRecord, UtxoRecord},
    set::{
        BuildPayload, ScannedUtxo, SpendPayload, UtxoAddView, UtxoChangeEvents, UtxoChangeListener,
        UtxoInserted, UtxoRemoved, UtxoScan,
    },
};

/// Per-shard hash table of compact, inline UTXO record owners.
pub struct ShardTable {
    /// Hash table of pointer-sized compact `UtxoRecord` owners stored inline (8 bytes on `x86_64`).
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

    /// Sums every record's heap allocation and live payload.
    ///
    /// The allocation is what the process actually holds — `AllocHeader` plus
    /// the buffer's capacity — while the payload is the encoded bytes inside it.
    /// The two differ wherever a record was grown and kept slack, and the gap
    /// between the allocation total and process RSS is what allocator size
    /// classes and fragmentation cost.
    pub(crate) fn allocation_and_payload_bytes(&self) -> (usize, usize) {
        self.table.iter().fold((0, 0), |(alloc, payload), record| {
            (
                alloc + record.allocation_bytes(),
                payload + record.payload_bytes(),
            )
        })
    }

    /// Estimated bytes held by the hash table itself, excluding record payloads.
    ///
    /// `hashbrown` exposes usable capacity, not bucket count, so this
    /// reconstructs the layout: buckets are a power of two above
    /// `capacity / 0.875`, and each carries one `UtxoRecord` (a pointer) plus one
    /// control byte. An estimate by construction — treat it as the right order of
    /// magnitude, not an exact figure.
    pub(crate) fn table_bytes(&self) -> usize {
        let capacity = self.table.capacity();
        if capacity == 0 {
            return 0;
        }
        let buckets = capacity.saturating_mul(8).div_ceil(7).next_power_of_two();
        buckets.saturating_mul(core::mem::size_of::<UtxoRecord>() + 1)
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

/// One cache-padded, lock-protected UTXO shard.
pub struct Shard {
    inner: CachePadded<RwLock<ShardTable>>,
}

impl Shard {
    /// Builds an empty shard.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: CachePadded::new(RwLock::new(ShardTable::new())),
        }
    }

    pub(crate) fn commit_batch(
        &self,
        adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
        removes: &[SpendPayload<'_>],
        listener: Option<&(dyn UtxoChangeListener + Send + Sync)>,
    ) -> Result<(), UtxoError> {
        let mut table = self.inner.write();
        if let Some(listener) = listener {
            commit_batch_with_listener(&mut table, adds, removes, listener)
        } else {
            commit_batch_coalesced(&mut table, adds, removes)
        }
    }

    pub(crate) fn commit_batch_collect_events<'a>(
        &self,
        adds: &'a [(UtxoKey, Hash256, BuildPayload<'a>)],
        removes: &[SpendPayload<'_>],
        coalesce_events: bool,
    ) -> (UtxoChangeEvents<'a>, Result<(), UtxoError>) {
        let mut table = self.inner.write();
        commit_batch_collect_events(&mut table, adds, removes, coalesce_events)
    }

    pub(crate) fn commit_single_shard_batch<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
        shard_idx: usize,
    ) -> Result<(), UtxoError> {
        let mut table = self.inner.write();
        commit_single_shard_coalesced(&mut table, adds, removes, shard_idx)
    }

    pub(crate) fn commit_single_shard_batch_with_listener<A: UtxoAddView>(
        &self,
        adds: &[A],
        removes: &[OutPoint],
        shard_idx: usize,
        listener: &(dyn UtxoChangeListener + Send + Sync),
    ) -> Result<(), UtxoError> {
        let mut table = self.inner.write();
        commit_single_shard_with_listener(&mut table, adds, removes, shard_idx, listener)
    }

    /// Returns an owned transaction output if `key:vout` is live in this shard.
    #[must_use]
    pub fn get(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<TxOut> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == *key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        Some(txout_from_parts(output.value, output.script_pubkey))
    }

    /// Returns the full live-output entry (txout + coinbase + height)
    /// if `key:vout` is live in this shard.
    #[must_use]
    pub fn get_entry(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<LiveOutput> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == *key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        Some(LiveOutput {
            txout: txout_from_parts(output.value, output.script_pubkey),
            coinbase: output.coinbase,
            height: output.height,
        })
    }

    /// Returns live-output metadata without materializing script bytes.
    #[must_use]
    pub fn get_meta(&self, key: &UtxoKey, txid: &Hash256, vout: u32) -> Option<LiveOutputMeta> {
        let table = self.inner.read();
        let record = table.table.find(key.hash(), |record| {
            record.key() == *key && record.txid() == *txid
        })?;
        let output = record.find_output(vout)?;
        Some(LiveOutputMeta {
            coinbase: output.coinbase,
            height: output.height,
        })
    }

    /// Returns true when this shard has any live output for `txid`.
    #[must_use]
    pub fn has_live_outputs_for_txid(&self, key: &UtxoKey, txid: &Hash256) -> bool {
        let table = self.inner.read();
        table
            .table
            .find(key.hash(), |record| {
                record.key() == *key && record.txid() == *txid
            })
            .is_some_and(|record| !record.is_empty())
    }

    pub(crate) fn with_table<R>(&self, f: impl FnOnce(&ShardTable) -> R) -> R {
        let table = self.inner.read();
        f(&table)
    }

    pub(crate) fn scan_script_pubkeys(&self, scripts: &[ScriptBuf], scan: &mut UtxoScan) {
        let table = self.inner.read();
        for record in &table.table {
            for output in record.outputs() {
                scan.txouts = scan.txouts.saturating_add(1);
                if scripts
                    .iter()
                    .any(|target| target.as_bytes() == output.script_pubkey)
                {
                    scan.unspents.push(ScannedUtxo {
                        outpoint: OutPoint::new(record.txid(), output.vout),
                        txout: txout_from_parts(output.value, output.script_pubkey),
                        coinbase: output.coinbase,
                        height: output.height,
                    });
                }
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

    pub(crate) fn allocation_and_payload_bytes(&self) -> (usize, usize) {
        let table = self.inner.read();
        table.allocation_and_payload_bytes()
    }

    pub(crate) fn table_bytes(&self) -> usize {
        let table = self.inner.read();
        table.table_bytes()
    }

    pub(crate) fn insert_owned_record(
        &self,
        key: UtxoKey,
        txid: Hash256,
        outputs: &[OwnedUtxoOut],
    ) -> Result<(), UtxoError> {
        let record = UtxoRecord::from_owned_outputs(txid, outputs)?;
        if record.is_empty() {
            return Ok(());
        }
        let mut table = self.inner.write();
        replace_record(&mut table, key, txid, record);
        Ok(())
    }
}

impl Default for Shard {
    fn default() -> Self {
        Self::new()
    }
}

struct StagedAdd {
    replacement: UtxoRecord,
    overwritten: Vec<Option<OwnedUtxoOut>>,
    add_unique: bool,
}

enum RecordMutation {
    NoChange,
    Replace(UtxoRecord),
    Delete,
}

struct StagedRemove {
    found_record: bool,
    mutation: RecordMutation,
    removed: Vec<Option<OwnedUtxoOut>>,
}

fn commit_batch_with_listener(
    table: &mut ShardTable,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    removes: &[SpendPayload<'_>],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let mut remaining_removes = removes;
    while let Some((first, rest)) = remaining_removes.split_first() {
        let run_len = rest
            .iter()
            .take_while(|remove| remove.key == first.key && remove.txid == first.txid)
            .count()
            .saturating_add(1);
        apply_remove_run_with_listener(table, &remaining_removes[..run_len], listener)?;
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, coalesced_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(key, txid, _payload)| *key == first.0 && *txid == first.1)
            .count()
            .saturating_add(1);
        apply_add_run_with_listener(
            table,
            first.0,
            first.1,
            &remaining_adds[..run_len],
            listener,
        )?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn commit_batch_collect_events<'a>(
    table: &mut ShardTable,
    adds: &'a [(UtxoKey, Hash256, BuildPayload<'a>)],
    removes: &[SpendPayload<'_>],
    coalesce_events: bool,
) -> (UtxoChangeEvents<'a>, Result<(), UtxoError>) {
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
        if let Err(error) = apply_remove_run_collect_events(
            table,
            &remaining_removes[..run_len],
            &mut events,
            coalesce_events,
        ) {
            return (events, Err(error));
        }
        remaining_removes = &remaining_removes[run_len..];
    }

    reserve_add_runs(table, coalesced_add_run_count(adds));
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(key, txid, _payload)| *key == first.0 && *txid == first.1)
            .count()
            .saturating_add(1);
        if let Err(error) = apply_add_run_collect_events(
            table,
            first.0,
            first.1,
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

fn commit_batch_coalesced(
    table: &mut ShardTable,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    removes: &[SpendPayload<'_>],
) -> Result<(), UtxoError> {
    let remove_spans = sorted_run_spans(removes, |remove| (remove.key, remove.txid));
    let add_spans = sorted_run_spans(adds, |add| (add.0, add.1));
    merge_commit_runs(
        table,
        &remove_spans,
        &add_spans,
        |index| removes[index].vout,
        |index| payload_parts(&adds[index].2),
    )
}

fn commit_single_shard_coalesced<A: UtxoAddView>(
    table: &mut ShardTable,
    adds: &[A],
    removes: &[OutPoint],
    shard_idx: usize,
) -> Result<(), UtxoError> {
    let remove_spans = sorted_run_spans(removes, |remove| {
        (UtxoKey::from_txid(&remove.txid), remove.txid)
    });
    let add_spans = sorted_run_spans(adds, |add| {
        let txid = add.outpoint().txid;
        (UtxoKey::from_txid(&txid), txid)
    });
    if cfg!(debug_assertions) {
        for span in remove_spans.iter().chain(&add_spans) {
            debug_assert_eq!(usize::from(span.key.shard()), shard_idx);
        }
    }
    merge_commit_runs(
        table,
        &remove_spans,
        &add_spans,
        |index| removes[index].vout,
        |index| {
            let payload = adds[index].payload();
            payload_parts(&payload)
        },
    )
}

/// One maximal run of consecutive same-identity payloads in a commit stream.
#[derive(Copy, Clone)]
struct RunSpan {
    key: UtxoKey,
    txid: Hash256,
    start: usize,
    len: usize,
}

/// Splits a commit stream into `(key, txid)` runs and sorts them by full
/// identity, letting the two no-listener sides be merged in one ordered pass
/// regardless of the caller's input order. The single-shard path never sorts
/// its input and the multi-shard path only groups runs for `<= 8` active
/// shards, so this sort is what makes the merge sound. It is stable, so
/// payloads keep their request/payload order within an identity. Spans
/// reference the original slice; no payload is copied here.
fn sorted_run_spans<T>(
    items: &[T],
    identity: impl Fn(&T) -> (UtxoKey, Hash256),
) -> SmallVec<[RunSpan; 8]> {
    let mut spans: SmallVec<[RunSpan; 8]> = SmallVec::new();
    let mut start = 0usize;
    while start < items.len() {
        let (key, txid) = identity(&items[start]);
        let mut len = 1usize;
        while start + len < items.len() {
            let (next_key, next_txid) = identity(&items[start + len]);
            if next_key != key || next_txid != txid {
                break;
            }
            len += 1;
        }
        spans.push(RunSpan {
            key,
            txid,
            start,
            len,
        });
        start += len;
    }
    spans.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.txid.cmp(&right.txid))
    });
    spans
}

/// Merges the sorted remove and add run streams by full identity. When both
/// sides carry the same record identity the combined editor rebuilds it once;
/// a one-sided identity keeps its existing optimized remove/add path. New-record
/// table capacity is reserved once up front, before any record borrow, so no
/// insert can reallocate the table mid-merge.
fn merge_commit_runs<'src>(
    table: &mut ShardTable,
    remove_spans: &[RunSpan],
    add_spans: &[RunSpan],
    vout_at: impl Fn(usize) -> u32,
    part_at: impl Fn(usize) -> OutputParts<'src>,
) -> Result<(), UtxoError> {
    reserve_add_runs(table, add_spans.len());
    let mut vouts: SmallVec<[u32; 8]> = SmallVec::new();
    let mut parts: SmallVec<[OutputParts<'src>; 8]> = SmallVec::new();
    let mut remove_index = 0usize;
    let mut add_index = 0usize;
    while remove_index < remove_spans.len() || add_index < add_spans.len() {
        let identity = match (remove_spans.get(remove_index), add_spans.get(add_index)) {
            (Some(remove), Some(add)) => {
                core::cmp::min((remove.key, remove.txid), (add.key, add.txid))
            }
            (Some(remove), None) => (remove.key, remove.txid),
            (None, Some(add)) => (add.key, add.txid),
            (None, None) => break,
        };
        let (key, txid) = identity;

        vouts.clear();
        while remove_spans
            .get(remove_index)
            .is_some_and(|remove| (remove.key, remove.txid) == identity)
        {
            let span = remove_spans[remove_index];
            vouts.reserve(span.len);
            for index in span.start..span.start + span.len {
                vouts.push(vout_at(index));
            }
            remove_index += 1;
        }

        parts.clear();
        while add_spans
            .get(add_index)
            .is_some_and(|add| (add.key, add.txid) == identity)
        {
            let span = add_spans[add_index];
            parts.reserve(span.len);
            for index in span.start..span.start + span.len {
                parts.push(part_at(index));
            }
            add_index += 1;
        }

        match (vouts.is_empty(), parts.is_empty()) {
            (false, false) => apply_combined_run(table, key, txid, &vouts, &parts)?,
            (false, true) => apply_remove_by_vouts(table, key, txid, &vouts)?,
            (true, false) => apply_add_by_parts(table, key, txid, &parts)?,
            (true, true) => {}
        }
    }
    Ok(())
}

fn commit_single_shard_with_listener<A: UtxoAddView>(
    table: &mut ShardTable,
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
        let run = spend_payloads(&remaining_removes[..run_len]);
        apply_remove_run_with_listener(table, &run, listener)?;
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
        let payloads = build_payloads(&remaining_adds[..run_len]);
        apply_add_payload_run_with_listener(
            table,
            key,
            first.outpoint().txid,
            &payloads,
            listener,
        )?;
        remaining_adds = &remaining_adds[run_len..];
    }
    Ok(())
}

fn reserve_add_runs(table: &mut ShardTable, additional_runs: usize) {
    if additional_runs != 0 {
        table
            .table
            .reserve(additional_runs, |record| record.key().hash());
    }
}

fn coalesced_add_run_count(adds: &[(UtxoKey, Hash256, BuildPayload<'_>)]) -> usize {
    let mut run_count = 0usize;
    let mut remaining_adds = adds;
    while let Some((first, rest)) = remaining_adds.split_first() {
        let run_len = rest
            .iter()
            .take_while(|(next_key, next_txid, _payload)| {
                *next_key == first.0 && *next_txid == first.1
            })
            .count()
            .saturating_add(1);
        run_count = run_count.saturating_add(1);
        remaining_adds = &remaining_adds[run_len..];
    }
    run_count
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

fn spend_payloads(removes: &[OutPoint]) -> Vec<SpendPayload<'_>> {
    removes
        .iter()
        .map(|op| {
            let key = UtxoKey::from_txid(&op.txid);
            SpendPayload {
                op,
                key,
                vout: op.vout,
                txid: op.txid,
            }
        })
        .collect()
}

fn build_payloads<A: UtxoAddView>(adds: &[A]) -> Vec<BuildPayload<'_>> {
    adds.iter().map(|add| add.payload()).collect()
}

fn apply_remove_by_vouts(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    vouts: &[u32],
) -> Result<(), UtxoError> {
    let mutation = match find_record(table, key, txid) {
        Some(record) => match record.remove_replacement(vouts)? {
            RemovedRecord::Unchanged => RecordMutation::NoChange,
            RemovedRecord::Emptied => RecordMutation::Delete,
            RemovedRecord::Replaced(replacement) => RecordMutation::Replace(replacement),
        },
        None => RecordMutation::NoChange,
    };
    apply_record_mutation(table, key, txid, mutation);
    Ok(())
}

fn apply_remove_run_with_listener(
    table: &mut ShardTable,
    removes: &[SpendPayload<'_>],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let Some(first) = removes.first() else {
        return Ok(());
    };
    let staged = stage_remove_run(table, first.key, first.txid, removes)?;
    let removed = removed_events(removes, staged.removed);
    apply_record_mutation(table, first.key, first.txid, staged.mutation);
    if staged.found_record {
        listener.on_remove_coins(&removed);
    }
    Ok(())
}

fn apply_remove_run_collect_events(
    table: &mut ShardTable,
    removes: &[SpendPayload<'_>],
    events: &mut UtxoChangeEvents<'_>,
    coalesce_events: bool,
) -> Result<(), UtxoError> {
    let Some(first) = removes.first() else {
        return Ok(());
    };
    let staged = stage_remove_run(table, first.key, first.txid, removes)?;
    let removed = removed_events(removes, staged.removed);
    apply_record_mutation(table, first.key, first.txid, staged.mutation);
    if staged.found_record {
        if coalesce_events {
            events.push_remove_batch_coalesced(removed);
        } else {
            events.push_remove_batch(removed);
        }
    }
    Ok(())
}

fn apply_add_by_parts(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    parts: &[OutputParts<'_>],
) -> Result<(), UtxoError> {
    let existing = find_record(table, key, txid);
    let add_unique = parts_are_increasing_unique(existing, parts);
    let replacement = match existing {
        Some(record) => record.add_replacement(parts, add_unique)?,
        None => UtxoRecord::new_add_replacement(txid, parts, add_unique)?,
    };
    replace_record(table, key, txid, replacement);
    Ok(())
}

/// Applies a coalesced remove run followed by a coalesced add run to one record
/// identity in a single probe, borrowed-descriptor pass, encode, and swap. A
/// missing record makes the removes no-ops and the additions build a fresh
/// record. A failed encode leaves the table byte-identical.
fn apply_combined_run(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    vouts: &[u32],
    parts: &[OutputParts<'_>],
) -> Result<(), UtxoError> {
    let mutation = if let Some(record) = find_record(table, key, txid) {
        match record.edit_replacement(vouts, parts)? {
            RemovedRecord::Unchanged => RecordMutation::NoChange,
            RemovedRecord::Emptied => RecordMutation::Delete,
            RemovedRecord::Replaced(replacement) => RecordMutation::Replace(replacement),
        }
    } else {
        let add_unique = parts_are_increasing_unique(None, parts);
        RecordMutation::Replace(UtxoRecord::new_add_replacement(txid, parts, add_unique)?)
    };
    apply_record_mutation(table, key, txid, mutation);
    Ok(())
}

fn parts_are_increasing_unique(record: Option<&UtxoRecord>, parts: &[OutputParts<'_>]) -> bool {
    let mut previous = record.and_then(UtxoRecord::max_vout);
    for part in parts {
        if previous.is_some_and(|vout| part.vout <= vout) {
            return false;
        }
        previous = Some(part.vout);
    }
    true
}

fn apply_add_run_with_listener(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    adds: &[(UtxoKey, Hash256, BuildPayload<'_>)],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let payloads: Vec<BuildPayload<'_>> =
        adds.iter().map(|(_key, _txid, payload)| *payload).collect();
    apply_add_payload_run_with_listener(table, key, txid, &payloads, listener)
}

fn apply_add_payload_run_with_listener(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    payloads: &[BuildPayload<'_>],
    listener: &(dyn UtxoChangeListener + Send + Sync),
) -> Result<(), UtxoError> {
    let StagedAdd {
        replacement,
        overwritten,
        add_unique: _,
    } = stage_add_run(table, key, txid, payloads)?;
    replace_record(table, key, txid, replacement);
    replay_add_listener(listener, payloads, &overwritten);
    Ok(())
}

fn apply_add_run_collect_events<'add>(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    adds: &'add [(UtxoKey, Hash256, BuildPayload<'add>)],
    events: &mut UtxoChangeEvents<'add>,
    coalesce_events: bool,
) -> Result<(), UtxoError> {
    let payloads: Vec<BuildPayload<'add>> =
        adds.iter().map(|(_key, _txid, payload)| *payload).collect();
    let StagedAdd {
        replacement,
        overwritten,
        add_unique,
    } = stage_add_run(table, key, txid, &payloads)?;
    replace_record(table, key, txid, replacement);
    collect_add_events(events, &payloads, &overwritten, add_unique, coalesce_events);
    Ok(())
}

fn stage_remove_run(
    table: &ShardTable,
    key: UtxoKey,
    txid: Hash256,
    removes: &[SpendPayload<'_>],
) -> Result<StagedRemove, UtxoError> {
    let Some(record) = find_record(table, key, txid) else {
        return Ok(StagedRemove {
            found_record: false,
            mutation: RecordMutation::NoChange,
            removed: vec![None; removes.len()],
        });
    };
    let vouts: SmallVec<[u32; 8]> = removes.iter().map(|remove| remove.vout).collect();
    if let Some(removed) = record.full_removals_by_vout(&vouts) {
        return Ok(StagedRemove {
            found_record: true,
            mutation: RecordMutation::Delete,
            removed: removed.into_iter().map(Some).collect(),
        });
    }

    let (replacement, removed) = record.stage_remove_run(&vouts)?;
    let mutation = match replacement {
        None => RecordMutation::NoChange,
        Some(record) if record.is_empty() => RecordMutation::Delete,
        Some(record) => RecordMutation::Replace(record),
    };
    Ok(StagedRemove {
        found_record: true,
        mutation,
        removed,
    })
}

fn stage_add_run(
    table: &ShardTable,
    key: UtxoKey,
    txid: Hash256,
    payloads: &[BuildPayload<'_>],
) -> Result<StagedAdd, UtxoError> {
    let parts: SmallVec<[OutputParts<'_>; 8]> = payloads.iter().map(payload_parts).collect();
    let existing = find_record(table, key, txid);
    let add_unique = adds_are_increasing_unique(existing, payloads);
    let (replacement, overwritten) = match existing {
        Some(record) => record.add_replacement_tracked(&parts, add_unique)?,
        None => UtxoRecord::new_add_replacement_tracked(txid, &parts, add_unique)?,
    };
    Ok(StagedAdd {
        replacement,
        overwritten,
        add_unique,
    })
}

fn find_record(table: &ShardTable, key: UtxoKey, txid: Hash256) -> Option<&UtxoRecord> {
    table.table.find(key.hash(), |record| {
        record.key() == key && record.txid() == txid
    })
}

fn payload_parts<'a>(payload: &BuildPayload<'a>) -> OutputParts<'a> {
    OutputParts::new(
        payload.vout,
        payload.txout.value.to_sat(),
        payload.txout.script_pubkey.as_bytes(),
        payload.coinbase,
        payload.height,
    )
}

fn adds_are_increasing_unique(record: Option<&UtxoRecord>, payloads: &[BuildPayload<'_>]) -> bool {
    let mut previous = record.and_then(UtxoRecord::max_vout);
    for payload in payloads {
        if previous.is_some_and(|vout| payload.vout <= vout) {
            return false;
        }
        previous = Some(payload.vout);
    }
    true
}

fn apply_record_mutation(
    table: &mut ShardTable,
    key: UtxoKey,
    txid: Hash256,
    mutation: RecordMutation,
) {
    match mutation {
        RecordMutation::NoChange => {}
        RecordMutation::Replace(record) => replace_record(table, key, txid, record),
        RecordMutation::Delete => remove_record(table, key, txid),
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

fn remove_record(table: &mut ShardTable, key: UtxoKey, txid: Hash256) {
    let Ok(entry) = table.table.find_entry(key.hash(), |record| {
        record.key() == key && record.txid() == txid
    }) else {
        return;
    };
    let (_record, _vacant) = entry.remove();
}

fn removed_events(
    removes: &[SpendPayload<'_>],
    removed: Vec<Option<OwnedUtxoOut>>,
) -> SmallVec<[UtxoRemoved; 2]> {
    let mut events = SmallVec::with_capacity(removes.len());
    for (remove, output) in removes.iter().zip(removed) {
        if let Some(output) = output {
            events.push(UtxoRemoved::new(
                *remove.op,
                txout_from_parts(output.value, &output.script_pubkey),
                output.height,
                output.coinbase,
            ));
        }
    }
    events
}

fn replay_add_listener(
    listener: &(dyn UtxoChangeListener + Send + Sync),
    payloads: &[BuildPayload<'_>],
    overwritten: &[Option<OwnedUtxoOut>],
) {
    let mut inserted = SmallVec::<[UtxoInserted<'_>; 8]>::with_capacity(payloads.len());
    for (payload, overwritten) in payloads.iter().zip(overwritten) {
        if let Some(output) = overwritten {
            flush_inserted_coins(listener, &mut inserted);
            let txout = txout_from_parts(output.value, &output.script_pubkey);
            listener.on_remove_coin(payload.outpoint, &txout, output.height, output.coinbase);
        }
        inserted.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    flush_inserted_coins(listener, &mut inserted);
}

fn collect_add_events<'a>(
    events: &mut UtxoChangeEvents<'a>,
    payloads: &[BuildPayload<'a>],
    overwritten: &[Option<OwnedUtxoOut>],
    add_unique: bool,
    coalesce_events: bool,
) {
    if add_unique && coalesce_events {
        for payload in payloads {
            events.push_insert_coin_coalesced(UtxoInserted::new(
                payload.outpoint,
                payload.txout,
                payload.height,
                payload.coinbase,
            ));
        }
        return;
    }

    let mut inserted = SmallVec::<[UtxoInserted<'a>; 8]>::with_capacity(payloads.len());
    for (payload, overwritten) in payloads.iter().zip(overwritten) {
        if let Some(output) = overwritten {
            flush_inserted_events(events, &mut inserted, coalesce_events);
            events.push_remove_coin(UtxoRemoved::new(
                *payload.outpoint,
                txout_from_parts(output.value, &output.script_pubkey),
                output.height,
                output.coinbase,
            ));
        }
        inserted.push(UtxoInserted::new(
            payload.outpoint,
            payload.txout,
            payload.height,
            payload.coinbase,
        ));
    }
    flush_inserted_events(events, &mut inserted, coalesce_events);
}

fn flush_inserted_events<'add>(
    events: &mut UtxoChangeEvents<'add>,
    inserted: &mut SmallVec<[UtxoInserted<'add>; 8]>,
    coalesce_events: bool,
) {
    if inserted.is_empty() {
        return;
    }
    if coalesce_events {
        events.push_insert_batch_coalesced(core::mem::take(inserted));
    } else {
        events.push_insert_batch(core::mem::take(inserted));
    }
}

fn flush_inserted_coins(
    listener: &(dyn UtxoChangeListener + Send + Sync),
    inserted: &mut SmallVec<[UtxoInserted<'_>; 8]>,
) {
    if !inserted.is_empty() {
        listener.on_insert_coins(inserted);
        inserted.clear();
    }
}

fn txout_from_parts(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_owned_record_is_not_inserted() -> Result<(), UtxoError> {
        let shard = Shard::new();
        shard.insert_owned_record(UtxoKey::from_prefix([0; 8]), Hash256::default(), &[])?;
        assert_eq!(shard.record_count(), 0);
        Ok(())
    }
}
