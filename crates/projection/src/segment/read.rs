#[cfg(test)]
type HistoryAnswer = Vec<(Vec<u8>, Vec<u8>)>;

use super::format;
use super::{Coverage, IndexGeneration, meta_gen_key};
use crate::types::{
    HashPrefixRow, SPENDING_RECORD_KEY_LEN, ScriptHash, ScriptHashRow, ScriptHistoryOccurrence,
    SpendingPrefixRow, TxPosition, TxPositionValue, TxidRow,
};
use crate::{
    BasicFilter, IndexCapability, IndexError, IndexWatermark, ScriptLiveRow, ScriptLiveScan,
    TxIndexPage, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
use bitcoin_rs_consensus::primitives::{OutPoint, Txid};
use bitcoin_rs_storage::{ColumnFamily, KvSnapshot, PrefixScan, PrefixScanLimit, StorageError};
use std::collections::{BTreeMap, VecDeque};
use zerocopy::IntoBytes as _;

const RECORD_ROW_LIMIT: usize = 4_000_000;

const TX_DIR_CHUNK_ROWS: usize = 1_024;

struct TxidRowStream {
    scope: Scope,
    from: Vec<u8>,
    rows: VecDeque<(Vec<u8>, Vec<u8>)>,
    exhausted: bool,
}

impl TxidRowStream {
    fn new(scope: Scope, start: &[u8]) -> Self {
        let mut from = scope.txid_prefix().to_vec();
        from.extend_from_slice(start);
        Self {
            scope,
            from,
            rows: VecDeque::new(),
            exhausted: false,
        }
    }

    fn head_txid(&self) -> Option<[u8; 32]> {
        let (key, _) = self.rows.front()?;
        format::decode_tx_dir_key(key).map(|(_, txid, _)| txid)
    }

    fn head_prefix(&self) -> Option<[u8; 8]> {
        self.head_txid()?.get(..8)?.try_into().ok()
    }
}

fn refill_txid_rows(kv: &dyn KvSnapshot, stream: &mut TxidRowStream) -> Result<(), IndexError> {
    while stream.rows.is_empty() && !stream.exhausted {
        let scan = kv.scan_prefix_from_bounded(
            ColumnFamily::TxDir,
            &stream.scope.txid_prefix(),
            &stream.from,
            PrefixScanLimit {
                max_rows: TX_DIR_CHUNK_ROWS,
                max_bytes: usize::MAX,
            },
        )?;
        stream.exhausted = scan.complete;
        let Some((last, _)) = scan.rows.last() else {
            break;
        };
        stream.from = last.clone();
        stream.from.push(0);
        for (key, value) in scan.rows {
            format::decode_tx_dir_key(&key).ok_or_else(|| malformed("tx_dir key"))?;
            stream.rows.push_back((key, value));
        }
    }
    Ok(())
}

fn skip_txid_rows(
    kv: &dyn KvSnapshot,
    stream: &mut TxidRowStream,
    txid: &[u8; 32],
) -> Result<(), IndexError> {
    loop {
        refill_txid_rows(kv, stream)?;
        if stream.head_txid().as_ref() != Some(txid) {
            return Ok(());
        }
        stream.rows.pop_front();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    Tail { lo: u32, hi: u32 },
    Sealed { segment_id: u64, coverage: Coverage },
}

impl Scope {
    const fn segment_id(self) -> u64 {
        match self {
            Self::Tail { .. } => 0,
            Self::Sealed { segment_id, .. } => segment_id,
        }
    }

    fn prefix(self) -> [u8; 8] {
        self.segment_id().to_be_bytes()
    }

    fn txid_prefix(self) -> [u8; 9] {
        format::tx_dir_kind_prefix(self.segment_id(), format::TX_KIND_TXID)
    }

    const fn covers(self, height: u32) -> bool {
        match self {
            Self::Tail { lo, hi } => lo <= height && height <= hi,
            Self::Sealed { coverage, .. } => {
                coverage.first_height <= height && height <= coverage.last_height
            }
        }
    }

    const fn first_height(self) -> u32 {
        match self {
            Self::Tail { lo, .. } => lo,
            Self::Sealed { coverage, .. } => coverage.first_height,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TxRef {
    txid: [u8; 32],
    height: u32,
    position: TxPosition,
}

fn collect_prefix_rows(
    kv: &dyn KvSnapshot,
    stream: &mut TxidRowStream,
    prefix: [u8; 8],
    by_height: &mut BTreeMap<u32, Vec<TxPosition>>,
) -> Result<(), IndexError> {
    loop {
        refill_txid_rows(kv, stream)?;
        if stream.head_prefix() != Some(prefix) {
            return Ok(());
        }
        let Some((key, value)) = stream.rows.pop_front() else {
            return Ok(());
        };
        let (_gen, _txid, height) =
            format::decode_tx_dir_key(&key).ok_or_else(|| malformed("tx_dir key"))?;
        if !stream.scope.covers(height) {
            continue;
        }
        let (_hash, _ordinal, offset, len) =
            format::decode_tx_dir_value(&value).ok_or_else(|| malformed("tx_dir value"))?;
        by_height
            .entry(height)
            .or_default()
            .push(TxPosition::new(offset, len));
    }
}

/// Read view over one pinned engine snapshot (`PRJ-05`, `PRJ-06`, `PRJ-07`).
///
/// Each segment-backed capability reads its mutable tail first, then every
/// sealed generation listed under its descriptor, each limited to that
/// generation's declared coverage. Capabilities without a published
/// descriptor have no scopes and refuse reads.
pub(crate) struct SegmentSnapshot<'a> {
    kv: Box<dyn KvSnapshot + 'a>,
    published: [Option<Vec<Scope>>; 4],
}

impl<'a> SegmentSnapshot<'a> {
    pub(crate) fn open(kv: Box<dyn KvSnapshot + 'a>) -> Result<Self, IndexError> {
        let mut published: [Option<Vec<Scope>>; 4] = std::array::from_fn(|_| None);
        for capability in IndexCapability::ALL {
            published[capability.index()] = read_scopes(kv.as_ref(), capability)?;
        }
        Ok(Self { kv, published })
    }

    fn scopes(&self, capability: IndexCapability) -> &[Scope] {
        self.published[capability.index()].as_deref().unwrap_or(&[])
    }

    fn scan(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, IndexError> {
        self.kv
            .scan_prefix_bounded(cf, prefix, limit)
            .map_err(IndexError::from)
    }

    fn resolve_ordinal(&self, scope: Scope, ordinal: u32) -> Result<Option<TxRef>, IndexError> {
        let key = format::encode_tx_ordinal_key(scope.segment_id(), ordinal);
        let Some(value) = self.kv.get(ColumnFamily::TxDir, &key)? else {
            return Ok(None);
        };
        let (txid, height, offset, len) =
            format::decode_tx_ordinal_value(&value).ok_or_else(|| malformed("tx ordinal value"))?;
        Ok(Some(TxRef {
            txid,
            height,
            position: TxPosition::new(offset, len),
        }))
    }

    fn transaction_entries(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<(Vec<(u32, TxPosition)>, bool), IndexError> {
        let mut rows = BTreeMap::new();
        let mut complete = true;
        for &scope in self.scopes(IndexCapability::TxLookup) {
            let mut prefix = scope.txid_prefix().to_vec();
            prefix.extend_from_slice(txid.as_bytes());
            let scan = self.scan(ColumnFamily::TxDir, &prefix, limit)?;
            complete &= scan.complete;
            for (key, value) in scan.rows {
                let (_gen, _txid, height) =
                    format::decode_tx_dir_key(&key).ok_or_else(|| malformed("tx_dir key"))?;
                if !scope.covers(height) {
                    continue;
                }
                let (_hash, _ordinal, offset, len) =
                    format::decode_tx_dir_value(&value).ok_or_else(|| malformed("tx_dir value"))?;
                rows.entry(height)
                    .or_insert_with(|| TxPosition::new(offset, len));
            }
        }
        Ok((rows.into_iter().collect(), complete))
    }

    fn stream_script_occurrences(
        &self,
        scope: Scope,
        scripthash: ScriptHash,
        start: u32,
        window: &mut HistoryWindow,
    ) -> Result<(), IndexError> {
        if scope.first_height() > start {
            return Ok(());
        }
        let dict_key =
            format::encode_script_dict_key(scope.segment_id(), &scripthash.to_byte_array());
        let Some(value) = self.kv.get(ColumnFamily::ScriptDict, &dict_key)? else {
            return Ok(());
        };
        let script_id = format::decode_script_dict_value(&value)
            .ok_or_else(|| malformed("script_dict value"))?;
        let query = ScriptQuery {
            scope,
            scripthash,
            script_id,
            start,
        };
        match scope {
            Scope::Tail { .. } => self.stream_tail_postings(query, window),
            Scope::Sealed { .. } => self.stream_sealed_postings(query, window),
        }
    }

    fn stream_tail_postings(
        &self,
        query: ScriptQuery,
        window: &mut HistoryWindow,
    ) -> Result<(), IndexError> {
        let mut prefix = query.scope.prefix().to_vec();
        prefix.extend_from_slice(&query.script_id.to_be_bytes());
        let mut postings = Vec::new();
        for entry in self.kv.iter_prefix(ColumnFamily::ScriptPost, &prefix)? {
            let (_key, value) = entry?;
            let items = format::decode_posting_items(&value)
                .ok_or_else(|| malformed("script_post value"))?;
            postings.extend(
                items
                    .into_iter()
                    .map(|item| (item.delta_ordinal, item.flags)),
            );
        }
        for (ordinal, flags) in postings.into_iter().rev() {
            self.push_posting(query, ordinal, flags, window)?;
            if window.is_closed() {
                break;
            }
        }
        Ok(())
    }

    fn stream_sealed_postings(
        &self,
        query: ScriptQuery,
        window: &mut HistoryWindow,
    ) -> Result<(), IndexError> {
        let segment = query.scope.segment_id();
        let Some(bound) = self.last_ordinal_at_or_below(query.scope, query.start)? else {
            return Ok(());
        };
        let mut prefix = query.scope.prefix().to_vec();
        prefix.extend_from_slice(&query.script_id.to_be_bytes());
        let limit = PrefixScanLimit {
            max_rows: 1,
            max_bytes: usize::MAX,
        };
        let mut seek =
            format::encode_script_post_chunk_key(segment, query.script_id, bound).to_vec();
        loop {
            let scan = self.kv.scan_prefix_from_bounded(
                ColumnFamily::ScriptPost,
                &prefix,
                &seek,
                limit,
            )?;
            let Some((key, value)) = scan.rows.into_iter().next() else {
                return Ok(());
            };
            let (_gen, _script, base) = format::decode_script_post_chunk_key(&key)
                .ok_or_else(|| malformed("script_post key"))?;
            let postings = format::decode_chunk_postings(base, &value)
                .ok_or_else(|| malformed("script_post value"))?;
            for (ordinal, flags) in postings.into_iter().rev() {
                self.push_posting(query, ordinal, flags, window)?;
                if window.is_closed() {
                    return Ok(());
                }
            }
            seek = key;
            seek.push(0);
        }
    }

    fn push_posting(
        &self,
        query: ScriptQuery,
        ordinal: u32,
        flags: u8,
        window: &mut HistoryWindow,
    ) -> Result<(), IndexError> {
        let tx = self
            .resolve_ordinal(query.scope, ordinal)?
            .ok_or_else(|| malformed("script posting ordinal absent from tx directory"))?;
        if !query.scope.covers(tx.height) || tx.height > query.start {
            return Ok(());
        }
        window.push(
            tx.height,
            ScriptHistoryOccurrence {
                scripthash: query.scripthash,
                txid: tx.txid,
                position: tx.position,
                flags,
            },
        );
        Ok(())
    }

    fn last_ordinal_at_or_below(
        &self,
        scope: Scope,
        start: u32,
    ) -> Result<Option<u32>, IndexError> {
        let within = |ordinal: u32| -> Result<bool, IndexError> {
            Ok(self
                .resolve_ordinal(scope, ordinal)?
                .is_some_and(|tx| tx.height <= start))
        };
        let Some(first) = self.first_stored_ordinal(scope)? else {
            return Ok(None);
        };
        if !within(first)? {
            return Ok(None);
        }
        let (mut low, mut high) = (first, u32::MAX);
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if within(middle)? {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        Ok(Some(low))
    }

    fn first_stored_ordinal(&self, scope: Scope) -> Result<Option<u32>, IndexError> {
        let prefix = format::tx_dir_kind_prefix(scope.segment_id(), format::TX_KIND_ORDINAL);
        let scan = self.scan(
            ColumnFamily::TxDir,
            &prefix,
            PrefixScanLimit {
                max_rows: 1,
                max_bytes: usize::MAX,
            },
        )?;
        let Some((key, _)) = scan.rows.into_iter().next() else {
            return Ok(None);
        };
        let ordinal: [u8; 4] = key
            .get(format::TX_ORDINAL_KEY_LEN - 4..)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| malformed("tx ordinal key"))?;
        Ok(Some(u32::from_be_bytes(ordinal)))
    }

    fn history_rows(
        &self,
        scripthash: ScriptHash,
        start_height: Option<u32>,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let start = start_height.unwrap_or(u32::MAX);
        let mut window = HistoryWindow::new(limit);
        for &scope in self.scopes(IndexCapability::ScriptHistory).iter().rev() {
            if window.is_closed() {
                break;
            }
            self.stream_script_occurrences(scope, scripthash, start, &mut window)?;
        }
        Ok(window.finish(scripthash))
    }

    fn spending_rows_for(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let scopes = self.scopes(IndexCapability::ScriptHistory);
        let mut creations = Vec::new();
        let mut complete = true;
        for &scope in scopes {
            let mut prefix = scope.txid_prefix().to_vec();
            prefix.extend_from_slice(outpoint.txid.as_bytes());
            let scan = self.scan(ColumnFamily::TxDir, &prefix, limit)?;
            complete &= scan.complete;
            for (key, value) in scan.rows {
                let (_gen, _txid, height) =
                    format::decode_tx_dir_key(&key).ok_or_else(|| malformed("tx_dir key"))?;
                if !scope.covers(height) {
                    continue;
                }
                let (_hash, ordinal, _offset, _len) =
                    format::decode_tx_dir_value(&value).ok_or_else(|| malformed("tx_dir value"))?;
                creations.push(ordinal);
            }
        }

        let mut spends: BTreeMap<u32, Vec<TxPosition>> = BTreeMap::new();
        for creation_ordinal in creations {
            for &spend_scope in scopes {
                let key = format::encode_spend_dir_key(
                    spend_scope.segment_id(),
                    creation_ordinal,
                    outpoint.vout,
                );
                let Some(value) = self.kv.get(ColumnFamily::SpendDir, &key)? else {
                    continue;
                };
                let spending_ordinal = format::decode_spend_dir_value(&value)
                    .ok_or_else(|| malformed("spend_dir value"))?;
                let Some(tx) = self.resolve_ordinal(spend_scope, spending_ordinal)? else {
                    return Err(malformed("spend names an ordinal absent from tx directory"));
                };
                if spend_scope.covers(tx.height) {
                    spends.entry(tx.height).or_default().push(tx.position);
                }
            }
        }

        let mut rows: Vec<TxIndexScanRow> = Vec::new();
        let mut bytes = 0_usize;
        for (height, positions) in spends {
            let row = HashPrefixRow {
                prefix: SpendingPrefixRow::scan_prefix(outpoint),
                height: crate::types::encode_height(height),
            };
            let value = TxPositionValue::encode(&positions);
            let row_bytes = row.as_bytes().len().saturating_add(value.len());
            if rows.len() >= limit.max_rows
                || (!rows.is_empty() && bytes.saturating_add(row_bytes) > limit.max_bytes)
            {
                complete = false;
                break;
            }
            bytes = bytes.saturating_add(row_bytes);
            rows.push(TxIndexScanRow { row, value });
        }
        Ok(TxIndexScan {
            rows,
            encoded_bytes: bytes,
            complete,
        })
    }
}

fn malformed(what: &'static str) -> IndexError {
    IndexError::Storage(StorageError::IncompatibleData(format!("malformed {what}")))
}

fn read_scopes(
    kv: &dyn KvSnapshot,
    capability: IndexCapability,
) -> Result<Option<Vec<Scope>>, IndexError> {
    let key = meta_gen_key(capability);
    let Some(bytes) = kv.get(ColumnFamily::IdxMeta, &key)? else {
        return Ok(None);
    };
    let head = IndexGeneration::decode_meta_value(&bytes).ok_or(IndexError::InvalidSealMarker)?;
    let mut scopes = Vec::new();
    let mut record_prefix = key;
    record_prefix.push(b'/');
    for item in kv.iter_prefix(ColumnFamily::IdxMeta, &record_prefix)? {
        let (record_key, value) = item?;
        let gen_bytes = record_key
            .strip_prefix(record_prefix.as_slice())
            .ok_or_else(|| malformed("generation record key"))?;
        let segment_id = u64::from_be_bytes(
            gen_bytes
                .try_into()
                .map_err(|_| malformed("generation record key"))?,
        );
        let coverage =
            Coverage::from_bytes(&value).ok_or_else(|| malformed("generation record"))?;
        scopes.push(Scope::Sealed {
            segment_id,
            coverage,
        });
    }
    let tail = head.tail;
    if tail.tail_lo <= tail.tail_hi {
        scopes.push(Scope::Tail {
            lo: tail.tail_lo,
            hi: tail.tail_hi,
        });
    }
    Ok(Some(scopes))
}

#[derive(Clone, Copy)]
struct ScriptQuery {
    scope: Scope,
    scripthash: ScriptHash,
    script_id: u32,
    start: u32,
}

/// Keeps the newest height groups that fit the page limit. Occurrences arrive
/// newest first; the first group that does not fit closes the window, and every
/// older group is then outside the page (`complete` is false).
struct HistoryWindow {
    max_groups: usize,
    max_bytes: usize,
    groups: Vec<(u32, Vec<ScriptHistoryOccurrence>, usize)>,
    current: Option<(u32, Vec<ScriptHistoryOccurrence>)>,
    bytes: usize,
    dropped: bool,
}

impl HistoryWindow {
    fn new(limit: PrefixScanLimit) -> Self {
        Self {
            max_groups: limit.max_rows,
            max_bytes: limit.max_bytes,
            groups: Vec::new(),
            current: None,
            bytes: 0,
            dropped: false,
        }
    }

    const fn is_closed(&self) -> bool {
        self.dropped
    }

    fn push(&mut self, height: u32, occurrence: ScriptHistoryOccurrence) {
        if self.dropped {
            return;
        }
        if let Some((current, group)) = self.current.as_mut() {
            if *current == height {
                group.push(occurrence);
                return;
            }
        }
        self.close_current();
        self.current = Some((height, vec![occurrence]));
    }

    fn close_current(&mut self) {
        let Some((height, mut group)) = self.current.take() else {
            return;
        };
        group.sort_by(|left, right| {
            right
                .position
                .cmp(&left.position)
                .then_with(|| right.txid.cmp(&left.txid))
                .then_with(|| right.flags.cmp(&left.flags))
        });
        let row_bytes = crate::HASH_PREFIX_ROW_SIZE
            .saturating_add(ScriptHistoryOccurrence::encode_all(&group).len());
        let kept = self.groups.len();
        let fits = kept < self.max_groups
            && (kept == 0 || self.bytes.saturating_add(row_bytes) <= self.max_bytes);
        if fits {
            self.bytes = self.bytes.saturating_add(row_bytes);
            self.groups.push((height, group, row_bytes));
        } else {
            self.dropped = true;
        }
    }

    fn into_groups(mut self) -> Vec<(u32, Vec<ScriptHistoryOccurrence>)> {
        self.close_current();
        self.groups
            .into_iter()
            .map(|(height, group, _)| (height, group))
            .collect()
    }

    fn finish(mut self, scripthash: ScriptHash) -> TxIndexScan {
        self.close_current();
        let rows = self
            .groups
            .into_iter()
            .map(|(height, group, _)| TxIndexScanRow {
                row: HashPrefixRow {
                    prefix: ScriptHashRow::scan_prefix(scripthash),
                    height: crate::types::encode_height(height),
                },
                value: ScriptHistoryOccurrence::encode_all(&group),
            })
            .collect();
        TxIndexScan {
            rows,
            encoded_bytes: self.bytes,
            complete: !self.dropped,
        }
    }
}

impl TxIndexSnapshot for SegmentSnapshot<'_> {
    fn compact_filter(
        &self,
        height: u32,
        hash: &[u8; 32],
    ) -> Result<Option<BasicFilter>, IndexError> {
        for &scope in self.scopes(IndexCapability::CompactFilters) {
            if !scope.covers(height) {
                continue;
            }
            let key = format::encode_filter_key(scope.segment_id(), height);
            let Some(value) = self.kv.get(ColumnFamily::Filters, &key)? else {
                continue;
            };
            let (block_hash, filter_hash, header, gcs) =
                format::decode_filter_value(&value).ok_or_else(|| malformed("filters value"))?;
            if &block_hash == hash {
                return Ok(Some(BasicFilter {
                    filter: gcs.to_vec(),
                    hash: filter_hash,
                    header,
                }));
            }
        }
        Ok(None)
    }

    fn capability_published(&self, capability: IndexCapability) -> Result<bool, IndexError> {
        Ok(capability == IndexCapability::ScriptLive
            || self.published[capability.index()].is_some())
    }

    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        IndexWatermark::read_from_snapshot(self.kv.as_ref(), capability)
    }

    fn tx_lookup_page(
        &self,
        start_after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexPage, IndexError> {
        let scopes = self.scopes(IndexCapability::TxLookup);
        let start: &[u8] = match start_after {
            Some(cursor) => cursor
                .get(..8)
                .ok_or_else(|| malformed("tx lookup cursor"))?,
            None => &[],
        };
        let mut streams: Vec<TxidRowStream> = scopes
            .iter()
            .map(|&scope| TxidRowStream::new(scope, start))
            .collect();
        let kv = self.kv.as_ref();
        let mut page = TxIndexPage {
            rows: Vec::new(),
            complete: false,
        };
        let mut bytes = 0_usize;
        loop {
            for stream in &mut streams {
                refill_txid_rows(kv, stream)?;
            }
            let Some(prefix) = streams.iter().filter_map(TxidRowStream::head_prefix).min() else {
                page.complete = true;
                return Ok(page);
            };
            let mut by_height: BTreeMap<u32, Vec<TxPosition>> = BTreeMap::new();
            for stream in &mut streams {
                collect_prefix_rows(kv, stream, prefix, &mut by_height)?;
            }
            for positions in by_height.values_mut() {
                positions.sort_unstable();
                positions.dedup();
            }
            for (height, positions) in by_height {
                let height = crate::types::encode_height(height);
                let mut key = prefix.to_vec();
                key.extend_from_slice(&height);
                if start_after.is_some_and(|cursor| key.as_slice() <= cursor) {
                    continue;
                }
                let value = TxPositionValue::encode(&positions);
                bytes = bytes.saturating_add(key.len().saturating_add(value.len()));
                page.rows.push(TxIndexScanRow {
                    row: HashPrefixRow { prefix, height },
                    value,
                });
            }
            if !page.rows.is_empty()
                && (page.rows.len() >= limit.max_rows || bytes >= limit.max_bytes)
            {
                return Ok(page);
            }
        }
    }

    fn capability_floor(&self, capability: IndexCapability) -> Result<u32, IndexError> {
        crate::index::read_coverage_floor(self.kv.as_ref(), capability)
    }

    fn transaction_rows(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let (entries, complete) = self.transaction_entries(txid, limit)?;
        let mut rows = Vec::with_capacity(entries.len());
        let mut bytes = 0_usize;
        for (height, position) in entries {
            let row = HashPrefixRow {
                prefix: TxidRow::scan_prefix(txid),
                height: crate::types::encode_height(height),
            };
            let value = TxPositionValue::encode(&[position]);
            bytes = bytes
                .saturating_add(row.as_bytes().len())
                .saturating_add(value.len());
            rows.push(TxIndexScanRow { row, value });
        }
        Ok(TxIndexScan {
            rows,
            encoded_bytes: bytes,
            complete,
        })
    }

    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.history_rows(scripthash, None, limit)
    }

    fn funding_rows_from(
        &self,
        scripthash: ScriptHash,
        start_height: u32,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.history_rows(scripthash, Some(start_height), limit)
    }

    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.spending_rows_for(outpoint, limit)
    }

    fn live_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError> {
        let scan = self.kv.scan_prefix_bounded(
            ColumnFamily::ScriptLive,
            &ScriptHashRow::scan_prefix(scripthash),
            limit,
        )?;
        let encoded_bytes = encoded_bytes(&scan);
        let mut rows = Vec::with_capacity(scan.rows.len());
        let mut coins = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            rows.push(
                ScriptLiveRow::from_db_row(&key)
                    .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?,
            );
            coins.push(
                crate::ScriptLiveCoin::decode_value(&value)
                    .map_err(|_| IndexError::InvalidLiveRowValue { len: value.len() })?,
            );
        }
        Ok(ScriptLiveScan {
            rows,
            coins,
            encoded_bytes,
            complete: scan.complete,
        })
    }
}

fn encoded_bytes(scan: &PrefixScan) -> usize {
    scan.rows.iter().fold(0_usize, |total, (key, value)| {
        total.saturating_add(key.len()).saturating_add(value.len())
    })
}

// PRJ-07
#[derive(Debug, Default)]
pub(crate) struct RecordPage {
    pub(crate) rows: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) complete: bool,
}

fn record_limit() -> PrefixScanLimit {
    PrefixScanLimit {
        max_rows: RECORD_ROW_LIMIT,
        max_bytes: usize::MAX,
    }
}

fn increment_be(bytes: &mut [u8]) -> bool {
    for byte in bytes.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return true;
        }
    }
    false
}

impl SegmentSnapshot<'_> {
    // PRJ-07
    pub(crate) fn funding_record_page(
        &self,
        after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<RecordPage, IndexError> {
        let scopes = self.scopes(IndexCapability::ScriptHistory);
        let mut start = [0_u8; 32];
        if let Some(after) = after {
            start[..8].copy_from_slice(&after[..8]);
        }
        let mut page = RecordPage::default();
        let mut bytes = 0_usize;
        loop {
            let Some(first) = self.next_script_hash(scopes, start)? else {
                page.complete = true;
                return Ok(page);
            };
            let mut prefix = [0_u8; 8];
            prefix.copy_from_slice(&first[..8]);
            let mut by_height: BTreeMap<u32, Vec<ScriptHistoryOccurrence>> = BTreeMap::new();
            for scripthash in self.scripts_with_prefix(scopes, prefix)? {
                let mut window = HistoryWindow::new(PrefixScanLimit {
                    max_rows: usize::MAX,
                    max_bytes: usize::MAX,
                });
                for &scope in scopes {
                    self.stream_script_occurrences(scope, scripthash, u32::MAX, &mut window)?;
                }
                for (height, group) in window.into_groups() {
                    by_height.entry(height).or_default().extend(group);
                }
            }
            for (height, mut occurrences) in by_height.into_iter().rev() {
                occurrences.sort_unstable_by_key(|occurrence| {
                    (
                        occurrence.position,
                        occurrence.txid,
                        occurrence.scripthash.to_byte_array(),
                        occurrence.flags,
                    )
                });
                let mut key = prefix.to_vec();
                key.extend_from_slice(&crate::types::encode_history_height(height));
                if after.is_some_and(|after| key.as_slice() <= after) {
                    continue;
                }
                let value = ScriptHistoryOccurrence::encode_all(&occurrences);
                bytes = bytes.saturating_add(key.len().saturating_add(value.len()));
                page.rows.push((key, value));
            }
            let full = page.rows.len() >= limit.max_rows || bytes >= limit.max_bytes;
            if full && !page.rows.is_empty() {
                return Ok(page);
            }
            if !increment_be(&mut prefix) {
                page.complete = true;
                return Ok(page);
            }
            start = [0_u8; 32];
            start[..8].copy_from_slice(&prefix);
        }
    }

    // PRJ-07
    pub(crate) fn spending_record_page(
        &self,
        after: Option<&[u8]>,
        limit: PrefixScanLimit,
    ) -> Result<RecordPage, IndexError> {
        let scopes = self.scopes(IndexCapability::ScriptHistory);
        let start: &[u8] = match after {
            Some(after) => after
                .get(..32)
                .ok_or_else(|| malformed("spending record cursor"))?,
            None => &[],
        };
        let kv = self.kv.as_ref();
        let mut streams: Vec<TxidRowStream> = scopes
            .iter()
            .map(|&scope| TxidRowStream::new(scope, start))
            .collect();
        let mut page = RecordPage::default();
        let mut bytes = 0_usize;
        loop {
            for stream in &mut streams {
                refill_txid_rows(kv, stream)?;
            }
            let Some(txid) = streams.iter().filter_map(TxidRowStream::head_txid).min() else {
                page.complete = true;
                return Ok(page);
            };
            for stream in &mut streams {
                skip_txid_rows(kv, stream, &txid)?;
            }
            for ((vout, height), mut positions) in self.spends_of(scopes, &txid)? {
                positions.sort_unstable();
                positions.dedup();
                let mut key = Vec::with_capacity(SPENDING_RECORD_KEY_LEN);
                key.extend_from_slice(&txid);
                key.extend_from_slice(&vout.to_be_bytes());
                key.extend_from_slice(&height.to_be_bytes());
                if after.is_some_and(|after| key.as_slice() <= after) {
                    continue;
                }
                let value = TxPositionValue::encode(&positions);
                bytes = bytes.saturating_add(key.len().saturating_add(value.len()));
                page.rows.push((key, value));
            }
            let full = page.rows.len() >= limit.max_rows || bytes >= limit.max_bytes;
            if full && !page.rows.is_empty() {
                return Ok(page);
            }
        }
    }

    fn next_script_hash(
        &self,
        scopes: &[Scope],
        start: [u8; 32],
    ) -> Result<Option<[u8; 32]>, IndexError> {
        let mut least: Option<[u8; 32]> = None;
        for &scope in scopes {
            let mut from = scope.prefix().to_vec();
            from.extend_from_slice(&start);
            let scan = self.kv.scan_prefix_from_bounded(
                ColumnFamily::ScriptDict,
                &scope.prefix(),
                &from,
                PrefixScanLimit {
                    max_rows: 1,
                    max_bytes: usize::MAX,
                },
            )?;
            for (key, _) in scan.rows {
                let (_, hash) = format::decode_script_dict_key(&key)
                    .ok_or_else(|| malformed("script_dict key"))?;
                least = Some(least.map_or(hash, |current| current.min(hash)));
            }
        }
        Ok(least)
    }

    fn scripts_with_prefix(
        &self,
        scopes: &[Scope],
        prefix: [u8; 8],
    ) -> Result<Vec<ScriptHash>, IndexError> {
        let mut hashes = Vec::new();
        for &scope in scopes {
            let mut scoped = scope.prefix().to_vec();
            scoped.extend_from_slice(&prefix);
            let scan = self.scan(ColumnFamily::ScriptDict, &scoped, record_limit())?;
            if !scan.complete {
                return Err(malformed(
                    "script dictionary prefix exceeds the reader bound",
                ));
            }
            for (key, _) in scan.rows {
                let (_, hash) = format::decode_script_dict_key(&key)
                    .ok_or_else(|| malformed("script_dict key"))?;
                hashes.push(ScriptHash::from_byte_array(hash));
            }
        }
        hashes.sort_unstable();
        hashes.dedup();
        Ok(hashes)
    }

    fn spends_of(
        &self,
        scopes: &[Scope],
        txid: &[u8; 32],
    ) -> Result<BTreeMap<(u32, u32), Vec<TxPosition>>, IndexError> {
        let mut creations = Vec::new();
        for &scope in scopes {
            let mut prefix = scope.txid_prefix().to_vec();
            prefix.extend_from_slice(txid);
            let scan = self.scan(ColumnFamily::TxDir, &prefix, record_limit())?;
            if !scan.complete {
                return Err(malformed("creation rows exceed the reader bound"));
            }
            for (key, value) in scan.rows {
                let (_gen, _txid, height) =
                    format::decode_tx_dir_key(&key).ok_or_else(|| malformed("tx_dir key"))?;
                if !scope.covers(height) {
                    continue;
                }
                let (_hash, ordinal, _offset, _len) =
                    format::decode_tx_dir_value(&value).ok_or_else(|| malformed("tx_dir value"))?;
                creations.push(ordinal);
            }
        }
        creations.sort_unstable();
        creations.dedup();

        let mut spends: BTreeMap<(u32, u32), Vec<TxPosition>> = BTreeMap::new();
        for creation in creations {
            for &spend_scope in scopes {
                let mut prefix = spend_scope.prefix().to_vec();
                prefix.extend_from_slice(&creation.to_be_bytes());
                let scan = self.scan(ColumnFamily::SpendDir, &prefix, record_limit())?;
                if !scan.complete {
                    return Err(malformed("spend rows exceed the reader bound"));
                }
                for (key, value) in scan.rows {
                    let (_gen, _creation, vout) = format::decode_spend_dir_key(&key)
                        .ok_or_else(|| malformed("spend_dir key"))?;
                    let spending = format::decode_spend_dir_value(&value)
                        .ok_or_else(|| malformed("spend_dir value"))?;
                    let tx = self
                        .resolve_ordinal(spend_scope, spending)?
                        .ok_or_else(|| {
                            malformed("spend names an ordinal absent from tx directory")
                        })?;
                    if spend_scope.covers(tx.height) {
                        spends
                            .entry((vout, tx.height))
                            .or_default()
                            .push(tx.position);
                    }
                }
            }
        }
        Ok(spends)
    }
}

#[cfg(test)]
impl SegmentSnapshot<'_> {
    pub(crate) fn tx_answer_for_test(
        &self,
        txid: &Txid,
    ) -> Result<Vec<(u32, TxPosition)>, IndexError> {
        Ok(self.transaction_entries(txid, unlimited_scan())?.0)
    }

    pub(crate) fn history_answer_for_test(
        &self,
        scripthash: ScriptHash,
    ) -> Result<HistoryAnswer, IndexError> {
        let scan = self.history_rows(scripthash, None, unlimited_scan())?;
        Ok(scan
            .rows
            .into_iter()
            .map(|row| (row.row.to_db_row().to_vec(), row.value))
            .collect())
    }
}

#[cfg(test)]
fn unlimited_scan() -> PrefixScanLimit {
    PrefixScanLimit {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bitcoin_rs_storage::KvIter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TXS: [u32; 2] = [3_000, 12_000];
    const SCOPES: u32 = 2;
    const PAGE_ROWS: usize = 64;
    const PAGE_READ_SLACK: usize = 1;
    type Row = (Vec<u8>, Vec<u8>);
    type SnapshotRows = Vec<Result<Row, StorageError>>;
    type FixtureRows = (BTreeMap<Vec<u8>, Vec<u8>>, Vec<Row>);

    struct CountingSnapshot {
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        scans: Arc<AtomicUsize>,
    }

    impl KvSnapshot for CountingSnapshot {
        fn get(&self, _cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.rows.get(key).cloned())
        }

        fn iter_prefix<'a>(
            &'a self,
            _cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            let rows: SnapshotRows = self
                .rows
                .range(prefix.to_vec()..)
                .take_while(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((key.clone(), value.clone())))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }

        fn scan_prefix_from_bounded(
            &self,
            _cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.scans.fetch_add(1, Ordering::Relaxed);
            let mut rows = Vec::new();
            for (key, value) in self.rows.range(start.max(prefix).to_vec()..) {
                if !key.starts_with(prefix) {
                    return Ok(PrefixScan {
                        rows,
                        complete: true,
                    });
                }
                if rows.len() == limit.max_rows {
                    return Ok(PrefixScan {
                        rows,
                        complete: false,
                    });
                }
                rows.push((key.clone(), value.clone()));
            }
            Ok(PrefixScan {
                rows,
                complete: true,
            })
        }
    }

    fn txid(index: u32) -> [u8; 32] {
        let mut txid = [0_u8; 32];
        let mixed = u64::from(index).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        txid[..8].copy_from_slice(&mixed.to_be_bytes());
        txid[8..12].copy_from_slice(&index.to_be_bytes());
        txid
    }

    fn scopes() -> Vec<Scope> {
        (0..SCOPES)
            .map(|segment| {
                if segment == 0 {
                    Scope::Tail {
                        lo: 0,
                        hi: u32::MAX,
                    }
                } else {
                    Scope::Sealed {
                        segment_id: u64::from(segment),
                        coverage: Coverage {
                            first_height: 0,
                            last_height: u32::MAX,
                            last_hash: [0; 32],
                        },
                    }
                }
            })
            .collect()
    }

    fn fixture(txs: u32) -> FixtureRows {
        let mut rows = BTreeMap::new();
        let mut expected = Vec::new();
        for index in 0..txs {
            let txid = txid(index);
            let segment = index % SCOPES;
            let ordinal = index / SCOPES;
            let height = 1 + index / 100;
            let offset = index * 10;
            let len = 100;
            rows.insert(
                format::encode_tx_dir_key(u64::from(segment), &txid, height).to_vec(),
                format::encode_tx_dir_value(&[0x11; 32], ordinal, offset, len).to_vec(),
            );
            rows.insert(
                format::encode_tx_ordinal_key(u64::from(segment), ordinal).to_vec(),
                format::encode_tx_ordinal_value(&txid, height, offset, len).to_vec(),
            );
            let mut key = txid[..8].to_vec();
            key.extend_from_slice(&crate::types::encode_height(height));
            expected.push((
                key,
                TxPositionValue::encode(&[TxPosition::new(offset, len)]),
            ));
        }
        expected.sort();
        (rows, expected)
    }

    fn page_all(
        snapshot: &SegmentSnapshot<'_>,
        scans: &AtomicUsize,
        max_rows: usize,
    ) -> (Vec<Row>, Vec<usize>) {
        let mut rows = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        let mut reads_per_page = Vec::new();
        loop {
            let before = scans.load(Ordering::Relaxed);
            let page = snapshot
                .tx_lookup_page(
                    cursor.as_deref(),
                    PrefixScanLimit {
                        max_rows,
                        max_bytes: usize::MAX,
                    },
                )
                .expect("tx lookup page");
            reads_per_page.push(scans.load(Ordering::Relaxed) - before);
            rows.extend(
                page.rows
                    .iter()
                    .map(|row| (row.row.to_db_row().to_vec(), row.value.clone())),
            );
            if page.complete {
                return (rows, reads_per_page);
            }
            let last = page.rows.last().expect("an incomplete page carries rows");
            let mut next = last.row.to_db_row().to_vec();
            next.push(0);
            cursor = Some(next);
        }
    }

    #[test]
    fn tx_lookup_pages_match_the_full_listing_and_bound_engine_reads() {
        let scope_count = usize::try_from(SCOPES).expect("scope count fits usize");
        let bound = scope_count + PAGE_READ_SLACK;
        for txs in TXS {
            let (rows, expected) = fixture(txs);
            let scans = Arc::new(AtomicUsize::new(0));
            let mut published: [Option<Vec<Scope>>; 4] = std::array::from_fn(|_| None);
            published[IndexCapability::TxLookup.index()] = Some(scopes());
            let snapshot = SegmentSnapshot {
                kv: Box::new(CountingSnapshot {
                    rows,
                    scans: Arc::clone(&scans),
                }),
                published,
            };

            let (paged, reads_per_page) = page_all(&snapshot, &scans, PAGE_ROWS);
            assert_eq!(
                paged, expected,
                "paged listing differs from the full listing at {txs} txs"
            );
            assert!(reads_per_page.len() > 1, "fixture must span several pages");
            for (page, &reads) in reads_per_page.iter().enumerate() {
                assert!(
                    reads <= bound,
                    "{txs} txs: page {page} made {reads} engine reads, bound {bound}"
                );
            }
        }
    }
}
