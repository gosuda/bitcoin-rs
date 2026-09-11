//! Snapshot-gated txindex queries and the index-side block source.

use super::{
    Arc, Block, BlockBodySource, BlockHash, BlockLog, BlockSource, BlockTree, Hash256,
    IndexCapabilities, IndexCapability, IndexReader, IndexWatermark, MAX_SERIALIZED_BLOCK_BYTES,
    Mutex, Ordering, OutPoint, PrefixScanLimit, QUERY_BODY_READ_LIMIT, QUERY_SCAN_BYTE_LIMIT,
    QUERY_SCAN_COUNT_LIMIT, QUERY_SCAN_ROW_LIMIT, RwLock, ScriptHash, ScriptHistoryRecord,
    ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan, SpendingRecord,
    TipSnapshot, Tx, TxIndexInfo, TxIndexQuery, TxIndexRuntime, TxIndexScan, TxIndexScanRow,
    TxIndexSnapshot, TxPosition, TxPositionValue, TxQueryError, Txid, deserialize,
    record_at_height,
};

/// Aggregate work budget shared by every operation in one public query.
struct QueryBudget {
    remaining_rows: usize,
    remaining_bytes: usize,
    remaining_scans: usize,
    remaining_body_reads: usize,
}

impl QueryBudget {
    const fn new() -> Self {
        Self {
            remaining_rows: QUERY_SCAN_ROW_LIMIT,
            remaining_bytes: QUERY_SCAN_BYTE_LIMIT,
            remaining_scans: QUERY_SCAN_COUNT_LIMIT,
            remaining_body_reads: QUERY_BODY_READ_LIMIT,
        }
    }

    fn next_scan_limit(&mut self) -> Result<PrefixScanLimit, TxQueryError> {
        if self.remaining_scans == 0 || self.remaining_rows == 0 || self.remaining_bytes == 0 {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exhausted".into(),
            ));
        }
        self.remaining_scans -= 1;
        Ok(PrefixScanLimit {
            max_rows: self.remaining_rows,
            max_bytes: self.remaining_bytes,
        })
    }

    fn accept_scan(&mut self, scan: TxIndexScan) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex prefix scan truncated".into(),
            ));
        }
        if scan.rows.len() > self.remaining_rows || scan.encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        self.remaining_rows -= scan.rows.len();
        self.remaining_bytes -= scan.encoded_bytes;
        Ok(scan.rows)
    }

    fn reserve_body_read(&mut self, max_bytes: usize) -> Result<(), TxQueryError> {
        if self.remaining_body_reads == 0 || max_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exhausted".into(),
            ));
        }
        self.remaining_body_reads -= 1;
        Ok(())
    }

    fn charge_body_bytes(&mut self, bytes: usize) -> Result<(), TxQueryError> {
        if bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exceeded".into(),
            ));
        }
        self.remaining_bytes -= bytes;
        Ok(())
    }
}

/// Authoritative Live query sources: capability selection, the UTXO set, and
/// the chain-transition lock Live composition requires.
pub(crate) struct QueryEngineLive {
    pub(crate) utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    pub(crate) chain_transition: Option<Arc<Mutex<()>>>,
    pub(crate) enabled: IndexCapabilities,
}

/// Node-owned, snapshot-gated transaction-index query engine.
///
/// Implements `bitcoin_rs_rpc::context::TxIndexQuery` and [`ScriptIndexQuery`] as the
/// only public read paths for the transaction index. Every query runs against
/// one typed point-in-time snapshot, captures
/// health/shutdown/revision/tip before and after work, and returns typed
/// `Retry`/`Unavailable` when the answer cannot be proven.
#[derive(Clone)]
pub(crate) struct TxIndexQueryEngine {
    runtime: Arc<TxIndexRuntime>,
    reader: Arc<dyn IndexReader>,
    block_source: IndexBlockSource,
    block_tree: Arc<RwLock<BlockTree>>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    body_source: Option<Arc<dyn BlockBodySource>>,
    utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    chain_transition: Option<Arc<Mutex<()>>>,
    enabled: IndexCapabilities,
}

impl core::fmt::Debug for TxIndexQueryEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxIndexQueryEngine").finish_non_exhaustive()
    }
}

impl TxIndexQueryEngine {
    /// Builds a query engine over the shared reader and authoritative block source.
    #[must_use]
    pub(crate) fn new(
        runtime: Arc<TxIndexRuntime>,
        reader: Arc<dyn IndexReader>,
        block_source: IndexBlockSource,
        block_tree: Arc<RwLock<BlockTree>>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        body_source: Option<Arc<dyn BlockBodySource>>,
        live: QueryEngineLive,
    ) -> Self {
        Self {
            runtime,
            reader,
            block_source,
            block_tree,
            applied_tip,
            body_source,
            utxo: live.utxo,
            chain_transition: live.chain_transition,
            enabled: live.enabled,
        }
    }

    fn query_health(&self) -> Result<(), TxQueryError> {
        if self.runtime.failed.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable(
                self.runtime
                    .failure_message()
                    .unwrap_or_else(|| "txindex worker failed".into()),
            ));
        }
        if self.runtime.shutdown.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable("txindex worker stopped".into()));
        }
        Ok(())
    }

    fn require_enabled(&self, required: IndexCapabilities) -> Result<(), TxQueryError> {
        if required.tx_lookup && !self.enabled.tx_lookup {
            return Err(TxQueryError::Unavailable("txindex is disabled".into()));
        }
        if required.script_history && !self.enabled.script_history {
            return Err(TxQueryError::Unavailable(
                "script history is disabled".into(),
            ));
        }
        if required.script_live && !self.enabled.script_live {
            return Err(TxQueryError::Unavailable("script live is disabled".into()));
        }
        Ok(())
    }

    fn with_snapshot<F, T>(&self, required: IndexCapabilities, f: F) -> Result<T, TxQueryError>
    where
        F: for<'s> FnOnce(
            &'s dyn TxIndexSnapshot,
            &TipSnapshot,
            &mut QueryBudget,
        ) -> Result<T, TxQueryError>,
    {
        self.query_health()?;
        self.require_enabled(required)?;

        // Live answers compose the index snapshot, the authoritative UTXO set,
        // and the applied tip. Apply mutates UTXO before publishing that tip,
        // so a before/after tip comparison cannot exclude that window. Hold
        // chain-transition across watermark check, locator scan, and UTXO
        // resolution. History and tx lookup never take it.
        let _chain_transition = if required.script_live {
            Some(
                self.chain_transition
                    .as_ref()
                    .ok_or_else(|| {
                        TxQueryError::Unavailable(
                            "chain transition authority missing for ScriptLive".into(),
                        )
                    })?
                    .lock(),
            )
        } else {
            None
        };

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;

        for capability in [
            IndexCapability::TxLookup,
            IndexCapability::ScriptHistory,
            IndexCapability::ScriptLive,
        ] {
            if !required.contains(capability) {
                continue;
            }
            let watermark = snapshot
                .capability_watermark(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
            let Some(watermark) = watermark else {
                return Err(TxQueryError::Retry);
            };
            if watermark.height != tip_before.height
                || watermark.hash != *tip_before.hash.as_byte_array()
            {
                return Err(TxQueryError::Retry);
            }
        }

        let mut budget = QueryBudget::new();
        let result = f(snapshot.as_ref(), &tip_before, &mut budget);

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();
        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        result
    }

    fn resolve_hash_at_height(
        &self,
        height: u32,
        tip: &TipSnapshot,
    ) -> Result<Hash256, TxQueryError> {
        let tree = self.block_tree.read();
        Self::hash_at_height(&tree, tip.tip_id, height).ok_or(TxQueryError::Retry)
    }

    fn hash_at_height(
        tree: &BlockTree,
        tip_id: bitcoin_rs_chain::NodeId,
        height: u32,
    ) -> Option<Hash256> {
        let node_id = tree.node_at_height_from(tip_id, height)?;
        tree.node(node_id).ok().map(|n| n.hash)
    }

    fn resolve_block(
        &self,
        budget: &mut QueryBudget,
        height: u32,
        hash: Hash256,
    ) -> Result<Block, TxQueryError> {
        budget.reserve_body_read(MAX_SERIALIZED_BLOCK_BYTES)?;
        let bytes = self.resolve_block_body_bytes(height, BlockHash::from(hash))?;
        budget.charge_body_bytes(bytes.len())?;
        Self::verify_block(&bytes, height, hash)
    }

    fn resolve_block_body_bytes(
        &self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Vec<u8>, TxQueryError> {
        if let Some(body_source) = self.body_source.as_ref() {
            if let Some(bytes) = body_source.block_body(height, hash) {
                return Ok(bytes);
            }
        }
        self.block_source
            .block_body_bytes_for(height, hash)
            .ok_or_else(|| {
                TxQueryError::Unavailable(
                    format!("block body missing for txindex query at height {height}").into(),
                )
            })
    }

    fn verify_block(bytes: &[u8], height: u32, hash: Hash256) -> Result<Block, TxQueryError> {
        let block = deserialize::<Block>(bytes).map_err(|_| {
            TxQueryError::Storage(format!("corrupt serialized block at height {height}").into())
        })?;
        let decoded = block.block_hash().0;
        if decoded != hash {
            return Err(TxQueryError::Storage(
                format!("block identity mismatch at height {height}").into(),
            ));
        }
        Ok(block)
    }

    fn validated_positions(value: &[u8]) -> Option<&[TxPosition]> {
        let positions = TxPositionValue::decode(value)?;
        let mut previous: Option<TxPosition> = None;
        for &position in positions {
            let end = position.end()?;
            if position.byte_len() == 0
                || usize::try_from(end).ok()? > MAX_SERIALIZED_BLOCK_BYTES
                || previous.is_some_and(|prior| {
                    position.offset() <= prior.offset()
                        || position.offset() < prior.end().unwrap_or(u32::MAX)
                })
            {
                return None;
            }
            previous = Some(position);
        }
        Some(positions)
    }

    fn resolve_positioned_transaction(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        position: TxPosition,
    ) -> Result<Option<Tx>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let Some(body_source) = self.body_source.as_ref() else {
            return Ok(None);
        };
        let byte_len = usize::try_from(position.byte_len())
            .map_err(|_| TxQueryError::Storage("transaction position length overflow".into()))?;
        budget.reserve_body_read(byte_len)?;
        let Some(bytes) = body_source.block_body_range(
            height,
            BlockHash::from(hash),
            position.offset(),
            position.byte_len(),
        ) else {
            return Ok(None);
        };
        budget.charge_body_bytes(bytes.len())?;
        if bytes.len() != byte_len {
            return Ok(None);
        }
        Ok(deserialize::<Tx>(&bytes).ok())
    }

    fn transaction_from_full_block(
        &self,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        height: u32,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        let hash = self.resolve_hash_at_height(height, tip)?;
        let block = self.resolve_block(budget, height, hash)?;
        Ok(block
            .txs
            .into_iter()
            .find(|transaction| transaction.txid() == *txid))
    }

    fn transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<Tx>, TxQueryError> {
        Ok(self
            .locate_transaction_for(snapshot, tip, budget, txid)?
            .map(|(_, transaction)| transaction))
    }

    /// Resolves both the confirming height and the transaction itself.
    ///
    /// `transaction_for` and `transaction_height_for` are the same walk, so they
    /// share it rather than keeping two copies of the row/position/full-block
    /// fallback ladder. The height caller pays for the deserialization it does
    /// not use, which is the price of not answering with an unverified row: a
    /// row surviving from a reorged block would otherwise name a height whose
    /// block never held the transaction.
    fn locate_transaction_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        txid: &Txid,
    ) -> Result<Option<(u32, Tx)>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(txid, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let rows = budget.accept_scan(scan)?;
        if rows.is_empty() {
            return Ok(None);
        }

        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                if let Some(transaction) =
                    self.transaction_from_full_block(tip, budget, height, txid)?
                {
                    return Ok(Some((height, transaction)));
                }
                continue;
            };
            let position = positions[0];
            match self.resolve_positioned_transaction(tip, budget, height, position)? {
                Some(transaction) if transaction.txid() == *txid => {
                    return Ok(Some((height, transaction)));
                }
                _ => {
                    if let Some(transaction) =
                        self.transaction_from_full_block(tip, budget, height, txid)?
                    {
                        return Ok(Some((height, transaction)));
                    }
                }
            }
        }
        Ok(None)
    }

    fn outpoint_value_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<u64>, TxQueryError> {
        let tx = self.transaction_for(snapshot, tip, budget, &outpoint.txid)?;
        let Some(tx) = tx else {
            return Ok(None);
        };
        let vout = usize::try_from(outpoint.vout)
            .map_err(|_| TxQueryError::Storage("outpoint vout overflow".into()))?;
        Ok(tx.outputs.get(vout).map(|o| o.value.to_sat()))
    }

    fn scan_funding_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .funding_rows(scripthash, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        budget.accept_scan(scan)
    }

    fn scan_spending_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .spending_rows(outpoint, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        budget.accept_scan(scan)
    }

    fn scan_live_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<bitcoin_rs_index::ScriptLiveRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan: ScriptLiveScan = snapshot
            .live_rows(scripthash, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex live prefix scan truncated".into(),
            ));
        }
        if scan.rows.len() > budget.remaining_rows || scan.encoded_bytes > budget.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        budget.remaining_rows -= scan.rows.len();
        budget.remaining_bytes -= scan.encoded_bytes;
        Ok(scan.rows)
    }

    fn collect_funding_outputs(
        transaction: &Tx,
        height: u32,
        scripthash: ScriptHash,
        outputs: &mut Vec<(Txid, u32, u64, u32)>,
    ) -> Result<bool, TxQueryError> {
        let txid = transaction.txid();
        let before = outputs.len();
        for (vout_idx, output) in transaction.outputs.iter().enumerate() {
            if ScriptHash::new(&output.script_pubkey) != scripthash {
                continue;
            }
            let vout = u32::try_from(vout_idx)
                .map_err(|_| TxQueryError::Storage("vout overflow".into()))?;
            outputs.push((txid, vout, output.value.to_sat(), height));
        }
        Ok(outputs.len() != before)
    }

    fn funding_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, TxQueryError> {
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut outputs = Vec::new();
        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                let hash = self.resolve_hash_at_height(height, tip)?;
                let block = self.resolve_block(budget, height, hash)?;
                for transaction in &block.txs {
                    Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
                }
                continue;
            };

            let row_start = outputs.len();
            let mut complete = true;
            for &position in positions {
                let Some(transaction) =
                    self.resolve_positioned_transaction(tip, budget, height, position)?
                else {
                    complete = false;
                    break;
                };
                if !Self::collect_funding_outputs(&transaction, height, scripthash, &mut outputs)? {
                    complete = false;
                    break;
                }
            }
            if complete {
                continue;
            }

            outputs.truncate(row_start);
            let hash = self.resolve_hash_at_height(height, tip)?;
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
            }
        }
        Ok(outputs)
    }

    fn spender_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<SpendingRecord>, TxQueryError> {
        let rows = Self::scan_spending_rows(snapshot, budget, outpoint)?;
        let mut last_height = None;
        for row in rows {
            let height = row.row.height();
            if last_height == Some(height) {
                continue;
            }
            last_height = Some(height);
            if let Some(positions) = Self::validated_positions(&row.value) {
                for &position in positions {
                    let Some(transaction) =
                        self.resolve_positioned_transaction(tip, budget, height, position)?
                    else {
                        break;
                    };
                    if let Some(record) = Self::spending_input(&transaction, height, outpoint)? {
                        return Ok(Some(record));
                    }
                }
            }
            let hash = self.resolve_hash_at_height(height, tip)?;
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                if let Some(record) = Self::spending_input(transaction, height, outpoint)? {
                    return Ok(Some(record));
                }
            }
        }
        Ok(None)
    }

    fn spending_input(
        transaction: &Tx,
        height: u32,
        outpoint: &OutPoint,
    ) -> Result<Option<SpendingRecord>, TxQueryError> {
        let Some(vin) = transaction
            .inputs
            .iter()
            .position(|input| input.previous_output == *outpoint)
        else {
            return Ok(None);
        };
        Ok(Some(SpendingRecord {
            txid: transaction.txid(),
            height,
            vin: u32::try_from(vin).map_err(|_| TxQueryError::Storage("vin overflow".into()))?,
        }))
    }

    fn history_snapshot_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        let funding_outputs = self.funding_outputs_for(snapshot, tip, budget, scripthash)?;

        let mut history = Vec::with_capacity(funding_outputs.len());
        let mut funding = Vec::with_capacity(funding_outputs.len());
        for (txid, vout, value, height) in funding_outputs {
            history.push(ScriptHistoryRecord { txid, height });
            funding.push(ScriptIndexRecord {
                txid,
                height,
                value,
                vout,
            });
            let outpoint = OutPoint { txid, vout };
            if let Some(spender) = self.spender_for(snapshot, tip, budget, &outpoint)? {
                history.push(ScriptHistoryRecord {
                    txid: spender.txid,
                    height: spender.height,
                });
            }
        }

        history.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.txid.cmp(&b.txid)));
        history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
        funding.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        funding.dedup();

        Ok(ScriptIndexSnapshot { history, funding })
    }

    fn unspent_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        _tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let Some(utxo) = self.utxo.as_ref() else {
            return Err(TxQueryError::Unavailable(
                "authoritative UTXO view is unavailable for ScriptLive".into(),
            ));
        };
        let rows = Self::scan_live_rows(snapshot, budget, scripthash)?;
        utxo.with_stable_view(|view| {
            let mut records = Vec::with_capacity(rows.len());
            for row in rows {
                let outpoint = row.outpoint();
                let Some(entry) = view.get_entry(&outpoint) else {
                    // A ready live watermark naming an unresolvable locator is
                    // corruption or a failed transition. Returning an empty
                    // result would turn that into a false negative.
                    return Err(TxQueryError::Unavailable(
                        "ScriptLive locator is absent from authoritative UTXO".into(),
                    ));
                };
                if ScriptHash::new(&entry.txout.script_pubkey) != scripthash {
                    // The locator is keyed by a compact hash prefix. A
                    // prefix collision is expected to be filtered by this
                    // exact script check.
                    continue;
                }
                records.push(ScriptIndexRecord {
                    txid: outpoint.txid,
                    height: entry.height,
                    value: entry.txout.value.to_sat(),
                    vout: outpoint.vout,
                });
            }
            records.sort_by(|a, b| {
                a.height
                    .cmp(&b.height)
                    .then_with(|| a.txid.cmp(&b.txid))
                    .then_with(|| a.vout.cmp(&b.vout))
            });
            records.dedup_by(|a, b| a.txid == b.txid && a.vout == b.vout);
            Ok(records)
        })
    }

    /// Watermark progress of `required` capabilities against one applied
    /// tip: `synced` when every one names that tip, `processed_height` the
    /// lowest of their heights, `target_height` the tip they were measured
    /// against. `Retry` when the tip or revision moved during the read.
    pub(crate) fn index_progress_for(
        &self,
        required: IndexCapabilities,
    ) -> Result<IndexProgress, TxQueryError> {
        self.query_health()?;

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
        let tx = required
            .tx_lookup
            .then(|| snapshot.capability_watermark(IndexCapability::TxLookup))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let script_index = required
            .script_history
            .then(|| snapshot.capability_watermark(IndexCapability::ScriptHistory))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let script_live = required
            .script_live
            .then(|| snapshot.capability_watermark(IndexCapability::ScriptLive))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let at_tip = |watermark: Option<IndexWatermark>| {
            watermark.is_some_and(|watermark| {
                watermark.height == tip_before.height
                    && watermark.hash == *tip_before.hash.as_byte_array()
            })
        };
        let synced = (!required.tx_lookup || at_tip(tx))
            && (!required.script_history || at_tip(script_index))
            && (!required.script_live || at_tip(script_live));
        let watermark_height =
            |watermark: Option<IndexWatermark>| watermark.map_or(0, |watermark| watermark.height);
        let best_block_height = [
            required.tx_lookup.then(|| watermark_height(tx)),
            required
                .script_history
                .then(|| watermark_height(script_index)),
            required.script_live.then(|| watermark_height(script_live)),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(0);

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();

        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        Ok(IndexProgress {
            synced,
            processed_height: best_block_height,
            target_height: tip_before.height,
        })
    }
}

/// One coherent read of index progress against a single applied tip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexProgress {
    pub synced: bool,
    pub processed_height: u32,
    pub target_height: u32,
}

/// Private index-side `BlockSource`: active-chain identity from the tree,
/// bodies from the chain body store. Not a node-owned concept.
#[derive(Clone)]
pub(crate) struct IndexBlockSource {
    blocks: Arc<RwLock<BlockLog>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    block_tree: Option<Arc<RwLock<BlockTree>>>,
}

impl IndexBlockSource {
    #[must_use]
    pub(crate) const fn new(blocks: Arc<RwLock<BlockLog>>) -> Self {
        Self {
            blocks,
            block_body_source: None,
            block_tree: None,
        }
    }

    #[must_use]
    pub(crate) fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    #[must_use]
    pub(crate) fn with_block_tree(mut self, tree: Arc<RwLock<BlockTree>>) -> Self {
        self.block_tree = Some(tree);
        self
    }

    pub(crate) fn block_body_bytes_for(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        self.block_body_source.as_ref()?.block_body(height, hash)
    }

    fn resolve_block_by_hash(&self, height: u32, active_hash: Hash256) -> Option<Block> {
        let bytes = self.block_body_bytes_for(height, BlockHash::from(active_hash))?;
        let block = deserialize::<Block>(&bytes).ok()?;
        (block.block_hash() == BlockHash::from(active_hash)).then_some(block)
    }
}

impl core::fmt::Debug for IndexBlockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IndexBlockSource").finish_non_exhaustive()
    }
}

impl BlockSource for IndexBlockSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let active_hash = if let Some(tree) = &self.block_tree {
            tree.read().active_node_at_height(height)?.hash
        } else {
            let guard = self.blocks.read();
            Hash256::from(record_at_height(&guard, height)?.hash)
        };
        self.resolve_block_by_hash(height, active_hash)
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let source = self.block_body_source.as_ref()?;
        let hash = if let Some(tree) = &self.block_tree {
            BlockHash::from(tree.read().active_node_at_height(height)?.hash)
        } else {
            let guard = self.blocks.read();
            record_at_height(&guard, height)?.hash
        };
        source.block_body_range(height, hash, offset, len)
    }
}

impl TxIndexQuery for TxIndexQueryEngine {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            self.transaction_for(snapshot, tip, budget, txid)
        })
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            self.outpoint_value_for(snapshot, tip, budget, outpoint)
        })
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            Ok(self
                .locate_transaction_for(snapshot, tip, budget, txid)?
                .map(|(height, _)| height))
        })
    }

    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError> {
        let progress = self.index_progress_for(IndexCapabilities::TX_LOOKUP)?;
        Ok(TxIndexInfo {
            synced: progress.synced,
            best_block_height: progress.processed_height,
        })
    }
}

impl ScriptIndexQuery for TxIndexQueryEngine {
    fn history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget| self.history_snapshot_for(snapshot, tip, budget, scripthash),
        )
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::SCRIPT_LIVE, |snapshot, tip, budget| {
            self.unspent_outputs_for(snapshot, tip, budget, scripthash)
        })
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget| self.spender_for(snapshot, tip, budget, &outpoint),
        )
    }
}
