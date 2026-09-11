//! Query health, exact watermark gating, and coherent progress snapshots.

use super::IndexProgress;
use super::QueryBudget;
use super::TxIndexQueryEngine;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_index::IndexCapability;
use bitcoin_rs_index::IndexReader;
use bitcoin_rs_index::IndexWatermark;
use bitcoin_rs_index::TxIndexSnapshot;
use bitcoin_rs_rpc::context::TxQueryError;
use std::sync::atomic::Ordering;

impl TxIndexQueryEngine {
    pub(super) fn query_health(&self) -> Result<(), TxQueryError> {
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

    pub(super) fn require_enabled(&self, required: IndexCapabilities) -> Result<(), TxQueryError> {
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

    pub(super) fn with_snapshot<F, T>(
        &self,
        required: IndexCapabilities,
        f: F,
    ) -> Result<T, TxQueryError>
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
