//! RPC query projection over the snapshot-gated query engine.

use super::TxIndexQueryEngine;
use bitcoin_rs_index::IndexCapabilities;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_rpc::context::ScriptIndexQuery;
use bitcoin_rs_rpc::context::ScriptIndexRecord;
use bitcoin_rs_rpc::context::ScriptIndexSnapshot;
use bitcoin_rs_rpc::context::SpendingRecord;
use bitcoin_rs_rpc::context::TxIndexInfo;
use bitcoin_rs_rpc::context::TxIndexQuery;
use bitcoin_rs_rpc::context::TxQueryError;

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
