//! RPC trait adapters over a single captured lifecycle query payload.
//!
//! Protocol-facing types remain in node, not in the derived index crate.

use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_primitives::{OutPoint, Tx, Txid};
use bitcoin_rs_rpc::context::{
    DerivedIndexInfo, DerivedIndexQuery, ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot,
    SpendingRecord, TxQueryError,
};

use super::DerivedIndexQueryAdapter;

impl DerivedIndexQuery for DerivedIndexQueryAdapter {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction(txid)
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.outpoint_value(outpoint)
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction_height(txid)
    }

    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        let engine = self.load_engine()?;
        engine.index_info()
    }
}

impl ScriptIndexQuery for DerivedIndexQueryAdapter {
    fn history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        let engine = self.load_engine()?;
        engine.history_snapshot(scripthash)
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.unspent_outputs(scripthash)
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.spender(outpoint)
    }
}
