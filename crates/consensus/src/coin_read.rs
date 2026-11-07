use crate::primitives::{Hash256, OutPoint, TxOut};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoCoin {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub coinbase: bool,
    pub height: u32,
}

pub trait CoinRead: Send + Sync {
    fn get_entry(&self, op: &OutPoint) -> Option<UtxoCoin>;
    fn has_live_outputs_for_txid(&self, txid: &Hash256) -> bool;
    fn scan_progress(&self) -> Option<u8>;
    fn abort_scan(&self) -> bool;
}
