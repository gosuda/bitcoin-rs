//! Confirmed coin lookup with current mempool outputs layered over it.
//! Transaction preparation and admission are owned by the gateway.

use crate::Mempool;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_primitives::{OutPoint, TxOut};

/// Chain UTXO set with the mempool's unconfirmed outputs layered on top.
///
/// Bitcoin Core's `CCoinsViewMemPool`. Mempool first: a txid present in the
/// pool is by definition unconfirmed, so the chain cannot hold the same
/// outpoint, and consulting the pool first is what lets a child spend its
/// unconfirmed parent.
///
/// Deliberately does **not** hide outputs another mempool transaction spends.
/// Detecting that is the replacement path's job, and hiding them here would
/// turn every RBF attempt into a missing-inputs rejection.
pub struct MempoolUtxoView<'a, V> {
    pool: &'a Mempool,
    chain: &'a V,
}

impl<'a, V> MempoolUtxoView<'a, V> {
    /// Layers `pool`'s unconfirmed outputs over `chain`.
    #[must_use]
    pub const fn new(pool: &'a Mempool, chain: &'a V) -> Self {
        Self { pool, chain }
    }
}

impl<V> UtxoView for MempoolUtxoView<'_, V>
where
    V: UtxoView,
{
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.pool.entry_by_txid(&outpoint.txid) {
            let vout = usize::try_from(outpoint.vout).ok()?;
            return entry.tx.outputs.get(vout).cloned();
        }
        self.chain.lookup(outpoint)
    }
}
