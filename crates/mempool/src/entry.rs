use alloc::sync::Arc;

use bitcoin::Transaction;

/// Stable mempool entry identifier.
pub type EntryId = u32;

/// Transaction plus policy accounting used by mempool ordering and limits.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// Transaction payload shared with downstream consumers.
    pub tx: Arc<Transaction>,
    /// Virtual transaction size in vbytes.
    pub vsize: u32,
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// Fee rate in sat/vB multiplied by 1000.
    pub fee_rate: u64,
    /// Total virtual size of this entry and all unconfirmed ancestors.
    pub ancestor_size: u64,
    /// Total fee of this entry and all unconfirmed ancestors.
    pub ancestor_fee: u64,
    /// Total virtual size of this entry and all unconfirmed descendants.
    pub descendant_size: u64,
    /// Total fee of this entry and all unconfirmed descendants.
    pub descendant_fee: u64,
    /// Mempool acceptance time in monotonically increasing seconds.
    pub time: u64,
    /// Chain height at acceptance.
    pub height: u32,
}

impl MempoolEntry {
    /// Builds a mempool entry with self-only ancestor and descendant accounting.
    #[must_use]
    pub fn new(tx: Arc<Transaction>, vsize: u32, fee: u64, time: u64, height: u32) -> Self {
        let own_size = u64::from(vsize);
        Self {
            tx,
            vsize,
            fee,
            fee_rate: fee_rate(fee, own_size),
            ancestor_size: own_size,
            ancestor_fee: fee,
            descendant_size: own_size,
            descendant_fee: fee,
            time,
            height,
        }
    }

    /// Ancestor package fee rate in sat/vB multiplied by 1000.
    #[must_use]
    pub const fn ancestor_fee_rate(&self) -> u64 {
        fee_rate(self.ancestor_fee, self.ancestor_size)
    }

    /// Descendant package fee rate in sat/vB multiplied by 1000.
    #[must_use]
    pub const fn descendant_fee_rate(&self) -> u64 {
        fee_rate(self.descendant_fee, self.descendant_size)
    }
}

pub(crate) const fn fee_rate(fee: u64, vsize: u64) -> u64 {
    if vsize == 0 {
        return 0;
    }
    fee.saturating_mul(1_000) / vsize
}
