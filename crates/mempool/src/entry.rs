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

    /// Returns whether this transaction signals BIP-125 replaceability
    /// (any input has `sequence < 0xFFFF_FFFE`).
    ///
    /// Bitcoin Core's `bip125-replaceable` mempool entry field is derived from
    /// this predicate. Lifted from the inline check in `Mempool::iter_replaceable_txids`.
    #[must_use]
    pub fn is_replaceable(&self) -> bool {
        const RBF_FLAG_THRESHOLD: u32 = 0xFFFF_FFFE;
        self.tx
            .input
            .iter()
            .any(|input| input.sequence.0 < RBF_FLAG_THRESHOLD)
    }
}

pub(crate) const fn fee_rate(fee: u64, vsize: u64) -> u64 {
    if vsize == 0 {
        return 0;
    }
    fee.saturating_mul(1_000) / vsize
}
#[cfg(test)]
mod is_replaceable_tests {
    use super::*;
    use std::sync::Arc;

    fn entry_with_sequence(sequence: u32) -> MempoolEntry {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(sequence),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7)
    }

    #[test]
    fn is_replaceable_true_for_rbf_signal() {
        let entry = entry_with_sequence(0xFFFF_FFFD);
        assert!(entry.is_replaceable());
    }

    #[test]
    fn is_replaceable_false_for_max_sequence() {
        let entry = entry_with_sequence(0xFFFF_FFFE);
        assert!(!entry.is_replaceable());
    }

    #[test]
    fn is_replaceable_false_for_disabled_sequence() {
        let entry = entry_with_sequence(0xFFFF_FFFF);
        assert!(!entry.is_replaceable());
    }

    #[test]
    fn is_replaceable_false_for_no_inputs() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7);
        assert!(!entry.is_replaceable());
    }
}
