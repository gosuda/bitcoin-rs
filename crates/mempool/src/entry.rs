use alloc::sync::Arc;

use bitcoin_rs_primitives::{Tx, Txid, Wtxid};
use bitcoin_rs_script::count_tx_legacy;

/// Stable mempool entry identifier.
pub type EntryId = u32;

/// Transaction plus policy accounting used by mempool ordering and limits.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// Transaction payload shared with downstream consumers.
    pub tx: Arc<Tx>,
    /// Transaction id, hashed once at construction.
    pub txid: Txid,
    /// Witness transaction id, hashed once at construction.
    pub wtxid: Wtxid,
    /// Policy-adjusted virtual transaction size in vbytes.
    pub vsize: u32,
    /// BIP141 virtual transaction size in vbytes.
    pub bip141_vsize: u32,
    /// Consensus serialization size, including witness, in bytes.
    pub size: u32,
    /// Consensus transaction weight in weight units.
    pub weight: u64,
    /// Actual transaction fee in satoshis.
    pub fee: u64,
    /// Actual fee rate in sat/kvB.
    pub fee_rate: u64,
    /// Signed mining-only fee adjustment for this transaction.
    pub fee_delta: i64,
    /// Total virtual size of this entry and all unconfirmed ancestors.
    pub ancestor_size: u64,
    /// Total actual fee of this entry and all unconfirmed ancestors.
    pub ancestor_fee: u64,
    /// Total signed fee adjustment of this entry and all unconfirmed ancestors.
    pub ancestor_fee_delta: i128,
    /// Total virtual size of this entry and all unconfirmed descendants.
    pub descendant_size: u64,
    /// Total actual fee of this entry and all unconfirmed descendants.
    pub descendant_fee: u64,
    /// Total signed fee adjustment of this entry and all unconfirmed descendants.
    pub descendant_fee_delta: i128,
    /// Mempool acceptance time in monotonically increasing seconds.
    pub time: u64,
    /// Chain height at acceptance.
    pub height: u32,
    /// BIP141 sigop cost, counted against the resolved prevouts.
    ///
    /// P2SH sigops cannot be counted from the transaction alone — the spent
    /// `scriptPubKey` is what says how many there are — so this is computed
    /// once by `accept_to_mempool`, where the prevouts are already resolved,
    /// and carried from there. Bitcoin Core does the same, storing
    /// `sigOpCost` on `CTxMemPoolEntry` at acceptance rather than recounting
    /// per block template.
    ///
    /// Zero for entries inserted through `MempoolEntry::new` without going
    /// through acceptance: the count is unknown, not known to be zero.
    pub sigop_cost: u32,
}

impl MempoolEntry {
    /// Builds an entry and derives all metadata available from the transaction.
    ///
    /// The default sigop count includes legacy sigops. Admission code that has
    /// resolved prevouts must replace it with [`Self::with_sigop_cost`] so P2SH
    /// and witness sigops are included.
    #[must_use]
    pub fn new(tx: Arc<Tx>, vsize: u32, fee: u64, time: u64, height: u32) -> Self {
        let own_size = u64::from(vsize);
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        let bip141_vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
        let weight = tx.weight();
        let sigop_cost = count_tx_legacy(&tx);
        Self {
            tx,
            txid,
            wtxid,
            vsize,
            bip141_vsize,
            size,
            weight,
            sigop_cost,
            fee,
            fee_rate: fee_rate(fee, own_size),
            fee_delta: 0,
            ancestor_size: own_size,
            ancestor_fee: fee,
            ancestor_fee_delta: 0,
            descendant_size: own_size,
            descendant_fee: fee,
            descendant_fee_delta: 0,
            time,
            height,
        }
    }

    /// Attaches a sigop cost counted against resolved prevouts.
    ///
    /// Only `accept_to_mempool` is in a position to call this correctly, since
    /// only it has the prevouts. Kept as a separate builder rather than a
    /// `new` parameter so the ~30 fixtures that construct entries directly do
    /// not have to invent a number they cannot compute.
    #[must_use]
    pub const fn with_sigop_cost(mut self, sigop_cost: u32) -> Self {
        self.sigop_cost = sigop_cost;
        self
    }

    /// Actual fee plus the signed mining-only adjustment.
    #[must_use]
    pub fn modified_fee(&self) -> i128 {
        i128::from(self.fee) + i128::from(self.fee_delta)
    }

    /// Modified transaction fee rate in sat/kvB.
    #[must_use]
    pub fn modified_fee_rate(&self) -> i128 {
        signed_fee_rate(self.modified_fee(), u64::from(self.vsize))
    }

    /// Actual ancestor package fee rate in sat/kvB.
    #[must_use]
    pub const fn ancestor_fee_rate(&self) -> u64 {
        fee_rate(self.ancestor_fee, self.ancestor_size)
    }

    /// Modified ancestor package fee rate in sat/kvB.
    #[must_use]
    pub fn modified_ancestor_fee_rate(&self) -> i128 {
        signed_fee_rate(
            i128::from(self.ancestor_fee) + self.ancestor_fee_delta,
            self.ancestor_size,
        )
    }

    /// Actual descendant package fee rate in sat/kvB.
    #[must_use]
    pub const fn descendant_fee_rate(&self) -> u64 {
        fee_rate(self.descendant_fee, self.descendant_size)
    }

    /// Returns whether this transaction signals BIP-125 replaceability.
    #[must_use]
    pub fn is_replaceable(&self) -> bool {
        const RBF_FLAG_THRESHOLD: u32 = 0xFFFF_FFFE;
        self.tx
            .inputs
            .iter()
            .any(|input| input.sequence < RBF_FLAG_THRESHOLD)
    }
}

pub(crate) const fn fee_rate(fee: u64, vsize: u64) -> u64 {
    if vsize == 0 {
        return 0;
    }
    fee.saturating_mul(1_000) / vsize
}

fn signed_fee_rate(fee: i128, vsize: u64) -> i128 {
    if vsize == 0 {
        return 0;
    }
    fee.saturating_mul(1_000) / i128::from(vsize)
}
#[cfg(test)]
mod is_replaceable_tests {
    use super::*;
    use bitcoin_rs_primitives::{OutPoint, Tx, TxIn};
    use std::sync::Arc;

    fn entry_with_sequence(sequence: u32) -> MempoolEntry {
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Vec::new(),
                sequence,
                witness: Vec::new(),
            }],
            outputs: vec![],
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
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
        };
        let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7);
        assert!(!entry.is_replaceable());
    }
}

#[cfg(test)]
mod mining_metadata_tests {
    use super::*;
    use bitcoin_rs_primitives::{Tx, TxOut};
    use std::sync::Arc;

    fn bare_entry() -> MempoolEntry {
        let tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
        };
        MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7)
    }

    /// The default count comes from the transaction alone — legacy sigops of
    /// its own scripts — and admission replaces it with the prevout-aware
    /// figure once it has resolved the outputs being spent.
    #[test]
    fn with_sigop_cost_overrides_the_transaction_derived_default() {
        let entry = bare_entry().with_sigop_cost(20_000);
        assert_eq!(entry.sigop_cost, 20_000);

        let mut tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
        };
        tx.outputs.push(TxOut {
            value: 1_000,
            script_pubkey: alloc::vec![0xac],
        });
        let counted = MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7);
        assert_eq!(counted.sigop_cost, count_tx_legacy(&counted.tx));
        assert!(counted.sigop_cost > 0, "an OP_CHECKSIG output costs sigops");
    }

    #[test]
    fn modified_fee_math_is_signed_and_starts_at_the_actual_fee() {
        let mut entry = bare_entry();
        assert_eq!(entry.fee_delta, 0);
        assert_eq!(entry.modified_fee(), 1_000);
        assert_eq!(entry.modified_fee_rate(), 10_000);
        assert_eq!(entry.ancestor_fee_delta, 0);

        entry.fee_delta = -3_000;
        assert_eq!(entry.modified_fee(), -2_000);
        assert_eq!(entry.modified_fee_rate(), -20_000);

        entry.ancestor_fee_delta = 4_000;
        assert_eq!(entry.modified_ancestor_fee_rate(), 50_000);
    }
}
