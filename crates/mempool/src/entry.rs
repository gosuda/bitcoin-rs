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
    /// Witness transaction id, reusing txid when no witness is present.
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
    /// by shared admission preparation after resolving prevouts, and carried
    /// through the gateway. Bitcoin Core does the same, storing
    /// `sigOpCost` on `CTxMemPoolEntry` at acceptance rather than recounting
    /// per block template.
    ///
    /// Raw `MempoolEntry::new` callers get the existing transaction-only
    /// legacy count; admission replaces it with the resolved weighted cost.
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
        // BIP141: witness-free transactions have identical txid and wtxid.
        // A stack containing an empty item still has witness serialization.
        let wtxid = if tx.has_witness() {
            tx.wtxid()
        } else {
            Wtxid(txid.0)
        };
        // Tx owns weight calculation. Reuse its result instead of calling
        // tx.vsize(), which computes the same weight and walks the tx again.
        let weight = tx.weight();
        let bip141_vsize = u32::try_from(weight.div_ceil(4)).unwrap_or(u32::MAX);
        let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
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
    /// Admission preparation derives this value from the transaction and
    /// resolved coins. Raw entry builders may omit it when that input context
    /// is unavailable.
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

#[cfg(test)]
mod wire_metadata_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid, Wtxid};

    use super::MempoolEntry;

    fn fixture(mode: usize) -> Tx {
        let mut tx = Tx {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x11; 32])), 0),
                    script_sig: vec![0x51],
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x22; 32])), 7),
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: Vec::new(),
                },
            ],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 9,
        };
        match mode {
            0 => {}
            1 => tx.inputs[0].witness = vec![Vec::new()],
            2..=4 => tx.inputs[1].witness = vec![vec![0xaa; mode - 1]],
            5 => {
                tx.inputs[0].witness = vec![Vec::new(), vec![0xbb; 253]];
                tx.inputs[1].witness = vec![Vec::new()];
            }
            6 => tx.inputs[1].witness = vec![Vec::new(); 253],
            _ => panic!("unknown fixture mode"),
        }
        tx
    }

    // BIP141, Specification / Transaction ID and Transaction size calculations;
    // BIP144, Serialization. Golden digests and lengths were computed by a
    // separate Python struct/hashlib wire encoder, not Tx's own methods.
    // These are serialization fixtures, not admission-valid transactions.
    #[test]
    fn wire_metadata_matches_bip141_and_bip144_vectors() -> Result<(), Box<dyn std::error::Error>> {
        let expected_txid = Txid(Hash256::from_str_be(
            "9e3f408ee773b8b6473f7cc02cbdef80644f916cee3981ee0704e279b7cdc6dc",
        )?);
        let vectors: [(&str, u32, u64, u32); 7] = [
            (
                "9e3f408ee773b8b6473f7cc02cbdef80644f916cee3981ee0704e279b7cdc6dc",
                103,
                412,
                103,
            ),
            (
                "355f450d4c027fb3ea905768e7fd9c7889bcab274af50a25a0d52d0003158c24",
                108,
                417,
                105,
            ),
            (
                "5d5f81eafa9ee33fd4b07eaa106cc816ea463cf2510c4a3d645e165c79f46853",
                109,
                418,
                105,
            ),
            (
                "74a2fc68cdd69b7961bea56f68994e232123a9648abe185151d184e2b4fddeee",
                110,
                419,
                105,
            ),
            (
                "5038e39e2bcc30a2ceaa1260780c6f3188df8b281d1b8758c083ea8b15cd54ed",
                111,
                420,
                105,
            ),
            (
                "f1582032a9749368080a092050f201b64f59a0090f1744fa6254eb3b6949f0f2",
                365,
                674,
                169,
            ),
            (
                "1a7818ed1b22f683be34b1c3a1834ec97d8cd5c1e15a2ce2b39cf4359ae3f989",
                362,
                671,
                168,
            ),
        ];
        for (mode, (wtxid, size, weight, vsize)) in vectors.into_iter().enumerate() {
            let tx = Arc::new(fixture(mode));
            let entry = MempoolEntry::new(Arc::clone(&tx), 999, 7_000, 42, 100);
            assert_eq!(entry.txid, expected_txid, "mode {mode}");
            assert_eq!(entry.wtxid, Wtxid(Hash256::from_str_be(wtxid)?), "mode {mode}");
            assert_eq!(
                (entry.size, entry.weight, entry.bip141_vsize),
                (size, weight, vsize)
            );
            assert!(Arc::ptr_eq(&entry.tx, &tx));
        }
        Ok(())
    }

    // MempoolEntry's vsize field is policy-adjusted; BIP141's rounded weight
    // is a separate field. Metadata reuse must not overwrite policy inputs.
    #[test]
    fn policy_size_is_not_overwritten_by_bip141_size() {
        for mode in 0..7 {
            for policy_size in [0, 1, 999, u32::MAX] {
                let entry =
                    MempoolEntry::new(Arc::new(fixture(mode)), policy_size, 7_000, 42, 100);
                assert_eq!(entry.vsize, policy_size);
                assert_eq!(entry.ancestor_size, u64::from(policy_size));
                assert_eq!(entry.descendant_size, u64::from(policy_size));
                assert_eq!(
                    (entry.fee, entry.ancestor_fee, entry.descendant_fee),
                    (7_000, 7_000, 7_000)
                );
                assert_eq!(entry.fee_delta, 0);
                assert_eq!(entry.ancestor_fee_delta, 0);
                assert_eq!(entry.descendant_fee_delta, 0);
                assert_eq!((entry.time, entry.height), (42, 100));
            }
        }
    }

    #[test]
    fn raw_empty_entry_keeps_zero_input_behavior() {
        let entry = MempoolEntry::new(Arc::new(Tx::default()), 0, 0, 0, 0);
        assert_eq!(entry.wtxid, Wtxid(entry.txid.0));
        assert_eq!((entry.size, entry.weight, entry.bip141_vsize), (10, 40, 10));
        assert_eq!(entry.fee_rate, 0);
    }
}
