use alloc::sync::Arc;

use bitcoin_rs_primitives::{Tx, Txid, Wtxid};

#[cfg(test)]
use bitcoin_rs_primitives::{LockTime, Script, Witness};

/// Slot index for a pooled transaction. Removal allows the slot to be reused.
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
    /// Mempool acceptance time in wall-clock seconds since the Unix epoch.
    pub time: u64,
    /// Locally submitted body still awaiting a successful peer getdata response.
    pub unbroadcast: bool,
    /// Chain height at acceptance.
    pub height: u32,
    /// BIP141 sigop cost, counted against the resolved prevouts.
    /// Admission supplies the resolved cost; callers without prevout facts use 0.
    pub sigop_cost: u32,
}

impl MempoolEntry {
    /// Policy-charged weight in weight units: the larger of the consensus
    /// weight and the sigop-adjusted weight, kept exact only while its vbyte
    /// rounding equals `vsize` and otherwise `vsize * 4`.
    ///
    /// This is the weight that chunk feerates and cluster limits charge. It
    /// stays unrounded so that a caller summing several entries rounds the sum
    /// to vbytes once: summing each entry's `vsize` instead can overstate it,
    /// since two 41 WU entries round to 11 vB each, while together they round
    /// to `ceil(82 / 4)` = 21 vB.
    #[must_use]
    pub fn policy_weight(&self) -> u64 {
        crate::accounting::charged_weight(self.weight, self.vsize, self.sigop_cost)
    }

    /// Builds a complete entry from the transaction and admission facts.
    #[must_use]
    pub fn new(tx: Arc<Tx>, vsize: u32, fee: u64, time: u64, height: u32, sigop_cost: u32) -> Self {
        let own_size = u64::from(vsize);
        let txid = tx.txid();
        // BIP141: witness-free transactions have identical txid and wtxid.
        // A stack containing an empty item still has witness serialization.
        let wtxid = if tx.has_witness() {
            tx.wtxid()
        } else {
            Wtxid(txid.0)
        };
        let weight = tx.weight();
        let bip141_vsize = u32::try_from(Tx::vsize_from_weight(weight)).unwrap_or(u32::MAX);
        let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
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
            unbroadcast: false,
            height,
        }
    }

    /// Actual fee plus the signed mining-only adjustment.
    #[must_use]
    pub fn modified_fee(&self) -> i128 {
        i128::from(self.fee) + i128::from(self.fee_delta)
    }

    /// Returns whether this transaction signals BIP-125 replaceability.
    #[must_use]
    pub fn is_replaceable(&self) -> bool {
        const RBF_FLAG_THRESHOLD: u32 = 0xFFFF_FFFE;
        self.tx
            .inputs
            .iter()
            .any(|input| input.sequence.to_consensus() < RBF_FLAG_THRESHOLD)
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
    use bitcoin_rs_primitives::{OutPoint, Sequence, Tx, TxIn};
    use std::sync::Arc;

    #[test]
    fn replaceability_follows_the_bip125_sequence_threshold() {
        for (sequence, replaceable) in [
            (0xFFFF_FFFD_u32, true),
            (0xFFFF_FFFE, false),
            (0xFFFF_FFFF, false),
        ] {
            assert_eq!(
                entry_with_sequence(sequence).is_replaceable(),
                replaceable,
                "sequence {sequence:#x}"
            );
        }
    }

    /// No inputs means no signal, and the `any()` over an empty iterator must
    /// not report one.
    #[test]
    fn is_replaceable_false_for_no_inputs() {
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![],
            outputs: vec![],
        };
        assert!(!MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0).is_replaceable());
    }

    fn entry_with_sequence(sequence: u32) -> MempoolEntry {
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            outputs: vec![],
        };
        MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0)
    }
}

#[cfg(test)]
mod mining_metadata_tests {
    use super::*;
    use bitcoin_rs_primitives::Tx;
    use std::sync::Arc;

    fn bare_entry() -> MempoolEntry {
        let tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![],
            outputs: vec![],
        };
        MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0)
    }

    #[test]
    fn modified_fee_math_is_signed_and_starts_at_the_actual_fee() {
        let mut entry = bare_entry();
        assert_eq!(entry.fee_delta, 0);
        assert_eq!(entry.modified_fee(), 1_000);
        assert_eq!(entry.ancestor_fee_delta, 0);

        entry.fee_delta = -3_000;
        assert_eq!(entry.modified_fee(), -2_000);
        assert_eq!(entry.fee, 1_000, "an overlay never changes the actual fee");
    }

    fn weighted_entry(weight: u64, vsize: u32, sigop_cost: u32) -> MempoolEntry {
        let mut entry = MempoolEntry::new(Arc::new(Tx::default()), vsize, 1_000, 1, 7, sigop_cost);
        entry.weight = weight;
        entry
    }

    /// Two 41 WU entries round to 11 vB each but 21 vB together, so a caller
    /// that sums `policy_weight` rounds once and gets the smaller figure.
    #[test]
    fn policy_weight_is_exact_so_a_sum_rounds_once() {
        let pair = [weighted_entry(41, 11, 0), weighted_entry(41, 11, 0)];
        let exact: u64 = pair.iter().map(MempoolEntry::policy_weight).sum();
        let rounded: u64 = pair.iter().map(|entry| u64::from(entry.vsize)).sum();
        assert_eq!((exact, rounded), (82, 22));
        assert_eq!(exact.div_ceil(4), 21);
    }

    #[test]
    fn policy_weight_follows_sigops_and_trusts_a_mismatched_vsize() {
        // Three sigops charge 60 WU, which rounds to the 15 vB the entry carries.
        assert_eq!(weighted_entry(41, 15, 3).policy_weight(), 60);
        // A vsize that is not the rounded exact weight wins: 20 vB is 80 WU.
        assert_eq!(weighted_entry(41, 20, 0).policy_weight(), 80);
    }
}

#[cfg(test)]
mod wire_metadata_tests {
    use alloc::sync::Arc;

    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
        Wtxid,
    };

    use super::MempoolEntry;

    fn fixture(mode: usize) -> Tx {
        let mut tx = Tx {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x11; 32])), 0),
                    script_sig: Script::from_bytes(vec![0x51]),
                    sequence: Sequence::from_consensus(0xffff_fffe),
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x22; 32])), 7),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::from_consensus(9),
        };
        match mode {
            0 => {}
            1 => tx.inputs[0].witness = Witness::from_stack(vec![Vec::new()]),
            2..=4 => tx.inputs[1].witness = Witness::from_stack(vec![vec![0xaa; mode - 1]]),
            5 => {
                tx.inputs[0].witness = Witness::from_stack(vec![Vec::new(), vec![0xbb; 253]]);
                tx.inputs[1].witness = Witness::from_stack(vec![Vec::new()]);
            }
            6 => tx.inputs[1].witness = Witness::from_stack(vec![Vec::new(); 253]),
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
            let entry = MempoolEntry::new(Arc::clone(&tx), 999, 7_000, 42, 100, 0);
            assert_eq!(entry.txid, expected_txid, "mode {mode}");
            assert_eq!(
                entry.wtxid,
                Wtxid(Hash256::from_str_be(wtxid)?),
                "mode {mode}"
            );
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
                    MempoolEntry::new(Arc::new(fixture(mode)), policy_size, 7_000, 42, 100, 0);
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
        let entry = MempoolEntry::new(Arc::new(Tx::default()), 0, 0, 0, 0, 0);
        assert_eq!(entry.wtxid, Wtxid(entry.txid.0));
        assert_eq!((entry.size, entry.weight, entry.bip141_vsize), (10, 40, 10));
        assert_eq!(entry.fee_rate, 0);
    }
}
