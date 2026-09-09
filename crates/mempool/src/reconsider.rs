//! Preparation of ordered transactions displaced by a chain change.
//!
//! The chain owner supplies candidates in dependency order and controls the
//! transition reservation. This builder owns both candidate accounting and the
//! earlier offered outputs needed by descendants, without doing block I/O or
//! replacing the gateway's reconsideration commit path.

use alloc::sync::Arc;
use alloc::vec::Vec;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid};
use hashbrown::HashMap;

use crate::MempoolEntry;

/// Candidate entries and the transactions already offered in the same batch.
///
/// The output overlay includes offered candidates, not just subsequently
/// accepted candidates. The gateway remains responsible for rejecting
/// descendants of candidates that fail or are immediately evicted.
pub struct DisconnectedCandidates {
    // Index retained candidate bodies; outputs keep their full scripts and
    // values without another body reference or a parallel output copy.
    offered: HashMap<Txid, usize>,
    entries: Vec<MempoolEntry>,
    time: u64,
    height: u32,
}

impl DisconnectedCandidates {
    /// Begins a reconsideration batch at the chain owner's applied height.
    #[must_use]
    pub fn new(time: u64, height: u32) -> Self {
        Self {
            offered: HashMap::new(),
            entries: Vec::new(),
            time,
            height,
        }
    }

    /// Offers a non-coinbase transaction using restored coins first, then
    /// outputs of earlier candidates. Returns false if a required input is
    /// unavailable; that transaction's outputs never enter the overlay.
    ///
    /// `lookup` reads the chain owner's current UTXO view before the gateway
    /// takes any pool lock. The caller must hold its chain transition across
    /// preparation and the eventual reconsideration commit.
    pub fn offer(&mut self, tx: &Tx, mut lookup: impl FnMut(&OutPoint) -> Option<TxOut>) -> bool {
        if tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null() {
            return false;
        }
        let mut prevouts = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let outpoint = input.previous_output;
            let Some(output) = lookup(&outpoint).or_else(|| {
                let index = self.offered.get(&outpoint.txid)?;
                self.entries[*index]
                    .tx
                    .outputs
                    .get(usize::try_from(outpoint.vout).ok()?)
                    .cloned()
            }) else {
                return false;
            };
            prevouts.push((outpoint, output));
        }
        // Reuse admission accounting, not its validation/commit path. In
        // particular, mining must retain BIP141 costs for P2SH and witness
        // inputs after a reorg just as it does after ordinary admission.
        let context = crate::accounting::prepared_context(tx, &prevouts, false);
        let entry = MempoolEntry::new(
            Arc::new(tx.clone()),
            context.vsize,
            context.fee,
            self.time,
            self.height,
        )
        .with_sigop_cost(context.sigop_cost);
        // The output overlay indexes this entry's full transaction body.
        self.offered.insert(entry.txid, self.entries.len());
        self.entries.push(entry);
        true
    }

    /// Finishes preparation for the existing reserved gateway batch commit.
    #[must_use]
    pub fn into_entries(self) -> Vec<MempoolEntry> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::{Hash256, TxIn};
    use bitcoin_rs_script::script::{opcode, push_data};

    fn spend(previous_output: OutPoint, value: u64) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        }
    }

    fn funded() -> OutPoint {
        OutPoint::new(Txid::from(Hash256::from_le_bytes(&[1; 32])), 0)
    }

    /// MPL-04: restored coins and dependency-ordered candidates price one batch.
    #[test]
    fn restored_coins_and_ordered_candidates_price_the_batch() {
        let parent = spend(funded(), 9_000);
        let child = spend(OutPoint::new(parent.txid(), 0), 8_000);
        let mut batch = DisconnectedCandidates::new(42, 100);
        assert!(
            batch.offer(&parent, |outpoint| (*outpoint == funded()).then_some(
                TxOut {
                    value: 10_000,
                    script_pubkey: Vec::new()
                }
            ))
        );
        assert!(batch.offer(&child, |_| None));
        let entries = batch.into_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].txid, parent.txid());
        assert_eq!(entries[1].txid, child.txid());
        for entry in entries {
            assert_eq!(entry.fee, 1_000);
            assert_eq!(entry.time, 42);
            assert_eq!(entry.height, 100);
        }
    }

    /// MPL-04: unavailable candidates cannot supply descendant outputs.
    #[test]
    fn unavailable_parent_never_offers_outputs_to_a_child() {
        let parent = spend(funded(), 9_000);
        let child = spend(OutPoint::new(parent.txid(), 0), 8_000);
        let mut batch = DisconnectedCandidates::new(0, 0);
        assert!(!batch.offer(&parent, |_| None));
        assert!(!batch.offer(&child, |_| None));
        assert!(batch.into_entries().is_empty());
    }

    /// MPL-04: authoritative restored coins take precedence over the overlay.
    #[test]
    fn restored_coin_takes_precedence_over_an_offered_output() {
        let mut parent = spend(funded(), 9_000);
        parent.outputs[0].script_pubkey = [vec![0x00, 0x14], vec![2; 20]].concat();
        let child = spend(OutPoint::new(parent.txid(), 0), 8_000);
        let mut batch = DisconnectedCandidates::new(0, 0);
        assert!(batch.offer(&parent, |_| Some(TxOut {
            value: 10_000,
            script_pubkey: Vec::new()
        })));
        assert!(batch.offer(&child, |_| Some(TxOut {
            value: 8_500,
            script_pubkey: Vec::new()
        })));
        let entries = batch.into_entries();
        assert_eq!(entries[1].fee, 500);
        assert_eq!(entries[1].sigop_cost, 0);
    }

    /// MPL-04: coinbase transactions are never reconsideration candidates.
    #[test]
    fn coinbase_does_not_become_a_reconsideration_candidate() {
        let coinbase = spend(OutPoint::new(Txid::default(), u32::MAX), 50_000);
        let mut batch = DisconnectedCandidates::new(0, 0);
        assert!(!batch.offer(&coinbase, |_| panic!("coinbase must not read coins")));
        assert!(batch.into_entries().is_empty());
    }

    /// BIP141 Sigops: legacy/P2SH cost four units; witness-v0 costs one.
    /// These accounting vectors do not claim to perform reorg script validation.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#sigops>
    #[test]
    fn bip141_sigops_are_preserved_from_restored_coins_and_offered_outputs() {
        let p2sh = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
        let p2wpkh = [vec![0x00, 0x14], vec![2; 20]].concat();
        let p2wsh = [vec![0x00, 0x20], vec![2; 32]].concat();
        let multisig = vec![opcode::OP_PUSHNUM_1 + 1, opcode::OP_CHECKMULTISIG];
        let cases = [
            (vec![0x51], Vec::new(), Vec::new(), vec![0xac], 4),
            (
                p2sh.clone(),
                push_data(&multisig),
                Vec::new(),
                Vec::new(),
                8,
            ),
            (p2wpkh, Vec::new(), Vec::new(), Vec::new(), 1),
            (
                p2wsh.clone(),
                Vec::new(),
                vec![multisig.clone()],
                Vec::new(),
                2,
            ),
            (p2sh, push_data(&p2wsh), vec![multisig], Vec::new(), 2),
        ];
        for (prevout_script, script_sig, witness, output_script, expected) in cases {
            let mut parent = spend(funded(), 9_000);
            parent.outputs[0].script_pubkey = prevout_script;
            let mut child = spend(OutPoint::new(parent.txid(), 0), 8_000);
            child.inputs[0].script_sig = script_sig;
            child.inputs[0].witness = witness;
            child.outputs[0].script_pubkey = output_script;

            let mut restored = DisconnectedCandidates::new(42, 100);
            assert!(restored.offer(&child, |_| Some(parent.outputs[0].clone())));
            let entry = &restored.into_entries()[0];
            assert_eq!(entry.sigop_cost, expected, "restored prevout");
            assert_eq!(entry.fee, 1_000);

            let mut offered = DisconnectedCandidates::new(42, 100);
            assert!(offered.offer(&parent, |_| Some(TxOut {
                value: 10_000,
                script_pubkey: vec![0x51],
            })));
            assert!(offered.offer(&child, |_| None));
            let entry = &offered.into_entries()[1];
            assert_eq!(entry.sigop_cost, expected, "offered prevout");
            assert_eq!(entry.fee, 1_000);
        }
    }
}
