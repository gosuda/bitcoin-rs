//! Preparation of ordered transactions displaced by a chain change.
//!
//! The chain owner supplies candidates in dependency order and controls the
//! transition reservation. This builder owns both candidate pricing and the
//! earlier offered outputs needed by descendants, without doing block I/O or
//! replacing the gateway's reconsideration commit path.

use alloc::sync::Arc;
use alloc::vec::Vec;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid};
use hashbrown::HashMap;

use crate::MempoolEntry;

/// Candidate entries and the outputs already offered in the same batch.
///
/// The output overlay includes offered candidates, not just subsequently
/// accepted candidates. The gateway remains responsible for rejecting
/// descendants of candidates that fail or are immediately evicted.
pub struct DisconnectedCandidates {
    // Index the retained transaction bodies rather than copying their outputs.
    // Children need full scripts as well as values for BIP141 accounting.
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
            let output = if let Some(output) = lookup(&outpoint) {
                output
            } else {
                let Some(output) = self.offered.get(&outpoint.txid).and_then(|index| {
                    let outputs = &self.entries[*index].tx.outputs;
                    usize::try_from(outpoint.vout)
                        .ok()
                        .and_then(|vout| outputs.get(vout))
                }) else {
                    return false;
                };
                output.clone()
            };
            prevouts.push((outpoint, output));
        }
        let accounting = crate::accounting::prepared_context(tx, &prevouts, false);
        // Preserve the reserved reorg commit and its existing validation scope,
        // but carry the same resolved-input accounting as ordinary admission.
        let entry = MempoolEntry::new(
            Arc::new(tx.clone()),
            accounting.vsize,
            accounting.fee,
            self.time,
            self.height,
        )
        .with_sigop_cost(accounting.sigop_cost);
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

    #[test]
    fn unavailable_parent_never_offers_outputs_to_a_child() {
        let parent = spend(funded(), 9_000);
        let child = spend(OutPoint::new(parent.txid(), 0), 8_000);
        let mut batch = DisconnectedCandidates::new(0, 0);
        assert!(!batch.offer(&parent, |_| None));
        assert!(!batch.offer(&child, |_| None));
        assert!(batch.into_entries().is_empty());
    }

    #[test]
    fn restored_coin_takes_precedence_over_an_offered_output() {
        let parent = spend(funded(), 9_000);
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
        assert_eq!(batch.into_entries()[1].fee, 500);
    }

    #[test]
    fn coinbase_does_not_become_a_reconsideration_candidate() {
        let coinbase = spend(OutPoint::new(Txid::default(), u32::MAX), 50_000);
        let mut batch = DisconnectedCandidates::new(0, 0);
        assert!(!batch.offer(&coinbase, |_| panic!("coinbase must not read coins")));
        assert!(batch.into_entries().is_empty());
    }
    #[test]
    fn reconsideration_counts_weighted_p2sh_and_witness_prevouts() {
        // BIP141: a two-key P2SH multisig costs 8; the same P2WSH script costs 2.
        let redeem = vec![0x52, 0xae];
        let mut p2sh_tx = spend(funded(), 9_000);
        p2sh_tx.inputs[0].script_sig = bitcoin_rs_script::push_data(&redeem);
        let mut p2sh_batch = DisconnectedCandidates::new(0, 0);
        assert!(p2sh_batch.offer(&p2sh_tx, |_| Some(TxOut {
            value: 10_000,
            script_pubkey: [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat(),
        })));
        assert_eq!(p2sh_batch.into_entries()[0].sigop_cost, 8);

        let mut witness_tx = spend(funded(), 9_000);
        witness_tx.inputs[0].witness = vec![redeem];
        let mut witness_batch = DisconnectedCandidates::new(0, 0);
        assert!(witness_batch.offer(&witness_tx, |_| Some(TxOut {
            value: 10_000,
            script_pubkey: [vec![0x00, 0x20], vec![2; 32]].concat(),
        })));
        assert_eq!(witness_batch.into_entries()[0].sigop_cost, 2);
    }

    #[test]
    fn offered_parent_scripts_are_retained_for_child_accounting() {
        let mut parent = spend(funded(), 9_000);
        parent.outputs[0].script_pubkey = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
        let mut child = spend(OutPoint::new(parent.txid(), 0), 8_000);
        child.inputs[0].script_sig = bitcoin_rs_script::push_data(&[0x52, 0xae]);
        let mut batch = DisconnectedCandidates::new(0, 0);
        assert!(batch.offer(&parent, |_| Some(TxOut {
            value: 10_000,
            script_pubkey: vec![0x51]
        })));
        assert!(batch.offer(&child, |_| None));
        let entries = batch.into_entries();
        assert_eq!(entries[1].fee, 1_000);
        assert_eq!(entries[1].sigop_cost, 8);
    }
}
