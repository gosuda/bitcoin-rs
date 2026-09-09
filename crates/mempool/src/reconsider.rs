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
    offered: HashMap<Txid, Vec<u64>>,
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
        let mut input_total = 0_u64;
        for input in &tx.inputs {
            let outpoint = input.previous_output;
            let value = if let Some(output) = lookup(&outpoint) {
                output.value
            } else {
                let Some(value) = self.offered.get(&outpoint.txid).and_then(|values| {
                    usize::try_from(outpoint.vout)
                        .ok()
                        .and_then(|vout| values.get(vout))
                }) else {
                    return false;
                };
                *value
            };
            input_total = input_total.saturating_add(value);
        }
        let output_values: Vec<u64> = tx.outputs.iter().map(|output| output.value).collect();
        let output_total = output_values
            .iter()
            .fold(0_u64, |total, value| total.saturating_add(*value));
        let fee = input_total.saturating_sub(output_total);
        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        // Preserve the existing reconsideration metadata contract. Full
        // prevout-aware verification belongs to the separate reorg work; this
        // move must not silently replace it with ordinary admission.
        let entry = MempoolEntry::new(Arc::new(tx.clone()), vsize, fee, self.time, self.height);
        self.offered.insert(entry.txid, output_values);
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
}
