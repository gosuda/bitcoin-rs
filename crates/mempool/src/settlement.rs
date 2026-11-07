use alloc::vec::Vec;

use bitcoin_rs_consensus::primitives::{BlockImage, OutPoint, TransactionView, Tx, Txid};

/// Ordered transition facts of one committed block (`MPS-01`).
///
/// The chain commit supplies spend effects and confirmed identities; the
/// mempool plans settlement from these facts alone and never borrows the
/// whole block. `spent[i]` lists the prevouts that `confirmed[i]` spends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransitionFacts {
    pub confirmed: Vec<Txid>,
    pub spent: Vec<Vec<OutPoint>>,
}

impl TransitionFacts {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            confirmed: Vec::new(),
            spent: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_block(block: &BlockImage) -> Self {
        let mut facts = Self {
            confirmed: Vec::with_capacity(block.tx_count()),
            spent: Vec::with_capacity(block.tx_count()),
        };
        for index in 0..block.tx_count() {
            let tx = block.tx(index);
            facts.push_tx_view(&tx);
        }
        facts
    }

    #[must_use]
    pub fn from_txs(txs: &[&Tx]) -> Self {
        let mut facts = Self {
            confirmed: Vec::with_capacity(txs.len()),
            spent: Vec::with_capacity(txs.len()),
        };
        for tx in txs {
            facts.push_tx(tx);
        }
        facts
    }

    fn push_tx(&mut self, tx: &Tx) {
        self.confirmed.push(tx.txid());
        self.spent.push(
            tx.inputs
                .iter()
                .map(|input| input.previous_output)
                .collect(),
        );
    }

    fn push_tx_view(&mut self, tx: &TransactionView<'_>) {
        self.confirmed.push(tx.txid());
        let mut spent = Vec::with_capacity(tx.input_count());
        for index in 0..tx.input_count() {
            spent.push(tx.input_outpoint(index));
        }
        self.spent.push(spent);
    }
}
