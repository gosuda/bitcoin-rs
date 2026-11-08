use alloc::vec::Vec;

use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, OutPoint, TransactionView, Tx, Txid};
use bitcoin_rs_storage::CommittedFacts;

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

    /// `MPS-01`: the commit's ordered transaction and spend effects.
    #[must_use]
    pub fn from_committed(facts: &CommittedFacts) -> Self {
        let tx_count: usize = facts.blocks.iter().map(|block| block.txs.len()).sum();
        let mut out = Self {
            confirmed: Vec::with_capacity(tx_count),
            spent: Vec::with_capacity(tx_count),
        };
        for block in &facts.blocks {
            for tx in &block.txs {
                out.confirmed
                    .push(Txid::from(Hash256::from_le_bytes(&tx.txid)));
                out.spent.push(
                    tx.inputs
                        .iter()
                        .map(|input| {
                            OutPoint::new(
                                Txid::from(Hash256::from_le_bytes(&input.txid)),
                                input.vout,
                            )
                        })
                        .collect(),
                );
            }
        }
        out
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
                .filter(|outpoint| !outpoint.is_null())
                .collect(),
        );
    }

    fn push_tx_view(&mut self, tx: &TransactionView<'_>) {
        self.confirmed.push(tx.txid());
        let mut spent = Vec::with_capacity(tx.input_count());
        for index in 0..tx.input_count() {
            let outpoint = tx.input_outpoint(index);
            if !outpoint.is_null() {
                spent.push(outpoint);
            }
        }
        self.spent.push(spent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, Header, LockTime, Script, Sequence, TxIn, TxOut, Witness,
    };
    use bitcoin_rs_storage::committed_facts::{
        CommittedBlock, CommittedFacts, SpentPrevout, TxFacts,
    };

    fn coinbase_tx() -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from(vec![0x51]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::from(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn spend_tx(prev_txid: Txid) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(prev_txid, 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49),
                script_pubkey: Script::from(vec![0x52]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn committed_facts(coinbase: &Tx, spend: &Tx) -> CommittedFacts {
        CommittedFacts {
            commit_id: 7,
            blocks: vec![CommittedBlock {
                height: 1,
                hash: [0xAA; 32],
                parent_hash: [0u8; 32],
                header: [0u8; 80],
                txs: vec![
                    TxFacts {
                        txid: *coinbase.txid().as_bytes(),
                        offset: 0,
                        len: 0,
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                    },
                    TxFacts {
                        txid: *spend.txid().as_bytes(),
                        offset: 0,
                        len: 0,
                        inputs: vec![SpentPrevout {
                            txid: *coinbase.txid().as_bytes(),
                            vout: 0,
                            value: 50,
                            script: bitcoin_rs_storage::Bytes::from_static(&[0x51]),
                            height: 1,
                            coinbase: true,
                        }],
                        outputs: Vec::new(),
                    },
                ],
            }],
        }
    }

    // MPS-01
    #[test]
    fn settlement_facts_come_from_the_commit() {
        let coinbase = coinbase_tx();
        let spend = spend_tx(coinbase.txid());
        let image = BlockImage::from_local(Block {
            header: Header::default(),
            txs: vec![coinbase.clone(), spend.clone()],
        });
        let committed = TransitionFacts::from_committed(&committed_facts(&coinbase, &spend));
        let from_image = TransitionFacts::from_block(&image);
        assert_eq!(committed, from_image);
        assert!(
            committed.spent[0].is_empty(),
            "a coinbase spends no prevout"
        );
        assert_eq!(committed.spent[1], vec![OutPoint::new(coinbase.txid(), 0)]);
    }
}
