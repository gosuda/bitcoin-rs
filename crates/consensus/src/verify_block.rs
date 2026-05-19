use bitcoin::Weight;
use bitcoin_rs_primitives::Block;

use crate::ConsensusError;
use crate::rust_path::TipState;

/// Verifies non-contextual block rules that do not require a UTXO set.
pub fn verify_block_rules(block: &Block, prev_tip: &TipState) -> Result<(), ConsensusError> {
    verify_block_rules_borrowed(&block.0, prev_tip)
}

/// Verifies non-contextual block rules for callers that already hold a
/// `&bitcoin::Block`, avoiding a clone into [`bitcoin_rs_primitives::Block`].
pub fn verify_block_rules_borrowed(
    block: &bitcoin::Block,
    _prev_tip: &TipState,
) -> Result<(), ConsensusError> {
    let txdata = &block.txdata;
    if txdata.is_empty() {
        return Err(ConsensusError::EmptyBlock);
    }
    if !txdata[0].is_coinbase() {
        return Err(ConsensusError::MissingCoinbase);
    }
    for (tx_index, tx) in txdata.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(ConsensusError::ExtraCoinbase { tx_index });
        }
    }
    if !block.check_merkle_root() {
        return Err(ConsensusError::MerkleRoot);
    }
    if !block.check_witness_commitment() {
        return Err(ConsensusError::WitnessCommitment);
    }
    let weight = block.weight().to_wu();
    let max = Weight::MAX_BLOCK.to_wu();
    if weight > max {
        return Err(ConsensusError::BlockWeight { weight, max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness, absolute, block, transaction,
    };
    use bitcoin_rs_primitives::Block;

    use super::verify_block_rules;
    use crate::ConsensusError;
    use crate::rust_path::TipState;

    #[test]
    fn valid_single_coinbase_block_passes() {
        let block = Block(bitcoin::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![coinbase_tx()],
        });
        let mut fixed = block;
        let Some(root) = fixed.0.compute_merkle_root() else {
            panic!("single coinbase block should have merkle root");
        };
        fixed.0.header.merkle_root = root;
        assert_eq!(verify_block_rules(&fixed, &tip()), Ok(()));
    }

    #[test]
    fn missing_coinbase_is_rejected() {
        let tx = Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let block = Block(bitcoin::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![tx],
        });
        assert_eq!(
            verify_block_rules(&block, &tip()),
            Err(ConsensusError::MissingCoinbase)
        );
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    const fn tip() -> TipState {
        TipState {
            height: None,
            block_hash: None,
            median_time_past: 0,
        }
    }
}
