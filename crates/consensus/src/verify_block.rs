use bitcoin::Weight;
use bitcoin_rs_primitives::Block;

use crate::ConsensusError;
use crate::rust_path::TipState;

/// Context needed for block rules whose activation is height-dependent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRuleContext {
    /// Whether BIP141 segwit block rules are active for the candidate block.
    pub segwit_active: bool,
}

impl BlockRuleContext {
    /// Conservative non-contextual mode: enforce checks from active softforks.
    #[must_use]
    pub const fn non_contextual() -> Self {
        Self {
            segwit_active: true,
        }
    }
}

/// Verifies non-contextual block rules that do not require a UTXO set.
pub fn verify_block_rules(block: &Block, prev_tip: &TipState) -> Result<(), ConsensusError> {
    verify_block_rules_contextual(block, prev_tip, BlockRuleContext::non_contextual())
}

/// Verifies block rules with caller-supplied deployment activation context.
pub fn verify_block_rules_contextual(
    block: &Block,
    prev_tip: &TipState,
    context: BlockRuleContext,
) -> Result<(), ConsensusError> {
    verify_block_rules_borrowed_contextual(&block.0, prev_tip, context)
}

/// Verifies non-contextual block rules for callers that already hold a
/// `&bitcoin::Block`, avoiding a clone into [`bitcoin_rs_primitives::Block`].
pub fn verify_block_rules_borrowed(
    block: &bitcoin::Block,
    prev_tip: &TipState,
) -> Result<(), ConsensusError> {
    verify_block_rules_borrowed_contextual(block, prev_tip, BlockRuleContext::non_contextual())
}

/// Verifies block rules for borrowed blocks with caller-supplied deployment context.
pub fn verify_block_rules_borrowed_contextual(
    block: &bitcoin::Block,
    _prev_tip: &TipState,
    context: BlockRuleContext,
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
    verify_merkle_root(block)?;
    if context.segwit_active && !block.check_witness_commitment() {
        return Err(ConsensusError::WitnessCommitment);
    }
    let weight = block.weight().to_wu();
    let max = Weight::MAX_BLOCK.to_wu();
    if weight > max {
        return Err(ConsensusError::BlockWeight { weight, max });
    }
    Ok(())
}

fn verify_merkle_root(block: &bitcoin::Block) -> Result<(), ConsensusError> {
    let hashes: Vec<_> = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    let Some(root) = merkle_root(&hashes) else {
        return Err(ConsensusError::MerkleRoot);
    };
    if block.header.merkle_root != root.into() {
        return Err(ConsensusError::MerkleRoot);
    }
    if merkle_tree_is_mutated(&hashes)? {
        return Err(ConsensusError::MerkleMutation);
    }
    Ok(())
}

fn merkle_tree_is_mutated<T>(hashes: &[T]) -> Result<bool, ConsensusError>
where
    T: bitcoin::hashes::Hash + bitcoin::consensus::Encodable + Eq + Copy,
    <T as bitcoin::hashes::Hash>::Engine: bitcoin::io::Write,
{
    let mut level = hashes.to_vec();
    while level.len() > 1 {
        if level.chunks_exact(2).any(|pair| pair[0] == pair[1]) {
            return Ok(true);
        }
        next_merkle_level(&mut level)?;
    }
    Ok(false)
}

fn merkle_root<T>(hashes: &[T]) -> Option<T>
where
    T: bitcoin::hashes::Hash + bitcoin::consensus::Encodable + Copy,
    <T as bitcoin::hashes::Hash>::Engine: bitcoin::io::Write,
{
    let mut hashes = hashes.to_vec();
    bitcoin::merkle_tree::calculate_root_inline(&mut hashes)
}

fn next_merkle_level<T>(level: &mut Vec<T>) -> Result<(), ConsensusError>
where
    T: bitcoin::hashes::Hash + bitcoin::consensus::Encodable + Copy,
    <T as bitcoin::hashes::Hash>::Engine: bitcoin::io::Write,
{
    let original_len = level.len();
    for idx in 0..original_len.div_ceil(2) {
        let left = level[2 * idx];
        let right = level[(2 * idx + 1).min(original_len - 1)];
        let mut encoder = T::engine();
        left.consensus_encode(&mut encoder)
            .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
        right
            .consensus_encode(&mut encoder)
            .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
        level[idx] = T::from_engine(encoder);
    }
    level.truncate(original_len.div_ceil(2));
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

    use super::{BlockRuleContext, verify_block_rules, verify_block_rules_contextual};
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

    #[test]
    fn contextual_rules_skip_bip141_commitment_before_segwit_activation() {
        let block = block_with_transactions(vec![coinbase_tx(), witness_spend_tx()]);

        assert_eq!(
            verify_block_rules_contextual(
                &block,
                &tip(),
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Ok(())
        );
    }

    #[test]
    fn contextual_rules_enforce_bip141_commitment_after_segwit_activation() {
        let block = block_with_transactions(vec![coinbase_tx(), witness_spend_tx()]);

        assert_eq!(
            verify_block_rules_contextual(
                &block,
                &tip(),
                BlockRuleContext {
                    segwit_active: true,
                },
            ),
            Err(ConsensusError::WitnessCommitment)
        );
    }

    #[test]
    fn contextual_rules_always_enforce_block_weight_limit() {
        let mut coinbase = coinbase_tx();
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![1; 1_000_001]);
        let block = block_with_transactions(vec![coinbase]);

        assert!(matches!(
            verify_block_rules_contextual(
                &block,
                &tip(),
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Err(ConsensusError::BlockWeight { .. })
        ));
        assert!(matches!(
            verify_block_rules_contextual(
                &block,
                &tip(),
                BlockRuleContext {
                    segwit_active: true,
                },
            ),
            Err(ConsensusError::BlockWeight { .. })
        ));
    }

    #[test]
    fn duplicate_transaction_ids_are_rejected_even_with_matching_merkle_root() {
        let tx = spend_tx(0x03);
        let block = block_with_transactions(vec![coinbase_tx(), spend_tx(0x02), tx.clone(), tx]);

        assert_eq!(
            verify_block_rules_contextual(
                &block,
                &tip(),
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Err(ConsensusError::MerkleMutation)
        );
    }

    #[test]
    fn duplicate_transaction_ids_without_merkle_mutation_reach_later_validation() {
        let tx = spend_tx(0x04);
        let distinct = spend_tx(0x05);
        let block = block_with_transactions(vec![coinbase_tx(), tx.clone(), distinct, tx]);

        assert_eq!(
            verify_block_rules_contextual(
                &block,
                &tip(),
                BlockRuleContext {
                    segwit_active: false,
                },
            ),
            Ok(())
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

    fn witness_spend_tx() -> Transaction {
        let mut witness = Witness::new();
        witness.push(vec![1; 32]);
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn spend_tx(seed: u8) -> Transaction {
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([seed; 32]),
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
        }
    }

    fn block_with_transactions(txdata: Vec<Transaction>) -> Block {
        let mut block = Block(bitcoin::Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        });
        let Some(root) = block.0.compute_merkle_root() else {
            panic!("block should have merkle root");
        };
        block.0.header.merkle_root = root;
        block
    }

    const fn tip() -> TipState {
        TipState {
            height: None,
            block_hash: None,
            median_time_past: 0,
        }
    }
}
