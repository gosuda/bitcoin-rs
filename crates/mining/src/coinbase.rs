use bitcoin_rs_consensus::WITNESS_COMMITMENT_PREFIX;
use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
use bitcoin_rs_script::push_int;
use thiserror::Error;

const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;
const MIN_COINBASE_SCRIPT_SIG_LEN: usize = 2;
const WITNESS_COMMITMENT_TAG: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Consensus witness reserved value used when constructing a BIP141 commitment.
pub const WITNESS_RESERVED_VALUE: [u8; 32] = [0; 32];

/// Candidate assembly failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MiningError {
    /// Coinbase subsidy plus fees exceeded the satoshi range.
    #[error("coinbase value overflows satoshi range")]
    CoinbaseValueOverflow,
    /// A generated coinbase scriptSig exceeded the consensus bound.
    #[error("coinbase scriptSig length {len} exceeds {max}")]
    CoinbaseScriptTooLarge {
        /// Generated scriptSig byte length.
        len: usize,
        /// Maximum consensus scriptSig byte length.
        max: usize,
    },
    /// The immutable snapshot contains an invalid ancestor position.
    #[error("snapshot entry {entry} names missing ancestor {ancestor}")]
    MissingAncestor {
        /// Snapshot position of the entry.
        entry: usize,
        /// Invalid ancestor position.
        ancestor: u32,
    },
    /// The immutable snapshot's dependency graph contains a cycle.
    #[error("snapshot dependency graph contains a cycle at entry {entry}")]
    DependencyCycle {
        /// Snapshot position at which the cycle was detected.
        entry: usize,
    },
    /// A selected fee sum exceeded the satoshi range.
    #[error("selected transaction fees overflow the satoshi range")]
    FeeOverflow,
    /// Candidate scalar arithmetic exceeded its supported width.
    #[error("candidate {field} overflows its supported width")]
    CandidateScalarOverflow {
        /// Scalar that overflowed.
        field: &'static str,
    },
    /// Coinbase reservation already exhausts a configured block limit.
    #[error("coinbase reservation exhausts the {field} limit")]
    CapacityExhausted {
        /// Limit that the coinbase alone exhausted.
        field: &'static str,
    },
    /// Exhausted `max_tries` without meeting the compact target.
    #[error("failed to meet compact target in {tries} nonce attempts")]
    Unsolved {
        /// Nonce attempts consumed.
        tries: u64,
    },
}

/// Builds the coinbase paying `payout`, optionally committing to `SegWit`.
pub(crate) fn build_coinbase(
    height: u32,
    subsidy_halving_interval: u32,
    fees: u64,
    payout: Vec<u8>,
    witness_commitment: Option<&Hash256>,
) -> Result<Tx, MiningError> {
    let value = bitcoin_rs_consensus::block_subsidy(height, subsidy_halving_interval)
        .checked_add(fees)
        .ok_or(MiningError::CoinbaseValueOverflow)?;

    let mut witness = Vec::new();
    let mut outputs = vec![TxOut {
        value,
        script_pubkey: payout,
    }];

    if let Some(commitment) = witness_commitment {
        witness.push(WITNESS_RESERVED_VALUE.to_vec());
        outputs.push(TxOut {
            value: 0,
            script_pubkey: witness_commitment_script(commitment),
        });
    }

    Ok(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0; 32])), 0xffff_ffff),
            script_sig: coinbase_script_sig(height)?,
            sequence: 0xffff_ffff,
            witness,
        }],
        outputs,
        lock_time: 0,
    })
}

/// Builds the BIP141 `OP_RETURN` witness-commitment script (`6a24aa21a9ed || commitment`).
pub fn witness_commitment_script(commitment: &Hash256) -> Vec<u8> {
    let mut script = Vec::with_capacity(38);
    script.push(0x6a); // OP_RETURN
    script.push(36); // PUSH36
    script.extend_from_slice(&WITNESS_COMMITMENT_TAG);
    script.extend_from_slice(commitment.as_byte_array());
    script
}

/// API-13: update an uncommitted coinbase witness before submitblock admission.
pub fn update_uncommitted_block_structures(block: &mut Block, segwit_active: bool) {
    if !segwit_active {
        return;
    }
    let Some(coinbase) = block.txs.first_mut() else {
        return;
    };
    if !coinbase_has_witness_commitment(coinbase) {
        return;
    }
    let Some(input) = coinbase.inputs.first_mut() else {
        return;
    };
    if !input.witness.is_empty() {
        return;
    }
    input.witness.push(WITNESS_RESERVED_VALUE.to_vec());
}

fn coinbase_has_witness_commitment(tx: &Tx) -> bool {
    tx.outputs.iter().any(|output| {
        output.script_pubkey.len() >= 38
            && output.script_pubkey.starts_with(&WITNESS_COMMITMENT_PREFIX)
    })
}

fn coinbase_script_sig(height: u32) -> Result<Vec<u8>, MiningError> {
    // BIP34 requires the minimal `CScriptNum` encoding. Heights 1..=16 therefore
    // use OP_1..OP_16 rather than a data push — `push_int` matches consensus
    // `check_bip34`.
    let mut script = push_int(i64::from(height));
    // Consensus rejects coinbase scriptSigs shorter than two bytes
    // (`bad-cb-length`). Heights whose BIP34 prefix is a single opcode need a
    // trailing OP_0, matching Bitcoin Core's `CreateNewBlock`.
    if script.len() < MIN_COINBASE_SCRIPT_SIG_LEN {
        script.push(0x00);
    }
    if script.len() > MAX_COINBASE_SCRIPT_SIG_LEN {
        return Err(MiningError::CoinbaseScriptTooLarge {
            len: script.len(),
            max: MAX_COINBASE_SCRIPT_SIG_LEN,
        });
    }
    Ok(script)
}

#[cfg(test)]
// CONTRACT: API-13
mod uncommitted_witness_tests {
    use super::{
        WITNESS_RESERVED_VALUE, update_uncommitted_block_structures, witness_commitment_script,
    };
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid,
    };

    fn commitment_block(witness: Vec<Vec<u8>>, with_commitment: bool) -> Block {
        let mut outputs = vec![TxOut {
            value: 50,
            script_pubkey: vec![0x51],
        }];
        if with_commitment {
            outputs.push(TxOut {
                value: 0,
                script_pubkey: witness_commitment_script(&Hash256::from_le_bytes(&[0xab; 32])),
            });
        }
        Block {
            header: Header {
                version: 0x2000_0000,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid::default(), u32::MAX),
                    script_sig: vec![0x51, 0x00],
                    sequence: u32::MAX,
                    witness,
                }],
                outputs,
                lock_time: 0,
            }],
        }
    }

    #[test]
    fn fills_reserved_nonce_when_commitment_present_and_witness_empty() {
        let mut block = commitment_block(Vec::new(), true);
        update_uncommitted_block_structures(&mut block, true);
        assert_eq!(
            block.txs[0].inputs[0].witness,
            vec![WITNESS_RESERVED_VALUE.to_vec()]
        );
    }

    #[test]
    fn leaves_an_existing_coinbase_witness_alone() {
        let custom = vec![vec![0x11; 32]];
        let mut block = commitment_block(custom.clone(), true);
        update_uncommitted_block_structures(&mut block, true);
        assert_eq!(block.txs[0].inputs[0].witness, custom);
    }

    #[test]
    fn skips_without_commitment_or_when_segwit_is_inactive() {
        let mut no_commitment = commitment_block(Vec::new(), false);
        update_uncommitted_block_structures(&mut no_commitment, true);
        assert!(no_commitment.txs[0].inputs[0].witness.is_empty());

        let mut pre_segwit = commitment_block(Vec::new(), true);
        update_uncommitted_block_structures(&mut pre_segwit, false);
        assert!(pre_segwit.txs[0].inputs[0].witness.is_empty());
    }
}
