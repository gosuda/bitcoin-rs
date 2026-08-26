use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
    script::Builder, transaction,
};
use bitcoin_rs_primitives::Hash256;
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
}

/// Builds the coinbase paying `payout`, optionally committing to `SegWit`.
pub(crate) fn build_coinbase(
    height: u32,
    subsidy_halving_interval: u32,
    fees: u64,
    payout: ScriptBuf,
    witness_commitment: Option<&Hash256>,
) -> Result<Transaction, MiningError> {
    let value = bitcoin_rs_consensus::block_subsidy(height, subsidy_halving_interval)
        .checked_add(fees)
        .ok_or(MiningError::CoinbaseValueOverflow)?;

    let mut witness = Witness::new();
    let mut output = vec![TxOut {
        value: Amount::from_sat(value),
        script_pubkey: payout,
    }];

    if let Some(commitment) = witness_commitment {
        witness.push(WITNESS_RESERVED_VALUE);
        output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: witness_commitment_script(commitment),
        });
    }

    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height)?,
            sequence: Sequence::MAX,
            witness,
        }],
        output,
    })
}

/// Builds the BIP141 `OP_RETURN` witness-commitment script (`6a24aa21a9ed || commitment`).
pub fn witness_commitment_script(commitment: &Hash256) -> ScriptBuf {
    let mut script = Vec::with_capacity(38);
    script.push(0x6a);
    script.push(36);
    script.extend_from_slice(&WITNESS_COMMITMENT_TAG);
    script.extend_from_slice(commitment.as_byte_array());
    ScriptBuf::from_bytes(script)
}

fn coinbase_script_sig(height: u32) -> Result<ScriptBuf, MiningError> {
    // BIP34 requires the minimal `CScriptNum` encoding. Heights 1..=16 therefore
    // use OP_1..OP_16 rather than a data push — `Builder::push_int` matches
    // consensus `check_bip34`.
    let mut script = Builder::new()
        .push_int(i64::from(height))
        .into_script()
        .into_bytes();
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
    Ok(ScriptBuf::from_bytes(script))
}
