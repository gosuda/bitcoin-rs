use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};
use bitcoin_rs_primitives::Hash256;
use thiserror::Error;

const HALVING_INTERVAL: u32 = 210_000;
const INITIAL_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;
const WITNESS_COMMITMENT_TAG: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Mining crate error type.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MiningError {
    /// Coinbase subsidy plus fees exceeded Bitcoin's money range.
    #[error("coinbase value overflows satoshi range")]
    CoinbaseValueOverflow,
    /// The generated coinbase scriptSig exceeded the consensus script size bound.
    #[error("coinbase scriptSig length {len} exceeds {max}")]
    CoinbaseScriptTooLarge {
        /// Generated scriptSig byte length.
        len: usize,
        /// Maximum consensus scriptSig byte length.
        max: usize,
    },
    /// A selected mempool entry disappeared before template assembly completed.
    #[error("selected mempool entry {0} is missing")]
    MissingMempoolEntry(u32),
    /// A transaction weight did not fit into the template field width.
    #[error("transaction weight does not fit in u32")]
    TransactionWeightOverflow,
}

/// Coinbase construction parameters that are stable across template requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinbaseTemplateConfig {
    /// Script receiving the subsidy plus selected transaction fees.
    pub miner_script_pubkey: ScriptBuf,
}

impl CoinbaseTemplateConfig {
    /// Creates a coinbase configuration paying the supplied miner script.
    #[must_use]
    pub const fn new(miner_script_pubkey: ScriptBuf) -> Self {
        Self {
            miner_script_pubkey,
        }
    }

    /// Builds a coinbase transaction with the configured miner payout script.
    pub fn build_coinbase_template(
        &self,
        height: u32,
        fees: u64,
        witness_commitment: &Hash256,
        extranonce_reserve: usize,
    ) -> Result<Transaction, MiningError> {
        let script_sig = coinbase_script_sig(height, extranonce_reserve)?;
        let coinbase_value = block_subsidy(height)
            .checked_add(fees)
            .ok_or(MiningError::CoinbaseValueOverflow)?;

        Ok(Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(coinbase_value),
                    script_pubkey: self.miner_script_pubkey.clone(),
                },
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: witness_commitment_script(witness_commitment),
                },
            ],
        })
    }
}

impl Default for CoinbaseTemplateConfig {
    fn default() -> Self {
        Self {
            miner_script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }
    }
}

/// Builds a coinbase template using the default miner payout script.
pub fn build_coinbase_template(
    height: u32,
    fees: u64,
    witness_commitment: &Hash256,
    extranonce_reserve: usize,
) -> Result<Transaction, MiningError> {
    CoinbaseTemplateConfig::default().build_coinbase_template(
        height,
        fees,
        witness_commitment,
        extranonce_reserve,
    )
}

/// Returns the block subsidy for a height in satoshis.
#[must_use]
pub const fn block_subsidy(height: u32) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= u64::BITS {
        return 0;
    }
    INITIAL_SUBSIDY_SATS >> halvings
}

/// Builds the BIP141 witness commitment output script.
#[must_use]
pub fn witness_commitment_script(witness_commitment: &Hash256) -> ScriptBuf {
    let mut script = Vec::with_capacity(38);
    script.push(0x6a);
    script.push(36);
    script.extend_from_slice(&WITNESS_COMMITMENT_TAG);
    script.extend_from_slice(witness_commitment.as_byte_array());
    ScriptBuf::from_bytes(script)
}

fn coinbase_script_sig(height: u32, extranonce_reserve: usize) -> Result<ScriptBuf, MiningError> {
    let encoded_height = encode_script_number(u64::from(height));
    let len = encoded_height
        .len()
        .saturating_add(1)
        .saturating_add(extranonce_reserve);
    if len > MAX_COINBASE_SCRIPT_SIG_LEN {
        return Err(MiningError::CoinbaseScriptTooLarge {
            len,
            max: MAX_COINBASE_SCRIPT_SIG_LEN,
        });
    }

    let mut script = Vec::with_capacity(len);
    script.push(
        u8::try_from(encoded_height.len())
            .unwrap_or_else(|_| unreachable!("u32 height script number fits in u8")),
    );
    script.extend_from_slice(&encoded_height);
    script.resize(len, 0);
    Ok(ScriptBuf::from_bytes(script))
}

fn encode_script_number(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let mut remaining = value;
    let mut result = Vec::new();
    while remaining > 0 {
        result.push(remaining.to_le_bytes()[0]);
        remaining >>= 8;
    }
    if result.last().is_some_and(|last| *last & 0x80 != 0) {
        result.push(0);
    }
    result
}
