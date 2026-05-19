use std::collections::BTreeMap;

use bitcoin::{Transaction, Txid, consensus};
use bitcoin_rs_mempool::{EntryId as MempoolEntryId, Mempool};
use bitcoin_rs_primitives::Hash256;
use serde::{Deserialize, Serialize};

use crate::coinbase::{MiningError, block_subsidy, witness_commitment_script};
use crate::policy::MiningPolicy;

/// Parameters supplied by chain state for one `getblocktemplate` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockTemplateParams {
    /// Previous block hash in consensus little-endian storage order.
    pub previous_block_hash: Hash256,
    /// Candidate block height.
    pub height: u32,
    /// Candidate block version.
    pub version: i32,
    /// Compact target bits as an eight-character big-endian hex string.
    pub bits: String,
    /// Full target as a 64-character big-endian hex string.
    pub target: String,
    /// Minimum valid block time.
    pub min_time: u32,
    /// Template creation time.
    pub current_time: u32,
    /// Long-poll identity for template invalidation.
    pub long_poll_id: String,
    /// Maximum candidate block weight.
    pub max_weight: u32,
    /// Maximum candidate block sigop cost.
    pub max_sigops: u32,
    /// Maximum serialized block size.
    pub max_size: u32,
    /// BIP141 default witness commitment payload.
    pub witness_commitment: Hash256,
}

/// BIP22/23 `getblocktemplate` response using Bitcoin Core's JSON field names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockTemplate {
    /// Candidate block version.
    pub version: i32,
    /// Previous block hash as conventional big-endian hex.
    pub previousblockhash: String,
    /// Non-coinbase transactions selected for the block.
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase auxiliary data object.
    pub coinbaseaux: BTreeMap<String, String>,
    /// Coinbase output value in satoshis, including subsidy and selected fees.
    pub coinbasevalue: u64,
    /// Long-poll identity for template invalidation.
    pub longpollid: String,
    /// Full target as conventional big-endian hex.
    pub target: String,
    /// Minimum valid block time.
    pub mintime: u32,
    /// Template fields miners may mutate.
    pub mutable: Vec<String>,
    /// Allowed nonce range encoded as hex.
    pub noncerange: String,
    /// Maximum candidate block sigop cost.
    pub sigoplimit: u32,
    /// Maximum serialized block size.
    pub sizelimit: u32,
    /// Maximum candidate block weight.
    pub weightlimit: u32,
    /// Template creation time.
    pub curtime: u32,
    /// Compact target bits as hex.
    pub bits: String,
    /// Candidate block height.
    pub height: u32,
    /// BIP141 default witness commitment output script as hex.
    pub default_witness_commitment: String,
}

impl BlockTemplate {
    /// Builds a template from the supplied mempool and chain-state parameters.
    pub fn from_mempool(
        mempool: &Mempool,
        policy: &MiningPolicy,
        params: BlockTemplateParams,
    ) -> Result<Self, MiningError> {
        let selected = policy.select_transactions(mempool, params.max_weight);
        Self::from_selected(mempool, selected, params)
    }

    fn from_selected(
        mempool: &Mempool,
        selected: Vec<MempoolEntryId>,
        params: BlockTemplateParams,
    ) -> Result<Self, MiningError> {
        let mut tx_positions = BTreeMap::<Txid, usize>::new();
        for (index, id) in selected.iter().copied().enumerate() {
            let entry = mempool
                .entry(id)
                .ok_or(MiningError::MissingMempoolEntry(id))?;
            tx_positions.insert(entry.tx.compute_txid(), index + 1);
        }

        let mut fees = 0_u64;
        let mut transactions = Vec::with_capacity(selected.len());
        for id in selected {
            let entry = mempool
                .entry(id)
                .ok_or(MiningError::MissingMempoolEntry(id))?;
            fees = fees
                .checked_add(entry.fee)
                .ok_or(MiningError::CoinbaseValueOverflow)?;
            transactions.push(TemplateTransaction::from_entry(
                &entry.tx,
                entry.fee,
                &tx_positions,
            )?);
        }

        let coinbasevalue = block_subsidy(params.height)
            .checked_add(fees)
            .ok_or(MiningError::CoinbaseValueOverflow)?;
        let witness_script = witness_commitment_script(&params.witness_commitment);

        Ok(Self {
            version: params.version,
            previousblockhash: params.previous_block_hash.to_string_be(),
            transactions,
            coinbaseaux: BTreeMap::new(),
            coinbasevalue,
            longpollid: params.long_poll_id,
            target: params.target,
            mintime: params.min_time,
            mutable: vec![
                String::from("time"),
                String::from("transactions"),
                String::from("prevblock"),
            ],
            noncerange: String::from("00000000ffffffff"),
            sigoplimit: params.max_sigops,
            sizelimit: params.max_size,
            weightlimit: params.max_weight,
            curtime: params.current_time,
            bits: params.bits,
            height: params.height,
            default_witness_commitment: hex_lower(witness_script.as_bytes()),
        })
    }
}

/// BIP22/23 transaction entry using Bitcoin Core's JSON field names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TemplateTransaction {
    /// Full transaction consensus serialization as hex.
    pub data: String,
    /// Transaction id as conventional big-endian hex.
    pub txid: String,
    /// Witness transaction id as conventional big-endian hex.
    pub hash: String,
    /// One-based indexes of selected in-template ancestors.
    pub depends: Vec<usize>,
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// Transaction sigop cost.
    pub sigops: u32,
    /// Transaction weight in weight units.
    pub weight: u32,
}

impl TemplateTransaction {
    fn from_entry(
        tx: &Transaction,
        fee: u64,
        tx_positions: &BTreeMap<Txid, usize>,
    ) -> Result<Self, MiningError> {
        let weight = u32::try_from(tx.weight().to_wu())
            .map_err(|_| MiningError::TransactionWeightOverflow)?;
        Ok(Self {
            data: hex_lower(&consensus::serialize(tx)),
            txid: tx.compute_txid().to_string(),
            hash: tx.compute_wtxid().to_string(),
            depends: depends(tx, tx_positions),
            fee,
            sigops: 0,
            weight,
        })
    }
}

fn depends(tx: &Transaction, tx_positions: &BTreeMap<Txid, usize>) -> Vec<usize> {
    let mut depends = tx
        .input
        .iter()
        .filter_map(|input| tx_positions.get(&input.previous_output.txid).copied())
        .collect::<Vec<_>>();
    depends.sort_unstable();
    depends.dedup();
    depends
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
