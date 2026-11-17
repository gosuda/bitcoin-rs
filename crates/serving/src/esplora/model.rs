use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub(super) struct TransactionStatus {
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_time: Option<u32>,
}

impl TransactionStatus {
    pub(super) const fn unconfirmed() -> Self {
        Self {
            confirmed: false,
            block_height: None,
            block_hash: None,
            block_time: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct TransactionOutput {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct TransactionInput {
    pub txid: String,
    pub vout: u32,
    pub prevout: Option<TransactionOutput>,
    pub scriptsig: String,
    pub scriptsig_asm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Vec<String>>,
    pub is_coinbase: bool,
    pub sequence: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_redeemscript_asm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_witnessscript_asm: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct TransactionValue {
    pub txid: String,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<TransactionInput>,
    pub vout: Vec<TransactionOutput>,
    pub size: u32,
    pub weight: u64,
    pub fee: u64,
    pub status: TransactionStatus,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct BlockValue {
    pub id: String,
    pub height: u32,
    pub version: u32,
    pub timestamp: u32,
    pub tx_count: u32,
    pub size: u32,
    pub weight: u64,
    pub merkle_root: String,
    pub previousblockhash: Option<String>,
    pub mediantime: u32,
    pub nonce: u32,
    pub bits: u32,
    pub difficulty: f64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct BlockStatus {
    pub in_best_chain: bool,
    pub height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_best: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Outspend {
    pub spent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vin: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TransactionStatus>,
}

impl Outspend {
    pub(super) const fn unspent() -> Self {
        Self {
            spent: false,
            txid: None,
            vin: None,
            status: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(super) struct ScriptStats {
    pub tx_count: u64,
    pub funded_txo_count: u64,
    pub funded_txo_sum: u64,
    pub spent_txo_count: u64,
    pub spent_txo_sum: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ScriptSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scripthash: Option<String>,
    pub chain_stats: ScriptStats,
    pub mempool_stats: ScriptStats,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct UtxoValue {
    pub txid: String,
    pub vout: u32,
    pub status: TransactionStatus,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct MerkleProof {
    pub block_height: u32,
    pub merkle: Vec<String>,
    pub pos: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct MempoolSummary {
    pub count: u64,
    pub vsize: u64,
    pub total_fee: u64,
    pub fee_histogram: Vec<(f64, u64)>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct RecentTransaction {
    pub txid: String,
    pub fee: u64,
    pub vsize: u32,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct AddressTransactionSummary {
    pub txid: String,
    pub value: u64,
    pub height: u32,
    pub time: u32,
}
