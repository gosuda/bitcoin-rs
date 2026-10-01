//! Block template conversion to SV2 TDP messages.
//!
//! Converts the node-owned [`BlockTemplate`](crate::BlockTemplate) into raw
//! SV2 TDP message bytes (`NewTemplate` + `SetNewPrevHash`) ready for transmission.

use std::sync::Arc;

use bitcoin_hashes::{Hash as _, sha256d};
use bitcoin_rs_primitives::encode::{consensus_bytes, deserialize};
use bitcoin_rs_primitives::{Block, CompactTarget, Hash256, Header, Tx};

use super::MiningSource;

/// Cached template data for block reconstruction on `SubmitSolution`.
#[derive(Clone)]
pub struct CachedTemplate {
    /// Template ID.
    pub template_id: u64,
    /// Header version.
    pub version: i32,
    /// Previous block hash.
    pub previous_block_hash: [u8; 32],
    /// Compact target bits.
    pub bits: u32,
    /// Candidate transactions (serialized).
    pub transactions: Vec<Vec<u8>>,
    /// Transaction IDs.
    pub txids: Vec<[u8; 32]>,
}

/// Maintains the latest template state for SV2 distribution.
pub struct TemplateHub {
    source: Arc<dyn MiningSource>,
    last_template_id: u64,
    last_prev_hash: Option<[u8; 32]>,
    /// Cache of recent templates for block reconstruction.
    template_cache: Vec<CachedTemplate>,
}

impl TemplateHub {
    /// Creates a new template hub.
    pub fn new(source: Arc<dyn MiningSource>) -> Self {
        Self {
            source,
            last_template_id: 0,
            last_prev_hash: None,
            template_cache: Vec::new(),
        }
    }

    /// Looks up a cached template by ID.
    pub fn get_template(&self, template_id: u64) -> Option<&CachedTemplate> {
        self.template_cache
            .iter()
            .find(|t| t.template_id == template_id)
    }

    /// Submits a block through the mining source.
    pub fn submit_block(
        &self,
        block: Block,
    ) -> Result<crate::BlockValidationResult, super::MiningControlError> {
        self.source.submit_block(block)
    }

    /// Returns the current template as SV2 TDP message bytes.
    pub fn check_for_update(
        &mut self,
    ) -> Result<Option<TemplateUpdate>, super::MiningControlError> {
        let template = self.source.current_template()?;

        let prev_hash: [u8; 32] = *template.candidate.previous_block_hash.as_byte_array();
        let tip_changed = self.last_prev_hash.is_none_or(|h| h != prev_hash);

        self.last_template_id += 1;
        let template_id = self.last_template_id;
        self.last_prev_hash = Some(prev_hash);

        let txids: Vec<[u8; 32]> = template
            .candidate
            .transactions
            .iter()
            .map(|tx| *tx.txid.as_bytes())
            .collect();

        // Serialize candidate transactions for block reconstruction
        let transactions: Vec<Vec<u8>> = template
            .candidate
            .transactions
            .iter()
            .map(|tx| consensus_bytes(&*tx.tx))
            .collect();

        // Cache the template for SubmitSolution block reconstruction
        let cached = CachedTemplate {
            template_id,
            version: template.candidate.version,
            previous_block_hash: prev_hash,
            bits: template.candidate.bits.to_consensus(),
            transactions,
            txids: txids.clone(),
        };
        self.template_cache.push(cached);
        if self.template_cache.len() > 16 {
            self.template_cache.remove(0);
        }

        let coinbase_prefix = coinbase_prefix(template.candidate.height);
        let n_bits = template.candidate.bits.to_consensus();
        let target = target_from_bits(n_bits);

        // Build SetNewPrevHash message bytes
        let mut prev_hash_msg = Vec::with_capacity(49);
        prev_hash_msg.push(0x72); // MESSAGE_TYPE_SET_NEW_PREV_HASH
        prev_hash_msg.extend_from_slice(&template_id.to_le_bytes());
        prev_hash_msg.extend_from_slice(&prev_hash);
        prev_hash_msg.extend_from_slice(&template.candidate.current_time.to_le_bytes());
        prev_hash_msg.extend_from_slice(&n_bits.to_le_bytes());
        prev_hash_msg.extend_from_slice(&target);
        prev_hash_msg.extend_from_slice(&template.candidate.height.to_le_bytes());

        // Build NewTemplate message bytes
        let mut new_template_msg = Vec::with_capacity(256);
        new_template_msg.push(0x71); // MESSAGE_TYPE_NEW_TEMPLATE
        new_template_msg.extend_from_slice(&template_id.to_le_bytes());
        new_template_msg.push(u8::from(tip_changed));
        new_template_msg.extend_from_slice(
            &u32::try_from(template.candidate.version)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        new_template_msg.extend_from_slice(&template.candidate.current_time.to_le_bytes());
        new_template_msg.extend_from_slice(&n_bits.to_le_bytes());
        new_template_msg.push(u8::try_from(coinbase_prefix.len()).unwrap_or(0));
        new_template_msg.extend_from_slice(&coinbase_prefix);
        new_template_msg.extend_from_slice(&2u32.to_le_bytes()); // coinbase_tx_version
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // coinbase_prefix_location
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_input_sequence
        new_template_msg.extend_from_slice(&0u64.to_le_bytes()); // coinbase_tx_value_remaining
        new_template_msg.push(0u8); // coinbase_tx_outputs_count
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_locktime
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // merkle_path len
        new_template_msg.extend_from_slice(&u32::try_from(txids.len()).unwrap_or(0).to_le_bytes());
        for txid in &txids {
            new_template_msg.extend_from_slice(txid);
        }

        Ok(Some(TemplateUpdate {
            new_template: new_template_msg,
            set_new_prev_hash: prev_hash_msg,
            template_id,
            height: template.candidate.height,
            txids,
        }))
    }

    /// Reconstructs a full block from a cached template and a solution.
    pub fn reconstruct_block(
        &self,
        template_id: u64,
        _version: u32,
        header_timestamp: u32,
        nonce: u32,
        coinbase_tx: &[u8],
    ) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
        let cached = self
            .get_template(template_id)
            .ok_or_else(|| format!("template {template_id} not found"))?;

        // Deserialize the coinbase transaction
        let coinbase: Tx =
            deserialize(coinbase_tx).map_err(|e| format!("invalid coinbase tx: {e}"))?;

        // Build the header
        let header = Header {
            version: cached.version,
            prev_blockhash: bitcoin_rs_primitives::BlockHash::from(Hash256::from_le_bytes(
                &cached.previous_block_hash,
            )),
            merkle_root: compute_merkle_root(coinbase_tx, &cached.transactions),
            time: header_timestamp,
            bits: CompactTarget::from_consensus(cached.bits),
            nonce,
        };

        // Build the block
        let txs = {
            let mut txs = vec![coinbase];
            for tx_bytes in &cached.transactions {
                let tx: Tx =
                    deserialize(tx_bytes).map_err(|e| format!("invalid candidate tx: {e}"))?;
                txs.push(tx);
            }
            txs
        };

        Ok(Block { header, txs })
    }
}

/// Computes the merkle root from the coinbase and candidate transactions.
#[allow(clippy::unwrap_used)]
fn compute_merkle_root(coinbase_tx: &[u8], candidate_txs: &[Vec<u8>]) -> Hash256 {
    let coinbase_hash = sha256d::Hash::hash(coinbase_tx);

    if candidate_txs.is_empty() {
        // Single transaction: merkle root is the tx hash doubled
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&coinbase_hash[..32]);
        combined.extend_from_slice(&coinbase_hash[..32]);
        return Hash256::from_le_bytes(&sha256d::Hash::hash(&combined)[..32].try_into().unwrap());
    }

    // Build the merkle tree
    let mut hashes: Vec<[u8; 32]> = vec![coinbase_hash[..32].try_into().unwrap()];
    for tx_bytes in candidate_txs {
        hashes.push(sha256d::Hash::hash(tx_bytes)[..32].try_into().unwrap());
    }

    // Duplicate the last hash if odd number of transactions
    if !hashes.len().is_multiple_of(2) {
        hashes.push(*hashes.last().unwrap());
    }

    // Compute pairwise hashes until one remains
    while hashes.len() > 1 {
        let mut new_hashes = Vec::with_capacity(hashes.len() / 2);
        for pair in hashes.chunks(2) {
            let combined = [pair[0], pair[1]].concat();
            new_hashes.push(sha256d::Hash::hash(&combined)[..32].try_into().unwrap());
        }
        hashes = new_hashes;
    }

    Hash256::from_le_bytes(&hashes[0])
}

/// A template update to send to connected pools.
pub struct TemplateUpdate {
    /// Raw `NewTemplate` message bytes.
    pub new_template: Vec<u8>,
    /// Raw `SetNewPrevHash` message bytes.
    pub set_new_prev_hash: Vec<u8>,
    /// Template ID.
    pub template_id: u64,
    /// Block height.
    pub height: u32,
    /// Candidate transaction IDs.
    pub txids: Vec<[u8; 32]>,
}

/// Builds a BIP34 coinbase prefix (height push).
#[allow(clippy::as_conversions)]
fn coinbase_prefix(height: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut h = height;
    while h > 0 {
        bytes.push((h & 0xff) as u8);
        h >>= 8;
    }
    let mut prefix = Vec::with_capacity(1 + bytes.len());
    prefix.push(u8::try_from(bytes.len()).unwrap_or(0));
    prefix.extend_from_slice(&bytes);
    prefix
}

/// Converts compact bits to a 256-bit target.
#[allow(clippy::as_conversions)]
fn target_from_bits(bits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];
    let exponent = ((bits >> 24) & 0xff) as usize;
    let mantissa = bits & 0x00ff_ffff;
    if exponent <= 3 {
        let m = mantissa >> (8 * (3 - exponent));
        target[31] = (m & 0xff) as u8;
        if m > 0xff {
            target[30] = ((m >> 8) & 0xff) as u8;
        }
    } else if exponent <= 33 {
        let pos = 32 - exponent + 2;
        if pos < 32 {
            target[pos] = ((mantissa >> 16) & 0xff) as u8;
        }
        if pos + 1 < 32 {
            target[pos + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if pos + 2 < 32 {
            target[pos + 2] = (mantissa & 0xff) as u8;
        }
    }
    target
}
