//! Typed mining candidate to SV2 wire projection. Mining policy stays in the node.
use bitcoin_rs_mining::Candidate;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Tx, consensus_bytes, deserialize, encode::double_sha256,
};
use std::sync::Arc;
use stratum_apps::stratum_core::binary_sv2::{B016MOwned, Seq064KOwned, Seq0255Owned, U256Owned};
use stratum_apps::stratum_core::template_distribution_sv2::{
    NewTemplateOwned, SetNewPrevHashOwned, SubmitSolutionOwned,
};

pub struct TemplateState {
    pub id: u64,
    pub candidate: Arc<Candidate>,
    merkle_branch: Vec<[u8; 32]>,
}

impl TemplateState {
    pub fn new(id: u64, candidate: Arc<Candidate>) -> Self {
        let mut level = std::iter::once([0; 32])
            .chain(candidate.transactions.iter().map(|tx| *tx.txid.as_bytes()))
            .collect::<Vec<_>>();
        let mut merkle_branch = Vec::new();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            merkle_branch.push(level[1]);
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
        }
        Self {
            id,
            candidate,
            merkle_branch,
        }
    }

    pub fn new_template_msg(&self) -> Result<NewTemplateOwned, String> {
        let c = &self.candidate;
        // The mining owner constructs payout first, followed by required outputs.
        let outputs = c
            .coinbase
            .outputs
            .iter()
            .skip(1)
            .flat_map(consensus_bytes)
            .collect::<Vec<_>>();
        Ok(NewTemplateOwned {
            template_id: self.id,
            future_template: true,
            version: c.version as u32,
            coinbase_tx_version: c.coinbase.version,
            coinbase_prefix: c.coinbase.inputs[0]
                .script_sig
                .as_bytes()
                .to_vec()
                .try_into()
                .map_err(|e| format!("coinbase prefix: {e:?}"))?,
            coinbase_tx_input_sequence: c.coinbase.inputs[0].sequence.to_consensus(),
            coinbase_tx_value_remaining: c.coinbase_value,
            coinbase_tx_outputs_count: u32::try_from(c.coinbase.outputs.len() - 1)
                .map_err(|e| e.to_string())?,
            coinbase_tx_outputs: outputs
                .try_into()
                .map_err(|e| format!("required outputs: {e:?}"))?,
            coinbase_tx_locktime: c.coinbase.lock_time.to_consensus(),
            merkle_path: Seq0255Owned::new(
                self.merkle_branch.iter().map(U256Owned::from).collect(),
            )
            .map_err(|e| format!("merkle path: {e:?}"))?,
        })
    }

    pub fn set_new_prev_hash_msg(&self) -> SetNewPrevHashOwned {
        use stratum_apps::stratum_core::bitcoin::pow::{CompactTarget, Target};
        let bits = self.candidate.bits.to_consensus();
        SetNewPrevHashOwned {
            template_id: self.id,
            prev_hash: U256Owned::from(*self.candidate.previous_block_hash.as_byte_array()),
            header_timestamp: self.candidate.current_time,
            n_bits: bits,
            target: U256Owned::from(
                Target::from(CompactTarget::from_consensus(bits)).to_le_bytes(),
            ),
        }
    }

    pub fn transaction_data(&self) -> Result<Seq064KOwned<B016MOwned>, String> {
        let txs = self
            .candidate
            .transactions
            .iter()
            .map(|tx| {
                B016MOwned::try_from(consensus_bytes(tx.tx.as_ref()))
                    .map_err(|e| format!("transaction size: {e:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Seq064KOwned::new(txs).map_err(|e| format!("transaction count: {e:?}"))
    }

    pub fn assemble_block(&self, solution: &SubmitSolutionOwned) -> Result<Block, String> {
        if solution.template_id != self.id {
            return Err("foreign template id".into());
        }
        let coinbase =
            deserialize::<Tx>(solution.coinbase_tx.as_ref()).map_err(|e| e.to_string())?;
        let mut root = *coinbase.txid().as_bytes();
        for sibling in &self.merkle_branch {
            root = hash_pair(&root, sibling);
        }
        Ok(Block {
            header: Header {
                version: solution.version as i32,
                prev_blockhash: BlockHash::from(self.candidate.previous_block_hash),
                merkle_root: Hash256::from_le_bytes(&root),
                time: solution.header_timestamp,
                bits: self.candidate.bits,
                nonce: solution.header_nonce,
            },
            txs: std::iter::once(coinbase)
                .chain(
                    self.candidate
                        .transactions
                        .iter()
                        .map(|tx| (*tx.tx).clone()),
                )
                .collect(),
        })
    }
}

fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(a);
    bytes[32..].copy_from_slice(b);
    *double_sha256(&bytes).as_byte_array()
}
