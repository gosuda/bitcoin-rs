//! Mining control protocol projection over the node-owned coordinator.

use super::MiningCoordinator;
use super::estimate_network_hashps;
use super::hash_ps_at;
use bitcoin_rs_mining::BlockTemplateMode;
use bitcoin_rs_mining::BlockTemplateRequest;
use bitcoin_rs_mining::BlockTemplateResult;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::GenerateRequest;
use bitcoin_rs_mining::GeneratedBlock;
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::MiningInfo;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Header;
use compact_str::CompactString;

impl MiningCoordinator {
    pub(super) fn mining_info_snapshot(&self) -> Result<MiningInfo, MiningControlError> {
        let network_hashes_per_second = {
            let tree = self.block_tree.read();
            let tip = self.applied_tip.load_full();
            tip.as_ref().map_or(0.0, |tip| {
                estimate_network_hashps(&tree, Some(tip.tip_id), 120, self.network)
            })
        };
        let warnings = crate::metrics::node_warnings()
            .messages()
            .into_iter()
            .map(CompactString::from)
            .collect();
        self.service
            .mining_info(network_hashes_per_second, warnings)
    }
}

impl MiningControl for MiningCoordinator {
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        match request.mode {
            BlockTemplateMode::Proposal(block) => {
                Ok(BlockTemplateResult::Proposal(self.propose(&block)))
            }
            BlockTemplateMode::Template => Ok(BlockTemplateResult::Template(
                self.service
                    .get_block_template(request.long_poll_id.as_deref())?,
            )),
        }
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        self.mining_info_snapshot()
    }

    fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError> {
        if lookup < -1 || lookup == 0 {
            return Err(MiningControlError::InvalidRequest(CompactString::from(
                "Invalid nblocks. Must be a positive number or -1.",
            )));
        }
        let tree = self.block_tree.read();
        let tip = self.applied_tip.load_full();
        hash_ps_at(&tree, tip.as_deref(), lookup, height, self.network)
    }

    fn submit_block(&self, mut block: Block) -> Result<BlockValidationResult, MiningControlError> {
        self.fill_uncommitted_witness(&mut block);
        self.submit(&block)
    }

    fn submit_header(&self, header: Header) -> Result<(), MiningControlError> {
        self.accept_submitted_header(header)
    }

    fn publish_generation(&self) {
        self.service.publish_generation();
    }

    fn generate(
        &self,
        request: GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        self.generate_blocks(&request)
    }
}
