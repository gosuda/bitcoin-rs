//! Mining control protocol projection over the node-owned coordinator.

use super::MiningCoordinator;
use super::estimate_network_hashps;
use super::hash_ps_at;
use super::hex_decode;
use super::long_poll::parse_long_poll_id;
use bitcoin_rs_mining::BlockTemplateMode;
use bitcoin_rs_mining::BlockTemplateRequest;
use bitcoin_rs_mining::BlockTemplateResult;
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::GenerateRequest;
use bitcoin_rs_mining::GeneratedBlock;
use bitcoin_rs_mining::MiningChainContext;
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::MiningInfo;
use bitcoin_rs_mining::SignetMiningInfo;
use bitcoin_rs_mining::difficulty_for_bits;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;
use compact_str::CompactString;

impl MiningCoordinator {
    pub(super) fn mining_info_snapshot(&self) -> Result<MiningInfo, MiningControlError> {
        let tip = self.applied_tip.load_full();
        let blocks = tip.as_ref().map_or(0, |tip| tip.height);
        let (bits, difficulty, next_bits, next_difficulty, network_hashes_per_second) =
            match tip.as_ref() {
                Some(tip) => {
                    let tree = self.block_tree.read();
                    let tip_bits =
                        tree.node(tip.tip_id)
                            .map(|node| node.header.bits)
                            .map_err(|error| {
                                MiningControlError::Failed(CompactString::from(error.to_string()))
                            })?;
                    let current_time = Self::current_time_secs().max(1);
                    let next =
                        MiningChainContext::resolve(&tree, self.network, tip.tip_id, current_time)
                            .map_err(|error| {
                                MiningControlError::Failed(CompactString::from(error.to_string()))
                            })?;
                    let rate = estimate_network_hashps(&tree, Some(tip.tip_id), 120, self.network);
                    (
                        tip_bits,
                        difficulty_for_bits(tip_bits),
                        next.bits,
                        difficulty_for_bits(next.bits),
                        rate,
                    )
                }
                None => (
                    CompactTarget::from_consensus(0),
                    0.0,
                    CompactTarget::from_consensus(0),
                    0.0,
                    0.0,
                ),
            };
        let (pooled_transactions, minimum_fee_rate) = {
            let mempool = self.mempool.read();
            (
                u64::try_from(mempool.len()).unwrap_or(u64::MAX),
                mempool.min_relay_fee_sat_per_kvb(),
            )
        };
        let last_candidate = self.state.lock().last_candidate;
        Ok(MiningInfo {
            blocks,
            last_candidate,
            bits,
            difficulty,
            network_hashes_per_second,
            pooled_transactions,
            network: self.network,
            next_bits,
            next_difficulty,
            minimum_fee_rate,
            signet: signet_info(self.network),
            warnings: crate::metrics::node_warnings()
                .messages()
                .into_iter()
                .map(CompactString::from)
                .collect(),
        })
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
            BlockTemplateMode::Template => {
                let waited = if let Some(long_poll_id) = request.long_poll_id.as_deref() {
                    let waited = parse_long_poll_id(long_poll_id).ok_or_else(|| {
                        MiningControlError::InvalidRequest(CompactString::from(
                            "longpollid is malformed",
                        ))
                    })?;
                    let live = {
                        let mut state = self.state.lock();
                        self.ensure_published(&mut state)
                    };
                    if live == waited {
                        self.wait_for_generation_change(waited)?;
                    }
                    Some(waited)
                } else {
                    None
                };
                if self.applied_tip.load_full().is_none() {
                    return Err(MiningControlError::Unavailable(CompactString::from(
                        "applied tip is not available",
                    )));
                }
                let candidate = self.live_candidate()?;
                let submit_old =
                    waited.map(|waited| candidate.previous_block_hash == waited.tip_hash);
                let (version_bits_available, version_bits_required) =
                    self.version_bits_for(&candidate);
                let template = Self::template_from_candidate(
                    self.network,
                    candidate,
                    &request,
                    submit_old,
                    version_bits_available,
                    version_bits_required,
                );
                Ok(BlockTemplateResult::Template(template))
            }
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

    fn submit_block(&self, block: Block) -> Result<BlockValidationResult, MiningControlError> {
        self.submit(&block)
    }

    fn submit_header(&self, header: Header) -> Result<(), MiningControlError> {
        self.accept_submitted_header(header)
    }

    fn publish_generation(&self) {
        Self::publish_generation(self);
    }

    fn generate(
        &self,
        request: GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        self.generate_blocks(&request)
    }
}

pub(super) fn signet_info(network: Network) -> Option<SignetMiningInfo> {
    const DEFAULT_SIGNET_CHALLENGE: &str = concat!(
        "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430",
        "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
    );

    if network != Network::Signet {
        return None;
    }
    let challenge = hex_decode(DEFAULT_SIGNET_CHALLENGE)
        .unwrap_or_else(|| panic!("Bitcoin Core's default Signet challenge is invalid hex"));
    Some(SignetMiningInfo { challenge })
}
