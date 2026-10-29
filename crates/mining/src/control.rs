//! Node-facing mining contract: one template model, one control trait.

use std::sync::Arc;
#[cfg(any(test, feature = "test-seam"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bitcoin_rs_mempool::SnapshotEntry;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::{
    Block, BlockHash, BlockPayload, CompactTarget, Header, Network, Tx, Txid,
};
use compact_str::CompactString;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::Mutex;

use crate::{Candidate, CoinbaseBudget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningCapability(CompactString);

impl MiningCapability {
    #[must_use]
    pub fn new(name: impl Into<CompactString>) -> Self {
        Self(name.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningRule(CompactString);

impl MiningRule {
    #[must_use]
    pub fn new(name: impl Into<CompactString>) -> Self {
        Self(name.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug)]
pub enum BlockTemplateMode {
    Template,
    Proposal(Block),
}

/// Transport-neutral input to [`MiningControl::get_block_template`].
#[derive(Clone, Debug)]
pub struct BlockTemplateRequest {
    pub mode: BlockTemplateMode,
    pub capabilities: Vec<MiningCapability>,
    pub rules: Vec<MiningRule>,
    pub long_poll_id: Option<CompactString>,
    pub coinbase_budget: Option<CoinbaseBudget>,
}

#[derive(Clone, Debug)]
pub struct AvailableMiningRule {
    pub rule: MiningRule,
    pub bit: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum TemplateMutation {
    Time,
    Transactions,
    PreviousBlock,
}

#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub candidate: Arc<Candidate>,
    pub rules: Vec<MiningRule>,
    pub version_bits_available: Vec<AvailableMiningRule>,
    pub version_bits_required: u32,
    pub capabilities: Vec<MiningCapability>,
    pub mutable: Vec<TemplateMutation>,
    pub submit_old: Option<bool>,
    pub signet: Option<SignetMiningInfo>,
}

/// BIP22 validation vocabulary shared by proposal and solved-block submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockValidationResult {
    Accepted,
    Duplicate,
    DuplicateInvalid,
    DuplicateInconclusive,
    Inconclusive,
    Rejected(CompactString),
}

#[derive(Debug)]
pub enum BlockTemplateResult {
    Template(BlockTemplate),
    Proposal(BlockValidationResult),
}

#[derive(Clone, Copy, Debug)]
pub struct LastCandidateInfo {
    pub weight: u64,
    pub transactions: u64,
}

#[derive(Clone, Debug)]
pub struct SignetMiningInfo {
    pub challenge: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MiningInfo {
    pub blocks: u32,
    pub last_candidate: Option<LastCandidateInfo>,
    pub bits: CompactTarget,
    pub difficulty: f64,
    pub network_hashes_per_second: f64,
    pub pooled_transactions: u64,
    pub network: Network,
    pub next_bits: CompactTarget,
    pub next_difficulty: f64,
    pub minimum_fee_rate: u64,
    pub signet: Option<SignetMiningInfo>,
    pub warnings: Vec<CompactString>,
}

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum MiningControlError {
    /// The semantic request is internally inconsistent or unsupported.
    #[error("{0}")]
    InvalidRequest(CompactString),
    /// Authoritative mining state is not currently available.
    #[error("{0}")]
    Unavailable(CompactString),
    /// Candidate construction, validation, or application failed operationally.
    #[error("{0}")]
    Failed(CompactString),
    /// Consensus or contextual verification rejected the input.
    /// RPC projects this as Bitcoin Core `RPC_VERIFY_ERROR` (-25).
    #[error("{0}")]
    Rejected(CompactString),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerateTx {
    Mempool(Txid),
    ResolvedMempool(SnapshotEntry),
    Raw(Tx),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerateSelection {
    Mempool,
    Ordered(Vec<GenerateTx>),
}

#[derive(Clone, Debug)]
pub struct GenerateRequest {
    pub payout: Vec<u8>,
    pub count: u32,
    pub max_tries: u64,
    pub selection: GenerateSelection,
    pub submit: bool,
}

#[derive(Clone, Debug)]
pub struct GeneratedBlock {
    pub hash: BlockHash,
    pub hex: String,
}

impl GenerateRequest {
    pub const DEFAULT_MAX_TRIES: u64 = 1_000_000;
}

pub trait MiningControl: Send + Sync {
    /// Assembles or long-polls a template, or dry-validates a proposal.
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError>;

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError>;

    /// `lookup` must be a positive block count or `-1` (since the last difficulty
    /// retarget).
    ///
    /// `height` must be `-1` (applied tip) or an existing applied-chain height. Matches
    /// Bitcoin Core's `getnetworkhashps`.
    fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError>;

    fn submit_block(
        &self,
        payload: BlockPayload,
    ) -> Result<BlockValidationResult, MiningControlError>;

    /// Admits a header through the same tree path as inbound P2P headers.
    ///
    /// The previous header must already be in the tree. Duplicates succeed. Failures
    /// are [`MiningControlError::Rejected`] with Core reject reasons.
    fn submit_header(&self, header: Header) -> Result<(), MiningControlError>;

    fn publish_generation(&self);

    fn publish_fee_delta_generation(&self, fee_delta_sequence: u64);

    fn generate(&self, request: GenerateRequest)
    -> Result<Vec<GeneratedBlock>, MiningControlError>;
}

#[cfg(any(test, feature = "test-seam"))]
pub struct FakeMiningControl {
    template: Mutex<Option<BlockTemplate>>,
    pub proposal: Mutex<BlockValidationResult>,
    pub submit: Mutex<BlockValidationResult>,
    pub info: Mutex<MiningInfo>,
    pub last_request: Mutex<Option<BlockTemplateRequest>>,
    pub last_hash_ps: Mutex<Option<(i64, i64)>>,
    pub last_generate: Mutex<Option<GenerateRequest>>,
    pub template_calls: AtomicUsize,
    pub submit_calls: AtomicUsize,
    pub info_calls: AtomicUsize,
    pub fail: Mutex<Option<MiningControlError>>,
    publishes: AtomicU64,
    pub published_from: Mutex<Vec<u64>>,
    pub published_fee_from: Mutex<Vec<u64>>,
    pub staged_tips: Mutex<Vec<Hash256>>,
    pub published_blocks: Mutex<Vec<Hash256>>,
}

#[cfg(any(test, feature = "test-seam"))]
impl Default for FakeMiningControl {
    fn default() -> Self {
        Self {
            template: Mutex::new(None),
            proposal: Mutex::new(BlockValidationResult::Accepted),
            submit: Mutex::new(BlockValidationResult::Accepted),
            info: Mutex::new(MiningInfo {
                blocks: 0,
                last_candidate: None,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                difficulty: 1.0,
                network_hashes_per_second: 0.0,
                pooled_transactions: 0,
                network: Network::Regtest,
                next_bits: CompactTarget::from_consensus(0x207f_ffff),
                next_difficulty: 1.0,
                minimum_fee_rate: 0,
                signet: None,
                warnings: Vec::new(),
            }),
            last_request: Mutex::new(None),
            last_hash_ps: Mutex::new(None),
            last_generate: Mutex::new(None),
            template_calls: AtomicUsize::new(0),
            submit_calls: AtomicUsize::new(0),
            info_calls: AtomicUsize::new(0),
            fail: Mutex::new(None),
            publishes: AtomicU64::new(0),
            published_from: Mutex::new(Vec::new()),
            published_fee_from: Mutex::new(Vec::new()),
            staged_tips: Mutex::new(Vec::new()),
            published_blocks: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl FakeMiningControl {
    pub fn unavailable(reason: &str) -> Arc<Self> {
        Arc::new(Self {
            fail: Mutex::new(Some(MiningControlError::Unavailable(CompactString::from(
                reason,
            )))),
            ..Self::default()
        })
    }

    pub fn with_template(template: BlockTemplate, info: MiningInfo) -> Arc<Self> {
        Arc::new(Self {
            template: Mutex::new(Some(template)),
            info: Mutex::new(info),
            ..Self::default()
        })
    }

    pub fn publish_count(&self) -> u64 {
        self.publishes.load(Ordering::Relaxed)
    }

    fn armed_failure(&self) -> Option<MiningControlError> {
        self.fail.lock().clone()
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl MiningControl for FakeMiningControl {
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        self.template_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.armed_failure() {
            return Err(error);
        }
        *self.last_request.lock() = Some(request.clone());
        match request.mode {
            BlockTemplateMode::Proposal(_) => {
                Ok(BlockTemplateResult::Proposal(self.proposal.lock().clone()))
            }
            BlockTemplateMode::Template => {
                let mut template = self
                    .template
                    .lock()
                    .clone()
                    .unwrap_or_else(|| panic!("template configured for fake control"));
                if request.long_poll_id.is_some() {
                    template.submit_old = Some(true);
                }
                Ok(BlockTemplateResult::Template(template))
            }
        }
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        self.info_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.armed_failure() {
            return Err(error);
        }
        Ok(self.info.lock().clone())
    }

    fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError> {
        if let Some(error) = self.armed_failure() {
            return Err(error);
        }
        *self.last_hash_ps.lock() = Some((lookup, height));
        Ok(self.info.lock().network_hashes_per_second)
    }

    fn submit_block(
        &self,
        _payload: BlockPayload,
    ) -> Result<BlockValidationResult, MiningControlError> {
        self.submit_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.armed_failure() {
            return Err(error);
        }
        Ok(self.submit.lock().clone())
    }

    fn submit_header(&self, _header: Header) -> Result<(), MiningControlError> {
        if let Some(error) = self.armed_failure() {
            return Err(error);
        }
        Ok(())
    }

    fn publish_generation(&self) {
        self.publishes.fetch_add(1, Ordering::Relaxed);
    }

    fn publish_fee_delta_generation(&self, fee_delta_sequence: u64) {
        self.published_fee_from.lock().push(fee_delta_sequence);
    }

    fn generate(
        &self,
        request: GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        if let Some(error) = self.armed_failure() {
            return Err(error);
        }
        *self.last_generate.lock() = Some(request.clone());
        let hash = BlockHash::from(Hash256::from_le_bytes(&[0xab; 32]));
        Ok(vec![
            GeneratedBlock {
                hash,
                hex: String::from("00"),
            };
            usize::try_from(request.count).unwrap_or(0)
        ])
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl crate::coordinator::MempoolSequenceWake for FakeMiningControl {
    fn publish_generation_from(&self, sequence: u64) {
        self.published_from.lock().push(sequence);
    }

    fn stage_tip(&self, tip: &bitcoin_rs_chain::TipSnapshot, _block: &Block) {
        self.staged_tips.lock().push(tip.hash);
    }

    fn publish_block_generation(
        &self,
        tip_hash: Hash256,
        _removals: &bitcoin_rs_mempool::MutationResult,
    ) {
        self.published_blocks.lock().push(tip_hash);
        self.publish_generation();
    }
}

/// Returns the f64 difficulty for `bits` using Bitcoin Core's calculation.
#[must_use]
pub fn difficulty_for_bits(consensus_bits: CompactTarget) -> f64 {
    let consensus_bits = consensus_bits.to_consensus();
    let mantissa = consensus_bits & 0x00ff_ffff;
    if mantissa == 0 {
        return 0.0;
    }
    let mut shift = (consensus_bits >> 24) & 0xff;
    let mut difficulty = f64::from(0x0000_ffff_u32) / f64::from(mantissa);
    while shift < 29 {
        difficulty *= 256.0;
        shift += 1;
    }
    while shift > 29 {
        difficulty /= 256.0;
        shift -= 1;
    }
    difficulty
}

#[cfg(test)]
mod tests {
    use super::difficulty_for_bits;

    #[test]
    fn difficulty_one_is_the_difficulty_1_target() {
        let difficulty = difficulty_for_bits(bitcoin_rs_primitives::CompactTarget::from_consensus(
            0x1d00_ffff,
        ));
        assert!(
            (difficulty - 1.0).abs() < f64::EPSILON,
            "0x1d00ffff must be difficulty 1, got {difficulty}"
        );
    }
}
