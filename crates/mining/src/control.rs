//! Node-facing mining contract: one template model, one control trait.
//!
//! RPC projects these types onto BIP22/BIP23 JSON. The node implements
//! [`MiningControl`]. Caching and long-poll live in this crate's
//! [`MiningService`](crate::MiningService); proposal validation and solved-block
//! submission stay on the node's authoritative apply path.

use std::sync::Arc;
#[cfg(any(test, feature = "test-seam"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::vec::Vec;

use bitcoin_rs_mempool::SnapshotEntry;
#[cfg(any(test, feature = "test-seam"))]
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::{Block, BlockHash, CompactTarget, Header, Network, Tx, Txid};
use compact_str::CompactString;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::Mutex;

use crate::Candidate;

/// One capability advertised by a `getblocktemplate` caller.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MiningCapability(CompactString);

impl MiningCapability {
    /// Preserves a BIP22/BIP23 capability name without coupling it to JSON.
    #[must_use]
    pub fn new(name: impl Into<CompactString>) -> Self {
        Self(name.into())
    }

    /// Returns the capability name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One versionbits rule named by a template request or response.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MiningRule(CompactString);

impl MiningRule {
    /// Preserves a deployment rule name without coupling it to its wire encoding.
    #[must_use]
    pub fn new(name: impl Into<CompactString>) -> Self {
        Self(name.into())
    }

    /// Returns the deployment rule name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Operation selected by a BIP22/BIP23 block-template request.
#[derive(Clone, Debug)]
pub enum BlockTemplateMode {
    /// Assemble or wait for a mining candidate.
    Template,
    /// Dry-run validation of a caller-provided block.
    Proposal(Block),
}

/// Transport-neutral input to [`MiningControl::get_block_template`].
#[derive(Clone, Debug)]
pub struct BlockTemplateRequest {
    /// Template assembly or proposal validation.
    pub mode: BlockTemplateMode,
    /// Advisory BIP22/BIP23 capabilities advertised by the caller.
    pub capabilities: Vec<MiningCapability>,
    /// Versionbits rules the caller can enforce.
    pub rules: Vec<MiningRule>,
    /// Opaque BIP22/BIP23 generation to wait beyond in template mode.
    pub long_poll_id: Option<CompactString>,
}

/// One versionbits deployment available for caller negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableMiningRule {
    /// Deployment rule name.
    pub rule: MiningRule,
    /// Header-version bit assigned to the deployment.
    pub bit: u8,
}

/// Candidate fields a template consumer may change before solving.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateMutation {
    /// Header time may advance within the consensus bounds.
    Time,
    /// Transactions may be added, removed, or reordered consistently.
    Transactions,
    /// The previous-block field may be replaced after a tip change.
    PreviousBlock,
}

/// Semantic template assembled by the node-owned mining coordinator.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// Immutable candidate generation and transaction facts.
    pub candidate: Arc<Candidate>,
    /// Active rules a solver must enforce.
    pub rules: Vec<MiningRule>,
    /// Optional deployments available for versionbits negotiation.
    pub version_bits_available: Vec<AvailableMiningRule>,
    /// Header-version bits the solver must preserve.
    ///
    /// Core v31 `getblocktemplate` always reports `vbrequired` as 0.
    pub version_bits_required: u32,
    /// Capabilities implemented by this template producer.
    pub capabilities: Vec<MiningCapability>,
    /// Candidate fields the solver may mutate.
    pub mutable: Vec<TemplateMutation>,
    /// Whether work derived from the request's prior generation remains valid.
    ///
    /// Present after a long-poll wait. `true` means the previous template's
    /// parent is still the applied tip (BIP23 `submitold`).
    pub submit_old: Option<bool>,
    /// Signet challenge, present only on signet.
    pub signet: Option<SignetMiningInfo>,
    /// Opaque server work identity when the producer requires one on submission.
    pub work_id: Option<CompactString>,
}

/// BIP22 validation vocabulary shared by proposal and solved-block submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockValidationResult {
    /// The block is valid and, for submission, was synchronously applied.
    Accepted,
    /// The block's body was already connected (scripts-valid), including after a later reorg.
    Duplicate,
    /// The block duplicates one already known to be invalid.
    ///
    /// GBT proposal returns this after `LookupBlockIndex`. `submitblock` does
    /// not short-circuit on an invalid header; Core v31 `ProcessNewBlock` runs.
    DuplicateInvalid,
    /// The block duplicates one whose validity is not yet conclusive.
    ///
    /// GBT proposal returns this for a header-only tree entry. `submitblock`
    /// still applies the body.
    DuplicateInconclusive,
    /// Validation could not reach a conclusive result.
    Inconclusive,
    /// Consensus or contextual validation rejected the block.
    Rejected(CompactString),
}

/// Semantic result of template assembly or proposal validation.
#[derive(Clone, Debug)]
pub enum BlockTemplateResult {
    /// A candidate ready for projection into a BIP22 template.
    Template(BlockTemplate),
    /// Dry-run proposal validation, with no chain or mempool mutation.
    Proposal(BlockValidationResult),
}

/// Facts from the most recently assembled candidate, when one exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastCandidateInfo {
    /// Total candidate weight.
    pub weight: u64,
    /// Number of transactions including the coinbase.
    pub transactions: u64,
}

/// Signet-specific mining configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignetMiningInfo {
    /// Consensus signet challenge script.
    pub challenge: Vec<u8>,
}

/// Authoritative semantic state returned by [`MiningControl::mining_info`].
#[derive(Clone, Debug, PartialEq)]
pub struct MiningInfo {
    /// Current applied-chain height.
    pub blocks: u32,
    /// Most recently assembled candidate facts.
    pub last_candidate: Option<LastCandidateInfo>,
    /// Compact target bits of the applied tip.
    pub bits: CompactTarget,
    /// Difficulty represented by `bits`.
    pub difficulty: f64,
    /// Estimated network hashes per second.
    pub network_hashes_per_second: f64,
    /// Transactions currently available in the mempool.
    pub pooled_transactions: u64,
    /// Active consensus network.
    pub network: Network,
    /// Compact target bits for the next candidate.
    pub next_bits: CompactTarget,
    /// Difficulty represented by `next_bits`.
    pub next_difficulty: f64,
    /// Configured minimum mining feerate in satoshis per kvB.
    pub minimum_fee_rate: u64,
    /// Signet mining data, absent on other networks.
    pub signet: Option<SignetMiningInfo>,
    /// Active node warnings.
    pub warnings: Vec<CompactString>,
}

/// Failure to execute a node-owned mining operation.
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
    ///
    /// RPC projects this as Bitcoin Core `RPC_VERIFY_ERROR` (-25).
    #[error("{0}")]
    Rejected(CompactString),
}

/// One `generateblock` body transaction: a mempool txid or a decoded raw tx.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerateTx {
    /// Include this currently-pooled transaction, looked up by txid.
    Mempool(Txid),
    /// Include this transaction resolved from the mempool at parse time.
    ResolvedMempool(SnapshotEntry),
    /// Include this decoded raw transaction even if it is not in the mempool.
    Raw(Tx),
}

/// How [`MiningControl::generate`] selects non-coinbase transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenerateSelection {
    /// Full mempool package selection (`generatetoaddress`).
    Mempool,
    /// These transactions, in this order. Empty is coinbase-only.
    Ordered(Vec<GenerateTx>),
}

/// Request to assemble, solve, and optionally submit one or more blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateRequest {
    /// Coinbase `scriptPubKey`.
    pub payout: Vec<u8>,
    /// Number of sequential blocks to produce.
    pub count: u32,
    /// Nonce search budget per block. Core default is `1_000_000`.
    pub max_tries: u64,
    /// Transaction source for each assembled candidate.
    pub selection: GenerateSelection,
    /// When false, solve but do not apply. Requires `count == 1`.
    pub submit: bool,
}

/// One solved block produced by [`MiningControl::generate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedBlock {
    /// Header hash of the solved block.
    pub hash: BlockHash,
    /// Consensus serialization as lowercase hex, for `generateblock` `submit=false`.
    pub hex: String,
}

impl GenerateRequest {
    /// Bitcoin Core's default `maxtries` for `generatetoaddress` / `generateblock`.
    pub const DEFAULT_MAX_TRIES: u64 = 1_000_000;
}

/// Node-owned control plane for candidate lifecycle and solved-block submission.
pub trait MiningControl: Send + Sync {
    /// Assembles or long-polls a template, or dry-validates a proposal.
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError>;

    /// Captures one coherent mining-state report.
    fn mining_info(&self) -> Result<MiningInfo, MiningControlError>;

    /// Estimated hashes per second over `lookup` blocks ending at `height`.
    ///
    /// `lookup` must be a positive block count or `-1` (since the last
    /// difficulty retarget). `height` must be `-1` (applied tip) or an existing
    /// applied-chain height. Matches Bitcoin Core's `getnetworkhashps`.
    fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError>;

    /// Synchronously validates and applies a solved block.
    fn submit_block(&self, block: Block) -> Result<BlockValidationResult, MiningControlError>;

    /// Applies a decoded block with its exact consensus serialization.
    ///
    /// Controls that do not preserve wire bytes fall back to [`Self::submit_block`].
    fn submit_block_with_bytes(
        &self,
        block: Block,
        raw: Vec<u8>,
    ) -> Result<BlockValidationResult, MiningControlError> {
        let _ = raw;
        self.submit_block(block)
    }

    /// Admits a header through the same tree path as inbound P2P headers.
    ///
    /// The previous header must already be in the tree. Duplicates succeed.
    /// Failures are [`MiningControlError::Rejected`] with Core reject reasons.
    fn submit_header(&self, header: Header) -> Result<(), MiningControlError>;

    /// Publishes a completed authoritative mutation to template waiters.
    fn publish_generation(&self);

    /// Assembles, solves, and optionally submits `request.count` blocks paying `request.payout`.
    ///
    /// Each submitted block's commit point is the ordinary apply path (`ARCH-07`):
    /// validation, persistence, and applied-tip publication complete before the
    /// next block is assembled. Durability, crash recovery, and visibility match
    /// [`Self::submit_block`]. An error after *N* successful submissions leaves
    /// those *N* blocks durable and visible; the failed block and any remaining
    /// count are not applied. Unsubmitted blocks (`submit = false`) are
    /// dry-validated through the same pre-write gates and are not persisted.
    /// Callers own retry and any compensation for partial progress. Failures are
    /// classified as [`MiningControlError`]: `InvalidRequest` is not retriable
    /// without changing the request; `Unavailable` and `Failed` may be retried
    /// by the caller after inspecting the applied tip.
    fn generate(&self, request: GenerateRequest)
    -> Result<Vec<GeneratedBlock>, MiningControlError>;
}

/// In-memory [`MiningControl`] double for tests in any crate.
///
/// Compile gate: available inside this crate's unit tests and, through the
/// `test-seam` feature, to downstream integration tests. Production code
/// never links it.
///
/// PRE: construction requires no external state and does not block.
///
/// POST: each result-returning operation checks [`Self::fail`] first; the
/// request captures and call counters have the semantics of the recording
/// fakes this type replaces; publication counters record every wake.
///
/// INVARIANT: an armed failure short-circuits every result-returning method,
/// including `submit_header`, before canned state is read; both wake counters
/// remain independently observable.
#[cfg(any(test, feature = "test-seam"))]
pub struct FakeMiningControl {
    /// Template returned by template-mode `get_block_template` calls.
    pub template: Mutex<Option<BlockTemplate>>,
    /// Proposal-mode `get_block_template` result.
    pub proposal: Mutex<BlockValidationResult>,
    /// `submit_block` result.
    pub submit: Mutex<BlockValidationResult>,
    /// `mining_info` and `network_hash_ps` state source.
    pub info: Mutex<MiningInfo>,
    /// Most recent template-mode or proposal request.
    pub last_request: Mutex<Option<BlockTemplateRequest>>,
    /// Most recent `network_hash_ps` arguments.
    pub last_hash_ps: Mutex<Option<(i64, i64)>>,
    /// Most recent `generate` request.
    pub last_generate: Mutex<Option<GenerateRequest>>,
    /// `get_block_template` call count.
    pub template_calls: AtomicUsize,
    /// `submit_block` call count.
    pub submit_calls: AtomicUsize,
    /// `mining_info` call count.
    pub info_calls: AtomicUsize,
    /// Armed failure returned by every result-returning operation.
    pub fail: Mutex<Option<MiningControlError>>,
    /// `publish_generation` wake count.
    pub publishes: AtomicU64,
    /// Every `publish_generation_from` sequence, in call order.
    pub published_from: Mutex<Vec<u64>>,
}

#[cfg(any(test, feature = "test-seam"))]
impl FakeMiningControl {
    /// Builds a control that fails every result-returning operation with
    /// [`MiningControlError::Unavailable`] and counts publication wakes.
    ///
    /// The placeholder mining info is never returned through the control:
    /// an armed failure short-circuits before it can be read.
    pub fn unavailable(reason: &str) -> Arc<Self> {
        Arc::new(Self {
            template: Mutex::new(None),
            proposal: Mutex::new(BlockValidationResult::Accepted),
            submit: Mutex::new(BlockValidationResult::Accepted),
            info: Mutex::new(placeholder_mining_info()),
            last_request: Mutex::new(None),
            last_hash_ps: Mutex::new(None),
            last_generate: Mutex::new(None),
            template_calls: AtomicUsize::new(0),
            submit_calls: AtomicUsize::new(0),
            info_calls: AtomicUsize::new(0),
            fail: Mutex::new(Some(MiningControlError::Unavailable(CompactString::from(
                reason,
            )))),
            publishes: AtomicU64::new(0),
            published_from: Mutex::new(Vec::new()),
        })
    }

    /// Builds a control that answers template requests with `template` and
    /// mining-info reads with `info`. Submissions and proposals are accepted
    /// by default; no failure is armed and every counter starts at zero.
    pub fn with_template(template: BlockTemplate, info: MiningInfo) -> Arc<Self> {
        Arc::new(Self {
            template: Mutex::new(Some(template)),
            proposal: Mutex::new(BlockValidationResult::Accepted),
            submit: Mutex::new(BlockValidationResult::Accepted),
            info: Mutex::new(info),
            last_request: Mutex::new(None),
            last_hash_ps: Mutex::new(None),
            last_generate: Mutex::new(None),
            template_calls: AtomicUsize::new(0),
            submit_calls: AtomicUsize::new(0),
            info_calls: AtomicUsize::new(0),
            fail: Mutex::new(None),
            publishes: AtomicU64::new(0),
            published_from: Mutex::new(Vec::new()),
        })
    }

    /// Loads the publication wake count.
    pub fn publish_count(&self) -> u64 {
        self.publishes.load(Ordering::Relaxed)
    }

    /// Clones the armed failure, if any, for the caller's short-circuit check.
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

    fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
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
}

#[cfg(any(test, feature = "test-seam"))]
fn placeholder_mining_info() -> MiningInfo {
    MiningInfo {
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
