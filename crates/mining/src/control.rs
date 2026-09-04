//! Node-facing mining contract: one template model, one control trait.
//!
//! RPC projects these types onto BIP22/BIP23 JSON. The node implements
//! [`MiningControl`]. This crate does not cache, long-poll, or submit.

use std::sync::Arc;
use std::vec::Vec;

use bitcoin_rs_primitives::{Block, BlockHash, Header, Network, Tx, Txid};
use compact_str::CompactString;

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
    /// See `API-16` in `docs/contracts/external-api.md`.
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
}

/// BIP22 validation vocabulary shared by proposal and solved-block submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockValidationResult {
    /// The block is valid and, for submission, was synchronously applied.
    Accepted,
    /// The block was already accepted (its body is on the applied chain).
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
    pub bits: u32,
    /// Difficulty represented by `bits`.
    pub difficulty: f64,
    /// Estimated network hashes per second.
    pub network_hashes_per_second: f64,
    /// Transactions currently available in the mempool.
    pub pooled_transactions: u64,
    /// Active consensus network.
    pub network: Network,
    /// Compact target bits for the next candidate.
    pub next_bits: u32,
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

/// Returns the f64 difficulty for `bits` using Bitcoin Core's calculation.
#[must_use]
pub fn difficulty_for_bits(consensus_bits: u32) -> f64 {
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
        let difficulty = difficulty_for_bits(0x1d00_ffff);
        assert!(
            (difficulty - 1.0).abs() < f64::EPSILON,
            "0x1d00ffff must be difficulty 1, got {difficulty}"
        );
    }
}
