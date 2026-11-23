#![forbid(unsafe_op_in_unsafe_fn)]

mod count;
mod deployment;
pub mod header_sync;
mod ibd;
pub mod node;
mod progress;
#[cfg(feature = "test-seam")]
pub mod regtest_fixture {
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint,
        Script, Sequence, Tx, TxIn, TxOut, Witness,
    };
    use bitcoin_rs_consensus::{block_subsidy, compute_merkle_root};

    use crate::chain::compact_is_met_by;

    pub const REGTEST_BITS: u32 = 0x207f_ffff;

    #[derive(Debug, thiserror::Error)]
    pub enum RegtestFixtureError {
        #[error("test fixture exhausted the header nonce space")]
        NonceExhausted,
        #[error("test fixture block carries no transactions")]
        EmptyMerkleRoot,
    }

    #[must_use]
    pub fn genesis_time() -> u32 {
        Network::Regtest.genesis_block().header.time
    }

    #[expect(
        clippy::expect_used,
        reason = "each expect guards a bound the preceding branch establishes"
    )]
    #[must_use]
    pub fn script_num_push(value: i64) -> Vec<u8> {
        if value == 0 {
            return vec![0x00];
        }
        if value == -1 {
            return vec![0x4f];
        }
        if (1..=16).contains(&value) {
            let small = u8::try_from(value).expect("1..=16 fits a u8");
            return vec![0x50 + small];
        }
        let negative = value < 0;
        let mut magnitude = value.unsigned_abs();
        let mut bytes = Vec::new();
        while magnitude > 0 {
            bytes.push(u8::try_from(magnitude & 0xff).expect("a masked byte is below 256"));
            magnitude >>= 8;
        }
        if let Some(last) = bytes.last_mut() {
            if *last & 0x80 != 0 {
                bytes.push(if negative { 0x80 } else { 0x00 });
            } else if negative {
                *last |= 0x80;
            }
        }
        let mut out = Vec::with_capacity(bytes.len() + 1);
        out.push(
            u8::try_from(bytes.len())
                .expect("an i64 magnitude serializes to at most 9 script-number bytes"),
        );
        out.extend_from_slice(&bytes);
        out
    }

    #[must_use]
    pub fn coinbase(height: u32) -> Tx {
        let mut script_sig = script_num_push(i64::from(height));
        script_sig.extend_from_slice(&script_num_push(0));
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(script_sig),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(block_subsidy(
                    height,
                    Network::Regtest.subsidy_halving_interval(),
                )),
                script_pubkey: Script::new(),
            }],
        }
    }

    #[must_use]
    pub fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
        let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
        compute_merkle_root(&mut leaves).map(|root| Hash256::from_le_bytes(&root))
    }

    pub fn mine_header_to_declared_target(header: &mut Header) -> Result<(), RegtestFixtureError> {
        while !compact_is_met_by(header.bits, Hash256::from(header.compute_hash())) {
            header.nonce = header
                .nonce
                .checked_add(1)
                .ok_or(RegtestFixtureError::NonceExhausted)?;
        }
        Ok(())
    }

    pub fn mine_block_to_declared_target(block: &mut Block) -> Result<(), RegtestFixtureError> {
        mine_header_to_declared_target(&mut block.header)
    }

    pub fn mined_regtest_child_at(
        prev_blockhash: BlockHash,
        height: u32,
    ) -> Result<Block, RegtestFixtureError> {
        mined_regtest_child_at_time(
            prev_blockhash,
            genesis_time().saturating_add(height),
            height,
        )
    }

    pub fn mined_regtest_child_at_time(
        prev_blockhash: BlockHash,
        time: u32,
        height: u32,
    ) -> Result<Block, RegtestFixtureError> {
        build_block(prev_blockhash, time, vec![coinbase(height)])
    }

    pub fn mined_block_with_prev_hash(
        prev_blockhash: BlockHash,
        height: u32,
        txs: Vec<Tx>,
    ) -> Result<Block, RegtestFixtureError> {
        build_block(prev_blockhash, genesis_time().saturating_add(height), txs)
    }

    pub fn mined_regtest_header(
        prev_blockhash: BlockHash,
        height: u32,
    ) -> Result<Header, RegtestFixtureError> {
        let mut header = Header {
            version: 4,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: genesis_time().saturating_add(height),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        };
        mine_header_to_declared_target(&mut header)?;
        Ok(header)
    }

    fn build_block(
        prev_blockhash: BlockHash,
        time: u32,
        txs: Vec<Tx>,
    ) -> Result<Block, RegtestFixtureError> {
        let mut block = Block {
            header: Header {
                version: 4,
                prev_blockhash,
                merkle_root: Hash256::default(),
                time,
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txs,
        };
        block.header.merkle_root =
            merkle_root(&block.txs).ok_or(RegtestFixtureError::EmptyMerkleRoot)?;
        mine_block_to_declared_target(&mut block)?;
        Ok(block)
    }
}
mod reorg;
#[cfg(test)]
pub(crate) mod test_error {
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum TestError {
        #[error(transparent)]
        Chain(#[from] crate::chain::ChainError),
        #[error(transparent)]
        AncestryBudget(#[from] crate::chain::AncestryBudgetExceeded),
        #[error(transparent)]
        DeploymentQuery(#[from] crate::chain::deployment::DeploymentQueryError),
        #[cfg(feature = "test-seam")]
        #[error(transparent)]
        RegtestFixture(#[from] crate::chain::regtest_fixture::RegtestFixtureError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        TryFromInt(#[from] core::num::TryFromIntError),
        #[error("missing expected value: {0}")]
        Missing(&'static str),
    }

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }
}
mod tip_wait;
mod transition;
mod tree;
mod view;

use bitcoin_rs_consensus::header_rules::ChainWork;
use bitcoin_rs_consensus::primitives::Hash256;
use thiserror::Error;

pub use bitcoin_rs_consensus::SoftforkState;
pub use count::ChainTxCount;
pub use deployment::{
    DeploymentQueryError, DeploymentStatus, SignallingDeployment, VersionBitsStatus,
    bip30_duplicate_scan_required, candidate_version, deployment_statuses, signalling_deployments,
    softfork_state,
};
pub use header_sync::{
    AcceptHeaders, HeaderAdmission, HeaderCandidate, HeaderCandidateError, HeaderCandidatePhase,
    HeaderContextError, HeaderRefusal, HeaderValidationMode, accept_headers,
    block_work, compact_is_met_by, compact_to_target, current_unix_seconds,
    permitted_difficulty_transition, validate_contextual_header, validate_pow,
};
pub use ibd::InitialBlockDownload;
pub use node::{BlockTreeNode, NodeId, NodeStatus};
pub use progress::{ChainProgress, ChainProgressReader};
pub use reorg::{ReorgPlan, plan_reorg};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipSnapshot {
    pub tip_id: NodeId,
    pub height: u32,
    pub chainwork: ChainWork,
    pub hash: Hash256,
    pub chain_tx_count: ChainTxCount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedEpoch {
    pub tip: TipSnapshot,
    pub commit_id: u64,
}

impl AppliedEpoch {
    #[must_use]
    pub const fn new(tip: TipSnapshot, commit_id: u64) -> Self {
        Self { tip, commit_id }
    }
}

pub use tip_wait::{ActiveTipWait, TipWaitCondition};
pub use transition::{
    StableRead, StableReadGuard, TransitionAuthority, TransitionAuthorityGuard, TransitionDomain,
};
pub use tree::{BlockTree, InvalidationOutcome};
pub use view::{BlockTreeReader, TipReader};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("block ancestry read budget exhausted")]
pub struct AncestryBudgetExceeded;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("block-tree logical node ID capacity exhausted (index {index})")]
    NodeIdOverflow { index: usize },
    #[error("unknown block-tree node {id:?}")]
    UnknownNode { id: NodeId },
    #[error("duplicate block header {hash}")]
    DuplicateHeader { hash: Hash256 },
    #[error("header {hash} is known invalid")]
    KnownInvalidHeader { hash: Hash256 },
    #[error("missing parent header {prev_hash}")]
    MissingParent { prev_hash: Hash256 },
    #[error("header extends invalid parent {parent:?}")]
    InvalidParent { parent: NodeId },
    #[error("header version {version:#010x} is below required {required} at height {height}")]
    BadVersion {
        version: i32,
        required: i32,
        height: u32,
    },
    #[error(
        "header timestamp {timestamp} at height {height} is below the timewarp floor {minimum}"
    )]
    TimewarpAttack {
        height: u32,
        timestamp: u32,
        minimum: u32,
    },

    #[error("header prev hash {actual_prev} does not match expected parent {expected_prev}")]
    NonContinuousHeader {
        expected_prev: Hash256,
        actual_prev: Hash256,
    },
    #[error("header {hash} has zero proof-of-work target")]
    ZeroTarget { hash: Hash256 },
    #[error("header {hash} target {target} exceeds network limit {max_target}")]
    TargetExceedsLimit {
        hash: Hash256,
        target: ChainWork,
        max_target: ChainWork,
    },
    #[error("nBits {bits:08x} overflows the 256-bit proof-of-work target")]
    TargetBitsOverflow { bits: u32 },
    #[error("header {hash} does not satisfy proof of work target {target}")]
    InvalidPow { hash: Hash256, target: ChainWork },
    #[error("nBits {actual:08x} does not match expected {expected:08x} at height {height}")]
    NbitsMismatch {
        actual: u32,
        expected: u32,
        height: u32,
    },
    #[error("chainwork overflow at header {hash}")]
    ChainworkOverflow { hash: Hash256 },
    #[error("height overflow after parent {parent:?}")]
    HeightOverflow { parent: NodeId },
    #[error("no common ancestor while planning reorg from {old_tip:?} to {new_tip:?}")]
    NoCommonAncestor { old_tip: NodeId, new_tip: NodeId },
    #[error("header {hash} timestamp {timestamp} is not greater than median-time-past {median}")]
    TimestampTooEarly {
        hash: Hash256,
        timestamp: u32,
        median: u32,
    },
    #[error(
        "header {hash} timestamp {timestamp} exceeds maximum allowed future time {max_allowed}"
    )]
    TimestampTooFarAhead {
        hash: Hash256,
        timestamp: u32,
        max_allowed: u32,
    },
}
