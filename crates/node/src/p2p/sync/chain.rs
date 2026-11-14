use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_consensus::primitives::Header;
use bitcoin_rs_consensus::primitives::Network;
pub use bitcoin_rs_execution::WindowApplyDisposition;
pub use bitcoin_rs_execution::assumeutxo::HistoricalAdvance;
use bitcoin_rs_execution::chain::BlockTree;
pub use bitcoin_rs_execution::chain::HeaderAdmission;
use bitcoin_rs_execution::chain::NodeId;
use bitcoin_rs_execution::chain::TipSnapshot;
pub use bitcoin_rs_execution::reorg::ReorgError;

use bitcoin_rs_consensus::primitives::BlockImage;
use parking_lot::RwLockReadGuard;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum SyncChainError {
    #[error(transparent)]
    Apply(#[from] bitcoin_rs_execution::ApplyError),
    #[error(transparent)]
    AssumeUtxo(#[from] bitcoin_rs_execution::assumeutxo::AssumeUtxoError),
    #[error(transparent)]
    BodyBinding(#[from] bitcoin_rs_consensus::ConsensusError),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_execution::chain::ChainError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Message(String),
}

impl From<&'static str> for SyncChainError {
    fn from(msg: &'static str) -> Self {
        Self::Message(msg.to_owned())
    }
}

pub struct WindowCommitError {
    pub applied: usize,
    pub disposition: WindowApplyDisposition,
    pub invalidated: Box<[Hash256]>,
    pub source: SyncChainError,
}

impl core::fmt::Display for WindowCommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "window commit stopped at {} blocks: {}",
            self.applied, self.source
        )
    }
}

impl core::fmt::Debug for WindowCommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowCommitError")
            .field("applied", &self.applied)
            .field("disposition", &self.disposition)
            .field("invalidated", &self.invalidated)
            .field("source", &self.source)
            .finish()
    }
}

pub trait SyncChain: Send + Sync {
    fn historical_base(&self) -> Option<Hash256> {
        None
    }

    /// True once the chain authority closed for recovery: apply must stop
    /// scheduling and planning new work, because the only recovery is a
    /// supervised restart that replays durable state.
    fn closed_for_recovery(&self) -> bool {
        false
    }

    fn advance_historical(&self) -> Result<HistoricalAdvance, SyncChainError> {
        Ok(HistoricalAdvance::Complete)
    }

    fn connect_historical(&self, _payload: &BlockImage) -> Result<(), SyncChainError> {
        Err("historical validation is not configured".into())
    }
    fn network(&self) -> Network;

    fn block_tree(&self) -> RwLockReadGuard<'_, BlockTree>;

    fn chain_tip(&self) -> Option<Arc<TipSnapshot>>;

    fn applied_tip(&self) -> Option<Arc<TipSnapshot>>;

    fn bootstrap_genesis(&self);

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission;

    fn minimum_chain_work(&self) -> bitcoin_rs_consensus::header_rules::ChainWork {
        bitcoin_rs_consensus::header_rules::ChainWork::from_be_bytes(
            self.network().minimum_chain_work(),
        )
    }

    fn check_body_binding(&self, block: &BlockImage) -> Result<(), SyncChainError>;

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize;

    #[expect(clippy::result_large_err)]
    fn commit_window(&self, payloads: &[&BlockImage]) -> Result<usize, WindowCommitError>;

    fn switch_to_branch(
        &self,
        target: NodeId,
        staged_body: &mut dyn FnMut(Hash256) -> Option<BlockImage>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), ReorgError>;
}
