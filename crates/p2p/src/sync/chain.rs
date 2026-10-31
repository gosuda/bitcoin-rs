use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;

pub use bitcoin_rs_chain::HeaderAdmission;
pub use bitcoin_rs_chainstate::WindowApplyDisposition;
pub use bitcoin_rs_chainstate::assumeutxo::HistoricalAdvance;
pub use bitcoin_rs_chainstate::reorg::ReorgError;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::BlockPayload;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;
use parking_lot::RwLockReadGuard;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum SyncChainError {
    #[error(transparent)]
    Apply(#[from] bitcoin_rs_chainstate::ApplyError),
    #[error(transparent)]
    AssumeUtxo(#[from] bitcoin_rs_chainstate::assumeutxo::AssumeUtxoError),
    #[error(transparent)]
    BodyBinding(#[from] bitcoin_rs_consensus::ConsensusError),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
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

    fn advance_historical(&self) -> Result<HistoricalAdvance, SyncChainError> {
        Ok(HistoricalAdvance::Complete)
    }

    fn connect_historical(&self, _payload: &BlockPayload) -> Result<(), SyncChainError> {
        Err("historical validation is not configured".into())
    }
    fn network(&self) -> Network;

    fn block_tree(&self) -> RwLockReadGuard<'_, BlockTree>;

    fn chain_tip(&self) -> Option<Arc<TipSnapshot>>;

    fn applied_tip(&self) -> Option<Arc<TipSnapshot>>;

    fn bootstrap_genesis(&self);

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission;

    fn minimum_chain_work(&self) -> bitcoin_rs_chain::ChainWork {
        bitcoin_rs_chain::ChainWork::from_be_bytes(self.network().minimum_chain_work())
    }

    fn check_body_binding(&self, block: &Block) -> Result<(), SyncChainError>;

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize;

    #[expect(clippy::result_large_err)]
    fn commit_window(&self, payloads: &[&BlockPayload]) -> Result<usize, WindowCommitError>;

    fn switch_to_branch(
        &self,
        target: NodeId,
        staged_body: &mut dyn FnMut(Hash256) -> Option<BlockPayload>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), ReorgError>;
}
