//! Applied-chain seam driven by the block-download executor. The
//! implementation owns applied-tip mutation (node, ARCH-07); the executor
//! owns download scheduling, staging, and peer policy.

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;

// Header admission is decided by the authoritative tree writer, so its
// outcome vocabulary belongs to the chain crate; the seam shares it.
pub use bitcoin_rs_chain::HeaderAdmission;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;
use bytes::Bytes;
use parking_lot::RwLock;

/// Boxed source for seam failures: the executor forwards them to logs and
/// metrics without naming the implementation's error types.
pub type SyncChainError = Box<dyn core::error::Error + Send + Sync>;

/// How the executor must treat a failed window commit or branch connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowCommitDisposition {
    /// `Permanent` failures poisoned the failed block's header subtree while
    /// the chain transition was still held.
    Permanent,
    /// The delivered body is mutated or not bound to its header. Discard
    /// this body and retry the same header/hash from another source; do not
    /// poison the header or its descendants.
    BodyMutated,
    /// `Operational` failures poisoned nothing; the failed block stays
    /// retryable.
    Operational,
    /// `Fatal` means the transition itself could not be settled, so
    /// admission stays closed until recovery.
    Fatal,
}

/// A window commit that stopped partway: `applied` committed, the block at
/// index `applied` failed, and `invalidated` carries the subtree the
/// implementation marked while the transition was held.
pub struct WindowCommitError {
    /// Blocks that committed before the failure.
    pub applied: usize,
    /// How the executor must treat this failure.
    pub disposition: WindowCommitDisposition,
    /// Hashes marked invalid while the transition was held; empty unless
    /// `disposition` is [`WindowCommitDisposition::Permanent`].
    pub invalidated: Box<[Hash256]>,
    /// The implementation's underlying failure.
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

/// Why a branch switch stopped, and what the applied chain looks like now.
pub enum BranchSwitchError {
    /// The first block the connect walk needed has no staged or stored body.
    MissingBody {
        /// Height the missing body sits at.
        height: u32,
    },
    /// A connect failed after some of the new branch was applied; the
    /// implementation has already evaluated the assume-valid gate over the
    /// post-invalidation tree when `invalidated` is non-empty.
    ConnectFailed {
        /// Hash of the block that failed to connect.
        hash: Hash256,
        /// How the executor must treat the failure — decided by the apply
        /// classifier at the failure.
        disposition: WindowCommitDisposition,
        /// Every hash marked `Invalid` under the held transition; empty for
        /// operational failures.
        invalidated: Box<[Hash256]>,
    },
    /// A disconnect-side body became unreadable mid-rollback; the chain is
    /// coherent at `stopped_at`.
    DisconnectBodyLost {
        /// Fully disconnected blocks before the loss, in plan order.
        disconnected: usize,
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
    },
    /// A connect-side body became unavailable after part of the branch
    /// applied; the chain is coherent at `stopped_at`.
    ConnectBodyLost {
        /// Fully disconnected blocks before the loss, in plan order.
        disconnected: usize,
        /// Fully connected new-branch blocks before the loss, in plan order.
        connected: usize,
        /// Height the applied tip reached before stopping.
        stopped_at: u32,
    },
    /// Chainstate torn by a failed disconnect; the implementation has
    /// already closed admission and requested shutdown.
    Fatal(SyncChainError),
    /// The walk concluded but its stable generation could not be published.
    TransitionSettlement(SyncChainError),
    /// A nonfatal switch completed but rolled-back state could not be
    /// checkpointed.
    CheckpointSettlement(SyncChainError),
    /// Any other typed outcome the executor only logs.
    Other(SyncChainError),
}

impl core::fmt::Display for BranchSwitchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingBody { height } => write!(f, "missing body at height {height}"),
            Self::ConnectFailed { hash, .. } => write!(f, "connect failed at {hash}"),
            Self::DisconnectBodyLost {
                disconnected,
                stopped_at,
            } => write!(
                f,
                "body lost mid-rollback after {disconnected} disconnects at height {stopped_at}"
            ),
            Self::ConnectBodyLost {
                disconnected,
                connected,
                stopped_at,
            } => write!(
                f,
                "body lost mid-connect after {disconnected} disconnects and {connected} connects at height {stopped_at}"
            ),
            Self::Fatal(source)
            | Self::TransitionSettlement(source)
            | Self::CheckpointSettlement(source)
            | Self::Other(source) => write!(f, "{source}"),
        }
    }
}

impl core::fmt::Debug for BranchSwitchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingBody { height } => f
                .debug_struct("MissingBody")
                .field("height", height)
                .finish(),
            Self::ConnectFailed {
                hash,
                disposition,
                invalidated,
            } => f
                .debug_struct("ConnectFailed")
                .field("hash", hash)
                .field("disposition", disposition)
                .field("invalidated", invalidated)
                .finish(),
            Self::DisconnectBodyLost {
                disconnected,
                stopped_at,
            } => f
                .debug_struct("DisconnectBodyLost")
                .field("disconnected", disconnected)
                .field("stopped_at", stopped_at)
                .finish(),
            Self::ConnectBodyLost {
                disconnected,
                connected,
                stopped_at,
            } => f
                .debug_struct("ConnectBodyLost")
                .field("disconnected", disconnected)
                .field("connected", connected)
                .field("stopped_at", stopped_at)
                .finish(),
            Self::Fatal(source) => f.debug_tuple("Fatal").field(source).finish(),
            Self::TransitionSettlement(source) => {
                f.debug_tuple("TransitionSettlement").field(source).finish()
            }
            Self::CheckpointSettlement(source) => {
                f.debug_tuple("CheckpointSettlement").field(source).finish()
            }
            Self::Other(source) => f.debug_tuple("Other").field(source).finish(),
        }
    }
}

/// Applied-chain seam driven by the block-download executor.
///
/// The implementation owns applied-tip mutation (node, ARCH-07) — header
/// admission under the chain-transition lock, window commit, branch switch,
/// and genesis bootstrap. The executor owns everything else.
pub trait SyncChain: Send + Sync {
    /// Network the applied chain validates against.
    fn network(&self) -> Network;

    /// Shared block tree (headers + applied chain topology).
    fn block_tree(&self) -> &RwLock<BlockTree>;

    /// Header (chain) tip cell published by header admission.
    fn chain_tip(&self) -> &ArcSwapOption<TipSnapshot>;

    /// Applied tip cell published by commits and branch switches.
    fn applied_tip(&self) -> &ArcSwapOption<TipSnapshot>;

    /// Applies genesis when nothing is applied yet.
    fn bootstrap_genesis(&self);

    /// Admits a headers batch (header tip move + assume-valid re-evaluation
    /// happen inside, under the implementation's transition lock).
    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission;

    /// Whether `block`'s body binds to its admitted header — txid merkle
    /// root plus witness commitment under the tree's segwit-active rule for
    /// the block's parent. `Ok(())` when bound or when the header is not in
    /// the tree; `Err` rejects the delivery. The consensus rule and the
    /// segwit-active derivation stay with the implementation; the executor
    /// only owns the staging policy that calls it.
    fn check_body_binding(&self, block: &Block) -> Result<(), SyncChainError>;

    /// Number of leading drained blocks that commit as one window
    /// (apply-side batch policy).
    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize;

    /// Commits `blocks` in order as one chain transition. `Ok(n)` = all `n`
    /// committed and settled.
    fn commit_window(
        &self,
        blocks: &[&Block],
        bodies: &[Bytes],
    ) -> Result<usize, WindowCommitError>;

    /// Moves the applied chain onto `target`'s branch. `staged_body`
    /// resolves connect-side bodies from bounded staging; `connected_body`
    /// runs once per committed connect so the executor can retire download
    /// accounting.
    fn switch_to_branch(
        &self,
        target: NodeId,
        staged_body: &mut dyn FnMut(Hash256) -> Option<(Block, Bytes)>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), BranchSwitchError>;
}
