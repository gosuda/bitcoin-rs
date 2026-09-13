//! Chainstate entry points over the single admitted transition capability.

use super::ApplyFinish;
use super::ApplyIntent;
use super::BlockProvenance;
use super::Chainstate;
use super::ChainstateSnapshot;
use super::ConnectOutcome;
use super::DisconnectOutcome;
use super::WindowApplyDisposition;
use super::WindowApplyError;
use super::connect::apply_block_admitted;
use super::connect::apply_block_inner;
use super::window::PublishMode;
use crate::apply::error::ApplyError;
use bitcoin_rs_primitives::Block;
use std::sync::atomic::Ordering;

impl Chainstate {
    /// Copies the published header tip and a coherent applied-tip / chain-tx
    /// count pair.
    ///
    /// Does not take the transition lock. Header tip is a separate cell and
    /// may be ahead of the applied chain. Applied tip and `chain_tx_count`
    /// are published together under `applied_seq`; this method retries until
    /// it observes a stable pair.
    #[must_use]
    pub fn snapshot(&self) -> ChainstateSnapshot {
        loop {
            let seq1 = self.applied_seq.load(Ordering::Acquire);
            if seq1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let header = self.chain_tip.load_full().as_deref().cloned();
            let applied = self.applied_tip.load_full().as_deref().cloned();
            let chain_tx_count = self.chain_tx_count.load(Ordering::Acquire);
            let seq2 = self.applied_seq.load(Ordering::Acquire);
            if seq1 == seq2 {
                return ChainstateSnapshot {
                    header,
                    applied,
                    chain_tx_count,
                };
            }
            std::hint::spin_loop();
        }
    }

    /// Publishes a checkpoint to settle rolled-back disconnect debt.
    ///
    /// Returns `Ok(true)` when a checkpoint was written, `Ok(false)` when
    /// there was no debt or no publisher. A publication failure leaves the
    /// `RolledBack` marker in place.
    pub(crate) fn checkpoint(
        &self,
    ) -> core::result::Result<bool, crate::checkpoint::CheckpointError> {
        match &self.checkpoint_publisher {
            Some(publisher) => publisher.settle_disconnect_debt(),
            None => Ok(false),
        }
    }

    /// Admits a transition, connects `block`, and finishes on success. Failure
    /// before admission acquires no transition and does not change generation.
    /// A refusal after admission drops the transition and leaves generation
    /// odd; callers that need to retry a clean refusal should use
    /// [`ChainTransition`] directly and finish it explicitly.
    ///
    /// Persistence matches [`ChainTransition::connect`]. Derived consumers are
    /// not invoked. Production paths with followers must dispatch while the
    /// [`ChainTransition`] is still held, then [`ChainTransition::finish`]
    /// (`ARCH-07`); [`crate::chain_effects::ChainFollowers::apply_connect`]
    /// is that sequence.
    pub fn apply_block(&self, block: &Block) -> core::result::Result<ConnectOutcome, ApplyError> {
        apply_block_inner(self, block, None, BlockProvenance::Network)
    }

    /// Admits a transition, connects `block` from preserved bytes, and finishes
    /// on success.
    ///
    /// Persistence matches [`ChainTransition::connect`].
    pub fn apply_block_with_serialized(
        &self,
        block: &Block,
        serialized: bytes::Bytes,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        apply_block_inner(self, block, Some(serialized), BlockProvenance::Network)
    }

    /// Admits a transition, replays a locally persisted body, and finishes on
    /// success.
    ///
    /// Persistence matches [`ChainTransition::replay_local`].
    pub fn replay_local_block(
        &self,
        block: &Block,
        serialized: bytes::Bytes,
    ) -> core::result::Result<ConnectOutcome, ApplyError> {
        apply_block_inner(self, block, Some(serialized), BlockProvenance::LocalReplay)
    }

    /// Admits a transition, disconnects `block`, and finishes on success.
    /// Failure before admission acquires no transition and does not change
    /// generation. A refusal after admission drops the transition and leaves
    /// generation odd; callers that need to retry should use [`ChainTransition`]
    /// directly.
    ///
    /// Persistence matches [`ChainTransition::disconnect`]. An admission
    /// failure is `DisconnectError::Refused`. Derived consumers are not
    /// invoked; see [`crate::chain_effects::ChainFollowers::apply_disconnect`].
    pub fn disconnect_block(
        &self,
        block: &Block,
    ) -> core::result::Result<DisconnectOutcome, crate::DisconnectError> {
        let transition = self
            .begin_transition()
            .map_err(|error| crate::DisconnectError::Refused(Box::new(error)))?;
        let result = transition.disconnect(block);
        if result.is_ok() {
            let _ = transition.finish();
        }
        result
    }

    /// Admits a transition, applies consecutive blocks, and finishes on success.
    /// Failure before admission acquires no transition and does not change
    /// generation. A refusal after admission drops the transition and leaves
    /// generation odd; callers that need to retry a clean refusal should use
    /// [`ChainTransition::connect_window`] directly and finish explicitly.
    ///
    /// Persistence matches [`ChainTransition::connect_window`].
    #[allow(clippy::result_large_err)]
    pub fn apply_window(
        &self,
        blocks: &[&Block],
        serialized: &[bytes::Bytes],
    ) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
        if blocks.len() != serialized.len() {
            return Err(WindowApplyError {
                applied: 0,
                committed: Vec::new(),
                source: ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Kernel(
                    format!(
                        "window has {} blocks but {} serialized bodies",
                        blocks.len(),
                        serialized.len()
                    ),
                )),
                disposition: WindowApplyDisposition::Operational,
                invalidated: Box::default(),
            });
        }
        let transition = self.begin_transition().map_err(|source| WindowApplyError {
            applied: 0,
            committed: Vec::new(),
            source,
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        })?;
        let result = transition.connect_window(blocks, serialized);
        if result.is_ok() {
            let _ = transition.finish();
        }
        result
    }

    /// See `ARCH-07` in `docs/contracts/architecture.md`.
    pub fn validate_block(&self, block: &Block) -> core::result::Result<(), ApplyError> {
        let _lock = self.lock_transition()?;
        match apply_block_admitted(
            self,
            block,
            None,
            None,
            BlockProvenance::Network,
            ApplyIntent::Propose,
            PublishMode::Now,
        )? {
            ApplyFinish::Proposed => Ok(()),
            ApplyFinish::Committed(_) => {
                unreachable!("propose intent does not persist")
            }
        }
    }
}
