//! Native Stratum V2 Template Distribution Protocol server.
//!
//! Implements an in-process SV2 TDP server that connects to the node's
//! [`MiningControl`](crate::MiningControl) trait. Pools connect directly
//! to bitcoin-rs — no external bridge container needed.
//!
//! Architecture:
//!
//! ```text
//! SRI pool
//!   ↕ SV2 TDP (Noise_XX, TCP)
//! Sv2TpServer (this module)
//!   ↕ MiningControl
//! MiningCoordinator → Chainstate → block application
//! ```
//!
//! The server handles:
//! - TCP listener + Noise_XX handshake
//! - TDP message exchange (SetupConnection, NewTemplate, SetNewPrevHash)
//! - SubmitSolution → authoritative block submission

mod server;
mod template;

pub use server::Sv2TpServer;
pub use template::TemplateHub;

use std::sync::Arc;

use bitcoin_rs_primitives::Block;

use crate::{BlockTemplate, MiningControlError};

/// Abstraction over the node's mining capabilities for the SV2 server.
///
/// The server consumes this trait rather than `MiningControl` directly,
/// so tests can mock the mining source and the server logic stays
/// independent of chainstate internals.
pub trait MiningSource: Send + Sync {
    /// Returns the current best block template.
    fn current_template(&self) -> Result<Arc<BlockTemplate>, MiningControlError>;

    /// Submits a solved block through the authoritative apply path.
    /// Returns the full validation result so the server can distinguish
    /// accepted, rejected, and duplicate outcomes.
    fn submit_block(
        &self,
        block: Block,
    ) -> Result<crate::BlockValidationResult, MiningControlError>;
}

/// In-process adapter wrapping any [`MiningControl`](crate::MiningControl).
pub struct InProcessSource<C: crate::MiningControl> {
    control: Arc<C>,
}

impl<C: crate::MiningControl> InProcessSource<C> {
    /// Creates a new adapter wrapping the given mining control.
    #[must_use]
    pub fn new(control: Arc<C>) -> Self {
        Self { control }
    }
}

impl<C: crate::MiningControl> MiningSource for InProcessSource<C> {
    fn current_template(&self) -> Result<Arc<BlockTemplate>, MiningControlError> {
        use crate::{BlockTemplateMode, BlockTemplateRequest};

        let request = BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
        };
        match self.control.get_block_template(request)? {
            crate::BlockTemplateResult::Template(t) => Ok(Arc::new(t)),
            crate::BlockTemplateResult::Proposal(_) => Err(MiningControlError::Rejected(
                compact_str::CompactString::new("expected template result"),
            )),
        }
    }

    fn submit_block(
        &self,
        block: Block,
    ) -> Result<crate::BlockValidationResult, MiningControlError> {
        self.control.submit_block(block)
    }
}
