//! Stratum V2 template-provider bridge.
//!
//! Translates the node-owned mining model into SV2 Template Distribution
//! Protocol messages without going through BIP22/BIP23 JSON-RPC.
//!
//! The bridge consumes [`MiningSource`], a trait that abstracts template
//! access and block submission. An in-process adapter wraps
//! [`MiningControl`](crate::MiningControl) directly; a future IPC adapter
//! could serialize the same types over Unix sockets.
//!
//! SV2 framing, Noise, pool protocol state, and SRI dependencies live
//! here — not in consensus, chainstate, or mempool.

mod server;
mod template;

use std::sync::Arc;

use bitcoin_rs_primitives::Block;
pub use server::Sv2Server;
use template::TemplateHub;

use crate::{BlockTemplate, MiningControlError};

/// Abstracted mining source for the SV2 bridge.
///
/// Provides template access and block submission without exposing
/// the full [`MiningControl`](crate::MiningControl) trait.
pub trait MiningSource: Send + Sync {
    /// Returns the current best template.
    ///
    /// Does NOT block. Callers should poll or use long-poll semantics
    /// via the underlying [`MiningControl`](crate::MiningControl) trait.
    fn current_template(&self) -> Result<Arc<BlockTemplate>, MiningControlError>;

    /// Submits a solved block through the authoritative apply path.
    ///
    /// Returns the full [`BlockValidationResult`] so callers can distinguish
    /// accepted, rejected, duplicate, and inconclusive outcomes.
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
    /// Creates a new adapter.
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
            crate::BlockTemplateResult::Proposal(_) => {
                Err(MiningControlError::Rejected(
                    compact_str::CompactString::new("expected template"),
                ))
            }
        }
    }

    fn submit_block(
        &self,
        block: Block,
    ) -> Result<crate::BlockValidationResult, MiningControlError> {
        self.control.submit_block(block)
    }
}

/// Runs the SV2 template-provider server.
///
/// Call from a tokio runtime. The server binds to `listen` and
/// distributes templates to connected pools via TDP.
pub async fn run(source: Arc<dyn MiningSource>, listen: std::net::SocketAddr) {
    let hub = TemplateHub::new(source);
    if let Err(e) = Sv2Server::new(listen, hub).run().await {
        tracing::error!(error = %e, "sv2 server failed");
    }
}
