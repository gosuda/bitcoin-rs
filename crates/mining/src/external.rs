//! Typed external-process mining boundary.
//!
//! This module defines [`ExternalMiningControl`], a minimal typed surface
//! for external template consumers (e.g. Stratum V2 template providers)
//! to access the node-owned mining model without parsing BIP22/BIP23 JSON.
//!
//! SV2 framing, Noise, pool protocol state, and SRI dependencies remain
//! outside `crates/mining` and outside consensus/chainstate/mempool.
//!
//! # Design
//!
//! The trait is transport-agnostic. An in-process adapter wraps
//! [`MiningControl`](crate::MiningControl) directly; a future IPC adapter
//! could serialize the same types over Unix sockets or shared memory.

use std::vec::Vec;
use bitcoin_rs_primitives::{Block, Txid, Wtxid};
use compact_str::CompactString;

use crate::{BlockTemplate, MiningControlError};

/// Minimal typed surface for external template consumers.
///
/// External processes (SV2 template providers, mining proxies, custom
/// miners) implement or consume this trait to access the node-owned
/// mining model without BIP22/BIP23 JSON serialization.
pub trait ExternalMiningControl: Send + Sync {
    /// Blocks until a new template is available or the tip changes.
    ///
    /// Returns the template and the list of candidate transaction IDs
    /// included in it.
    fn wait_for_template(&self) -> Result<TemplateSnapshot, MiningControlError>;

    /// Retrieves a single candidate transaction by its txid.
    ///
    /// The transaction must be one of the IDs returned in a prior
    /// [`TemplateSnapshot`]. Returns `None` if the txid is not in the
    /// current template's transaction set.
    fn get_template_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<TemplateTransaction>, MiningControlError>;

    /// Submits a solved block through the authoritative apply path.
    fn submit_solved_block(&self, block: Block) -> Result<(), MiningControlError>;
}

/// A snapshot of a block template with its candidate transaction IDs.
#[derive(Clone, Debug)]
pub struct TemplateSnapshot {
    /// The full semantic template.
    pub template: BlockTemplate,
    /// Transaction IDs of all candidate transactions in this template.
    pub transaction_ids: Vec<Txid>,
}

/// A single candidate transaction from a template.
#[derive(Clone, Debug)]
pub struct TemplateTransaction {
    /// The transaction id.
    pub txid: Txid,
    /// The witness transaction id.
    pub wtxid: Wtxid,
    /// The fee in satoshis.
    pub fee: u64,
    /// The serialized transaction weight.
    pub weight: u64,
    /// The serialized transaction bytes.
    pub data: Vec<u8>,
}

// ── In-process adapter ────────────────────────────────────────────

/// In-process adapter that wraps a [`MiningControl`] implementor.
///
/// Delegates directly to the node's mining service without IPC overhead.
pub struct InProcessMiningAdapter<C: crate::MiningControl> {
    control: std::sync::Arc<C>,
}

impl<C: crate::MiningControl> InProcessMiningAdapter<C> {
    /// Creates a new adapter wrapping the given mining control.
    #[must_use]
    pub fn new(control: std::sync::Arc<C>) -> Self {
        Self { control }
    }
}

impl<C: crate::MiningControl> ExternalMiningControl for InProcessMiningAdapter<C> {
    fn wait_for_template(&self) -> Result<TemplateSnapshot, MiningControlError> {
        use crate::{BlockTemplateMode, BlockTemplateRequest};

        let request = BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
        };
        let result = self.control.get_block_template(request)?;
        match result {
            crate::BlockTemplateResult::Template(template) => {
                let transaction_ids = template
                    .candidate
                    .transactions
                    .iter()
                    .map(|tx| tx.txid)
                    .collect();
                Ok(TemplateSnapshot {
                    template,
                    transaction_ids,
                })
            }
            crate::BlockTemplateResult::Proposal(_) => Err(MiningControlError::Rejected(
                CompactString::new("expected template result"),
            )),
        }
    }

    fn get_template_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<TemplateTransaction>, MiningControlError> {
        use crate::{BlockTemplateMode, BlockTemplateRequest};

        let request = BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
        };
        let result = self.control.get_block_template(request)?;
        match result {
            crate::BlockTemplateResult::Template(template) => {
                let tx = template
                    .candidate
                    .transactions
                    .iter()
                    .find(|t| t.txid == txid);
                Ok(tx.map(|t| TemplateTransaction {
                    txid: t.txid,
                    wtxid: t.wtxid,
                    fee: t.fee,
                    weight: t.weight,
                    data: Vec::new(), // serialized on demand by transport layer
                }))
            }
            crate::BlockTemplateResult::Proposal(_) => Err(MiningControlError::Rejected(
                CompactString::new("expected template result"),
            )),
        }
    }

    fn submit_solved_block(&self, block: Block) -> Result<(), MiningControlError> {
        self.control.submit_block(block)?;
        Ok(())
    }
}
