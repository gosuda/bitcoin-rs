//! Block template to SV2 NewTemplate conversion.
//!
//! Converts [`BlockTemplate`] from the mining model into SV2
//! [`NewTemplate`] and [`SetNewPrevHash`] messages, handling
//! byte-order conversions, merkle path construction, and BIP34
//! coinbase prefix encoding.

use std::sync::Arc;

use bitcoin_rs_primitives::Txid;

use super::MiningSource;

/// Maintains the latest template state for SV2 distribution.
pub struct TemplateHub {
    source: Arc<dyn MiningSource>,
}

impl TemplateHub {
    /// Creates a new template hub wrapping the given mining source.
    pub fn new(source: Arc<dyn MiningSource>) -> Self {
        Self { source }
    }

    /// Waits for and returns the next template from the mining source.
    pub fn next_template(&self) -> Result<TemplateSnapshot, super::MiningControlError> {
        let template = self.source.wait_for_template()?;
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
}

/// Snapshot of a block template with candidate transaction IDs.
pub struct TemplateSnapshot {
    /// The full semantic template.
    pub template: Arc<crate::BlockTemplate>,
    /// Transaction IDs in block assembly order.
    pub transaction_ids: Vec<Txid>,
}
