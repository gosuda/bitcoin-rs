//! Block template conversion to SV2 TDP messages.
//!
//! Converts the node-owned [`BlockTemplate`](crate::BlockTemplate) into raw
//! SV2 TDP message bytes (`NewTemplate` + `SetNewPrevHash`) ready for transmission.

use std::sync::Arc;

use super::MiningSource;

/// Maintains the latest template state for SV2 distribution.
pub struct TemplateHub {
    source: Arc<dyn MiningSource>,
    last_template_id: u64,
    last_prev_hash: Option<[u8; 32]>,
}

impl TemplateHub {
    /// Creates a new template hub.
    pub fn new(source: Arc<dyn MiningSource>) -> Self {
        Self {
            source,
            last_template_id: 0,
            last_prev_hash: None,
        }
    }

    /// Returns the current template as SV2 TDP message bytes.
    ///
    /// Returns `None` if no new template is needed.
    pub fn check_for_update(
        &mut self,
    ) -> Result<Option<TemplateUpdate>, super::MiningControlError> {
        let template = self.source.current_template()?;

        let prev_hash: [u8; 32] = *template.candidate.previous_block_hash.as_byte_array();
        let tip_changed = self.last_prev_hash.is_none_or(|h| h != prev_hash);

        self.last_template_id += 1;
        let template_id = self.last_template_id;
        self.last_prev_hash = Some(prev_hash);

        let txids: Vec<[u8; 32]> = template
            .candidate
            .transactions
            .iter()
            .map(|tx| *tx.txid.as_bytes())
            .collect();

        let coinbase_prefix = coinbase_prefix(template.candidate.height);
        let n_bits = template.candidate.bits.to_consensus();
        let target = target_from_bits(n_bits);

        // Build SetNewPrevHash message bytes
        let mut prev_hash_msg = Vec::with_capacity(49);
        prev_hash_msg.push(0x72); // MESSAGE_TYPE_SET_NEW_PREV_HASH
        prev_hash_msg.extend_from_slice(&template_id.to_le_bytes());
        prev_hash_msg.extend_from_slice(&prev_hash);
        prev_hash_msg.extend_from_slice(&template.candidate.current_time.to_le_bytes());
        prev_hash_msg.extend_from_slice(&n_bits.to_le_bytes());
        prev_hash_msg.extend_from_slice(&target);
        prev_hash_msg.extend_from_slice(&template.candidate.height.to_le_bytes());

        // Build NewTemplate message bytes
        let mut new_template_msg = Vec::with_capacity(256);
        new_template_msg.push(0x71); // MESSAGE_TYPE_NEW_TEMPLATE
        new_template_msg.extend_from_slice(&template_id.to_le_bytes());
        new_template_msg.push(u8::from(tip_changed));
        new_template_msg.extend_from_slice(
            &u32::try_from(template.candidate.version)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        new_template_msg.extend_from_slice(&template.candidate.current_time.to_le_bytes());
        new_template_msg.extend_from_slice(&n_bits.to_le_bytes());
        new_template_msg.push(u8::try_from(coinbase_prefix.len()).unwrap_or(0));
        new_template_msg.extend_from_slice(&coinbase_prefix);
        new_template_msg.extend_from_slice(&2u32.to_le_bytes()); // coinbase_tx_version
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // coinbase_prefix_location
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_input_sequence
        new_template_msg.extend_from_slice(&0u64.to_le_bytes()); // coinbase_tx_value_remaining
        new_template_msg.push(0u8); // coinbase_tx_outputs_count
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // coinbase_tx_locktime
        new_template_msg.extend_from_slice(&0u32.to_le_bytes()); // merkle_path len
        new_template_msg.extend_from_slice(&u32::try_from(txids.len()).unwrap_or(0).to_le_bytes());
        for txid in &txids {
            new_template_msg.extend_from_slice(txid);
        }

        Ok(Some(TemplateUpdate {
            new_template: new_template_msg,
            set_new_prev_hash: prev_hash_msg,
            template_id,
            height: template.candidate.height,
            txids,
        }))
    }
}

/// A template update to send to connected pools.
pub struct TemplateUpdate {
    /// Raw `NewTemplate` message bytes.
    pub new_template: Vec<u8>,
    /// Raw `SetNewPrevHash` message bytes.
    pub set_new_prev_hash: Vec<u8>,
    /// Template ID.
    pub template_id: u64,
    /// Block height.
    pub height: u32,
    /// Candidate transaction IDs.
    pub txids: Vec<[u8; 32]>,
}

/// Builds a BIP34 coinbase prefix (height push).
#[allow(clippy::as_conversions)]
fn coinbase_prefix(height: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut h = height;
    while h > 0 {
        bytes.push((h & 0xff) as u8);
        h >>= 8;
    }
    let mut prefix = Vec::with_capacity(1 + bytes.len());
    prefix.push(u8::try_from(bytes.len()).unwrap_or(0));
    prefix.extend_from_slice(&bytes);
    prefix
}

/// Converts compact bits to a 256-bit target.
#[allow(clippy::as_conversions)]
fn target_from_bits(bits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];
    let exponent = ((bits >> 24) & 0xff) as usize;
    let mantissa = bits & 0x00ff_ffff;
    if exponent <= 3 {
        let m = mantissa >> (8 * (3 - exponent));
        target[31] = (m & 0xff) as u8;
        if m > 0xff {
            target[30] = ((m >> 8) & 0xff) as u8;
        }
    } else if exponent <= 33 {
        let pos = 32 - exponent + 2;
        if pos < 32 {
            target[pos] = ((mantissa >> 16) & 0xff) as u8;
        }
        if pos + 1 < 32 {
            target[pos + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if pos + 2 < 32 {
            target[pos + 2] = (mantissa & 0xff) as u8;
        }
    }
    target
}
