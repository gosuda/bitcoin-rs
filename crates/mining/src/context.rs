//! Candidate chain context: version, work, time, and proposal checks.
//!
//! Consensus owns BIP9/finality rules. Chain owns historical/MTP lookups
//! and next-work. This module resolves those facts into the one record a
//! candidate builder needs, and dry-runs a proposal through the same
//! header validators full validation applies.

use bitcoin_rs_chain::{
    BlockTree, ChainError, candidate_version, header_sync,
    node::{BlockHeader, NodeId},
    softfork_state,
};
use bitcoin_rs_consensus::{MEDIAN_TIME_PAST_WINDOW, locktime_cutoff};
use bitcoin_rs_primitives::{Hash256, Network};

/// Contextual facts for the block that would extend `previous_tip_id`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningChainContext {
    /// Parent header hash in consensus little-endian storage order.
    pub previous_block_hash: Hash256,
    /// Height the candidate would have.
    pub height: u32,
    /// Versionbits candidate version: top bits set plus every `Started` or
    /// `LockedIn` deployment bit.
    pub version: i32,
    /// Compact target the candidate's nBits must equal.
    pub bits: u32,
    /// Earliest timestamp the candidate may carry: previous-tip MTP + 1.
    pub min_time: u32,
    /// Median time past of the previous tip over the BIP113 window.
    pub prev_median_time_past: u32,
    /// Whether CSV (BIP68/112/113) is active at the candidate's height.
    pub csv_active: bool,
    /// Whether Segwit (BIP141/143) is active at the candidate's height.
    pub segwit_active: bool,
}

impl MiningChainContext {
    /// Resolves the context for the block extending `previous_tip_id`.
    ///
    /// `candidate_time` is the timestamp the candidate would carry; it feeds
    /// the minimum-difficulty branch of [`header_sync::next_work_required`],
    /// exactly as the candidate's header time would during validation.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::UnknownNode`] when `previous_tip_id` is not in
    /// the tree and [`ChainError::HeightOverflow`] at the last height.
    pub fn resolve(
        tree: &BlockTree,
        network: Network,
        previous_tip_id: NodeId,
        candidate_time: u32,
    ) -> Result<Self, ChainError> {
        let parent = tree.node(previous_tip_id)?;
        let height = parent
            .height
            .checked_add(1)
            .ok_or(ChainError::HeightOverflow {
                parent: previous_tip_id,
            })?;
        let softfork = softfork_state(tree, network, Some(previous_tip_id), height);
        let prev_median_time_past = tree
            .median_time_past_at(previous_tip_id, MEDIAN_TIME_PAST_WINDOW)
            .ok_or(ChainError::UnknownNode {
                id: previous_tip_id,
            })?;
        Ok(Self {
            previous_block_hash: parent.hash,
            height,
            version: candidate_version(tree, network, previous_tip_id, height),
            bits: header_sync::next_work_required(tree, previous_tip_id, candidate_time, network)?,
            min_time: prev_median_time_past.saturating_add(1),
            prev_median_time_past,
            csv_active: softfork.csv_active,
            segwit_active: softfork.segwit_active,
        })
    }

    /// BIP113 locktime cutoff for a candidate carrying `candidate_time`.
    #[must_use]
    pub const fn locktime_cutoff(&self, candidate_time: u32) -> u32 {
        locktime_cutoff(self.csv_active, self.prev_median_time_past, candidate_time)
    }
}

/// Dry-run contextual check for a proposed block header.
///
/// Runs exactly the contextual validators full validation runs — nBits via
/// [`header_sync::validate_header_nbits`] and the median-time-past/future
/// bounds via [`header_sync::validate_header_timestamp`] — without mutating
/// the tree, so a proposal verdict and a later apply verdict cannot disagree
/// by construction.
///
/// # Errors
///
/// Propagates the underlying [`ChainError`] from either validator.
pub fn check_candidate_header(
    tree: &BlockTree,
    network: Network,
    previous_tip_id: NodeId,
    header: &BlockHeader,
    hash: Hash256,
    now_secs: u32,
) -> Result<(), ChainError> {
    header_sync::validate_header_nbits(tree, previous_tip_id, header, network)?;
    header_sync::validate_header_timestamp(tree, header, hash, now_secs)
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_chain::{BlockTree, ChainError, node::NodeStatus};
    use bitcoin_rs_primitives::{BlockHash, Hash256, Header, Network};

    use super::{MiningChainContext, check_candidate_header};

    fn synthetic_header_with_version(prev_blockhash: BlockHash, time: u32, version: i32) -> Header {
        Header {
            version,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits: 0x207f_ffff,
            nonce: 0,
        }
    }

    #[test]
    fn mining_context_resolves_regtest_candidate_facts() -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let chain_bits: u32 = 0x207f_fffe;
        let tip = append_chain_with_bits(&mut tree, 12, 1_000_000, |_| 0x2000_0000, chain_bits)?;
        let tip_hash = tree.node(tip)?.hash;
        let tip_time = 1_000_000 + 11 * 600;

        let context = MiningChainContext::resolve(&tree, Network::Regtest, tip, tip_time + 600)?;
        assert_eq!(context.previous_block_hash, tip_hash);
        assert_eq!(context.height, 12);
        assert_eq!(
            u32::from_ne_bytes(context.version.to_ne_bytes()),
            0x2000_0000
        );
        assert_eq!(context.bits, chain_bits);
        assert_eq!(context.prev_median_time_past, 1_000_000 + 6 * 600);
        assert_eq!(context.min_time, 1_000_000 + 6 * 600 + 1);
        assert!(!context.csv_active);
        assert!(context.segwit_active);
        assert_eq!(context.locktime_cutoff(tip_time + 600), tip_time + 600);

        let recovered = MiningChainContext::resolve(&tree, Network::Regtest, tip, tip_time + 1201)?;
        assert_eq!(recovered.bits, 0x207f_ffff);

        let unknown = bitcoin_rs_chain::node::NodeId::new(u32::MAX);
        assert_eq!(
            MiningChainContext::resolve(&tree, Network::Regtest, unknown, 0),
            Err(ChainError::UnknownNode { id: unknown })
        );
        Ok(())
    }

    #[test]
    fn mining_context_version_signals_started_and_clears_active_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 3000, 1_462_060_800, |height| {
            if height >= 2016 {
                0x2000_0001
            } else {
                0x2000_0000
            }
        })?;
        let started =
            MiningChainContext::resolve(&tree, Network::Mainnet, tip, 1_462_060_800 + 3000 * 600)?;
        assert_eq!(
            u32::from_ne_bytes(started.version.to_ne_bytes()),
            0x2000_0001
        );
        assert!(!started.csv_active);
        assert_eq!(started.locktime_cutoff(7), 7);

        let mut tree = BlockTree::new();
        let tip = append_chain(&mut tree, 6048, 1_462_060_800, |height| {
            if (2016..3932).contains(&height) {
                0x2000_0001
            } else {
                0x2000_0000
            }
        })?;
        let active =
            MiningChainContext::resolve(&tree, Network::Mainnet, tip, 1_462_060_800 + 6048 * 600)?;
        assert_eq!(
            u32::from_ne_bytes(active.version.to_ne_bytes()),
            0x2000_0000
        );
        assert!(active.csv_active);
        assert_eq!(
            active.locktime_cutoff(u32::MAX),
            active.prev_median_time_past
        );
        Ok(())
    }

    #[test]
    fn check_candidate_header_shares_full_validation_verdicts()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut tree = BlockTree::new();
        let chain_bits: u32 = 0x207f_fffe;
        let tip = append_chain_with_bits(&mut tree, 12, 1_000_000, |_| 0x2000_0000, chain_bits)?;
        let context = MiningChainContext::resolve(&tree, Network::Regtest, tip, 1_003_600 + 600)?;
        let tip_blockhash = BlockHash(context.previous_block_hash);

        let candidate = candidate_header(tip_blockhash, context.min_time, context.bits);
        let hash = candidate.compute_hash().0;
        check_candidate_header(&tree, Network::Regtest, tip, &candidate, hash, u32::MAX)?;

        let bad_bits = candidate_header(tip_blockhash, context.min_time, 0x207f_fffd);
        let hash = bad_bits.compute_hash().0;
        assert!(matches!(
            check_candidate_header(&tree, Network::Regtest, tip, &bad_bits, hash, u32::MAX),
            Err(ChainError::NbitsMismatch { .. })
        ));

        let early = candidate_header(tip_blockhash, context.prev_median_time_past, context.bits);
        let hash = early.compute_hash().0;
        assert!(matches!(
            check_candidate_header(&tree, Network::Regtest, tip, &early, hash, u32::MAX),
            Err(ChainError::TimestampTooEarly { .. })
        ));
        Ok(())
    }

    fn candidate_header(prev_blockhash: BlockHash, time: u32, bits: u32) -> Header {
        Header {
            version: 0x2000_0000,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits,
            nonce: 0,
        }
    }

    fn append_chain(
        tree: &mut BlockTree,
        len: u32,
        start_time: u32,
        version_at: impl Fn(u32) -> i32,
    ) -> Result<bitcoin_rs_chain::node::NodeId, Box<dyn std::error::Error>> {
        append_chain_with_bits(tree, len, start_time, version_at, 0x207f_ffff)
    }

    fn append_chain_with_bits(
        tree: &mut BlockTree,
        len: u32,
        start_time: u32,
        version_at: impl Fn(u32) -> i32,
        bits: u32,
    ) -> Result<bitcoin_rs_chain::node::NodeId, Box<dyn std::error::Error>> {
        let mut prev = BlockHash::default();
        let mut tip = None;
        for height in 0..len {
            let mut header = synthetic_header_with_version(
                prev,
                start_time.saturating_add(height.saturating_mul(600)),
                version_at(height),
            );
            header.bits = bits;
            prev = header.compute_hash();
            tip = Some(tree.insert_header(header, NodeStatus::HeaderValid)?);
        }
        let Some(tip) = tip else {
            panic!("synthetic chain length must be non-zero");
        };
        Ok(tip)
    }
}
