use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};
use bitcoin_rs_consensus::primitives::{CompactTarget, Hash256, Network, deserialize};

use crate::chain::{BlockTree, ChainError, NodeId, NodeStatus};

use super::HeaderValidationMode;

pub(crate) const HEADER_CONTEXT_SNAPSHOT_LEN: usize = 174;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderContextError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error("height overflow after header {parent}")]
    HeightOverflow { parent: Hash256 },
    #[error("invalid temporary header-validation context")]
    InvalidSnapshot,
    #[error(transparent)]
    SnapshotDecode(#[from] bitcoin_rs_consensus::primitives::encode::DecodeError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeaderValidationContext {
    pub(super) network: Network,
    pub(super) parent: BlockHeader,
    pub(super) height: u32,
    pub(super) chainwork: ChainWork,
    pub(super) times: [u32; 11],
    pub(super) time_count: usize,
    pub(super) next_time: usize,
    pub(super) period_anchor: super::RetargetAnchor,
    pub(super) last_nonminimum_bits: CompactTarget,
}

impl HeaderValidationContext {
    pub(crate) fn from_tree(
        tree: &BlockTree,
        parent_id: NodeId,
        network: Network,
    ) -> Result<Self, ChainError> {
        let parent = tree.node(parent_id)?;
        if parent.status == NodeStatus::Invalid {
            return Err(ChainError::InvalidParent { parent: parent_id });
        }
        let interval = network.retarget_interval();
        let anchor_height = if interval == 0 {
            0
        } else {
            parent.height - parent.height % interval
        };
        let anchor_id = tree
            .node_at_height_from(parent_id, anchor_height)
            .ok_or(ChainError::UnknownNode { id: parent_id })?;
        let period_anchor = super::RetargetAnchor::from_header(&tree.node(anchor_id)?.header);
        let mut times = [0; 11];
        let mut time_count = 0;
        let mut cursor = Some(parent_id);
        while time_count < times.len()
            && let Some(id) = cursor
        {
            let node = tree.node(id)?;
            times[time_count] = node.header.time;
            time_count += 1;
            cursor = node.parent;
        }
        times[..time_count].reverse();
        Ok(Self {
            network,
            parent: parent.header,
            height: parent.height,
            chainwork: parent.chainwork,
            times,
            time_count,
            next_time: time_count % times.len(),
            period_anchor,
            last_nonminimum_bits: super::expected_non_retarget_bits(
                network,
                tree,
                parent_id,
                parent.header.time,
            )?,
        })
    }

    pub(super) fn next_height(&self) -> Result<u32, HeaderContextError> {
        self.height
            .checked_add(1)
            .ok_or(HeaderContextError::HeightOverflow {
                parent: Hash256::from(self.parent.compute_hash()),
            })
    }

    pub(super) fn median_time_past(&self) -> u32 {
        let mut sorted = self.times;
        sorted[..self.time_count].sort_unstable();
        sorted[self.time_count / 2]
    }

    pub(super) fn next_bits(&self, candidate_time: u32) -> Result<CompactTarget, HeaderContextError> {
        let height = self.next_height()?;
        let interval = self.network.retarget_interval();
        if interval != 0 && height.is_multiple_of(interval) {
            return Ok(if self.network.pow_no_retargeting() {
                self.parent.bits
            } else {
                super::calculate_retarget_bits(self.network, &self.parent, self.period_anchor)
            });
        }
        Ok(
            super::immediate_non_retarget_bits(self.network, &self.parent, candidate_time)
                .unwrap_or(self.last_nonminimum_bits),
        )
    }

    pub(super) fn accept_contextual_header(
        &mut self,
        header: &BlockHeader,
        now_secs: u32,
        mode: HeaderValidationMode,
    ) -> Result<(), HeaderContextError> {
        let expected_prev = Hash256::from(self.parent.compute_hash());
        let actual_prev = Hash256::from(header.prev_blockhash);
        if actual_prev != expected_prev {
            return Err(ChainError::NonContinuousHeader {
                expected_prev,
                actual_prev,
            }
            .into());
        }
        let height = self.next_height()?;
        super::validate_nbits(header.bits, self.next_bits(header.time)?, height)?;
        super::validate_time_and_version(
            header,
            height,
            self.parent.time,
            self.median_time_past(),
            self.network,
            now_secs,
            mode,
        )?;
        let chainwork = self
            .chainwork
            .checked_add(super::block_work(header))
            .ok_or(ChainError::ChainworkOverflow {
                hash: Hash256::from(header.compute_hash()),
            })?;
        let interval = self.network.retarget_interval();
        let period_boundary = interval != 0 && height.is_multiple_of(interval);
        if period_boundary {
            self.period_anchor = super::RetargetAnchor::from_header(header);
        }
        if period_boundary || header.bits != super::pow_limit_bits(self.network) {
            self.last_nonminimum_bits = header.bits;
        }
        self.times[self.next_time] = header.time;
        self.time_count = (self.time_count + 1).min(self.times.len());
        self.next_time = (self.next_time + 1) % self.times.len();
        self.parent = *header;
        self.height = height;
        self.chainwork = chainwork;
        Ok(())
    }
}


impl HeaderValidationContext {
    pub(crate) fn header(&self) -> &BlockHeader { &self.parent }
    pub(crate) fn hash(&self) -> Hash256 { Hash256::from(self.parent.compute_hash()) }
    pub(crate) fn height(&self) -> u32 { self.height }
    pub(crate) fn chainwork(&self) -> ChainWork { self.chainwork }

    pub(crate) fn accept_header(&mut self, header: &BlockHeader, now_secs: u32, mode: HeaderValidationMode) -> Result<(), HeaderContextError> {
        super::validate_pow(header, Hash256::from(header.compute_hash()), self.network)?;
        self.accept_contextual_header(header, now_secs, mode)
    }

    #[expect(clippy::expect_used, reason = "timestamp ring indices are bounded by eleven")]
    pub(crate) fn encode_snapshot(&self) -> [u8; HEADER_CONTEXT_SNAPSHOT_LEN] {
        let mut encoded = [0_u8; HEADER_CONTEXT_SNAPSHOT_LEN];
        encoded[..80].copy_from_slice(&self.parent.to_bytes());
        encoded[80..84].copy_from_slice(&self.height.to_le_bytes());
        encoded[84..116].copy_from_slice(&self.chainwork.to_le_bytes::<32>());
        for (slot, time) in encoded[116..160].chunks_exact_mut(4).zip(self.times) {
            slot.copy_from_slice(&time.to_le_bytes());
        }
        encoded[160] = u8::try_from(self.time_count).expect("timestamp count is at most eleven");
        encoded[161] = u8::try_from(self.next_time).expect("timestamp index is below eleven");
        encoded[162..166].copy_from_slice(&self.period_anchor.time.to_le_bytes());
        encoded[166..170].copy_from_slice(&self.period_anchor.bits.to_le_bytes());
        encoded[170..174].copy_from_slice(&self.last_nonminimum_bits.to_le_bytes());
        encoded
    }

    pub(crate) fn decode_snapshot(network: Network, encoded: &[u8; HEADER_CONTEXT_SNAPSHOT_LEN]) -> Result<Self, HeaderContextError> {
        let parent = deserialize::<BlockHeader>(&encoded[..80])?;
        let height = u32::from_le_bytes(snapshot_array(encoded, 80));
        let chainwork = ChainWork::from_le_bytes(snapshot_array::<32>(encoded, 84));
        let mut times = [0_u32; 11];
        for (index, time) in times.iter_mut().enumerate() {
            *time = u32::from_le_bytes(snapshot_array(encoded, 116 + 4 * index));
        }
        let time_count = usize::from(encoded[160]);
        let next_time = usize::from(encoded[161]);
        if u32::from(encoded[160]) != height.saturating_add(1).min(11)
            || next_time >= times.len()
            || (time_count < times.len() && next_time != time_count)
        {
            return Err(HeaderContextError::InvalidSnapshot);
        }
        let last_time = if next_time == 0 { times.len() - 1 } else { next_time - 1 };
        if times[last_time] != parent.time || chainwork < super::block_work(&parent) {
            return Err(HeaderContextError::InvalidSnapshot);
        }
        let period_anchor = super::RetargetAnchor {
            time: u32::from_le_bytes(snapshot_array(encoded, 162)),
            bits: CompactTarget::from_consensus(u32::from_le_bytes(snapshot_array(encoded, 166))),
        };
        let last_nonminimum_bits = CompactTarget::from_consensus(u32::from_le_bytes(snapshot_array(encoded, 170)));
        for bits in [parent.bits, period_anchor.bits, last_nonminimum_bits] {
            let target = super::compact_to_target(bits);
            if super::pow::compact_overflows(bits) || target == ChainWork::ZERO || target > network.max_target() {
                return Err(HeaderContextError::InvalidSnapshot);
            }
        }
        Ok(Self { network, parent, height, chainwork, times, time_count, next_time, period_anchor, last_nonminimum_bits })
    }
}

fn snapshot_array<const N: usize>(encoded: &[u8; HEADER_CONTEXT_SNAPSHOT_LEN], start: usize) -> [u8; N] {
    let mut result = [0_u8; N];
    result.copy_from_slice(&encoded[start..start + N]);
    result
}

#[cfg(test)]
mod tests {
    use super::{HeaderContextError, HeaderValidationContext};
    use crate::chain::header_sync::{HeaderValidationMode, accept_headers, fixture::mine_regtest};
    use crate::chain::{BlockTree, ChainError};
    use bitcoin_rs_consensus::primitives::{CompactTarget, Hash256, Network};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Context(#[from] HeaderContextError),
        #[error(transparent)]
        Chain(#[from] ChainError),
    }

    // P2P-10, RCV-03
    #[test]
    fn restored_context_retains_header_validation_and_rejects_invalid_ring_state() -> Result<(), TestError> {
        let network = Network::Regtest;
        let genesis = network.genesis_block().header;
        let mut tree = BlockTree::new();
        let root = accept_headers(&mut tree, &[genesis], network, 0, HeaderValidationMode::HistoricalReplay)?.ids[0];
        let mut context = HeaderValidationContext::from_tree(&tree, root, network)?;
        for height in 1..=24_u32 {
            context = HeaderValidationContext::decode_snapshot(network, &context.encode_snapshot())?;
            let header = mine_regtest(context.header().compute_hash(), height, genesis.time + height * 600, 4);
            context.accept_header(&header, 0, HeaderValidationMode::HistoricalReplay)?;
            let accepted = accept_headers(&mut tree, &[header], network, 0, HeaderValidationMode::HistoricalReplay)?;
            let node = tree.node(accepted.ids[0])?;
            assert_eq!(context.hash(), Hash256::from(header.compute_hash()));
            assert_eq!(context.height(), node.height);
            assert_eq!(context.chainwork(), node.chainwork);
        }
        for (offset, value) in [(160, 0), (160, 12), (161, 11)] {
            let mut encoded = context.encode_snapshot();
            encoded[offset] = value;
            assert_eq!(HeaderValidationContext::decode_snapshot(network, &encoded), Err(HeaderContextError::InvalidSnapshot));
        }
        let before = context.clone();
        let mut invalid = mine_regtest(context.header().compute_hash(), 25, genesis.time + 25 * 600, 4);
        invalid.bits = CompactTarget::from_consensus(0);
        assert!(matches!(context.accept_header(&invalid, 0, HeaderValidationMode::HistoricalReplay), Err(HeaderContextError::Chain(ChainError::ZeroTarget { .. }))));
        assert_eq!(context, before);
        Ok(())
    }
}
