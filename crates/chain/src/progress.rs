use std::sync::Arc;

use bitcoin_rs_primitives::{CompactTarget, Hash256, Network, i64_to_f64, u64_to_f64};

use crate::TipSnapshot;
use crate::ibd::InitialBlockDownload;
use crate::node::ChainWork;
use crate::view::{BlockTreeReader, TipReader};

#[derive(Clone, Debug, PartialEq)]
pub struct ChainProgress {
    pub blocks: u32,
    pub headers: u32,
    pub best_block_hash: Hash256,
    pub bits: Option<CompactTarget>,
    pub time: u64,
    pub median_time: u64,
    pub verification_progress: f64,
    pub initial_block_download: bool,
    pub chain_work: Option<ChainWork>,
}

#[derive(Clone)]
pub struct ChainProgressReader {
    header_tip: TipReader,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    ibd: Arc<InitialBlockDownload>,
}

impl ChainProgressReader {
    #[must_use]
    pub const fn new(
        header_tip: TipReader,
        applied_tip: TipReader,
        block_tree: BlockTreeReader,
        ibd: Arc<InitialBlockDownload>,
    ) -> Self {
        Self {
            header_tip,
            applied_tip,
            block_tree,
            ibd,
        }
    }

    #[must_use]
    pub fn initial_block_download(&self, now: u64, network: Network) -> bool {
        self.ibd.is_active(now, network)
    }

    #[must_use]
    pub fn progress(&self, network: Network, now: u64) -> ChainProgress {
        self.progress_at(self.applied_tip.load_full().as_deref(), network, now)
    }

    #[must_use]
    pub fn progress_at(
        &self,
        applied: Option<&TipSnapshot>,
        network: Network,
        now: u64,
    ) -> ChainProgress {
        let header_tip = self.header_tip.load_full();
        let blocks = applied.map_or(0, |tip| tip.height);
        let headers = header_tip.as_ref().map_or(0, |tip| tip.height);
        let (bits, time, median_time) = applied
            .and_then(|tip| {
                let tree = self.block_tree.read();
                let node = tree.node(tip.tip_id).ok()?;
                Some((
                    Some(node.header.bits),
                    u64::from(node.header.time),
                    u64::from(tree.median_time_past_at(tip.tip_id).unwrap_or(0)),
                ))
            })
            .unwrap_or((None, 0, 0));
        let verification_progress = applied
            .and_then(|tip| tip.chain_tx_count.get())
            .map_or_else(
                || {
                    if headers > 0 {
                        (f64::from(blocks) / f64::from(headers)).min(1.0)
                    } else {
                        0.0
                    }
                },
                |chain_tx_count| {
                    verification_progress(network, chain_tx_count, blocks, headers, time, now)
                },
            );
        ChainProgress {
            blocks,
            headers,
            best_block_hash: applied.map_or_else(|| network.genesis_block_hash(), |tip| tip.hash),
            bits,
            time,
            median_time,
            verification_progress,
            initial_block_download: self.ibd.is_active(now, network),
            chain_work: applied.or(header_tip.as_deref()).map(|tip| tip.chainwork),
        }
    }
}

fn verification_progress(
    network: Network,
    chain_tx_count: u64,
    applied_height: u32,
    header_height: u32,
    tip_time: u64,
    now: u64,
) -> f64 {
    const RECENT_TIP_WINDOW_SECONDS: i64 = 2 * 60 * 60;

    if chain_tx_count == 0 {
        return 0.0;
    }
    let data = network.chain_tx_data();

    let now_signed = i64::try_from(now).unwrap_or(i64::MAX);
    let tip_time_signed = i64::try_from(tip_time).unwrap_or(i64::MAX);
    let block_time = if (now_signed - tip_time_signed).abs() <= RECENT_TIP_WINDOW_SECONDS
        && header_height >= applied_height
    {
        let behind = i64::from(header_height - applied_height);
        let spacing = i64::from(network.target_spacing_seconds());
        now_signed.saturating_sub(behind.saturating_mul(spacing))
    } else {
        tip_time_signed
    };

    let total = if chain_tx_count <= data.tx_count {
        let elapsed = now_signed.saturating_sub(i64::try_from(data.time).unwrap_or(i64::MAX));
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(data.tx_count))
    } else {
        let elapsed = now_signed.saturating_sub(block_time);
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(chain_tx_count))
    };
    if total <= 0.0 {
        return 0.0;
    }
    (u64_to_f64(chain_tx_count) / total).clamp(0.0, 1.0)
}

#[cfg(test)]
mod reader_tests {
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin_rs_primitives::{Hash256, Network};
    use parking_lot::RwLock;

    use super::ChainProgressReader;
    use crate::{
        BlockTree, BlockTreeReader, ChainTxCount, ChainWork, InitialBlockDownload, NodeId,
        TipReader, TipSnapshot,
    };

    fn reader() -> (ChainProgressReader, TipReader, TipReader) {
        let header = TipReader::new(Arc::new(ArcSwapOption::empty()));
        let applied = TipReader::new(Arc::new(ArcSwapOption::empty()));
        let tree = BlockTreeReader::new(Arc::new(RwLock::new(BlockTree::new())));
        let ibd = Arc::new(InitialBlockDownload::new(applied.clone(), tree.clone()));
        let reader = ChainProgressReader::new(header.clone(), applied.clone(), tree, ibd);
        (reader, header, applied)
    }

    fn tip(height: u32, work: u64, count: ChainTxCount) -> Arc<TipSnapshot> {
        Arc::new(TipSnapshot {
            tip_id: NodeId::new(0),
            height,
            chainwork: ChainWork::from(work),
            hash: Hash256::from_le_bytes(&[7; 32]),
            chain_tx_count: count,
        })
    }

    #[test]
    fn an_empty_chain_reports_genesis_and_no_work() {
        let (reader, _, _) = reader();
        let progress = reader.progress(Network::Regtest, 1_800_000_000);
        assert_eq!((progress.blocks, progress.headers), (0, 0));
        assert_eq!(
            progress.best_block_hash,
            Network::Regtest.genesis_block_hash()
        );
        assert_eq!((progress.bits, progress.chain_work), (None, None));
        assert!(progress.verification_progress.abs() < f64::EPSILON);
        assert!(progress.initial_block_download);
    }

    #[test]
    fn before_the_first_applied_tip_the_header_chain_supplies_the_work() {
        let (reader, header, _) = reader();
        header.store(Some(tip(5, 9, ChainTxCount::UNKNOWN)));
        let progress = reader.progress(Network::Regtest, 1_800_000_000);
        assert_eq!((progress.blocks, progress.headers), (0, 5));
        assert_eq!(progress.chain_work, Some(ChainWork::from(9_u64)));
    }

    #[test]
    fn an_unknown_count_reports_the_height_ratio_at_the_retained_snapshot() {
        let (reader, header, applied) = reader();
        header.store(Some(tip(100, 9, ChainTxCount::UNKNOWN)));
        let retained = tip(50, 7, ChainTxCount::UNKNOWN);
        applied.store(Some(tip(60, 8, ChainTxCount::UNKNOWN)));
        let progress = reader.progress_at(Some(retained.as_ref()), Network::Regtest, 1_800_000_000);
        assert_eq!(
            progress.blocks, 50,
            "the retained snapshot, not the newer one"
        );
        assert_eq!(progress.chain_work, Some(ChainWork::from(7_u64)));
        assert!((progress.verification_progress - 0.5).abs() < 1e-12);
    }
}

#[cfg(test)]
mod verification_progress_tests {
    use super::verification_progress;
    use bitcoin_rs_primitives::Network;

    #[test]
    fn verification_progress_is_transactions_verified_over_transactions_estimated() {
        let now = 1_800_000_000_u64;
        let tip_time = now - 10_000;

        let progress = verification_progress(Network::Regtest, 100, 9, 9, tip_time, now);
        assert!(
            (progress - (100.0 / 110.0)).abs() < 1e-12,
            "expected 100/110, got {progress}"
        );
    }

    #[test]
    fn verification_progress_is_not_the_height_ratio_it_replaced() {
        let now = 1_800_000_000_u64;
        let progress = verification_progress(Network::Mainnet, 5_000, 50, 100, now - 10_000, now);
        assert!(
            progress < 0.001,
            "50 blocks of a 1.3-billion-transaction chain is not half of it, got {progress}"
        );
    }

    #[test]
    fn verification_progress_ignores_the_tip_timestamp_when_the_tip_is_recent() {
        let now = 1_800_000_000_u64;
        let a = verification_progress(Network::Regtest, 100, 9, 10, now - 60, now);
        let b = verification_progress(Network::Regtest, 100, 9, 10, now - 3_600, now);
        let boundary = verification_progress(Network::Regtest, 100, 9, 10, now - 2 * 60 * 60, now);
        assert!((a - b).abs() < 1e-12, "{a} != {b}");
        assert!(
            (a - boundary).abs() < 1e-12,
            "Core includes the exact two-hour boundary: {a} != {boundary}"
        );

        let outside = verification_progress(Network::Regtest, 100, 9, 10, now - 100_000, now);
        assert!(outside < a, "{outside} should trail {a}");
    }

    #[test]
    fn verification_progress_is_zero_before_anything_is_verified() {
        assert!(
            (verification_progress(Network::Mainnet, 0, 0, 0, 0, 1_800_000_000) - 0.0).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn verification_progress_never_exceeds_one_for_a_future_dated_tip() {
        let now = 1_800_000_000_u64;
        let tip_time = now + 10_000;
        let unclamped_total = 10_000.0_f64.mul_add(-0.001, 100.0_f64);
        assert!(
            100.0 / unclamped_total > 1.0,
            "the fixture must actually overshoot, or the clamp is untested"
        );

        let progress = verification_progress(Network::Regtest, 100, 9, 10, tip_time, now);
        assert!((progress - 1.0).abs() < f64::EPSILON, "got {progress}");
    }
}
