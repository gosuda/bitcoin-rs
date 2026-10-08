//! Synchronization progress of the applied chain.
//!
//! Like the initial-block-download latch beside it, progress is chain state:
//! [`ChainProgressReader`] derives it from the node's published tips and block
//! tree, so `getblockchaininfo` and the embedding API report it without
//! rebuilding it from those handles. Bitcoin Core derives the same facts from
//! its `ChainstateManager`.

use std::sync::Arc;

use bitcoin_rs_primitives::{CompactTarget, Hash256, Network, i64_to_f64, u64_to_f64};

use crate::ibd::InitialBlockDownload;
use crate::node::ChainWork;
use crate::tip::TipSnapshot;
use crate::view::{BlockTreeReader, TipReader};

/// Chain synchronization facts at one applied publication.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainProgress {
    /// Applied height; `0` before the first applied tip.
    pub blocks: u32,
    /// Header-chain height; may lead `blocks` during sync.
    pub headers: u32,
    /// Applied tip hash, or the network's genesis hash before the first
    /// applied tip.
    pub best_block_hash: Hash256,
    /// The applied tip header's `bits`, `None` without an applied tip.
    pub bits: Option<CompactTarget>,
    /// The applied tip header's timestamp, UNIX seconds; `0` without one.
    pub time: u64,
    /// Median time past at the applied tip; `0` without one.
    pub median_time: u64,
    /// Core `GuessVerificationProgress` in the inclusive range `[0, 1]`.
    pub verification_progress: f64,
    /// The shared [`InitialBlockDownload`] decision.
    pub initial_block_download: bool,
    /// The applied chain's work, or the header chain's before the first
    /// applied tip; `None` with neither.
    pub chain_work: Option<ChainWork>,
}

/// Read-only synchronization progress over the node's chain handles.
///
/// PRE: the readers and the latch are the node's published handles; Chainstate
///   mints this from its own.
/// POST: [`Self::progress_at`] derives every [`ChainProgress`] field from one
///   applied snapshot plus the header tip sampled with it.
/// INVARIANT: holds readers only; it can publish no tip and mutate no tree.
#[derive(Clone)]
pub struct ChainProgressReader {
    header_tip: TipReader,
    applied_tip: TipReader,
    block_tree: BlockTreeReader,
    ibd: Arc<InitialBlockDownload>,
}

impl ChainProgressReader {
    /// Builds the reader over node-owned chain handles.
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

    /// The shared initial-block-download decision at `now` for `network`.
    #[must_use]
    pub fn initial_block_download(&self, now: u64, network: Network) -> bool {
        self.ibd.is_active(now, network)
    }

    /// Progress at the current applied publication.
    #[must_use]
    pub fn progress(&self, network: Network, now: u64) -> ChainProgress {
        self.progress_at(self.applied_tip.load_full().as_deref(), network, now)
    }

    /// Progress at a retained applied snapshot.
    ///
    /// PRE: `applied` is the publication the caller's response is built from;
    ///   `now` is UNIX seconds; `network` is the node's network.
    /// POST: applied fields come from `applied`; the header height and the
    ///   pre-applied chain work come from one header-tip sample, which may lead.
    /// INVARIANT: never reloads the applied publication.
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
        // Core's estimate when the verified-transaction count is known, the
        // height ratio when it is not; `None` is a pre-tracking datadir and
        // means unknown, never zero.
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

/// Bitcoin Core's `GuessVerificationProgress`, as a fraction in `[0, 1]`.
///
/// The quantity is **transactions verified over transactions believed to
/// exist** — not a ratio of heights. Early blocks are nearly empty, so a height
/// ratio reports the chain as most of the way done while most of the work is
/// still ahead; Core moved off height for that reason.
///
/// The denominator cannot be known, so it is extrapolated from the network's
/// pinned [`bitcoin_rs_primitives::ChainTxData`] observation at `tx_rate`
/// transactions per second. When the node is already past that observation its
/// own count is used as the baseline instead, which keeps the fraction from
/// sticking at 1.0 forever.
///
/// `tip_time` is the applied tip's block timestamp. When the tip is within two
/// hours of `now`, Core stops trusting that miner-set timestamp and estimates
/// the tip's age from how many blocks the header chain is ahead instead — which
/// also quantizes the answer near 1.0, where people expect to see it settle.
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
        // Still behind the pinned observation: extrapolate forward from it.
        let elapsed = now_signed.saturating_sub(i64::try_from(data.time).unwrap_or(i64::MAX));
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(data.tx_count))
    } else {
        // Past it, so this node's own count is the better baseline. Without
        // this the fraction would pin at 1.0 and stay there.
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

    /// Regtest's pinned observation is `{time: 0, tx_count: 0, tx_rate: 0.001}`,
    /// so the estimate reduces to arithmetic that can be done by hand:
    /// `total = verified + elapsed * 0.001`.
    #[test]
    fn verification_progress_is_transactions_verified_over_transactions_estimated() {
        let now = 1_800_000_000_u64;
        // Ten thousand seconds behind, which is outside the two-hour window, so
        // the tip's own timestamp is the one used.
        let tip_time = now - 10_000;

        // 100 / (100 + 10_000 * 0.001) = 100 / 110
        let progress = verification_progress(Network::Regtest, 100, 9, 9, tip_time, now);
        assert!(
            (progress - (100.0 / 110.0)).abs() < 1e-12,
            "expected 100/110, got {progress}"
        );
    }

    #[test]
    fn verification_progress_is_not_the_height_ratio_it_replaced() {
        let now = 1_800_000_000_u64;
        // Half the headers applied, on a mainnet whose pinned observation counts
        // more than a billion transactions. The old field said 0.5 here.
        let progress = verification_progress(Network::Mainnet, 5_000, 50, 100, now - 10_000, now);
        assert!(
            progress < 0.001,
            "50 blocks of a 1.3-billion-transaction chain is not half of it, got {progress}"
        );
    }

    #[test]
    fn verification_progress_ignores_the_tip_timestamp_when_the_tip_is_recent() {
        let now = 1_800_000_000_u64;
        // Both inside the two-hour window: Core stops trusting the miner-set
        // timestamp there and derives the tip's age from the header chain, so
        // these must agree despite an hour between them.
        let a = verification_progress(Network::Regtest, 100, 9, 10, now - 60, now);
        let b = verification_progress(Network::Regtest, 100, 9, 10, now - 3_600, now);
        let boundary = verification_progress(Network::Regtest, 100, 9, 10, now - 2 * 60 * 60, now);
        assert!((a - b).abs() < 1e-12, "{a} != {b}");
        assert!(
            (a - boundary).abs() < 1e-12,
            "Core includes the exact two-hour boundary: {a} != {boundary}"
        );

        // Outside the window the timestamp is used again, so this one differs.
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
        // A miner-set timestamp ahead of our clock by more than the two-hour
        // window, so the tip's own time is used and the elapsed term goes
        // negative — the estimated total lands *below* what this node has
        // already verified. Unclamped that is a progress above 1.0.
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
