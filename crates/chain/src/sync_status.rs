//! The one owner of the node's chain-synchronization status.
//!
//! Every externally visible surface that reports how far the node has
//! synced — `getblockchaininfo`, the embedded `Node::sync_progress`, and
//! the operator's periodic `sync progress` log line — derives its fields
//! from one [`SyncStatus`] observed here. They may present the same fact
//! differently (JSON, typed struct, log fields) but none of them defines
//! "in initial block download" or "verification progress" on its own.
//!
//! This mirrors where Bitcoin Core keeps the same decisions:
//! `IsInitialBlockDownload` and `GuessVerificationProgress` live in
//! `validation.cpp` beside the chainstate, not in the RPC layer.

use core::sync::atomic::{AtomicBool, Ordering};

use bitcoin_rs_primitives::{Hash256, Network};

use crate::node::ChainWork;
use crate::tip::TipSnapshot;
use crate::tree::BlockTree;

/// How stale the applied tip may be while the node still counts as synced:
/// Bitcoin Core's `-maxtipage` default of 24 hours.
pub const MAX_TIP_AGE_SECONDS: u64 = 24 * 60 * 60;

/// Window inside which Core distrusts the miner-set tip timestamp and
/// estimates the tip's age from the header chain instead.
const RECENT_TIP_WINDOW_SECONDS: i64 = 2 * 60 * 60;

/// Whether this node has ever observed itself to be out of initial block
/// download. Once set it is never cleared.
///
/// Bitcoin Core latches the same way (`m_cached_is_ibd`, cleared once by
/// `UpdateIBDStatus` and never set again). Without the latch the answer
/// oscillates: a synced node that has not seen a block for longer than the
/// tip-age window would announce that it is back in initial sync, and
/// callers treat that as "do not trust this node's data yet".
///
/// One latch per chainstate: the apply path, the RPC context, and the sync
/// orchestrator share the same instance so they cannot disagree about it.
#[derive(Debug, Default)]
pub struct IbdLatch {
    left: AtomicBool,
}

impl IbdLatch {
    /// A latch that has not yet observed the node leaving initial sync.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            left: AtomicBool::new(false),
        }
    }

    /// Whether the node has already been observed out of initial block download.
    #[must_use]
    pub fn has_left(&self) -> bool {
        self.left.load(Ordering::Relaxed)
    }

    fn mark_left(&self) {
        self.left.store(true, Ordering::Relaxed);
    }
}

/// Everything one synchronization-status observation reads.
///
/// The caller owns the locks and clocks: it loads both tip snapshots, holds
/// the block-tree read guard, reads the cumulative transaction counter, and
/// supplies `now`, so the decision itself is a pure function of observable
/// state and the latch.
#[derive(Clone, Copy)]
pub struct SyncInputs<'a> {
    /// Consensus network, for its minimum chain work and chain-tx data.
    pub network: Network,
    /// Best header-chain tip, `None` before the first header.
    pub chain_tip: Option<&'a TipSnapshot>,
    /// Best fully applied tip, `None` before the first applied block.
    pub applied_tip: Option<&'a TipSnapshot>,
    /// Block tree holding the applied tip's header and ancestry.
    pub tree: &'a BlockTree,
    /// Cumulative transaction count of the applied chain, `0` when unknown
    /// (Bitcoin Core's `HaveNumChainTxs() == false`).
    pub chain_tx_count: u64,
    /// The chainstate's shared initial-block-download latch.
    pub ibd_latch: &'a IbdLatch,
    /// UNIX seconds now.
    pub now: u64,
}

/// One coherent observation of chain-synchronization status.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncStatus {
    /// Height of the best fully applied block; `0` before the first.
    pub applied_height: u32,
    /// Height of the best validated header; `0` before the first.
    pub header_height: u32,
    /// Hash of the best fully applied block; all-zero before the first.
    pub best_block_hash: Hash256,
    /// Accumulated work through the applied tip; `None` before the first
    /// applied block.
    pub chainwork: Option<ChainWork>,
    /// Compact target of the applied tip's header; `0` before the first.
    pub tip_bits: u32,
    /// Difficulty of the applied tip, by Bitcoin Core's `GetDifficulty`.
    pub difficulty: f64,
    /// Applied tip header timestamp, UNIX seconds; `0` before the first.
    pub tip_time: u64,
    /// Median time past of the last eleven applied blocks; `0` before the first.
    pub median_time_past: u64,
    /// Bitcoin Core's `GuessVerificationProgress` in `[0, 1]`.
    pub verification_progress: f64,
    /// Whether the node is still in initial block download.
    pub initial_block_download: bool,
}

impl SyncStatus {
    /// Observes the current synchronization status.
    ///
    /// Leaving initial block download is recorded in the caller's
    /// [`IbdLatch`], so a later observation of a quiet node keeps reporting
    /// `initial_block_download: false`.
    #[must_use]
    pub fn observe(inputs: SyncInputs<'_>) -> Self {
        let SyncInputs {
            network,
            chain_tip,
            applied_tip,
            tree,
            chain_tx_count,
            ibd_latch,
            now,
        } = inputs;
        let applied_height = applied_tip.map_or(0, |tip| tip.height);
        let header_height = chain_tip.map_or(0, |tip| tip.height);
        let applied_node = applied_tip.and_then(|tip| tree.node(tip.tip_id).ok());
        let (tip_bits, tip_time, median_time_past) = match (applied_tip, applied_node) {
            (Some(tip), Some(node)) => (
                node.header.bits,
                u64::from(node.header.time),
                u64::from(tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0)),
            ),
            _ => (0, 0, 0),
        };
        let initial_block_download = is_initial_block_download(
            network,
            applied_tip,
            applied_node.map(|node| u64::from(node.header.time)),
            ibd_latch,
            now,
        );
        Self {
            applied_height,
            header_height,
            best_block_hash: applied_tip.map_or_else(Hash256::default, |tip| tip.hash),
            chainwork: applied_tip.map(|tip| tip.chainwork),
            tip_bits,
            difficulty: difficulty_for_bits(tip_bits),
            tip_time,
            median_time_past,
            verification_progress: verification_progress(
                network,
                chain_tx_count,
                applied_height,
                header_height,
                tip_time,
                now,
            ),
            initial_block_download,
        }
    }

    /// Headers known but not yet applied.
    #[must_use]
    pub const fn gap(&self) -> u32 {
        self.header_height.saturating_sub(self.applied_height)
    }

    /// Applied chain work as 64 lowercase big-endian hex digits, or `"00"`
    /// before the first applied block (`bitcoind`'s pre-genesis spelling).
    #[must_use]
    pub fn chainwork_hex(&self) -> String {
        use core::fmt::Write as _;

        let Some(chainwork) = self.chainwork else {
            return "00".to_owned();
        };
        let bytes: [u8; 32] = chainwork.to_be_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }
}

/// Bitcoin Core's `IsInitialBlockDownload()` for the applied tip.
///
/// A node has left initial block download once its applied tip has at least
/// the network's `nMinimumChainWork` **and** carries a timestamp no older
/// than [`MAX_TIP_AGE_SECONDS`]. Both are required: work alone would trust a
/// stale chain, and recency alone would trust a cheap one that simply claims
/// a recent timestamp. A tip whose header the tree cannot resolve has no age
/// to judge and stays in initial sync.
fn is_initial_block_download(
    network: Network,
    applied_tip: Option<&TipSnapshot>,
    tip_time: Option<u64>,
    latch: &IbdLatch,
    now: u64,
) -> bool {
    if latch.has_left() {
        return false;
    }
    let Some(tip) = applied_tip else {
        return true;
    };
    // Big-endian, fixed width: byte order is numeric order.
    let work: [u8; 32] = tip.chainwork.to_be_bytes();
    if work < network.minimum_chain_work() {
        return true;
    }
    let Some(tip_time) = tip_time else {
        return true;
    };
    if tip_time < now.saturating_sub(MAX_TIP_AGE_SECONDS) {
        return true;
    }
    latch.mark_left();
    false
}

/// Bitcoin Core's `GuessVerificationProgress`, as a fraction in `[0, 1]`.
///
/// The quantity is **transactions verified over transactions believed to
/// exist** — not a ratio of heights. Early blocks are nearly empty, so a
/// height ratio reports the chain as most of the way done while most of the
/// work is still ahead; Core moved off height for that reason.
///
/// The denominator cannot be known, so it is extrapolated from the network's
/// pinned `ChainTxData` observation at `tx_rate` transactions per second.
/// When the node is already past that observation its own count is used as
/// the baseline instead, which keeps the fraction from sticking at 1.0.
///
/// `tip_time` is the applied tip's block timestamp. When the tip is within
/// two hours of `now`, Core stops trusting that miner-set timestamp and
/// estimates the tip's age from how many blocks the header chain is ahead
/// instead — which also quantizes the answer near 1.0, where people expect
/// to see it settle.
///
/// A `chain_tx_count` of `0` means the count is unknown: a datadir written
/// before the node tracked it, which nothing short of re-reading every block
/// body could recover. Those chains keep the height ratio they have always
/// reported rather than being told a confident `0.0`.
fn verification_progress(
    network: Network,
    chain_tx_count: u64,
    applied_height: u32,
    header_height: u32,
    tip_time: u64,
    now: u64,
) -> f64 {
    if chain_tx_count == 0 {
        return height_ratio(applied_height, header_height);
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
        // Past it, so this node's own count is the better baseline.
        let elapsed = now_signed.saturating_sub(block_time);
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(chain_tx_count))
    };
    if total <= 0.0 {
        return 0.0;
    }
    (u64_to_f64(chain_tx_count) / total).clamp(0.0, 1.0)
}

/// Applied over header height, clamped into `[0, 1]`; `0.0` without headers.
fn height_ratio(applied_height: u32, header_height: u32) -> f64 {
    if header_height == 0 {
        0.0
    } else {
        (f64::from(applied_height) / f64::from(header_height)).min(1.0)
    }
}

/// Bitcoin Core's `GetDifficulty` for a compact target.
///
/// Keep the operation order in sync with Core: changing the repeated 256
/// scaling into an equivalent exponentiation can change the final
/// floating-point bit.
#[must_use]
pub fn difficulty_for_bits(bits: u32) -> f64 {
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 {
        return 0.0;
    }
    let mut shift = (bits >> 24) & 0xff;
    let mut difficulty = f64::from(0x0000_ffff_u32) / f64::from(mantissa);
    while shift < 29 {
        difficulty *= 256.0;
        shift += 1;
    }
    while shift > 29 {
        difficulty /= 256.0;
        shift -= 1;
    }
    difficulty
}

/// `u64` to `f64` without a silent `as` cast, which this workspace forbids.
///
/// Exact for every input up to `2^53`; above that the low half rounds, which
/// is inherent to `f64` and is what Bitcoin Core accepts here too.
fn u64_to_f64(value: u64) -> f64 {
    const TWO_POW_32: f64 = 4_294_967_296.0;

    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX);
    f64::from(high).mul_add(TWO_POW_32, f64::from(low))
}

/// [`u64_to_f64`] with a sign; the elapsed times here can run either way.
fn i64_to_f64(value: i64) -> f64 {
    let magnitude = u64_to_f64(value.unsigned_abs());
    if value < 0 { -magnitude } else { magnitude }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use bitcoin_rs_primitives::{BlockHash, Header};

    use super::*;
    use crate::node::{NodeId, NodeStatus};

    const DAY: u64 = 24 * 60 * 60;
    const NOW: u64 = 1_800_000_000;

    fn header(prev: BlockHash, time: u32, nonce: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: 0x207f_ffff,
            nonce,
        }
    }

    /// A two-block tree whose applied tip is stamped `tip_time`, so the tip
    /// has an age to be judged on. Chain work comes from the tree's own
    /// accounting, which for a two-block regtest-difficulty chain is far
    /// below any production `nMinimumChainWork` — hence the network
    /// parameter: regtest pins that floor at zero, mainnet does not.
    fn tree_with_tip_at(tip_time: u32) -> (BlockTree, TipSnapshot) {
        let mut tree = BlockTree::new();
        let genesis = header(BlockHash::default(), 1_000_000, 0);
        let genesis_id = tree
            .insert_node(None, genesis, NodeStatus::Active)
            .expect("genesis");
        let child = header(genesis.compute_hash(), tip_time, 1);
        tree.insert_node(Some(genesis_id), child, NodeStatus::Active)
            .expect("child");
        let tip = (*tree.tip().expect("tip")).clone();
        (tree, tip)
    }

    fn observe_ibd(
        network: Network,
        tree: &BlockTree,
        tip: &TipSnapshot,
        latch: &IbdLatch,
        now: u64,
    ) -> bool {
        SyncStatus::observe(SyncInputs {
            network,
            chain_tip: Some(tip),
            applied_tip: Some(tip),
            tree,
            chain_tx_count: 0,
            ibd_latch: latch,
            now,
        })
        .initial_block_download
    }

    fn at(now: u64) -> u32 {
        u32::try_from(now).unwrap_or(u32::MAX)
    }

    #[test]
    fn a_node_that_has_applied_nothing_is_in_initial_block_download() {
        let status = SyncStatus::observe(SyncInputs {
            network: Network::Regtest,
            chain_tip: None,
            applied_tip: None,
            tree: &BlockTree::new(),
            chain_tx_count: 0,
            ibd_latch: &IbdLatch::new(),
            now: NOW,
        });
        assert!(status.initial_block_download);
        assert_eq!(status.chainwork, None);
        assert_eq!(status.chainwork_hex(), "00");
        assert_eq!(status.best_block_hash, Hash256::default());
        assert!(status.verification_progress.abs() < f64::EPSILON);
    }

    #[test]
    fn a_recent_tip_without_the_networks_minimum_work_is_still_initial_block_download() {
        // Timestamped one minute ago, so recency is satisfied and only the
        // work floor can be what decides.
        let (tree, tip) = tree_with_tip_at(at(NOW - 60));
        assert!(
            observe_ibd(Network::Mainnet, &tree, &tip, &IbdLatch::new(), NOW),
            "a chain this cheap must not count as synced merely for being recent"
        );
    }

    #[test]
    fn a_stale_tip_with_enough_work_is_still_initial_block_download() {
        // Regtest's work floor is zero, so only the tip's age is left to decide.
        let (tree, tip) = tree_with_tip_at(at(NOW - DAY - 60));
        assert!(observe_ibd(
            Network::Regtest,
            &tree,
            &tip,
            &IbdLatch::new(),
            NOW
        ));
    }

    #[test]
    fn a_recent_tip_with_enough_work_has_left_initial_block_download() {
        let (tree, tip) = tree_with_tip_at(at(NOW - 60));
        let latch = IbdLatch::new();
        assert!(!observe_ibd(Network::Regtest, &tree, &tip, &latch, NOW));
        assert!(latch.has_left());
    }

    #[test]
    fn the_tip_age_boundary_is_twenty_four_hours() {
        let (tree, tip) = tree_with_tip_at(at(NOW - DAY));
        assert!(
            !observe_ibd(Network::Regtest, &tree, &tip, &IbdLatch::new(), NOW),
            "exactly `max_tip_age` old is still recent enough"
        );
        let (tree, tip) = tree_with_tip_at(at(NOW - DAY - 1));
        assert!(observe_ibd(
            Network::Regtest,
            &tree,
            &tip,
            &IbdLatch::new(),
            NOW
        ));
    }

    #[test]
    fn leaving_initial_block_download_latches() {
        let (tree, tip) = tree_with_tip_at(at(NOW - 60));
        let latch = IbdLatch::new();
        assert!(!observe_ibd(Network::Regtest, &tree, &tip, &latch, NOW));
        // Two days later, with no new block. Judged afresh the tip is stale
        // and the answer would flip back to `true`; latched, it does not.
        assert!(
            !observe_ibd(Network::Regtest, &tree, &tip, &latch, NOW + 2 * DAY),
            "the answer must not flip back once the node has left initial sync"
        );
    }

    #[test]
    fn the_latch_does_not_fire_before_the_conditions_are_met() {
        let (tree, tip) = tree_with_tip_at(at(NOW - DAY - 60));
        let latch = IbdLatch::new();
        assert!(observe_ibd(Network::Regtest, &tree, &tip, &latch, NOW));
        assert!(!latch.has_left());
        // Same tip, asked at a time when it *is* within the window.
        assert!(!observe_ibd(
            Network::Regtest,
            &tree,
            &tip,
            &latch,
            NOW - DAY
        ));
    }

    #[test]
    fn a_header_lead_alone_does_not_define_initial_block_download() {
        // The operator log used to say `ibd = headers > applied`. A synced
        // node one block behind the header tip is not in initial sync by
        // Core's definition, and every surface must agree on that.
        let (tree, tip) = tree_with_tip_at(at(NOW - 60));
        let header_tip = TipSnapshot {
            height: tip.height + 1,
            tip_id: tip.tip_id,
            chainwork: tip.chainwork,
            hash: tip.hash,
        };
        let status = SyncStatus::observe(SyncInputs {
            network: Network::Regtest,
            chain_tip: Some(&header_tip),
            applied_tip: Some(&tip),
            tree: &tree,
            chain_tx_count: 0,
            ibd_latch: &IbdLatch::new(),
            now: NOW,
        });
        assert_eq!(status.gap(), 1);
        assert!(!status.initial_block_download);
    }

    #[test]
    fn status_reports_the_applied_tip_not_the_header_tip() {
        let (tree, applied) = tree_with_tip_at(at(NOW - 60));
        let header_tip = TipSnapshot {
            tip_id: applied.tip_id,
            height: 99,
            chainwork: ChainWork::from_be_bytes([2; 32]),
            hash: Hash256::from_le_bytes(&[9; 32]),
        };
        let applied = TipSnapshot {
            chainwork: ChainWork::from_be_bytes([1; 32]),
            ..applied
        };
        let status = SyncStatus::observe(SyncInputs {
            network: Network::Regtest,
            chain_tip: Some(&header_tip),
            applied_tip: Some(&applied),
            tree: &tree,
            chain_tx_count: 0,
            ibd_latch: &IbdLatch::new(),
            now: NOW,
        });
        assert_eq!(status.applied_height, 1);
        assert_eq!(status.header_height, 99);
        assert_eq!(status.best_block_hash, applied.hash);
        assert_eq!(status.chainwork_hex(), "01".repeat(32));
        assert_eq!(status.tip_bits, 0x207f_ffff);
        assert_eq!(status.tip_time, NOW - 60);
        // Two-block window: the upper median of {1_000_000, NOW - 60}.
        assert_eq!(status.median_time_past, NOW - 60);
    }

    #[test]
    fn a_tip_missing_from_the_tree_has_no_age_and_stays_in_initial_sync() {
        let phantom = TipSnapshot {
            tip_id: NodeId::new(7),
            height: 5,
            chainwork: ChainWork::from_be_bytes([0xff; 32]),
            hash: Hash256::from_le_bytes(&[1; 32]),
        };
        let status = SyncStatus::observe(SyncInputs {
            network: Network::Regtest,
            chain_tip: Some(&phantom),
            applied_tip: Some(&phantom),
            tree: &BlockTree::new(),
            chain_tx_count: 0,
            ibd_latch: &IbdLatch::new(),
            now: NOW,
        });
        assert!(status.initial_block_download);
        assert_eq!(
            (status.tip_bits, status.tip_time, status.median_time_past),
            (0, 0, 0)
        );
    }

    /// Regtest's pinned observation is `{time: 0, tx_count: 0, tx_rate: 0.001}`,
    /// so the estimate reduces to arithmetic that can be done by hand:
    /// `total = verified + elapsed * 0.001`.
    #[test]
    fn verification_progress_is_transactions_verified_over_transactions_estimated() {
        // Ten thousand seconds behind, outside the two-hour window, so the
        // tip's own timestamp is the one used: 100 / (100 + 10_000 * 0.001).
        let progress = verification_progress(Network::Regtest, 100, 9, 9, NOW - 10_000, NOW);
        assert!(
            (progress - (100.0 / 110.0)).abs() < 1e-12,
            "expected 100/110, got {progress}"
        );
    }

    #[test]
    fn verification_progress_is_not_the_height_ratio_it_replaced() {
        // Half the headers applied, on a mainnet whose pinned observation
        // counts more than a billion transactions.
        let progress = verification_progress(Network::Mainnet, 5_000, 50, 100, NOW - 10_000, NOW);
        assert!(
            progress < 0.001,
            "50 blocks of a 1.3-billion-transaction chain is not half of it, got {progress}"
        );
    }

    #[test]
    fn verification_progress_ignores_the_tip_timestamp_when_the_tip_is_recent() {
        // Both inside the two-hour window: Core derives the tip's age from
        // the header chain there, so these must agree despite an hour apart.
        let a = verification_progress(Network::Regtest, 100, 9, 10, NOW - 60, NOW);
        let b = verification_progress(Network::Regtest, 100, 9, 10, NOW - 3_600, NOW);
        let boundary = verification_progress(Network::Regtest, 100, 9, 10, NOW - 2 * 60 * 60, NOW);
        assert!((a - b).abs() < 1e-12, "{a} != {b}");
        assert!(
            (a - boundary).abs() < 1e-12,
            "Core includes the exact two-hour boundary: {a} != {boundary}"
        );
        // Outside the window the timestamp is used again, so this one differs.
        let outside = verification_progress(Network::Regtest, 100, 9, 10, NOW - 100_000, NOW);
        assert!(outside < a, "{outside} should trail {a}");
    }

    #[test]
    fn an_unknown_count_keeps_the_height_ratio_rather_than_reporting_zero() {
        assert!((verification_progress(Network::Mainnet, 0, 50, 100, 0, NOW) - 0.5).abs() < 1e-12);
        assert!(verification_progress(Network::Mainnet, 0, 0, 0, 0, NOW).abs() < f64::EPSILON);
        assert!(
            (verification_progress(Network::Mainnet, 0, 100, 50, 0, NOW) - 1.0).abs()
                < f64::EPSILON,
            "an applied tip temporarily above the header tip is capped at 1.0"
        );
    }

    #[test]
    fn verification_progress_never_exceeds_one_for_a_future_dated_tip() {
        // A miner-set timestamp ahead of our clock by more than the two-hour
        // window, so the tip's own time is used and the elapsed term goes
        // negative — the estimated total lands *below* what this node has
        // already verified. Unclamped that is a progress above 1.0.
        let tip_time = NOW + 10_000;
        let unclamped_total = 10_000.0_f64.mul_add(-0.001, 100.0_f64);
        assert!(
            100.0 / unclamped_total > 1.0,
            "the fixture must actually overshoot, or the clamp is untested"
        );
        let progress = verification_progress(Network::Regtest, 100, 9, 10, tip_time, NOW);
        assert!((progress - 1.0).abs() < f64::EPSILON, "got {progress}");
    }

    #[test]
    fn difficulty_matches_bitcoin_core_for_the_reference_targets() {
        assert!((difficulty_for_bits(0x1d00_ffff) - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            difficulty_for_bits(0x207f_ffff).to_bits(),
            4.656_542_373_906_924_7e-10_f64.to_bits()
        );
        assert!(difficulty_for_bits(0x1d00_0000).abs() < f64::EPSILON);
    }

    #[test]
    fn u64_to_f64_is_exact_below_two_to_the_fifty_third() {
        for value in [
            0_u64,
            1,
            4_294_967_295,
            4_294_967_296,
            1_315_805_869,
            1 << 52,
        ] {
            // Independently derived: the halves recombined by hand.
            let expected = f64::from(u32::try_from(value >> 32).unwrap_or(u32::MAX))
                * 4_294_967_296.0_f64
                + f64::from(u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX));
            assert!(
                (u64_to_f64(value) - expected).abs() < f64::EPSILON,
                "{value}"
            );
        }
    }

    #[test]
    fn i64_to_f64_carries_the_sign() {
        assert!((i64_to_f64(-3_600) + 3_600.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(3_600) - 3_600.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(0) - 0.0).abs() < f64::EPSILON);
    }
}
