//! Txindex capability readiness gauge.
//!
//! The gauge reads the same live snapshot the RPC `getcapabilities`
//! projection reads — [`DerivedIndexCapabilitySource`] — and never
//! re-derives what ready, catching up, rebuilding, failed, or disabled
//! means. Each pass writes every outcome label independently, so a scrape
//! that lands between two writes may briefly show zero or two active
//! outcomes; see [`publish_txindex_readiness`] for the scrape caveats.

use alloc::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin_rs_rpc::capabilities::{CapabilityState, DerivedIndexCapabilitySource};

/// Gauge name for the txindex readiness outcome.
pub(crate) const TXINDEX_READINESS_GAUGE: &str = "node.capability.txindex_readiness";

/// How often the sampler republishes the readiness gauge.
const READINESS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Readiness outcomes, spelled exactly as the `getcapabilities` wire
/// rendering of [`CapabilityState`] spells them, so a scraped label and the
/// RPC row for one poll are the same token.
pub(crate) const READINESS_OUTCOMES: [&str; 8] = [
    "Ready",
    "CatchingUp",
    "RollingBack",
    "Rebuilding",
    "Failed",
    "Disabled",
    "Opening",
    "ShutdownAbandoned",
];

/// Returns the `getcapabilities` wire spelling of a capability state.
#[must_use]
pub(crate) fn readiness_state_name(state: &CapabilityState) -> &'static str {
    match state {
        CapabilityState::Ready => "Ready",
        CapabilityState::CatchingUp { .. } => "CatchingUp",
        CapabilityState::RollingBack { .. } => "RollingBack",
        CapabilityState::Rebuilding { .. } => "Rebuilding",
        CapabilityState::Failed { .. } => "Failed",
        CapabilityState::Disabled => "Disabled",
        CapabilityState::Opening => "Opening",
        CapabilityState::ShutdownAbandoned => "ShutdownAbandoned",
    }
}

/// Publishes one readiness sample from the RPC capability source.
///
/// Outcome labels are set independently, so a scrape during a transition may
/// observe zero or two active outcomes; the 1s sample interval bounds the window.
/// Treat a single scrape as approximate and the RPC source as authoritative.
pub(crate) fn publish_txindex_readiness(source: &dyn DerivedIndexCapabilitySource) {
    let status = source.capability();
    let active = readiness_state_name(&status.state);
    for outcome in READINESS_OUTCOMES {
        metrics::gauge!(TXINDEX_READINESS_GAUGE, "state" => outcome)
            .set(f64::from(outcome == active));
    }
}

/// Spawns the one-hertz readiness sampler.
///
/// The thread owns clones of the shared status source and the shutdown flag;
/// teardown joins it through `NodeServices` before `NodeState` closes, so it
/// never touches closed storage.
pub(crate) fn spawn_readiness_sampler(
    source: Arc<dyn DerivedIndexCapabilitySource>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-metrics-readiness".into())
        .spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                publish_txindex_readiness(source.as_ref());
                let deadline = Instant::now() + READINESS_SAMPLE_INTERVAL;
                while !shutdown.load(Ordering::Acquire) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .map_err(|error| anyhow::anyhow!("spawn readiness sampler: {error}"))
}
