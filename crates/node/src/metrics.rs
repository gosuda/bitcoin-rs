use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Result;
use bitcoin_rs_index::{CapabilityState, DerivedIndexCapabilitySource};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Hex(pub [u8; 32]);

impl Sha256Hex {
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::digest(bytes).into())
    }
}

impl core::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Sha256Hex {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let malformed = || format!("digest {text:?} is not 64 lowercase hex characters");
        if text.len() != 64 {
            return Err(malformed());
        }
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let text = core::str::from_utf8(pair).map_err(|_| malformed())?;
            if text.bytes().any(|c| c.is_ascii_uppercase()) {
                return Err(malformed());
            }
            *byte = u8::from_str_radix(text, 16).map_err(|_| malformed())?;
        }
        Ok(Self(bytes))
    }
}

impl serde::Serialize for Sha256Hex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Hex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusIdentity {
    pub id: String,
    pub manifest_sha256: Sha256Hex,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentity {
    pub binary_sha256: Sha256Hex,
    pub version: String,
    pub config_sha256: Sha256Hex,
    pub corpus: Option<CorpusIdentity>,
    pub backend: String,
    pub durability: String,
    pub hardware: String,
}

fn hardware_identity() -> String {
    let model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("model name"))
                .and_then(|rest| rest.split_once(':'))
                .map(|(_, model)| model.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown-cpu".into());
    let cores = std::thread::available_parallelism().map_or(0, usize::from);
    format!("{model} x{cores}")
}

impl EvidenceIdentity {
    pub fn of_process(config: &crate::config::NodeConfig) -> Result<Self> {
        let executable = std::env::current_exe()?;
        let binary_sha256 = Sha256Hex::digest(&std::fs::read(&executable)?);
        let journal = config.chainstate_journal;
        let durability = if journal.enabled {
            format!("journal:{}b/{}s", journal.blocks, journal.seconds)
        } else {
            "checkpoint-only".into()
        };
        Ok(Self {
            binary_sha256,
            version: env!("CARGO_PKG_VERSION").into(),
            config_sha256: Sha256Hex::digest(format!("{config:?}").as_bytes()),
            corpus: None,
            backend: config.storage.backend.as_str().into(),
            durability,
            hardware: hardware_identity(),
        })
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "keep metric descriptions together in the process-wide registry"
)]
fn describe_node_metrics() {
    metrics::describe_counter!("node.event_loop.sync_ticks", "block sync ticks");
    metrics::describe_counter!(
        "node.event_loop.sync_wakes",
        "block sync wakeups from inbound p2p data"
    );
    metrics::describe_gauge!(
        "node.shutdown.requested",
        "whether shutdown has been requested"
    );
    metrics::describe_counter!(
        "node.mempool.observer_failures_total",
        "mempool observer callback failures"
    );
    metrics::describe_counter!(
        "node.package_charge_overrun",
        "bytes by which a decoded peer package's measured heap exceeded its planned charge"
    );
    metrics::describe_histogram!(
        "node.event_loop.tick_seconds",
        "event loop tick latency seconds"
    );
    metrics::describe_counter!(
        "node.sync.duplicate_deliveries",
        "blocks received that were already staged"
    );
    metrics::describe_histogram!(
        "node.sync.apply_idle_seconds",
        "durations the apply frontier stayed starved while the window owed downloads"
    );
    metrics::describe_histogram!(
        "node.sync.download_blocked_by_apply_seconds",
        "durations the window front stayed in flight while apply held the frontier"
    );
    metrics::describe_gauge!(
        "node.sync.pending_blocks_high_water",
        "highest in-flight block count observed"
    );
    metrics::describe_gauge!(
        "node.sync.pending_bytes_high_water",
        "highest in-flight byte estimate observed"
    );
    metrics::describe_gauge!(
        "node.sync.staged_blocks_high_water",
        "highest staged block count observed"
    );
    metrics::describe_gauge!(
        "node.sync.staged_bytes_high_water",
        "highest staged serialized byte total observed"
    );
    metrics::describe_gauge!(
        "node.sync.staged_decoded_bytes",
        "decoded heap capacity bytes owned by staged blocks, excluding allocator rounding"
    );
    metrics::describe_gauge!(
        "node.sync.staged_retained_bytes",
        "attributed staged bytes: decoded heap capacity plus preserved serialized buffers, excluding allocator rounding; not process RSS"
    );
    metrics::describe_gauge!(
        "node.sync.staged_retained_bytes_high_water",
        "highest attributed staged retained byte total observed"
    );
    metrics::describe_gauge!(
        "node.sync.inbound_block_queue_depth",
        "block bodies queued in the bounded inbound channel when the sync drain pass emitted its gauges, after it emptied the receiver; a residual, not a peak"
    );
    metrics::describe_gauge!(
        "node.sync.inbound_header_queue_depth",
        "header batches remaining in the bounded inbound channel when sync emits its gauges; a sampled backlog, not a peak or byte count"
    );
    metrics::describe_counter!(
        "storage.writes_total",
        "storage write batches applied, by backend and durability"
    );
    metrics::describe_counter!(
        "storage.flushes_total",
        "storage durability flushes by backend"
    );
    metrics::describe_histogram!("storage.write_bytes", "storage write batch payload bytes");
    metrics::describe_gauge!(
        "storage.cache_capacity_bytes",
        "configured per-engine cache capacity in bytes"
    );
    metrics::describe_gauge!(
        TXINDEX_READINESS_GAUGE,
        "txindex capability readiness from the live getcapabilities source; 1 for the active state label, 0 for the others"
    );
    metrics::describe_histogram!(
        "index.family_planned_write_bytes",
        "pre-coalescing planned logical write bytes by index row family"
    );
    metrics::describe_gauge!(
        "rpc.connections.active",
        "admitted live HTTP connections, by listener surface"
    );
    metrics::describe_counter!(
        "rpc.connections.rejected_total",
        "HTTP connection budget refusals, by listener surface"
    );
    metrics::describe_histogram!(
        "rpc.http.request_seconds",
        "HTTP time from complete request head through response, by listener surface and route family"
    );
}

static PROMETHEUS_HANDLE: Mutex<Option<(EvidenceIdentity, PrometheusHandle)>> = Mutex::new(None);

fn prometheus_handle(identity: &EvidenceIdentity) -> Result<PrometheusHandle> {
    let mut slot = PROMETHEUS_HANDLE.lock();
    if let Some((installed, handle)) = slot.as_ref() {
        anyhow::ensure!(
            installed == identity,
            "metrics recorder already serves a different evidence identity"
        );
        return Ok(handle.clone());
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| anyhow::anyhow!("install prometheus recorder: {error}"))?;
    *slot = Some((identity.clone(), handle.clone()));
    Ok(handle)
}

pub(crate) struct MetricsServer {
    #[cfg(test)]
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MetricsServer {
    pub(crate) fn bind(
        addr: SocketAddr,
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
        identity: &EvidenceIdentity,
    ) -> Result<Self> {
        let shutdown = shutdown.into();
        let listener = TcpListener::bind(addr)?;
        #[cfg(test)]
        let local_addr = listener.local_addr()?;
        #[cfg(not(test))]
        listener.local_addr()?;
        let handle = prometheus_handle(identity)?;
        describe_node_metrics();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("bitcoin-rs-metrics".into())
            .spawn(move || serve_metrics(&listener, &handle, &thread_stop, &shutdown))?;
        Ok(Self {
            #[cfg(test)]
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("metrics scrape thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        if let Err(error) = self.stop_and_join() {
            tracing::warn!(%error, "metrics shutdown failed");
        }
    }
}

pub(crate) fn start_metrics(
    bind: Option<SocketAddr>,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
    identity: &EvidenceIdentity,
) -> Result<Option<MetricsServer>> {
    let shutdown = shutdown.into();
    bind.map(|addr| MetricsServer::bind(addr, shutdown, identity))
        .transpose()
}

fn serve_metrics(
    listener: &TcpListener,
    handle: &PrometheusHandle,
    stop: &Arc<AtomicBool>,
    shutdown: &bitcoin_rs_chain::LatchReader,
) {
    loop {
        if stop.load(Ordering::Acquire) || shutdown.is_triggered() {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                serve_scrape(&mut stream, handle);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn serve_scrape(stream: &mut TcpStream, handle: &PrometheusHandle) {
    let mut buf = [0_u8; 1024];
    let _ = stream.read(&mut buf);
    let body = handle.render();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

pub(crate) const TXINDEX_READINESS_GAUGE: &str = "node.capability.txindex_readiness";

const READINESS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) fn publish_txindex_readiness(source: &dyn DerivedIndexCapabilitySource) {
    let status = source.capability();
    let active = status.state.wire_name();
    for outcome in CapabilityState::ALL {
        metrics::gauge!(TXINDEX_READINESS_GAUGE, "state" => outcome.wire_name())
            .set(f64::from(outcome.wire_name() == active));
    }
}

pub(crate) fn spawn_readiness_sampler(
    source: Arc<dyn DerivedIndexCapabilitySource>,
    shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
) -> anyhow::Result<JoinHandle<()>> {
    let shutdown = shutdown.into();
    std::thread::Builder::new()
        .name("bitcoin-rs-metrics-readiness".into())
        .spawn(move || {
            while !shutdown.is_triggered() {
                publish_txindex_readiness(source.as_ref());
                let deadline = Instant::now() + READINESS_SAMPLE_INTERVAL;
                while !shutdown.is_triggered() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .map_err(|error| anyhow::anyhow!("spawn readiness sampler: {error}"))
}

#[cfg(test)]
mod tests;
