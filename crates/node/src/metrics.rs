use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bitcoin_rs_index::{CapabilityState, DerivedIndexCapabilitySource};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;

use crate::run::RunError;

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

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Sha256HexError {
    #[error("digest {text:?} is not 64 lowercase hex characters")]
    Malformed { text: String },
}

impl core::str::FromStr for Sha256Hex {
    type Err = Sha256HexError;

    fn from_str(text: &str) -> Result<Self, Sha256HexError> {
        let malformed = || Sha256HexError::Malformed {
            text: text.to_owned(),
        };
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
    pub fn of_process(config: &crate::config::NodeConfig) -> std::io::Result<Self> {
        let executable = std::env::current_exe()?;
        let binary_sha256 = Sha256Hex::digest(&std::fs::read(&executable)?);
        let durability = "atomic-batch".to_owned();
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

fn describe_node_metrics() {
    metrics::describe_gauge!(
        "rpc.esplora.expensive.active",
        "admitted address and scripthash projections across all node listeners"
    );
    metrics::describe_counter!(
        "rpc.esplora.expensive.rejected_total",
        "Esplora projections rejected before index work because the query quota is full"
    );
    metrics::describe_histogram!(
        "rpc.esplora.expensive.execution_seconds",
        "admitted Esplora projection duration including failed queries, excluding socket writes"
    );
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

fn prometheus_handle(identity: &EvidenceIdentity) -> Result<PrometheusHandle, RunError> {
    let mut slot = PROMETHEUS_HANDLE.lock();
    if let Some((installed, handle)) = slot.as_ref() {
        if installed != identity {
            return Err(RunError::MetricsIdentityMismatch);
        }
        return Ok(handle.clone());
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| RunError::MetricsInstall { error })?;
    *slot = Some((identity.clone(), handle.clone()));
    Ok(handle)
}

pub(crate) struct MetricsServer {
    #[cfg(test)]
    local_addr: SocketAddr,
    cancel: bitcoin_rs_consensus::latch::LatchWriter,
    thread: Option<JoinHandle<()>>,
}

impl MetricsServer {
    pub(crate) fn bind(
        addr: SocketAddr,
        shutdown: impl Into<bitcoin_rs_consensus::latch::LatchReader>,
        identity: &EvidenceIdentity,
    ) -> Result<Self, RunError> {
        let shutdown = shutdown.into();
        let cancel = shutdown.child();
        let cancel_reader = cancel.reader();
        let listener = TcpListener::bind(addr)?;
        #[cfg(test)]
        let local_addr = listener.local_addr()?;
        #[cfg(not(test))]
        listener.local_addr()?;
        let handle = prometheus_handle(identity)?;
        describe_node_metrics();
        let thread = thread::Builder::new()
            .name("bitcoin-rs-metrics".into())
            .spawn(move || serve_metrics(&listener, &handle, &cancel_reader))?;
        Ok(Self {
            #[cfg(test)]
            local_addr,
            cancel,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn stop_and_join(&mut self) -> Result<(), RunError> {
        self.cancel.trigger();
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| RunError::MetricsScrapeThreadPanicked)?;
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
    shutdown: impl Into<bitcoin_rs_consensus::latch::LatchReader>,
    identity: &EvidenceIdentity,
) -> Result<Option<MetricsServer>, RunError> {
    let shutdown = shutdown.into();
    bind.map(|addr| MetricsServer::bind(addr, shutdown, identity))
        .transpose()
}

fn serve_metrics(
    listener: &TcpListener,
    handle: &PrometheusHandle,
    cancel: &bitcoin_rs_consensus::latch::LatchReader,
) {
    let Ok(local_addr) = listener.local_addr() else {
        return;
    };
    let connect_addr = crate::run::loopback_connect_addr(local_addr);
    let _guard = cancel.on_cancel(move || {
        let _ = TcpStream::connect(connect_addr);
    });
    while !cancel.is_triggered() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if cancel.is_triggered() {
                    break;
                }
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                serve_scrape(&mut stream, handle);
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
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
) -> Result<JoinHandle<()>, RunError> {
    spawn_readiness_sampler_polling(source, shutdown, READINESS_SAMPLE_INTERVAL)
}

fn spawn_readiness_sampler_polling(
    source: Arc<dyn DerivedIndexCapabilitySource>,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
    interval: Duration,
) -> Result<JoinHandle<()>, RunError> {
    std::thread::Builder::new()
        .name("bitcoin-rs-metrics-readiness".into())
        .spawn(move || {
            while !shutdown.is_triggered() {
                publish_txindex_readiness(source.as_ref());
                crossbeam_channel::select! {
                    recv(shutdown.closed()) -> _ => break,
                    recv(crossbeam_channel::after(interval)) -> _ => {}
                }
            }
        })
        .map_err(|error| RunError::SpawnReadinessSampler { error })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use bitcoin_rs_index::{
        CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource, derived_index_status,
    };
    use parking_lot::Mutex;

    use super::{
        CorpusIdentity, EvidenceIdentity, MetricsServer, PROMETHEUS_HANDLE, Sha256Hex,
        TXINDEX_READINESS_GAUGE, publish_txindex_readiness, spawn_readiness_sampler_polling,
        start_metrics,
    };

    pub(super) static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());

    impl MetricsServer {
        pub(crate) fn with_worker_for_test(worker: thread::JoinHandle<()>) -> Self {
            Self {
                local_addr: unused_ephemeral(),
                cancel: bitcoin_rs_consensus::latch::LatchWriter::new(),
                thread: Some(worker),
            }
        }
    }

    fn unused_ephemeral() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    pub(super) fn identity() -> EvidenceIdentity {
        EvidenceIdentity {
            binary_sha256: Sha256Hex([1; 32]),
            version: "test".into(),
            config_sha256: Sha256Hex([2; 32]),
            corpus: Some(CorpusIdentity {
                id: "probe".into(),
                manifest_sha256: Sha256Hex([3; 32]),
            }),
            backend: "memory".into(),
            durability: "checkpoint-only".into(),
            hardware: "test x1".into(),
        }
    }

    fn scrape(addr: SocketAddr) -> (u16, String) {
        let mut last = None;
        for _ in 0..50 {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
                Ok(mut stream) => {
                    stream
                    .write_all(
                        b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap_or_else(|error| panic!("write scrape request: {error}"));
                    stream
                        .flush()
                        .unwrap_or_else(|error| panic!("flush scrape request: {error}"));
                    let mut body = String::new();
                    stream
                        .read_to_string(&mut body)
                        .unwrap_or_else(|error| panic!("read scrape response: {error}"));
                    let status = body
                        .split_whitespace()
                        .nth(1)
                        .and_then(|token| token.parse().ok())
                        .unwrap_or(0);
                    return (status, body);
                }
                Err(error) => last = Some(error),
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("scrape connect failed: {last:?}");
    }

    #[test]
    fn occupied_address_bind_errors_and_in_process_retry_succeeds() {
        let _guard = SERVER_TEST_LOCK.lock();
        let shutdown = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let occupied = TcpListener::bind(unused_ephemeral())
            .unwrap_or_else(|error| panic!("occupy port: {error}"));
        let addr = occupied
            .local_addr()
            .unwrap_or_else(|error| panic!("occupied local addr: {error}"));
        let installed_before = PROMETHEUS_HANDLE.lock().is_some();

        let first = start_metrics(Some(addr), shutdown.clone(), &identity());
        assert!(first.is_err(), "occupied bind must fail");
        assert_eq!(
            PROMETHEUS_HANDLE.lock().is_some(),
            installed_before,
            "failed bind must not install the process recorder"
        );

        drop(occupied);
        let mut server = start_metrics(Some(unused_ephemeral()), shutdown, &identity())
            .unwrap_or_else(|error| panic!("retry after occupied bind: {error}"))
            .unwrap_or_else(|| panic!("metrics server"));
        metrics::counter!("node_metrics_retry_probe").increment(1);
        let (status, body) = scrape(server.local_addr());
        assert_eq!(status, 200);
        assert!(
            body.contains("node_metrics_retry_probe"),
            "retry scrape missing recorded metric: {body}"
        );
        server
            .stop_and_join()
            .unwrap_or_else(|error| panic!("join metrics scrape worker: {error}"));
    }

    #[test]
    fn scrape_returns_operator_metrics_without_evidence_identity_labels() {
        let _guard = SERVER_TEST_LOCK.lock();
        let shutdown = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let mut server = MetricsServer::bind(unused_ephemeral(), shutdown, &identity())
            .unwrap_or_else(|error| panic!("bind metrics: {error}"));
        metrics::counter!("node_metrics_scrape_probe").increment(1);
        publish_txindex_readiness(&FixedSource::enabled(CapabilityState::Ready));
        let (status, body) = scrape(server.local_addr());
        assert_eq!(status, 200);
        assert!(
            body.contains("text/plain"),
            "content-type must be prometheus text: {body}"
        );
        let (_, exposition) = body
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("HTTP response missing header boundary: {body}"));
        let samples = exposition
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        assert!(
            samples
                .clone()
                .any(|line| line.starts_with("node_metrics_scrape_probe")),
            "probe sample missing from scrape: {body}"
        );
        assert_one_active(&readiness_samples(exposition), "Ready");
        for sample in samples {
            for retired_label in [
                "binary_sha256=",
                "version=",
                "config_sha256=",
                "corpus_id=",
                "corpus_manifest_sha256=",
                "hardware=",
            ] {
                assert!(
                    !sample.contains(retired_label),
                    "operator metrics must not carry evidence label {retired_label}: {sample}"
                );
            }
            if !sample.starts_with("storage_") {
                for identity_label in ["backend=", "durability="] {
                    assert!(
                        !sample.contains(identity_label),
                        "non-storage metrics must not inherit global identity {identity_label}: {sample}"
                    );
                }
            }
        }
        server
            .stop_and_join()
            .unwrap_or_else(|error| panic!("join metrics scrape worker: {error}"));
    }

    #[test]
    fn two_sequential_servers_in_one_process_both_serve() {
        let _guard = SERVER_TEST_LOCK.lock();
        let shutdown = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let mut first = MetricsServer::bind(unused_ephemeral(), shutdown.clone(), &identity())
            .unwrap_or_else(|error| panic!("first: {error}"));
        metrics::counter!("node_metrics_sequential_probe").increment(1);
        let (status, body) = scrape(first.local_addr());
        assert_eq!(status, 200);
        assert!(body.contains("node_metrics_sequential_probe"));
        first
            .stop_and_join()
            .unwrap_or_else(|error| panic!("join first metrics scrape worker: {error}"));

        let mut second = MetricsServer::bind(unused_ephemeral(), shutdown, &identity())
            .unwrap_or_else(|error| panic!("second: {error}"));
        metrics::counter!("node_metrics_sequential_probe").increment(1);
        let (status, body) = scrape(second.local_addr());
        assert_eq!(status, 200);
        assert!(body.contains("node_metrics_sequential_probe"));
        second
            .stop_and_join()
            .unwrap_or_else(|error| panic!("join second metrics scrape worker: {error}"));
    }

    #[test]
    fn shutdown_exits_the_listener_thread() {
        let _guard = SERVER_TEST_LOCK.lock();
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let mut server = MetricsServer::bind(unused_ephemeral(), shutdown.reader(), &identity())
            .unwrap_or_else(|error| panic!("bind metrics: {error}"));
        let addr = server.local_addr();
        shutdown.trigger();
        let deadline = Instant::now() + Duration::from_secs(10);
        while TcpListener::bind(addr).is_err() {
            if Instant::now() >= deadline {
                drop(server.thread.take());
                panic!("listener never exited on the shutdown flag");
            }
            thread::sleep(Duration::from_millis(20));
        }
        server
            .stop_and_join()
            .unwrap_or_else(|error| panic!("join metrics scrape worker: {error}"));
    }

    type RenderedSample = (String, f64);

    fn is_one(value: f64) -> bool {
        value.to_bits() == 1.0f64.to_bits()
    }

    fn is_zero(value: f64) -> bool {
        value.to_bits() == 0.0f64.to_bits()
    }

    struct FixedSource {
        enabled: bool,
        state: CapabilityState,
    }

    impl FixedSource {
        fn enabled(state: CapabilityState) -> Self {
            Self {
                enabled: true,
                state,
            }
        }
    }

    impl DerivedIndexCapabilitySource for FixedSource {
        fn capability(&self) -> CapabilityStatus {
            derived_index_status(self.enabled, self.state.clone())
        }
    }

    fn scrape_body(addr: SocketAddr) -> String {
        scrape(addr).1
    }

    fn readiness_samples(body: &str) -> Vec<RenderedSample> {
        let metric = TXINDEX_READINESS_GAUGE.replace('.', "_");
        let prefix = format!("{metric}{{");
        body.lines()
            .filter_map(|line| {
                let rest = line.strip_prefix(&prefix)?;
                let (labels, value) = rest.split_once('}')?;
                let state = labels.split(',').find_map(|label| {
                    label
                        .trim()
                        .strip_prefix("state=\"")
                        .and_then(|spelled| spelled.strip_suffix('"'))
                })?;
                let value = value.trim().parse::<f64>().ok()?;
                Some((state.to_owned(), value))
            })
            .collect()
    }

    fn assert_one_active(samples: &[RenderedSample], expected: &str) {
        let active: Vec<_> = samples.iter().filter(|(_, value)| is_one(*value)).collect();
        assert_eq!(
            active.len(),
            1,
            "exactly one outcome must be active: {samples:?}"
        );
        assert_eq!(
            active.first().map(|(state, _)| state.as_str()),
            Some(expected),
            "the active label must be the getcapabilities spelling"
        );
    }

    #[test]
    fn published_gauge_flips_its_active_label_with_the_rpc_source() {
        let _guard = SERVER_TEST_LOCK.lock();
        let shutdown = bitcoin_rs_consensus::latch::LatchReader::fixture_never();
        let mut server = MetricsServer::bind(unused_ephemeral(), shutdown, &identity())
            .unwrap_or_else(|error| panic!("bind metrics: {error}"));

        publish_txindex_readiness(&FixedSource::enabled(CapabilityState::Ready));
        let samples = readiness_samples(&scrape_body(server.local_addr()));
        assert_one_active(&samples, "Ready");

        publish_txindex_readiness(&FixedSource::enabled(CapabilityState::Rebuilding {
            processed_height: 40,
            target_height: 101,
        }));
        let samples = readiness_samples(&scrape_body(server.local_addr()));
        assert_one_active(&samples, "Rebuilding");
        assert!(
            samples
                .iter()
                .all(|(state, value)| state != "Ready" || is_zero(*value)),
            "the retired Ready label must read 0 after the transition: {samples:?}"
        );

        publish_txindex_readiness(&FixedSource {
            enabled: false,
            state: CapabilityState::Disabled,
        });
        let samples = readiness_samples(&scrape_body(server.local_addr()));
        assert_one_active(&samples, "Disabled");

        server
            .stop_and_join()
            .unwrap_or_else(|error| panic!("join metrics scrape worker: {error}"));
    }

    #[test]
    fn readiness_sampler_stops_promptly_on_cancellation() {
        let writer = bitcoin_rs_consensus::latch::LatchWriter::new();
        let reader = writer.reader();
        let source = Arc::new(FixedSource::enabled(CapabilityState::Ready));
        let worker = spawn_readiness_sampler_polling(source, reader, Duration::from_secs(3600))
            .unwrap_or_else(|error| panic!("spawn readiness sampler: {error}"));
        let (tx, rx) = crossbeam_channel::bounded(1);
        let handle = std::thread::spawn(move || {
            let _ = worker.join();
            let _ = tx.send(());
        });
        std::thread::sleep(Duration::from_millis(5));
        writer.trigger();
        let res = rx.recv_timeout(Duration::from_secs(10));
        assert!(
            res.is_ok(),
            "readiness sampler did not exit promptly: timed out waiting for trigger"
        );
        assert!(handle.join().is_ok(), "thread panicked");
    }

    #[test]
    fn metrics_listener_stops_promptly_on_cancellation() {
        let _guard = SERVER_TEST_LOCK.lock();
        let writer = bitcoin_rs_consensus::latch::LatchWriter::new();
        let reader = writer.reader();
        let mut server = MetricsServer::bind(unused_ephemeral(), reader, &identity())
            .unwrap_or_else(|error| panic!("bind metrics: {error}"));
        let (tx, rx) = crossbeam_channel::bounded(1);
        let handle = std::thread::spawn(move || {
            let res = server.stop_and_join();
            let _ = tx.send(res);
        });
        std::thread::sleep(Duration::from_millis(5));
        writer.trigger();
        let Ok(outcome) = rx.recv_timeout(Duration::from_secs(5)) else {
            panic!("join deadline exceeded: metrics server did not stop within 5 seconds");
        };
        assert!(outcome.is_ok(), "stop_and_join failed: {outcome:?}");
        assert!(handle.join().is_ok(), "thread panicked");
    }
}
