//! Metrics instrumentation and optional exposition.
//!
//! `MetricsServer` serves the Prometheus text scrape; the readiness sampler
//! projects the txindex capability source into a gauge; `EvidenceIdentity`
//! carries the artifact/configuration/durability every sample is labeled with.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Result;
use bitcoin_rs_rpc::capabilities::{CapabilityState, DerivedIndexCapabilitySource};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;

/// A SHA-256 digest carried as 64 lowercase hex characters in evidence.
///
/// A digest is bytes, not a label: a placeholder such as "unmeasured" cannot
/// parse, so an identity is either real or absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Hex(pub [u8; 32]);

impl Sha256Hex {
    /// Hashes `bytes` with SHA-256.
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

/// The corpus a measurement replayed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusIdentity {
    /// Corpus identifier from `docs/contracts/campaign-corpora.md`.
    pub id: String,
    /// Digest of the corpus manifest.
    pub manifest_sha256: Sha256Hex,
}

/// Everything a measurement was taken under.
///
/// A number without this record is a rumor: it cannot be matched against a
/// control cell or regenerated later.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentity {
    /// Digest of the executable that produced the sample.
    pub binary_sha256: Sha256Hex,
    /// Crate version of that executable.
    pub version: String,
    /// Digest of the fully resolved configuration.
    pub config_sha256: Sha256Hex,
    /// Replayed corpus. A live node has none; a product cell always has one.
    pub corpus: Option<CorpusIdentity>,
    /// Storage backend that held the state.
    pub backend: String,
    /// Durability policy in force, for example `journal:500b/5s`.
    pub durability: String,
    /// Hardware the sample ran on: CPU model and logical core count.
    pub hardware: String,
}

/// CPU model and core count, the two hardware facts a matched treatment
/// must share before its numbers are comparable.
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
    /// Identity for the running process under `config`.
    ///
    /// The digest covers the executable file on disk and the resolved
    /// configuration's debug rendering, which is the one canonical form the
    /// runtime already owns.
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

    /// The identity as Prometheus global labels.
    #[must_use]
    pub fn labels(&self) -> Vec<(&'static str, String)> {
        let mut labels = vec![
            ("binary_sha256", self.binary_sha256.to_string()),
            ("version", self.version.clone()),
            ("config_sha256", self.config_sha256.to_string()),
            ("backend", self.backend.clone()),
            ("durability", self.durability.clone()),
            ("hardware", self.hardware.clone()),
        ];
        if let Some(corpus) = &self.corpus {
            labels.push(("corpus_id", corpus.id.clone()));
            labels.push(("corpus_manifest_sha256", corpus.manifest_sha256.to_string()));
        }
        labels
    }
}

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
        "highest staged byte total observed"
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
}

static PROMETHEUS_HANDLE: Mutex<Option<(EvidenceIdentity, PrometheusHandle)>> = Mutex::new(None);

/// One process serves one identity: every scraped sample carries the
/// artifact, configuration, corpus and durability it was taken under as
/// global labels, so a reader can never attribute a value to the wrong build.
fn prometheus_handle(identity: &EvidenceIdentity) -> Result<PrometheusHandle> {
    let mut slot = PROMETHEUS_HANDLE.lock();
    if let Some((installed, handle)) = slot.as_ref() {
        anyhow::ensure!(
            installed == identity,
            "metrics recorder already serves a different evidence identity"
        );
        return Ok(handle.clone());
    }
    let mut builder = PrometheusBuilder::new();
    for (label, value) in identity.labels() {
        builder = builder.add_global_label(label, value);
    }
    let handle = builder
        .install_recorder()
        .map_err(|error| anyhow::anyhow!("install prometheus recorder: {error}"))?;
    *slot = Some((identity.clone(), handle.clone()));
    Ok(handle)
}

/// Process-global Prometheus scrape listener bound by [`start_metrics`].
pub struct MetricsServer {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MetricsServer {
    /// Binds `addr` before installing the recorder, then serves Prometheus text.
    ///
    /// Listener-first ordering keeps an occupied-address failure from consuming
    /// the process-global recorder slot, so a later in-process retry cannot hit
    /// `SetRecorderError`.
    pub fn bind(
        addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
        identity: &EvidenceIdentity,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        let handle = prometheus_handle(identity)?;
        describe_node_metrics();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("bitcoin-rs-metrics".into())
            .spawn(move || serve_metrics(&listener, &handle, &thread_stop, &shutdown))?;
        Ok(Self {
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    /// Address the scrape thread is listening on.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Signals the scrape thread and waits for it to exit.
    pub fn join(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Starts the production scrape listener when `metrics_bind` is configured.
///
/// This is the entry `run` uses after [`crate::state::NodeState::open`].
pub(crate) fn start_metrics(
    bind: Option<SocketAddr>,
    shutdown: Arc<AtomicBool>,
    identity: &EvidenceIdentity,
) -> Result<Option<MetricsServer>> {
    bind.map(|addr| MetricsServer::bind(addr, shutdown, identity))
        .transpose()
}

fn serve_metrics(
    listener: &TcpListener,
    handle: &PrometheusHandle,
    stop: &Arc<AtomicBool>,
    shutdown: &Arc<AtomicBool>,
) {
    loop {
        if stop.load(Ordering::Acquire) || shutdown.load(Ordering::Acquire) {
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

/// Gauge name for the txindex readiness outcome.
pub(crate) const TXINDEX_READINESS_GAUGE: &str = "node.capability.txindex_readiness";

/// How often the sampler republishes the readiness gauge.
const READINESS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Publishes one readiness sample from the RPC capability source.
///
/// Outcome labels are the `getcapabilities` wire spellings and are set
/// independently, so a scrape during a transition may observe zero or two
/// active outcomes; the 1s sample interval bounds the window. Treat a single
/// scrape as approximate and the RPC source as authoritative.
pub(crate) fn publish_txindex_readiness(source: &dyn DerivedIndexCapabilitySource) {
    let status = source.capability();
    let active = status.state.wire_name();
    for outcome in CapabilityState::ALL {
        metrics::gauge!(TXINDEX_READINESS_GAUGE, "state" => outcome.wire_name())
            .set(f64::from(outcome.wire_name() == active));
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

#[cfg(test)]
#[path = "../tests/unit/metrics/tests.rs"]
mod tests;
