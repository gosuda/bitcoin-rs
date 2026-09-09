extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::Mutex;

/// Monotonic process start, recorded once at node startup.
///
/// Core initializes its uptime clock at process start (`GetUptime`,
/// `src/common/system.cpp`), so every later query reports true elapsed
/// runtime. A lazily initialized clock would restart on first read, which is
/// the first-call-reports-approximately-zero bug the utility parity audit
/// records for `uptime`; the earliest-wins record here makes the node, not
/// the first RPC caller, own the origin.
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// Records the authoritative process start instant for uptime accounting.
///
/// Idempotent and earliest-wins: the first caller fixes the uptime origin,
/// mirroring Core's static initialization. `run` records this before wiring
/// subsystems so the clock covers the whole node lifecycle.
pub fn record_process_start(start: Instant) {
    let _ = PROCESS_START.set(start);
}

/// Returns the recorded process start instant, or `None` before
/// [`record_process_start`] has run.
#[must_use]
pub fn process_start() -> Option<Instant> {
    PROCESS_START.get().copied()
}

/// Returns monotonic uptime since the recorded process start, or `None`
/// before [`record_process_start`] has run.
///
/// `None` keeps the not-yet-started state observable instead of silently
/// restarting the clock on read.
#[must_use]
pub fn process_uptime() -> Option<Duration> {
    PROCESS_START.get().map(Instant::elapsed)
}

/// Warning kinds the node can raise, mirroring Core's kernel and node warning
/// ids.
///
/// Declaration order is the report order: Core keys its registry by
/// `std::variant<kernel::Warning, node::Warning>`, so kernel-issued warnings
/// sort before node-issued ones.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WarningKind {
    /// A versionbit unknown to this node activated on the network.
    UnknownNewRulesActivated,
    /// An invalid chain with substantially more work than the best chain was
    /// found.
    LargeWorkInvalidChain,
    /// The system clock is far out of sync with peer clocks.
    ClockOutOfSync,
    /// An internal error put the node in a state it cannot recover from.
    FatalInternalError,
}

/// Node warning registry, mirroring Core's `node::Warnings`.
///
/// At most one message per [`WarningKind`]: setting an already-active kind
/// keeps the original message, and [`Warnings::messages`] reports in kind
/// order. The registry is node-owned state; RPC projections read it live at
/// call time instead of copying warnings into transport-owned storage.
pub struct Warnings {
    active: Mutex<BTreeMap<WarningKind, String>>,
}

impl Default for Warnings {
    fn default() -> Self {
        Self::new()
    }
}

impl Warnings {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            active: Mutex::new(BTreeMap::new()),
        }
    }

    /// Activates the warning for `kind` with `message`.
    ///
    /// Returns `true` when the warning was newly set. An already-active kind
    /// keeps its original message and returns `false`, matching Core's
    /// `Warnings::Set`.
    pub fn set(&self, kind: WarningKind, message: impl Into<String>) -> bool {
        let mut active = self.active.lock();
        if active.contains_key(&kind) {
            return false;
        }
        active.insert(kind, message.into());
        true
    }

    /// Deactivates the warning for `kind`, returning whether one was active.
    pub fn unset(&self, kind: WarningKind) -> bool {
        self.active.lock().remove(&kind).is_some()
    }

    /// Returns the active warning messages ordered by kind.
    #[must_use]
    pub fn messages(&self) -> Vec<String> {
        self.active.lock().values().cloned().collect()
    }
}

static NODE_WARNINGS: Warnings = Warnings::new();

/// Returns the process-wide node warning registry.
///
/// This is the authoritative warnings fact source: the `getblockchaininfo`,
/// `getnetworkinfo`, and `getmininginfo` projections read it at invocation,
/// the way Core reads `NodeContext::warnings` through `GetWarningsForRpc`.
#[must_use]
pub fn node_warnings() -> &'static Warnings {
    &NODE_WARNINGS
}

fn describe_node_metrics() {
    metrics::describe_counter!("node.event_loop.mempool_ticks", "mempool maintenance ticks");
    metrics::describe_counter!("node.event_loop.metrics_scrapes", "metrics scrape ticks");
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
}

static PROMETHEUS_HANDLE: Mutex<Option<PrometheusHandle>> = Mutex::new(None);

fn prometheus_handle() -> Result<PrometheusHandle> {
    let mut slot = PROMETHEUS_HANDLE.lock();
    if let Some(handle) = slot.as_ref() {
        return Ok(handle.clone());
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|error| anyhow::anyhow!("install prometheus recorder: {error}"))?;
    *slot = Some(handle.clone());
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
    pub fn bind(addr: SocketAddr, shutdown: Arc<AtomicBool>) -> Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        let handle = prometheus_handle()?;
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
) -> Result<Option<MetricsServer>> {
    bind.map(|addr| MetricsServer::bind(addr, shutdown))
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
#[cfg(test)]
pub(crate) fn test_recorder() -> metrics::NoopRecorder {
    metrics::NoopRecorder
}
#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn process_start_is_recorded_once_and_uptime_advances() {
        use std::thread;
        use std::time::Duration;

        record_process_start(Instant::now());
        let first = process_start();
        let before = process_uptime();

        thread::sleep(Duration::from_millis(25));
        // A second record must not move the clock — earliest-wins is what
        // makes the node, rather than the latest caller, own the origin.
        record_process_start(Instant::now());

        assert_eq!(
            process_start(),
            first,
            "a second record_process_start must not move the start instant"
        );
        let Some(before) = before else {
            panic!("uptime must be observable after record_process_start");
        };
        let after = process_uptime().unwrap_or_else(|| panic!("uptime must stay observable"));
        assert!(
            after >= before + Duration::from_millis(20),
            "uptime must advance with elapsed time: {before:?} -> {after:?}"
        );
    }

    #[test]
    fn warnings_keep_first_message_and_report_in_kind_order() {
        let warnings = Warnings::new();
        assert!(warnings.messages().is_empty());

        assert!(warnings.set(WarningKind::ClockOutOfSync, "clock out of sync"));
        // Core ignores a later message for an already-active kind.
        assert!(!warnings.set(WarningKind::ClockOutOfSync, "superseded message"));
        assert!(warnings.set(WarningKind::FatalInternalError, "fatal"));
        assert!(warnings.set(WarningKind::UnknownNewRulesActivated, "unknown rules"));

        assert_eq!(
            warnings.messages(),
            [
                "unknown rules".to_owned(),
                "clock out of sync".to_owned(),
                "fatal".to_owned(),
            ],
            "kernel warnings must sort before node warnings regardless of set order"
        );

        assert!(warnings.unset(WarningKind::ClockOutOfSync));
        assert!(!warnings.unset(WarningKind::ClockOutOfSync));
        assert_eq!(
            warnings.messages(),
            ["unknown rules".to_owned(), "fatal".to_owned()]
        );
    }

    fn unused_ephemeral() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn scrape(addr: SocketAddr) -> (u16, String) {
        let mut last = None;
        for _ in 0..50 {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
                Ok(mut stream) => {
                    stream
                        .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let occupied = TcpListener::bind(unused_ephemeral())
            .unwrap_or_else(|error| panic!("occupy port: {error}"));
        let addr = occupied
            .local_addr()
            .unwrap_or_else(|error| panic!("occupied local addr: {error}"));
        let installed_before = PROMETHEUS_HANDLE.lock().is_some();

        let first = start_metrics(Some(addr), Arc::clone(&shutdown));
        assert!(first.is_err(), "occupied bind must fail");
        assert_eq!(
            PROMETHEUS_HANDLE.lock().is_some(),
            installed_before,
            "failed bind must not install the process recorder"
        );

        drop(occupied);
        let server = start_metrics(Some(unused_ephemeral()), shutdown)
            .unwrap_or_else(|error| panic!("retry after occupied bind: {error}"))
            .unwrap_or_else(|| panic!("metrics server"));
        metrics::counter!("node_metrics_retry_probe").increment(1);
        let (status, body) = scrape(server.local_addr());
        assert_eq!(status, 200);
        assert!(
            body.contains("node_metrics_retry_probe"),
            "retry scrape missing recorded metric: {body}"
        );
        server.join();
    }

    #[test]
    fn scrape_returns_prometheus_text_with_recorded_metrics() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = MetricsServer::bind(unused_ephemeral(), shutdown)
            .unwrap_or_else(|error| panic!("bind metrics: {error}"));
        metrics::counter!("node_metrics_scrape_probe").increment(1);
        let (status, body) = scrape(server.local_addr());
        assert_eq!(status, 200);
        assert!(
            body.contains("text/plain"),
            "content-type must be prometheus text: {body}"
        );
        assert!(
            body.contains("node_metrics_scrape_probe"),
            "body must include recorded metric: {body}"
        );
        server.join();
    }

    #[test]
    fn two_sequential_servers_in_one_process_both_serve() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let first = MetricsServer::bind(unused_ephemeral(), Arc::clone(&shutdown))
            .unwrap_or_else(|error| panic!("first: {error}"));
        metrics::counter!("node_metrics_sequential_probe").increment(1);
        let (status, body) = scrape(first.local_addr());
        assert_eq!(status, 200);
        assert!(body.contains("node_metrics_sequential_probe"));
        first.join();

        let second = MetricsServer::bind(unused_ephemeral(), shutdown)
            .unwrap_or_else(|error| panic!("second: {error}"));
        metrics::counter!("node_metrics_sequential_probe").increment(1);
        let (status, body) = scrape(second.local_addr());
        assert_eq!(status, 200);
        assert!(body.contains("node_metrics_sequential_probe"));
        second.join();
    }

    #[test]
    fn shutdown_exits_the_listener_thread() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = MetricsServer::bind(unused_ephemeral(), Arc::clone(&shutdown))
            .unwrap_or_else(|error| panic!("bind: {error}"));
        let addr = server.local_addr();
        shutdown.store(true, Ordering::Release);
        server.join();
        TcpListener::bind(addr)
            .unwrap_or_else(|error| panic!("port released after listener join: {error}"));
    }

    #[test]
    fn run_retries_metrics_bind_after_occupied_address() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let occupied =
            TcpListener::bind(unused_ephemeral()).unwrap_or_else(|error| panic!("occupy: {error}"));
        let busy = occupied
            .local_addr()
            .unwrap_or_else(|error| panic!("busy addr: {error}"));
        assert!(
            start_metrics(Some(busy), Arc::clone(&shutdown)).is_err(),
            "run-path bind must fail on an occupied address"
        );
        drop(occupied);
        let server = start_metrics(Some(unused_ephemeral()), shutdown)
            .unwrap_or_else(|error| panic!("run-path retry: {error}"))
            .unwrap_or_else(|| panic!("server"));
        let (status, _) = scrape(server.local_addr());
        assert_eq!(status, 200);
        server.join();
    }
}
