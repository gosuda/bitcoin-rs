extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Result;
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use parking_lot::Mutex;

type MetricCell = Arc<Mutex<MetricValue>>;

/// Handle to the in-memory metrics recorder installed by the node.
#[derive(Clone, Debug)]
pub struct MetricsHandle {
    bind: SocketAddr,
    recorder: InMemoryRecorder,
}

impl MetricsHandle {
    /// Address associated with this diagnostic recorder.
    #[must_use]
    pub const fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Returns a point-in-time copy of recorded metric values.
    #[must_use]
    pub fn snapshot(&self) -> HashMap<String, MetricValue> {
        self.recorder
            .values
            .lock()
            .iter()
            .map(|(key, value)| (key.clone(), *value.lock()))
            .collect()
    }
}

/// Metric values retained by the in-memory recorder.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MetricValue {
    /// Monotonic counter value.
    Counter(u64),
    /// Last observed gauge value.
    Gauge(f64),
    /// Histogram sample count and sum.
    Histogram {
        /// Number of samples observed.
        count: u64,
        /// Sum of observed sample values.
        sum: f64,
    },
}

#[derive(Clone, Debug, Default)]
struct InMemoryRecorder {
    values: Arc<Mutex<HashMap<String, MetricCell>>>,
}

impl InMemoryRecorder {
    fn metric_key(key: &Key) -> String {
        key.name().to_owned()
    }

    fn ensure_counter(&self, key: String) -> MetricCell {
        self.ensure_metric(key, MetricValue::Counter(0))
    }

    fn ensure_gauge(&self, key: String) -> MetricCell {
        self.ensure_metric(key, MetricValue::Gauge(0.0))
    }

    fn ensure_histogram(&self, key: String) -> MetricCell {
        self.ensure_metric(key, MetricValue::Histogram { count: 0, sum: 0.0 })
    }

    fn ensure_metric(&self, key: String, initial: MetricValue) -> MetricCell {
        self.values
            .lock()
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(initial)))
            .clone()
    }
}

impl Recorder for InMemoryRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let key = Self::metric_key(key);
        let value = self.ensure_counter(key);
        Counter::from_arc(Arc::new(CounterHandle { value }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let key = Self::metric_key(key);
        let value = self.ensure_gauge(key);
        Gauge::from_arc(Arc::new(GaugeHandle { value }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let key = Self::metric_key(key);
        let value = self.ensure_histogram(key);
        Histogram::from_arc(Arc::new(HistogramHandle { value }))
    }
}

struct CounterHandle {
    value: MetricCell,
}

impl CounterFn for CounterHandle {
    fn increment(&self, value: u64) {
        let mut entry = self.value.lock();
        if let MetricValue::Counter(current) = &mut *entry {
            *current = current.saturating_add(value);
        }
    }

    fn absolute(&self, value: u64) {
        let mut entry = self.value.lock();
        if let MetricValue::Counter(current) = &mut *entry {
            *current = (*current).max(value);
        }
    }
}

struct GaugeHandle {
    value: MetricCell,
}

impl GaugeFn for GaugeHandle {
    fn increment(&self, value: f64) {
        let mut entry = self.value.lock();
        if let MetricValue::Gauge(current) = &mut *entry {
            *current += value;
        }
    }

    fn decrement(&self, value: f64) {
        let mut entry = self.value.lock();
        if let MetricValue::Gauge(current) = &mut *entry {
            *current -= value;
        }
    }

    fn set(&self, value: f64) {
        *self.value.lock() = MetricValue::Gauge(value);
    }
}

struct HistogramHandle {
    value: MetricCell,
}

impl HistogramFn for HistogramHandle {
    fn record(&self, value: f64) {
        let mut entry = self.value.lock();
        if let MetricValue::Histogram { count, sum } = &mut *entry {
            *count = count.saturating_add(1);
            *sum += value;
        }
    }
}

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

/// Resident set size of this process in bytes, or `None` where the platform
/// cannot report it.
///
/// Used by the memory-attribution reporting on the checkpoint path. The G14
/// budget is written against RSS, and the UTXO set can only account for its own
/// allocations, so the residual between the two is the number that says whether
/// an encoding change is worth making.
#[must_use]
pub fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        parse_proc_status_rss(&std::fs::read_to_string("/proc/self/status").ok()?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No `/proc`; shell out rather than take a platform-specific dependency
        // for one number read once per checkpoint.
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        parse_ps_rss(&String::from_utf8(output.stdout).ok()?)
    }
}

/// Extracts `VmRSS` from `/proc/{pid}/status` content, in bytes.
///
/// Split out from the read so it is testable off Linux. Without this the parser
/// is `cfg`-compiled out of every run on a macOS development host and first
/// executes in production, on the one path whose output the memory attribution
/// divides by.
///
/// The kernel reports `VmRSS:` in kibibytes with variable leading whitespace,
/// and the field is absent for a kernel thread.
// Unreachable off Linux, and deliberately still compiled there: the point of
// splitting it out is that its tests run everywhere, which they cannot do if
// the function is `cfg`-ed away with its caller.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "tested on every host, called only on Linux")
)]
fn parse_proc_status_rss(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    })
}

/// Extracts the kibibyte count `ps -o rss=` prints, in bytes.
// Mirror of the note on `parse_proc_status_rss`: unreachable on Linux, still
// compiled and still tested there.
#[cfg_attr(
    target_os = "linux",
    allow(dead_code, reason = "tested on every host, called only off Linux")
)]
fn parse_ps_rss(output: &str) -> Option<u64> {
    output.trim().parse::<u64>().ok()?.checked_mul(1024)
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

/// Installs the in-memory diagnostic recorder and returns its handle when a
/// bind address is provided.
///
/// This path does not serve HTTP. Production scrape exposition uses
/// [`start_metrics`] / [`MetricsServer`].
pub fn install_diagnostic_metrics(bind: Option<SocketAddr>) -> Result<Option<MetricsHandle>> {
    install_diagnostic_metrics_with(bind, metrics::set_global_recorder)
}

fn install_diagnostic_metrics_with(
    bind: Option<SocketAddr>,
    install_recorder: impl FnOnce(
        InMemoryRecorder,
    ) -> Result<(), metrics::SetRecorderError<InMemoryRecorder>>,
) -> Result<Option<MetricsHandle>> {
    let Some(bind) = bind else {
        return Ok(None);
    };

    let recorder = InMemoryRecorder::default();
    install_recorder(recorder.clone())?;

    let handle = MetricsHandle { bind, recorder };
    describe_node_metrics();
    Ok(Some(handle))
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
pub(crate) fn test_recorder() -> (impl Recorder, MetricsHandle) {
    let recorder = InMemoryRecorder::default();
    let handle = MetricsHandle {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        recorder: recorder.clone(),
    };
    (recorder, handle)
}
#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    /// Real `/proc/{pid}/status` content, so the Linux parser is exercised on
    /// every host rather than only wherever CI happens to run Linux.
    ///
    /// The field is kibibytes with variable leading whitespace, sits between
    /// other `Vm*` keys that share its prefix shape, and is absent for a kernel
    /// thread.
    #[test]
    fn proc_status_rss_is_parsed_from_the_kernel_format() {
        const STATUS: &str = "\
Name:\tbitcoin-rs
Umask:\t0022
State:\tS (sleeping)
VmPeak:\t14680064 kB
VmSize:\t14680064 kB
VmLck:\t       0 kB
VmHWM:\t 3019751 kB
VmRSS:\t 2949952 kB
RssAnon:\t 2900000 kB
Threads:\t17
";
        assert_eq!(
            super::parse_proc_status_rss(STATUS),
            Some(2_949_952 * 1024),
            "VmRSS must be read in kibibytes and returned in bytes"
        );

        // `VmHWM` and `VmSize` share the prefix shape and must not be taken.
        assert_ne!(super::parse_proc_status_rss(STATUS), Some(3_019_751 * 1024));

        // A kernel thread has no `VmRSS` at all.
        assert_eq!(
            super::parse_proc_status_rss("Name:\tkthreadd\nThreads:\t1\n"),
            None
        );
        assert_eq!(super::parse_proc_status_rss(""), None);
        assert_eq!(
            super::parse_proc_status_rss("VmRSS:\tnot-a-number kB"),
            None
        );
        assert_eq!(super::parse_proc_status_rss("VmRSS:\t"), None);
    }

    #[test]
    fn ps_rss_output_is_parsed_in_kibibytes() {
        assert_eq!(super::parse_ps_rss(" 2949952\n"), Some(2_949_952 * 1024));
        assert_eq!(super::parse_ps_rss(""), None);
        assert_eq!(super::parse_ps_rss("  "), None);
        assert_eq!(super::parse_ps_rss("garbage"), None);
        // A value large enough to overflow the kibibyte conversion.
        assert_eq!(super::parse_ps_rss(&u64::MAX.to_string()), None);
    }

    /// The reading must track real resident memory, not merely return a number.
    ///
    /// Asserting only `is_some()` would pass for a stub returning a constant,
    /// and this figure is what the memory-attribution reporting divides the
    /// UTXO set against — a wrong denominator silently misprices every
    /// encoding decision made from it. So the test allocates, touches every
    /// page to make it resident rather than merely reserved, and requires the
    /// reading to move.
    ///
    /// It is also the only coverage the Linux branch has: `/proc/self/status`
    /// is `cfg`-compiled out on the development host, so this parser runs for
    /// the first time wherever CI runs Linux.
    #[test]
    fn process_rss_bytes_tracks_a_real_allocation() {
        const BALLAST_BYTES: u64 = 128 << 20;
        const PAGE: usize = 4096;

        let Some(before) = process_rss_bytes() else {
            // A platform with neither `/proc` nor `ps` is a legitimate `None`.
            return;
        };
        assert!(
            before > (1 << 20),
            "implausibly small RSS before allocating: {before} bytes"
        );

        let mut ballast = vec![0_u8; usize::try_from(BALLAST_BYTES).unwrap_or(0)];
        for page in ballast.chunks_mut(PAGE) {
            if let Some(first) = page.first_mut() {
                *first = 1;
            }
        }

        // `unwrap_or(0)` rather than `expect`: a `None` here fails the
        // assertion below with the reading it produced, which says more than a
        // panic message would.
        let after = process_rss_bytes().unwrap_or(0);
        assert!(
            after >= before + (BALLAST_BYTES / 2),
            "RSS did not track a {BALLAST_BYTES}-byte resident allocation: {before} -> {after}"
        );

        // Keep the ballast alive across the second reading.
        assert_eq!(
            u64::try_from(std::hint::black_box(&ballast).len()).unwrap_or(0),
            BALLAST_BYTES
        );
    }

    #[test]
    fn install_diagnostic_metrics_returns_error_when_global_recorder_install_fails() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let result = install_diagnostic_metrics_with(Some(bind), |recorder| {
            Err(metrics::SetRecorderError(recorder))
        });

        assert!(result.is_err());
    }

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

    #[test]
    fn in_memory_recorder_records_counter_gauge_and_histogram_values() {
        let (recorder, handle) = test_recorder();

        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("node.test.counter").increment(2);
            metrics::counter!("node.test.counter").absolute(5);
            metrics::counter!("node.test.counter").absolute(3);

            metrics::gauge!("node.test.gauge").set(10.0);
            metrics::gauge!("node.test.gauge").increment(2.5);
            metrics::gauge!("node.test.gauge").decrement(1.5);

            metrics::histogram!("node.test.histogram").record(1.25);
            metrics::histogram!("node.test.histogram").record(2.75);
        });

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.get("node.test.counter"),
            Some(&MetricValue::Counter(5))
        );
        assert_eq!(
            snapshot.get("node.test.gauge"),
            Some(&MetricValue::Gauge(11.0))
        );
        assert_eq!(
            snapshot.get("node.test.histogram"),
            Some(&MetricValue::Histogram { count: 2, sum: 4.0 })
        );
    }

    #[test]
    fn in_memory_recorder_duplicate_registrations_share_metric_cell() {
        let (recorder, handle) = test_recorder();

        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("node.test.duplicate").increment(2);
            metrics::counter!("node.test.duplicate").increment(3);
            metrics::histogram!("node.test.repeat_histogram").record(1.0);
            metrics::histogram!("node.test.repeat_histogram").record(4.0);
        });

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.get("node.test.duplicate"),
            Some(&MetricValue::Counter(5))
        );
        assert_eq!(
            snapshot.get("node.test.repeat_histogram"),
            Some(&MetricValue::Histogram { count: 2, sum: 5.0 })
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
