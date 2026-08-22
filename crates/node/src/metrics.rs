extern crate alloc;

use alloc::sync::Arc;
use hashbrown::HashMap;
use std::net::SocketAddr;

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
    /// Address requested for the future Prometheus exporter.
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

/// Installs in-memory process metrics and returns its handle when configured.
///
/// The workspace pins `metrics-exporter-prometheus` without its HTTP listener.
/// This recorder keeps v1 metrics in process; wiring the Prometheus endpoint is
/// left to the follow-up feature that enables the exporter listener.
pub fn install_metrics(bind: Option<SocketAddr>) -> Result<Option<MetricsHandle>> {
    install_metrics_with(bind, metrics::set_global_recorder)
}

fn install_metrics_with(
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

    Ok(Some(handle))
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
    use std::net::{IpAddr, Ipv4Addr};

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
    fn install_metrics_returns_error_when_global_recorder_install_fails() {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let result = install_metrics_with(Some(bind), |recorder| {
            Err(metrics::SetRecorderError(recorder))
        });

        assert!(result.is_err());
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
}
