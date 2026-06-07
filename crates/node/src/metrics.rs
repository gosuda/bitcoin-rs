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
    metrics::describe_counter!("node.event_loop.defrag_ticks", "utxo defragmentation ticks");
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
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

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

    fn test_recorder() -> (InMemoryRecorder, MetricsHandle) {
        let recorder = InMemoryRecorder::default();
        let handle = MetricsHandle {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            recorder: recorder.clone(),
        };
        (recorder, handle)
    }
}
