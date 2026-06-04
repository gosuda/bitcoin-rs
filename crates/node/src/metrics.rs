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
        self.recorder.values.lock().clone()
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
    values: Arc<Mutex<HashMap<String, MetricValue>>>,
}

impl InMemoryRecorder {
    fn metric_key(key: &Key) -> String {
        key.name().to_owned()
    }

    fn ensure_counter(&self, key: String) {
        self.values
            .lock()
            .entry(key)
            .or_insert(MetricValue::Counter(0));
    }

    fn ensure_gauge(&self, key: String) {
        self.values
            .lock()
            .entry(key)
            .or_insert(MetricValue::Gauge(0.0));
    }

    fn ensure_histogram(&self, key: String) {
        self.values
            .lock()
            .entry(key)
            .or_insert(MetricValue::Histogram { count: 0, sum: 0.0 });
    }
}

impl Recorder for InMemoryRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let key = Self::metric_key(key);
        self.ensure_counter(key.clone());
        Counter::from_arc(Arc::new(CounterHandle {
            key,
            recorder: self.clone(),
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let key = Self::metric_key(key);
        self.ensure_gauge(key.clone());
        Gauge::from_arc(Arc::new(GaugeHandle {
            key,
            recorder: self.clone(),
        }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let key = Self::metric_key(key);
        self.ensure_histogram(key.clone());
        Histogram::from_arc(Arc::new(HistogramHandle {
            key,
            recorder: self.clone(),
        }))
    }
}

struct CounterHandle {
    key: String,
    recorder: InMemoryRecorder,
}

impl CounterFn for CounterHandle {
    fn increment(&self, value: u64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(MetricValue::Counter(0));
        if let MetricValue::Counter(current) = entry {
            *current = current.saturating_add(value);
        }
    }

    fn absolute(&self, value: u64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(MetricValue::Counter(0));
        if let MetricValue::Counter(current) = entry {
            *current = (*current).max(value);
        }
    }
}

struct GaugeHandle {
    key: String,
    recorder: InMemoryRecorder,
}

impl GaugeFn for GaugeHandle {
    fn increment(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(MetricValue::Gauge(0.0));
        if let MetricValue::Gauge(current) = entry {
            *current += value;
        }
    }

    fn decrement(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(MetricValue::Gauge(0.0));
        if let MetricValue::Gauge(current) = entry {
            *current -= value;
        }
    }

    fn set(&self, value: f64) {
        self.recorder
            .values
            .lock()
            .insert(self.key.clone(), MetricValue::Gauge(value));
    }
}

struct HistogramHandle {
    key: String,
    recorder: InMemoryRecorder,
}

impl HistogramFn for HistogramHandle {
    fn record(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(MetricValue::Histogram { count: 0, sum: 0.0 });
        if let MetricValue::Histogram { count, sum } = entry {
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
}
