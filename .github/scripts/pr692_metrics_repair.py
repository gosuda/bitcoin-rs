from pathlib import Path


metrics = Path("crates/node/src/metrics.rs")
text = metrics.read_text()
text = text.replace(
    "use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};",
    "use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};",
    1,
)
start = text.index("static PROMETHEUS_HANDLE:")
end = text.index("\nfn serve_metrics(", start)
replacement = r'''#[derive(Default)]
struct RouterState {
    generation: u64,
    target: Option<RouterTarget>,
}

struct RouterTarget {
    generation: u64,
    recorder: Arc<PrometheusRecorder>,
    leased: bool,
}

/// Process-global metrics facade whose target is owned by one node lifecycle.
///
/// The facade itself is installed once, but a failed startup may discard its
/// Prometheus target and a later startup may replace it with a different
/// evidence identity. Every thread records through this facade, so recovery
/// and worker metrics emitted before the scrape listener starts are retained.
#[derive(Default)]
struct PrometheusRouter {
    state: Mutex<RouterState>,
}

impl PrometheusRouter {
    fn recorder(&self) -> Option<Arc<PrometheusRecorder>> {
        self.state
            .lock()
            .target
            .as_ref()
            .map(|target| Arc::clone(&target.recorder))
    }

    fn prepare(&self, recorder: Arc<PrometheusRecorder>) -> Result<u64> {
        let mut state = self.state.lock();
        anyhow::ensure!(
            !state.target.as_ref().is_some_and(|target| target.leased),
            "metrics recorder is already owned by another node lifecycle"
        );
        state.generation = state.generation.wrapping_add(1).max(1);
        let generation = state.generation;
        state.target = Some(RouterTarget {
            generation,
            recorder,
            leased: true,
        });
        Ok(generation)
    }

    fn abort(&self, generation: u64) {
        let mut state = self.state.lock();
        if state
            .target
            .as_ref()
            .is_some_and(|target| target.generation == generation && target.leased)
        {
            state.target = None;
        }
    }

    fn release(&self, generation: u64) {
        let mut state = self.state.lock();
        if let Some(target) = state
            .target
            .as_mut()
            .filter(|target| target.generation == generation)
        {
            target.leased = false;
        }
    }

    #[cfg(test)]
    fn has_active_lease(&self) -> bool {
        self.state
            .lock()
            .target
            .as_ref()
            .is_some_and(|target| target.leased)
    }
}

impl metrics::Recorder for PrometheusRouter {
    fn describe_counter(
        &self,
        key: metrics::KeyName,
        unit: Option<metrics::Unit>,
        description: metrics::SharedString,
    ) {
        if let Some(recorder) = self.recorder() {
            metrics::Recorder::describe_counter(recorder.as_ref(), key, unit, description);
        }
    }

    fn describe_gauge(
        &self,
        key: metrics::KeyName,
        unit: Option<metrics::Unit>,
        description: metrics::SharedString,
    ) {
        if let Some(recorder) = self.recorder() {
            metrics::Recorder::describe_gauge(recorder.as_ref(), key, unit, description);
        }
    }

    fn describe_histogram(
        &self,
        key: metrics::KeyName,
        unit: Option<metrics::Unit>,
        description: metrics::SharedString,
    ) {
        if let Some(recorder) = self.recorder() {
            metrics::Recorder::describe_histogram(recorder.as_ref(), key, unit, description);
        }
    }

    fn register_counter(
        &self,
        key: &metrics::Key,
        metadata: &metrics::Metadata<'_>,
    ) -> metrics::Counter {
        self.recorder().map_or_else(metrics::Counter::noop, |recorder| {
            metrics::Recorder::register_counter(recorder.as_ref(), key, metadata)
        })
    }

    fn register_gauge(
        &self,
        key: &metrics::Key,
        metadata: &metrics::Metadata<'_>,
    ) -> metrics::Gauge {
        self.recorder().map_or_else(metrics::Gauge::noop, |recorder| {
            metrics::Recorder::register_gauge(recorder.as_ref(), key, metadata)
        })
    }

    fn register_histogram(
        &self,
        key: &metrics::Key,
        metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        self.recorder().map_or_else(metrics::Histogram::noop, |recorder| {
            metrics::Recorder::register_histogram(recorder.as_ref(), key, metadata)
        })
    }
}

static PROMETHEUS_ROUTER: OnceLock<core::result::Result<Arc<PrometheusRouter>, String>> =
    OnceLock::new();

fn prometheus_router() -> Result<Arc<PrometheusRouter>> {
    let result = PROMETHEUS_ROUTER.get_or_init(|| {
        let router = Arc::new(PrometheusRouter::default());
        metrics::set_global_recorder(Arc::clone(&router))
            .map_err(|error| format!("install prometheus recorder router: {error}"))?;
        Ok(router)
    });
    match result {
        Ok(router) => Ok(Arc::clone(router)),
        Err(error) => Err(anyhow::anyhow!(error.clone())),
    }
}

#[cfg(test)]
fn metrics_target_is_leased() -> bool {
    PROMETHEUS_ROUTER
        .get()
        .and_then(|result| result.as_ref().ok())
        .is_some_and(|router| router.has_active_lease())
}

/// A bound metrics listener and identity-specific recorder reserved for a
/// startup that has not yet finished.
pub(crate) struct PreparedMetrics {
    router: Arc<PrometheusRouter>,
    generation: u64,
    handle: PrometheusHandle,
    listener: Option<TcpListener>,
    local_addr: SocketAddr,
    armed: bool,
}

impl PreparedMetrics {
    fn bind(addr: SocketAddr, identity: &EvidenceIdentity) -> Result<Self> {
        // Reserve the port before touching process-global metrics state.
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let mut builder = PrometheusBuilder::new();
        for (label, value) in identity.labels() {
            builder = builder.add_global_label(label, value);
        }
        let recorder = Arc::new(builder.build_recorder());
        let handle = recorder.handle();
        let router = prometheus_router()?;
        let generation = router.prepare(recorder)?;
        describe_node_metrics();

        Ok(Self {
            router,
            generation,
            handle,
            listener: Some(listener),
            local_addr,
            armed: true,
        })
    }

    /// Starts the scrape thread and transfers the recorder lease to the server.
    /// If thread creation fails, this object remains armed so startup rollback
    /// tears down workers before its drop discards the prepared recorder.
    pub(crate) fn activate(&mut self, shutdown: Arc<AtomicBool>) -> Result<MetricsServer> {
        let listener = self
            .listener
            .take()
            .ok_or_else(|| anyhow::anyhow!("prepared metrics listener already activated"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = self.handle.clone();
        let thread = thread::Builder::new()
            .name("bitcoin-rs-metrics".into())
            .spawn(move || serve_metrics(&listener, &handle, &thread_stop, &shutdown))?;
        self.armed = false;
        Ok(MetricsServer {
            local_addr: self.local_addr,
            stop,
            thread: Some(thread),
            router: Arc::clone(&self.router),
            generation: Some(self.generation),
        })
    }
}

impl Drop for PreparedMetrics {
    fn drop(&mut self) {
        if self.armed {
            self.router.abort(self.generation);
        }
    }
}

/// Process-global Prometheus scrape listener bound by [`start_metrics`].
pub struct MetricsServer {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    router: Arc<PrometheusRouter>,
    generation: Option<u64>,
}

impl MetricsServer {
    /// Binds a listener and immediately activates its lifecycle-owned recorder.
    pub fn bind(
        addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
        identity: &EvidenceIdentity,
    ) -> Result<Self> {
        let mut prepared = PreparedMetrics::bind(addr, identity)?;
        prepared.activate(shutdown)
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
        if let Some(generation) = self.generation.take() {
            // Keep the last recorder as an inert sink for any teardown metric;
            // the next lifecycle can replace it once this lease is released.
            self.router.release(generation);
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Reserves the metrics port and routes every thread into an identity-specific
/// recorder before state opening or worker startup.
pub(crate) fn prepare_metrics(
    bind: Option<SocketAddr>,
    identity: &EvidenceIdentity,
) -> Result<Option<PreparedMetrics>> {
    bind.map(|addr| PreparedMetrics::bind(addr, identity)).transpose()
}

/// Starts the production scrape listener when `metrics_bind` is configured.
pub(crate) fn start_metrics(
    bind: Option<SocketAddr>,
    shutdown: Arc<AtomicBool>,
    identity: &EvidenceIdentity,
) -> Result<Option<MetricsServer>> {
    let Some(addr) = bind else {
        return Ok(None);
    };
    let mut prepared = PreparedMetrics::bind(addr, identity)?;
    prepared.activate(shutdown).map(Some)
}
'''
text = text[:start] + replacement + text[end:]
text = text.replace(
    "let installed_before = PROMETHEUS_HANDLE.lock().is_some();",
    "let installed_before = metrics_target_is_leased();",
    1,
)
text = text.replace(
    "PROMETHEUS_HANDLE.lock().is_some(),\n            installed_before,",
    "metrics_target_is_leased(),\n            installed_before,",
    1,
)
marker = "    #[test]\n    fn scrape_returns_prometheus_text_with_recorded_metrics() {"
test = r'''    #[test]
    fn prepared_recorder_captures_workers_and_allows_changed_identity_retry() {
        let _guard = SERVER_TEST_LOCK.lock();

        let mut abandoned_identity = identity();
        abandoned_identity.version = "abandoned-start".into();
        {
            let _prepared = PreparedMetrics::bind(unused_ephemeral(), &abandoned_identity)
                .unwrap_or_else(|error| panic!("prepare abandoned start: {error}"));
            metrics::counter!("node_metrics_abandoned_start_probe").increment(1);
        }
        assert!(
            !metrics_target_is_leased(),
            "dropping an uncommitted startup must release its recorder lease"
        );

        let mut retry_identity = identity();
        retry_identity.version = "retry-start".into();
        let mut prepared = PreparedMetrics::bind(unused_ephemeral(), &retry_identity)
            .unwrap_or_else(|error| panic!("prepare retry: {error}"));
        metrics::counter!("node_metrics_recovery_probe").increment(1);
        std::thread::spawn(|| {
            metrics::counter!("node_metrics_early_worker_probe").increment(1);
        })
        .join()
        .unwrap_or_else(|_| panic!("early worker"));

        let shutdown = Arc::new(AtomicBool::new(false));
        let server = prepared
            .activate(shutdown)
            .unwrap_or_else(|error| panic!("activate retry: {error}"));
        let (status, body) = scrape(server.local_addr());
        assert_eq!(status, 200);
        assert!(
            body.contains("node_metrics_recovery_probe"),
            "pre-activation recovery sample missing: {body}"
        );
        assert!(
            body.contains("node_metrics_early_worker_probe"),
            "pre-activation worker sample missing: {body}"
        );
        server.join();
    }

'''
if marker not in text:
    raise SystemExit("metrics test insertion marker missing")
text = text.replace(marker, test + marker, 1)
metrics.write_text(text)

run = Path("crates/node/src/run.rs")
text = run.read_text()
old = "    cap_global_thread_pool();\n\n    let injected_shutdown = runtime.shutdown;"
new = '''    cap_global_thread_pool();

    // Reserve the metrics listener and route all threads into this startup's
    // recorder before storage/recovery can emit a sample. The recorder lease
    // is discarded if any later startup step fails, so a retry may use a
    // different evidence identity without losing recovery/worker metrics.
    let mut prepared_metrics = if config.observability.metrics_bind.is_some() {
        let identity = crate::metrics::EvidenceIdentity::of_process(&config)?;
        crate::metrics::prepare_metrics(config.observability.metrics_bind, &identity)?
    } else {
        None
    };

    let injected_shutdown = runtime.shutdown;'''
if old not in text:
    raise SystemExit("run startup marker missing")
text = text.replace(old, new, 1)
old = '''    let metrics = if let Some(bind) = state.config().observability.metrics_bind {
        let identity = crate::metrics::EvidenceIdentity::of_process(state.config())?;
        crate::metrics::start_metrics(Some(bind), state.shutdown(), &identity)?
    } else {
        None
    };
    guard.services.metrics = metrics;

'''
if old not in text:
    raise SystemExit("old metrics startup block missing")
text = text.replace(old, "", 1)
old = "    guard.services.event_loop = Some(event_loop);\n    let (state, services) = guard.disarm();"
new = '''    guard.services.event_loop = Some(event_loop);
    // Starting the scrape thread is the final fallible startup step. All
    // previously spawned workers have already been recording through the
    // prepared process-global router, and failures before here release that
    // recorder lease after StartupGuard has joined those workers.
    if let Some(prepared) = prepared_metrics.as_mut() {
        guard.services.metrics = Some(prepared.activate(state.shutdown())?);
    }
    let (state, services) = guard.disarm();'''
if old not in text:
    raise SystemExit("run activation marker missing")
text = text.replace(old, new, 1)
run.write_text(text)
