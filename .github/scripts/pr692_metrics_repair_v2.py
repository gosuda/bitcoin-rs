from pathlib import Path


metrics = Path("crates/node/src/metrics.rs")
text = metrics.read_text()
start = text.index("#[derive(Default)]\nstruct RouterState")
end = text.index("\nfn serve_metrics(", start)
replacement = r'''#[derive(Default)]
struct RouterState {
    generation: u64,
    target: Option<RouterTarget>,
}

struct RouterTarget {
    generation: u64,
    recorder: Arc<PrometheusRecorder>,
}

/// Process-global metrics facade whose target is owned by one node lifecycle.
///
/// The facade itself is installed once, but a failed startup or completed node
/// clears its identity-specific target. A later lifecycle can therefore use a
/// different evidence identity. Every thread records through this facade, so
/// recovery and worker metrics emitted before the scrape listener starts are
/// retained without permanently committing a failed startup's identity.
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
            state.target.is_none(),
            "metrics recorder is already owned by another node lifecycle"
        );
        state.generation = state.generation.wrapping_add(1).max(1);
        let generation = state.generation;
        state.target = Some(RouterTarget {
            generation,
            recorder,
        });
        Ok(generation)
    }

    fn clear(&self, generation: u64) {
        let mut state = self.state.lock();
        if state
            .target
            .as_ref()
            .is_some_and(|target| target.generation == generation)
        {
            state.target = None;
        }
    }

    #[cfg(test)]
    fn has_active_target(&self) -> bool {
        self.state.lock().target.is_some()
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
fn metrics_target_is_active() -> bool {
    PROMETHEUS_ROUTER
        .get()
        .and_then(|result| result.as_ref().ok())
        .is_some_and(|router| router.has_active_target())
}

/// Identity-specific recorder reserved for a startup that has not yet
/// completed. The target is process-global so worker threads participate, but
/// the scrape socket is deliberately bound only at activation time to preserve
/// startup's existing storage/recovery-before-service-bind ordering.
pub(crate) struct PreparedMetrics {
    router: Arc<PrometheusRouter>,
    generation: u64,
    handle: PrometheusHandle,
    bind_addr: SocketAddr,
    armed: bool,
}

impl PreparedMetrics {
    fn prepare(bind_addr: SocketAddr, identity: &EvidenceIdentity) -> Result<Self> {
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
            bind_addr,
            armed: true,
        })
    }

    /// Binds the scrape socket and transfers the recorder target to the server.
    /// Any bind or thread-spawn error leaves this object armed so its drop
    /// clears the target after startup rollback has joined earlier workers.
    pub(crate) fn activate(&mut self, shutdown: Arc<AtomicBool>) -> Result<MetricsServer> {
        let listener = TcpListener::bind(self.bind_addr)?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = self.handle.clone();
        let thread = thread::Builder::new()
            .name("bitcoin-rs-metrics".into())
            .spawn(move || serve_metrics(&listener, &handle, &thread_stop, &shutdown))?;
        self.armed = false;
        Ok(MetricsServer {
            local_addr,
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
            self.router.clear(self.generation);
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
        let mut prepared = PreparedMetrics::prepare(addr, identity)?;
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
            self.router.clear(generation);
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Routes every thread into an identity-specific recorder before state opening
/// or worker startup. The scrape listener remains unbound until activation.
pub(crate) fn prepare_metrics(
    bind: Option<SocketAddr>,
    identity: &EvidenceIdentity,
) -> Result<Option<PreparedMetrics>> {
    bind.map(|addr| PreparedMetrics::prepare(addr, identity))
        .transpose()
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
    let mut prepared = PreparedMetrics::prepare(addr, identity)?;
    prepared.activate(shutdown).map(Some)
}
'''
text = text[:start] + replacement + text[end:]
text = text.replace("metrics_target_is_leased()", "metrics_target_is_active()")
text = text.replace("PreparedMetrics::bind(", "PreparedMetrics::prepare(")
text = text.replace(
    '"failed bind must not install the process recorder"',
    '"failed bind must release the startup recorder target"',
)
text = text.replace(
    "// MetricsServer::bind installs a process-global recorder. Serialize only\n"
    "    // these server tests so another test cannot change the recorder between\n"
    "    // the occupied-bind precondition and its assertion. Production is unchanged.\n"
    "    static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());\n",
    "// Metrics server tests and the run-level lifecycle regression share the\n"
    "    // process-global router. One lock makes their lifecycle assertions deterministic.\n",
)
text = text.replace("SERVER_TEST_LOCK.lock()", "METRICS_TEST_LOCK.lock()")
needle = "#[cfg(test)]\npub(crate) fn test_recorder() -> metrics::NoopRecorder {"
replacement_lock = "#[cfg(test)]\npub(crate) static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());\n\n" + needle
if needle not in text:
    raise SystemExit("metrics test-lock insertion marker missing")
text = text.replace(needle, replacement_lock, 1)
metrics.write_text(text)

run = Path("crates/node/src/run.rs")
text = run.read_text()
marker = "    #[test]\n    fn disabled_zmq_still_seals_the_observer_slot() {"
regression = r'''    #[test]
    fn late_start_failure_releases_metrics_identity_and_keeps_startup_metrics() -> anyhow::Result<()> {
        let _metrics_guard = crate::metrics::METRICS_TEST_LOCK.lock();
        let temp = tempfile::tempdir()?;
        let mut config = NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("metrics-retry");
        config.rpc.auth = crate::Auth::basic("user", "password");
        config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
        config.p2p.listen.clear();
        config.observability.metrics_bind = Some(SocketAddr::from(([127, 0, 0, 1], 0)));

        let occupied = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        config.rpc.bind = occupied.local_addr()?;
        let abandoned_identity = crate::metrics::EvidenceIdentity::of_process(&config)?;
        assert!(
            start_node(config.clone(), RuntimeInputs::default(), false).is_err(),
            "occupied RPC address must fail after state/recovery has emitted metrics"
        );
        drop(occupied);

        config.rpc.bind = SocketAddr::from(([127, 0, 0, 1], 0));
        let retry_identity = crate::metrics::EvidenceIdentity::of_process(&config)?;
        assert_ne!(
            abandoned_identity.config_sha256,
            retry_identity.config_sha256,
            "the retry must exercise a distinct evidence identity"
        );
        let (state, mut services, context) =
            start_node(config, RuntimeInputs::default(), false)?;
        let metrics_addr = services
            .metrics
            .as_ref()
            .map(crate::metrics::MetricsServer::local_addr)
            .unwrap_or_else(|| panic!("metrics server must be active after successful retry"));

        let mut response = None;
        for _ in 0..50 {
            match std::net::TcpStream::connect_timeout(
                &metrics_addr,
                std::time::Duration::from_millis(100),
            ) {
                Ok(mut stream) => {
                    use std::io::{Read as _, Write as _};
                    stream.write_all(
                        b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    )?;
                    stream.flush()?;
                    let mut body = String::new();
                    stream.read_to_string(&mut body)?;
                    response = Some(body);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let response = response.unwrap_or_else(|| panic!("metrics listener must accept scrapes"));
        assert!(
            response.contains("storage_cache_capacity_bytes"),
            "storage-open metric emitted before listener activation must survive: {response}"
        );

        drop(context);
        services.teardown(Some(&state), TeardownMode::StartupAbort)?;
        drop(state);
        Ok(())
    }

'''
if marker not in text:
    raise SystemExit("run regression insertion marker missing")
text = text.replace(marker, regression + marker, 1)
run.write_text(text)
