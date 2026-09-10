//! Prometheus recorder identity and synchronous scrape-listener lifecycle.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Result;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;

use super::EvidenceIdentity;
use super::catalog::describe_node_metrics;

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
    stop: &AtomicBool,
    shutdown: &AtomicBool,
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
mod tests;
