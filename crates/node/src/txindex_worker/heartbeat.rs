//! Observable progress while a node-owned storage open is blocked.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Heartbeat helper: emits a log line every 30 seconds while the worker's
/// backend open is blocked. Observability only — not a timeout.
pub(super) struct Heartbeat {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Heartbeat {
    pub(super) fn start(capability: &'static str, namespace: String, backend: String) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let start = Instant::now();
        let handle = thread::Builder::new()
            .name(format!("bitcoin-rs-{capability}-heartbeat"))
            .spawn(move || {
                while !stop_clone.load(Ordering::Acquire) {
                    let elapsed = start.elapsed();
                    tracing::info!(
                        capability,
                        namespace = %namespace,
                        backend = %backend,
                        elapsed_secs = elapsed.as_secs(),
                        "index store recovery in progress"
                    );
                    for _ in 0..300 {
                        if stop_clone.load(Ordering::Acquire) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            })
            .ok();
        Self { stop, handle }
    }

    pub(super) fn stop_and_join(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_starts_and_stops() {
        let heartbeat = Heartbeat::start("test", "test-ns".to_owned(), "test-backend".to_owned());
        // Give it a moment to potentially emit.
        std::thread::sleep(std::time::Duration::from_millis(50));
        heartbeat.stop_and_join();
        // If we get here without hanging, the heartbeat stopped and joined.
    }
}
