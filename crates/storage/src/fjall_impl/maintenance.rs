use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fjall::{AbstractTree, Keyspace};

const INTERVAL: Duration = Duration::from_secs(10);
pub(super) const L0_DRAIN_THRESHOLD: usize = 15;

struct ReportWorkerPanic;

impl Drop for ReportWorkerPanic {
    fn drop(&mut self) {
        if thread::panicking() {
            tracing::error!("Fjall L0 maintenance worker panicked; maintenance stopped");
        }
    }
}

/// Joins before the store closes its engine and releases its directory guard.
pub(super) struct Maintenance {
    stop: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl Maintenance {
    pub(super) fn start(keyspaces: Vec<Keyspace>) -> std::io::Result<Self> {
        Self::start_with_interval(keyspaces, INTERVAL)
    }

    pub(super) fn start_with_interval(
        keyspaces: Vec<Keyspace>,
        interval: Duration,
    ) -> std::io::Result<Self> {
        let (stop, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("bitcoin-rs-fjall-maintenance".into())
            .spawn(move || {
                let _panic_report = ReportWorkerPanic;
                loop {
                    for keyspace in &keyspaces {
                        match receiver.try_recv() {
                            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return,
                            Err(mpsc::TryRecvError::Empty) => {}
                        }
                        if let Err(error) = drain_l0(keyspace) {
                            tracing::error!(keyspace = %keyspace.name(), %error, "Fjall L0 maintenance failed");
                        }
                    }
                    match receiver.recv_timeout(interval) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Maintenance {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// A zero GC watermark retains versions for every live Fjall snapshot.
fn drain_l0(keyspace: &Keyspace) -> Result<(), fjall::LsmError> {
    let l0_runs = keyspace.tree.l0_run_count();
    if l0_runs >= L0_DRAIN_THRESHOLD {
        tracing::info!(keyspace = %keyspace.name(), l0_runs, "Compacting Fjall L0 to relieve write backpressure");
        keyspace
            .tree
            .compact(Arc::new(lsm_tree::compaction::PullDown(0, 1)), 0)?;
    }
    Ok(())
}
