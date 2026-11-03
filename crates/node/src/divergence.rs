use bitcoin_rs_chain::{HookGuard, LatchReader, LatchWriter};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub(crate) struct DivergenceWatch {
    stop: LatchWriter,
    worker: Option<JoinHandle<()>>,
    pub(crate) quarantine: LatchReader,
    pub(crate) mining_stop: LatchReader,
    _containment: HookGuard,
}

impl DivergenceWatch {
    pub(crate) fn start(datadir: &Path, shutdown: &LatchReader) -> io::Result<Self> {
        let metric = metrics::gauge!("node.consensus_quarantine");
        metric.set(0.0);
        let marker = datadir.join("consensus-divergence.json");
        let incident = LatchWriter::new();
        let quarantine = incident.reader();
        let mining = Arc::new(shutdown.child());
        let mining_stop = mining.reader();
        let containment = quarantine.on_cancel(move || mining.trigger());
        let stop = shutdown.child();
        let wait = stop.reader();
        let detect = move || match std::fs::symlink_metadata(&marker) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            result => {
                if let Err(error) = result {
                    tracing::error!(%error, "cannot inspect the consensus quarantine marker");
                }
                tracing::error!("consensus quarantine: mining and economic services suspended");
                incident.trigger();
                metric.set(1.0);
                true
            }
        };
        let worker = if detect() {
            None
        } else {
            Some(
                std::thread::Builder::new()
                    .name("divergence-watch".into())
                    .spawn(move || {
                        while wait
                            .closed()
                            .recv_timeout(Duration::from_millis(250))
                            .is_err()
                            && !wait.is_triggered()
                        {
                            if detect() {
                                break;
                            }
                        }
                    })?,
            )
        };
        Ok(Self {
            stop,
            worker,
            quarantine,
            mining_stop,
            _containment: containment,
        })
    }
}

impl Drop for DivergenceWatch {
    fn drop(&mut self) {
        self.stop.trigger();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
