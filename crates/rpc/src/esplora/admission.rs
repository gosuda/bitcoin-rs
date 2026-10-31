//! Node-wide admission for public script projections, independent of sockets.

use std::num::NonZeroUsize;
use std::time::Instant;

use parking_lot::Mutex;

#[derive(Debug)]
pub(crate) struct Admission {
    limit: NonZeroUsize,
    active: Mutex<usize>,
}

impl Admission {
    pub(crate) const fn new(limit: NonZeroUsize) -> Self {
        Self {
            limit,
            active: Mutex::new(0),
        }
    }

    pub(crate) fn try_acquire(&self) -> Option<Permit<'_>> {
        let mut active = self.active.lock();
        if *active >= self.limit.get() {
            metrics::counter!("rpc.esplora.expensive.rejected_total").increment(1);
            return None;
        }
        *active += 1;
        metrics::gauge!("rpc.esplora.expensive.active").increment(1.0);
        Some(Permit {
            admission: self,
            started: Instant::now(),
        })
    }
}

pub(crate) struct Permit<'a> {
    admission: &'a Admission,
    started: Instant,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut active = self.admission.active.lock();
        *active -= 1;
        metrics::gauge!("rpc.esplora.expensive.active").decrement(1.0);
        drop(active);
        metrics::histogram!("rpc.esplora.expensive.execution_seconds")
            .record(self.started.elapsed().as_secs_f64());
    }
}

pub(super) fn is_expensive(path: &str) -> bool {
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    matches!(
        parts.as_slice(),
        ["address" | "scripthash", _]
            | ["address" | "scripthash", _, "utxo" | "txs"]
            | [
                "address" | "scripthash",
                _,
                "txs",
                "summary" | "mempool" | "chain"
            ]
            | ["address" | "scripthash", _, "txs", "chain", _]
    )
}
