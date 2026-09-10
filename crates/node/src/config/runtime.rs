//! Process dependencies that are deliberately separate from user settings.

use std::sync::Arc;

use crossbeam_channel::Receiver;

/// Process and test dependencies that are not configuration.
#[derive(Default)]
pub struct RuntimeInputs {
    /// Optional in-process shutdown notification receiver.
    pub shutdown: Option<Receiver<()>>,
    /// Optional test-only mempool observer.
    pub mempool_observer: Option<Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
}

impl RuntimeInputs {
    /// Returns a copy with the given shutdown receiver.
    #[must_use]
    pub fn with_shutdown(mut self, rx: Receiver<()>) -> Self {
        self.shutdown = Some(rx);
        self
    }

    /// Returns a copy with the given mempool observer.
    #[must_use]
    pub fn with_mempool_observer(
        mut self,
        observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver>,
    ) -> Self {
        self.mempool_observer = Some(observer);
        self
    }
}
