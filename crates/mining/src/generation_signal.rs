use std::sync::{Arc, Weak};

use bitcoin_rs_mempool::MempoolObserver;
use bitcoin_rs_mempool::MutationEnvelope;
use parking_lot::RwLock;

use crate::MempoolSequenceWake;
use crate::MiningControl;

/// Wake seam from authoritative mutations to the template coordinator.
/// Built with node state before the coordinator exists; the coordinator attaches
/// at startup. Detached, every wake is a no-op.
#[derive(Default)]
pub struct MiningGenerationSignal {
    coordinator: RwLock<Option<Weak<dyn MiningControl>>>,
    /// Lock-free mempool-sequence wake; set by [`Self::attach_sequence_wake`].
    sequence_wake: RwLock<Option<Weak<dyn MempoolSequenceWake>>>,
}

impl MiningGenerationSignal {
    /// Creates a detached signal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Weak: the RPC context owns the coordinator and `apply_handles` carries this signal back, so a strong ref would cycle.
    pub fn attach(&self, coordinator: &Arc<dyn MiningControl>) {
        *self.coordinator.write() = Some(Arc::downgrade(coordinator));
    }

    /// Attaches a lock-free mempool-sequence wake.
    pub fn attach_sequence_wake(&self, wake: &Arc<dyn MempoolSequenceWake>) {
        *self.sequence_wake.write() = Some(Arc::downgrade(wake));
    }

    /// Forwards one authoritative-mutation wake to the attached coordinator.
    pub fn publish_generation(&self) {
        if let Some(coordinator) = self.coordinator.read().as_ref().and_then(Weak::upgrade) {
            coordinator.publish_generation();
        }
    }

    /// Forwards one mempool-sequence wake.
    pub fn publish_generation_from(&self, sequence: u64) {
        if let Some(wake) = self.sequence_wake.read().as_ref().and_then(Weak::upgrade) {
            wake.publish_generation_from(sequence);
        } else {
            self.publish_generation();
        }
    }
}

impl MempoolObserver for MiningGenerationSignal {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let wake_sequence = result
            .sequence_of(result.changes.len().saturating_sub(1))
            .unwrap_or(result.sequence_base);
        self.publish_generation_from(wake_sequence);
    }

    fn on_gap(&self, latest_sequence: u64) {
        self.publish_generation_from(latest_sequence);
    }
}
