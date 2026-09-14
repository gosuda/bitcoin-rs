// CONTRACT: `docs/contracts/architecture.md#ARCH-07` owns post-commit
// consumer ordering; `MiningGenerationSignal` is the mining wake projection.
use super::MiningGenerationSignal;
use crate::BlockTemplateRequest;
use crate::BlockTemplateResult;
use crate::MempoolSequenceWake;
use crate::MiningControl;
use crate::MiningControlError;
use bitcoin_rs_primitives::Block;
use compact_str::CompactString;
use parking_lot::Mutex;
use std::sync::Arc;

/// Records `publish_generation` and `publish_generation_from` calls; every
/// other control operation is unsupported in these tests.
#[derive(Default)]
struct RecordingControl {
    published: Mutex<usize>,
    published_from: Mutex<Vec<u64>>,
}

fn unavailable() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from("not wired in this test"))
}

impl MiningControl for RecordingControl {
    fn get_block_template(
        &self,
        _request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        Err(unavailable())
    }

    fn mining_info(&self) -> Result<crate::MiningInfo, MiningControlError> {
        Err(unavailable())
    }

    fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
        Err(unavailable())
    }

    fn submit_block(
        &self,
        _block: Block,
    ) -> Result<crate::BlockValidationResult, MiningControlError> {
        Err(unavailable())
    }

    fn submit_header(
        &self,
        _header: bitcoin_rs_primitives::Header,
    ) -> Result<(), MiningControlError> {
        Err(unavailable())
    }

    fn publish_generation(&self) {
        *self.published.lock() += 1;
    }

    fn generate(
        &self,
        _request: crate::GenerateRequest,
    ) -> Result<Vec<crate::GeneratedBlock>, MiningControlError> {
        Err(unavailable())
    }
}

impl MempoolSequenceWake for RecordingControl {
    fn publish_generation_from(&self, sequence: u64) {
        self.published_from.lock().push(sequence);
    }
}

#[test]
fn attached_signal_forwards_every_generation_publication() {
    // Detached: nothing to wake, nothing panics.
    let detached = MiningGenerationSignal::new();
    detached.publish_generation();
    detached.publish_generation_from(1);

    let signal = MiningGenerationSignal::new();
    let control = Arc::new(RecordingControl::default());
    let control_dyn: Arc<dyn MiningControl> = control.clone();
    signal.attach(&control_dyn);

    assert_eq!(*control.published.lock(), 0);
    signal.publish_generation();
    signal.publish_generation();
    assert_eq!(
        *control.published.lock(),
        2,
        "every authoritative-mutation wake must reach the coordinator"
    );
}

#[test]
fn attached_signal_forwards_sequence_wake_without_mempool_lock() {
    let signal = MiningGenerationSignal::new();
    let control = Arc::new(RecordingControl::default());
    let control_dyn: Arc<dyn MiningControl> = control.clone();
    signal.attach(&control_dyn);

    // Without attach_sequence_wake, publish_generation_from falls back.
    signal.publish_generation_from(1);
    assert_eq!(*control.published.lock(), 1);
    assert!(control.published_from.lock().is_empty());

    let wake_dyn: Arc<dyn MempoolSequenceWake> = control.clone();
    signal.attach_sequence_wake(&wake_dyn);

    signal.publish_generation_from(7);
    signal.publish_generation_from(8);
    assert_eq!(
        *control.published_from.lock(),
        vec![7, 8],
        "sequence wakes must reach the lock-free path"
    );
    assert_eq!(
        *control.published.lock(),
        1,
        "sequence wakes must not fall back to publish_generation"
    );
}
