use super::MempoolSequenceWake;
use super::MiningGenerationSignal;
use bitcoin_rs_mining::BlockTemplateRequest;
use bitcoin_rs_mining::BlockTemplateResult;
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::MiningControlError;
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

    fn mining_info(&self) -> Result<bitcoin_rs_mining::MiningInfo, MiningControlError> {
        Err(unavailable())
    }

    fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
        Err(unavailable())
    }

    fn submit_block(
        &self,
        _block: Block,
    ) -> Result<bitcoin_rs_mining::BlockValidationResult, MiningControlError> {
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
        _request: bitcoin_rs_mining::GenerateRequest,
    ) -> Result<Vec<bitcoin_rs_mining::GeneratedBlock>, MiningControlError> {
        Err(unavailable())
    }
}

impl MempoolSequenceWake for RecordingControl {
    fn publish_generation_from(&self, sequence: u64) {
        self.published_from.lock().push(sequence);
    }
}

// Contract: `MiningGenerationSignal`'s public methods document detached
// no-op behavior, forwarding, and the lock-free sequence-wake fallback.
#[test]
fn detached_signal_is_a_noop() {
    let signal = MiningGenerationSignal::new();
    // No coordinator attached: nothing to wake, nothing panics.
    signal.publish_generation();
    signal.publish_generation();
    signal.publish_generation_from(1);
}

#[test]
fn attached_signal_forwards_every_generation_publication() {
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
    let wake_dyn: Arc<dyn MempoolSequenceWake> = control.clone();
    signal.attach(&control_dyn);
    signal.attach_sequence_wake(&wake_dyn);

    assert!(control.published_from.lock().is_empty());
    signal.publish_generation_from(7);
    signal.publish_generation_from(8);
    assert_eq!(
        *control.published_from.lock(),
        vec![7, 8],
        "sequence wakes must reach the lock-free path"
    );
    assert_eq!(
        *control.published.lock(),
        0,
        "sequence wakes must not fall back to publish_generation"
    );
}

#[test]
fn sequence_wake_falls_back_when_not_attached() {
    let signal = MiningGenerationSignal::new();
    let control = Arc::new(RecordingControl::default());
    let control_dyn: Arc<dyn MiningControl> = control.clone();
    signal.attach(&control_dyn);

    signal.publish_generation_from(1);
    assert_eq!(
        *control.published.lock(),
        1,
        "without attach_sequence_wake, publish_generation_from falls back"
    );
    assert!(
        control.published_from.lock().is_empty(),
        "the lock-free path is not taken without attach_sequence_wake"
    );
}
